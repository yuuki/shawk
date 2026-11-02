package shawkconnector

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	"go.opentelemetry.io/collector/component"
	"go.opentelemetry.io/collector/connector"
	"go.opentelemetry.io/collector/consumer"
	"go.opentelemetry.io/collector/pdata/pmetric"
	"go.uber.org/zap"
)

type shawkConnector struct {
	cfg  *Config
	log  *zap.Logger
	next consumer.Metrics

	// newStore opens the store; replaced in tests.
	newStore func(ctx context.Context, dsn string) (store, error)
	store    store
	resolver *resolver

	mu      sync.Mutex
	agg     *aggregator
	changes *changes
	// ready tells that the schema has been migrated, or checked to be
	// recent enough, so that writes may proceed.
	ready bool
	// cidrsSynced tells that peer_cidrs has been written to PostgreSQL.
	cidrsSynced bool
	cidrs       []namedPrefix

	lastPrune, lastRefresh time.Time

	// Errors of the pipeline after the connector, logged at most once a
	// minute.
	downstreamErrs    int
	lastDownstreamLog time.Time

	// foldWarned holds, by host whose agent folds the edges of hosts that run
	// an agent and by side it folds, when it was last logged and the hosts
	// it folded since.
	foldWarned map[foldWarnKey]*foldWarning
	// cidrWarned is when what agents fold, and the ranges of peer_cidrs they
	// fold, were last logged.
	cidrWarned map[string]time.Time

	cancel context.CancelFunc
	done   chan struct{}
	now    func() time.Time
}

func newConnector(set connector.Settings, cfg *Config, next consumer.Metrics) (*shawkConnector, error) {
	cidrs, err := parsePeerCIDRs(cfg.PeerCIDRs)
	if err != nil {
		return nil, err
	}
	now := time.Now()
	return &shawkConnector{
		cfg:      cfg,
		log:      set.Logger,
		next:     next,
		newStore: newPGStore,
		resolver: newResolver(cidrs),
		agg:      newAggregator(cfg.IdleTTL, cfg.MaxPeers, cfg.KeepPeerAddress, now),
		changes:  newChanges(cfg.IdleTTL),
		cidrs:    cidrs,
		now:      time.Now,

		foldWarned: map[foldWarnKey]*foldWarning{},
		cidrWarned: map[string]time.Time{},
	}, nil
}

func (c *shawkConnector) Capabilities() consumer.Capabilities {
	return consumer.Capabilities{MutatesData: false}
}

func (c *shawkConnector) Start(ctx context.Context, _ component.Host) error {
	dsn := c.cfg.Postgres.DSN
	if c.cfg.Postgres.DSNFile != "" {
		b, err := os.ReadFile(c.cfg.Postgres.DSNFile)
		if err != nil {
			return fmt.Errorf("reading postgres.dsn_file: %w", err)
		}
		dsn = strings.TrimSpace(string(b))
		if dsn == "" {
			return fmt.Errorf("postgres.dsn_file %s is empty", c.cfg.Postgres.DSNFile)
		}
	}
	st, err := c.newStore(ctx, dsn)
	if err != nil {
		return err
	}
	c.store = st

	loopCtx, cancel := context.WithCancel(context.Background())
	c.cancel = cancel
	c.done = make(chan struct{})
	// Read the names of peers before the first request if the database is
	// up; otherwise the loop retries.
	initCtx, initCancel := context.WithTimeout(ctx, 10*time.Second)
	c.prepare(initCtx)
	initCancel()
	go c.loop(loopCtx)
	return nil
}

// prepare migrates the schema if configured to, or checks its version,
// writes peer_cidrs and reloads the names of peers. It reports whether the
// schema is ready.
func (c *shawkConnector) prepare(ctx context.Context) bool {
	if !c.prepareSchemaOnly(ctx) {
		return false
	}
	c.mu.Lock()
	synced := c.cidrsSynced
	c.mu.Unlock()
	if !synced {
		// PostgreSQL names peers without a service by peer_cidrs too.
		if err := c.store.syncPeerCIDRs(ctx, c.cidrs); err != nil {
			c.log.Warn("writing peer_cidrs to PostgreSQL", zap.Error(err))
		} else {
			c.mu.Lock()
			c.cidrsSynced = true
			c.mu.Unlock()
		}
	}
	at := c.now()
	rows, err := c.store.peers(ctx)
	if err != nil {
		c.log.Warn("reading the names of peers from PostgreSQL", zap.Error(err))
		return true
	}
	c.resolver.load(rows, at)
	return true
}

// prepareSchemaOnly migrates the schema if configured to, or checks that
// it is not older than the connector, if that is still pending, and
// reports whether writes may proceed.
func (c *shawkConnector) prepareSchemaOnly(ctx context.Context) bool {
	c.mu.Lock()
	ready := c.ready
	c.mu.Unlock()
	if ready {
		return true
	}
	if c.cfg.Postgres.Migrate {
		applied, err := c.store.migrate(ctx)
		if err != nil {
			c.log.Error("migrating the PostgreSQL schema; writes wait until it succeeds", zap.Error(err))
			return false
		}
		if len(applied) > 0 {
			c.log.Info("migrated the PostgreSQL schema", zap.Strings("applied", applied))
		}
	} else {
		v, err := c.store.schemaVersion(ctx)
		if err != nil {
			c.log.Error("reading the version of the PostgreSQL schema; writes wait until it succeeds", zap.Error(err))
			return false
		}
		switch want := SchemaVersion(); {
		case v < want:
			c.log.Error("the PostgreSQL schema is older than the connector; run shawk-migrate, writes wait until then",
				zap.Int("version", v), zap.Int("required", want))
			return false
		case v > want:
			c.log.Warn("the PostgreSQL schema is newer than the connector; upgrade the connector",
				zap.Int("version", v), zap.Int("connector", want))
		}
	}
	c.mu.Lock()
	c.ready = true
	c.mu.Unlock()
	return true
}

func (c *shawkConnector) loop(ctx context.Context) {
	defer close(c.done)
	t := time.NewTicker(c.cfg.WriteInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			// Write what is pending before the collector stops.
			fctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			if c.prepareSchemaOnly(fctx) {
				c.flush(fctx)
			}
			cancel()
			return
		case <-t.C:
			// Writes and the reload of peers have their own deadlines, so
			// that a slow write does not stop the names from being reloaded.
			wctx, cancel := context.WithTimeout(ctx, c.cfg.WriteInterval)
			if c.prepareSchemaOnly(wctx) {
				c.flush(wctx)
			}
			cancel()
			rctx, cancel := context.WithTimeout(ctx, c.cfg.WriteInterval)
			c.prepare(rctx)
			cancel()
			c.pruneIfDue(ctx)
			c.refreshIfDue(ctx)
			now := c.now()
			c.mu.Lock()
			c.agg.expire(now)
			c.changes.expire(now)
			// A host that folded hosts since it was logged is kept, so that
			// the next warning counts them.
			for k, w := range c.foldWarned {
				if len(w.hosts) == 0 && now.Sub(w.logged) >= foldWarnInterval {
					delete(c.foldWarned, k)
				}
			}
			for k, t := range c.cidrWarned {
				if now.Sub(t) >= foldWarnInterval {
					delete(c.cidrWarned, k)
				}
			}
			c.mu.Unlock()
			c.resolver.expire(now.Add(-c.cfg.IdleTTL), now)
		}
	}
}

// pruneBatch bounds the rows deleted per table in one transaction.
const pruneBatch = 10000

// pruneIfDue deletes the rows older than the retention, once an hour, in
// batches so that no transaction holds locks for long.
func (c *shawkConnector) pruneIfDue(ctx context.Context) {
	if c.cfg.Retention == 0 || c.now().Sub(c.lastPrune) < time.Hour {
		return
	}
	c.mu.Lock()
	ready := c.ready
	c.mu.Unlock()
	if !ready {
		return
	}
	var total int64
	for range 1000 {
		pctx, cancel := context.WithTimeout(ctx, time.Minute)
		n, err := c.store.prune(pctx, c.cfg.Retention, pruneBatch)
		cancel()
		if err != nil {
			c.log.Error("deleting rows older than the retention", zap.Error(err))
			return
		}
		total += n
		if n == 0 {
			break
		}
	}
	c.lastPrune = c.now()
	if total > 0 {
		c.log.Info("deleted rows older than the retention", zap.Int64("rows", total), zap.Duration("retention", c.cfg.Retention))
	}
}

// refreshInterval is how often the history of dependencies between
// services, which tells a dependency that comes back from one that is new,
// is brought up to date.
const refreshInterval = 5 * time.Minute

// refreshIfDue brings the history of dependencies up to date.
func (c *shawkConnector) refreshIfDue(ctx context.Context) {
	if c.now().Sub(c.lastRefresh) < refreshInterval {
		return
	}
	c.mu.Lock()
	ready := c.ready
	c.mu.Unlock()
	if !ready {
		return
	}
	rctx, cancel := context.WithTimeout(ctx, time.Minute)
	defer cancel()
	if _, err := c.store.refreshDependencies(rctx); err != nil {
		c.log.Error("updating the history of dependencies", zap.Error(err))
		return
	}
	c.lastRefresh = c.now()
}

// flush writes the pending changes, one transaction per host. The changes
// of a host that fail to be written are kept for the next flush.
func (c *shawkConnector) flush(ctx context.Context) {
	c.mu.Lock()
	pending := c.changes.take()
	c.mu.Unlock()
	var failed int
	var lastErr error
	for _, h := range pending {
		if err := c.store.write(ctx, h); err != nil {
			if isDataError(err) {
				// Writing these changes again would fail again and block the
				// host for good; drop them.
				c.log.Error("dropping changes that PostgreSQL rejects", zap.String("host", h.hostname),
					zap.Int("rows", h.size()), zap.Error(err))
				c.mu.Lock()
				c.changes.forget(h.key, c.now())
				c.mu.Unlock()
				continue
			}
			failed++
			lastErr = err
			c.mu.Lock()
			c.changes.restore(h)
			c.mu.Unlock()
		}
	}
	if failed > 0 {
		c.mu.Lock()
		size := c.changes.pendingSize()
		c.mu.Unlock()
		c.log.Error("writing to PostgreSQL; the changes are kept for the next write",
			zap.Int("hosts", failed), zap.Int("pending_rows", size), zap.Error(lastErr))
	}
}

func (c *shawkConnector) Shutdown(context.Context) error {
	if c.cancel != nil {
		c.cancel()
		<-c.done
	}
	if c.store != nil {
		c.store.close()
	}
	return nil
}

// ConsumeMetrics consumes the requests of agents. Every resource is the
// request of one agent.
//
// An error of the pipeline after the connector, e.g. Prometheus being
// down, is logged rather than returned: the request has been taken for
// PostgreSQL, and an agent that sees an error counts a failed export and
// eventually restarts its observation segment.
func (c *shawkConnector) ConsumeMetrics(ctx context.Context, md pmetric.Metrics) error {
	out := pmetric.NewMetrics()
	now := c.now()
	rms := md.ResourceMetrics()
	for i := range rms.Len() {
		b, err := parseResource(rms.At(i))
		if err != nil {
			if errors.Is(err, errNotAgent) {
				c.log.Debug("ignoring metrics that do not come from a shawk agent")
				continue
			}
			c.log.Warn("ignoring a resource", zap.Error(err))
			continue
		}
		if b.invalid > 0 {
			c.log.Warn("ignoring invalid data points", zap.String("host", b.hostname), zap.Int("count", b.invalid))
		}
		c.resolver.learn(b, now)
		c.mu.Lock()
		c.foldedCIDRs(b, now)
		c.changes.add(b, now)
		c.agg.add(b, func(id *edgeID) peer {
			p := c.resolver.peer(b.key, id, now)
			if p.foldedBy != "" {
				c.foldedAgentPeer(b, id, p, now)
			}
			return p
		}, now, out)
		c.mu.Unlock()
	}
	if out.ResourceMetrics().Len() > 0 {
		if err := c.next.ConsumeMetrics(ctx, out); err != nil {
			c.downstreamError(err, now)
		}
	}
	return nil
}

// foldWarnInterval is how often a host is logged by foldedAgentPeer and
// foldedCIDRs.
const foldWarnInterval = time.Hour

// foldWarnKey is a host whose agent folds, and whether it folds servers
// (the clients otherwise).
type foldWarnKey struct {
	host    string
	servers bool
}

// foldWarning is what foldedAgentPeer logged of a host whose agent folds.
type foldWarning struct {
	logged time.Time
	hosts  map[string]bool // folded since logged
}

// foldedAgentPeer logs an edge whose peer runs an agent that folds this side
// into its external peers although it runs an agent too, as happens to
// hosts that talk over public addresses: the agent of a server folds a
// client outside its internal ranges, or the agent of a client with
// -fold-external=all a server outside them. The two sides of their
// connections do not match in PostgreSQL. It logs each host whose agent
// folds at most once an hour, with the number of hosts it folded since.
// When both agents fold the other side, both edges are folded and neither
// tells the other host, so nothing is logged. c.mu is held.
func (c *shawkConnector) foldedAgentPeer(b *hostBatch, id *edgeID, p peer, now time.Time) {
	k := foldWarnKey{host: p.foldedBy, servers: p.foldsServer}
	w := c.foldWarned[k]
	if w == nil {
		w = &foldWarning{hosts: map[string]bool{}}
		c.foldWarned[k] = w
	}
	w.hosts[b.key] = true
	if !w.logged.IsZero() && now.Sub(w.logged) < foldWarnInterval {
		return
	}
	n := len(w.hosts)
	w.logged, w.hosts = now, map[string]bool{}
	folder := p.foldedByName
	if folder == "" {
		folder = p.foldedBy
	}
	msg := "the agent of a server folds a client that runs an agent into its external peers; " +
		"add the address of the client to the internal peers of the server's agent (-internal-peers)"
	client, server := zap.String("client_host", b.hostname), zap.String("server_host", folder)
	clientAddr, serverAddr := zap.String("client_address", id.local.String()), zap.String("server_address", id.peer.String())
	if p.foldsServer {
		msg = "the agent of a client folds a server that runs an agent into its external peers (-fold-external=all); " +
			"add the address of the server to the internal peers of the client's agent (-internal-peers)"
		client, server = zap.String("client_host", folder), zap.String("server_host", b.hostname)
		clientAddr, serverAddr = zap.String("client_address", id.peer.String()), zap.String("server_address", id.local.String())
	}
	c.log.Warn(msg, client, clientAddr, server, serverAddr, zap.Uint16("port", id.port),
		zap.String("transport", id.proto), zap.Int("hosts_folded", n))
}

// foldedCIDRs logs agents that fold peers in ranges of peer_cidrs: a
// folded peer has lost its address, so it is named ~external rather than
// after its range. A range of a whole network names the folded peers
// themselves, and is left out. Agents usually share their configuration,
// so each configuration (what is folded and the ranges kept exact) is
// logged at most once an hour, with a host that has it. c.mu is held.
func (c *shawkConnector) foldedCIDRs(b *hostBatch, now time.Time) {
	if !b.final || (b.peerFold != foldIn && b.peerFold != foldAll) {
		return
	}
	a := agentHost{fold: b.peerFold, internal: b.peerInternal}
	var folded []string
	for _, r := range c.cidrs {
		if r.prefix.Bits() > 0 && !a.keepsRange(r.prefix) {
			folded = append(folded, r.name+"="+r.prefix.String())
		}
	}
	if len(folded) == 0 {
		return
	}
	k := fmt.Sprint(b.peerFold, b.peerInternal)
	if t, ok := c.cidrWarned[k]; ok && now.Sub(t) < foldWarnInterval {
		return
	}
	c.cidrWarned[k] = now
	msg := "agents fold the clients in ranges of peer_cidrs, which their servers then name ~external; " +
		"add the ranges to their internal peers (-internal-peers)"
	if b.peerFold == foldAll {
		msg = "agents fold the peers in ranges of peer_cidrs, which are then named ~external; " +
			"add the ranges to their internal peers (-internal-peers)"
	}
	c.log.Warn(msg, zap.String("host", b.hostname), zap.String("fold", b.peerFold), zap.Strings("peer_cidrs", folded))
}

// downstreamError logs an error of the pipeline after the connector, at
// most once a minute.
func (c *shawkConnector) downstreamError(err error, now time.Time) {
	c.mu.Lock()
	c.downstreamErrs++
	n := c.downstreamErrs
	if !c.lastDownstreamLog.IsZero() && now.Sub(c.lastDownstreamLog) < time.Minute {
		c.mu.Unlock()
		return
	}
	c.lastDownstreamLog, c.downstreamErrs = now, 0
	c.mu.Unlock()
	c.log.Error("forwarding the aggregated metrics; they are sent again with the next interval of each host",
		zap.Int("failures", n), zap.Error(err))
}

// isDataError tells whether PostgreSQL rejected the data itself (SQLSTATE
// classes 22, data exception, and 23, integrity constraint violation),
// rather than failing for a reason that may pass, such as a lost
// connection.
func isDataError(err error) bool {
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) {
		return false
	}
	return strings.HasPrefix(pgErr.Code, "22") || strings.HasPrefix(pgErr.Code, "23")
}
