package shawkconnector

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	"go.opentelemetry.io/collector/component"
	"go.opentelemetry.io/collector/connector"
	"go.opentelemetry.io/collector/consumer"
	"go.opentelemetry.io/collector/consumer/consumererror"
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
	limits   *limits

	mu      sync.Mutex
	agg     *aggregator
	changes *changes
	// ready tells that the schema has been migrated, or checked to be
	// recent enough, so that writes may proceed.
	ready bool
	// cidrsSynced tells that peer_cidrs, the translations and the rules of
	// ports have been written to PostgreSQL.
	cidrsSynced  bool
	cidrs        []namedPrefix
	translations []translation
	ports        *portRules

	// inventory is the inventory last read from inventory_file, or from
	// PostgreSQL while the file cannot be read; nil while none is known.
	inventory atomic.Pointer[inventory]
	// inventoryReadAt is when the inventory was read from the file, and
	// inventoryUnwritten tells that writing it to PostgreSQL failed since.
	inventoryReadAt    time.Time
	inventoryUnwritten bool
	// inventoryErr is the latest failure to read inventory_file, and when
	// it was logged.
	inventoryErr       string
	lastInventoryLog   time.Time
	inventoryFromStore bool
	// inventoryWarned is when hosts whose agents send addresses that the
	// inventory gives to other hosts were last logged, by host.
	inventoryWarned map[string]time.Time

	lastPrune, lastRefresh time.Time
	// written is when the latest write that took every pending change
	// started: what was seen before it is in PostgreSQL.
	written time.Time
	// portRulesWarned is when rules of ports in PostgreSQL other than
	// those of this connector were last logged.
	portRulesWarned time.Time

	// Of the node_states_file and the maintenance_file, used by the loop
	// only: when the states last written were read from Slurm, the
	// maintenance windows last written and when, the errors last logged,
	// and whether stale states were logged.
	nodeStatesAt                  time.Time
	windowsKey                    string
	windowsSynced                 time.Time
	nodeStatesErr, maintenanceErr string
	nodeStatesStale               bool
	// unknownNodes are the nodes the inventory did not map, last logged.
	unknownNodes string

	// Errors of the pipeline after the connector, logged at most once a
	// minute.
	downstreamErrs    int
	lastDownstreamLog time.Time
	// Requests refused by host_identity, logged at most once a minute.
	refused        int
	lastRefusedLog time.Time
	// Metrics and points of agents that are not forwarded, logged at most
	// once a minute.
	agentDropped        int
	lastAgentDroppedLog time.Time
	// Requests of hosts refused by max_hosts, and series and input series
	// dropped by max_series_per_host, logged at most once a minute each.
	hostsRefused                 int
	lastHostsLog                 time.Time
	seriesDropped, inputsDropped int
	lastSeriesLog                time.Time

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
	translations, err := parseTranslations(cfg.Translations)
	if err != nil {
		return nil, err
	}
	ports, err := parsePortRules(cfg.PortAgnosticServices, cfg.DynamicPorts)
	if err != nil {
		return nil, err
	}
	now := time.Now()
	res := newResolver(cidrs, translations)
	res.maxInferred = cfg.MaxSeriesPerHost
	res.peerHosts = cfg.PeerHosts
	agg := newAggregator(cfg.IdleTTL, cfg.MaxPeers, cfg.MaxServices, cfg.KeepPeerAddress, now)
	agg.maxInputs = maxValuesPerEdge * cfg.MaxSeriesPerHost
	if cfg.PeerHosts {
		agg.setPeerHosts(cfg.MaxPeerHosts, cfg.PeerHostServices)
	}
	agg.ports = ports
	c := &shawkConnector{
		cfg:      cfg,
		log:      set.Logger,
		next:     next,
		newStore: newPGStore,
		resolver: res,
		limits:   newLimits(cfg.MaxHosts, cfg.MaxSeriesPerHost, cfg.IdleTTL),
		agg:      agg,
		changes:  newChanges(cfg.IdleTTL, cfg.JobUsers),
		cidrs:    cidrs,
		now:      time.Now,

		translations: translations,
		ports:        ports,

		foldWarned: map[foldWarnKey]*foldWarning{},
		cidrWarned: map[string]time.Time{},

		inventoryWarned: map[string]time.Time{},
	}
	// The inventory is the first evidence of the host of a peer (§5.2 of
	// docs/design.md), read from inventory_file every write interval.
	res.inventory = func(a netip.Addr) (string, bool) { return c.inventory.Load().hostOf(a) }
	return c, nil
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
// writes peer_cidrs, the translations and the rules of ports, reads the
// inventory and writes it, writes what changed in the node_states_file and
// the maintenance_file, and reloads the names of peers.
// It reports whether the schema is ready.
func (c *shawkConnector) prepare(ctx context.Context) bool {
	if !c.prepareSchemaOnly(ctx) {
		return false
	}
	c.mu.Lock()
	synced := c.cidrsSynced
	c.mu.Unlock()
	if !synced {
		// PostgreSQL names peers without a service by peer_cidrs too,
		// matches edges through the translations, and aggregates
		// dependencies by the rules of ports.
		if err := c.store.syncConfig(ctx, c.cidrs, c.translations, c.ports); err != nil {
			c.log.Warn("writing peer_cidrs, the translations, port_agnostic_services and dynamic_ports to PostgreSQL", zap.Error(err))
		} else {
			c.mu.Lock()
			c.cidrsSynced = true
			c.mu.Unlock()
		}
	}
	c.syncInventory(ctx)
	c.syncNodeStates(ctx)
	at := c.now()
	var former time.Duration
	if c.cfg.PeerHosts {
		former = formerHolderWindow
	}
	rows, err := c.store.peers(ctx, c.cfg.IdleTTL, former)
	if err != nil {
		c.log.Warn("reading the names of peers from PostgreSQL", zap.Error(err))
		return true
	}
	c.resolver.load(rows, at)
	c.mu.Lock()
	written := c.written
	c.mu.Unlock()
	if !written.IsZero() {
		// The holders of addresses seen before the latest write are read
		// back from PostgreSQL now.
		c.resolver.forgetHeld(written)
	}
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
		if errors.Is(err, errDevelopmentSchema) {
			c.log.Error("the PostgreSQL schema cannot be used; writes wait until it is created again", zap.Error(err))
			return false
		}
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
			started := c.now()
			written := c.prepareSchemaOnly(wctx) && c.flush(wctx)
			cancel()
			if written {
				c.mu.Lock()
				c.written = started
				c.mu.Unlock()
			} else {
				c.boundPending()
			}
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
			for k, t := range c.inventoryWarned {
				if now.Sub(t) >= foldWarnInterval {
					delete(c.inventoryWarned, k)
				}
			}
			c.mu.Unlock()
			c.resolver.expire(now.Add(-c.cfg.IdleTTL), now)
			c.limits.expire(now)
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
	c.checkPortRules(rctx)
	if _, err := c.store.refreshDependencies(rctx); err != nil {
		c.log.Error("updating the history of dependencies", zap.Error(err))
		return
	}
	c.lastRefresh = c.now()
}

// checkPortRules logs, at most once an hour, that the rules of ports in
// PostgreSQL are not those of this connector: another connector with
// other port_agnostic_services or dynamic_ports wrote them since, e.g.
// during a rolling update of the configuration. PostgreSQL aggregates the
// dependencies by its rules, and the outputs of this connector by its own,
// so the two disagree until every connector has the same configuration.
func (c *shawkConnector) checkPortRules(ctx context.Context) {
	if c.now().Sub(c.portRulesWarned) < foldWarnInterval {
		return
	}
	got, err := c.store.portRuleKeys(ctx)
	if err != nil {
		c.log.Warn("reading the rules of ports from PostgreSQL", zap.Error(err))
		return
	}
	if want := c.ports.keys(); !slices.Equal(got, want) {
		c.log.Error("PostgreSQL has other port_agnostic_services or dynamic_ports than this connector, "+
			"written by a connector with another configuration; dependencies on them are aggregated differently "+
			"in PostgreSQL and in the outputs until every connector has the same configuration",
			zap.Strings("postgres", got), zap.Strings("connector", want))
		c.portRulesWarned = c.now()
	}
}

// flush writes the pending changes, one transaction per host. The changes
// of a host that fail to be written are kept for the next flush. It reports
// whether none failed.
func (c *shawkConnector) flush(ctx context.Context) bool {
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
	return failed == 0
}

// boundPending drops the changes of the hosts pending the longest beyond
// max_pending_rows, after they could not be written. As after changes that
// PostgreSQL rejects, the edges and listeners agents still send are written
// again, and the next session of such a host starts no earlier than the
// idle TTL of an agent before now: the time in between shows as not
// observed.
func (c *shawkConnector) boundPending() {
	c.mu.Lock()
	hosts, rows := c.changes.bound(c.cfg.MaxPendingRows, c.now())
	c.mu.Unlock()
	if hosts > 0 {
		c.log.Error("dropping the changes of hosts that could not be written to PostgreSQL, beyond max_pending_rows; "+
			"the hosts are not observed over them", zap.Int("hosts", hosts), zap.Int("rows", rows),
			zap.Int("max_pending_rows", c.cfg.MaxPendingRows))
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
	var refused, full error
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
		if err := c.checkIdentity(ctx, b); err != nil {
			c.refuse(b, err, now)
			refused = err
			continue
		}
		admitted, dropped := c.limits.admit(b, now)
		if !admitted {
			full = c.refuseHost(b, now)
			continue
		}
		if b.invalid > 0 {
			c.log.Warn("ignoring invalid data points", zap.String("host", b.hostname), zap.Int("count", b.invalid))
		}
		if b.agentDropped > 0 {
			c.droppedAgentMetrics(b, now)
		}
		c.resolver.learn(b, now)
		c.mu.Lock()
		c.foldedCIDRs(b, now)
		c.inventoryConflicts(b, now)
		c.changes.add(b, now)
		c.agg.add(b, func(id *edgeID) peer {
			p := c.resolver.peer(b.key, id, now)
			if p.foldedBy != "" {
				c.foldedAgentPeer(b, id, p, now)
			}
			return p
		}, now, out)
		inputs := c.agg.dropped
		c.agg.dropped = 0
		c.mu.Unlock()
		if dropped > 0 || inputs > 0 {
			c.dropSeries(b, dropped, inputs, now)
		}
	}
	if out.ResourceMetrics().Len() > 0 {
		if err := c.next.ConsumeMetrics(ctx, out); err != nil {
			c.downstreamError(err, now)
		}
	}
	if refused != nil {
		// The agent counts the failure (shawk.agent.export.failures) and
		// logs it, and its observation segment does not succeed.
		return consumererror.NewPermanent(fmt.Errorf("refusing the metrics of the host: %w", refused))
	}
	if full != nil {
		// Likewise; the host may be taken once hosts held expire, so the
		// error is not permanent.
		return full
	}
	return nil
}

// refuseHost logs a batch of a new host refused by max_hosts, at most once
// a minute, and returns the error for the agent.
func (c *shawkConnector) refuseHost(b *hostBatch, now time.Time) error {
	err := fmt.Errorf("refusing the metrics of a new host: the connector holds max_hosts (%d) hosts", c.cfg.MaxHosts)
	c.mu.Lock()
	c.hostsRefused++
	n := c.hostsRefused
	if !c.lastHostsLog.IsZero() && now.Sub(c.lastHostsLog) < time.Minute {
		c.mu.Unlock()
		return err
	}
	c.lastHostsLog, c.hostsRefused = now, 0
	c.mu.Unlock()
	c.log.Error("refusing the metrics of new hosts beyond max_hosts, until hosts held stop sending for idle_ttl",
		zap.String("host", b.hostname), zap.Int("refused", n), zap.Int("max_hosts", c.cfg.MaxHosts))
	return err
}

// dropSeries logs the series of a host dropped by max_series_per_host, and
// its input series dropped beyond maxValuesPerEdge times it, at most once a
// minute.
func (c *shawkConnector) dropSeries(b *hostBatch, series, inputs int, now time.Time) {
	c.mu.Lock()
	c.seriesDropped += series
	c.inputsDropped += inputs
	s, in := c.seriesDropped, c.inputsDropped
	if !c.lastSeriesLog.IsZero() && now.Sub(c.lastSeriesLog) < time.Minute {
		c.mu.Unlock()
		return
	}
	c.lastSeriesLog, c.seriesDropped, c.inputsDropped = now, 0, 0
	c.mu.Unlock()
	c.log.Error("dropping new series of hosts beyond max_series_per_host, until others stop for idle_ttl; "+
		"a host is not observed in the intervals in which its dependencies, listeners, translations or addresses are dropped",
		zap.String("host", b.hostname), zap.Int("series", s), zap.Int("metric_series", in),
		zap.Int("max_series_per_host", c.cfg.MaxSeriesPerHost))
}

// checkIdentity checks, with host_identity: certificate, that the client
// certificate of the request names the host of a batch.
func (c *shawkConnector) checkIdentity(ctx context.Context, b *hostBatch) error {
	if c.cfg.HostIdentity != hostIdentityCertificate {
		return nil
	}
	cert, err := clientCertificate(ctx)
	if err != nil {
		return err
	}
	return certifiedHost(cert, b.hostname)
}

// refuse logs a batch refused by host_identity, at most once a minute.
func (c *shawkConnector) refuse(b *hostBatch, err error, now time.Time) {
	c.mu.Lock()
	c.refused++
	n := c.refused
	if !c.lastRefusedLog.IsZero() && now.Sub(c.lastRefusedLog) < time.Minute {
		c.mu.Unlock()
		return
	}
	c.lastRefusedLog = now
	c.refused = 0
	c.mu.Unlock()
	c.log.Warn("refusing the metrics of a host that the client certificate does not name (host_identity)",
		zap.String("host", b.hostname), zap.Int("refused", n), zap.Error(err))
}

// droppedAgentMetrics logs the metrics and points of an agent that are not
// forwarded (see addAgentMetric), at most once a minute, with their number
// since the last time.
func (c *shawkConnector) droppedAgentMetrics(b *hostBatch, now time.Time) {
	c.mu.Lock()
	c.agentDropped += b.agentDropped
	n := c.agentDropped
	if !c.lastAgentDroppedLog.IsZero() && now.Sub(c.lastAgentDroppedLog) < time.Minute {
		c.mu.Unlock()
		return
	}
	c.lastAgentDroppedLog, c.agentDropped = now, 0
	c.mu.Unlock()
	c.log.Warn("dropping metrics or points of agents that the connector does not know, as of newer agents or forged ones; "+
		"they are not forwarded",
		zap.String("host", b.hostname), zap.String("metric", b.agentDroppedName), zap.Int("dropped", n))
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
	fields := []zap.Field{client, clientAddr, server, serverAddr, zap.Uint16("port", id.port),
		zap.String("transport", id.proto), zap.Int("hosts_folded", n)}
	if p.foldedVirtual.IsValid() {
		msg = "the agent of a client folds the virtual address of a translation to a server that runs an agent " +
			"into its external peers (-fold-external=all); add the virtual address to the internal peers of the client's agent (-internal-peers)"
		fields = append(fields, zap.String("virtual_address", p.foldedVirtual.String()))
	}
	c.log.Warn(msg, fields...)
}

// foldedCIDRs logs agents that fold peers in ranges of peer_cidrs: a
// folded peer has lost its address, so it is named ~external rather than
// after its range. A range of a whole network names the folded peers
// themselves, and is left out. Agents usually share their configuration,
// so what is folded, with the ranges folded, is logged at most once an hour,
// with a host that folds them. The ranges are those of peer_cidrs, so
// that agents do not make the warnings held grow. c.mu is held.
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
	k := fmt.Sprint(b.peerFold, folded)
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
