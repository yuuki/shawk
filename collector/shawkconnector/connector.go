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

	mu       sync.Mutex
	agg      *aggregator
	changes  *changes
	migrated bool

	lastPrune time.Time

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
		migrated: !cfg.Postgres.Migrate,
		now:      time.Now,
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

// prepare migrates the schema if configured to and reloads the names of
// peers. It reports whether the schema is ready.
func (c *shawkConnector) prepare(ctx context.Context) bool {
	c.mu.Lock()
	migrated := c.migrated
	c.mu.Unlock()
	if !migrated {
		applied, err := c.store.migrate(ctx)
		if err != nil {
			c.log.Error("migrating the PostgreSQL schema; writes wait until it succeeds", zap.Error(err))
			return false
		}
		if len(applied) > 0 {
			c.log.Info("migrated the PostgreSQL schema", zap.Strings("applied", applied))
		}
		c.mu.Lock()
		c.migrated = true
		c.mu.Unlock()
	}
	rows, err := c.store.peers(ctx)
	if err != nil {
		c.log.Warn("reading the names of peers from PostgreSQL", zap.Error(err))
		return true
	}
	c.resolver.load(rows)
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
			now := c.now()
			c.mu.Lock()
			c.agg.expire(now)
			c.changes.expire(now)
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
	migrated := c.migrated
	c.mu.Unlock()
	if !migrated {
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

// prepareSchemaOnly migrates the schema if that is still pending, without
// reloading peers, and reports whether writes may proceed.
func (c *shawkConnector) prepareSchemaOnly(ctx context.Context) bool {
	c.mu.Lock()
	migrated := c.migrated
	c.mu.Unlock()
	if migrated {
		return true
	}
	return c.prepare(ctx)
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
func (c *shawkConnector) ConsumeMetrics(ctx context.Context, md pmetric.Metrics) error {
	out := pmetric.NewMetrics()
	now := c.now()
	rms := md.ResourceMetrics()
	var errs []error
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
		c.changes.add(b, now)
		c.agg.add(b, func(id *edgeID) peer { return c.resolver.peer(b.key, id, now) }, now, out)
		c.mu.Unlock()
	}
	if out.ResourceMetrics().Len() > 0 {
		if err := c.next.ConsumeMetrics(ctx, out); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
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
