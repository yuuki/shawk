package shawkconnector

import (
	"context"
	"errors"
	"slices"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"go.opentelemetry.io/collector/connector/connectortest"
	"go.opentelemetry.io/collector/consumer/consumertest"
)

// testClock is a clock that a test sets while the loop of a connector
// reads it.
type testClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *testClock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *testClock) set(t time.Time) {
	c.mu.Lock()
	c.t = t
	c.mu.Unlock()
}

// storeCall is a call of a loopStore, with the deadline of its context.
type storeCall struct {
	name     string
	deadline time.Time // zero without one
	// left is how long the context had left at the call.
	left time.Duration
}

// loopStore is a fakeStore through which a test runs the loop of the
// connector one write interval at a time: its reads of the names of peers,
// which the loop makes once per interval after its write, wait until the
// test lets them through or ungates the store. The first, of Start, does
// not wait, so that the loop waits in its first interval. It records the
// calls of the loop, and fails a write whose context is canceled, as
// PostgreSQL does.
type loopStore struct {
	*fakeStore
	reads   atomic.Int64
	reached chan struct{}
	release chan struct{}
	stop    chan struct{}
	stopped sync.Once
	// onCall is called by every call, after it is recorded.
	onCall func(name string)

	callsMu sync.Mutex
	calls   []storeCall

	// stopIn is the call ("write" or "peers") in which the next interval
	// stops the connector with stopLoop, see stopping. inStop is closed
	// once it has, and canceled tells whether that canceled the context of
	// the call.
	stopMu   sync.Mutex
	stopIn   string
	stopLoop func()
	inStop   chan struct{}
	canceled atomic.Bool
}

func newLoopStore() *loopStore {
	return &loopStore{fakeStore: &fakeStore{}, reached: make(chan struct{}), release: make(chan struct{}),
		stop: make(chan struct{}), inStop: make(chan struct{})}
}

func (s *loopStore) record(ctx context.Context, name string) {
	call := storeCall{name: name}
	if d, ok := ctx.Deadline(); ok {
		call.deadline, call.left = d, time.Until(d)
	}
	s.callsMu.Lock()
	s.calls = append(s.calls, call)
	s.callsMu.Unlock()
	if s.onCall != nil {
		s.onCall(name)
	}
}

// take returns the calls recorded since the last take.
func (s *loopStore) take() []storeCall {
	s.callsMu.Lock()
	defer s.callsMu.Unlock()
	calls := s.calls
	s.calls = nil
	return calls
}

// stopAt makes the next interval stop the connector with stop from within
// the call named in, "write" or "peers".
func (s *loopStore) stopAt(in string, stop func()) {
	s.stopMu.Lock()
	s.stopIn, s.stopLoop = in, stop
	s.stopMu.Unlock()
}

// stopping stops the connector from within the call name, if it is the
// one of stopAt, and records whether that canceled the context of the
// call: canceling a context cancels those derived from it before it
// returns. A call whose deadline passed already, which would hide the
// cancellation, fails instead, so that the next interval tries again.
func (s *loopStore) stopping(ctx context.Context, name string) error {
	s.stopMu.Lock()
	defer s.stopMu.Unlock()
	if s.stopIn != name {
		return nil
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	s.stopIn = ""
	s.stopLoop()
	s.canceled.Store(errors.Is(ctx.Err(), context.Canceled))
	close(s.inStop)
	return nil
}

func (s *loopStore) write(ctx context.Context, h *hostChanges) error {
	s.record(ctx, "write")
	if err := s.stopping(ctx, "write"); err != nil {
		return err
	}
	if errors.Is(ctx.Err(), context.Canceled) {
		return ctx.Err()
	}
	return s.fakeStore.write(ctx, h)
}

func (s *loopStore) peers(ctx context.Context, ttl, former time.Duration) (peerRows, error) {
	s.record(ctx, "peers")
	if err := s.stopping(ctx, "peers"); err != nil {
		return peerRows{}, err
	}
	if s.reads.Add(1) > 1 {
		select {
		case s.reached <- struct{}{}:
			select {
			case <-s.release:
			case <-s.stop:
			}
		case <-s.stop:
		}
	}
	return s.fakeStore.peers(ctx, ttl, former)
}

func (s *loopStore) prune(ctx context.Context, retention time.Duration, batch int) (int64, error) {
	s.record(ctx, "prune")
	return s.fakeStore.prune(ctx, retention, batch)
}

func (s *loopStore) portRuleKeys(ctx context.Context) ([]string, error) {
	s.record(ctx, "portRuleKeys")
	return s.fakeStore.portRuleKeys(ctx)
}

func (s *loopStore) refreshDependencies(ctx context.Context) (int64, error) {
	s.record(ctx, "refreshDependencies")
	return s.fakeStore.refreshDependencies(ctx)
}

// wait waits until the loop reads the names of peers, where it stays until
// step.
func (s *loopStore) wait(t *testing.T) {
	t.Helper()
	select {
	case <-s.reached:
	case <-time.After(10 * time.Second):
		t.Fatal("the loop does not read the names of peers")
	}
}

// step lets the loop finish its interval, and waits until it reads the
// names of peers in the next one, after writing.
func (s *loopStore) step(t *testing.T) {
	t.Helper()
	select {
	case s.release <- struct{}{}:
	case <-time.After(10 * time.Second):
		t.Fatal("the loop does not wait for the test")
	}
	s.wait(t)
}

// ungate lets the loop run freely, as it must to stop.
func (s *loopStore) ungate() { s.stopped.Do(func() { close(s.stop) }) }

// newLoopConnector returns a connector, not started, whose loop writes into
// st every interval, with a clock at t0 that the test sets.
func newLoopConnector(t *testing.T, st *loopStore, interval time.Duration, mod func(*Config)) (*shawkConnector,
	*consumertest.MetricsSink, *testClock) {
	t.Helper()
	cfg := createDefaultConfig()
	cfg.Postgres.DSN = "postgres://unused"
	if mod != nil {
		mod(cfg)
	}
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	cfg.WriteInterval = interval
	sink := new(consumertest.MetricsSink)
	c, err := newConnector(connectortest.NewNopSettings(Type), cfg, sink)
	if err != nil {
		t.Fatal(err)
	}
	c.newStore = func(context.Context, string) (store, error) { return st, nil }
	clock := &testClock{t: t0}
	c.now = clock.now
	c.agg.started = t0.Add(-time.Hour)
	return c, sink, clock
}

// startLoop starts a connector of newLoopConnector, and stops it when the
// test ends.
func startLoop(t *testing.T, c *shawkConnector, st *loopStore) {
	t.Helper()
	if err := c.Start(context.Background(), nil); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		st.ungate()
		c.Shutdown(context.Background())
	})
}

// loopConnector returns a connector of newLoopConnector, started.
func loopConnector(t *testing.T, st *loopStore, interval time.Duration, mod func(*Config)) (*shawkConnector,
	*consumertest.MetricsSink, *testClock) {
	t.Helper()
	c, sink, clock := newLoopConnector(t, st, interval, mod)
	startLoop(t, c, st)
	return c, sink, clock
}

// loopAgent is a request of app-01 at a time, which closes an interval.
func loopAgent(at time.Time) tAgent {
	return tAgent{host: "app-01", addrs: []string{"10.0.0.11"}, time: at,
		edges: []tEdge{{role: roleClient, proto: "tcp", local: "10.0.0.11", peer: "10.0.0.10", port: 5432, svc: "app",
			comm: "app", opened: 1}},
		listeners: []tListener{{proto: "tcp", addr: "10.0.0.11", port: 80, svc: "web", comm: "web"}}}
}

const loopInterval = 20 * time.Millisecond

// TestLoopInterval: every write interval, the loop writes the pending
// changes, then reads the names of peers, then prunes and refreshes the
// history of dependencies when they are due. The write and the read have
// deadlines of their own, of a write interval each. What was seen before
// the write started is written, however long it takes.
func TestLoopInterval(t *testing.T) {
	st := newLoopStore()
	c, sink, clock := loopConnector(t, st, loopInterval, func(cfg *Config) { cfg.Retention = 24 * time.Hour })
	st.wait(t)
	st.step(t) // prunes and refreshes at t0
	st.take()

	at := t0.Add(2 * time.Hour)
	clock.set(at)
	consume(t, c, sink, loopAgent(at))
	st.onCall = func(name string) {
		if name == "write" {
			clock.set(clock.now().Add(10 * time.Second))
		}
	}
	st.step(t)
	calls := st.take()
	var names []string
	for _, call := range calls {
		names = append(names, call.name)
	}
	if want := []string{"prune", "portRuleKeys", "refreshDependencies", "write", "peers"}; !slices.Equal(names, want) {
		t.Fatalf("calls = %v, want %v", names, want)
	}
	write, peers := calls[3], calls[4]
	if write.deadline.IsZero() || write.left > loopInterval || !peers.deadline.After(write.deadline) ||
		peers.left > loopInterval {
		t.Errorf("deadlines: write %+v, peers %+v; want their own, within %v", write, peers, loopInterval)
	}
	c.mu.Lock()
	written := c.written
	c.mu.Unlock()
	st.mu.Lock()
	writes := len(st.writes)
	st.mu.Unlock()
	if writes != 1 || !written.Equal(at) {
		t.Errorf("%d writes, written as of %v; want 1, as of %v", writes, written, at)
	}

	// The names of peers are read again every interval.
	st.mu.Lock()
	st.rows = peerRows{agents: []agentAddrRow{{addr: addrOf("10.0.0.20"), host: "db-01", seen: at,
		agent: agentHost{seen: at, name: "db-01"}}}}
	st.mu.Unlock()
	st.step(t)
	c.resolver.mu.RLock()
	_, ok := c.resolver.dbAgents["db-01"]
	c.resolver.mu.RUnlock()
	if !ok {
		t.Error("the names of peers are not read again")
	}
}

// TestLoopWriteFailure: after a write that fails, the pending changes are
// bounded by max_pending_rows, and what was seen is not taken for written.
// After one that succeeds, what was seen before it started is, before the
// names of peers are read: with peer_hosts, the holders of addresses seen
// before are forgotten once read back.
func TestLoopWriteFailure(t *testing.T) {
	st := newLoopStore()
	c, sink, clock := loopConnector(t, st, loopInterval, func(cfg *Config) {
		cfg.PeerHosts = true
		cfg.MaxPendingRows = 1
	})
	st.wait(t) // written as of t0, with nothing pending
	check := func(step string, written time.Time, held int) {
		t.Helper()
		c.mu.Lock()
		gotPending, gotWritten := c.changes.pendingSize(), c.written
		c.mu.Unlock()
		c.resolver.mu.RLock()
		gotHeld := len(c.resolver.localHeld)
		c.resolver.mu.RUnlock()
		if gotPending != 0 || !gotWritten.Equal(written) || gotHeld != held {
			t.Errorf("%s: %d rows pending, written as of %v, %d addresses held; want 0, %v, %d",
				step, gotPending, gotWritten, gotHeld, written, held)
		}
	}
	at := func(d time.Duration) time.Time { return t0.Add(d * time.Second) }

	st.mu.Lock()
	st.fail = true
	st.mu.Unlock()
	clock.set(at(1))
	consume(t, c, sink, loopAgent(at(1)))
	clock.set(at(2))
	st.step(t)
	check("after a failure", t0, 1)

	st.mu.Lock()
	st.fail = false
	st.mu.Unlock()
	clock.set(at(3))
	consume(t, c, sink, loopAgent(at(3)))
	clock.set(at(4))
	st.step(t)
	check("after a write", at(4), 1)
	clock.set(at(5))
	st.step(t)
	check("read back", at(5), 0)
}

// TestLoopExpiry: every write interval, the loop forgets what expired: the
// state of the hosts not seen for the idle TTL, the agents not seen within
// the alive window, and the warnings logged at least foldWarnInterval
// before, except those of hosts whose agents folded hosts since.
func TestLoopExpiry(t *testing.T) {
	st := newLoopStore()
	c, sink, clock := loopConnector(t, st, loopInterval, nil)
	st.wait(t)
	consume(t, c, sink, loopAgent(t0))
	key := hostKey("", "app-01")
	held := func() (agent, state []bool) {
		c.mu.Lock()
		_, agg := c.agg.hosts[key]
		_, accepted := c.changes.acceptedEdges[key]
		c.mu.Unlock()
		c.limits.mu.Lock()
		_, limited := c.limits.hosts[key]
		c.limits.mu.Unlock()
		c.resolver.mu.RLock()
		_, alive := c.resolver.localAgents[key]
		_, addr := c.resolver.localAddrs[addrOf("10.0.0.11")]
		endpoints, clients := len(c.resolver.localEndpoints) == 1, len(c.resolver.localClients) == 1
		c.resolver.mu.RUnlock()
		return []bool{alive, addr}, []bool{agg, accepted, limited, endpoints, clients}
	}

	expired := t0.Add(aliveWindow)
	logged := expired.Add(-foldWarnInterval)
	c.mu.Lock()
	c.foldWarned[foldWarnKey{host: "logged"}] = &foldWarning{logged: logged, hosts: map[string]bool{}}
	c.foldWarned[foldWarnKey{host: "recent"}] = &foldWarning{logged: logged.Add(time.Nanosecond), hosts: map[string]bool{}}
	c.foldWarned[foldWarnKey{host: "folding", servers: true}] = &foldWarning{logged: logged.Add(-time.Hour),
		hosts: map[string]bool{"app-02": true}}
	c.cidrWarned["logged"], c.cidrWarned["recent"] = logged, logged.Add(time.Nanosecond)
	c.inventoryWarned["logged"], c.inventoryWarned["recent"] = logged, logged.Add(time.Nanosecond)
	c.mu.Unlock()

	for _, step := range []struct {
		name         string
		at           time.Time
		agent, state bool
	}{
		{"within the alive window", t0.Add(aliveWindow), true, true},
		{"after the alive window", t0.Add(aliveWindow + time.Nanosecond), false, true},
		{"within the idle TTL", t0.Add(c.cfg.IdleTTL), false, true},
		{"after the idle TTL", t0.Add(c.cfg.IdleTTL + time.Nanosecond), false, false},
	} {
		clock.set(step.at)
		st.step(t)
		agent, state := held()
		for _, v := range agent {
			if v != step.agent {
				t.Errorf("%s: agent and address held %v, want %v", step.name, agent, step.agent)
				break
			}
		}
		for _, v := range state {
			if v != step.state {
				t.Errorf("%s: outputs, accepted, limits, endpoints, clients held %v, want %v", step.name, state, step.state)
				break
			}
		}
		if step.at.Equal(expired) {
			c.mu.Lock()
			var fold []string
			for k := range c.foldWarned {
				fold = append(fold, k.host)
			}
			_, cidr := c.cidrWarned["logged"]
			_, inv := c.inventoryWarned["logged"]
			n := len(c.cidrWarned) + len(c.inventoryWarned)
			c.mu.Unlock()
			slices.Sort(fold)
			if !slices.Equal(fold, []string{"folding", "recent"}) || cidr || inv || n != 2 {
				t.Errorf("warnings held: folds %v, peer_cidrs %v, inventory %v", fold, c.cidrWarned, c.inventoryWarned)
			}
		}
	}
}

// TestLoopShutdown: when the collector stops, the loop writes what is
// pending, with a deadline of its own, unless the schema is older than the
// connector.
func TestLoopShutdown(t *testing.T) {
	st := newLoopStore()
	c, sink, _ := loopConnector(t, st, time.Hour, nil)
	consume(t, c, sink, loopAgent(t0))
	st.take()
	st.ungate()
	if err := c.Shutdown(context.Background()); err != nil {
		t.Fatal(err)
	}
	calls := st.take()
	if len(st.writes) != 1 || len(calls) != 1 || calls[0].deadline.IsZero() || calls[0].left > 10*time.Second ||
		calls[0].left <= time.Second {
		t.Errorf("%d writes, calls %+v; want one with a deadline of 10s", len(st.writes), calls)
	}

	st = newLoopStore()
	st.behind = 1
	c, sink, _ = loopConnector(t, st, time.Hour, nil)
	consume(t, c, sink, loopAgent(t0))
	st.ungate()
	c.Shutdown(context.Background())
	if len(st.writes) != 0 {
		t.Errorf("%d writes into an older schema", len(st.writes))
	}
}

// TestLoopExpiresLast: the loop forgets what expired at the end of a write
// interval, as of then: after it wrote what is pending and read the names
// of peers, whatever expired before, and after it pruned and refreshed,
// however long they take.
func TestLoopExpiresLast(t *testing.T) {
	st := newLoopStore()
	c, sink, clock := newLoopConnector(t, st, loopInterval, func(cfg *Config) { cfg.Retention = 24 * time.Hour })
	ttl := c.cfg.IdleTTL
	held := func(host string) bool {
		c.limits.mu.Lock()
		defer c.limits.mu.Unlock()
		_, ok := c.limits.hosts[hostKey("", host)]
		return ok
	}
	// app-01, seen at t0, has expired by the first interval.
	consume(t, c, sink, loopAgent(t0))
	clock.set(t0.Add(ttl + time.Nanosecond))
	startLoop(t, c, st)
	st.wait(t)
	st.mu.Lock()
	writes := len(st.writes)
	st.mu.Unlock()
	if !held("app-01") || writes != 1 {
		t.Errorf("reading the names of peers: app-01 held %v, %d writes; want held, written once", held("app-01"), writes)
	}

	// app-02 is seen now, and expires a nanosecond after the two minutes
	// that pruning and refreshing take.
	at := clock.now()
	ta := loopAgent(at)
	ta.host = "app-02"
	consume(t, c, sink, ta)
	clock.set(at.Add(ttl - 2*time.Minute + time.Nanosecond))
	st.onCall = func(name string) {
		if name == "prune" || name == "refreshDependencies" {
			clock.set(clock.now().Add(time.Minute))
		}
	}
	st.step(t)
	if held("app-01") || held("app-02") {
		t.Errorf("after the interval: app-01 held %v, app-02 held %v; want neither", held("app-01"), held("app-02"))
	}
}

// TestLoopShutdownInInterval: when the collector stops while the loop is in
// a write interval, writing or reading the names of peers, what the
// interval does is canceled, and then what is pending is written. The
// connector is stopped from within the call, so that its deadline cannot
// pass first.
func TestLoopShutdownInInterval(t *testing.T) {
	for _, in := range []string{"write", "peers"} {
		t.Run(in, func(t *testing.T) {
			st := newLoopStore()
			c, sink, _ := loopConnector(t, st, loopInterval, nil)
			st.ungate()
			var consumed error
			if in == "write" {
				st.stopAt(in, c.cancel)
				consume(t, c, sink, loopAgent(t0))
			} else {
				// A request arrives while the names of peers are read.
				st.stopAt(in, func() {
					consumed = c.ConsumeMetrics(context.Background(), loopAgent(t0).metrics())
					c.cancel()
				})
			}
			select {
			case <-st.inStop:
			case <-time.After(10 * time.Second):
				t.Fatalf("no %s to stop the connector in", in)
			}
			if err := c.Shutdown(context.Background()); err != nil {
				t.Fatal(err)
			}
			if consumed != nil {
				t.Fatal(consumed)
			}
			if !st.canceled.Load() || len(st.writes) != 1 {
				t.Errorf("the %s canceled %v, %d writes; want canceled, 1", in, st.canceled.Load(), len(st.writes))
			}
		})
	}
}
