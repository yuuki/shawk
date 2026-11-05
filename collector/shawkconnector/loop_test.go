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
// connector one write interval at a time: once gated, its reads of the
// names of peers, which the loop makes once per interval after its write,
// wait until the test lets them through or ungates the store, or the loop
// stops. It records the calls of the loop, and fails a write whose context
// is canceled, as PostgreSQL does.
type loopStore struct {
	*fakeStore
	gated   atomic.Bool
	reached chan struct{}
	release chan struct{}
	stop    chan struct{}
	stopped sync.Once
	// holdWrite makes the next write wait as a gated read of the names of
	// peers does, and canceled tells that a call was canceled while it
	// waited.
	holdWrite atomic.Bool
	canceled  atomic.Bool
	// onWrite is called by every write.
	onWrite func()

	callsMu sync.Mutex
	calls   []storeCall
}

func newLoopStore() *loopStore {
	return &loopStore{fakeStore: &fakeStore{}, reached: make(chan struct{}), release: make(chan struct{}),
		stop: make(chan struct{})}
}

func (s *loopStore) record(ctx context.Context, name string) {
	call := storeCall{name: name}
	if d, ok := ctx.Deadline(); ok {
		call.deadline, call.left = d, time.Until(d)
	}
	s.callsMu.Lock()
	s.calls = append(s.calls, call)
	s.callsMu.Unlock()
}

// take returns the calls recorded since the last take.
func (s *loopStore) take() []storeCall {
	s.callsMu.Lock()
	defer s.callsMu.Unlock()
	calls := s.calls
	s.calls = nil
	return calls
}

func (s *loopStore) write(ctx context.Context, h *hostChanges) error {
	s.record(ctx, "write")
	if s.holdWrite.CompareAndSwap(true, false) {
		select {
		case s.reached <- struct{}{}:
			s.hold(ctx)
		case <-s.stop:
		}
	}
	if s.onWrite != nil {
		s.onWrite()
	}
	if errors.Is(ctx.Err(), context.Canceled) {
		return ctx.Err()
	}
	return s.fakeStore.write(ctx, h)
}

func (s *loopStore) peers(ctx context.Context, ttl, former time.Duration) (peerRows, error) {
	s.record(ctx, "peers")
	if s.gated.Load() {
		select {
		case s.reached <- struct{}{}:
			s.hold(ctx)
		case <-s.stop:
		}
	}
	return s.fakeStore.peers(ctx, ttl, former)
}

// hold waits until the test lets the loop through, or the loop stops: the
// deadline of ctx may pass meanwhile.
func (s *loopStore) hold(ctx context.Context) {
	done := ctx.Done()
	for {
		select {
		case <-s.release:
			return
		case <-s.stop:
			return
		case <-done:
			if errors.Is(ctx.Err(), context.Canceled) {
				s.canceled.Store(true)
				return
			}
			done = nil
		}
	}
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

// wait waits until the loop reads the names of peers, or writes with
// holdWrite, where it stays until step.
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

// loopConnector returns a started connector whose loop writes into st
// every interval, with a clock at t0 that the test sets. st is gated once
// the connector started.
func loopConnector(t *testing.T, st *loopStore, interval time.Duration, mod func(*Config)) (*shawkConnector,
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
	if err := c.Start(context.Background(), nil); err != nil {
		t.Fatal(err)
	}
	st.gated.Store(true)
	t.Cleanup(func() {
		st.ungate()
		c.Shutdown(context.Background())
	})
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
	st.onWrite = func() { clock.set(clock.now().Add(10 * time.Second)) }
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

// TestLoopExpiry: every write interval, after the rest, the loop forgets
// what expired as of then: the state of the hosts not seen for the idle
// TTL, the agents not seen within the alive window, and the warnings
// logged foldWarnInterval ago, except those of hosts whose agents folded
// hosts since.
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

// TestLoopShutdownInInterval: when the collector stops while the loop is in
// a write interval, writing or reading the names of peers, what the
// interval does is canceled, and then what is pending is written.
func TestLoopShutdownInInterval(t *testing.T) {
	for _, in := range []string{"write", "peers"} {
		t.Run(in, func(t *testing.T) {
			st := newLoopStore()
			c, sink, _ := loopConnector(t, st, time.Second, nil)
			if in == "write" {
				st.gated.Store(false)
				st.holdWrite.Store(true)
				consume(t, c, sink, loopAgent(t0))
				st.wait(t)
			} else {
				st.wait(t)
				consume(t, c, sink, loopAgent(t0))
			}
			done := make(chan error, 1)
			go func() { done <- c.Shutdown(context.Background()) }()
			select {
			case err := <-done:
				if err != nil {
					t.Fatal(err)
				}
			case <-time.After(5 * time.Second):
				st.ungate()
				<-done
				t.Fatalf("the %s is not canceled when the collector stops", in)
			}
			if !st.canceled.Load() || len(st.writes) != 1 {
				t.Errorf("canceled %v, %d writes; want canceled, 1", st.canceled.Load(), len(st.writes))
			}
		})
	}
}
