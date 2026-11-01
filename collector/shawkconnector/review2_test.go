package shawkconnector

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	"go.opentelemetry.io/collector/connector/connectortest"
	"go.opentelemetry.io/collector/consumer/consumertest"
	"go.opentelemetry.io/collector/pdata/pcommon"
	"go.opentelemetry.io/collector/pdata/pmetric"
)

// The tests in this file reproduce the findings of a second adversarial
// review and check their fixes.

// pointTimes returns the timestamps of the data points the sink received.
func pointTimes(sink *consumertest.MetricsSink) []pcommon.Timestamp {
	var out []pcommon.Timestamp
	for _, md := range sink.AllMetrics() {
		rms := md.ResourceMetrics()
		for i := range rms.Len() {
			sms := rms.At(i).ScopeMetrics()
			for j := range sms.Len() {
				ms := sms.At(j).Metrics()
				for k := range ms.Len() {
					m := ms.At(k)
					switch m.Type() {
					case pmetric.MetricTypeSum:
						for l := range m.Sum().DataPoints().Len() {
							out = append(out, m.Sum().DataPoints().At(l).Timestamp())
						}
					case pmetric.MetricTypeGauge:
						for l := range m.Gauge().DataPoints().Len() {
							out = append(out, m.Gauge().DataPoints().At(l).Timestamp())
						}
					case pmetric.MetricTypeHistogram:
						for l := range m.Histogram().DataPoints().Len() {
							out = append(out, m.Histogram().DataPoints().At(l).Timestamp())
						}
					}
				}
			}
		}
	}
	return out
}

// TestClockStepBack: after the clock of an agent went back, its host
// emitted nothing until the clock caught up, and increments were dropped;
// inputs that expired meanwhile were counted again in full.
func TestClockStepBack(t *testing.T) {
	c, _, sink, now := testConnector(t, nil)
	ahead := 9 * time.Hour
	start := t0.Add(-time.Hour).Add(ahead) // by the clock that is ahead
	req := func(v int64, skew time.Duration) []series {
		*now = now.Add(15 * time.Second)
		return consume(t, c, sink, tAgent{host: "app-01", addrs: []string{"10.0.0.11"}, time: now.Add(skew),
			edges: []tEdge{{role: "client", proto: "tcp", local: "10.0.0.11", peer: "1.1.1.1", port: 443,
				svc: "app", comm: "app", opened: v, start: start}}})
	}
	req(100, ahead) // a baseline: the series started before the connector
	if v := opened(t, req(110, ahead), "app", "~external", roleClient); v != 10 {
		t.Fatalf("before the step = %v", v)
	}
	// NTP steps the clock back by 9 hours.
	out := req(120, 0)
	if len(find(out, metricConnOpened, "app", "*", roleClient, "")) == 0 {
		t.Fatal("no outputs after the clock went back")
	}
	if v := opened(t, out, "app", "~external", roleClient); v != 10 {
		t.Errorf("the point after the step is a baseline: %v, want 10", v)
	}
	if v := opened(t, req(125, 0), "app", "~external", roleClient); v != 15 {
		t.Errorf("after the step = %v, want 15", v)
	}
	// Long after, nothing is counted twice.
	for range 80 {
		req(125, 0)
	}
	c.agg.expire(*now)
	if v := opened(t, req(126, 0), "app", "~external", roleClient); v != 16 {
		t.Errorf("20 minutes after the step = %v, want 16", v)
	}
}

// TestHostMovesToAnotherConnector: a connector that had run for longer than
// the series of a host routed to it counted their whole values as new.
func TestHostMovesToAnotherConnector(t *testing.T) {
	c, _, sink, now := testConnector(t, nil) // started an hour before t0
	*now = t0.Add(30 * time.Minute)
	edge := func(peer string, v int64, start time.Time) tEdge {
		return tEdge{role: "client", proto: "tcp", local: "10.0.0.11", peer: peer, port: 443,
			svc: "app", comm: "app", opened: v, start: start}
	}
	// The series to 1.1.1.1 started 20 minutes ago, after this connector,
	// and was counted by the connector the host was routed to before. The
	// series to 2.2.2.2 started in the last interval.
	out := consume(t, c, sink, tAgent{host: "app-01", addrs: []string{"10.0.0.11"}, time: *now,
		edges: []tEdge{edge("1.1.1.1", 6000, now.Add(-20*time.Minute)), edge("2.2.2.2", 3, now.Add(-15*time.Second))}})
	if v := opened(t, out, "app", "~external", roleClient); v != 3 {
		t.Errorf("first interval on this connector = %v, want 3", v)
	}
	*now = now.Add(15 * time.Second)
	out = consume(t, c, sink, tAgent{host: "app-01", addrs: []string{"10.0.0.11"}, time: *now,
		edges: []tEdge{edge("1.1.1.1", 6010, now.Add(-20*time.Minute-15*time.Second)), edge("2.2.2.2", 3, now.Add(-30*time.Second))}})
	if v := opened(t, out, "app", "~external", roleClient); v != 13 {
		t.Errorf("second interval = %v, want 13", v)
	}

	// The same holds for a host silent for longer than the TTL whose agent
	// kept its series.
	*now = now.Add(20 * time.Minute)
	c.agg.expire(*now)
	out = consume(t, c, sink, tAgent{host: "app-01", addrs: []string{"10.0.0.11"}, time: *now,
		edges: []tEdge{edge("1.1.1.1", 6500, now.Add(-40*time.Minute))}})
	if v := opened(t, out, "app", "~external", roleClient); v != 0 {
		t.Errorf("after the host was silent = %v, want a baseline", v)
	}
}

// TestDBSnapshotDuringOutage: agents learned from PostgreSQL aged with the
// clock while the database could not be read, so that their peers lost
// shawk.peer.agent and the recording rules counted them twice.
func TestDBSnapshotDuringOutage(t *testing.T) {
	c, _, _, now := testConnector(t, nil)
	seen := now.Add(-30 * time.Second)
	c.resolver.load(peerRows{agents: []agentAddrRow{{addr: addrOf("10.0.0.11"), host: "remote", seen: seen,
		agent: agentHost{seen: seen, udpTraced: true}}}}, *now)
	id := &edgeID{role: roleServer, proto: "tcp", local: addrOf("10.0.0.10"), peer: addrOf("10.0.0.11"), port: 5432}
	// The database stays down: nothing is loaded for 10 minutes.
	later := now.Add(10 * time.Minute)
	if p := c.resolver.peer("db-01", id, later); !p.agent {
		t.Errorf("an agent known from PostgreSQL expired while it could not be read: %+v", p)
	}
	// Once loaded again, a dead agent expires.
	c.resolver.load(peerRows{agents: []agentAddrRow{{addr: addrOf("10.0.0.11"), host: "remote", seen: seen,
		agent: agentHost{seen: seen, udpTraced: true}}}}, later)
	if p := c.resolver.peer("db-01", id, later); p.agent {
		t.Errorf("an agent silent for 10 minutes is alive: %+v", p)
	}
}

// TestPartialIntervalIsNotAlive: the addresses of a host whose final
// requests never arrive kept its agent alive for its peers, while it
// emitted nothing.
func TestPartialIntervalIsNotAlive(t *testing.T) {
	c, st, sink, now := testConnector(t, nil)
	for range 4 {
		*now = now.Add(15 * time.Second)
		consume(t, c, sink, tAgent{host: "app-01", addrs: []string{"10.0.0.11"}, time: *now, partial: true,
			edges: []tEdge{{role: "client", proto: "tcp", local: "10.0.0.11", peer: "1.1.1.1", port: 443,
				svc: "app", comm: "app", opened: 1}}})
	}
	id := &edgeID{role: roleServer, proto: "tcp", local: addrOf("10.0.0.10"), peer: addrOf("10.0.0.11"), port: 5432}
	if p := c.resolver.peer("db-01", id, *now); p.agent {
		t.Errorf("a host without complete intervals counts as traced: %+v", p)
	}
	c.flush(context.Background())
	for _, h := range st.writes {
		if len(h.addrs) != 0 || len(h.sessions) != 0 {
			t.Errorf("addresses or heartbeats written from partial requests: %+v", h)
		}
	}
}

// TestLostFinalGauge: the open connections of an interval whose last
// request was lost were added to those of the next interval under another
// peer name.
func TestLostFinalGauge(t *testing.T) {
	c, _, sink, now := testConnector(t, nil)
	edge := tEdge{role: "client", proto: "tcp", local: "10.0.0.11", peer: "10.0.0.10", port: 5432,
		svc: "app", comm: "app", opened: 1, count: 7}
	*now = now.Add(15 * time.Second)
	// The partial request arrives; the last one of the interval is lost.
	consume(t, c, sink, tAgent{host: "app-01", addrs: []string{"10.0.0.11"}, time: *now, partial: true, edges: []tEdge{edge}})
	// The peer is now known as db.
	c.resolver.load(peerRows{endpoints: []endpointRow{{key: endpointKey{addrOf("10.0.0.10"), 5432, "tcp"},
		endpoint: endpoint{host: "db-host", service: "db", exact: true}}}}, *now)
	*now = now.Add(15 * time.Second)
	out := consume(t, c, sink, tAgent{host: "app-01", addrs: []string{"10.0.0.11"}, time: *now, edges: []tEdge{edge}})
	total := 0.0
	for _, s := range find(out, metricConnCount, "app", "*", roleClient, "") {
		total += s.value
	}
	if total != 7 {
		t.Errorf("open connections = %v, want 7 (%v)", total, find(out, metricConnCount, "app", "*", roleClient, ""))
	}
}

// TestOutputsByConnectorClock: outputs carried the time of the agent; one
// host with a clock far off made Prometheus reject the batch of every host.
func TestOutputsByConnectorClock(t *testing.T) {
	c, _, sink, now := testConnector(t, nil)
	*now = now.Add(time.Minute)
	consume(t, c, sink, tAgent{host: "app-01", addrs: []string{"10.0.0.11"}, time: now.Add(20 * time.Minute),
		edges: []tEdge{{role: "client", proto: "tcp", local: "10.0.0.11", peer: "1.1.1.1", port: 443,
			svc: "app", comm: "app", opened: 1}}})
	times := pointTimes(sink)
	if len(times) == 0 {
		t.Fatal("no outputs")
	}
	for _, ts := range times {
		if !ts.AsTime().Equal(*now) {
			t.Errorf("an output at %v, want the time of the connector %v", ts.AsTime(), *now)
		}
	}
}

// TestDownstreamErrorNotReturned: an error of Prometheus was returned to
// the agent, which counted a failed export although PostgreSQL had the data.
func TestDownstreamErrorNotReturned(t *testing.T) {
	cfg := createDefaultConfig()
	cfg.Postgres.DSN = "postgres://unused"
	next := consumertest.NewErr(errors.New("prometheus is down"))
	c, err := newConnector(connectortest.NewNopSettings(Type), cfg, next)
	if err != nil {
		t.Fatal(err)
	}
	c.newStore = func(context.Context, string) (store, error) { return &fakeStore{}, nil }
	if err := c.Start(context.Background(), nil); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Shutdown(context.Background()) })
	md := tAgent{host: "app-01", time: time.Now(), edges: []tEdge{{role: "client", proto: "tcp", local: "10.0.0.11",
		peer: "1.1.1.1", port: 443, svc: "app", comm: "app", opened: 1}}}.metrics()
	if err := c.ConsumeMetrics(context.Background(), md); err != nil {
		t.Errorf("ConsumeMetrics returned the error of the next consumer: %v", err)
	}
}

// TestDataErrorForgetsAcceptedSpans: after changes were dropped, an idle
// edge was never written again, and the session hid the loss.
func TestDataErrorForgetsAcceptedSpans(t *testing.T) {
	c, st, sink, now := testConnector(t, nil)
	edge := tEdge{role: "client", proto: "tcp", local: "10.0.0.11", peer: "10.0.0.10", port: 5432,
		svc: "app", comm: "app", opened: 1, last: t0}
	ta := tAgent{host: "app-01", addrs: []string{"10.0.0.11"}, time: *now, segment: t0.Add(-time.Hour), edges: []tEdge{edge}}
	consume(t, c, sink, ta)
	c.flush(context.Background())
	first := st.writes[0]
	var session time.Time
	for s := range first.sessions {
		session = s
	}

	st.err = &pgconn.PgError{Code: "22021"}
	*now = now.Add(15 * time.Second)
	ta.time = *now
	ta.edges[0].last = *now
	consume(t, c, sink, ta)
	c.flush(context.Background()) // dropped
	st.err = nil

	// The edge is idle since; it is still sent and written again.
	*now = now.Add(15 * time.Second)
	ta.time = *now
	consume(t, c, sink, ta)
	c.flush(context.Background())
	h := st.writes[len(st.writes)-1]
	if len(h.edges) != 1 {
		t.Errorf("the idle edge was not written again: %+v", h.edges)
	}
	for s := range h.sessions {
		if !s.After(session) {
			t.Errorf("the session continues over the dropped changes: %v, then %v", session, s)
		}
	}
}

// TestUnknownListenerNotLearned: the connector named peers after a listener
// without a known owner (~unknown), which PostgreSQL does not keep, so that
// names differed between connectors and restarts.
func TestUnknownListenerNotLearned(t *testing.T) {
	c, _, sink, now := testConnector(t, nil)
	consume(t, c, sink, tAgent{host: "nfs-01", addrs: []string{"10.0.0.30"}, time: *now,
		listeners: []tListener{{proto: "tcp", addr: "0.0.0.0", port: 2049, svc: unknownService}}})
	p := c.resolver.peer("app-01", &edgeID{role: roleClient, proto: "tcp", local: addrOf("10.0.0.11"),
		peer: addrOf("10.0.0.30"), port: 2049}, *now)
	if p.name != peerUnresolved {
		t.Errorf("peer = %+v, want %s", p, peerUnresolved)
	}
}

// TestSchemaVersionChecked: a connector that does not migrate wrote to a
// schema older than it needs, and failed for good.
func TestSchemaVersionChecked(t *testing.T) {
	cfg := createDefaultConfig()
	cfg.Postgres.DSN = "postgres://unused"
	st := &fakeStore{version: SchemaVersion() - 1}
	c, err := newConnector(connectortest.NewNopSettings(Type), cfg, new(consumertest.MetricsSink))
	if err != nil {
		t.Fatal(err)
	}
	c.newStore = func(context.Context, string) (store, error) { return st, nil }
	if err := c.Start(context.Background(), nil); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Shutdown(context.Background()) })
	if c.prepareSchemaOnly(context.Background()) {
		t.Error("writes proceed on an older schema")
	}
	st.mu.Lock()
	st.version = SchemaVersion()
	st.mu.Unlock()
	if !c.prepare(context.Background()) {
		t.Error("writes wait on a current schema")
	}
}

// TestPeerCIDRsSynced: PostgreSQL names peers without a service like the
// connector, from the peer_cidrs the connector writes.
func TestPeerCIDRsSynced(t *testing.T) {
	_, st, _, _ := testConnector(t, func(cfg *Config) { cfg.PeerCIDRs = map[string]string{"office-lan": "192.168.10.0/24"} })
	st.mu.Lock()
	defer st.mu.Unlock()
	if len(st.cidrs) != 1 || st.cidrs[0].name != "office-lan" {
		t.Errorf("peer_cidrs written: %+v", st.cidrs)
	}
}

func TestWriteIntervalBound(t *testing.T) {
	cfg := createDefaultConfig()
	cfg.Postgres.DSN = "postgres://x"
	cfg.WriteInterval = 2 * time.Minute
	if err := cfg.Validate(); err == nil {
		t.Error("a write_interval beyond the alive window of agents was accepted")
	}
}
