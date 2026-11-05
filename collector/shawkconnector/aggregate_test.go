package shawkconnector

import (
	"fmt"
	"maps"
	"testing"
	"time"

	"go.opentelemetry.io/collector/pdata/pmetric"
)

// TestLateAndDuplicateRequests: a request processed after a newer one, or
// twice, adds nothing; it is not taken for a counter reset.
func TestLateAndDuplicateRequests(t *testing.T) {
	c, _, sink, now := testConnector(t, nil)
	req := func(at time.Time, v int64) tAgent {
		return tAgent{host: "app-01", addrs: []string{"10.0.0.11"}, time: at,
			edges: []tEdge{{role: "client", proto: "tcp", local: "10.0.0.11", peer: "1.1.1.1", port: 443,
				svc: "app", comm: "app", opened: v, start: t0}}}
	}
	at := func(i int) time.Time { return t0.Add(time.Duration(i) * 15 * time.Second) }
	*now = at(4)
	if v := opened(t, consume(t, c, sink, req(at(1), 1000)), "app", "~external", roleClient); v != 1000 {
		t.Fatalf("first = %v", v)
	}
	consume(t, c, sink, req(at(2), 1020))
	// The request of interval 3 is processed after that of interval 4.
	out := consume(t, c, sink, req(at(4), 1030))
	if v := opened(t, out, "app", "~external", roleClient); v != 1030 {
		t.Errorf("after interval 4 = %v, want 1030", v)
	}
	if out := consume(t, c, sink, req(at(3), 1025)); len(find(out, metricConnOpened, "app", "*", roleClient, "")) != 0 {
		t.Error("a late request emitted outputs at an older time")
	}
	// A retry of an earlier request.
	consume(t, c, sink, req(at(2), 1020))
	if v := opened(t, consume(t, c, sink, req(at(5), 1040)), "app", "~external", roleClient); v != 1040 {
		t.Errorf("after a late and a duplicate request = %v, want 1040", v)
	}
}

// TestRetriedFinalRequest: a request that closes an interval and arrives
// again with the same time, as an agent retries it, emits nothing again.
func TestRetriedFinalRequest(t *testing.T) {
	c, _, sink, now := testConnector(t, nil)
	*now = t0.Add(15 * time.Second)
	req := tAgent{host: "app-01", addrs: []string{"10.0.0.11"}, time: *now,
		edges: []tEdge{{role: "client", proto: "tcp", local: "10.0.0.11", peer: "1.1.1.1", port: 443,
			svc: "app", comm: "app", opened: 3, start: t0}}}
	if v := opened(t, consume(t, c, sink, req), "app", "~external", roleClient); v != 3 {
		t.Fatalf("first = %v", v)
	}
	if out := consume(t, c, sink, req); len(out) != 0 {
		t.Errorf("the retried request emitted %v", out)
	}
}

// TestSplitInterval: an agent with many edges sends an interval in several
// requests; the outputs are emitted once, when the last one arrives.
func TestSplitInterval(t *testing.T) {
	c, _, sink, _ := testConnector(t, nil)
	edge := func(peer string, opened, open int64) tEdge {
		return tEdge{role: "client", proto: "tcp", local: "10.0.0.11", peer: peer, port: 443, svc: "app", comm: "app",
			opened: opened, count: open, start: t0}
	}
	interval := func(i int, a, b tEdge) []series {
		at := t0.Add(time.Duration(i) * 15 * time.Second)
		first := consume(t, c, sink, tAgent{host: "app-01", time: at, partial: true, edges: []tEdge{a}})
		if len(first) != 0 {
			t.Errorf("interval %d: a partial request emitted %v", i, first)
		}
		return consume(t, c, sink, tAgent{host: "app-01", time: at, edges: []tEdge{b}})
	}
	out := interval(1, edge("1.1.1.1", 5, 2), edge("2.2.2.2", 7, 3))
	if v := opened(t, out, "app", "~external", roleClient); v != 12 {
		t.Errorf("opened = %v, want 12", v)
	}
	// The open connections of both requests add up, and are not reset by
	// the second request of the interval.
	if s := find(out, metricConnCount, "app", "~external", roleClient, ""); len(s) != 1 || s[0].value != 5 {
		t.Errorf("open connections = %v, want 5", s)
	}
	out = interval(2, edge("1.1.1.1", 6, 0), edge("2.2.2.2", 7, 1))
	if s := find(out, metricConnCount, "app", "~external", roleClient, ""); len(s) != 1 || s[0].value != 1 {
		t.Errorf("open connections = %v, want 1", s)
	}
	if v := opened(t, out, "app", "~external", roleClient); v != 13 {
		t.Errorf("opened = %v, want 13", v)
	}
}

// TestBaselineWithClockSkew: the start of an input series, by the clock of
// the agent, is converted with the clock skew of the agent before it is
// compared with the start of the connector, so that a series that started
// after the connector is counted rather than taken as a baseline.
func TestBaselineWithClockSkew(t *testing.T) {
	c, _, sink, now := testConnector(t, nil)
	c.agg.started = t0
	*now = t0.Add(2 * time.Minute)
	// The clock of the agent is 10 minutes behind: its series started a
	// minute after the connector, at t0+1m by the connector's clock.
	skew := -10 * time.Minute
	out := consume(t, c, sink, tAgent{host: "app-01", time: now.Add(skew),
		edges: []tEdge{{role: "client", proto: "tcp", local: "10.0.0.11", peer: "1.1.1.1", port: 443,
			svc: "app", comm: "app", opened: 7, start: t0.Add(time.Minute + skew)}}})
	if v := opened(t, out, "app", "~external", roleClient); v != 7 {
		t.Errorf("a series that started after the connector was taken as a baseline: %v", v)
	}
}

// TestClockStepBack: after the clock of an agent steps back, its host keeps
// emitting outputs: the first point after the step is a baseline, the
// increments after it are counted, and inputs that expire meanwhile are not
// counted again in full.
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

// TestHostMovesToAnotherConnector: a connector that runs for longer than the
// series of a host routed to it takes the values of series that started
// before the host reached it as a baseline rather than counting them as new;
// a series that started in the last interval is counted in full.
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

// TestLostFinalGauge: the open connections of an interval whose last
// request is lost are not added to those of the next interval under another
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

// TestOutputsByConnectorClock: outputs carry the time of the connector, so
// that one host with a clock far off does not make Prometheus reject the
// batch of every host.
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

// testBatch decodes the request of an agent.
func testBatch(t *testing.T, ta tAgent) *hostBatch {
	t.Helper()
	b, err := parseResource(ta.metrics().ResourceMetrics().At(0))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// TestRequestWithoutTime: a request without a time of the agent is taken as
// of its receipt, so that the start of its series stays the time of the
// agent. A value of a metric that has no output is left out.
func TestRequestWithoutTime(t *testing.T) {
	a := newAggregator(15*time.Minute, 50, 200, false, t0.Add(-time.Hour))
	b := testBatch(t, tAgent{host: "app-01", time: t0, edges: []tEdge{{role: "client", proto: "tcp",
		local: "10.0.0.11", peer: "10.0.0.10", port: 5432, svc: "app", comm: "app", opened: 3}}})
	b.time = time.Time{}
	for _, e := range b.edges {
		e.values[valueKey{metric: metricEdgeFirst}] = point{value: 1}
	}
	now := t0.Add(15 * time.Second)
	out := pmetric.NewMetrics()
	a.add(b, func(*edgeID) peer { return peer{name: "postgres"} }, now, out)
	h := a.hosts[b.key]
	if !h.latest.Equal(now) || !h.emitted.Equal(now) {
		t.Errorf("latest %v, emitted %v, want %v", h.latest, h.emitted, now)
	}
	for k := range h.inputs {
		if k.value.metric == metricEdgeFirst {
			t.Errorf("input %v of a metric without output", k.value)
		}
	}
	var starts []time.Time
	rms := out.ResourceMetrics()
	for i := range rms.Len() {
		ms := rms.At(i).ScopeMetrics().At(0).Metrics()
		for j := range ms.Len() {
			if m := ms.At(j); m.Name() == metricConnOpened {
				for k := range m.Sum().DataPoints().Len() {
					dp := m.Sum().DataPoints().At(k)
					starts = append(starts, dp.StartTimestamp().AsTime())
					if dp.IntValue() != 3 {
						t.Errorf("connections opened = %d, want 3", dp.IntValue())
					}
				}
			}
		}
	}
	if len(starts) != 1 || !starts[0].Equal(t0) {
		t.Errorf("starts of connection.opened = %v, want [%v]", starts, t0)
	}
}

// TestPeerHostOfOutputs: the outputs per peer host name a peer on the host
// itself after the host, and a peer whose host is not known ~unknown.
func TestPeerHostOfOutputs(t *testing.T) {
	a := newAggregator(15*time.Minute, 50, 200, false, t0.Add(-time.Hour))
	a.setPeerHosts(10, nil)
	edge := func(peer string) tEdge {
		return tEdge{role: "client", proto: "tcp", local: "10.0.0.11", peer: peer, port: 5432, svc: "app", comm: "app", opened: 1}
	}
	b := testBatch(t, tAgent{host: "app-01", time: t0, edges: []tEdge{edge("10.0.0.10"), edge("10.0.0.11"), edge("10.0.0.12")}})
	out := pmetric.NewMetrics()
	a.add(b, func(id *edgeID) peer {
		switch id.peer.String() {
		case "10.0.0.10":
			return peer{name: "db", host: "db-01"}
		case "10.0.0.11":
			return peer{name: "cache", self: true}
		}
		return peer{name: "queue"}
	}, t0, out)
	got := map[string]string{}
	for _, s := range find(flatten(out), metricHostConnOpened, "app", "*", roleClient, "") {
		got[s.peer] = s.peerHost
	}
	if want := map[string]string{"db": "db-01", "cache": "app-01", "queue": hostUnknown}; !maps.Equal(got, want) {
		t.Errorf("peer hosts = %v, want %v", got, want)
	}
}

// BenchmarkRequestWithFleet measures one request of a host while the
// connector holds the outputs of a fleet, which should not grow with the
// number of hosts.
func BenchmarkRequestWithFleet(b *testing.B) {
	for _, hosts := range []int{10, 10000} {
		b.Run(fmt.Sprintf("hosts=%d", hosts), func(b *testing.B) {
			a := newAggregator(15*time.Minute, 50, 200, false, t0.Add(-time.Hour))
			r := newResolver(nil, nil)
			now := t0
			req := func(host string) *hostBatch {
				md := tAgent{host: host, time: now, edges: []tEdge{
					{role: "client", proto: "tcp", local: "10.0.0.1", peer: "1.1.1.1", port: 443, svc: "a", comm: "a", opened: 1},
					{role: "client", proto: "tcp", local: "10.0.0.1", peer: "1.1.1.2", port: 80, svc: "b", comm: "b", opened: 1},
					{role: "server", proto: "tcp", local: "10.0.0.1", peer: "10.9.9.9", port: 8080, svc: "c", comm: "c", opened: 1},
				}}.metrics()
				hb, err := parseResource(md.ResourceMetrics().At(0))
				if err != nil {
					b.Fatal(err)
				}
				return hb
			}
			for i := range hosts {
				hb := req(fmt.Sprintf("host-%d", i))
				a.add(hb, func(id *edgeID) peer { return r.peer(hb.key, id, now) }, now, pmetric.NewMetrics())
			}
			hb := req("host-0")
			b.ResetTimer()
			for range b.N {
				now = now.Add(15 * time.Second)
				hb.time = now
				hb.final = true
				a.add(hb, func(id *edgeID) peer { return r.peer(hb.key, id, now) }, now, pmetric.NewMetrics())
			}
		})
	}
}
