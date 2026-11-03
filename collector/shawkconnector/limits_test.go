package shawkconnector

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"go.opentelemetry.io/collector/consumer/consumererror"
)

// Tests of the bounds of what the connector holds (#145): the hosts, the
// series of every host, the endpoints inferred from them, and the changes
// pending while PostgreSQL is down.

// TestMaxHosts: beyond max_hosts, the requests of new hosts are refused with
// an error that is not permanent, and nothing of them is kept; the hosts
// held are not evicted, and a new host is taken once one has expired.
func TestMaxHosts(t *testing.T) {
	c, _, sink, now := testConnector(t, func(cfg *Config) { cfg.MaxHosts = 2 })
	logs := observe(c)
	agent := func(host, addr string) tAgent {
		return tAgent{host: host, addrs: []string{addr}, time: *now, edges: []tEdge{{role: "client", proto: "tcp",
			local: addr, peer: "10.0.0.10", port: 5432, svc: "app", comm: "app", opened: 1}}}
	}
	consume(t, c, sink, agent("app-01", "10.0.0.11"))
	consume(t, c, sink, agent("app-02", "10.0.0.12"))
	err := c.ConsumeMetrics(context.Background(), agent("app-03", "10.0.0.13").metrics())
	if err == nil || consumererror.IsPermanent(err) {
		t.Fatalf("the request of a third host = %v, want an error that is not permanent", err)
	}
	key := hostKey("", "app-03")
	_, pending := c.changes.pending[key]
	_, agentKnown := c.resolver.localAgents[key]
	if pending || agentKnown || c.agg.hosts[key] != nil {
		t.Error("the state of a refused host is kept")
	}
	if got := logs.FilterMessageSnippet("max_hosts").Len(); got != 1 {
		t.Errorf("%d warnings about max_hosts, want 1", got)
	}

	// The hosts held stay; app-02 stops, and app-03 is taken once app-02
	// has not sent for the idle TTL.
	*now = now.Add(time.Minute)
	consume(t, c, sink, agent("app-01", "10.0.0.11"))
	*now = now.Add(c.cfg.IdleTTL)
	c.limits.expire(*now)
	consume(t, c, sink, agent("app-01", "10.0.0.11"))
	consume(t, c, sink, agent("app-03", "10.0.0.13"))
	if _, ok := c.changes.pending[key]; !ok {
		t.Error("a new host is refused after a host expired")
	}
}

// TestMaxSeriesPerHost: beyond max_series_per_host, the new series of a
// host are dropped and the series held are kept. A host is not observed in
// an interval with drops: its session ends at the heartbeat before, and the
// next one starts at the request that closed that interval, after which
// the series dropped are either sent and written or were last active
// before.
func TestMaxSeriesPerHost(t *testing.T) {
	c, st, sink, now := testConnector(t, func(cfg *Config) { cfg.MaxSeriesPerHost = 3 })
	logs := observe(c)
	edge := func(port int64) tEdge {
		return tEdge{role: "client", proto: "tcp", local: "10.0.0.11", peer: "10.0.0.10", port: port, svc: "app", comm: "app", opened: 1}
	}
	ports := func(out []series) []int64 {
		var ps []int64
		for _, s := range find(out, metricConnOpened, "app", "*", roleClient, "") {
			ps = append(ps, s.port)
		}
		return ps
	}
	// The address, the listener and the edge make three series.
	ta := tAgent{host: "app-01", addrs: []string{"10.0.0.11"}, time: *now, segment: t0.Add(-time.Hour),
		listeners: []tListener{{proto: "tcp", addr: "0.0.0.0", port: 8080, svc: "app", comm: "app"}},
		edges:     []tEdge{edge(5432)}}
	consume(t, c, sink, ta)
	c.flush(context.Background())
	if len(st.writes[0].sessions) != 1 {
		t.Fatalf("sessions = %v", st.writes[0].sessions)
	}

	// Two more edges are dropped.
	*now = now.Add(15 * time.Second)
	ta.time = *now
	ta.edges = append(ta.edges, edge(5433), edge(5434))
	if ps := ports(consume(t, c, sink, ta)); len(ps) != 1 || ps[0] != 5432 {
		t.Errorf("outputs of the ports %v, want 5432 alone", ps)
	}
	c.flush(context.Background())
	h := st.writes[1]
	for k := range h.edges {
		if k.port != 5432 {
			t.Errorf("a dropped edge is written: %+v", k)
		}
	}
	if len(h.sessions) != 0 {
		t.Errorf("the session continues over an interval with drops: %v", h.sessions)
	}
	if got := logs.FilterMessageSnippet("max_series_per_host").All(); len(got) != 1 || got[0].ContextMap()["series"] != int64(2) {
		t.Errorf("warnings = %v, want one about 2 series", got)
	}

	// The new edges stop: the next session starts at the request whose
	// series were dropped.
	limited := ta.time
	*now = now.Add(15 * time.Second)
	ta.time = *now
	ta.edges = ta.edges[:1]
	consume(t, c, sink, ta)
	c.flush(context.Background())
	h = st.writes[2]
	if len(h.sessions) != 1 {
		t.Fatalf("sessions = %v", h.sessions)
	}
	for s := range h.sessions {
		if !s.Equal(limited) {
			t.Errorf("the session starts at %v, want %v, when series were last dropped", s, limited)
		}
	}

	// The listener closes; once it has not been sent for the idle TTL, a
	// new edge is taken.
	ta.listeners = nil
	*now = now.Add(10 * time.Minute)
	ta.time = *now
	consume(t, c, sink, ta)
	*now = now.Add(6 * time.Minute)
	c.limits.expire(*now)
	ta.time = *now
	ta.edges = append(ta.edges, edge(5433))
	if ps := ports(consume(t, c, sink, ta)); len(ps) != 2 {
		t.Errorf("outputs of the ports %v, want 5432 and 5433", ps)
	}
}

// TestMaxSeriesPerHostAddresses: the addresses of a host count among its
// series, and so bound the endpoints inferred from its listeners on
// unspecified addresses, which are also bounded on their own by
// max_series_per_host, and forgotten when they expire.
func TestMaxSeriesPerHostAddresses(t *testing.T) {
	c, _, sink, now := testConnector(t, func(cfg *Config) { cfg.MaxSeriesPerHost = 10 })
	var addrs []string
	for i := range 12 {
		addrs = append(addrs, fmt.Sprintf("10.0.0.%d", i+1))
	}
	ta := tAgent{host: "app-01", addrs: addrs, time: *now}
	for _, port := range []int64{8080, 8081, 8082} {
		ta.listeners = append(ta.listeners, tListener{proto: "tcp", addr: "0.0.0.0", port: port, svc: "app", comm: "app"})
	}
	key := hostKey("", "app-01")
	inferred := func() int {
		n := 0
		for _, es := range c.resolver.localEndpoints {
			for e := range es {
				if e.host == key && !e.exact {
					n++
				}
			}
		}
		return n
	}
	// Ten addresses are held, then no listener.
	consume(t, c, sink, ta)
	if n := len(c.changes.pending[key].addrs); n != 10 {
		t.Errorf("%d addresses kept, want 10", n)
	}
	if n := len(c.changes.pending[key].listeners); n != 0 {
		t.Errorf("%d listeners kept, want 0", n)
	}
	// With five addresses, the listeners are held and infer 15 endpoints,
	// of which 10 are kept.
	c.limits.expire(now.Add(c.cfg.IdleTTL + time.Second))
	c.resolver.expire(now.Add(time.Second), now.Add(time.Second))
	ta.addrs = addrs[:5]
	for range 2 {
		consume(t, c, sink, ta)
		if n := inferred(); n != 10 || c.resolver.inferred[key] != 10 {
			t.Errorf("%d endpoints inferred (counted %d), want 10", n, c.resolver.inferred[key])
		}
	}
	c.resolver.expire(now.Add(time.Second), now.Add(time.Second))
	if len(c.resolver.localEndpoints) != 0 || len(c.resolver.inferred) != 0 {
		t.Errorf("endpoints inferred after they expired: %v, %v", c.resolver.localEndpoints, c.resolver.inferred)
	}
}

// TestInputSeriesBound: the input series of the edges of a host are bounded
// by maxValuesPerEdge times max_series_per_host, whatever the reasons of
// failure an edge carries.
func TestInputSeriesBound(t *testing.T) {
	c, _, sink, now := testConnector(t, func(cfg *Config) { cfg.MaxSeriesPerHost = 1 })
	logs := observe(c)
	reasons := map[string]tReason{}
	for i := range 40 {
		reasons[fmt.Sprintf("reason-%d", i)] = tReason{value: 1}
	}
	// Seven metrics and 40 reasons.
	consume(t, c, sink, tAgent{host: "app-01", time: *now, edges: []tEdge{{role: "client", proto: "tcp", local: "10.0.0.11",
		peer: "10.0.0.10", port: 5432, svc: "app", comm: "app", opened: 1, reasons: reasons}}})
	if n := len(c.agg.hosts[hostKey("", "app-01")].inputs); n != maxValuesPerEdge {
		t.Errorf("%d input series, want %d", n, maxValuesPerEdge)
	}
	if got := logs.FilterMessageSnippet("max_series_per_host").All(); len(got) != 1 ||
		got[0].ContextMap()["metric_series"] != int64(47-maxValuesPerEdge) {
		t.Errorf("warnings = %v, want one about %d metric series", got, 47-maxValuesPerEdge)
	}
}

// TestMaxPendingRows: while PostgreSQL is down, the changes of the hosts
// pending the longest are dropped beyond max_pending_rows, as changes that
// it rejects: the edges their agents still send are written again, and the
// next session of such a host starts after the one dropped.
func TestMaxPendingRows(t *testing.T) {
	// A host, a session, an address, a process and an edge per host.
	c, st, sink, now := testConnector(t, func(cfg *Config) { cfg.MaxPendingRows = 6 })
	agent := func(host, addr string) tAgent {
		return tAgent{host: host, addrs: []string{addr}, time: *now, segment: t0.Add(-time.Hour),
			edges: []tEdge{{role: "client", proto: "tcp", local: addr, peer: "10.0.0.10", port: 5432, svc: "app",
				comm: "app", opened: 1, last: t0}}}
	}
	app1, app2 := hostKey("", "app-01"), hostKey("", "app-02")
	st.fail = true
	ta := agent("app-01", "10.0.0.11")
	consume(t, c, sink, ta)
	var dropped time.Time
	for s := range c.changes.pending[app1].sessions {
		dropped = s
	}
	*now = now.Add(15 * time.Second)
	consume(t, c, sink, agent("app-02", "10.0.0.12"))
	if c.flush(context.Background()) {
		t.Fatal("a failed flush reports success")
	}
	c.boundPending()
	if _, ok := c.changes.pending[app1]; ok {
		t.Error("the changes pending the longest are kept")
	}
	if _, ok := c.changes.pending[app2]; !ok {
		t.Error("the changes of app-02 are dropped")
	}
	if n := c.changes.pendingSize(); n > 6 {
		t.Errorf("%d rows pending", n)
	}

	// PostgreSQL is back. app-01 still sends its edge, idle since t0.
	st.fail = false
	*now = now.Add(15 * time.Second)
	ta.time = *now
	consume(t, c, sink, ta)
	if !c.flush(context.Background()) {
		t.Fatal("flush failed")
	}
	for _, h := range st.writes {
		if h.key != app1 {
			continue
		}
		if len(h.edges) != 1 {
			t.Errorf("the idle edge was not written again: %v", h.edges)
		}
		for s := range h.sessions {
			if !s.After(dropped) {
				t.Errorf("the session continues over the dropped changes: %v, then %v", dropped, s)
			}
		}
	}
}

// TestAgentInputBounds: the strings of agents are cut to maxStringBytes, at
// the start of a character, and their internal ranges to maxInternalPeers,
// so that what is held of a series or a host has a bounded size.
func TestAgentInputBounds(t *testing.T) {
	unit := "a" + strings.Repeat("é", 3000)
	var internal []string
	for i := range maxInternalPeers + 10 {
		internal = append(internal, fmt.Sprintf("10.%d.%d.0/24", i>>8, i&255))
	}
	b, err := parseResource(tAgent{host: "app-01", time: t0, internal: internal, edges: []tEdge{{role: "client",
		proto: "tcp", local: "10.0.0.11", peer: "10.0.0.10", port: 5432, svc: "app", comm: "app", unit: unit,
		opened: 1}}}.metrics().ResourceMetrics().At(0))
	if err != nil {
		t.Fatal(err)
	}
	for id := range b.edges {
		if id.unit != unit[:maxStringBytes-1] {
			t.Errorf("a unit of %d bytes is kept as %d bytes, want the first %d", len(unit), len(id.unit), maxStringBytes-1)
		}
	}
	if len(b.peerInternal) != maxInternalPeers {
		t.Errorf("%d internal ranges kept, want %d", len(b.peerInternal), maxInternalPeers)
	}
}

// TestFoldedCIDRsWarningsBounded: the warnings about agents that fold the
// ranges of peer_cidrs are held by what is folded, not by the ranges agents
// keep exact, which agents choose.
func TestFoldedCIDRsWarningsBounded(t *testing.T) {
	c, _, sink, now := testConnector(t, func(cfg *Config) {
		cfg.PeerCIDRs = map[string]string{"office": "203.0.113.0/24"}
	})
	logs := observe(c)
	for i := range 20 {
		consume(t, c, sink, tAgent{host: fmt.Sprintf("app-%02d", i), time: *now, fold: foldIn,
			internal: []string{fmt.Sprintf("10.%d.0.0/16", i)}})
	}
	if len(c.cidrWarned) != 1 || logs.Len() != 1 {
		t.Errorf("%d warnings held, %d logged, want 1", len(c.cidrWarned), logs.Len())
	}
}
