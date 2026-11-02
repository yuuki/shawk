package shawkconnector

import (
	"context"
	"fmt"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"go.opentelemetry.io/collector/connector/connectortest"
	"go.opentelemetry.io/collector/consumer/consumertest"
	"go.opentelemetry.io/collector/pdata/pmetric"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest/observer"
)

// Tests of folded peers (#96): an agent folds the peers outside its
// internal ranges into the network 0.0.0.0/0 or ::/0.

func webAgent(ts time.Time) tAgent {
	return tAgent{host: "web-01", machineID: "m-web", addrs: []string{"203.0.113.10", "2001:db8::10"}, time: ts,
		fold: foldAll, internal: []string{"10.0.0.0/8", "::ffff:192.168.0.0/112", "fc00::1/7", "bogus"},
		edges: []tEdge{
			{role: "server", proto: "tcp", local: "203.0.113.10", peer: "0.0.0.0", folded: true, port: 443, svc: "nginx", comm: "nginx", opened: 100},
			{role: "server", proto: "tcp", local: "2001:db8::10", peer: "::", folded: true, port: 443, svc: "nginx", comm: "nginx", opened: 10},
			{role: "client", proto: "tcp", local: "203.0.113.10", peer: "0.0.0.0", folded: true, port: 443, svc: "nginx", comm: "nginx", opened: 3},
			// An agent of the previous version sends a peer 0.0.0.0 as an
			// address.
			{role: "server", proto: "tcp", local: "203.0.113.10", peer: "0.0.0.0", port: 8080, svc: "nginx", comm: "nginx", opened: 1},
		}}
}

func TestParseFoldedEdges(t *testing.T) {
	b, err := parseResource(webAgent(t0).metrics().ResourceMetrics().At(0))
	if err != nil {
		t.Fatal(err)
	}
	if b.invalid != 0 {
		t.Errorf("%d invalid data points", b.invalid)
	}
	var got []string
	for _, e := range b.edges {
		got = append(got, e.id.role+" "+e.id.peerString()+" "+e.id.peer.String())
		if e.id.folded != (e.id.port == 443) {
			t.Errorf("edge %+v folded = %v", e.id, e.id.folded)
		}
	}
	slices.Sort(got)
	want := []string{"client 0.0.0.0/0 0.0.0.0", "server 0.0.0.0 0.0.0.0", "server 0.0.0.0/0 0.0.0.0", "server ::/0 ::"}
	if !slices.Equal(got, want) {
		t.Errorf("edges = %q, want %q", got, want)
	}
	// Invalid ranges are left out, IPv4-mapped ones are taken as IPv4, and
	// bits beyond the length are cleared.
	wantInternal := []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8"), netip.MustParsePrefix("192.168.0.0/16"),
		netip.MustParsePrefix("fc00::/7")}
	if b.peerFold != foldAll || !slices.Equal(b.peerInternal, wantInternal) {
		t.Errorf("fold %q, internal %v", b.peerFold, b.peerInternal)
	}

	// An agent of the previous version folds nothing and does not tell its
	// internal ranges.
	b, err = parseResource(tAgent{host: "old-01", time: t0, dropped: 3, droppedSince: t0.Add(-time.Hour)}.metrics().ResourceMetrics().At(0))
	if err != nil {
		t.Fatal(err)
	}
	if b.peerFold != foldNone || b.peerInternal != nil {
		t.Errorf("previous agent: fold %q, internal %v", b.peerFold, b.peerInternal)
	}
	if b.dropped != 3 || !b.droppedSince.Equal(t0.Add(-time.Hour)) {
		t.Errorf("dropped %d since %v", b.dropped, b.droppedSince)
	}
}

// peerAddrs returns the network.peer.address of the output series of a
// metric of a role.
func peerAddrs(sink *consumertest.MetricsSink, metric, role string) []string {
	var out []string
	for _, md := range sink.AllMetrics() {
		rms := md.ResourceMetrics()
		for i := range rms.Len() {
			sms := rms.At(i).ScopeMetrics()
			for j := range sms.Len() {
				ms := sms.At(j).Metrics()
				for k := range ms.Len() {
					m := ms.At(k)
					if m.Name() != metric || m.Type() != pmetric.MetricTypeSum {
						continue
					}
					for l := range m.Sum().DataPoints().Len() {
						a := m.Sum().DataPoints().At(l).Attributes()
						if getString(a, attrRole) == role {
							out = append(out, getString(a, attrPeerService)+" "+getString(a, attrPeerAddr))
						}
					}
				}
			}
		}
	}
	slices.Sort(out)
	return out
}

func TestFoldedPeerNames(t *testing.T) {
	c, st, sink, _ := testConnector(t, func(cfg *Config) {
		cfg.KeepPeerAddress = true
		cfg.PeerCIDRs = map[string]string{"office-lan": "192.168.10.0/24"}
	})
	// A service and a client at the address of the folded peers do not name
	// them.
	c.resolver.localEndpoints[endpointKey{addrOf("0.0.0.0"), 443, "tcp"}] = map[endpoint]time.Time{
		{host: "x", service: "postgres", exact: true}: t0}
	c.resolver.localClients[clientKey{addrOf("0.0.0.0"), addrOf("203.0.113.10"), 443, "tcp"}] = map[endpoint]time.Time{
		{host: "x", service: "crawler", exact: true}: t0}
	out := consume(t, c, sink, webAgent(t0.Add(15*time.Second)))
	for _, s := range find(out, metricConnOpened, "nginx", "*", "*", "") {
		want := map[int64]string{443: peerExternal, 8080: peerUnresolved}[s.port]
		if s.peer != want || s.agent {
			t.Errorf("%s peer on port %d = %q, agent %v; want %s", s.role, s.port, s.peer, s.agent, want)
		}
	}
	// keep_peer_address outputs the network; the folded peers and the
	// address 0.0.0.0 are different series.
	if got := peerAddrs(sink, metricConnOpened, roleServer); !slices.Equal(got,
		[]string{"~external 0.0.0.0/0", "~external ::/0", "~unresolved 0.0.0.0"}) {
		t.Errorf("server peers = %q", got)
	}
	if got := peerAddrs(sink, metricConnOpened, roleClient); !slices.Equal(got, []string{"~external 0.0.0.0/0"}) {
		t.Errorf("client peers = %q", got)
	}
	var total float64
	for _, s := range find(out, metricConnOpened, "nginx", peerExternal, roleServer, "") {
		total += s.value
	}
	if total != 110 {
		t.Errorf("connections from folded clients = %v", total)
	}

	// A folded client edge is no client endpoint to name a server edge by.
	c.resolver.mu.RLock()
	for k := range c.resolver.localClients {
		if k.server.IsUnspecified() && k.client == addrOf("203.0.113.10") {
			t.Errorf("client endpoint learned from a folded edge: %+v", k)
		}
	}
	c.resolver.mu.RUnlock()

	// The edges are written with their networks, apart from the address.
	c.flush(context.Background())
	var rows []string
	for _, w := range st.writes {
		for k := range w.edges {
			rows = append(rows, k.role+" "+peerString(k.peer, k.folded))
		}
	}
	slices.Sort(rows)
	if want := []string{"client 0.0.0.0/0", "server 0.0.0.0", "server 0.0.0.0/0", "server ::/0"}; !slices.Equal(rows, want) {
		t.Errorf("edges written = %q, want %q", rows, want)
	}
}

// TestFoldedPeerCIDRs: a range of peer_cidrs that holds a whole network
// names its folded peers, as peer_class() does in PostgreSQL.
func TestFoldedPeerCIDRs(t *testing.T) {
	r := newResolver(must(parsePeerCIDRs(map[string]string{"internet": "0.0.0.0/0", "docs": "2001:db8::/32"})))
	for _, tc := range []struct {
		peer string
		want string
	}{
		{"0.0.0.0", "internet"},
		{"::", peerExternal},
	} {
		id := edgeID{role: roleServer, proto: "tcp", local: addrOf("203.0.113.10"), peer: addrOf(tc.peer), folded: true, port: 443}
		if p := r.peer("h", &id, t0); p.name != tc.want || p.agent {
			t.Errorf("%s: %+v, want %s", tc.peer, p, tc.want)
		}
	}
}

func must[T any](v T, err error) T {
	if err != nil {
		panic(err)
	}
	return v
}

// observe replaces the logger of a connector with one that records warnings.
func observe(c *shawkConnector) *observer.ObservedLogs {
	core, logs := observer.New(zapcore.WarnLevel)
	c.log = zap.New(core)
	return logs
}

// foldWarnings returns the client and server hosts of the warnings about
// agents that fold clients that run agents.
func foldWarnings(logs *observer.ObservedLogs) []string {
	var out []string
	for _, e := range logs.TakeAll() {
		m := e.ContextMap()
		if _, ok := m["server_host"]; ok {
			out = append(out, m["client_host"].(string)+" "+m["client_address"].(string)+" -> "+
				m["server_host"].(string)+" "+m["server_address"].(string))
		}
	}
	slices.Sort(out)
	return out
}

// TestFoldedAgentPeerDiagnostic: a host whose agent folds the clients of its
// servers sees a client that runs an agent as external when the address of
// the client is outside its internal ranges. The two sides of the
// connections do not match, and both are counted; the connector warns.
func TestFoldedAgentPeerDiagnostic(t *testing.T) {
	c, st, sink, now := testConnector(t, nil)
	logs := observe(c)
	edge := func(at time.Time) tAgent {
		return tAgent{host: "edge-01", addrs: []string{"203.0.113.10"}, time: at, fold: foldIn,
			internal: []string{"10.0.0.0/8"},
			listeners: []tListener{{proto: "tcp", addr: "0.0.0.0", port: 443, svc: "nginx", comm: "nginx"},
				{proto: "udp", addr: "0.0.0.0", port: 53, svc: "named", comm: "named"}}}
	}
	plain := tAgent{host: "plain-01", addrs: []string{"203.0.113.30"}, time: t0, fold: foldNone,
		listeners: []tListener{{proto: "tcp", addr: "0.0.0.0", port: 443, svc: "nginx", comm: "nginx"}}}
	client := func(host, addr string, at time.Time, peers ...string) tAgent {
		ta := tAgent{host: host, addrs: []string{addr}, time: at}
		for _, p := range peers {
			ta.edges = append(ta.edges, tEdge{role: "client", proto: "tcp", local: addr, peer: p, port: 443,
				svc: "app", comm: "app", opened: 1})
		}
		return ta
	}
	consume(t, c, sink, edge(t0))
	consume(t, c, sink, plain)
	// A public client of the folding host; an internal one; a client of a
	// host that folds nothing.
	out := consume(t, c, sink, client("app-01", "198.51.100.7", t0, "203.0.113.10", "203.0.113.30"))
	consume(t, c, sink, client("app-02", "10.0.0.7", t0, "203.0.113.10"))
	if got, want := foldWarnings(logs), []string{"app-01 198.51.100.7 -> edge-01 203.0.113.10"}; !slices.Equal(got, want) {
		t.Errorf("warnings = %q, want %q", got, want)
	}
	// The client still names the server and its agent.
	if s := find(out, metricConnOpened, "app", "nginx", roleClient, ""); len(s) != 1 || !s[0].agent {
		t.Errorf("client series = %v", s)
	}
	// Once an hour per host whose agent folds, with the hosts it folded
	// since.
	consume(t, c, sink, client("app-01", "198.51.100.7", t0.Add(15*time.Second), "203.0.113.10"))
	consume(t, c, sink, client("app-05", "198.51.100.8", t0.Add(15*time.Second), "203.0.113.10"))
	if got := foldWarnings(logs); len(got) != 0 {
		t.Errorf("warned again within the hour: %q", got)
	}
	later := t0.Add(61 * time.Minute)
	*now = later
	consume(t, c, sink, edge(later))
	consume(t, c, sink, client("app-01", "198.51.100.7", later, "203.0.113.10"))
	if got := logs.TakeAll(); len(got) != 1 || got[0].ContextMap()["hosts_folded"] != int64(2) {
		t.Errorf("warnings an hour later = %v, want one with hosts_folded 2", got)
	}

	// UDP of a host that does not trace UDP: no server edge to mismatch.
	noUDP := edge(later)
	noUDP.noUDP = true
	consume(t, c, sink, noUDP)
	consume(t, c, sink, tAgent{host: "app-03", addrs: []string{"198.51.100.9"}, time: later,
		edges: []tEdge{{role: "client", proto: "udp", local: "198.51.100.9", peer: "203.0.113.10", port: 53, svc: "app", comm: "app"}}})
	if got := foldWarnings(logs); len(got) != 0 {
		t.Errorf("warnings for UDP not traced = %q", got)
	}

	// A host behind another connector is known from PostgreSQL.
	st.mu.Lock()
	st.rows.agents = []agentAddrRow{{addr: addrOf("203.0.113.20"), host: "k-edge-02", seen: later,
		agent: agentHost{seen: later, udpTraced: true, name: "edge-02", fold: foldAll,
			internal: []netip.Prefix{netip.MustParsePrefix("198.51.100.0/28")}}}}
	st.mu.Unlock()
	c.prepare(context.Background())
	consume(t, c, sink, client("app-01", "198.51.100.7", later, "203.0.113.20"))
	consume(t, c, sink, client("app-04", "198.51.100.77", later, "203.0.113.20"))
	if got, want := foldWarnings(logs), []string{"app-04 198.51.100.77 -> edge-02 203.0.113.20"}; !slices.Equal(got, want) {
		t.Errorf("warnings for a host in PostgreSQL = %q, want %q", got, want)
	}
}

// TestFoldAllAgentServer: a client host whose agent folds the peers of its
// clients too (-fold-external=all) folds a server that runs an agent when
// the address of the server is outside its internal ranges. Its client
// edge then names no service, so the server edge tells that its peer has
// no agent, and is counted; the connector warns.
func TestFoldAllAgentServer(t *testing.T) {
	c, _, sink, _ := testConnector(t, nil)
	logs := observe(c)
	app := tAgent{host: "app-01", addrs: []string{"198.51.100.7"}, time: t0, fold: foldAll,
		internal: []string{"10.0.0.0/8"},
		edges: []tEdge{{role: "client", proto: "tcp", local: "198.51.100.7", peer: "0.0.0.0", folded: true, port: 443,
			svc: "app", comm: "app", opened: 1}}}
	web := tAgent{host: "web-01", addrs: []string{"203.0.113.10"}, time: t0, fold: foldIn,
		internal:  []string{"10.0.0.0/8", "198.51.100.0/24"},
		listeners: []tListener{{proto: "tcp", addr: "0.0.0.0", port: 443, svc: "nginx", comm: "nginx"}},
		edges: []tEdge{{role: "server", proto: "tcp", local: "203.0.113.10", peer: "198.51.100.7", port: 443,
			svc: "nginx", comm: "nginx", opened: 1}}}
	consume(t, c, sink, app)
	out := consume(t, c, sink, web)
	s := find(out, metricConnOpened, "nginx", "*", roleServer, "")
	if len(s) != 1 || s[0].agent {
		t.Errorf("server series = %v, want one whose peer has no agent", s)
	}
	if got, want := foldWarnings(logs), []string{"app-01 198.51.100.7 -> web-01 203.0.113.10"}; !slices.Equal(got, want) {
		t.Errorf("warnings = %q, want %q", got, want)
	}
	// A server in the internal ranges of the client stays matched.
	app.internal = append(app.internal, "203.0.113.0/24")
	app.time, web.time = t0.Add(15*time.Second), t0.Add(15*time.Second)
	web.edges[0].opened = 2
	consume(t, c, sink, app)
	out = consume(t, c, sink, web)
	// The series of the folded peer is kept until it is idle.
	if s := find(out, metricConnOpened, "nginx", "*", roleServer, ""); !slices.ContainsFunc(s, func(s series) bool { return s.agent }) {
		t.Errorf("server series = %v, want one whose peer has an agent", s)
	}
}

// TestFoldedCIDRsWarning: an agent that folds the peers in a range of
// peer_cidrs makes them ~external; the connector warns once an hour per
// configuration of the agents, and not about a range of a whole network,
// which names folded peers.
func TestFoldedCIDRsWarning(t *testing.T) {
	c, _, sink, now := testConnector(t, func(cfg *Config) {
		cfg.PeerCIDRs = map[string]string{"office": "203.0.113.0/24", "dc": "10.20.0.0/16",
			"internet": "0.0.0.0/0", "internet6": "::/0"}
	})
	logs := observe(c)
	host := func(name string, fold string, internal ...string) tAgent {
		return tAgent{host: name, addrs: []string{"10.0.0.9"}, time: *now, fold: fold, internal: internal}
	}
	consume(t, c, sink, host("edge-01", foldIn, "10.0.0.0/8"))
	consume(t, c, sink, host("edge-02", foldIn, "10.0.0.0/8", "203.0.113.0/24"))
	consume(t, c, sink, host("edge-03", foldNone))
	// More hosts with the same configuration.
	for i := range 5 {
		consume(t, c, sink, host(fmt.Sprintf("app-%02d", i), foldIn, "10.0.0.0/8"))
	}
	got := logs.TakeAll()
	if len(got) != 1 || got[0].ContextMap()["host"] != "edge-01" || !strings.Contains(got[0].Message, "clients") {
		t.Fatalf("warnings = %v, want one about the clients of edge-01", got)
	}
	if r := got[0].ContextMap()["peer_cidrs"]; fmt.Sprint(r) != "[office=203.0.113.0/24]" {
		t.Errorf("ranges = %v", r)
	}
	consume(t, c, sink, host("edge-04", foldAll, "10.0.0.0/8"))
	if got := logs.TakeAll(); len(got) != 1 || strings.Contains(got[0].Message, "clients") {
		t.Errorf("warnings for another configuration = %v, want one about all peers", got)
	}
}

// TestFoldWarningCount: a host whose agent folds is logged once an hour with
// the hosts it folded since, also when the loop of the connector expires
// its warnings meanwhile.
func TestFoldWarningCount(t *testing.T) {
	cfg := createDefaultConfig()
	cfg.Postgres.DSN = "postgres://unused"
	cfg.WriteInterval = 10 * time.Millisecond
	sink := new(consumertest.MetricsSink)
	c, err := newConnector(connectortest.NewNopSettings(Type), cfg, sink)
	if err != nil {
		t.Fatal(err)
	}
	c.newStore = func(context.Context, string) (store, error) { return &fakeStore{}, nil }
	var mu sync.Mutex
	now := t0
	c.now = func() time.Time { mu.Lock(); defer mu.Unlock(); return now }
	c.agg.started = t0.Add(-time.Hour)
	if err := c.Start(context.Background(), nil); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Shutdown(context.Background()) })
	logs := observe(c)
	at := func(minutes int, host, addr string) {
		ts := t0.Add(time.Duration(minutes) * time.Minute)
		mu.Lock()
		now = ts
		mu.Unlock()
		consume(t, c, sink, tAgent{host: "edge-01", addrs: []string{"203.0.113.10"}, time: ts, fold: foldIn,
			internal:  []string{"10.0.0.0/8"},
			listeners: []tListener{{proto: "tcp", addr: "0.0.0.0", port: 443, svc: "nginx", comm: "nginx"}}})
		consume(t, c, sink, tAgent{host: host, addrs: []string{addr}, time: ts,
			edges: []tEdge{{role: "client", proto: "tcp", local: addr, peer: "203.0.113.10", port: 443, svc: "app", comm: "app", opened: 1}}})
	}
	at(0, "app-01", "198.51.100.1")
	for i := 2; i <= 4; i++ {
		at(10, fmt.Sprintf("app-%02d", i), fmt.Sprintf("198.51.100.%d", i))
	}
	mu.Lock()
	now = t0.Add(61 * time.Minute)
	mu.Unlock()
	time.Sleep(100 * time.Millisecond) // the loop expires its warnings
	at(61, "app-05", "198.51.100.5")
	var counts []any
	for _, e := range logs.TakeAll() {
		counts = append(counts, e.ContextMap()["hosts_folded"])
	}
	if fmt.Sprint(counts) != "[1 4]" {
		t.Errorf("hosts_folded of the warnings = %v, want [1 4]", counts)
	}
}

// TestSessionFoldAndDrops: the session of a request carries what the agent
// folds and when its counters started, by the clock of the agent, which
// tells its runs apart whatever the clock of the connector.
func TestSessionFoldAndDrops(t *testing.T) {
	ch := newChanges(15 * time.Minute)
	ta := webAgent(t0)
	ta.segment = t0.Add(-time.Minute)
	ta.dropped, ta.droppedSince = 5, t0.Add(-time.Hour)
	b, err := parseResource(ta.metrics().ResourceMetrics().At(0))
	if err != nil {
		t.Fatal(err)
	}
	// The clock of the agent is ten seconds behind.
	ch.add(b, t0.Add(10*time.Second))
	h := ch.pending[b.key]
	if len(h.sessions) != 1 {
		t.Fatalf("sessions = %v", h.sessions)
	}
	for _, s := range h.sessions {
		if s.dropped != 5 || !s.countersStarted.Equal(t0.Add(-time.Hour)) || s.peerFold != foldAll ||
			len(s.peerInternal) != 3 {
			t.Errorf("session = %+v", s)
		}
	}
}
