package shawkconnector

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	"go.opentelemetry.io/collector/pdata/pmetric"
)

func TestHostKey(t *testing.T) {
	// The host id of shawk before the connector existed: the first 8 bytes
	// of SHA-256 of the machine id, a newline and the host name.
	if got := hostKey("4c4c4544003910528036b4c04f4d3732", "app-01"); got != "c101ee9541aca28b" {
		t.Errorf("hostKey = %s", got)
	}
	if hostKey("a", "h1") == hostKey("a", "h2") {
		t.Error("cloned hosts with the same machine id collide")
	}
}

// TestGoldenRequest decodes a request written by the agent's tests.
func TestGoldenRequest(t *testing.T) {
	b, err := os.ReadFile("testdata/agent-request.json")
	if err != nil {
		t.Fatal(err)
	}
	md, err := (&pmetric.JSONUnmarshaler{}).UnmarshalMetrics(b)
	if err != nil {
		t.Fatal(err)
	}
	hb, err := parseResource(md.ResourceMetrics().At(0))
	if err != nil {
		t.Fatal(err)
	}
	if hb.invalid != 0 {
		t.Errorf("%d invalid data points", hb.invalid)
	}
	if hb.key != hostKey("4c4c4544003910528036b4c04f4d3732", "app-01") || hb.hostname != "app-01" ||
		hb.kernel != "5.14.0-503.el9.x86_64" || hb.agentVersion != "v0.9.0" || len(hb.addrs) != 2 {
		t.Errorf("host = %+v", hb)
	}
	if !hb.segmentStart.Equal(t0.Add(-time.Hour)) || !hb.udpTraced || hb.dropped != 7 || hb.netnsScope != "all" {
		t.Errorf("agent status = %v %v %v %q", hb.segmentStart, hb.udpTraced, hb.dropped, hb.netnsScope)
	}
	if !hb.time.Equal(t0.Add(15 * time.Second)) {
		t.Errorf("time = %v", hb.time)
	}
	if len(hb.edges) != 3 || len(hb.listeners) != 2 {
		t.Fatalf("%d edges, %d listeners", len(hb.edges), len(hb.listeners))
	}
	var client *edgeInput
	for _, e := range hb.edges {
		if e.id.role == roleClient && e.id.proto == "tcp" {
			client = e
		}
	}
	if client == nil {
		t.Fatal("no TCP client edge")
	}
	want := process{unit: "app.service", comm: "puma", exe: "/usr/bin/ruby", service: "app", svcNS: "shop"}
	if client.id.process != want || client.id.port != 5432 || client.id.peer.String() != "10.0.0.10" ||
		client.id.netns != 4026531840 || client.id.job() != "shop/app" {
		t.Errorf("client edge = %+v", client.id)
	}
	if !client.first.Equal(t0.Add(15*time.Second)) || !client.last.Equal(client.first) {
		t.Errorf("client edge seen %v..%v", client.first, client.last)
	}
	for k, v := range map[valueKey]float64{
		{metric: metricConnOpened}:                 3,
		{metric: metricConnFailed}:                 1,
		{metric: metricConnCount}:                  2,
		{metric: metricRetransmits}:                4,
		{metric: metricNetworkIO, dir: "transmit"}: 100,
		{metric: metricNetworkIO, dir: "receive"}:  200,
		{metric: metricRTT}:                        0.0015,
	} {
		if p, ok := client.values[k]; !ok || p.value != v || p.start.AsTime() != t0 {
			t.Errorf("%v = %+v, want %v", k, p, v)
		}
	}
	if p := client.values[valueKey{metric: metricRTT}]; p.count != 3 {
		t.Errorf("rtt count = %d", p.count)
	}
	var names []string
	for i := range hb.agent.Len() {
		names = append(names, hb.agent.At(i).Name())
	}
	if got := strings.Join(names, ","); got != "shawk.agent.up,shawk.agent.udp.traced,shawk.agent.flows.dropped,shawk.agent.export.failures,shawk.agent.bpf.run_count,shawk.agent.bpf.run_time" {
		t.Errorf("forwarded agent metrics = %s", got)
	}
}

func TestPeerNames(t *testing.T) {
	c, _, sink, _ := testConnector(t, func(cfg *Config) {
		cfg.PeerCIDRs = map[string]string{"office-lan": "192.168.10.0/24", "corp": "192.168.0.0/16, 172.20.0.0/16"}
	})
	ts := t0.Add(15 * time.Second)
	// The database host listens on all addresses and serves the app host,
	// which runs an agent, and an office PC without one.
	consume(t, c, sink, tAgent{host: "db-01", addrs: []string{"127.0.0.1", "10.0.0.10"}, time: ts,
		listeners: []tListener{{proto: "tcp", addr: "0.0.0.0", port: 5432, svc: "postgres", unit: "postgresql.service", comm: "postgres"}},
		edges: []tEdge{
			{role: "server", proto: "tcp", local: "10.0.0.10", peer: "10.0.0.11", port: 5432, svc: "postgres", comm: "postgres", opened: 5},
			{role: "server", proto: "tcp", local: "10.0.0.10", peer: "192.168.10.7", port: 5432, svc: "postgres", comm: "postgres", opened: 1},
			{role: "server", proto: "tcp", local: "10.0.0.10", peer: "10.9.9.9", port: 5432, svc: "postgres", comm: "postgres", opened: 1},
			{role: "server", proto: "tcp", local: "127.0.0.1", peer: "127.0.0.1", port: 5432, svc: "postgres", comm: "postgres", opened: 1},
		}})
	out := consume(t, c, sink, tAgent{host: "app-01", addrs: []string{"127.0.0.1", "10.0.0.11"}, time: ts,
		edges: []tEdge{
			{role: "client", proto: "tcp", local: "10.0.0.11", peer: "10.0.0.10", port: 5432, svc: "app", ns: "shop", comm: "puma", opened: 3},
			{role: "client", proto: "tcp", local: "10.0.0.11", peer: "93.184.215.14", port: 443, svc: "app", ns: "shop", comm: "puma", opened: 1},
			{role: "client", proto: "tcp", local: "10.0.0.11", peer: "192.168.3.3", port: 80, svc: "app", ns: "shop", comm: "puma", opened: 1},
			{role: "client", proto: "tcp", local: "10.0.0.11", peer: "10.0.0.99", port: 80, svc: "app", ns: "shop", comm: "puma", opened: 1},
			// The listener on the database host's loopback is not this host's.
			{role: "client", proto: "tcp", local: "127.0.0.1", peer: "127.0.0.1", port: 5432, svc: "app", ns: "shop", comm: "puma", opened: 1},
		}})
	peers := map[string]bool{}
	for _, s := range find(out, metricConnOpened, "shop/app", "*", roleClient, "") {
		peers[s.peer] = true
		if s.instance != "app-01" {
			t.Errorf("instance = %q", s.instance)
		}
	}
	for _, p := range []string{"postgres", "~external", "corp", "~unresolved"} {
		if !peers[p] {
			t.Errorf("client peers %v lack %s", peers, p)
		}
	}
	if len(peers) != 4 {
		t.Errorf("client peers = %v", peers)
	}

	// The server side, now that the app host is known as an agent.
	out = consume(t, c, sink, tAgent{host: "db-01", addrs: []string{"127.0.0.1", "10.0.0.10"}, time: ts.Add(15 * time.Second),
		edges: []tEdge{
			{role: "server", proto: "tcp", local: "10.0.0.10", peer: "10.0.0.11", port: 5432, svc: "postgres", comm: "postgres", opened: 6},
			{role: "server", proto: "tcp", local: "10.0.0.10", peer: "192.168.10.7", port: 5432, svc: "postgres", comm: "postgres", opened: 1},
			{role: "server", proto: "tcp", local: "10.0.0.10", peer: "10.9.9.9", port: 5432, svc: "postgres", comm: "postgres", opened: 1},
			{role: "server", proto: "tcp", local: "127.0.0.1", peer: "127.0.0.1", port: 5432, svc: "postgres", comm: "postgres", opened: 1},
		}})
	got := map[string]float64{}
	for _, s := range find(out, metricConnOpened, "postgres", "*", roleServer, "") {
		got[s.peer] = s.value
	}
	// The edge from 10.0.0.11 was named ~unresolved while app-01 was
	// unknown; its increase since then goes to ~agent, as does the loopback
	// edge.
	if len(got) != 3 || got["office-lan"] != 1 || got["~unresolved"] != 6 || got["~agent"] != 2 {
		t.Errorf("server peers = %v", got)
	}
}

func TestCumulativeAggregation(t *testing.T) {
	c, _, sink, now := testConnector(t, nil)
	edge := func(peer string, opened, count int64, start time.Time) tEdge {
		return tEdge{role: "client", proto: "tcp", local: "10.0.0.11", peer: peer, port: 443, svc: "app", comm: "app",
			opened: opened, count: count, tx: opened * 10, rttSum: float64(opened) / 1000, rttCount: uint64(opened), start: start}
	}
	opened := func(out []series) float64 {
		s := find(out, metricConnOpened, "app", "~external", roleClient, "")
		if len(s) != 1 {
			t.Fatalf("connection.opened = %v", s)
		}
		return s[0].value
	}
	gauge := func(out []series) float64 {
		s := find(out, metricConnCount, "app", "~external", roleClient, "")
		if len(s) != 1 {
			t.Fatalf("connection.count = %v", s)
		}
		return s[0].value
	}
	agent := func(edges ...tEdge) tAgent {
		*now = now.Add(15 * time.Second)
		return tAgent{host: "app-01", addrs: []string{"10.0.0.11"}, time: *now, edges: edges}
	}
	// A series that started before the connector is a baseline.
	old := t0.Add(-2 * time.Hour)
	out := consume(t, c, sink, agent(edge("1.1.1.1", 100, 2, old)))
	if v := opened(out); v != 0 {
		t.Errorf("baseline = %v", v)
	}
	if v := gauge(out); v != 2 {
		t.Errorf("open connections = %v", v)
	}
	// Two peer addresses fold into one series.
	out = consume(t, c, sink, agent(edge("1.1.1.1", 103, 1, old), edge("2.2.2.2", 5, 1, t0)))
	if v := opened(out); v != 8 {
		t.Errorf("after two inputs = %v, want 8", v)
	}
	if v := gauge(out); v != 2 {
		t.Errorf("open connections = %v", v)
	}
	// An input disappears: the output does not decrease.
	out = consume(t, c, sink, agent(edge("2.2.2.2", 6, 0, t0)))
	if v := opened(out); v != 9 {
		t.Errorf("after an input disappeared = %v, want 9", v)
	}
	if v := gauge(out); v != 0 {
		t.Errorf("open connections = %v", v)
	}
	// The agent restarts: its counters start again.
	out = consume(t, c, sink, agent(edge("2.2.2.2", 2, 0, *now)))
	if v := opened(out); v != 11 {
		t.Errorf("after a restart = %v, want 11", v)
	}
	rtt := find(out, metricRTT, "app", "~external", roleClient, "")
	if len(rtt) != 1 || rtt[0].count != 11 {
		t.Errorf("rtt = %+v", rtt)
	}
	tx := find(out, metricNetworkIO, "app", "~external", roleClient, "transmit")
	if len(tx) != 1 || tx[0].value != 110 {
		t.Errorf("bytes = %+v", tx)
	}

	// An output series without input is sent until the TTL, then dropped.
	*now = now.Add(14 * time.Minute)
	out = consume(t, c, sink, tAgent{host: "app-01", addrs: []string{"10.0.0.11"}, time: *now})
	if v := opened(out); v != 11 {
		t.Errorf("without input = %v", v)
	}
	*now = now.Add(2 * time.Minute)
	out = consume(t, c, sink, tAgent{host: "app-01", addrs: []string{"10.0.0.11"}, time: *now})
	if s := find(out, metricConnOpened, "app", "*", roleClient, ""); len(s) != 0 {
		t.Errorf("expired series still sent: %v", s)
	}
	if s := find(out, metricAgentUp, "shawk-agent", "", "", ""); len(s) != 1 || s[0].instance != "app-01" {
		t.Errorf("agent metrics = %v", s)
	}
	if s := find(out, metricAgentSegmentStart, "shawk-agent", "", "", ""); len(s) != 0 {
		t.Error("segment.start forwarded")
	}
}

func TestMaxPeers(t *testing.T) {
	c, _, sink, _ := testConnector(t, func(cfg *Config) { cfg.MaxPeers = 2 })
	var edges []tEdge
	for i, peer := range []string{"1.1.1.1", "2.2.2.2", "3.3.3.3", "4.4.4.4"} {
		edges = append(edges, tEdge{role: "client", proto: "tcp", local: "10.0.0.11", peer: peer, port: int64(443 + i),
			svc: "app", comm: "app", opened: 1, start: t0})
	}
	c.resolver.load([]endpointRow{
		{key: endpointKey{addrOf("1.1.1.1"), 443, "tcp"}, endpoint: endpoint{host: "x", service: "a"}},
		{key: endpointKey{addrOf("2.2.2.2"), 444, "tcp"}, endpoint: endpoint{host: "x", service: "b"}},
		{key: endpointKey{addrOf("3.3.3.3"), 445, "tcp"}, endpoint: endpoint{host: "x", service: "c"}},
		{key: endpointKey{addrOf("4.4.4.4"), 446, "tcp"}, endpoint: endpoint{host: "x", service: "d"}},
	}, nil)
	out := consume(t, c, sink, tAgent{host: "app-01", time: t0.Add(15 * time.Second), edges: edges})
	peers := map[string]int{}
	for _, s := range find(out, metricConnOpened, "app", "*", roleClient, "") {
		peers[s.peer]++
	}
	if len(peers) != 3 || peers["~other"] != 2 {
		t.Errorf("peers = %v, want two named and two folded series", peers)
	}
}

func TestWrites(t *testing.T) {
	c, st, sink, now := testConnector(t, nil)
	edge := tEdge{role: "client", proto: "tcp", local: "10.0.0.11", peer: "10.0.0.10", port: 5432, svc: "app",
		unit: "app.service", comm: "puma", exe: "/usr/bin/ruby", opened: 1, first: t0.Add(15 * time.Second)}
	ta := tAgent{host: "app-01", machineID: "m1", addrs: []string{"10.0.0.11"}, time: t0.Add(15 * time.Second),
		segment: t0.Add(-time.Hour), edges: []tEdge{edge},
		listeners: []tListener{{proto: "tcp", addr: "0.0.0.0", port: 8080, svc: "app", unit: "app.service", comm: "puma"},
			{proto: "udp", addr: "0.0.0.0", port: 68}}}
	consume(t, c, sink, ta)
	c.flush(context.Background())
	if len(st.writes) != 1 {
		t.Fatalf("%d writes", len(st.writes))
	}
	h := st.writes[0]
	if h.key != hostKey("m1", "app-01") || h.machineID != "m1" || len(h.edges) != 1 || len(h.listeners) != 2 ||
		len(h.processes) != 1 || len(h.addrs) != 1 || len(h.sessions) != 1 {
		t.Fatalf("changes = %+v", h)
	}
	if s := h.sessions[t0.Add(-time.Hour)]; s == nil || !s.lastHeartbeat.Equal(ta.time) || s.netnsScope != "all" {
		t.Errorf("session = %+v", s)
	}
	for k, l := range h.listeners {
		if k.port == 68 && l.proc != (procKey{}) {
			t.Errorf("a listener without owner has a process: %+v", l)
		}
	}

	// The edge is still sent but idle: it is not written again.
	*now = now.Add(15 * time.Second)
	ta.time = ta.time.Add(15 * time.Second)
	ta.edges[0].last = t0.Add(15 * time.Second)
	consume(t, c, sink, ta)
	c.flush(context.Background())
	if h := st.writes[1]; len(h.edges) != 0 || len(h.sessions) != 1 {
		t.Errorf("idle edge written again: %+v", h)
	}

	// A failed write is retried with the newer changes merged.
	st.fail = true
	ta.time = ta.time.Add(15 * time.Second)
	ta.edges[0].last = ta.time
	consume(t, c, sink, ta)
	c.flush(context.Background())
	st.fail = false
	ta.time = ta.time.Add(15 * time.Second)
	ta.edges[0].last = ta.time
	consume(t, c, sink, ta)
	c.flush(context.Background())
	h = st.writes[len(st.writes)-1]
	for _, s := range h.edges {
		if !s.first.Equal(t0.Add(15*time.Second)) || !s.last.Equal(ta.time) {
			t.Errorf("merged edge span = %+v", s)
		}
	}
}

func TestMigrateOnStart(t *testing.T) {
	c, st, _, _ := testConnector(t, func(cfg *Config) { cfg.Postgres.Migrate = true })
	if st.migrated != 1 || !c.migrated {
		t.Errorf("migrated %d times", st.migrated)
	}
}

func TestConfigValidate(t *testing.T) {
	ok := createDefaultConfig()
	ok.Postgres.DSNFile = "/etc/shawk/postgres-dsn"
	ok.PeerCIDRs = map[string]string{"office-lan": "192.168.10.0/24"}
	if err := ok.Validate(); err != nil {
		t.Errorf("valid config: %v", err)
	}
	for name, mod := range map[string]func(*Config){
		"no dsn":            func(c *Config) { c.Postgres.DSNFile = "" },
		"both dsn":          func(c *Config) { c.Postgres.DSN = "postgres://x" },
		"no write interval": func(c *Config) { c.WriteInterval = 0 },
		"short ttl":         func(c *Config) { c.IdleTTL = time.Second },
		"no peers":          func(c *Config) { c.MaxPeers = 0 },
		"bad cidr":          func(c *Config) { c.PeerCIDRs = map[string]string{"x": "10.0.0.0/33"} },
		"reserved name":     func(c *Config) { c.PeerCIDRs = map[string]string{"~agent": "10.0.0.0/8"} },
	} {
		c := *ok
		mod(&c)
		if err := c.Validate(); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestNarrowestCIDRWins(t *testing.T) {
	ps, err := parsePeerCIDRs(map[string]string{"wide": "10.0.0.0/8", "narrow": "10.1.0.0/16", "host": "10.1.2.3/32"})
	if err != nil {
		t.Fatal(err)
	}
	r := newResolver(ps)
	for addr, want := range map[string]string{"10.1.2.3": "host", "10.1.9.9": "narrow", "10.9.9.9": "wide",
		"172.16.0.1": "~unresolved", "100.64.0.1": "~unresolved", "fd00::1": "~unresolved", "2001:db8::1": "~external"} {
		if got := r.classify(addrOf(addr)); got != want {
			t.Errorf("classify(%s) = %s, want %s", addr, got, want)
		}
	}
}
