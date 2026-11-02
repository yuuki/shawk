package shawkconnector

import (
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"go.opentelemetry.io/collector/confmap"
	"go.yaml.in/yaml/v3"
)

// Tests of translations of addresses (#107).

func TestParseEndpoint(t *testing.T) {
	for _, c := range []struct {
		in   string
		want string
		port uint16
	}{
		{"10.0.0.1", "10.0.0.1/32", 0},
		{" 10.0.0.1:5432 ", "10.0.0.1/32", 5432},
		{"10.0.0.7/24", "10.0.0.0/24", 0},
		{"10.0.0.0/24:80", "10.0.0.0/24", 80},
		{"2001:db8::1", "2001:db8::1/128", 0},
		{"[2001:db8::1]:443", "2001:db8::1/128", 443},
		{"[2001:db8::/64]:8080", "2001:db8::/64", 8080},
		{"2001:db8::/64", "2001:db8::/64", 0},
		{"[2001:db8::1]", "2001:db8::1/128", 0},
		{"::ffff:10.0.0.1", "10.0.0.1/32", 0},
		{"[::ffff:10.0.0.0/120]:80", "10.0.0.0/24", 80},
	} {
		p, port, err := parseEndpoint(c.in)
		if err != nil || p.String() != c.want || port != c.port {
			t.Errorf("parseEndpoint(%q) = %v, %d, %v; want %s, %d", c.in, p, port, err, c.want, c.port)
		}
	}
	for _, in := range []string{"", "10.0.0.1:", "10.0.0.1:0", "10.0.0.1:65536", "10.0.0.1:http", "[2001:db8::1",
		"[2001:db8::1]443", "[2001:db8::1]:", "fe80::1%eth0", "10.0.0.1/33", "host.example:80"} {
		if p, port, err := parseEndpoint(in); err == nil {
			t.Errorf("parseEndpoint(%q) = %v, %d; want an error", in, p, port)
		}
	}
}

func TestParseTranslations(t *testing.T) {
	ts, err := parseTranslations(map[string]TranslationConfig{
		"pg": {Virtual: []string{"10.0.100.1:5432", "10.0.100.1:5432"}, Backends: []string{"10.0.1.10", "10.0.2.0/24:6432"},
			Transport: "tcp"},
		"web": {Virtual: []string{"10.0.100.2:80", "[2001:db8::2]:80"}, Backends: []string{"10.0.1.20:8080"},
			Sources: []string{"10.0.100.250", "10.0.100.240/29"}},
		// Every port of a virtual address, to the same port of the backends;
		// the same address may take a port in another translation of
		// another transport.
		"dns": {Virtual: []string{"10.0.100.1"}, Backends: []string{"10.0.1.53"}, Transport: "udp"},
	})
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, r := range translationRows(ts) {
		got = append(got, fmt.Sprintf("%s %s %s %s %d", r.name, r.side, r.proto, r.prefix, r.port))
	}
	want := []string{
		"dns virtual udp 10.0.100.1/32 0",
		"dns backend udp 10.0.1.53/32 0",
		"pg virtual tcp 10.0.100.1/32 5432",
		"pg backend tcp 10.0.1.10/32 0",
		"pg backend tcp 10.0.2.0/24 6432",
		"web virtual tcp 10.0.100.2/32 80",
		"web virtual tcp 2001:db8::2/128 80",
		"web backend tcp 10.0.1.20/32 8080",
		"web source tcp 10.0.100.250/32 0",
		"web source tcp 10.0.100.240/29 0",
		"web virtual udp 10.0.100.2/32 80",
		"web virtual udp 2001:db8::2/128 80",
		"web backend udp 10.0.1.20/32 8080",
		"web source udp 10.0.100.250/32 0",
		"web source udp 10.0.100.240/29 0",
	}
	if !slices.Equal(got, want) {
		t.Errorf("rows:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}

	for name, c := range map[string]map[string]TranslationConfig{
		"no virtual":         {"a": {Backends: []string{"10.0.0.1"}}},
		"no backend":         {"a": {Virtual: []string{"10.0.0.1:80"}}},
		"virtual range":      {"a": {Virtual: []string{"10.0.0.0/24:80"}, Backends: []string{"10.0.1.1"}}},
		"unspecified":        {"a": {Virtual: []string{"0.0.0.0:80"}, Backends: []string{"10.0.1.1"}}},
		"port of every port": {"a": {Virtual: []string{"10.0.0.1"}, Backends: []string{"10.0.1.1:80"}}},
		"source port":        {"a": {Virtual: []string{"10.0.0.1:80"}, Backends: []string{"10.0.1.1"}, Sources: []string{"10.0.2.1:80"}}},
		"transport":          {"a": {Virtual: []string{"10.0.0.1:80"}, Backends: []string{"10.0.1.1"}, Transport: "sctp"}},
		"invalid backend":    {"a": {Virtual: []string{"10.0.0.1:80"}, Backends: []string{"db.example"}}},
		"no name":            {" ": {Virtual: []string{"10.0.0.1:80"}, Backends: []string{"10.0.1.1"}}},
		"same endpoint": {
			"a": {Virtual: []string{"10.0.0.1:80"}, Backends: []string{"10.0.1.1"}},
			"b": {Virtual: []string{"10.0.0.1:80"}, Backends: []string{"10.0.1.2"}, Transport: "tcp"},
		},
		"every port overlaps a port": {
			"a": {Virtual: []string{"10.0.0.1"}, Backends: []string{"10.0.1.1"}, Transport: "tcp"},
			"b": {Virtual: []string{"10.0.0.1:443"}, Backends: []string{"10.0.1.2"}},
		},
	} {
		if _, err := parseTranslations(c); err == nil {
			t.Errorf("%s: no error", name)
		}
	}
}

// TestTranslationsConfig: translations are read from the configuration of
// the collector and checked by Validate.
func TestTranslationsConfig(t *testing.T) {
	var raw map[string]any
	if err := yaml.Unmarshal([]byte(`
postgres:
  dsn: postgres://unused
translations:
  postgres-vip:
    virtual: [10.0.100.1:5432]
    backends: [10.0.1.0/24]
    transport: tcp
  web-lb:
    virtual: ["10.0.100.2:80", "[2001:db8::2]:80"]
    backends: [10.0.1.20:8080]
    sources: [10.0.100.250]
`), &raw); err != nil {
		t.Fatal(err)
	}
	cfg := createDefaultConfig()
	if err := confmap.NewFromStringMap(raw).Unmarshal(cfg); err != nil {
		t.Fatal(err)
	}
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	want := map[string]TranslationConfig{
		"postgres-vip": {Virtual: []string{"10.0.100.1:5432"}, Backends: []string{"10.0.1.0/24"}, Transport: "tcp"},
		"web-lb": {Virtual: []string{"10.0.100.2:80", "[2001:db8::2]:80"}, Backends: []string{"10.0.1.20:8080"},
			Sources: []string{"10.0.100.250"}},
	}
	if !maps.EqualFunc(cfg.Translations, want, func(a, b TranslationConfig) bool {
		return slices.Equal(a.Virtual, b.Virtual) && slices.Equal(a.Backends, b.Backends) &&
			slices.Equal(a.Sources, b.Sources) && a.Transport == b.Transport
	}) {
		t.Errorf("translations = %+v", cfg.Translations)
	}
	cfg.Translations["broken"] = TranslationConfig{Virtual: []string{"10.0.100.3"}, Backends: []string{"10.0.1.1:80"}}
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "broken") {
		t.Errorf("Validate = %v", err)
	}
}

// TestPackagedTranslationsExample: the example of translations commented
// out in the packaged configuration is valid.
func TestPackagedTranslationsExample(t *testing.T) {
	b, err := os.ReadFile(filepath.Join(packaging, "collector/config.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	var lines []string
	in := false
	for _, l := range strings.Split(string(b), "\n") {
		switch {
		case strings.HasPrefix(l, "    # translations:"):
			in = true
		case in && !strings.HasPrefix(l, "    #"):
			in = false
		}
		if in {
			lines = append(lines, strings.Replace(l, "# ", "", 1))
		}
	}
	if len(lines) < 2 {
		t.Fatal("no example of translations")
	}
	var raw map[string]any
	if err := yaml.Unmarshal([]byte(strings.Join(lines, "\n")), &raw); err != nil {
		t.Fatal(err)
	}
	cfg := createDefaultConfig()
	cfg.Postgres.DSN = "postgres://unused"
	if err := confmap.NewFromStringMap(raw).Unmarshal(cfg); err != nil {
		t.Fatal(err)
	}
	if err := cfg.Validate(); err != nil {
		t.Error(err)
	}
	if ts := must(parseTranslations(cfg.Translations)); len(ts) != 2 || len(ts[1].sources) != 1 {
		t.Errorf("translations = %+v", ts)
	}
}

// translationAgents are a client host and two backends of a DNAT virtual
// address, and a backend behind a relay with a source and another port.
func translationAgents(ts time.Time) (app, db1, db2, web tAgent) {
	app = tAgent{host: "app-01", addrs: []string{"127.0.0.1", "10.0.0.11"}, time: ts,
		edges: []tEdge{
			{role: "client", proto: "tcp", local: "10.0.0.11", peer: "10.0.100.1", port: 5432, svc: "app", ns: "shop", comm: "puma", opened: 4},
			{role: "client", proto: "tcp", local: "10.0.0.11", peer: "10.0.100.2", port: 80, svc: "app", ns: "shop", comm: "puma", opened: 2},
			// A virtual address that nothing behind listens on yet.
			{role: "client", proto: "tcp", local: "10.0.0.11", peer: "10.0.100.3", port: 443, svc: "app", ns: "shop", comm: "puma", opened: 1},
		}}
	db := func(host, addr string, opened int64) tAgent {
		return tAgent{host: host, addrs: []string{"127.0.0.1", addr}, time: ts,
			listeners: []tListener{{proto: "tcp", addr: "0.0.0.0", port: 5432, svc: "postgres", unit: "postgresql.service", comm: "postgres"}},
			edges: []tEdge{{role: "server", proto: "tcp", local: addr, peer: "10.0.0.11", port: 5432, svc: "postgres",
				unit: "postgresql.service", comm: "postgres", opened: opened}}}
	}
	db1, db2 = db("db-01", "10.0.1.10", 3), db("db-02", "10.0.1.11", 1)
	web = tAgent{host: "web-01", addrs: []string{"127.0.0.1", "10.0.1.20"}, time: ts,
		listeners: []tListener{{proto: "tcp", addr: "10.0.1.20", port: 8080, svc: "web", unit: "web.service", comm: "web"}},
		edges: []tEdge{{role: "server", proto: "tcp", local: "10.0.1.20", peer: "10.0.100.250", port: 8080, svc: "web",
			unit: "web.service", comm: "web", opened: 9}}}
	return app, db1, db2, web
}

func translationConfig(cfg *Config) {
	cfg.PeerCIDRs = map[string]string{"lb": "10.0.100.240/28"}
	cfg.Translations = map[string]TranslationConfig{
		"postgres-vip": {Virtual: []string{"10.0.100.1:5432"}, Backends: []string{"10.0.1.10", "10.0.1.11", "10.0.1.12"}, Transport: "tcp"},
		"web-lb":       {Virtual: []string{"10.0.100.2:80"}, Backends: []string{"10.0.1.20:8080"}, Sources: []string{"10.0.100.250"}},
		"api-lb":       {Virtual: []string{"10.0.100.3:443"}, Backends: []string{"10.0.3.0/24:8443"}},
	}
}

// TestTranslatedPeerNames: the peer of a client edge to a virtual address is
// the service of its backends, on their port; the peer of a server edge
// behind a translation that keeps the address of the client is the client
// service; behind a relay with sources, it is named after the source.
func TestTranslatedPeerNames(t *testing.T) {
	c, st, sink, now := testConnector(t, translationConfig)
	ts := t0.Add(15 * time.Second)
	app, db1, db2, web := translationAgents(ts)
	consume(t, c, sink, db1)
	consume(t, c, sink, db2)
	consume(t, c, sink, web)
	out := consume(t, c, sink, app)

	got := map[string]string{}
	for _, s := range find(out, metricConnOpened, "shop/app", "*", roleClient, "") {
		got[fmt.Sprintf("%s:%d", s.peer, s.port)] = fmt.Sprintf("%v %v", s.value, s.agent)
	}
	// The backends of api-lb are not known yet.
	want := map[string]string{"postgres:5432": "4 true", "web:8080": "2 true", "~unresolved:443": "1 false"}
	if !maps.Equal(got, want) {
		t.Errorf("client peers = %v, want %v", got, want)
	}

	// The next interval of the servers, now that the client is known. The
	// connections db-01 accepted before were named ~unresolved; those since
	// go to the client service, whose agent counts them.
	db1.time, web.time = ts.Add(15*time.Second), ts.Add(15*time.Second)
	db1.edges[0].opened, web.edges[0].opened = 5, 11
	out = consume(t, c, sink, db1)
	got = map[string]string{}
	for _, s := range find(out, metricConnOpened, "postgres", "*", roleServer, "") {
		got[fmt.Sprintf("%s:%d", s.peer, s.port)] = fmt.Sprintf("%v %v", s.value, s.agent)
	}
	if want := map[string]string{"~unresolved:5432": "3 false", "shop/app:5432": "2 true"}; !maps.Equal(got, want) {
		t.Errorf("server peers of db-01 = %v, want %v", got, want)
	}
	out = consume(t, c, sink, web)
	got = map[string]string{}
	for _, s := range find(out, metricConnOpened, "web", "*", roleServer, "") {
		got[fmt.Sprintf("%s:%d", s.peer, s.port)] = fmt.Sprintf("%v %v", s.value, s.agent)
	}
	// The server sees the relay, which may forward clients without an agent:
	// it counts the connections, named after the range of the relay.
	if want := map[string]string{"lb:8080": "11 false"}; !maps.Equal(got, want) {
		t.Errorf("server peers of web-01 = %v, want %v", got, want)
	}

	// A range of backends, from what PostgreSQL holds.
	st.mu.Lock()
	st.rows.endpoints = append(st.rows.endpoints,
		endpointRow{key: endpointKey{addrOf("10.0.3.7"), 8443, "tcp"}, endpoint: endpoint{host: "h-api", service: "api", exact: true, lastSeen: *now}},
		endpointRow{key: endpointKey{addrOf("10.0.4.7"), 8443, "tcp"}, endpoint: endpoint{host: "h-other", service: "other", exact: true, lastSeen: *now}},
		endpointRow{key: endpointKey{addrOf("10.0.3.8"), 443, "tcp"}, endpoint: endpoint{host: "h-api", service: "wrong-port", exact: true, lastSeen: *now}})
	st.mu.Unlock()
	c.prepare(t.Context())
	app.time = ts.Add(15 * time.Second)
	out = consume(t, c, sink, app)
	var peers []string
	for _, s := range find(out, metricConnOpened, "shop/app", "*", roleClient, "") {
		peers = append(peers, fmt.Sprintf("%s:%d", s.peer, s.port))
	}
	slices.Sort(peers)
	if want := []string{"api:8443", "postgres:5432", "web:8080", "~unresolved:443"}; !slices.Equal(peers, want) {
		// ~unresolved:443 keeps its series until its idle TTL.
		t.Errorf("client peers = %v, want %v", peers, want)
	}

	// The translations are written to PostgreSQL.
	st.mu.Lock()
	var names []string
	for _, tr := range st.trans {
		names = append(names, tr.name)
	}
	st.mu.Unlock()
	if !slices.Equal(names, []string{"api-lb", "postgres-vip", "web-lb"}) {
		t.Errorf("translations written = %v", names)
	}
}

// TestTranslationPrecedence: a virtual address that a host with an agent
// serves itself names that service, not the backends of the translation.
func TestTranslationPrecedence(t *testing.T) {
	c, _, sink, _ := testConnector(t, translationConfig)
	ts := t0.Add(15 * time.Second)
	app, db1, _, _ := translationAgents(ts)
	consume(t, c, sink, db1)
	consume(t, c, sink, tAgent{host: "lb-01", addrs: []string{"127.0.0.1", "10.0.100.1"}, time: ts,
		listeners: []tListener{{proto: "tcp", addr: "10.0.100.1", port: 5432, svc: "haproxy", comm: "haproxy"}}})
	out := consume(t, c, sink, app)
	if s := find(out, metricConnOpened, "shop/app", "haproxy", roleClient, ""); len(s) != 1 || s[0].port != 5432 {
		t.Errorf("client series to the virtual address = %+v", find(out, metricConnOpened, "shop/app", "*", roleClient, ""))
	}
}

// TestTranslatedClientPorts: the server side finds the client service on
// the virtual port that reaches the port of the server.
func TestTranslatedClientPorts(t *testing.T) {
	ts, err := parseTranslations(map[string]TranslationConfig{
		"fixed": {Virtual: []string{"10.0.100.1:80", "10.0.100.1:8000"}, Backends: []string{"10.0.1.0/24:8080"}},
		"same":  {Virtual: []string{"10.0.100.2"}, Backends: []string{"10.0.2.10"}},
		"snat":  {Virtual: []string{"10.0.100.3:80"}, Backends: []string{"10.0.3.10:80"}, Sources: []string{"10.0.100.250"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	r := newResolver(nil, ts)
	now := t0
	client := func(server string, port uint16, svc string) {
		r.localClients[clientKey{addrOf("10.0.0.11"), addrOf(server), port, "tcp"}] = map[endpoint]time.Time{
			{host: "app-01", service: svc, exact: true}: now}
	}
	client("10.0.100.1", 8000, "app-8000")
	client("10.0.100.2", 5432, "app-pg")
	client("10.0.100.3", 80, "app-snat")
	for _, c := range []struct {
		local string
		port  uint16
		want  string
	}{
		{"10.0.1.10", 8080, "app-8000"},
		{"10.0.1.10", 80, "~unresolved"}, // not the port of the backends
		{"10.0.2.10", 5432, "app-pg"},
		{"10.0.2.10", 6379, "~unresolved"}, // no client edge to that port
		{"10.0.3.10", 80, "~unresolved"},   // the server sees the relay
		{"10.0.9.10", 8080, "~unresolved"}, // not a backend
	} {
		id := &edgeID{role: roleServer, proto: "tcp", local: addrOf(c.local), peer: addrOf("10.0.0.11"), port: c.port}
		if p := r.peer("db", id, now); p.name != c.want {
			t.Errorf("%s:%d: peer %q, want %q", c.local, c.port, p.name, c.want)
		}
	}
	// The client side of the same translations, without endpoints, keeps
	// the port it connected to and is named after the virtual address.
	id := &edgeID{role: roleClient, proto: "tcp", local: addrOf("10.0.0.11"), peer: addrOf("10.0.100.1"), port: 80}
	if p := r.peer("app-01", id, now); p.name != peerUnresolved || p.port != 0 {
		t.Errorf("client peer = %+v", p)
	}
	// A range is scanned once until the next load or expiry: a server
	// learned since is named from then on.
	r.localEndpoints[endpointKey{addrOf("10.0.1.33"), 8080, "tcp"}] = map[endpoint]time.Time{{host: "web-01", service: "web", exact: true}: now}
	if p := r.peer("app-01", id, now); p.name != peerUnresolved {
		t.Errorf("client peer before the expiry = %+v", p)
	}
	r.expire(now.Add(-time.Hour), now)
	if p := r.peer("app-01", id, now); p.name != "web" || p.port != 8080 || p.agent {
		t.Errorf("client peer after the expiry = %+v", p)
	}
	// The most recently seen service in the range wins.
	r.localEndpoints[endpointKey{addrOf("10.0.1.34"), 8080, "tcp"}] = map[endpoint]time.Time{{host: "web-02", service: "aaa", exact: true}: now.Add(time.Second)}
	r.load(peerRows{}, now)
	if p := r.peer("app-01", id, now); p.name != "aaa" {
		t.Errorf("client peer after the load = %+v", p)
	}
}
