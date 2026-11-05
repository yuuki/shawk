package shawkconnector

import (
	"context"
	"maps"
	"net/netip"
	"reflect"
	"slices"
	"testing"
	"time"
)

// TestPeerAgentAliveWindow: shawk.peer.agent turns false within the alive
// window after the client agent stops, rather than after the idle TTL, and
// an address that moves to a renamed host does not count as shared.
func TestPeerAgentAliveWindow(t *testing.T) {
	c, _, sink, now := testConnector(t, nil)
	server := func() series {
		out := consume(t, c, sink, tAgent{host: "db-01", addrs: []string{"10.0.0.10"}, time: *now,
			edges: []tEdge{{role: "server", proto: "tcp", local: "10.0.0.10", peer: "10.0.0.11", port: 5432, svc: "db", comm: "db", opened: 1}}})
		s := find(out, metricConnOpened, "db", "*", roleServer, "")
		if len(s) == 0 {
			t.Fatal("no server series")
		}
		return s[len(s)-1]
	}
	advance := func(d time.Duration) {
		*now = now.Add(d)
		c.resolver.expire(now.Add(-c.cfg.IdleTTL), *now)
	}
	consume(t, c, sink, tAgent{host: "app-01", addrs: []string{"10.0.0.11"}, time: *now})
	if s := server(); !s.agent {
		t.Fatalf("client with an agent: %+v", s)
	}
	// The agent of app-01 stops.
	advance(4 * time.Minute)
	if s := server(); !s.agent {
		t.Errorf("4 minutes after the client agent stopped: %+v", s)
	}
	advance(2 * time.Minute)
	if p := c.resolver.peer("db-01", &edgeID{role: roleServer, proto: "tcp", local: addrOf("10.0.0.10"),
		peer: addrOf("10.0.0.11"), port: 5432}, *now); p.agent {
		t.Error("6 minutes after the client agent stopped, the peer still counts as having an agent")
	}

	// app-01 is rebuilt as app-02 with the same address: a move, not a
	// shared address.
	consume(t, c, sink, tAgent{host: "app-02", addrs: []string{"10.0.0.11"}, time: *now})
	advance(time.Minute)
	consume(t, c, sink, tAgent{host: "app-02", addrs: []string{"10.0.0.11"}, time: *now})
	p := c.resolver.peer("db-01", &edgeID{role: roleServer, proto: "tcp", local: addrOf("10.0.0.10"),
		peer: addrOf("10.0.0.11"), port: 5432}, *now)
	if !p.agent {
		t.Errorf("the new holder of the address has an agent: %+v", p)
	}
}

// TestPeerAgentCoverage: a peer whose agent traces no UDP does not record
// the other side of a UDP edge. An agent tracing one network namespace
// reports the addresses of that namespace only, which it records.
func TestPeerAgentCoverage(t *testing.T) {
	c, _, sink, now := testConnector(t, nil)
	consume(t, c, sink, tAgent{host: "noudp-01", addrs: []string{"10.0.0.21"}, time: *now, noUDP: true})
	consume(t, c, sink, tAgent{host: "onens-01", addrs: []string{"10.0.0.22"}, time: *now, netnsScope: "4026532001"})
	consume(t, c, sink, tAgent{host: "full-01", addrs: []string{"10.0.0.23"}, time: *now})
	for _, tc := range []struct {
		peer, proto string
		want        bool
	}{
		{"10.0.0.21", "tcp", true},
		{"10.0.0.21", "udp", false},
		{"10.0.0.22", "tcp", true},
		{"10.0.0.23", "udp", true},
	} {
		p := c.resolver.peer("dns-01", &edgeID{role: roleServer, proto: tc.proto, local: addrOf("10.0.0.53"),
			peer: addrOf(tc.peer), port: 53}, *now)
		if p.agent != tc.want {
			t.Errorf("%s %s: agent = %v, want %v", tc.peer, tc.proto, p.agent, tc.want)
		}
	}
	// Loopback UDP on a host whose agent traces no UDP.
	p := c.resolver.peer(hostKey("", "noudp-01"), &edgeID{role: roleServer, proto: "udp", local: addrOf("127.0.0.1"),
		peer: addrOf("127.0.0.1"), port: 53}, *now)
	if p.agent {
		t.Error("loopback UDP peer of an agent that traces no UDP")
	}
}

// TestPartialIntervalIsNotAlive: the addresses of a host whose final
// requests never arrive do not keep its agent alive for its peers, since it
// emits nothing.
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

// TestDBSnapshotDuringOutage: agents learned from PostgreSQL do not age
// with the clock while the database cannot be read, so that their peers
// keep shawk.peer.agent and the recording rules do not count them twice.
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

// TestDeterministicNames: of candidates of equal rank, the same one is
// always chosen, whatever the order of a map.
func TestDeterministicNames(t *testing.T) {
	c, _, sink, now := testConnector(t, nil)
	// Two services on one host listen on all addresses of the port, e.g. in
	// two network namespaces.
	consume(t, c, sink, tAgent{host: "node-01", addrs: []string{"10.0.0.31"}, time: *now,
		listeners: []tListener{
			{proto: "tcp", addr: "0.0.0.0", port: 8080, svc: "b-svc", comm: "b"},
			{proto: "tcp", addr: "0.0.0.0", port: 8080, svc: "a-svc", comm: "a"},
		}})
	id := &edgeID{role: roleClient, proto: "tcp", local: addrOf("10.0.0.40"), peer: addrOf("10.0.0.31"), port: 8080}
	for i := range 50 {
		if p := c.resolver.peer("client-01", id, *now); p.name != "a-svc" {
			t.Fatalf("lookup %d = %s", i, p.name)
		}
	}
	// A server edge observed the address on a socket: it wins.
	consume(t, c, sink, tAgent{host: "node-01", addrs: []string{"10.0.0.31"}, time: *now,
		edges: []tEdge{{role: "server", proto: "tcp", local: "10.0.0.31", peer: "10.0.0.40", port: 8080, svc: "b-svc", comm: "b", opened: 1}}})
	if p := c.resolver.peer("client-01", id, *now); p.name != "b-svc" {
		t.Errorf("with a server edge = %s, want b-svc", p.name)
	}
}

// TestUnknownListenerNotLearned: peers are not named after a listener
// without a known owner (~unknown), which PostgreSQL does not keep, so that
// names do not differ between connectors and restarts.
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

// TestPeerHolderWithoutAgent: an address that one host alone holds is that
// host's even while its agent is not alive, since PostgreSQL keeps when the
// address was last seen apart from the last heartbeat of the agent. The
// clients that other hosts report at the address name no peer, also
// behind a translation, and the peer has no agent that records the other
// side.
func TestPeerHolderWithoutAgent(t *testing.T) {
	r := newResolver(nil, must(parseTranslations(map[string]TranslationConfig{
		"vip": {Virtual: []string{"10.0.100.1:5432"}, Backends: []string{"10.0.1.10"}},
	})))
	now := t0
	client := func(host, service string, seen time.Time) clientRow {
		return clientRow{key: clientKey{addrOf("10.0.0.11"), addrOf("10.0.100.1"), 5432, "tcp"},
			endpoint: endpoint{host: host, service: service, exact: true, lastSeen: seen}}
	}
	r.load(peerRows{
		// app-01 last held the address a minute ago, but its agent sent no
		// heartbeat for 10 minutes.
		agents: []agentAddrRow{{addr: addrOf("10.0.0.11"), host: "app-01", seen: now.Add(-time.Minute),
			agent: agentHost{seen: now.Add(-10 * time.Minute), udpTraced: true, name: "app-01"}}},
		// A client edge that another host reports at the address, more
		// recent: a socket it no longer has.
		clients: []clientRow{client("app-01", "app", now.Add(-time.Minute)), client("other-01", "other", now)},
	}, now)
	p := r.peer("db-01", &edgeID{role: roleServer, proto: "tcp", local: addrOf("10.0.1.10"), peer: addrOf("10.0.0.11"),
		port: 5432}, now)
	if p.name != "app" || p.agent {
		t.Errorf("peer = %+v, want app without an agent", p)
	}
}

// TestPeerOnItsOwnHost: a peer at an address that only the host of the edge
// holds is on that host, whose agent records both sides of the edge: it
// folds neither, whatever it does with the local address.
func TestPeerOnItsOwnHost(t *testing.T) {
	r := newResolver(nil, nil)
	now := t0
	r.load(peerRows{agents: []agentAddrRow{{addr: addrOf("10.0.0.11"), host: "app-01", seen: now,
		agent: agentHost{seen: now, udpTraced: true, name: "app-01", fold: foldIn,
			internal: []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}}}}}, now)
	p := r.peer("app-01", &edgeID{role: roleClient, proto: "tcp", local: addrOf("192.0.2.7"), peer: addrOf("10.0.0.11"),
		port: 80}, now)
	if !p.agent || p.foldedBy != "" {
		t.Errorf("peer = %+v, want one with an agent that folds nothing", p)
	}
}

// learnBatch is a request of node-01, whose agent is ten seconds behind t0,
// with listeners, edges and translations of each kind that learn records.
func learnBatch() *hostBatch {
	app := process{unit: "app.service", comm: "app", service: "app"}
	job := process{unit: slurmJobUnit + "job_7", comm: "python", service: "python"}
	at := t0.Add(-10 * time.Second)
	b := &hostBatch{key: "node-01", hostname: "node-01.example", time: at,
		addrs:     []netip.Addr{addrOf("10.0.0.31"), addrOf("fd00::31"), addrOf("10.0.0.32")},
		udpTraced: true, peerFold: foldIn, peerInternal: []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")},
		edges: map[edgeID]*edgeInput{}, listeners: map[listenerID]*listenerInput{},
		translations: map[translationID]*translationInput{}}
	for _, id := range []listenerID{
		{proto: "tcp", addr: addrOf("10.0.0.31"), port: 80, process: app},
		{proto: "tcp", addr: addrOf("0.0.0.0"), port: 8080, process: job},
		{proto: "udp", addr: addrOf("::"), port: 53, process: app},
		{proto: "tcp", addr: addrOf("10.0.0.31"), port: 2049, process: process{service: unknownService}},
	} {
		b.listeners[id] = &listenerInput{id: id}
	}
	for _, id := range []edgeID{
		{role: roleServer, proto: "tcp", local: addrOf("10.0.0.31"), peer: addrOf("10.0.0.50"), port: 5432, process: app},
		{role: roleServer, proto: "tcp", local: addrOf("10.0.0.32"), peer: addrOf("0.0.0.0"), folded: true, port: 443,
			process: app},
		{role: roleClient, proto: "tcp", local: addrOf("10.0.0.31"), peer: addrOf("10.0.0.60"), port: 6379, process: job},
		{role: roleClient, proto: "tcp", local: addrOf("10.0.0.31"), peer: addrOf("0.0.0.0"), folded: true, port: 443,
			process: app},
	} {
		b.edges[id] = &edgeInput{id: id}
	}
	for _, x := range []translationInput{
		// A DNAT last used 30 seconds before the request.
		{id: translationID{proto: "tcp", netns: 4026532001, client: addrOf("10.0.0.70"), virtual: addrOf("10.96.0.1"),
			vport: 80, source: addrOf("10.0.0.70"), backend: addrOf("10.0.0.31"), bport: 8080}, last: at.Add(-30 * time.Second)},
		// A SNAT last used after the time of the request, and a DNAT
		// without a last use: both seen as of the request.
		{id: translationID{proto: "tcp", client: addrOf("10.0.0.71"), virtual: addrOf("10.96.0.2"), vport: 443,
			source: addrOf("10.0.0.254"), backend: addrOf("10.0.0.32"), bport: 8443}, last: at.Add(time.Second)},
		{id: translationID{proto: "udp", client: addrOf("10.0.0.72"), virtual: addrOf("10.96.0.10"), vport: 53,
			source: addrOf("10.0.0.72"), backend: addrOf("10.0.0.33"), bport: 53}},
	} {
		b.translations[x.id] = &x
	}
	return b
}

// learnedState is what learn records in a resolver.
type learnedState struct {
	endpoints      map[endpointKey]map[endpoint]time.Time
	served         map[clientKey]map[endpoint]time.Time
	clients        map[clientKey]map[endpoint]time.Time
	learned        map[learnedClientKey]map[learnedBackend]time.Time
	learnedServers map[learnedServerKey]map[learnedClient]time.Time
	inferred       map[string]int
	addrs          map[netip.Addr]map[string]time.Time
	agents         map[string]agentHost
	held           map[netip.Addr]map[string]time.Time
	names          map[string]string
}

func learnedStateOf(r *resolver) learnedState {
	return learnedState{r.localEndpoints, r.localServed, r.localClients, r.localLearned, r.localLearnedServers,
		r.inferred, r.localAddrs, r.localAgents, r.localHeld, r.localNames}
}

// wantLearned is what learn records of learnBatch: its endpoints, clients
// and, if final, addresses and agent seen at seen, its translations at
// translated (30 seconds before for the first), and, with peer_hosts, its
// holding the addresses at held.
func wantLearned(seen, translated, held time.Time, final, peerHosts bool) learnedState {
	const host = "node-01"
	at := func(e endpoint) map[endpoint]time.Time { return map[endpoint]time.Time{e: seen} }
	app, job := endpoint{host: host, service: "app", exact: true}, endpoint{host: host, service: slurmJobService, exact: true}
	inferredApp, inferredJob := endpoint{host: host, service: "app"}, endpoint{host: host, service: slurmJobService}
	w := learnedState{
		endpoints: map[endpointKey]map[endpoint]time.Time{
			{addrOf("10.0.0.31"), 80, "tcp"}:   at(app),
			{addrOf("10.0.0.31"), 8080, "tcp"}: at(inferredJob),
			{addrOf("10.0.0.32"), 8080, "tcp"}: at(inferredJob),
			{addrOf("10.0.0.31"), 53, "udp"}:   at(inferredApp),
			{addrOf("fd00::31"), 53, "udp"}:    at(inferredApp),
			{addrOf("10.0.0.32"), 53, "udp"}:   at(inferredApp),
			{addrOf("10.0.0.31"), 5432, "tcp"}: at(app),
			{addrOf("10.0.0.32"), 443, "tcp"}:  at(app),
		},
		served:  map[clientKey]map[endpoint]time.Time{{addrOf("10.0.0.50"), addrOf("10.0.0.31"), 5432, "tcp"}: at(app)},
		clients: map[clientKey]map[endpoint]time.Time{{addrOf("10.0.0.31"), addrOf("10.0.0.60"), 6379, "tcp"}: at(job)},
		learned: map[learnedClientKey]map[learnedBackend]time.Time{
			{"tcp", addrOf("10.0.0.70"), addrOf("10.96.0.1"), 80}: {
				{host, 4026532001, addrOf("10.0.0.70"), addrOf("10.0.0.31"), 8080}: translated.Add(-30 * time.Second)},
			{"tcp", addrOf("10.0.0.71"), addrOf("10.96.0.2"), 443}: {
				{host, 0, addrOf("10.0.0.254"), addrOf("10.0.0.32"), 8443}: translated},
			{"udp", addrOf("10.0.0.72"), addrOf("10.96.0.10"), 53}: {
				{host, 0, addrOf("10.0.0.72"), addrOf("10.0.0.33"), 53}: translated},
		},
		learnedServers: map[learnedServerKey]map[learnedClient]time.Time{
			{"tcp", addrOf("10.0.0.31"), 8080, addrOf("10.0.0.70")}: {
				{host, 4026532001, addrOf("10.96.0.1"), 80}: translated.Add(-30 * time.Second)},
			{"udp", addrOf("10.0.0.33"), 53, addrOf("10.0.0.72")}: {{host, 0, addrOf("10.96.0.10"), 53}: translated},
		},
		inferred: map[string]int{host: 5},
		addrs:    map[netip.Addr]map[string]time.Time{},
		agents:   map[string]agentHost{},
		held:     map[netip.Addr]map[string]time.Time{},
		names:    map[string]string{},
	}
	if !final {
		return w
	}
	for _, a := range []string{"10.0.0.31", "fd00::31", "10.0.0.32"} {
		w.addrs[addrOf(a)] = map[string]time.Time{host: seen}
	}
	w.agents[host] = agentHost{seen: seen, udpTraced: true, name: "node-01.example", fold: foldIn,
		internal: []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}}
	if peerHosts {
		for _, a := range []string{"10.0.0.31", "fd00::31", "10.0.0.32"} {
			w.held[addrOf(a)] = map[string]time.Time{host: held}
		}
		w.names[host] = "node-01.example"
	}
	return w
}

// TestLearn: a request records the endpoints of its listeners, on every
// address of the host of their family for those on an unspecified address;
// the endpoints of its server edges and the clients they served, unless
// folded; the client sides of its client edges that are not folded; and its
// translations, as long before now as their last use before the request.
// The processes of Slurm jobs are named as in the outputs. Only a request
// that closes an interval records the addresses of the host and its agent,
// and with peer_hosts that the host holds them. A request seen earlier
// than the one before, after a step of the clock, takes the endpoints and
// the agent back to then, not the translations or the holders.
func TestLearn(t *testing.T) {
	r := newResolver(nil, nil)
	r.peerHosts = true
	b := learnBatch()
	steps := []struct {
		name                  string
		now, translated, held time.Time
		final                 bool
	}{
		{"not final", t0, t0, time.Time{}, false},
		{"final", t0.Add(15 * time.Second), t0.Add(15 * time.Second), t0.Add(15 * time.Second), true},
		{"earlier", t0.Add(5 * time.Second), t0.Add(15 * time.Second), t0.Add(15 * time.Second), true},
	}
	for _, s := range steps {
		b.final = s.final
		r.learn(b, s.now)
		if got, want := learnedStateOf(r), wantLearned(s.now, s.translated, s.held, s.final, true); !reflect.DeepEqual(got, want) {
			t.Errorf("%s:\n got %+v\nwant %+v", s.name, got, want)
		}
	}

	// Without peer_hosts, the holders of addresses are not recorded.
	r = newResolver(nil, nil)
	r.learn(b, t0)
	if got, want := learnedStateOf(r), wantLearned(t0, t0, t0, true, false); !reflect.DeepEqual(got, want) {
		t.Errorf("without peer_hosts:\n got %+v\nwant %+v", got, want)
	}

	// A request without a time of the agent: its translations are seen now.
	r = newResolver(nil, nil)
	b.time = time.Time{}
	r.learn(b, t0)
	k := learnedClientKey{"tcp", addrOf("10.0.0.70"), addrOf("10.96.0.1"), 80}
	if got := r.localLearned[k]; len(got) != 1 || !slices.Equal(slices.Collect(maps.Values(got)), []time.Time{t0}) {
		t.Errorf("translation of a request without a time = %v, want seen at %v", got, t0)
	}
}

// TestLearnInferredBudget: of the endpoints inferred from the listeners of
// a request on unspecified addresses, max_series_per_host bounds those the
// request infers, whether new or seen again, counting the addresses of the
// other family that an IPv4 listener skips; listeners on an exact address
// count nothing.
func TestLearnInferredBudget(t *testing.T) {
	const host = "node-01"
	app := process{unit: "app.service", comm: "app", service: "app"}
	listen := func(addr string, port uint16) listenerID {
		return listenerID{proto: "tcp", addr: addrOf(addr), port: port, process: app}
	}
	batch := func(addrs []string, ls ...listenerID) *hostBatch {
		b := &hostBatch{key: host, listeners: map[listenerID]*listenerInput{}}
		for _, a := range addrs {
			b.addrs = append(b.addrs, addrOf(a))
		}
		for _, id := range ls {
			b.listeners[id] = &listenerInput{id: id}
		}
		return b
	}
	inferred := func(r *resolver) map[endpointKey]time.Time {
		out := map[endpointKey]time.Time{}
		for k, es := range r.localEndpoints {
			for e, at := range es {
				if !e.exact {
					out[k] = at
				}
			}
		}
		return out
	}

	// The IPv6 address that the IPv4 listener skips takes one of the two.
	r := newResolver(nil, nil)
	r.maxInferred = 2
	r.learn(batch([]string{"fd00::31", "10.0.0.31", "10.0.0.32"}, listen("0.0.0.0", 8080)), t0)
	if got, want := inferred(r), map[endpointKey]time.Time{{addrOf("10.0.0.31"), 8080, "tcp"}: t0}; !maps.Equal(got, want) {
		t.Errorf("IPv4 listener = %v, want %v", got, want)
	}

	// Two listeners share the bound of the request: seen again with a new
	// address first, the first listener takes it all, so that the endpoint
	// of the second is not seen again.
	r = newResolver(nil, nil)
	r.maxInferred = 2
	r.learn(batch([]string{"10.0.0.31"}, listen("0.0.0.0", 80), listen("0.0.0.0", 81)), t0)
	later := t0.Add(time.Minute)
	r.learn(batch([]string{"10.0.0.33", "10.0.0.31"}, listen("0.0.0.0", 80), listen("0.0.0.0", 81)), later)
	got := inferred(r)
	var times []time.Time
	for _, port := range []uint16{80, 81} {
		times = append(times, got[endpointKey{addrOf("10.0.0.31"), port, "tcp"}])
	}
	slices.SortFunc(times, time.Time.Compare)
	if len(got) != 2 || !slices.Equal(times, []time.Time{t0, later}) {
		t.Errorf("seen again = %v, want one of the two endpoints seen again", got)
	}

	// Listeners on exact addresses leave the bound to the others, in
	// whatever order the request has them.
	for range 20 {
		r = newResolver(nil, nil)
		r.maxInferred = 1
		ls := []listenerID{listen("0.0.0.0", 8080)}
		for port := range uint16(5) {
			ls = append(ls, listen("10.0.0.31", 80+port))
		}
		r.learn(batch([]string{"10.0.0.31"}, ls...), t0)
		if got := inferred(r); len(got) != 1 {
			t.Fatalf("with listeners on exact addresses = %v, want one inferred", got)
		}
	}
}
