package shawkconnector

import (
	"context"
	"net/netip"
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
