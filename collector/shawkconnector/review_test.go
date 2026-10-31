package shawkconnector

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	"go.opentelemetry.io/collector/pdata/pmetric"
)

// The tests in this file reproduce the findings of an adversarial review
// and check their fixes.

func opened(t *testing.T, out []series, job, peer, role string) float64 {
	t.Helper()
	s := find(out, metricConnOpened, job, peer, role, "")
	if len(s) != 1 {
		t.Fatalf("connection.opened of %s to %s = %v", job, peer, s)
	}
	return s[0].value
}

// TestLateAndDuplicateRequests: a request processed after a newer one, or
// twice, was taken for a counter reset and its whole value added again.
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

// TestPeerAgentAliveWindow: shawk.peer.agent stayed true for the idle TTL
// after the client agent stopped, and an address that moved to a renamed
// host counted as shared.
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

// TestPeerAgentCoverage: a peer whose agent traces no UDP, or one network
// namespace only, does not record the other side of the edge.
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
		{"10.0.0.22", "tcp", false},
		{"10.0.0.23", "udp", true},
	} {
		p := c.resolver.peer("dns-01", &edgeID{role: roleServer, proto: tc.proto, local: addrOf("10.0.0.53"),
			peer: addrOf(tc.peer), port: 53}, *now)
		if p.agent != tc.want {
			t.Errorf("%s %s: agent = %v, want %v", tc.peer, tc.proto, p.agent, tc.want)
		}
	}
	// Loopback stays within a namespace the agent sees.
	p := c.resolver.peer("onens-01", &edgeID{role: roleServer, proto: "tcp", local: addrOf("127.0.0.1"),
		peer: addrOf("127.0.0.1"), port: 6379}, *now)
	if !p.agent {
		t.Error("loopback peer of an agent tracing one namespace")
	}
}

// TestDeterministicNames: candidates of equal rank were chosen in the order
// of a map.
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

// TestRejectedRowsAreDropped: changes that PostgreSQL rejects were kept and
// written again at every flush, blocking the host for good.
func TestRejectedRowsAreDropped(t *testing.T) {
	c, st, sink, _ := testConnector(t, nil)
	consume(t, c, sink, tAgent{host: "app-01", addrs: []string{"fe80::1%eth0", "10.0.0.11"}, time: t0.Add(15 * time.Second)})
	h := c.changes.pending[hostKey("", "app-01")]
	for a := range h.addrs {
		if a.Zone() != "" {
			t.Errorf("address with a zone kept: %s", a)
		}
	}
	st.err = &pgconn.PgError{Code: "22P02", Message: "invalid input syntax"}
	c.flush(context.Background())
	if n := c.changes.pendingSize(); n != 0 {
		t.Errorf("%d rejected rows kept", n)
	}
	consume(t, c, sink, tAgent{host: "app-01", addrs: []string{"10.0.0.11"}, time: t0.Add(30 * time.Second)})
	st.err = fmt.Errorf("connection refused")
	c.flush(context.Background())
	if n := c.changes.pendingSize(); n == 0 {
		t.Error("changes dropped after a transient failure")
	}
}

// TestBaselineWithClockSkew: the start of an input series by the clock of
// the agent was compared with the start of the connector by its own clock.
func TestBaselineWithClockSkew(t *testing.T) {
	c, _, sink, now := testConnector(t, nil)
	c.agg.started = t0
	*now = t0.Add(5 * time.Minute)
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

func TestConfigReviewFixes(t *testing.T) {
	cfg := createDefaultConfig()
	cfg.Postgres.DSN = "postgres://x"
	cfg.PeerCIDRs = map[string]string{"lan": "10.0.0.0/8", "office": "10.0.0.0/8"}
	if err := cfg.Validate(); err == nil {
		t.Error("the same prefix under two names was accepted")
	}
	cfg.PeerCIDRs = nil
	cfg.WriteInterval = time.Second
	cfg.IdleTTL = 30 * time.Second
	if err := cfg.Validate(); err == nil {
		t.Error("an idle_ttl shorter than 2m was accepted")
	}
}

// BenchmarkRequestWithFleet measures one request of a host while the
// connector holds the outputs of a fleet; the cost used to grow with the
// number of hosts.
func BenchmarkRequestWithFleet(b *testing.B) {
	for _, hosts := range []int{10, 10000} {
		b.Run(fmt.Sprintf("hosts=%d", hosts), func(b *testing.B) {
			a := newAggregator(15*time.Minute, 50, false, t0.Add(-time.Hour))
			r := newResolver(nil)
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
