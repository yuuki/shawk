package shawkconnector

import (
	"context"
	"testing"
	"time"
)

// Tests of what an agent reports at the addresses of other hosts.

// farFuture is a time an agent may send although no clock shows it.
var farFuture = time.Date(9999, 1, 1, 0, 0, 0, 0, time.UTC)

// TestEndpointAtAddressOfAnotherHost: a service that a host reports at an
// address that another live host holds alone, on a listener or a server
// edge and with a time far in the future, does not name the peers at that
// address. A host that also declares the address in host.ip makes it
// shared, and the peer is named after no host.
func TestEndpointAtAddressOfAnotherHost(t *testing.T) {
	c, _, sink, now := testConnector(t, nil)
	db := tAgent{host: "db-01", addrs: []string{"10.0.0.5"}, time: *now,
		listeners: []tListener{{proto: "tcp", addr: "0.0.0.0", port: 5432, svc: "postgres", comm: "postgres"}}}
	evil := tAgent{host: "evil-01", addrs: []string{"10.0.0.66"}, time: *now,
		listeners: []tListener{{proto: "tcp", addr: "10.0.0.5", port: 5432, svc: "evil", comm: "evil", last: farFuture}},
		edges: []tEdge{{role: "server", proto: "tcp", local: "10.0.0.5", peer: "10.0.0.11", port: 5432, svc: "evil",
			comm: "evil", opened: 1, last: farFuture}}}
	app := func(opened int64) tAgent {
		return tAgent{host: "app-01", addrs: []string{"10.0.0.11"}, time: *now,
			edges: []tEdge{{role: "client", proto: "tcp", local: "10.0.0.11", peer: "10.0.0.5", port: 5432, svc: "app",
				comm: "app", opened: opened}}}
	}
	consume(t, c, sink, db)
	consume(t, c, sink, evil)
	out := consume(t, c, sink, app(1))
	if s := find(out, metricConnOpened, "app", "postgres", roleClient, ""); len(s) != 1 || !s[0].agent {
		t.Errorf("client series = %+v, want postgres with an agent", find(out, metricConnOpened, "app", "*", roleClient, ""))
	}

	// evil-01 declares the address too: held by two hosts, it is resolved
	// on each of them only.
	*now = now.Add(15 * time.Second)
	evil.time, evil.addrs = *now, []string{"10.0.0.66", "10.0.0.5"}
	consume(t, c, sink, evil)
	id := &edgeID{role: roleClient, proto: "tcp", local: addrOf("10.0.0.11"), peer: addrOf("10.0.0.5"), port: 5432}
	if p := c.resolver.peer("app-01", id, *now); p.name != peerUnresolved {
		t.Errorf("peer at a shared address = %+v, want %s", p, peerUnresolved)
	}
}

// TestEndpointAtMovedAddress: when a virtual address moves to another host,
// the idle server edges that the former holder keeps sending at it do not
// name its peers once the new holder holds it alone, although they were
// observed on a socket and the listener of the new holder is on an
// unspecified address.
func TestEndpointAtMovedAddress(t *testing.T) {
	c, _, sink, now := testConnector(t, nil)
	served := t0.Add(-time.Minute)
	old := func(addrs ...string) tAgent {
		return tAgent{host: "lb-01", addrs: addrs, time: *now,
			edges: []tEdge{{role: "server", proto: "tcp", local: "10.0.0.100", peer: "10.0.0.11", port: 443, svc: "haproxy",
				comm: "haproxy", opened: 1, first: served, last: served}}}
	}
	replacement := func() tAgent {
		return tAgent{host: "lb-02", addrs: []string{"10.0.0.2", "10.0.0.100"}, time: *now,
			listeners: []tListener{{proto: "tcp", addr: "0.0.0.0", port: 443, svc: "envoy", comm: "envoy"}}}
	}
	id := &edgeID{role: roleClient, proto: "tcp", local: addrOf("10.0.0.11"), peer: addrOf("10.0.0.100"), port: 443}
	consume(t, c, sink, old("10.0.0.1", "10.0.0.100"))
	if p := c.resolver.peer("app-01", id, *now); p.name != "haproxy" {
		t.Fatalf("peer before the move = %+v", p)
	}
	// The address moves to lb-02; lb-01 sends its idle edge until its idle
	// TTL.
	for range 5 {
		*now = now.Add(time.Minute)
		consume(t, c, sink, old("10.0.0.1"))
		consume(t, c, sink, replacement())
	}
	if p := c.resolver.peer("app-01", id, *now); p.name != "envoy" || !p.agent {
		t.Errorf("peer after the move = %+v, want envoy", p)
	}
}

// TestClientAtAddressOfAnotherHost: the client edges a host reports from an
// address that another live host holds alone do not name the clients of
// server edges, even when they were seen last.
func TestClientAtAddressOfAnotherHost(t *testing.T) {
	c, _, sink, now := testConnector(t, nil)
	consume(t, c, sink, tAgent{host: "app-01", addrs: []string{"10.0.0.11"}, time: *now,
		edges: []tEdge{{role: "client", proto: "tcp", local: "10.0.0.11", peer: "10.0.0.10", port: 5432, svc: "app",
			comm: "app", opened: 1}}})
	*now = now.Add(time.Second)
	consume(t, c, sink, tAgent{host: "evil-01", addrs: []string{"10.0.0.66"}, time: *now,
		edges: []tEdge{{role: "client", proto: "tcp", local: "10.0.0.11", peer: "10.0.0.10", port: 5432, svc: "evil",
			comm: "evil", opened: 1, last: farFuture}}})
	out := consume(t, c, sink, tAgent{host: "db-01", addrs: []string{"10.0.0.10"}, time: *now,
		edges: []tEdge{{role: "server", proto: "tcp", local: "10.0.0.10", peer: "10.0.0.11", port: 5432, svc: "postgres",
			comm: "postgres", opened: 1}}})
	if s := find(out, metricConnOpened, "postgres", "app", roleServer, ""); len(s) != 1 || !s[0].agent {
		t.Errorf("server series = %+v, want app with an agent", find(out, metricConnOpened, "postgres", "*", roleServer, ""))
	}
}

// TestBackendAtAddressOfAnotherHost: through a translation, a service that a
// host reports at the address of a backend that another live host holds
// alone is not taken for the backend, whether the backend is an address or
// a range.
func TestBackendAtAddressOfAnotherHost(t *testing.T) {
	c, _, sink, now := testConnector(t, func(cfg *Config) {
		cfg.Translations = map[string]TranslationConfig{
			"pg":  {Virtual: []string{"10.0.100.1:5432"}, Backends: []string{"10.0.1.10:6432"}},
			"pg2": {Virtual: []string{"10.0.100.2:5432"}, Backends: []string{"10.0.2.0/24:6432"}},
		}
	})
	for _, b := range []struct{ host, addr string }{{"pgb-01", "10.0.1.10"}, {"pgb-02", "10.0.2.7"}} {
		consume(t, c, sink, tAgent{host: b.host, addrs: []string{b.addr}, time: *now,
			listeners: []tListener{{proto: "tcp", addr: b.addr, port: 6432, svc: "pgbouncer", comm: "pgbouncer"}}})
	}
	// evil-01 reports a service that sorts first at both backends.
	consume(t, c, sink, tAgent{host: "evil-01", addrs: []string{"10.0.0.66"}, time: *now,
		listeners: []tListener{
			{proto: "tcp", addr: "10.0.1.10", port: 6432, svc: "aaa", comm: "aaa"},
			{proto: "tcp", addr: "10.0.2.7", port: 6432, svc: "aaa", comm: "aaa"},
		}})
	for _, virtual := range []string{"10.0.100.1", "10.0.100.2"} {
		id := &edgeID{role: roleClient, proto: "tcp", local: addrOf("10.0.0.11"), peer: addrOf(virtual), port: 5432}
		if p := c.resolver.peer("app-01", id, *now); p.name != "pgbouncer" || p.port != 6432 || !p.agent {
			t.Errorf("peer through %s = %+v, want pgbouncer on 6432", virtual, p)
		}
	}
}

// TestFutureTimesNotWritten: the times of edges, listeners and translations
// are written no later than maxClockAhead after the time the request was
// received; a clock ahead by less keeps its times.
func TestFutureTimesNotWritten(t *testing.T) {
	c, st, sink, now := testConnector(t, nil)
	ahead := now.Add(time.Minute)
	consume(t, c, sink, tAgent{host: "evil-01", addrs: []string{"10.0.0.66"}, time: *now,
		listeners: []tListener{{proto: "tcp", addr: "10.0.0.66", port: 5432, svc: "evil", comm: "evil",
			first: farFuture, last: farFuture}},
		edges: []tEdge{
			{role: "server", proto: "tcp", local: "10.0.0.66", peer: "10.0.0.11", port: 5432, svc: "evil", comm: "evil",
				opened: 1, first: t0.Add(-time.Hour), last: farFuture},
			{role: "client", proto: "tcp", local: "10.0.0.66", peer: "10.0.0.10", port: 5432, svc: "evil", comm: "evil",
				opened: 1, first: ahead, last: ahead},
		},
		translations: []tTranslation{{client: "172.17.0.2", virtual: "10.0.0.66", vport: 8080, backend: "172.17.0.2",
			bport: 80, first: farFuture, last: farFuture}}})
	c.flush(context.Background())
	if len(st.writes) != 1 {
		t.Fatalf("%d writes", len(st.writes))
	}
	h := st.writes[0]
	latest := now.Add(maxClockAhead)
	check := func(what string, s, want span) {
		t.Helper()
		if !s.first.Equal(want.first) || !s.last.Equal(want.last) {
			t.Errorf("%s: %v - %v, want %v - %v", what, s.first, s.last, want.first, want.last)
		}
	}
	for k, s := range h.listeners {
		check("listener "+k.addr.String(), s, span{latest, latest})
	}
	for k, s := range h.edges {
		if k.role == roleServer {
			check("server edge", s, span{t0.Add(-time.Hour), latest})
		} else {
			check("client edge", s, span{ahead, ahead})
		}
	}
	for _, s := range h.translations {
		check("translation", s, span{latest, latest})
	}
	for k, p := range h.processes {
		if p.last.After(latest) {
			t.Errorf("process %v last seen %v", k, p.last)
		}
	}
	if len(h.listeners) != 1 || len(h.edges) != 2 || len(h.translations) != 1 {
		t.Errorf("changes = %+v", h)
	}
}
