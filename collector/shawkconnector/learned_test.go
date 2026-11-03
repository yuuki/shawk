package shawkconnector

import (
	"fmt"
	"maps"
	"slices"
	"strings"
	"testing"
	"time"
)

// Tests of the names of peers through translations learned by the agents
// (#107, phase 2).

// peersOf returns the peers of the opened connections of a service on a
// side, with their port, value and shawk.peer.agent.
func peersOf(out []series, job, role string) map[string]string {
	got := map[string]string{}
	for _, s := range find(out, metricConnOpened, job, "*", role, "") {
		got[fmt.Sprintf("%s:%d", s.peer, s.port)] = fmt.Sprintf("%v %v", s.value, s.agent)
	}
	return got
}

// TestLearnedPeerNames: kube-proxy on the host of the client translates a
// ClusterIP to a pod on another port. The client edge is named after the
// pod, with its port, and the server edge after the client.
func TestLearnedPeerNames(t *testing.T) {
	c, _, sink, _ := testConnector(t, nil)
	ts := t0.Add(15 * time.Second)
	db := tAgent{host: "db-01", addrs: []string{"10.0.1.10"}, time: ts,
		edges: []tEdge{{role: "server", proto: "tcp", local: "10.0.1.10", peer: "10.0.0.11", port: 6432,
			svc: "postgres", comm: "postgres", opened: 3}}}
	app := tAgent{host: "app-01", addrs: []string{"10.0.0.11"}, time: ts,
		edges: []tEdge{{role: "client", proto: "tcp", local: "10.0.0.11", peer: "10.96.0.10", port: 5432,
			svc: "app", comm: "app", opened: 3}},
		translations: []tTranslation{{client: "10.0.0.11", virtual: "10.96.0.10", vport: 5432,
			backend: "10.0.1.10", bport: 6432}}}
	consume(t, c, sink, db)
	out := consume(t, c, sink, app)
	if got, want := peersOf(out, "app", roleClient), map[string]string{"postgres:6432": "3 true"}; !maps.Equal(got, want) {
		t.Errorf("client peers = %v, want %v", got, want)
	}
	db.time = ts.Add(15 * time.Second)
	db.edges[0].opened = 5
	out = consume(t, c, sink, db)
	// The connections accepted before were named ~unresolved; those since go
	// to the client, whose agent counts them.
	if got, want := peersOf(out, "postgres", roleServer), map[string]string{"~unresolved:6432": "3 false", "app:6432": "2 true"}; !maps.Equal(got, want) {
		t.Errorf("server peers = %v, want %v", got, want)
	}
}

// TestLearnedSharedBackend: a host publishes a port to a container at a
// bridge address that a container of another host also has; the client is
// named after the container of the host that translated it.
func TestLearnedSharedBackend(t *testing.T) {
	c, _, sink, _ := testConnector(t, nil)
	ts := t0.Add(15 * time.Second)
	bridge := func(host, addr, svc string, xs ...tTranslation) tAgent {
		return tAgent{host: host, addrs: []string{"127.0.0.1", addr, "172.17.0.1", "172.17.0.5"}, time: ts,
			edges: []tEdge{{role: "server", proto: "tcp", local: "172.17.0.5", peer: "10.0.0.11", port: 80,
				svc: svc, comm: svc, opened: 1}},
			translations: xs}
	}
	consume(t, c, sink, bridge("h2", "10.0.0.2", "nginx", tTranslation{client: "10.0.0.11", virtual: "10.0.0.2", vport: 8080,
		backend: "172.17.0.5", bport: 80}))
	consume(t, c, sink, bridge("h4", "10.0.0.4", "billing"))
	out := consume(t, c, sink, tAgent{host: "k", addrs: []string{"10.0.0.11"}, time: ts,
		edges: []tEdge{{role: "client", proto: "tcp", local: "10.0.0.11", peer: "10.0.0.2", port: 8080,
			svc: "curl", comm: "curl", opened: 1}}})
	if got, want := peersOf(out, "curl", roleClient), map[string]string{"nginx:80": "1 true"}; !maps.Equal(got, want) {
		t.Errorf("client peers = %v, want %v", got, want)
	}
}

// TestLearnedSNATServer: a server edge behind a learned SNAT keeps its name
// and shawk.peer.agent; one behind the relay of a static translation keeps
// shawk.peer.agent false, even if the relay learns its translations.
func TestLearnedSNATServer(t *testing.T) {
	c, _, sink, _ := testConnector(t, func(cfg *Config) {
		cfg.Translations = map[string]TranslationConfig{
			"lvs": {Virtual: []string{"10.0.100.1:80"}, Backends: []string{"10.0.1.20"}, Sources: []string{"10.0.2.1"}},
		}
	})
	ts := t0.Add(15 * time.Second)
	// h1 masquerades its container to db-01; the director lvs forwards a
	// client to web-01.
	consume(t, c, sink, tAgent{host: "h1", addrs: []string{"10.0.0.1", "172.17.0.2"}, time: ts,
		edges: []tEdge{{role: "client", proto: "tcp", local: "172.17.0.2", peer: "10.0.1.10", port: 5432, svc: "a", comm: "a", opened: 1}},
		translations: []tTranslation{{client: "172.17.0.2", virtual: "10.0.1.10", vport: 5432, source: "10.0.0.1",
			backend: "10.0.1.10", bport: 5432}}})
	consume(t, c, sink, tAgent{host: "lvs", addrs: []string{"10.0.2.1"}, time: ts,
		translations: []tTranslation{{client: "10.0.0.11", virtual: "10.0.100.1", vport: 80, source: "10.0.2.1",
			backend: "10.0.1.20", bport: 80}}})
	consume(t, c, sink, tAgent{host: "app", addrs: []string{"10.0.0.11"}, time: ts,
		edges: []tEdge{{role: "client", proto: "tcp", local: "10.0.0.11", peer: "10.0.100.1", port: 80, svc: "app", comm: "app", opened: 1}}})
	out := consume(t, c, sink, tAgent{host: "db-01", addrs: []string{"10.0.1.10"}, time: ts,
		edges: []tEdge{{role: "server", proto: "tcp", local: "10.0.1.10", peer: "10.0.0.1", port: 5432,
			svc: "postgres", comm: "postgres", opened: 2}}})
	if got, want := peersOf(out, "postgres", roleServer), map[string]string{"~unresolved:5432": "2 true"}; !maps.Equal(got, want) {
		t.Errorf("server peers of db-01 = %v, want %v", got, want)
	}
	out = consume(t, c, sink, tAgent{host: "web-01", addrs: []string{"10.0.1.20"}, time: ts,
		edges: []tEdge{{role: "server", proto: "tcp", local: "10.0.1.20", peer: "10.0.2.1", port: 80,
			svc: "web", comm: "web", opened: 4}}})
	if got, want := peersOf(out, "web", roleServer), map[string]string{"~unresolved:80": "4 false"}; !maps.Equal(got, want) {
		t.Errorf("server peers of web-01 = %v, want %v", got, want)
	}
}

// TestLearnedFromPostgreSQL: the translations of other connectors, read
// from PostgreSQL, name peers too, in their scope: a loopback client of
// another host, or of another namespace of the host, is not one.
func TestLearnedFromPostgreSQL(t *testing.T) {
	c, st, sink, now := testConnector(t, nil)
	row := func(host, client string, netns uint64) learnedRow {
		return learnedRow{host: host, lastSeen: *now, id: translationID{proto: "tcp", netns: netns,
			client: addrOf(client), virtual: addrOf("10.96.0.10"), vport: 5432, source: addrOf(client),
			backend: addrOf("10.0.1.10"), bport: 6432}}
	}
	st.mu.Lock()
	st.rows.learned = []learnedRow{row(hostKey("", "app-01"), "10.0.0.11", 4026531840),
		row(hostKey("", "other"), "127.0.0.1", 4026531840), row(hostKey("", "app-01"), "127.0.0.1", 4026532000)}
	st.rows.endpoints = []endpointRow{{key: endpointKey{addrOf("10.0.1.10"), 6432, "tcp"},
		endpoint: endpoint{host: hostKey("", "db-01"), service: "postgres", exact: true, lastSeen: *now}}}
	st.mu.Unlock()
	c.prepare(t.Context())
	ts := t0.Add(15 * time.Second)
	out := consume(t, c, sink, tAgent{host: "app-01", addrs: []string{"127.0.0.1", "10.0.0.11"}, time: ts,
		edges: []tEdge{
			{role: "client", proto: "tcp", local: "10.0.0.11", peer: "10.96.0.10", port: 5432, svc: "app", comm: "app", opened: 1},
			{role: "client", proto: "tcp", local: "127.0.0.1", peer: "10.96.0.10", port: 5432, svc: "local", comm: "local", opened: 1},
		}})
	if got, want := peersOf(out, "app", roleClient), map[string]string{"postgres:6432": "1 false"}; !maps.Equal(got, want) {
		t.Errorf("client peers = %v, want %v", got, want)
	}
	if got := peersOf(out, "local", roleClient); len(got) != 1 || got["~unresolved:5432"] == "" {
		t.Errorf("loopback client of another host = %v", got)
	}
}

func TestTranslationNameReserved(t *testing.T) {
	_, err := parseTranslations(map[string]TranslationConfig{
		"~learned": {Virtual: []string{"10.0.100.1:80"}, Backends: []string{"10.0.1.20"}},
	})
	if err == nil || !strings.Contains(err.Error(), "may not start with ~") {
		t.Errorf("err = %v", err)
	}
}

// TestLearnedStaleBackend: a published port re-pointed to another
// container; the former address, now another service, is not the peer.
func TestLearnedStaleBackend(t *testing.T) {
	c, _, sink, now := testConnector(t, nil)
	ts := t0.Add(15 * time.Second)
	h2 := func(ts time.Time, backend string, edges ...tEdge) tAgent {
		return tAgent{host: "h2", addrs: []string{"10.0.0.2", "172.17.0.5", "172.17.0.6"}, time: ts, edges: edges,
			translations: []tTranslation{{client: "10.0.0.11", virtual: "10.0.0.2", vport: 8080, backend: backend, bport: 80}}}
	}
	consume(t, c, sink, h2(ts, "172.17.0.5", tEdge{role: "server", proto: "tcp", local: "172.17.0.5", peer: "10.0.0.11", port: 80,
		svc: "web", comm: "web", opened: 1}))
	*now = t0.Add(10 * time.Minute)
	ts = ts.Add(10 * time.Minute)
	consume(t, c, sink, h2(ts, "172.17.0.6",
		tEdge{role: "server", proto: "tcp", local: "172.17.0.6", peer: "10.0.0.11", port: 80, svc: "web", comm: "web", opened: 1},
		tEdge{role: "server", proto: "tcp", local: "172.17.0.5", peer: "10.0.0.99", port: 80, svc: "api", comm: "api", opened: 1}))
	out := consume(t, c, sink, tAgent{host: "k", addrs: []string{"10.0.0.11"}, time: ts,
		edges: []tEdge{{role: "client", proto: "tcp", local: "10.0.0.11", peer: "10.0.0.2", port: 8080,
			svc: "curl", comm: "curl", opened: 1}}})
	// The values of the first interval of the series do not matter here.
	got := slices.Collect(maps.Keys(peersOf(out, "curl", roleClient)))
	if !slices.Equal(got, []string{"web:80"}) {
		t.Errorf("client peers = %v, want web:80", got)
	}
}

// TestLearnedFoldedVirtual: the agent of the client folds the virtual
// address of a DNAT that another host learned; the server side counts the
// connections, which the client side counts as external.
func TestLearnedFoldedVirtual(t *testing.T) {
	c, _, sink, _ := testConnector(t, nil)
	ts := t0.Add(15 * time.Second)
	consume(t, c, sink, tAgent{host: "lb", addrs: []string{"10.0.2.1"}, time: ts,
		translations: []tTranslation{{client: "10.0.0.11", virtual: "192.0.2.10", vport: 80, backend: "10.0.1.20", bport: 80}}})
	consume(t, c, sink, tAgent{host: "app", addrs: []string{"10.0.0.11"}, time: ts, fold: foldAll, internal: []string{"10.0.0.0/8"},
		edges: []tEdge{{role: "client", proto: "tcp", local: "10.0.0.11", peer: "0.0.0.0", folded: true, port: 80,
			svc: "app", comm: "app", opened: 1}}})
	out := consume(t, c, sink, tAgent{host: "web-01", addrs: []string{"10.0.1.20"}, time: ts,
		edges: []tEdge{{role: "server", proto: "tcp", local: "10.0.1.20", peer: "10.0.0.11", port: 80,
			svc: "web", comm: "web", opened: 4}}})
	for _, s := range find(out, metricConnOpened, "web", "*", roleServer, "") {
		if s.agent {
			t.Errorf("server side %s:%d has shawk.peer.agent, but the client folds the virtual address", s.peer, s.port)
		}
	}
}

// TestLearnedStaleBackendResent: the agent goes on sending the former
// translation, with its last seen time, for its idle TTL; it is as old as
// that.
func TestLearnedStaleBackendResent(t *testing.T) {
	c, _, sink, now := testConnector(t, nil)
	ts := t0.Add(15 * time.Second)
	old := tTranslation{client: "10.0.0.11", virtual: "10.0.0.2", vport: 8080, backend: "172.17.0.5", bport: 80, first: ts, last: ts}
	consume(t, c, sink, tAgent{host: "h2", addrs: []string{"10.0.0.2", "172.17.0.5", "172.17.0.6"}, time: ts,
		edges:        []tEdge{{role: "server", proto: "tcp", local: "172.17.0.5", peer: "10.0.0.11", port: 80, svc: "web", comm: "web", opened: 1}},
		translations: []tTranslation{old}})
	*now = t0.Add(10 * time.Minute)
	ts = ts.Add(10 * time.Minute)
	consume(t, c, sink, tAgent{host: "h2", addrs: []string{"10.0.0.2", "172.17.0.5", "172.17.0.6"}, time: ts,
		edges: []tEdge{
			{role: "server", proto: "tcp", local: "172.17.0.6", peer: "10.0.0.11", port: 80, svc: "web", comm: "web", opened: 1},
			{role: "server", proto: "tcp", local: "172.17.0.5", peer: "10.0.0.99", port: 80, svc: "api", comm: "api", opened: 1}},
		translations: []tTranslation{old, {client: "10.0.0.11", virtual: "10.0.0.2", vport: 8080, backend: "172.17.0.6", bport: 80}}})
	out := consume(t, c, sink, tAgent{host: "k", addrs: []string{"10.0.0.11"}, time: ts,
		edges: []tEdge{{role: "client", proto: "tcp", local: "10.0.0.11", peer: "10.0.0.2", port: 8080, svc: "curl", comm: "curl", opened: 1}}})
	got := slices.Collect(maps.Keys(peersOf(out, "curl", roleClient)))
	if !slices.Equal(got, []string{"web:80"}) {
		t.Errorf("client peers = %v, want web:80", got)
	}
}

// TestTranslationInputBounds: a translation with a network namespace or a
// port out of range is invalid.
func TestTranslationInputBounds(t *testing.T) {
	for _, netns := range []string{"-1", "4294967296"} {
		md := tAgent{host: "h", addrs: []string{"10.0.0.1"}, time: t0, partial: true,
			translations: []tTranslation{{client: "10.0.0.1", virtual: "10.96.0.1", vport: 80, backend: "10.0.1.1", bport: 80,
				netns: netns}}}.metrics()
		b, err := parseResource(md.ResourceMetrics().At(0))
		if err != nil {
			t.Fatal(err)
		}
		if len(b.translations) != 0 || b.invalid == 0 {
			t.Errorf("netns %s: %d translations, %d invalid points", netns, len(b.translations), b.invalid)
		}
	}
}

// TestLearnedDockerProxyHairpin: on a Docker host with the userland proxy
// (the default), a container that reaches the published port at the
// address of its host goes through docker-proxy, whose server edge at
// 10.0.0.5:8080 is exact and recent. A remote client of the same port is
// DNATed to the container, which the host learns; it is named after the
// container, as PostgreSQL matches it (docker-proxy served other clients).
func TestLearnedDockerProxyHairpin(t *testing.T) {
	c, _, sink, _ := testConnector(t, nil)
	ts := t0.Add(15 * time.Second)
	consume(t, c, sink, tAgent{host: "dk", addrs: []string{"10.0.0.5", "172.17.0.1", "172.17.0.2", "172.17.0.3"}, time: ts,
		edges: []tEdge{
			{role: "server", proto: "tcp", local: "10.0.0.5", peer: "172.17.0.2", port: 8080, svc: "docker-proxy",
				comm: "docker-proxy", opened: 1},
			{role: "server", proto: "tcp", local: "172.17.0.3", peer: "10.0.0.11", port: 80, svc: "web", comm: "web", opened: 1},
		},
		translations: []tTranslation{{client: "10.0.0.11", virtual: "10.0.0.5", vport: 8080, backend: "172.17.0.3", bport: 80}}})
	out := consume(t, c, sink, tAgent{host: "app", addrs: []string{"10.0.0.11"}, time: ts,
		edges: []tEdge{{role: "client", proto: "tcp", local: "10.0.0.11", peer: "10.0.0.5", port: 8080, svc: "app", comm: "app", opened: 1}}})
	got := slices.Collect(maps.Keys(peersOf(out, "app", roleClient)))
	if !slices.Equal(got, []string{"web:80"}) {
		t.Errorf("client peers = %v, want web:80, as PostgreSQL matches it", got)
	}
	// A client that docker-proxy served (its translation once, docker-proxy
	// since) is named after docker-proxy, as a match by address comes first.
	consume(t, c, sink, tAgent{host: "dk", addrs: []string{"10.0.0.5", "172.17.0.1", "172.17.0.2", "172.17.0.3"}, time: ts,
		edges: []tEdge{{role: "server", proto: "tcp", local: "10.0.0.5", peer: "10.0.0.12", port: 8080, svc: "docker-proxy",
			comm: "docker-proxy", opened: 1}},
		translations: []tTranslation{{client: "10.0.0.12", virtual: "10.0.0.5", vport: 8080, backend: "172.17.0.3", bport: 80}}})
	out = consume(t, c, sink, tAgent{host: "app2", addrs: []string{"10.0.0.12"}, time: ts,
		edges: []tEdge{{role: "client", proto: "tcp", local: "10.0.0.12", peer: "10.0.0.5", port: 8080, svc: "app2", comm: "app2", opened: 1}}})
	if got := slices.Collect(maps.Keys(peersOf(out, "app2", roleClient))); !slices.Equal(got, []string{"docker-proxy:8080"}) {
		t.Errorf("client peers of the client docker-proxy served = %v", got)
	}
}

// TestLearnedServerScope: a server edge at a shared or loopback backend is
// named after the client of a learned DNAT only on the host, and in the
// namespace, of the translation.
func TestLearnedServerScope(t *testing.T) {
	c, _, sink, _ := testConnector(t, nil)
	ts := t0.Add(15 * time.Second)
	consume(t, c, sink, tAgent{host: "app", addrs: []string{"10.0.0.11"}, time: ts,
		edges: []tEdge{
			{role: "client", proto: "tcp", local: "10.0.0.11", peer: "10.0.0.2", port: 8080, svc: "curl", comm: "curl", opened: 1},
			{role: "client", proto: "tcp", local: "10.0.0.11", peer: "10.96.0.20", port: 80, svc: "curl", comm: "curl", opened: 1},
		}})
	bridge := func(host, addr string, xs ...tTranslation) tAgent {
		return tAgent{host: host, addrs: []string{"127.0.0.1", addr, "172.17.0.1", "172.17.0.5"}, time: ts, translations: xs}
	}
	consume(t, c, sink, bridge("h2", "10.0.0.2",
		tTranslation{client: "10.0.0.11", virtual: "10.0.0.2", vport: 8080, backend: "172.17.0.5", bport: 80},
		tTranslation{client: "10.0.0.11", virtual: "10.96.0.20", vport: 80, backend: "127.0.0.1", bport: 15001, netns: "100"}))
	consume(t, c, sink, bridge("h4", "10.0.0.4"))
	next := ts
	serve := func(host, addr, local string, port int64, netns, svc string) []series {
		a := bridge(host, addr)
		next = next.Add(15 * time.Second)
		a.time = next
		a.edges = []tEdge{{role: "server", proto: "tcp", local: local, peer: "10.0.0.11", port: port, svc: svc, comm: svc,
			opened: 1, netns: netns}}
		return consume(t, c, sink, a)
	}
	for _, k := range []struct {
		host, addr, local string
		port              int64
		netns, want       string
	}{
		{"h2", "10.0.0.2", "172.17.0.5", 80, "", "curl"},
		{"h4", "10.0.0.4", "172.17.0.5", 80, "", "~unresolved"},
		{"h2", "10.0.0.2", "127.0.0.1", 15001, "100", "curl"},
		{"h2", "10.0.0.2", "127.0.0.1", 15001, "200", "~unresolved"},
	} {
		svc := fmt.Sprintf("srv%d", k.port) + k.netns + k.host
		out := serve(k.host, k.addr, k.local, k.port, k.netns, svc)
		got := slices.Collect(maps.Keys(peersOf(out, svc, roleServer)))
		if want := []string{fmt.Sprintf("%s:%d", k.want, k.port)}; !slices.Equal(got, want) {
			t.Errorf("server edge at %s:%d on %s in %q: peers = %v, want %v", k.local, k.port, k.host, k.netns, got, want)
		}
	}
}

// TestLearnedSharedClient: a client at a shared address (a container
// bridge) is named through the learned translations of its own host only.
func TestLearnedSharedClient(t *testing.T) {
	c, _, sink, _ := testConnector(t, nil)
	ts := t0.Add(15 * time.Second)
	consume(t, c, sink, tAgent{host: "db", addrs: []string{"10.0.1.70"}, time: ts,
		edges: []tEdge{{role: "server", proto: "tcp", local: "10.0.1.70", peer: "10.0.0.1", port: 80, svc: "web", comm: "web", opened: 1}}})
	host := func(name, addr string, xs ...tTranslation) tAgent {
		return tAgent{host: name, addrs: []string{"127.0.0.1", addr, "172.17.0.1", "172.17.0.2"}, time: ts,
			edges: []tEdge{{role: "client", proto: "tcp", local: "172.17.0.2", peer: "10.96.0.50", port: 80,
				svc: "c-" + name, comm: "c", opened: 1}},
			translations: xs}
	}
	out := consume(t, c, sink, host("h1", "10.0.0.1", tTranslation{client: "172.17.0.2", virtual: "10.96.0.50", vport: 80,
		source: "10.0.0.1", backend: "10.0.1.70", bport: 80}))
	if got := slices.Collect(maps.Keys(peersOf(out, "c-h1", roleClient))); !slices.Equal(got, []string{"web:80"}) {
		t.Errorf("client on h1 = %v, want web:80", got)
	}
	out = consume(t, c, sink, host("h2", "10.0.0.2"))
	if got := slices.Collect(maps.Keys(peersOf(out, "c-h2", roleClient))); !slices.Equal(got, []string{"~unresolved:80"}) {
		t.Errorf("client on h2 = %v, want ~unresolved:80", got)
	}
}

// TestLearnedSharedClientServer: the server edge of a learned DNAT from a
// shared address (a container of the host that translates, to a service of
// the host) is named after a client on that host only, not after one at the
// same address on another host.
func TestLearnedSharedClientServer(t *testing.T) {
	c, _, sink, _ := testConnector(t, nil)
	ts := t0.Add(15 * time.Second)
	host := func(name, addr string, edges []tEdge, xs ...tTranslation) tAgent {
		return tAgent{host: name, addrs: []string{"127.0.0.1", addr, "172.17.0.1", "172.17.0.2"}, time: ts, edges: edges, translations: xs}
	}
	consume(t, c, sink, host("h2", "10.0.0.2", []tEdge{{role: "client", proto: "tcp", local: "172.17.0.2", peer: "10.96.0.60",
		port: 80, svc: "b", comm: "b", opened: 1}}))
	out := consume(t, c, sink, host("h1", "10.0.0.1",
		[]tEdge{{role: "server", proto: "tcp", local: "10.0.0.1", peer: "172.17.0.2", port: 9000, svc: "web", comm: "web", opened: 1}},
		tTranslation{client: "172.17.0.2", virtual: "10.96.0.60", vport: 80, backend: "10.0.0.1", bport: 9000}))
	if got := slices.Collect(maps.Keys(peersOf(out, "web", roleServer))); !slices.Equal(got, []string{"~unresolved:9000"}) {
		t.Errorf("server peers = %v, want ~unresolved:9000, not the client of another host", got)
	}
}

// TestLearnedSNATNoFoldWarning: behind a learned SNAT the backend sees the
// source, not the client: that its agent would fold the address of the
// client is no warning.
func TestLearnedSNATNoFoldWarning(t *testing.T) {
	c, _, sink, _ := testConnector(t, nil)
	logs := observe(c)
	ts := t0.Add(15 * time.Second)
	consume(t, c, sink, tAgent{host: "db-01", addrs: []string{"192.0.2.10"}, time: ts, fold: foldIn, internal: []string{"10.0.0.0/8"},
		edges: []tEdge{{role: "server", proto: "tcp", local: "192.0.2.10", peer: "10.0.0.1", port: 5432,
			svc: "postgres", comm: "postgres", opened: 1}}})
	consume(t, c, sink, tAgent{host: "h1", addrs: []string{"10.0.0.1", "172.17.0.2"}, time: ts,
		edges: []tEdge{{role: "client", proto: "tcp", local: "172.17.0.2", peer: "10.96.0.70", port: 5432, svc: "a", comm: "a", opened: 1}},
		translations: []tTranslation{{client: "172.17.0.2", virtual: "10.96.0.70", vport: 5432, source: "10.0.0.1",
			backend: "192.0.2.10", bport: 5432}}})
	if got := foldWarnings(logs); len(got) != 0 {
		t.Errorf("warnings = %q", got)
	}
}
