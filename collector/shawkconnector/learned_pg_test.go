package shawkconnector

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

// PostgreSQL tests of the translations learned by the agents (#107, phase
// 2).

// checkDeps compares the rows of translationDeps of the view and of the
// function over all time with want.
func checkDeps(t *testing.T, got func(q string, args ...any) []string, want []string) {
	t.Helper()
	for _, q := range []string{
		translationDeps + ` FROM shawk_v1.dependencies`,
		translationDeps + ` FROM shawk_v1.dependencies_between('-infinity', 'infinity')`,
	} {
		if g := got(q); !slices.Equal(g, want) {
			t.Errorf("%s:\n%s\nwant:\n%s", q, strings.Join(g, "\n"), strings.Join(want, "\n"))
		}
	}
}

// TestPGLearnedDNAT: kube-proxy on the host of the client translates a
// ClusterIP to a pod on another port; the agent of the client learns it,
// and the two edges are matched through it.
func TestPGLearnedDNAT(t *testing.T) {
	c, sink, conn := pgConnectorWith(t, nil)
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Second)
	hour := now.Add(-time.Hour)
	app := tAgent{host: "app-01", addrs: []string{"10.0.0.11"}, time: now,
		edges: []tEdge{{role: "client", proto: "tcp", local: "10.0.0.11", peer: "10.96.0.10", port: 5432,
			svc: "app", comm: "app", opened: 1, first: hour}},
		translations: []tTranslation{{client: "10.0.0.11", virtual: "10.96.0.10", vport: 5432,
			backend: "10.0.1.10", bport: 6432, first: hour}}}
	db := tAgent{host: "db-01", addrs: []string{"10.0.1.10"}, time: now,
		edges: []tEdge{{role: "server", proto: "tcp", local: "10.0.1.10", peer: "10.0.0.11", port: 6432,
			svc: "postgres", comm: "postgres", opened: 1, first: hour}}}
	for _, a := range []tAgent{db, app} {
		consume(t, c, sink, a)
	}
	c.flush(ctx)
	q := func(s string, args ...any) []string { return queryStrings(t, conn, s, args...) }
	checkDeps(t, q, []string{"app-01 app 10.0.0.11 db-01 postgres 10.0.1.10 6432 both 10.96.0.10 5432 ~learned"})
	got := q(`SELECT h.hostname, proto, netns, host(client_addr), host(virtual_addr), virtual_port, host(source_addr),
	  host(backend_addr), backend_port, t.first_seen = $1, t.last_seen = $2
	  FROM shawk.learned_translations t JOIN shawk.hosts h ON h.id = t.host_id`, hour, now)
	if want := []string{"app-01 tcp 4026531840 10.0.0.11 10.96.0.10 5432 10.0.0.11 10.0.1.10 6432 true true"}; !slices.Equal(got, want) {
		t.Errorf("learned_translations = %q, want %q", got, want)
	}

	// A later report widens the row; one already written is not written
	// again.
	app.time = now.Add(time.Minute)
	app.translations[0].last = now.Add(time.Minute)
	consume(t, c, sink, app)
	if h := c.changes.pending[hostKey("", "app-01")]; h == nil || len(h.translations) != 1 {
		t.Fatalf("pending translations = %+v", h)
	}
	consume(t, c, sink, app)
	c.flush(ctx)
	consume(t, c, sink, app)
	if h := c.changes.pending[hostKey("", "app-01")]; h != nil && len(h.translations) != 0 {
		t.Errorf("an unchanged translation is written again: %+v", h.translations)
	}
	if got := q(`SELECT last_seen = $1 FROM shawk.learned_translations`, now.Add(time.Minute)); !slices.Equal(got, []string{"true"}) {
		t.Errorf("last_seen not widened: %q", got)
	}
}

// TestPGLearnedPeriods: the period of a matched row is bounded by the
// learned rows: a client pinned to another backend since does not stay on
// the former one, which keeps its own rows.
func TestPGLearnedPeriods(t *testing.T) {
	c, sink, conn := pgConnectorWith(t, nil)
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Second)
	long, switched := now.Add(-5*time.Hour), now.Add(-3*time.Hour)
	app := tAgent{host: "app-01", addrs: []string{"10.0.0.11"}, time: now,
		edges: []tEdge{
			{role: "client", proto: "tcp", local: "10.0.0.11", peer: "10.96.0.10", port: 5432,
				svc: "app", comm: "app", opened: 1, first: long},
			// Another service, whose translation of hours before the client
			// edge tells nothing of it.
			{role: "client", proto: "tcp", local: "10.0.0.11", peer: "10.96.0.11", port: 5432,
				svc: "app", comm: "app", opened: 1, first: now.Add(-time.Hour)},
		},
		translations: []tTranslation{
			{client: "10.0.0.11", virtual: "10.96.0.10", vport: 5432, backend: "10.0.1.10", bport: 5432, first: long, last: switched},
			{client: "10.0.0.11", virtual: "10.96.0.10", vport: 5432, backend: "10.0.1.11", bport: 5432, first: switched},
			{client: "10.0.0.11", virtual: "10.96.0.11", vport: 5432, backend: "10.0.1.10", bport: 5432,
				first: long, last: long.Add(time.Hour)},
		}}
	server := func(host, addr string) tAgent {
		// Both backends still serve the client: db-01 directly.
		return tAgent{host: host, addrs: []string{addr}, time: now,
			edges: []tEdge{{role: "server", proto: "tcp", local: addr, peer: "10.0.0.11", port: 5432,
				svc: "postgres", comm: "postgres", opened: 1, first: long}}}
	}
	for _, a := range []tAgent{server("db-01", "10.0.1.10"), server("db-02", "10.0.1.11"), app} {
		consume(t, c, sink, a)
	}
	c.flush(ctx)
	q := func(s string, args ...any) []string { return queryStrings(t, conn, s, args...) }
	// db-02 served the client before the translation sent it there, and
	// db-01 since: both keep rows of their own.
	checkDeps(t, q, []string{
		"- - 10.0.0.11 db-01 postgres 10.0.1.10 5432 server - - -",
		"- - 10.0.0.11 db-02 postgres 10.0.1.11 5432 server - - -",
		"app-01 app 10.0.0.11 - - 10.96.0.11 5432 client - - -",
		"app-01 app 10.0.0.11 db-01 postgres 10.0.1.10 5432 both 10.96.0.10 5432 ~learned",
		"app-01 app 10.0.0.11 db-02 postgres 10.0.1.11 5432 both 10.96.0.10 5432 ~learned",
	})
	got := q(`SELECT server_host, first_seen = $1, last_seen = $2, last_seen = $3
	  FROM shawk_v1.dependencies WHERE translation IS NOT NULL ORDER BY 1`, long, switched, now)
	// (The own row of db-02 ends when the translation began.)
	if want := []string{"db-01 true true false", "db-02 false false true"}; !slices.Equal(got, want) {
		t.Errorf("periods = %q, want %q", got, want)
	}
	// In the last hour the former backend is no dependency through the
	// virtual address.
	got = q(translationDeps + ` FROM shawk_v1.dependencies_between(now() - interval '1 hour', now())`)
	if want := []string{
		"- - 10.0.0.11 db-01 postgres 10.0.1.10 5432 server - - -",
		"app-01 app 10.0.0.11 - - 10.96.0.11 5432 client - - -",
		"app-01 app 10.0.0.11 db-02 postgres 10.0.1.11 5432 both 10.96.0.10 5432 ~learned",
	}; !slices.Equal(got, want) {
		t.Errorf("last hour:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
}

// TestPGLearnedSNAT: a container masqueraded by its host reaches a database
// on another host; the learned row of its host matches it with the server
// edge from the address of the host, which keeps its own row. A container
// of another host at the same bridge address is not matched.
func TestPGLearnedSNAT(t *testing.T) {
	c, sink, conn := pgConnectorWith(t, nil)
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Second)
	hour := now.Add(-time.Hour)
	ctr := func(host, addr, svc string, xs ...tTranslation) tAgent {
		return tAgent{host: host, addrs: []string{"127.0.0.1", addr, "172.17.0.1", "172.17.0.2"}, time: now,
			edges: []tEdge{{role: "client", proto: "tcp", local: "172.17.0.2", peer: "10.0.1.10", port: 5432,
				svc: svc, comm: svc, opened: 1, first: hour}},
			translations: xs}
	}
	h1 := ctr("h1", "10.0.0.1", "a", tTranslation{client: "172.17.0.2", virtual: "10.0.1.10", vport: 5432,
		source: "10.0.0.1", backend: "10.0.1.10", bport: 5432, first: hour})
	h2 := ctr("h2", "10.0.0.2", "b")
	db := tAgent{host: "db-01", addrs: []string{"10.0.1.10"}, time: now,
		edges: []tEdge{
			{role: "server", proto: "tcp", local: "10.0.1.10", peer: "10.0.0.1", port: 5432, svc: "postgres", comm: "postgres",
				opened: 1, first: hour},
			{role: "server", proto: "tcp", local: "10.0.1.10", peer: "10.0.0.2", port: 5432, svc: "postgres", comm: "postgres",
				opened: 1, first: hour},
		}}
	for _, a := range []tAgent{db, h1, h2} {
		consume(t, c, sink, a)
	}
	c.flush(ctx)
	execAll(t, conn, `UPDATE shawk.host_addrs SET first_seen = first_seen - interval '1 hour'`)
	q := func(s string, args ...any) []string { return queryStrings(t, conn, s, args...) }
	checkDeps(t, q, []string{
		"- - 10.0.0.1 db-01 postgres 10.0.1.10 5432 server - - -",
		"- - 10.0.0.2 db-01 postgres 10.0.1.10 5432 server - - -",
		"h1 a 172.17.0.2 db-01 postgres 10.0.1.10 5432 both 10.0.1.10 5432 ~learned",
		"h2 b 172.17.0.2 - - 10.0.1.10 5432 client - - -",
	})
}

// TestPGLearnedPrecedence: a static translation of the virtual address and
// port comes first; one of another port leaves the learned rows alone; a
// relay with an agent at the virtual address matches by address.
func TestPGLearnedPrecedence(t *testing.T) {
	c, sink, conn := pgConnectorWith(t, func(cfg *Config) {
		cfg.Translations = map[string]TranslationConfig{
			"vip": {Virtual: []string{"10.0.100.1:5432"}, Backends: []string{"10.0.1.10"}},
		}
	})
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Second)
	hour := now.Add(-time.Hour)
	client := func(vip string, port int64) tEdge {
		return tEdge{role: "client", proto: "tcp", local: "10.0.0.11", peer: vip, port: port, svc: "app", comm: "app",
			opened: 1, first: hour}
	}
	learned := func(vip string, port int64, backend string) tTranslation {
		return tTranslation{client: "10.0.0.11", virtual: vip, vport: port, backend: backend, bport: port, first: hour}
	}
	app := tAgent{host: "app-01", addrs: []string{"10.0.0.11"}, time: now,
		edges: []tEdge{client("10.0.100.1", 5432), client("10.0.100.1", 80), client("10.0.100.9", 443)},
		translations: []tTranslation{learned("10.0.100.1", 5432, "10.0.1.11"), learned("10.0.100.1", 80, "10.0.1.20"),
			learned("10.0.100.9", 443, "10.0.1.30")}}
	server := func(host, addr string, port int64) tAgent {
		return tAgent{host: host, addrs: []string{addr}, time: now,
			edges: []tEdge{{role: "server", proto: "tcp", local: addr, peer: "10.0.0.11", port: port, svc: host,
				comm: host, opened: 1, first: hour}}}
	}
	for _, a := range []tAgent{server("db1", "10.0.1.10", 5432), server("db2", "10.0.1.11", 5432),
		server("web", "10.0.1.20", 80), server("relay", "10.0.100.9", 443), server("api", "10.0.1.30", 443), app} {
		consume(t, c, sink, a)
	}
	c.flush(ctx)
	q := func(s string, args ...any) []string { return queryStrings(t, conn, s, args...) }
	checkDeps(t, q, []string{
		"- - 10.0.0.11 api api 10.0.1.30 443 server - - -",
		"- - 10.0.0.11 db2 db2 10.0.1.11 5432 server - - -",
		"app-01 app 10.0.0.11 db1 db1 10.0.1.10 5432 both 10.0.100.1 5432 vip",
		"app-01 app 10.0.0.11 relay relay 10.0.100.9 443 both - - -",
		"app-01 app 10.0.0.11 web web 10.0.1.20 80 both 10.0.100.1 80 ~learned",
	})
}

// TestPGLearnedHosts: two directors translate in turn; their rows make one
// dependency. A loopback backend (a REDIRECT) is matched on the host of the
// row only.
func TestPGLearnedHosts(t *testing.T) {
	c, sink, conn := pgConnectorWith(t, nil)
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Second)
	long, failover := now.Add(-4*time.Hour), now.Add(-2*time.Hour)
	vip := func(first, last time.Time) tTranslation {
		return tTranslation{client: "10.0.0.11", virtual: "10.0.100.1", vport: 5432, backend: "10.0.1.10", bport: 5432,
			first: first, last: last}
	}
	for _, a := range []tAgent{
		{host: "lb1", addrs: []string{"10.0.2.1"}, time: now, translations: []tTranslation{vip(long, failover)}},
		{host: "lb2", addrs: []string{"10.0.2.2"}, time: now, translations: []tTranslation{vip(failover, now)}},
		{host: "db-01", addrs: []string{"10.0.1.10"}, time: now, edges: []tEdge{{role: "server", proto: "tcp",
			local: "10.0.1.10", peer: "10.0.0.11", port: 5432, svc: "postgres", comm: "postgres", opened: 1, first: long}}},
		// The sidecar of app-01 accepts its connections to a ClusterIP; that
		// of app-02, at the same loopback address, does not.
		{host: "app-01", addrs: []string{"127.0.0.1", "10.0.0.11"}, time: now,
			edges: []tEdge{
				{role: "client", proto: "tcp", local: "10.0.0.11", peer: "10.0.100.1", port: 5432, svc: "app", comm: "app",
					opened: 1, first: long},
				{role: "client", proto: "tcp", local: "10.0.0.11", peer: "10.96.0.20", port: 80, svc: "app", comm: "app",
					opened: 1, first: long},
				{role: "server", proto: "tcp", local: "127.0.0.1", peer: "10.0.0.11", port: 15001, svc: "envoy", comm: "envoy",
					opened: 1, first: long},
			},
			translations: []tTranslation{{client: "10.0.0.11", virtual: "10.96.0.20", vport: 80, backend: "127.0.0.1",
				bport: 15001, first: long}}},
		{host: "app-02", addrs: []string{"127.0.0.1", "10.0.0.12"}, time: now,
			edges: []tEdge{{role: "server", proto: "tcp", local: "127.0.0.1", peer: "10.0.0.11", port: 15001, svc: "envoy2",
				comm: "envoy", opened: 1, first: long}}},
	} {
		consume(t, c, sink, a)
	}
	c.flush(ctx)
	q := func(s string, args ...any) []string { return queryStrings(t, conn, s, args...) }
	checkDeps(t, q, []string{
		"- - 10.0.0.11 app-02 envoy2 127.0.0.1 15001 server - - -",
		"app-01 app 10.0.0.11 app-01 envoy 127.0.0.1 15001 both 10.96.0.20 80 ~learned",
		"app-01 app 10.0.0.11 db-01 postgres 10.0.1.10 5432 both 10.0.100.1 5432 ~learned",
	})
	got := q(`SELECT first_seen = $1, last_seen = $2 FROM shawk_v1.dependencies WHERE server_host = 'db-01'`, long, now)
	if !slices.Equal(got, []string{"true true"}) {
		t.Errorf("period of the row through two directors: %q", got)
	}

	// The retention deletes the rows of translations, and keeps the hosts
	// that have some.
	execAll(t, conn, `UPDATE shawk.learned_translations SET last_seen = last_seen - interval '30 days',
	    first_seen = first_seen - interval '30 days' WHERE host_id = (SELECT id FROM shawk.hosts WHERE hostname = 'lb1')`,
		`UPDATE shawk.hosts SET last_seen = last_seen - interval '30 days' WHERE hostname = 'lb1'`,
		`DELETE FROM shawk.agent_sessions WHERE host_id = (SELECT id FROM shawk.hosts WHERE hostname = 'lb1')`,
		`DELETE FROM shawk.host_addrs WHERE host_id = (SELECT id FROM shawk.hosts WHERE hostname = 'lb1')`)
	execAll(t, conn, `SELECT shawk.prune(now() - interval '7 days')`)
	if got := q(`SELECT count(*) FROM shawk.learned_translations`); !slices.Equal(got, []string{"2"}) {
		t.Errorf("learned translations after the retention: %q", got)
	}
	if got := q(`SELECT count(*) FROM shawk.hosts WHERE hostname = 'lb1'`); !slices.Equal(got, []string{"0"}) {
		t.Errorf("hosts after the retention: %q", got)
	}
}

// TestPGLearnedSidecar: a sidecar REDIRECTs the connections of its pod to
// itself and connects to the server from the address of the pod. The
// server edge matches the client edge of the application by address, which
// comes first: the application depends on the server, and the inbound edge
// of the sidecar has no client edge of its own.
func TestPGLearnedSidecar(t *testing.T) {
	c, sink, conn := pgConnectorWith(t, nil)
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Second)
	long := now.Add(-time.Hour)
	for _, a := range []tAgent{
		{host: "db-01", addrs: []string{"10.0.1.10"}, time: now, edges: []tEdge{{role: "server", proto: "tcp",
			local: "10.0.1.10", peer: "10.0.0.11", port: 5432, svc: "postgres", comm: "postgres", opened: 1, first: long}}},
		{host: "app-01", addrs: []string{"127.0.0.1", "10.0.0.11"}, time: now,
			edges: []tEdge{
				{role: "client", proto: "tcp", local: "10.0.0.11", peer: "10.0.1.10", port: 5432, svc: "app", comm: "app",
					opened: 1, first: long},
				{role: "server", proto: "tcp", local: "127.0.0.1", peer: "10.0.0.11", port: 15001, svc: "envoy", comm: "envoy",
					opened: 1, first: long},
				{role: "client", proto: "tcp", local: "10.0.0.11", peer: "10.0.1.10", port: 5432, svc: "envoy", comm: "envoy",
					opened: 1, first: long},
			},
			translations: []tTranslation{{client: "10.0.0.11", virtual: "10.0.1.10", vport: 5432, backend: "127.0.0.1",
				bport: 15001, first: long}}},
	} {
		consume(t, c, sink, a)
	}
	c.flush(ctx)
	q := func(s string, args ...any) []string { return queryStrings(t, conn, s, args...) }
	checkDeps(t, q, []string{
		"- - 10.0.0.11 app-01 envoy 127.0.0.1 15001 server - - -",
		"app-01 app 10.0.0.11 db-01 postgres 10.0.1.10 5432 both - - -",
		"app-01 envoy 10.0.0.11 db-01 postgres 10.0.1.10 5432 both - - -",
	})
}

// TestPGLearnedAsConnectorRole: with the privileges of grants.sql, the role
// of the connector writes the learned translations, reads them to name
// peers, and deletes them with the retention.
func TestPGLearnedAsConnectorRole(t *testing.T) {
	c, _, conn := pgConnectorWith(t, nil)
	ctx := context.Background()
	if _, err := conn.Exec(ctx, `DO $$ BEGIN
	    IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'shawk_connector') THEN CREATE ROLE shawk_connector NOLOGIN; END IF;
	    IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'shawk_grafana') THEN CREATE ROLE shawk_grafana NOLOGIN; END IF;
	  END $$`); err != nil {
		t.Fatal(err)
	}
	grants, err := os.ReadFile(filepath.Join(packaging, "postgres/grants.sql"))
	if err != nil {
		t.Fatal(err)
	}
	execAll(t, conn, string(grants))
	t.Cleanup(func() { conn.Exec(ctx, "DROP OWNED BY shawk_connector, shawk_grafana") })
	dsn := c.cfg.Postgres.DSN + "?options=-c%20role%3Dshawk_connector"
	st, err := newPGStore(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer st.close()

	then := time.Now().UTC().Add(-2 * time.Hour).Truncate(time.Second)
	h := newHostChanges(hostKey("", "app-01"))
	h.setHost("", "app-01", "5.14", "test", then)
	h.addProcess(procKey{"app.service", "app", "app", ""}, "/usr/bin/app", span{then, then})
	h.addEdge(edgeRowKey{role: "client", proto: "tcp", local: addrOf("10.0.0.11"), peer: addrOf("10.96.0.10"), port: 5432,
		netns: 1, procKey: procKey{"app.service", "app", "app", ""}}, span{then, then})
	h.addTranslation(translationID{proto: "tcp", netns: 1, client: addrOf("10.0.0.11"), virtual: addrOf("10.96.0.10"),
		vport: 5432, source: addrOf("10.0.0.11"), backend: addrOf("10.0.1.10"), bport: 6432}, span{then, then})
	if err := st.write(ctx, h); err != nil {
		t.Fatal(err)
	}
	rows, err := st.peers(ctx, 3*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows.learned) != 1 {
		t.Errorf("learned translations read = %d, want 1", len(rows.learned))
	}
	if _, err := st.prune(ctx, time.Hour, 100); err != nil {
		t.Fatal(err)
	}
	got := queryStrings(t, conn, `SELECT (SELECT count(*) FROM shawk.edges), (SELECT count(*) FROM shawk.learned_translations),
  (SELECT count(*) FROM shawk.hosts)`)
	if !slices.Equal(got, []string{"0 0 0"}) {
		t.Errorf("edges, learned translations and hosts after the retention = %q", got)
	}
}

// TestPGLearnedWindowFirstSeen: two directors in turn; in the last hour the
// function combines the rows of both, as the view does, though the row of
// the first one ended before the period.
func TestPGLearnedWindowFirstSeen(t *testing.T) {
	c, sink, conn := pgConnectorWith(t, nil)
	now := time.Now().UTC().Truncate(time.Second)
	long, failover := now.Add(-4*time.Hour), now.Add(-2*time.Hour)
	vip := func(first, last time.Time) tTranslation {
		return tTranslation{client: "10.0.0.11", virtual: "10.0.100.1", vport: 5432, backend: "10.0.1.10", bport: 5432,
			first: first, last: last}
	}
	for _, a := range []tAgent{
		{host: "lb1", addrs: []string{"10.0.2.1"}, time: now, translations: []tTranslation{vip(long, failover)}},
		{host: "lb2", addrs: []string{"10.0.2.2"}, time: now, translations: []tTranslation{vip(failover, now)}},
		{host: "db-01", addrs: []string{"10.0.1.10"}, time: now, edges: []tEdge{{role: "server", proto: "tcp",
			local: "10.0.1.10", peer: "10.0.0.11", port: 5432, svc: "postgres", comm: "postgres", opened: 1, first: long}}},
		{host: "app-01", addrs: []string{"10.0.0.11"}, time: now, edges: []tEdge{{role: "client", proto: "tcp",
			local: "10.0.0.11", peer: "10.0.100.1", port: 5432, svc: "app", comm: "app", opened: 1, first: long}}},
	} {
		consume(t, c, sink, a)
	}
	c.flush(context.Background())
	view := queryStrings(t, conn, `SELECT first_seen FROM shawk_v1.dependencies WHERE server_host = 'db-01'`)
	fn := queryStrings(t, conn, `SELECT first_seen FROM shawk_v1.dependencies_between(now() - interval '1 hour', now()) WHERE server_host = 'db-01'`)
	if !slices.Equal(view, fn) {
		t.Errorf("first_seen: view %q, function over the last hour %q", view, fn)
	}
}

// TestPGLearnedDockerProxyHairpin: the same in PostgreSQL: app depends on
// web through the learned translation.
func TestPGLearnedDockerProxyHairpin(t *testing.T) {
	c, sink, conn := pgConnectorWith(t, nil)
	now := time.Now().UTC().Truncate(time.Second)
	hour := now.Add(-time.Hour)
	for _, a := range []tAgent{
		{host: "dk", addrs: []string{"10.0.0.5", "172.17.0.1", "172.17.0.2", "172.17.0.3"}, time: now,
			edges: []tEdge{
				{role: "server", proto: "tcp", local: "10.0.0.5", peer: "172.17.0.2", port: 8080, svc: "docker-proxy",
					comm: "docker-proxy", opened: 1, first: hour},
				{role: "server", proto: "tcp", local: "172.17.0.3", peer: "10.0.0.11", port: 80, svc: "web", comm: "web", opened: 1, first: hour},
			},
			translations: []tTranslation{{client: "10.0.0.11", virtual: "10.0.0.5", vport: 8080, backend: "172.17.0.3", bport: 80, first: hour}}},
		{host: "app", addrs: []string{"10.0.0.11"}, time: now,
			edges: []tEdge{{role: "client", proto: "tcp", local: "10.0.0.11", peer: "10.0.0.5", port: 8080, svc: "app", comm: "app",
				opened: 1, first: hour}}},
	} {
		consume(t, c, sink, a)
	}
	c.flush(context.Background())
	got := queryStrings(t, conn, `SELECT coalesce(server_service, '-'), port FROM shawk_v1.dependencies WHERE client_service = 'app'`)
	if !slices.Equal(got, []string{"web 80"}) {
		t.Errorf("app depends on %q", got)
	}
}

// TestPGLearnedLoopbackScope: a loopback client and a loopback backend are
// matched in the host and the network namespace of the learned row only.
func TestPGLearnedLoopbackScope(t *testing.T) {
	c, sink, conn := pgConnectorWith(t, nil)
	now := time.Now().UTC().Truncate(time.Second)
	hour := now.Add(-time.Hour)
	client := func(svc, netns string) tEdge {
		return tEdge{role: "client", proto: "tcp", local: "127.0.0.1", peer: "10.96.0.30", port: 80, svc: svc, comm: svc,
			opened: 1, first: hour, netns: netns}
	}
	server := func(svc, netns string) tEdge {
		return tEdge{role: "server", proto: "tcp", local: "127.0.0.1", peer: "127.0.0.1", port: 8080, svc: svc, comm: svc,
			opened: 1, first: hour, netns: netns}
	}
	for _, a := range []tAgent{
		{host: "h1", addrs: []string{"127.0.0.1", "10.0.0.11"}, time: now,
			edges: []tEdge{client("a", "100"), client("b", "200"), server("proxy", "100"), server("other", "200")},
			translations: []tTranslation{{client: "127.0.0.1", virtual: "10.96.0.30", vport: 80, backend: "127.0.0.1", bport: 8080,
				netns: "100", first: hour}}},
		{host: "h2", addrs: []string{"127.0.0.1", "10.0.0.12"}, time: now, edges: []tEdge{client("c", "100")}},
	} {
		consume(t, c, sink, a)
	}
	c.flush(context.Background())
	checkDeps(t, func(s string, args ...any) []string { return queryStrings(t, conn, s, args...) }, []string{
		"- - 127.0.0.1 h1 other 127.0.0.1 8080 server - - -",
		"h1 a 127.0.0.1 h1 proxy 127.0.0.1 8080 both 10.96.0.30 80 ~learned",
		"h1 b 127.0.0.1 - - 10.96.0.30 80 client - - -",
		"h2 c 127.0.0.1 - - 10.96.0.30 80 client - - -",
	})
}

// TestPGLearnedSharedBackend: a backend at an address several hosts hold
// (a container bridge) is matched on the host of the learned row only.
func TestPGLearnedSharedBackend(t *testing.T) {
	c, sink, conn := pgConnectorWith(t, nil)
	now := time.Now().UTC().Truncate(time.Second)
	hour := now.Add(-time.Hour)
	server := func(host, addr, svc string, xs ...tTranslation) tAgent {
		return tAgent{host: host, addrs: []string{"127.0.0.1", addr, "172.17.0.1", "172.17.0.5"}, time: now,
			edges: []tEdge{{role: "server", proto: "tcp", local: "172.17.0.5", peer: "10.0.0.11", port: 80, svc: svc, comm: svc,
				opened: 1, first: hour}},
			translations: xs}
	}
	for _, a := range []tAgent{
		server("h1", "10.0.0.1", "web", tTranslation{client: "10.0.0.11", virtual: "10.0.0.1", vport: 8080,
			backend: "172.17.0.5", bport: 80, first: hour}),
		server("h2", "10.0.0.2", "billing"),
		{host: "app", addrs: []string{"10.0.0.11"}, time: now, edges: []tEdge{{role: "client", proto: "tcp", local: "10.0.0.11",
			peer: "10.0.0.1", port: 8080, svc: "app", comm: "app", opened: 1, first: hour}}},
	} {
		consume(t, c, sink, a)
	}
	c.flush(context.Background())
	execAll(t, conn, `UPDATE shawk.host_addrs SET first_seen = first_seen - interval '1 hour'`)
	checkDeps(t, func(s string, args ...any) []string { return queryStrings(t, conn, s, args...) }, []string{
		"- - 10.0.0.11 h2 billing 172.17.0.5 80 server - - -",
		"app app 10.0.0.11 h1 web 172.17.0.5 80 both 10.0.0.1 8080 ~learned",
	})
}

// TestPGLearnedOverlaps: a pair needs the client edge, the server edge and
// the learned row to overlap each other; a ClusterIP or a pod address used
// again later does not pair an old edge with a new one over the time in
// between.
func TestPGLearnedOverlaps(t *testing.T) {
	c, sink, conn := pgConnectorWith(t, nil)
	now := time.Now().UTC().Truncate(time.Second)
	h := func(n int) time.Time { return now.Add(-time.Duration(n) * time.Hour) }
	type period struct{ first, last time.Time }
	var app []tEdge
	var xs []tTranslation
	var agents []tAgent
	// Each case: the periods of the client edge, the server edge and the
	// learned row, which do not all overlap.
	for i, k := range []struct{ c, s, l period }{
		{period{h(10), now}, period{h(2), now}, period{h(10), h(9)}}, // the server edge starts after the row
		{period{h(10), now}, period{h(10), h(9)}, period{h(2), now}}, // the row starts after the server edge
		{period{h(10), h(8)}, period{h(10), now}, period{h(2), now}}, // the row starts after the client edge
		{period{h(10), h(8)}, period{h(2), now}, period{h(10), now}}, // the server edge starts after the client edge
		{period{h(2), now}, period{h(10), h(8)}, period{h(10), now}}, // the client edge starts after the server edge
	} {
		virtual, backend := fmt.Sprintf("10.96.0.%d", 40+i), fmt.Sprintf("10.0.1.%d", 40+i)
		app = append(app, tEdge{role: "client", proto: "tcp", local: "10.0.0.11", peer: virtual, port: 80, svc: "app", comm: "app",
			opened: 1, first: k.c.first, last: k.c.last})
		xs = append(xs, tTranslation{client: "10.0.0.11", virtual: virtual, vport: 80, backend: backend, bport: 80,
			first: k.l.first, last: k.l.last})
		agents = append(agents, tAgent{host: fmt.Sprintf("s%d", i), addrs: []string{backend}, time: now,
			edges: []tEdge{{role: "server", proto: "tcp", local: backend, peer: "10.0.0.11", port: 80, svc: "web", comm: "web",
				opened: 1, first: k.s.first, last: k.s.last}}})
	}
	agents = append(agents, tAgent{host: "app", addrs: []string{"10.0.0.11"}, time: now, edges: app, translations: xs})
	for _, a := range agents {
		consume(t, c, sink, a)
	}
	c.flush(context.Background())
	var want []string
	for i := range 5 {
		want = append(want, fmt.Sprintf("- - 10.0.0.11 s%d web 10.0.1.%d 80 server - - -", i, 40+i))
	}
	for i := range 5 {
		want = append(want, fmt.Sprintf("app app 10.0.0.11 - - 10.96.0.%d 80 client - - -", 40+i))
	}
	checkDeps(t, func(s string, args ...any) []string { return queryStrings(t, conn, s, args...) }, want)
}

// TestPGLearnedStaticAnyPort: a static translation of a virtual address
// without a port comes before the learned rows of every port of it.
func TestPGLearnedStaticAnyPort(t *testing.T) {
	c, sink, conn := pgConnectorWith(t, func(cfg *Config) {
		cfg.Translations = map[string]TranslationConfig{
			"vip": {Virtual: []string{"10.0.100.5"}, Backends: []string{"10.0.1.50"}},
		}
	})
	now := time.Now().UTC().Truncate(time.Second)
	hour := now.Add(-time.Hour)
	server := func(host, addr string) tAgent {
		return tAgent{host: host, addrs: []string{addr}, time: now,
			edges: []tEdge{{role: "server", proto: "tcp", local: addr, peer: "10.0.0.11", port: 443, svc: host, comm: host,
				opened: 1, first: hour}}}
	}
	for _, a := range []tAgent{server("db50", "10.0.1.50"), server("db60", "10.0.1.60"),
		{host: "app", addrs: []string{"10.0.0.11"}, time: now,
			edges: []tEdge{{role: "client", proto: "tcp", local: "10.0.0.11", peer: "10.0.100.5", port: 443, svc: "app", comm: "app",
				opened: 1, first: hour}},
			translations: []tTranslation{{client: "10.0.0.11", virtual: "10.0.100.5", vport: 443, backend: "10.0.1.60", bport: 443,
				first: hour}}},
	} {
		consume(t, c, sink, a)
	}
	c.flush(context.Background())
	checkDeps(t, func(s string, args ...any) []string { return queryStrings(t, conn, s, args...) }, []string{
		"- - 10.0.0.11 db60 db60 10.0.1.60 443 server - - -",
		"app app 10.0.0.11 db50 db50 10.0.1.50 443 both 10.0.100.5 443 vip",
	})
}
