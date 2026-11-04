package shawkconnector

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"go.opentelemetry.io/collector/connector/connectortest"
	"go.opentelemetry.io/collector/consumer/consumertest"
)

// The tests in this file run against PostgreSQL when SHAWK_TEST_POSTGRES_DSN
// is a URL of a role that may create databases, e.g.
// postgres://postgres@127.0.0.1:5432/postgres. Each test creates its own
// database and drops it at the end.

func testDB(t *testing.T) (string, *pgx.Conn) {
	t.Helper()
	base := os.Getenv("SHAWK_TEST_POSTGRES_DSN")
	if base == "" {
		t.Skip("SHAWK_TEST_POSTGRES_DSN is not set")
	}
	ctx := context.Background()
	admin, err := pgx.Connect(ctx, base)
	if err != nil {
		t.Fatal(err)
	}
	name := fmt.Sprintf("shawk_test_%d", time.Now().UnixNano())
	if _, err := admin.Exec(ctx, "CREATE DATABASE "+name); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		admin.Exec(ctx, "DROP DATABASE "+name+" WITH (FORCE)")
		admin.Close(ctx)
	})
	u, err := url.Parse(base)
	if err != nil {
		t.Fatal(err)
	}
	u.Path = "/" + name
	conn, err := pgx.Connect(ctx, u.String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close(ctx) })
	return u.String(), conn
}

func TestPGMigrate(t *testing.T) {
	_, conn := testDB(t)
	ctx := context.Background()
	applied, err := Migrate(ctx, conn)
	if err != nil {
		t.Fatal(err)
	}
	if len(applied) == 0 || applied[0] != "0001_schema.sql" {
		t.Errorf("applied = %v", applied)
	}
	applied, err = Migrate(ctx, conn)
	if err != nil || len(applied) != 0 {
		t.Errorf("second migration applied %v, %v", applied, err)
	}
	var v int
	conn.QueryRow(ctx, `SELECT max(version) FROM shawk.schema_migrations`).Scan(&v)
	if v != SchemaVersion() {
		t.Errorf("schema version %d, want %d", v, SchemaVersion())
	}
}

// TestPGMigrateDevelopmentSchema: a database whose history of migrations
// is not that of the bundled migrations, as one created before they were
// consolidated, is refused rather than taken as up to date.
func TestPGMigrateDevelopmentSchema(t *testing.T) {
	_, conn := testDB(t)
	ctx := context.Background()
	if _, err := conn.Exec(ctx, `CREATE SCHEMA shawk;
CREATE TABLE shawk.schema_migrations (version integer PRIMARY KEY, name text NOT NULL, applied_at timestamptz NOT NULL DEFAULT now());
INSERT INTO shawk.schema_migrations (version, name) VALUES (1, '0001_init.sql'), (2, '0002_client_endpoints.sql')`); err != nil {
		t.Fatal(err)
	}
	applied, err := Migrate(ctx, conn)
	if err == nil || !strings.Contains(err.Error(), "drop the schemas shawk and shawk_v1") {
		t.Errorf("Migrate = %v, %v; want an error that tells to recreate the schema", applied, err)
	}
}

// pgConnector returns a started connector writing to a fresh database.
func pgConnector(t *testing.T) (*shawkConnector, *consumertest.MetricsSink, *pgx.Conn) {
	t.Helper()
	return pgConnectorWith(t, nil)
}

// pgConnectorWith returns a started connector with the configuration mod
// changes, writing to a fresh database.
func pgConnectorWith(t *testing.T, mod func(*Config)) (*shawkConnector, *consumertest.MetricsSink, *pgx.Conn) {
	t.Helper()
	dsn, conn := testDB(t)
	cfg := createDefaultConfig()
	cfg.Postgres.DSN = dsn
	cfg.Postgres.Migrate = true
	cfg.WriteInterval = 10 * time.Minute
	if mod != nil {
		mod(cfg)
	}
	sink := new(consumertest.MetricsSink)
	c, err := newConnector(connectortest.NewNopSettings(Type), cfg, sink)
	if err != nil {
		t.Fatal(err)
	}
	c.agg.started = time.Now().Add(-24 * time.Hour)
	if err := c.Start(context.Background(), nil); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Shutdown(context.Background()) })
	if !c.ready {
		t.Fatal("not migrated")
	}
	return c, sink, conn
}

func queryStrings(t *testing.T, conn *pgx.Conn, sql string, args ...any) []string {
	t.Helper()
	rows, err := conn.Query(context.Background(), sql, args...)
	if err != nil {
		t.Fatalf("%s: %v", sql, err)
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		vals, err := rows.Values()
		if err != nil {
			t.Fatal(err)
		}
		var parts []string
		for _, v := range vals {
			parts = append(parts, fmt.Sprint(v))
		}
		out = append(out, strings.Join(parts, " "))
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("%s: %v", sql, err)
	}
	slices.Sort(out)
	return out
}

func TestPGPipeline(t *testing.T) {
	c, sink, conn := pgConnector(t)
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Second)
	base := now.Add(-time.Minute)

	redis := func(host string) []tEdge {
		return []tEdge{
			{role: "client", proto: "tcp", local: "127.0.0.1", peer: "127.0.0.1", port: 6379, svc: host + "-worker", comm: "worker", unit: "worker.service", opened: 1},
			{role: "server", proto: "tcp", local: "127.0.0.1", peer: "127.0.0.1", port: 6379, svc: "redis", comm: "redis-server", unit: "redis.service", opened: 1},
		}
	}
	db := tAgent{host: "db-01", machineID: "m-db", addrs: []string{"127.0.0.1", "10.0.0.10", "fe80::1"}, time: base,
		segment: base.Add(-time.Hour),
		listeners: []tListener{
			{proto: "tcp", addr: "0.0.0.0", port: 5432, svc: "postgres", unit: "postgresql.service", comm: "postgres", exe: "/usr/bin/postgres"},
			{proto: "tcp", addr: "127.0.0.1", port: 6379, svc: "redis", unit: "redis.service", comm: "redis-server"},
		},
		edges: append(redis("db"),
			tEdge{role: "server", proto: "tcp", local: "10.0.0.10", peer: "10.0.0.11", port: 5432, svc: "postgres", unit: "postgresql.service", comm: "postgres", opened: 3},
			// A client without an agent, last seen an hour ago.
			tEdge{role: "server", proto: "tcp", local: "10.0.0.10", peer: "10.0.0.50", port: 5432, svc: "postgres", unit: "postgresql.service", comm: "postgres", opened: 1,
				first: now.Add(-3 * time.Hour), last: now.Add(-time.Hour)},
		)}
	app := tAgent{host: "app-01", machineID: "m-app", addrs: []string{"127.0.0.1", "10.0.0.11"}, time: base,
		segment:   base.Add(-time.Hour),
		listeners: []tListener{{proto: "tcp", addr: "127.0.0.1", port: 6379, svc: "redis", unit: "redis.service", comm: "redis-server"}},
		edges: append(redis("app"),
			tEdge{role: "client", proto: "tcp", local: "10.0.0.11", peer: "10.0.0.10", port: 5432, svc: "app", ns: "shop", unit: "app.service", comm: "puma", opened: 3},
			tEdge{role: "client", proto: "tcp", local: "10.0.0.11", peer: "93.184.215.14", port: 443, svc: "app", ns: "shop", unit: "app.service", comm: "puma", opened: 1},
		)}
	consume(t, c, sink, db)
	consume(t, c, sink, app)
	c.flush(ctx)

	deps := queryStrings(t, conn, `SELECT client_host, client_service, server_host, server_service, host(server_addr), port, observed_by,
	  client_observed_until IS NOT NULL, server_observed_until IS NOT NULL FROM shawk_v1.dependencies`)
	want := []string{
		"<nil> <nil> db-01 postgres 10.0.0.10 5432 server false true",
		"app-01 app-worker app-01 redis 127.0.0.1 6379 both true true",
		"app-01 shop/app <nil> <nil> 93.184.215.14 443 client true false",
		"app-01 shop/app db-01 postgres 10.0.0.10 5432 both true true",
		"db-01 db-worker db-01 redis 127.0.0.1 6379 both true true",
	}
	if !slices.Equal(deps, want) {
		t.Errorf("dependencies:\n%s\nwant:\n%s", strings.Join(deps, "\n"), strings.Join(want, "\n"))
	}

	eps := queryStrings(t, conn, `SELECT host(addr), port, proto, host, service FROM shawk_v1.service_endpoints`)
	wantEps := []string{
		"10.0.0.10 5432 tcp db-01 postgres",
		"127.0.0.1 5432 tcp db-01 postgres",
		"127.0.0.1 6379 tcp app-01 redis",
		"127.0.0.1 6379 tcp db-01 redis",
	}
	if !slices.Equal(eps, wantEps) {
		t.Errorf("service_endpoints:\n%s\nwant:\n%s", strings.Join(eps, "\n"), strings.Join(wantEps, "\n"))
	}

	// The agents started an hour ago, but this connector first sees them
	// now: their sessions start no earlier than the shortest idle TTL of an
	// agent before.
	agents := queryStrings(t, conn, `SELECT host, alive, udp_traced, netns_scope, started_at = $1 FROM shawk_v1.agents`, base.Add(-minAgentIdleTTL))
	if !slices.Equal(agents, []string{"app-01 true true all true", "db-01 true true all true"}) {
		t.Errorf("agents = %v", agents)
	}

	addrs := queryStrings(t, conn, `SELECT host(addr), host FROM shawk_v1.agent_addrs WHERE NOT addr << '127.0.0.0/8'`)
	if !slices.Equal(addrs, []string{"10.0.0.10 db-01", "10.0.0.11 app-01", "fe80::1 db-01"}) {
		t.Errorf("agent_addrs = %v", addrs)
	}

	edges := queryStrings(t, conn, `SELECT source, target, mainstat FROM shawk_v1.graph_edges`)
	// Peers without a known service are named like in Prometheus.
	if !slices.Contains(edges, "shop/app postgres 5432/tcp") || !slices.Contains(edges, "~unresolved postgres 5432/tcp") {
		t.Errorf("graph_edges = %v", edges)
	}
	nodes := queryStrings(t, conn, `SELECT id, subtitle, mainstat FROM shawk_v1.graph_nodes`)
	if !slices.Contains(nodes, "postgres db-01 1") || !slices.Contains(nodes, "~external  0") {
		t.Errorf("graph_nodes = %v", nodes)
	}

	changes := queryStrings(t, conn, `SELECT change, client_service, server_service FROM shawk_v1.dependency_changes`)
	if !slices.Contains(changes, "disappeared ~unresolved postgres") || !slices.Contains(changes, "appeared shop/app postgres") ||
		slices.Contains(changes, "disappeared shop/app postgres") {
		t.Errorf("dependency_changes = %v", changes)
	}

	// The functions over a period return what the views return for the
	// dependencies active in it.
	for _, q := range [][2]string{
		{`SELECT client_service, server_service, port, observed_by FROM shawk_v1.dependencies WHERE last_seen >= $1`,
			`SELECT client_service, server_service, port, observed_by FROM shawk_v1.dependencies_between($1, now())`},
		{`SELECT source, target, mainstat FROM shawk_v1.graph_edges WHERE last_seen >= $1`,
			`SELECT source, target, mainstat FROM shawk_v1.graph_edges_between($1, now())`},
		{`SELECT change, client_service, server_service FROM shawk_v1.dependency_changes WHERE time >= $1`,
			`SELECT change, client_service, server_service FROM shawk_v1.dependency_changes_between($1, now())`},
	} {
		for _, since := range []time.Time{now.Add(-30 * time.Minute), now.Add(-2 * time.Hour)} {
			view, fn := queryStrings(t, conn, q[0], since), queryStrings(t, conn, q[1], since)
			if !slices.Equal(view, fn) || len(fn) == 0 {
				t.Errorf("since %v:\n%s\n%v\n%s\n%v", since, q[0], view, q[1], fn)
			}
		}
	}
	if got := queryStrings(t, conn, `SELECT count(*) FROM shawk_v1.dependencies_between($1, $2)`,
		now.Add(-48*time.Hour), now.Add(-47*time.Hour)); !slices.Equal(got, []string{"0"}) {
		t.Errorf("dependencies two days ago = %v", got)
	}

	// The names of peers come from the database after a reload.
	c2, sink2, _ := func() (*shawkConnector, *consumertest.MetricsSink, *pgx.Conn) {
		cfg := *c.cfg
		cfg.Postgres.Migrate = false
		s := new(consumertest.MetricsSink)
		c2, err := newConnector(connectortest.NewNopSettings(Type), &cfg, s)
		if err != nil {
			t.Fatal(err)
		}
		if err := c2.Start(ctx, nil); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { c2.Shutdown(ctx) })
		return c2, s, conn
	}()
	// The server side first: its client is named from client_endpoints.
	db.time = base.Add(15 * time.Second)
	out := consume(t, c2, sink2, db)
	var server []series
	for _, s := range find(out, metricConnOpened, "postgres", "*", roleServer, "") {
		if s.port == 5432 && s.peer == "shop/app" && s.agent {
			server = append(server, s)
		}
	}
	if len(server) != 1 {
		t.Errorf("client of a server edge not named from the database: %v", find(out, metricConnOpened, "postgres", "*", roleServer, ""))
	}
	app.time = base.Add(15 * time.Second)
	app.listeners = nil
	out = consume(t, c2, sink2, app)
	if s := find(out, metricConnOpened, "shop/app", "postgres", roleClient, ""); len(s) != 1 || !s[0].agent {
		t.Errorf("peer not named from the database: %v", find(out, metricConnOpened, "shop/app", "*", roleClient, ""))
	}

	// Replaying older data does not move times back.
	var before time.Time
	conn.QueryRow(ctx, `SELECT max(last_seen) FROM shawk.edges`).Scan(&before)
	old := newHostChanges(hostKey("m-app", "app-01"))
	old.setHost("m-app", "app-01", "4.18", "old", base.Add(-48*time.Hour))
	old.addProcess(procKey{"app.service", "puma", "shop/app", ""}, "/old", span{base.Add(-48 * time.Hour), base.Add(-48 * time.Hour)})
	old.addEdge(edgeRowKey{role: "client", proto: "tcp", local: addrOf("10.0.0.11"), peer: addrOf("10.0.0.10"), port: 5432,
		netns: 4026531840, procKey: procKey{"app.service", "puma", "shop/app", ""}}, span{base.Add(-48 * time.Hour), base.Add(-48 * time.Hour)})
	if err := c.store.write(ctx, old); err != nil {
		t.Fatal(err)
	}
	got := queryStrings(t, conn, `SELECT h.kernel, p.service_name, e.first_seen = $1, e.last_seen = $2
	  FROM shawk.edges e JOIN shawk.processes p ON p.id = e.process_id JOIN shawk.hosts h ON h.id = e.host_id
	  WHERE h.hostname = 'app-01' AND e.port = 5432`, base.Add(-48*time.Hour), base)
	if !slices.Equal(got, []string{"5.14.0 shop/app true true"}) {
		t.Errorf("after a replay = %v", got)
	}
}

func TestPGUnobserved(t *testing.T) {
	c, sink, conn := pgConnector(t)
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Second)
	// Two sessions with a gap between them.
	for _, s := range []struct{ start, at time.Time }{
		{now.Add(-2 * time.Hour), now.Add(-90 * time.Minute)},
		{now.Add(-30 * time.Minute), now.Add(-time.Minute)},
	} {
		// The connector receives the requests at the times of the agent.
		c.now = func() time.Time { return s.at }
		consume(t, c, sink, tAgent{host: "h1", machineID: "m1", addrs: []string{"10.0.0.1"}, time: s.at, segment: s.start})
	}
	// An agent whose clock is ten minutes behind is alive by the clock of
	// the connector, and its skew is kept.
	c.now = time.Now
	consume(t, c, sink, tAgent{host: "h2", machineID: "m2", addrs: []string{"10.0.0.2"}, time: now.Add(-10 * time.Minute),
		segment: now.Add(-time.Hour)})
	c.flush(ctx)
	agents := queryStrings(t, conn, `SELECT host, alive, round(extract(epoch FROM clock_skew) / 60)::int FROM shawk_v1.agents ORDER BY host`)
	if !slices.Equal(agents, []string{"h1 true 0", "h2 true 10"}) {
		t.Errorf("agents = %v", agents)
	}
	got := queryStrings(t, conn, `SELECT host, gap_start = $1, gap_end = $2 FROM shawk_v1.unobserved($3, $4) WHERE host = 'h1'`,
		now.Add(-87*time.Minute), now.Add(-30*time.Minute), now.Add(-3*time.Hour), now)
	// Before the first session and between them; the last heartbeat plus
	// the tolerance reaches now.
	if len(got) != 2 || !slices.Contains(got, "h1 true true") {
		t.Errorf("unobserved = %v", got)
	}
	got = queryStrings(t, conn, `SELECT host FROM shawk_v1.unobserved($1, $2) WHERE host = 'h1'`, now.Add(-20*time.Minute), now.Add(-5*time.Minute))
	if len(got) != 0 {
		t.Errorf("unobserved within a session = %v", got)
	}
}

// TestPGReaderRole checks that a role with SELECT on shawk_v1 only can read
// the contract, but not the tables.
func TestPGReaderRole(t *testing.T) {
	c, sink, conn := pgConnector(t)
	ctx := context.Background()
	consume(t, c, sink, tAgent{host: "h1", machineID: "m1", addrs: []string{"10.0.0.1"}, time: time.Now(),
		edges: []tEdge{{role: "client", proto: "tcp", local: "10.0.0.1", peer: "10.0.0.2", port: 80, svc: "a", comm: "a", opened: 1}}})
	c.flush(ctx)
	role := fmt.Sprintf("shawk_reader_%d", time.Now().UnixNano())
	for _, q := range []string{
		"CREATE ROLE " + role + " NOLOGIN",
		"GRANT USAGE ON SCHEMA shawk_v1 TO " + role,
		"GRANT SELECT ON ALL TABLES IN SCHEMA shawk_v1 TO " + role,
	} {
		if _, err := conn.Exec(ctx, q); err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(func() {
		conn.Exec(ctx, "RESET ROLE")
		conn.Exec(ctx, "DROP OWNED BY "+role)
		conn.Exec(ctx, "DROP ROLE "+role)
	})
	if _, err := conn.Exec(ctx, "SET ROLE "+role); err != nil {
		t.Fatal(err)
	}
	for _, q := range []string{
		"SELECT count(*) FROM shawk_v1.dependencies",
		"SELECT count(*) FROM shawk_v1.graph_nodes",
		"SELECT count(*) FROM shawk_v1.graph_edges",
		"SELECT count(*) FROM shawk_v1.dependency_changes",
		"SELECT count(*) FROM shawk_v1.service_endpoints",
		"SELECT count(*) FROM shawk_v1.agent_addrs",
		"SELECT count(*) FROM shawk_v1.agents",
		"SELECT count(*) FROM shawk_v1.unobserved(now() - interval '1 day', now())",
		"SELECT count(*) FROM shawk_v1.unobserved_by_name(now() - interval '1 day', now())",
		"SELECT count(*) FROM shawk_v1.partly_observed(now() - interval '1 day', now())",
		"SELECT count(*) FROM shawk_v1.client_endpoints",
		"SELECT count(*) FROM shawk_v1.dependencies_between(now() - interval '1 day', now())",
		"SELECT count(*) FROM shawk_v1.graph_edges_between(now() - interval '1 day', now())",
		"SELECT count(*) FROM shawk_v1.graph_nodes_between(now() - interval '1 day', now())",
		"SELECT count(*) FROM shawk_v1.dependency_changes_between(now() - interval '1 day', now())",
	} {
		var n int
		if err := conn.QueryRow(ctx, q).Scan(&n); err != nil {
			t.Errorf("%s: %v", q, err)
		}
	}
	var n int
	if err := conn.QueryRow(ctx, "SELECT count(*) FROM shawk.edges").Scan(&n); err == nil {
		t.Error("the reader can read the tables")
	}
}

func TestPGPrune(t *testing.T) {
	c, _, conn := pgConnector(t)
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Second)
	old := now.Add(-4 * 365 * 24 * time.Hour)
	write := func(host string, at time.Time, port uint16) {
		h := newHostChanges(hostKey("m", host))
		h.setHost("m", host, "5.14", "test", at)
		h.addSession(at.Add(-time.Hour), sessionRow{lastHeartbeat: at, netnsScope: "all"})
		h.addAddr(addrOf("10.0.0.1"), span{at, at})
		pk := procKey{host + ".service", host, host, ""}
		h.addProcess(pk, "/usr/bin/"+host, span{at, at})
		for i := range 5 {
			h.addEdge(edgeRowKey{role: "client", proto: "tcp", local: addrOf("10.0.0.1"), peer: addrOf("10.0.1.1"),
				port: port + uint16(i), netns: 1, procKey: pk}, span{at, at})
		}
		h.addListener(listenerRowKey{proto: "tcp", addr: addrOf("0.0.0.0"), port: port, netns: 1, procKey: pk}, span{at, at})
		if err := c.store.write(ctx, h); err != nil {
			t.Fatal(err)
		}
	}
	write("gone-01", old, 80)  // a host decommissioned four years ago
	write("live-01", old, 80)  // a live host with old dependencies
	write("live-01", now, 443) // and recent ones
	var total int64
	for i := 0; ; i++ {
		n, err := c.store.prune(ctx, 3*365*24*time.Hour, 2)
		if err != nil {
			t.Fatal(err)
		}
		if n == 0 {
			break
		}
		if i > 20 {
			t.Fatal("prune does not end")
		}
		total += n
	}
	got := queryStrings(t, conn, `
SELECT 'hosts', string_agg(hostname, ',' ORDER BY hostname) FROM shawk.hosts
UNION ALL SELECT 'edges', string_agg(DISTINCT port::text, ',') FROM shawk.edges
UNION ALL SELECT 'listeners', string_agg(port::text, ',') FROM shawk.listeners
UNION ALL SELECT 'processes', count(*)::text FROM shawk.processes
UNION ALL SELECT 'sessions', count(*)::text FROM shawk.agent_sessions`)
	want := []string{"edges 443,444,445,446,447", "hosts live-01", "listeners 443", "processes 1", "sessions 1"}
	if !slices.Equal(got, want) {
		t.Errorf("after pruning %d rows: %v, want %v", total, got, want)
	}
}

// TestPGSharedAddresses checks that edges through an address several hosts
// hold, the gateway of a container bridge, match within their host only.
func TestPGSharedAddresses(t *testing.T) {
	c, sink, conn := pgConnector(t)
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Second)
	// Both hosts hold the bridge address for 20 minutes; held together for
	// less than 10 minutes it would not count as shared.
	for _, h := range []string{"a-01", "b-01"} {
		for _, at := range []time.Time{now.Add(-20 * time.Minute), now} {
			c.now = func() time.Time { return at }
			consume(t, c, sink, tAgent{host: h, machineID: "m-" + h, addrs: []string{"172.17.0.1"}, time: at, segment: now.Add(-time.Hour),
				edges: []tEdge{
					{role: "client", proto: "tcp", local: "172.17.0.2", peer: "172.17.0.1", port: 5432, svc: h + "-app", comm: "app", opened: 1},
					{role: "server", proto: "tcp", local: "172.17.0.1", peer: "172.17.0.2", port: 5432, svc: h + "-db", comm: "db", opened: 1},
				}})
		}
	}
	c.now = time.Now
	c.flush(ctx)
	got := queryStrings(t, conn, `SELECT client_service, server_service, observed_by FROM shawk_v1.dependencies`)
	want := []string{"a-01-app a-01-db both", "b-01-app b-01-db both"}
	if !slices.Equal(got, want) {
		t.Errorf("dependencies = %v, want %v", got, want)
	}
}

// TestPGLastKnownEndpoints checks which endpoints name peers: the last
// known listeners of each host, not those of hosts gone for a month or of
// addresses taken over by another host.
func TestPGLastKnownEndpoints(t *testing.T) {
	c, sink, conn := pgConnector(t)
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Second)
	day := 24 * time.Hour
	report := func(at time.Time, ta tAgent) {
		c.now = func() time.Time { return at }
		ta.time, ta.segment = at, at.Add(-time.Hour)
		ta.machineID = "m-" + ta.host
		consume(t, c, sink, ta)
	}
	lst := func(addr string, port int64, svc string) tListener {
		return tListener{proto: "tcp", addr: addr, port: port, svc: svc, comm: svc}
	}
	// The agent of quiet-01 stopped ten days ago; its services keep names.
	report(now.Add(-10*day), tAgent{host: "quiet-01", addrs: []string{"10.0.0.5"}, listeners: []tListener{lst("0.0.0.0", 5432, "postgres")}})
	// gone-01 stopped forty days ago.
	report(now.Add(-40*day), tAgent{host: "gone-01", addrs: []string{"10.0.0.6"}, listeners: []tListener{lst("0.0.0.0", 6379, "redis")}})
	// old-01 held 10.0.0.7 until three days ago; new-01 holds it since.
	report(now.Add(-3*day), tAgent{host: "old-01", addrs: []string{"10.0.0.7"}, listeners: []tListener{lst("10.0.0.7", 80, "web-old")}})
	report(now.Add(-2*day), tAgent{host: "new-01", addrs: []string{"10.0.0.7"}, listeners: []tListener{lst("10.0.0.7", 8080, "web-new")}})
	// live-01 closed its port 9000 two hours ago.
	report(now.Add(-2*time.Hour), tAgent{host: "live-01", addrs: []string{"10.0.0.8"},
		listeners: []tListener{lst("0.0.0.0", 9000, "old-api"), lst("0.0.0.0", 9100, "api")}})
	report(now, tAgent{host: "live-01", addrs: []string{"10.0.0.8"}, listeners: []tListener{lst("0.0.0.0", 9100, "api")}})
	c.flush(ctx)
	got := queryStrings(t, conn, `SELECT host(addr), port, service FROM shawk_v1.service_endpoints`)
	want := []string{"10.0.0.5 5432 postgres", "10.0.0.7 8080 web-new", "10.0.0.8 9100 api"}
	if !slices.Equal(got, want) {
		t.Errorf("service_endpoints = %v, want %v", got, want)
	}
}

func migratedDB(t *testing.T) (string, *pgx.Conn) {
	t.Helper()
	dsn, conn := testDB(t)
	if _, err := Migrate(context.Background(), conn); err != nil {
		t.Fatal(err)
	}
	return dsn, conn
}

func execAll(t *testing.T, conn *pgx.Conn, stmts ...string) {
	t.Helper()
	for _, q := range stmts {
		if _, err := conn.Exec(context.Background(), q); err != nil {
			t.Fatalf("%s: %v", q, err)
		}
	}
}

// fixture writes rows of the schema directly. Times are SQL expressions.
type fixture struct {
	t    *testing.T
	conn *pgx.Conn
}

// host adds a host observed until now, with a process per service.
func (f fixture) host(id string, services ...string) {
	f.t.Helper()
	execAll(f.t, f.conn,
		fmt.Sprintf(`INSERT INTO shawk.hosts VALUES ('%s','m','%s','k','v',now()-interval '30 days',now())`, id, id),
		fmt.Sprintf(`INSERT INTO shawk.agent_sessions (host_id, started_at, last_heartbeat, udp_traced, netns_scope)
		             VALUES ('%s', now()-interval '30 days', now(), true, 'all')`, id))
	for _, svc := range services {
		execAll(f.t, f.conn, fmt.Sprintf(`INSERT INTO shawk.processes (host_id, unit, comm, exe, service_name, first_seen, last_seen)
			VALUES ('%s','%s.service','%s','','%s',now()-interval '30 days',now())`, id, svc, svc, svc))
	}
}

// edge adds an edge of the process of svc on host.
func (f fixture) edge(host, svc, role, local, remote string, port int, first, last string) {
	f.t.Helper()
	execAll(f.t, f.conn, fmt.Sprintf(`INSERT INTO shawk.edges (host_id, process_id, role, proto, local_addr, remote_addr, port, netns, first_seen, last_seen)
		VALUES ('%s', (SELECT id FROM shawk.processes WHERE host_id = '%s' AND service_name = '%s'), '%s', 'tcp', '%s', '%s', %d, 1, %s, %s)`,
		host, host, svc, role, local, remote, port, first, last))
}

// conn adds both sides of a connection from client to server.
func (f fixture) conn2(clientHost, clientSvc, clientAddr, serverHost, serverSvc, serverAddr string, port int, first, last string) {
	f.t.Helper()
	f.edge(clientHost, clientSvc, "client", clientAddr, serverAddr, port, first, last)
	f.edge(serverHost, serverSvc, "server", serverAddr, clientAddr, port, first, last)
}

// TestPGProcessesKeepTheirServices: processes of one unit with the same comm
// and different OTEL_SERVICE_NAME are kept apart, each with its edges.
func TestPGProcessesKeepTheirServices(t *testing.T) {
	dsn, conn := migratedDB(t)
	st, err := newPGStore(context.Background(), dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer st.close()
	now := time.Now().UTC().Truncate(time.Second)
	h := newHostChanges("h1")
	h.setHost("m", "h1", "k", "v", now)
	for i, svc := range []string{"billing", "mailer"} {
		pk := procKey{"workers.service", "python3", svc, ""}
		at := now.Add(time.Duration(i) * time.Minute)
		h.addProcess(pk, "/usr/bin/python3", span{at, at})
		h.addEdge(edgeRowKey{role: "client", proto: "tcp", local: addrOf("10.0.0.1"), peer: addrOf("10.0.0." + []string{"5", "6"}[i]),
			port: []uint16{5432, 25}[i], netns: 1, procKey: pk}, span{at, at})
	}
	if err := st.write(context.Background(), h); err != nil {
		t.Fatal(err)
	}
	got := queryStrings(t, conn, `SELECT client_service, port FROM shawk_v1.dependencies`)
	if !slices.Equal(got, []string{"billing 5432", "mailer 25"}) {
		t.Errorf("dependencies = %v", got)
	}
}

// TestPGSlurmJobPeers: the endpoints and clients of the processes of Slurm
// jobs read from PostgreSQL are named slurm-job, as the peers the connector
// learns, while PostgreSQL keeps the names of the processes; a process of
// the same name on the same port of the host, at another address, is not
// a job's (#173).
func TestPGSlurmJobPeers(t *testing.T) {
	dsn, conn := migratedDB(t)
	st, err := newPGStore(context.Background(), dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer st.close()
	now := time.Now().UTC().Truncate(time.Second)
	h := newHostChanges("n1")
	h.setHost("m1", "n1", "k", "v", now)
	h.addAddr(addrOf("10.0.0.1"), span{now, now})
	h.addAddr(addrOf("10.0.1.1"), span{now, now})
	job := procKey{"slurm/step", "python3", "python3", ""}
	batch := procKey{"slurm/batch", "python3", "python3", ""}
	svc := procKey{"jupyter.service", "python3", "python3", ""}
	for _, pk := range []procKey{job, batch, svc} {
		h.addProcess(pk, "/usr/bin/python3", span{now, now})
	}
	h.addListener(listenerRowKey{proto: "tcp", addr: addrOf("10.0.0.1"), port: 8888, netns: 1, procKey: job}, span{now, now})
	h.addListener(listenerRowKey{proto: "tcp", addr: addrOf("10.0.1.1"), port: 8888, netns: 1, procKey: svc}, span{now, now})
	h.addEdge(edgeRowKey{role: "server", proto: "tcp", local: addrOf("10.0.0.1"), peer: addrOf("10.0.0.2"), port: 40001,
		netns: 1, procKey: job}, span{now, now})
	h.addEdge(edgeRowKey{role: "client", proto: "tcp", local: addrOf("10.0.0.1"), peer: addrOf("10.0.0.2"), port: 5432,
		netns: 1, procKey: batch}, span{now, now})
	h.addEdge(edgeRowKey{role: "client", proto: "tcp", local: addrOf("10.0.0.1"), peer: addrOf("10.0.0.3"), port: 5432,
		netns: 1, procKey: svc}, span{now, now})
	if err := st.write(context.Background(), h); err != nil {
		t.Fatal(err)
	}
	rows, err := st.peers(context.Background(), time.Hour, 0)
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, e := range rows.endpoints {
		got = append(got, fmt.Sprint("server ", e.key.addr, ":", e.key.port, " ", e.service))
	}
	for _, c := range rows.clients {
		got = append(got, fmt.Sprint("client ", c.key.server, ":", c.key.port, " ", c.service))
	}
	slices.Sort(got)
	want := []string{"client 10.0.0.2:5432 slurm-job", "client 10.0.0.3:5432 python3",
		"server 10.0.0.1:40001 slurm-job", "server 10.0.0.1:8888 slurm-job", "server 10.0.1.1:8888 python3"}
	if !slices.Equal(got, want) {
		t.Errorf("endpoints read = %q, want %q", got, want)
	}
	if got := queryStrings(t, conn, `SELECT unit, service_name FROM shawk.processes ORDER BY 1`); !slices.Equal(got,
		[]string{"jupyter.service python3", "slurm/batch python3", "slurm/step python3"}) {
		t.Errorf("processes = %q", got)
	}
}

// TestPGAddressPeriods: an address that moves to another host and comes back
// is not held by the first host in between: it does not count as shared,
// and the host it moved to does not keep it.
func TestPGAddressPeriods(t *testing.T) {
	dsn, conn := migratedDB(t)
	ctx := context.Background()
	st, err := newPGStore(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer st.close()
	now := time.Now().UTC().Truncate(time.Second)
	day := 24 * time.Hour
	write := func(host string, first, last time.Time) {
		t.Helper()
		h := newHostChanges(host)
		h.setHost("m", host, "k", "v", last)
		h.addAddr(addrOf("10.0.0.100"), span{first, last})
		pk := procKey{"haproxy.service", "haproxy", "haproxy", ""}
		h.addProcess(pk, "", span{first, last})
		h.addListener(listenerRowKey{proto: "tcp", addr: addrOf("0.0.0.0"), port: 80, netns: 1, procKey: pk}, span{first, last})
		if err := st.write(ctx, h); err != nil {
			t.Fatal(err)
		}
	}
	// The VIP is on lb1, fails over to lb2 and back.
	write("lb1", now.Add(-20*day), now.Add(-10*day))
	write("lb2", now.Add(-10*day+time.Hour), now.Add(-8*day))
	write("lb1", now.Add(-8*day+time.Hour), now.Add(-time.Minute))
	// Writes a minute apart continue the period.
	write("lb1", now.Add(-time.Minute+15*time.Second), now)
	got := queryStrings(t, conn, `SELECT host_id, count(*) FROM shawk.host_addrs GROUP BY host_id`)
	if !slices.Equal(got, []string{"lb1 2", "lb2 1"}) {
		t.Errorf("periods = %v", got)
	}
	if got := queryStrings(t, conn, `SELECT host(addr) FROM shawk.shared_addrs`); len(got) != 0 {
		t.Errorf("shared_addrs = %v", got)
	}
	got = queryStrings(t, conn, `SELECT host, service FROM shawk_v1.service_endpoints WHERE addr = '10.0.0.100'`)
	if !slices.Equal(got, []string{"lb1 haproxy"}) {
		t.Errorf("service_endpoints = %v", got)
	}
}

// TestPGPruneKeepsRefreshedRows: a row refreshed by a concurrent write while
// prune waits for its lock is kept.
func TestPGPruneKeepsRefreshedRows(t *testing.T) {
	dsn, conn := migratedDB(t)
	ctx := context.Background()
	execAll(t, conn,
		`INSERT INTO shawk.hosts VALUES ('h','m','h','k','v',now()-interval '400 days',now())`,
		`INSERT INTO shawk.processes (host_id, unit, comm, exe, service_name, first_seen, last_seen)
		 VALUES ('h','a.service','a','','a',now()-interval '400 days',now())`,
		`INSERT INTO shawk.edges (host_id, process_id, role, proto, local_addr, remote_addr, port, netns, first_seen, last_seen)
		 VALUES ('h',(SELECT id FROM shawk.processes),'client','tcp','10.0.0.1','10.0.0.2',80,1,
		         now()-interval '400 days',now()-interval '400 days')`)
	writer, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer writer.Close(ctx)
	tx, err := writer.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(ctx, `UPDATE shawk.edges SET last_seen = now()`); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		var n int64
		done <- conn.QueryRow(ctx, `SELECT shawk.prune(now() - interval '365 days')`).Scan(&n)
	}()
	time.Sleep(300 * time.Millisecond) // prune waits for the row lock
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if got := queryStrings(t, conn, `SELECT count(*) FROM shawk.edges`); !slices.Equal(got, []string{"1"}) {
		t.Errorf("edges after prune = %v; the refreshed edge was deleted", got)
	}
}

// TestPGPruneWaitsForMigration: prune waits for the lock of migrations, like
// writes, rather than taking the locks of tables in the reverse order of a
// migration and deadlocking with it.
func TestPGPruneWaitsForMigration(t *testing.T) {
	dsn, conn := migratedDB(t)
	ctx := context.Background()
	other, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer other.Close(ctx)
	if _, err := other.Exec(ctx, `SELECT pg_advisory_lock($1)`, int64(migrationLock)); err != nil {
		t.Fatal(err)
	}
	execAll(t, conn, `SET lock_timeout = '300ms'`)
	var n int64
	err = conn.QueryRow(ctx, `SELECT shawk.prune(now() - interval '1 year')`).Scan(&n)
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) || pgErr.Code != "55P03" {
		t.Errorf("prune during a migration: %v", err)
	}
	h := newHostChanges("h")
	h.setHost("m", "h", "k", "v", time.Now())
	err = pgx.BeginFunc(ctx, conn, func(tx pgx.Tx) error { return writeHost(ctx, tx, h) })
	if !errors.As(err, &pgErr) || pgErr.Code != "55P03" {
		t.Errorf("write during a migration: %v", err)
	}
}

// TestPGSchemaVersion: a connector that does not migrate reads the version
// of the schema, 0 in a database without it.
func TestPGSchemaVersion(t *testing.T) {
	dsn, _ := migratedDB(t)
	ctx := context.Background()
	st, err := newPGStore(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer st.close()
	if v, err := st.schemaVersion(ctx); err != nil || v != SchemaVersion() {
		t.Errorf("schemaVersion = %d, %v", v, err)
	}
	empty, _ := testDB(t)
	st2, err := newPGStore(ctx, empty)
	if err != nil {
		t.Fatal(err)
	}
	defer st2.close()
	if v, err := st2.schemaVersion(ctx); err != nil || v != 0 {
		t.Errorf("schemaVersion of an empty database = %d, %v", v, err)
	}
	// A schema created before the migrations were consolidated, which has a
	// higher version, is refused rather than taken for a newer one: it has
	// no shawk.schema_history(), or its history has other migrations.
	for name, stmts := range map[string][]string{
		"without the history": {`DELETE FROM shawk.schema_migrations WHERE version > 1`,
			`UPDATE shawk.schema_migrations SET version = 13, name = '0013_learned_translations.sql'`,
			`DROP FUNCTION shawk.schema_history()`},
		"with another history": {`UPDATE shawk.schema_migrations SET name = '0001_init.sql' WHERE version = 1`},
	} {
		dsn, conn := migratedDB(t)
		execAll(t, conn, stmts...)
		st, err := newPGStore(ctx, dsn)
		if err != nil {
			t.Fatal(err)
		}
		if v, err := st.schemaVersion(ctx); !errors.Is(err, errDevelopmentSchema) {
			t.Errorf("schemaVersion of a schema %s = %d, %v", name, v, err)
		}
		st.close()
	}
}
