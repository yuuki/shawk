package shawkconnector

import (
	"context"
	"fmt"
	"net/url"
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
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
	if len(applied) == 0 || applied[0] != "0001_init.sql" {
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

// pgConnector returns a started connector writing to a fresh database.
func pgConnector(t *testing.T) (*shawkConnector, *consumertest.MetricsSink, *pgx.Conn) {
	t.Helper()
	dsn, conn := testDB(t)
	cfg := createDefaultConfig()
	cfg.Postgres.DSN = dsn
	cfg.Postgres.Migrate = true
	cfg.WriteInterval = 10 * time.Minute
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
	if !c.migrated {
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

	agents := queryStrings(t, conn, `SELECT host, alive, udp_traced, netns_scope, started_at = $1 FROM shawk_v1.agents`, base.Add(-time.Hour))
	if !slices.Equal(agents, []string{"app-01 true false all true", "db-01 true false all true"}) {
		t.Errorf("agents = %v", agents)
	}

	addrs := queryStrings(t, conn, `SELECT host(addr), host FROM shawk_v1.agent_addrs WHERE NOT addr << '127.0.0.0/8'`)
	if !slices.Equal(addrs, []string{"10.0.0.10 db-01", "10.0.0.11 app-01", "fe80::1 db-01"}) {
		t.Errorf("agent_addrs = %v", addrs)
	}

	edges := queryStrings(t, conn, `SELECT source, target, mainstat FROM shawk_v1.graph_edges`)
	if !slices.Contains(edges, "shop/app postgres 5432/tcp") || !slices.Contains(edges, "10.0.0.50 postgres 5432/tcp") {
		t.Errorf("graph_edges = %v", edges)
	}
	nodes := queryStrings(t, conn, `SELECT id, subtitle, mainstat FROM shawk_v1.graph_nodes`)
	if !slices.Contains(nodes, "postgres db-01 1") || !slices.Contains(nodes, "93.184.215.14  0") {
		t.Errorf("graph_nodes = %v", nodes)
	}

	changes := queryStrings(t, conn, `SELECT change, client_service, server_service FROM shawk_v1.dependency_changes`)
	if !slices.Contains(changes, "disappeared 10.0.0.50 postgres") || !slices.Contains(changes, "appeared shop/app postgres") ||
		slices.Contains(changes, "disappeared shop/app postgres") {
		t.Errorf("dependency_changes = %v", changes)
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
	old.addProcess(procKey{"app.service", "puma"}, "/old", "old", span{base.Add(-48 * time.Hour), base.Add(-48 * time.Hour)})
	old.addEdge(edgeRowKey{role: "client", proto: "tcp", local: addrOf("10.0.0.11"), peer: addrOf("10.0.0.10"), port: 5432,
		netns: 4026531840, procKey: procKey{"app.service", "puma"}}, span{base.Add(-48 * time.Hour), base.Add(-48 * time.Hour)})
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
		consume(t, c, sink, tAgent{host: "h1", machineID: "m1", addrs: []string{"10.0.0.1"}, time: s.at, segment: s.start})
	}
	c.flush(ctx)
	got := queryStrings(t, conn, `SELECT host, gap_start = $1, gap_end = $2 FROM shawk_v1.unobserved($3, $4)`,
		now.Add(-87*time.Minute), now.Add(-30*time.Minute), now.Add(-3*time.Hour), now)
	// Before the first session and between them; the last heartbeat plus
	// the tolerance reaches now.
	if len(got) != 2 || !slices.Contains(got, "h1 true true") {
		t.Errorf("unobserved = %v", got)
	}
	got = queryStrings(t, conn, `SELECT host FROM shawk_v1.unobserved($1, $2)`, now.Add(-20*time.Minute), now.Add(-5*time.Minute))
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
		pk := procKey{host + ".service", host}
		h.addProcess(pk, "/usr/bin/"+host, host, span{at, at})
		for i := range 5 {
			h.addEdge(edgeRowKey{role: "client", proto: "tcp", local: addrOf("10.0.0.1"), peer: addrOf("10.0.1.1"),
				port: port + uint16(i), netns: 1, procKey: pk}, span{at, at})
		}
		h.addListener(listenerRowKey{proto: "tcp", addr: addrOf("0.0.0.0"), port: port, netns: 1}, pk, span{at, at})
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
