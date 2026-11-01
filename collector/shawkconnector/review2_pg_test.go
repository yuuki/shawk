package shawkconnector

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// PostgreSQL tests of the findings of a second adversarial review.

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

// TestPGReturningDependencyIsNotNew: a dependency idle for a while that came
// back on new edges, e.g. from a new container, was reported as new.
func TestPGReturningDependencyIsNotNew(t *testing.T) {
	_, conn := migratedDB(t)
	f := fixture{t, conn}
	f.host("report-01", "report")
	f.host("report-02", "report")
	f.host("db-01", "postgres")
	f.host("cache-01", "memcached")
	f.conn2("report-01", "report", "10.0.0.21", "db-01", "postgres", "10.0.0.10", 5432,
		"now()-interval '2 days'", "now()-interval '2 days'+interval '1 hour'")
	// The history is built from all edges, as when the schema is migrated
	// over existing data.
	execAll(t, conn, `DELETE FROM shawk.known_dependencies_state`, `SELECT shawk.refresh_known_dependencies(interval '0')`)
	// It comes back from another host, and a dependency never seen appears.
	f.conn2("report-02", "report", "10.0.0.22", "db-01", "postgres", "10.0.0.10", 5432,
		"now()-interval '2 minutes'", "now()-interval '1 minute'")
	f.conn2("report-02", "report", "10.0.0.22", "cache-01", "memcached", "10.0.0.30", 11211,
		"now()-interval '2 minutes'", "now()-interval '1 minute'")
	got := queryStrings(t, conn, `SELECT change, client_service, server_service
		FROM shawk_v1.dependency_changes_between(now() - interval '15 minutes', now())`)
	if !slices.Equal(got, []string{"appeared report memcached"}) {
		t.Errorf("changes = %v", got)
	}
}

// TestPGRotatingAddressesFold: a peer without a service was named by its
// address, so that every new address of a cloud API was a new dependency,
// and every address it stopped using a disappeared one.
func TestPGRotatingAddressesFold(t *testing.T) {
	_, conn := migratedDB(t)
	f := fixture{t, conn}
	f.host("web-01", "web")
	execAll(t, conn, `INSERT INTO shawk.peer_cidrs VALUES ('192.168.10.0/24', 'office-lan')`)
	for i := range 6 {
		f.edge("web-01", "web", "client", "10.0.0.11", fmt.Sprintf("3.5.%d.20", i), 443,
			fmt.Sprintf("now()-interval '%d minutes'", 60-i*5), fmt.Sprintf("now()-interval '%d minutes'", 30-i*5))
	}
	f.edge("web-01", "web", "client", "10.0.0.11", "192.168.10.5", 389, "now()-interval '1 day'", "now()")
	execAll(t, conn, `DELETE FROM shawk.known_dependencies_state`, `SELECT shawk.refresh_known_dependencies(interval '0')`)
	got := queryStrings(t, conn, `SELECT change, client_service, server_service
		FROM shawk_v1.dependency_changes_between(now() - interval '40 minutes', now())`)
	if len(got) != 0 {
		t.Errorf("changes = %v", got)
	}
	got = queryStrings(t, conn, `SELECT source, target FROM shawk_v1.graph_edges_between(now() - interval '1 day', now())`)
	if !slices.Equal(got, []string{"web office-lan", "web ~external"}) {
		t.Errorf("graph_edges = %v", got)
	}
}

// TestPGWindowEdgeSides: at the edges of a period one side of a connection
// was left out, and the other came out alone named after its address.
func TestPGWindowEdgeSides(t *testing.T) {
	_, conn := migratedDB(t)
	f := fixture{t, conn}
	f.host("web-01", "web")
	f.host("db-01", "postgres")
	f.edge("web-01", "web", "client", "10.0.0.11", "10.0.0.10", 5432, "now()-interval '2 hours'", "now()-interval '29 minutes 40 seconds'")
	f.edge("db-01", "postgres", "server", "10.0.0.10", "10.0.0.11", 5432, "now()-interval '2 hours'", "now()-interval '30 minutes 20 seconds'")
	got := queryStrings(t, conn, `SELECT client_service, server_service, observed_by
		FROM shawk_v1.dependencies_between(now() - interval '30 minutes', now())`)
	if !slices.Equal(got, []string{"web postgres both"}) {
		t.Errorf("dependencies_between = %v", got)
	}
	// A connection active only before the period is not in it.
	got = queryStrings(t, conn, `SELECT count(*) FROM shawk_v1.dependencies_between(now() - interval '20 minutes', now())`)
	if !slices.Equal(got, []string{"0"}) {
		t.Errorf("dependencies in the last 20 minutes = %v", got)
	}
}

// TestPGAddressPeriods: an address that moved to another host and came back
// was held by the first host all along: it counted as shared, and the host
// it had moved to kept it.
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
		pk := procKey{"haproxy.service", "haproxy", "haproxy"}
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

// TestPGPruneWaitsForMigration: prune took the locks of tables in the
// reverse order of a migration and deadlocked with it; it now waits for the
// lock of migrations, like writes.
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
// of the schema; one without the function is older.
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
}
