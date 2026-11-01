package shawkconnector

import (
	"context"
	"slices"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
)

// PostgreSQL tests of the findings of an adversarial review of the schema.

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

// TestPGUnobservedClockAhead: with an agent clock ahead of the connector,
// a young session had its start after its heartbeat and unobserved() failed
// for every host.
func TestPGUnobservedClockAhead(t *testing.T) {
	_, conn := migratedDB(t)
	execAll(t, conn,
		`INSERT INTO shawk.hosts VALUES ('h1','m','h1','k','v',now()-interval '1 day',now()),
		                                ('h2','m','h2','k','v',now()-interval '1 day',now())`,
		// h1's clock is 9 minutes ahead; its session started 1 minute ago.
		`INSERT INTO shawk.agent_sessions (host_id, started_at, last_heartbeat, udp_traced, netns_scope, clock_skew)
		 VALUES ('h1', now() + interval '8 minutes', now(), true, 'all', interval '-9 minutes'),
		        ('h2', now() - interval '2 hours', now(), true, 'all', '0')`)
	got := queryStrings(t, conn, `SELECT host, round(extract(epoch FROM gap_end - now()) / 60)::int
		FROM shawk_v1.unobserved(now() - interval '1 hour', now())`)
	// h1 was not observed until a minute ago; h2 all along.
	if !slices.Equal(got, []string{"h1 -1"}) {
		t.Errorf("unobserved = %v", got)
	}
}

// TestPGProcessesKeepTheirServices: processes of one unit with the same comm
// and different OTEL_SERVICE_NAME were merged and renamed.
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
		pk := procKey{"workers.service", "python3", svc}
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

// TestPGSharedAddressReuse: an address reused by another host within 5
// minutes counted as shared for the whole retention.
func TestPGSharedAddressReuse(t *testing.T) {
	_, conn := migratedDB(t)
	execAll(t, conn,
		`INSERT INTO shawk.hosts VALUES ('old','m','old','k','v',now()-interval '60 days',now()-interval '30 days'),
		  ('new','m','new','k','v',now()-interval '30 days',now()),
		  ('a','m','a','k','v',now()-interval '1 day',now()), ('b','m','b','k','v',now()-interval '1 day',now())`,
		`INSERT INTO shawk.host_addrs VALUES
		  ('old','10.0.0.2',now()-interval '60 days',now()-interval '30 days 2 minutes'),
		  ('new','10.0.0.2',now()-interval '30 days',now()),
		  ('a','172.17.0.1',now()-interval '1 day',now()), ('b','172.17.0.1',now()-interval '1 day',now())`)
	got := queryStrings(t, conn, `SELECT host(addr) FROM shawk.shared_addrs`)
	if !slices.Equal(got, []string{"172.17.0.1"}) {
		t.Errorf("shared_addrs = %v", got)
	}
}

// TestPGEndpointsCurrentAddresses: a listener on 0.0.0.0 was expanded to
// addresses its host gave up long ago; endpoints say whether they were
// observed on a socket.
func TestPGEndpointsCurrentAddresses(t *testing.T) {
	_, conn := migratedDB(t)
	execAll(t, conn,
		`INSERT INTO shawk.hosts VALUES ('h','m','portal-01','k','v',now()-interval '400 days',now())`,
		`INSERT INTO shawk.host_addrs VALUES ('h','10.0.0.50',now()-interval '400 days',now()-interval '365 days'),
		  ('h','10.0.1.50',now()-interval '365 days',now())`,
		`INSERT INTO shawk.processes (host_id, unit, comm, exe, service_name, first_seen, last_seen)
		 VALUES ('h','portal.service','portal','','portal',now()-interval '400 days',now())`,
		`INSERT INTO shawk.listeners VALUES ('h',(SELECT id FROM shawk.processes),'tcp','0.0.0.0',443,1,now()-interval '400 days',now())`,
		`INSERT INTO shawk.edges (host_id, process_id, role, proto, local_addr, remote_addr, port, netns, first_seen, last_seen)
		 VALUES ('h',(SELECT id FROM shawk.processes),'server','tcp','10.0.1.50','10.0.9.9',443,1,now()-interval '1 day',now())`)
	got := queryStrings(t, conn, `SELECT host(addr), port, exact FROM shawk_v1.service_endpoints`)
	if !slices.Equal(got, []string{"10.0.1.50 443 true"}) {
		t.Errorf("service_endpoints = %v", got)
	}
}

// TestPGAgentAddrsCoverage: agent_addrs tells what the agent traces.
func TestPGAgentAddrsCoverage(t *testing.T) {
	_, conn := migratedDB(t)
	execAll(t, conn,
		`INSERT INTO shawk.hosts VALUES ('h','m','h','k','v',now(),now())`,
		`INSERT INTO shawk.host_addrs VALUES ('h','10.0.0.1',now(),now())`,
		`INSERT INTO shawk.agent_sessions (host_id, started_at, last_heartbeat, udp_traced, netns_scope)
		 VALUES ('h', now()-interval '2 days', now()-interval '1 day', true, 'all'),
		        ('h', now()-interval '1 hour', now(), false, '4026532001')`)
	got := queryStrings(t, conn, `SELECT host(addr), udp_traced, netns_scope FROM shawk_v1.agent_addrs`)
	if !slices.Equal(got, []string{"10.0.0.1 false 4026532001"}) {
		t.Errorf("agent_addrs = %v", got)
	}
}

// TestPGPruneKeepsRefreshedRows: a row refreshed by a concurrent write while
// prune waited for its lock was deleted.
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
