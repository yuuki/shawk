package shawkconnector

import (
	"context"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"
)

// TestPGJobUsers: with job_users, the processes of Slurm jobs have a row per
// user, NULL where the user is unknown, and shawk_v1.job_edges tells the
// users of the edges of jobs. Replays update the same rows.
func TestPGJobUsers(t *testing.T) {
	c, sink, conn := pgConnectorWith(t, func(cfg *Config) { cfg.JobUsers = true })
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Second)
	edge := func(user string) tEdge {
		return tEdge{role: roleClient, proto: "tcp", local: "10.0.0.11", peer: "10.0.0.20", port: 27000,
			svc: "a.out", unit: "slurm/batch", comm: "a.out", exe: "/home/x/a.out", user: user, opened: 1}
	}
	ta := tAgent{host: "cn01", machineID: "m", addrs: []string{"10.0.0.11"}, time: now, segment: now.Add(-time.Hour),
		edges: []tEdge{edge("1001"), edge("1002"), edge(""),
			{role: roleClient, proto: "tcp", local: "10.0.0.11", peer: "10.0.0.1", port: 6817, svc: "slurmd",
				unit: "slurmd.service", comm: "slurmd", exe: "/usr/sbin/slurmd", user: "0", opened: 1}},
		listeners: []tListener{{proto: "tcp", addr: "0.0.0.0", port: 40000, svc: "a.out", unit: "slurm/step",
			comm: "a.out", exe: "/home/x/a.out", user: "1001"}}}
	consume(t, c, sink, ta)
	c.flush(ctx)
	// A replay, as from another connector.
	ta.time = now.Add(15 * time.Second)
	for i := range ta.edges {
		ta.edges[i].opened++
	}
	consume(t, c, sink, ta)
	c.flush(ctx)

	got := queryStrings(t, conn, `SELECT unit, coalesce(user_id::text, '-') FROM shawk.processes`)
	want := []string{"slurm/batch -", "slurm/batch 1001", "slurm/batch 1002", "slurm/step 1001", "slurmd.service -"}
	if !slices.Equal(got, want) {
		t.Errorf("processes = %q, want %q", got, want)
	}
	got = queryStrings(t, conn, `SELECT o.port, p.user_id FROM shawk.listener_owners o JOIN shawk.processes p ON p.id = o.process_id`)
	if want := []string{"40000 1001"}; !slices.Equal(got, want) {
		t.Errorf("listener owners = %q, want %q", got, want)
	}
	got = queryStrings(t, conn, `SELECT l.port, p.user_id FROM shawk.listeners l JOIN shawk.processes p ON p.id = l.process_id`)
	if want := []string{"40000 1001"}; !slices.Equal(got, want) {
		t.Errorf("listeners = %q, want %q", got, want)
	}
	got = queryStrings(t, conn, `SELECT host, unit, service, exe, coalesce(user_id::text, '-'), role, host(remote_addr), port FROM shawk_v1.job_edges`)
	want = []string{
		"cn01 slurm/batch a.out /home/x/a.out - client 10.0.0.20 27000",
		"cn01 slurm/batch a.out /home/x/a.out 1001 client 10.0.0.20 27000",
		"cn01 slurm/batch a.out /home/x/a.out 1002 client 10.0.0.20 27000",
	}
	if !slices.Equal(got, want) {
		t.Errorf("job_edges = %q, want %q", got, want)
	}
	// The dependencies of the contract are those of the services, whose
	// rows the users do not show.
	got = queryStrings(t, conn, `SELECT DISTINCT client_service, port FROM shawk_v1.dependencies`)
	if want := []string{"a.out 27000", "slurmd 6817"}; !slices.Equal(got, want) {
		t.Errorf("dependencies = %q, want %q", got, want)
	}
}

// TestPGJobUsersMigration: the migration of the users keeps the processes
// of an existing database, without users, which the connector then updates
// rather than duplicates. The view of the users is only for its owner, from
// its creation, although default privileges grant the other views of
// shawk_v1 to the connector and Grafana, and after grants.sql.
func TestPGJobUsersMigration(t *testing.T) {
	dsn, conn := testDB(t)
	ctx := context.Background()
	execAll(t, conn, `DO $$ BEGIN
		   IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'shawk_connector') THEN CREATE ROLE shawk_connector NOLOGIN; END IF;
		   IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'shawk_grafana') THEN CREATE ROLE shawk_grafana NOLOGIN; END IF;
		 END $$`)
	t.Cleanup(func() {
		conn.Exec(ctx, "RESET ROLE")
		conn.Exec(ctx, "DROP OWNED BY shawk_connector, shawk_grafana")
	})
	ms, err := Migrations()
	if err != nil || len(ms) < 2 || ms[0].Name != "0001_schema.sql" {
		t.Fatalf("migrations = %v, %v", ms, err)
	}
	// The schema before the users, set up with grants.sql.
	execAll(t, conn,
		`CREATE SCHEMA shawk; CREATE TABLE shawk.schema_migrations (version integer PRIMARY KEY, name text NOT NULL, applied_at timestamptz NOT NULL DEFAULT now())`,
		ms[0].SQL,
		`INSERT INTO shawk.schema_migrations (version, name) VALUES (1, '0001_schema.sql')`)
	grants, err := os.ReadFile(filepath.Join(packaging, "postgres/grants.sql"))
	if err != nil {
		t.Fatal(err)
	}
	execAll(t, conn, string(grants),
		`INSERT INTO shawk.hosts VALUES ('h', 'm', 'cn01', 'k', 'v', now(), now())`,
		`INSERT INTO shawk.processes (id, host_id, unit, comm, exe, service_name, first_seen, last_seen)
		 VALUES (1, 'h', 'slurm/batch', 'a.out', '/old', 'a.out', now() - interval '1 day', now() - interval '1 day')`,
		`SELECT setval('shawk.processes_id_seq', 1)`,
		`INSERT INTO shawk.edges (host_id, process_id, role, proto, local_addr, remote_addr, port, netns, first_seen, last_seen)
		 VALUES ('h', 1, 'client', 'tcp', '10.0.0.11', '10.0.0.20', 27000, 1, now() - interval '1 day', now() - interval '1 day')`)

	if _, err := Migrate(ctx, conn); err != nil {
		t.Fatal(err)
	}
	readable := func(when string) {
		t.Helper()
		for _, role := range []string{"shawk_connector", "shawk_grafana"} {
			var users, others bool
			if err := conn.QueryRow(ctx, `SELECT has_table_privilege($1, 'shawk_v1.job_edges', 'SELECT'),
			    has_table_privilege($1, 'shawk_v1.agents', 'SELECT')`, role).Scan(&users, &others); err != nil {
				t.Fatal(err)
			}
			if users || !others {
				t.Errorf("%s: %s reads job_edges: %v, agents: %v", when, role, users, others)
			}
		}
	}
	readable("after the migration")
	execAll(t, conn, string(grants))
	readable("after grants.sql")

	st, err := newPGStore(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer st.close()
	now := time.Now().UTC().Truncate(time.Second)
	h := newHostChanges("h")
	h.setHost("m", "cn01", "k", "v", now)
	for _, user := range []string{"", "1001"} {
		pk := procKey{"slurm/batch", "a.out", "a.out", user}
		h.addProcess(pk, "/home/x/a.out", span{now, now})
		h.addEdge(edgeRowKey{role: roleClient, proto: "tcp", local: addrOf("10.0.0.11"), peer: addrOf("10.0.0.20"),
			port: 27000, netns: 1, procKey: pk}, span{now, now})
	}
	if err := st.write(ctx, h); err != nil {
		t.Fatal(err)
	}
	got := queryStrings(t, conn, `
SELECT p.id = 1, coalesce(p.user_id::text, '-'), p.exe, count(e.id)
FROM shawk.processes p LEFT JOIN shawk.edges e ON e.process_id = p.id GROUP BY p.id`)
	want := []string{"false 1001 /home/x/a.out 1", "true - /home/x/a.out 1"}
	if !slices.Equal(got, want) {
		t.Errorf("processes = %q, want %q", got, want)
	}
	if _, err := conn.Exec(ctx, `INSERT INTO shawk.processes (host_id, unit, comm, service_name, first_seen, last_seen)
	    VALUES ('h', 'slurm/batch', 'a.out', 'a.out', now(), now())`); err == nil {
		t.Error("a second process without a user")
	}
}
