package shawkconnector

import (
	"context"
	"slices"
	"strconv"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
)

// activeHours returns the hours of the activity PostgreSQL holds, as "port
// month hour" of the edges of TCP and UDP and "path month hour" of those
// of Unix sockets, sorted.
func activeHours(t *testing.T, conn *pgx.Conn) []string {
	t.Helper()
	return queryStrings(t, conn, `
SELECT e.port::text, to_char(a.month AT TIME ZONE 'UTC', 'YYYY-MM'), i
FROM shawk.edge_activity a JOIN shawk.edges e ON e.id = a.edge_id
CROSS JOIN generate_series(0, 743) i WHERE get_bit(a.hours, i) = 1
UNION ALL
SELECT e.path, to_char(a.month AT TIME ZONE 'UTC', 'YYYY-MM'), i
FROM shawk.unix_edge_activity a JOIN shawk.unix_edges e ON e.id = a.edge_id
CROSS JOIN generate_series(0, 743) i WHERE get_bit(a.hours, i) = 1`)
}

// TestPGEdgeActivity: the hours in which edges were active are written
// with their edges, and written again they add hours and remove none, in
// any order; a month before the retention is pruned on its own, and the
// months of an edge go with it.
func TestPGEdgeActivity(t *testing.T) {
	dsn, conn := migratedDB(t)
	ctx := context.Background()
	st, err := newPGStore(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer st.close()
	oct := func(day, hour int) time.Time { return time.Date(2026, 10, day, hour, 30, 0, 0, time.UTC) }
	app := procKey{"app.service", "puma", "app", ""}
	client := edgeRowKey{role: roleClient, proto: "tcp", local: addrOf("10.0.0.11"), peer: addrOf("10.0.0.10"), port: 5432,
		netns: 1, procKey: app}
	folded := edgeRowKey{role: roleServer, proto: "tcp", local: addrOf("10.0.0.11"), peer: addrOf("0.0.0.0"), folded: true,
		port: 8443, netns: 1, procKey: app}
	sock := edgeRowKey{role: roleClient, proto: transportUnix, path: "/run/redis.sock", netns: 1, procKey: app}
	// write writes the edges of the host, each active at its times.
	write := func(active map[edgeRowKey][]time.Time) {
		t.Helper()
		h := newHostChanges(hostKey("m", "app-01"))
		h.setHost("m", "app-01", "6.8", "test", oct(31, 23))
		h.addProcess(app, "/usr/bin/ruby", span{oct(1, 0), oct(31, 23)})
		for k, times := range active {
			for _, at := range times {
				h.addEdge(k, span{at, at})
				h.addActivity(k, at)
			}
		}
		if err := st.write(ctx, h); err != nil {
			t.Fatal(err)
		}
	}
	write(map[edgeRowKey][]time.Time{
		client: {oct(1, 0), oct(31, 23)},
		folded: {oct(2, 5)},
		sock:   {oct(3, 7)},
	})
	want := []string{"/run/redis.sock 2026-10 55", "5432 2026-10 0", "5432 2026-10 743", "8443 2026-10 29"}
	if got := activeHours(t, conn); !slices.Equal(got, want) {
		t.Errorf("hours = %v, want %v", got, want)
	}
	// Written again, an older hour after a newer one and the next month:
	// the hours are added.
	write(map[edgeRowKey][]time.Time{
		client: {oct(31, 23), oct(1, 1), time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)},
		sock:   {oct(3, 8)},
	})
	want = []string{"/run/redis.sock 2026-10 55", "/run/redis.sock 2026-10 56", "5432 2026-10 0", "5432 2026-10 1",
		"5432 2026-10 743", "5432 2026-11 0", "8443 2026-10 29"}
	if got := activeHours(t, conn); !slices.Equal(got, want) {
		t.Errorf("hours written again = %v, want %v", got, want)
	}
	// The same hours again change no row.
	versions := func() []string {
		return queryStrings(t, conn, `SELECT edge_id, month, xmin FROM shawk.edge_activity
			UNION ALL SELECT edge_id, month, xmin FROM shawk.unix_edge_activity`)
	}
	before := versions()
	write(map[edgeRowKey][]time.Time{client: {oct(1, 1)}, sock: {oct(3, 8)}})
	if after := versions(); !slices.Equal(before, after) {
		t.Errorf("hours already written rewrote their rows: %v, then %v", before, after)
	}

	// A month whose end is before the retention goes; its edge, seen since,
	// stays with the months since.
	execAll(t, conn,
		`DELETE FROM shawk.edge_activity`, `DELETE FROM shawk.unix_edge_activity`,
		`UPDATE shawk.edges SET last_seen = now() WHERE port = 5432`,
		`UPDATE shawk.unix_edges SET last_seen = now()`,
		`INSERT INTO shawk.edge_activity
		 SELECT id, date_trunc('month', now() - interval '80 days', 'UTC'), repeat('1', 744)::bit(744) FROM shawk.edges WHERE port = 5432`,
		`INSERT INTO shawk.edge_activity
		 SELECT id, date_trunc('month', now(), 'UTC'), repeat('1', 744)::bit(744) FROM shawk.edges WHERE port = 5432`,
		`INSERT INTO shawk.unix_edge_activity
		 SELECT id, date_trunc('month', now() - interval '80 days', 'UTC'), repeat('1', 744)::bit(744) FROM shawk.unix_edges`)
	if _, err := st.prune(ctx, 45*24*time.Hour, 1000); err != nil {
		t.Fatal(err)
	}
	got := queryStrings(t, conn, `SELECT e.port, a.month = date_trunc('month', now(), 'UTC')
		FROM shawk.edge_activity a JOIN shawk.edges e ON e.id = a.edge_id`)
	if !slices.Equal(got, []string{"5432 true"}) {
		t.Errorf("months after the prune = %v, want the current month of the edge seen since", got)
	}
	if got := queryStrings(t, conn, `SELECT count(*) FROM shawk.unix_edge_activity`); !slices.Equal(got, []string{"0"}) {
		t.Errorf("%v months of Unix sockets after the prune, want none", got)
	}
	// A month that ended within the retention stays: the cutoff is in it.
	execAll(t, conn, `INSERT INTO shawk.edge_activity
		SELECT id, date_trunc('month', now() - interval '40 days', 'UTC'), repeat('1', 744)::bit(744) FROM shawk.edges WHERE port = 5432
		ON CONFLICT DO NOTHING`)
	if _, err := st.prune(ctx, 45*24*time.Hour, 1000); err != nil {
		t.Fatal(err)
	}
	if got := queryStrings(t, conn, `SELECT count(*) > 0 FROM shawk.edge_activity
		WHERE month = date_trunc('month', now() - interval '40 days', 'UTC')`); !slices.Equal(got, []string{"true"}) {
		t.Error("a month that holds hours within the retention was pruned")
	}
	// The months go with their edge.
	execAll(t, conn, `DELETE FROM shawk.edges`)
	if got := queryStrings(t, conn, `SELECT count(*) FROM shawk.edge_activity`); !slices.Equal(got, []string{"0"}) {
		t.Errorf("%v months left of deleted edges", got)
	}
	// A month must be the start of a month in UTC.
	execAll(t, conn, `INSERT INTO shawk.unix_edges (host_id, process_id, path, netns, first_seen, last_seen)
		SELECT host_id, id, '/run/x.sock', 1, now(), now() FROM shawk.processes`)
	if _, err := conn.Exec(ctx, `INSERT INTO shawk.unix_edge_activity
		SELECT id, '2026-10-02T00:00:00Z', repeat('0', 744)::bit(744) FROM shawk.unix_edges WHERE path = '/run/x.sock'`); err == nil {
		t.Error("a month that is not the start of a month was written")
	}
}

// TestPGActivityThroughTheConnector: the connector writes the hour in
// which an agent last saw an edge active, with the edge.
func TestPGActivityThroughTheConnector(t *testing.T) {
	c, sink, conn := pgConnector(t)
	now := time.Now().UTC().Truncate(time.Second)
	seen := now.Add(-time.Minute)
	consume(t, c, sink, tAgent{host: "app-01", machineID: "m-app", addrs: []string{"10.0.0.11"}, time: now,
		segment: now.Add(-time.Hour),
		edges: []tEdge{
			{role: "client", proto: "tcp", local: "10.0.0.11", peer: "10.0.0.10", port: 5432, svc: "app", comm: "puma",
				opened: 1, first: seen, last: seen},
			{role: "client", proto: transportUnix, path: "/run/redis.sock", svc: "app", comm: "puma", opened: 1,
				first: seen, last: seen},
		}})
	c.flush(context.Background())
	month, hour := activityOf(seen)
	got := queryStrings(t, conn, `
SELECT 'tcp', extract(epoch FROM month)::bigint, bit_count(hours), get_bit(hours, $1) FROM shawk.edge_activity
UNION ALL
SELECT 'unix', extract(epoch FROM month)::bigint, bit_count(hours), get_bit(hours, $1) FROM shawk.unix_edge_activity`, hour)
	want := []string{
		"tcp " + strconv.FormatInt(month, 10) + " 1 1",
		"unix " + strconv.FormatInt(month, 10) + " 1 1",
	}
	if !slices.Equal(got, want) {
		t.Errorf("activity = %v, want %v", got, want)
	}
}

// TestPGCadenceThroughTheConnector: the hours that the connector records
// from the requests of agents give the cadence of their dependencies. Over
// four days, app keeps a connection to postgres open, and a job reads it
// for five minutes at 2 every night.
func TestPGCadenceThroughTheConnector(t *testing.T) {
	c, sink, conn := pgConnector(t)
	ctx := context.Background()
	start := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	now := start
	c.now = func() time.Time { return now }
	app := tEdge{proto: "tcp", port: 5432, svc: "app", comm: "puma", unit: "app.service", count: 1, first: start}
	job := tEdge{proto: "tcp", port: 5432, svc: "report", comm: "report", unit: "report.service", opened: 1}
	// sides returns the client edge of a connection from an address to
	// postgres and the server edge that matches it.
	sides := func(e tEdge, from string) (client, server tEdge) {
		client, server = e, e
		client.role, client.local, client.peer = "client", from, "10.0.0.10"
		server.role, server.local, server.peer = "server", "10.0.0.10", from
		server.svc, server.comm, server.unit = "postgres", "postgres", "postgresql.service"
		return client, server
	}
	for hour := 0; hour <= 4*24; hour++ {
		now = start.Add(time.Duration(hour) * time.Hour)
		app.last = now
		appClient, appServer := sides(app, "10.0.0.11")
		clients, servers := []tEdge{appClient}, []tEdge{appServer}
		if hour%24 == 2 {
			// The job ran from 2:00 to 2:05, and the agents still send it
			// at 2:10; they have dropped it by 3:00.
			now = now.Add(10 * time.Minute)
			job.first, job.last = now.Add(-10*time.Minute), now.Add(-5*time.Minute)
			jobClient, jobServer := sides(job, "10.0.0.12")
			clients, servers = append(clients, jobClient), append(servers, jobServer)
		}
		consume(t, c, sink, tAgent{host: "db-01", machineID: "m-db", addrs: []string{"10.0.0.10"}, time: now,
			segment: start.Add(-time.Hour), edges: servers})
		consume(t, c, sink, tAgent{host: "app-01", machineID: "m-app", addrs: []string{"10.0.0.11", "10.0.0.12"}, time: now,
			segment: start.Add(-time.Hour), edges: clients})
		if hour%7 == 0 {
			c.flush(ctx)
		}
	}
	c.flush(ctx)
	got := queryStrings(t, conn, `
SELECT client_service, observed_by, cadence, period::text, runs,
       to_char(next_expected AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI')
FROM shawk_v1.impact('db-01', $1, $2)`, start, now)
	want := []string{
		"app both continuous <nil> 1 <nil>",
		"report both daily 1 day 4 2026-10-05T02:00",
	}
	if !slices.Equal(got, want) {
		t.Errorf("dependents of db-01 = %v, want %v", got, want)
	}
	if got := queryStrings(t, conn, `SELECT verdict, direct, coverage::text FROM shawk_v1.impact_verdict('db-01', $1, $2)`, start, now); !slices.Equal(got, []string{"UNSAFE 2 1.000000"}) {
		t.Errorf("verdict on db-01 = %v", got)
	}
	// The hours of the job: one a day, on both sides.
	if got := queryStrings(t, conn, `SELECT e.role, sum(bit_count(a.hours))::int FROM shawk.edge_activity a
		JOIN shawk.edges e ON e.id = a.edge_id WHERE e.local_addr = '10.0.0.12' OR e.remote_addr = '10.0.0.12' GROUP BY e.role`); !slices.Equal(got, []string{"client 4", "server 4"}) {
		t.Errorf("hours of the job = %v, want 4 on each side", got)
	}
}
