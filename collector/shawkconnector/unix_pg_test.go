package shawkconnector

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"
)

// unixHost writes a host with an agent that traces Unix sockets, its
// processes, the client edges of app to Unix sockets and the owners of
// listening Unix sockets, through the store as the connector writes them.
type unixHost struct {
	t     *testing.T
	store store
	h     *hostChanges
}

func newUnixHost(t *testing.T, st store, name string, now time.Time) *unixHost {
	h := newHostChanges(hostKey("m", name))
	h.setHost("m", name, "6.8", "test", now)
	traced := true
	h.addSession(now.Add(-24*time.Hour), sessionRow{lastHeartbeat: now, netnsScope: "all", udpTraced: true, unixTraced: &traced})
	h.addAddr(addrOf("10.0.0.1"), span{now, now})
	return &unixHost{t: t, store: st, h: h}
}

func (u *unixHost) proc(svc string) procKey {
	pk := procKey{svc + ".service", svc, svc, ""}
	if strings.HasPrefix(svc, "slurm/") {
		pk = procKey{svc, "python3", "python3", ""}
	}
	u.h.addProcess(pk, "/usr/bin/"+pk.comm, span{u.h.first, u.h.last})
	return pk
}

func (u *unixHost) edge(svc, path string, netns uint64, first, last time.Time) {
	u.h.addEdge(edgeRowKey{role: roleClient, proto: transportUnix, path: path, netns: netns, procKey: u.proc(svc)}, span{first, last})
}

func (u *unixHost) listener(svc, path string, netns uint64, first, last time.Time) {
	u.h.addListener(listenerRowKey{proto: transportUnix, path: path, netns: netns, procKey: u.proc(svc)}, span{first, last})
}

func (u *unixHost) write() {
	u.t.Helper()
	if err := u.store.write(context.Background(), u.h); err != nil {
		u.t.Fatal(err)
	}
}

// TestPGUnixDependencies: the client edges of Unix sockets are matched with
// the owners of the listeners of their names on their host: in the
// namespace of the client, else in the only namespace that has one.
func TestPGUnixDependencies(t *testing.T) {
	dsn, conn := migratedDB(t)
	ctx := context.Background()
	st, err := newPGStore(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer st.close()
	now := time.Now().UTC().Truncate(time.Second)
	u := newUnixHost(t, st, "app-01", now)
	up := now.Add(-time.Hour)
	u.listener("postgres", "/run/pg.sock", 1, up, now)
	u.listener("dockerd", "/run/docker.sock", 1, up, now)
	u.listener("sidecar", "/tmp/app.sock", 2, up, now)
	u.listener("other", "/tmp/app.sock", 3, up, now)
	u.listener("one", "/run/twice.sock", 2, up, now)
	u.listener("two", "/run/twice.sock", 3, up, now)
	// Edges that ended 20 minutes ago while the agent kept observing: their
	// dependencies disappeared.
	first, last := now.Add(-50*time.Minute), now.Add(-20*time.Minute)
	u.edge("app", "/run/pg.sock", 1, first, last)
	u.edge("app", "/run/docker.sock", 2, first, last) // from a container
	u.edge("app", "/tmp/app.sock", 2, first, last)
	u.edge("app", "/run/twice.sock", 1, first, last) // ambiguous
	u.edge("app", "/run/gone.sock", 1, first, last)  // no listener seen
	u.write()

	deps := queryStrings(t, conn, `SELECT client_host, client_service, server_host, server_service, server_unit, path, port,
	  observed_by, client_addr IS NULL AND server_addr IS NULL, first_seen = $1 AND last_seen = $2,
	  client_observed_until = $3, server_observed_until = $3
	FROM shawk_v1.dependencies WHERE proto = 'unix'`, first, last, now)
	want := []string{
		"app-01 app <nil> <nil> <nil> /run/gone.sock 0 client true true true <nil>",
		"app-01 app <nil> <nil> <nil> /run/twice.sock 0 client true true true <nil>",
		"app-01 app app-01 dockerd dockerd.service /run/docker.sock 0 both true true true true",
		"app-01 app app-01 postgres postgres.service /run/pg.sock 0 both true true true true",
		"app-01 app app-01 sidecar sidecar.service /tmp/app.sock 0 both true true true true",
	}
	if !slices.Equal(deps, want) {
		t.Errorf("dependencies:\n%s\nwant:\n%s", strings.Join(deps, "\n"), strings.Join(want, "\n"))
	}
	// The function over a period returns what the view returns.
	for _, since := range []time.Time{now.Add(-25 * time.Minute), now.Add(-2 * time.Hour)} {
		q := `SELECT client_service, server_service, path, port, proto, observed_by, first_seen, last_seen`
		view := queryStrings(t, conn, q+` FROM shawk_v1.dependencies WHERE last_seen >= $1`, since)
		fn := queryStrings(t, conn, q+` FROM shawk_v1.dependencies_between($1, now())`, since)
		if !slices.Equal(view, fn) || len(fn) != 5 {
			t.Errorf("since %v: view %v, function %v", since, view, fn)
		}
	}
	if got := queryStrings(t, conn, `SELECT count(*) FROM shawk_v1.dependencies_between($1, $2)`,
		now.Add(-10*time.Minute), now); !slices.Equal(got, []string{"0"}) {
		t.Errorf("dependencies after the edges = %v", got)
	}
	// A server without a known service is named like in Prometheus; the map
	// has no port for Unix sockets.
	edges := queryStrings(t, conn, `SELECT source, target, mainstat FROM shawk_v1.graph_edges`)
	if !slices.Equal(edges, []string{"app dockerd unix", "app postgres unix", "app sidecar unix", "app ~unresolved unix"}) {
		t.Errorf("graph_edges = %v", edges)
	}
	if got := queryStrings(t, conn, `SELECT source, target, mainstat FROM shawk_v1.graph_edges_between($1, now())`,
		now.Add(-time.Hour)); !slices.Equal(got, edges) {
		t.Errorf("graph_edges_between = %v", got)
	}
	if got := queryStrings(t, conn, `SELECT id, subtitle FROM shawk_v1.graph_nodes WHERE id IN ('postgres', '~unresolved')`); !slices.Equal(got,
		[]string{"postgres app-01", "~unresolved "}) {
		t.Errorf("graph_nodes = %v", got)
	}
	if got := queryStrings(t, conn, `SELECT change, client_service, server_service, port, proto FROM shawk_v1.dependency_changes
	  WHERE server_service = 'postgres'`); !slices.Equal(got, []string{"appeared app postgres 0 unix", "disappeared app postgres 0 unix"}) {
		t.Errorf("dependency_changes = %v", got)
	}
	if got := queryStrings(t, conn, `SELECT host, udp_traced, unix_traced FROM shawk_v1.agents`); !slices.Equal(got,
		[]string{"app-01 true true"}) {
		t.Errorf("agents = %v", got)
	}
	// The connector names the peers of Unix sockets from unix_endpoints.
	eps := queryStrings(t, conn, `SELECT path, netns, host, service, slurm_job FROM shawk_v1.unix_endpoints`)
	if len(eps) != 6 || !slices.Contains(eps, "/run/pg.sock 1 app-01 postgres false") {
		t.Errorf("unix_endpoints = %v", eps)
	}
	rows, err := st.peers(ctx, time.Hour, 0)
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, r := range rows.unix {
		got = append(got, fmt.Sprint(r.key.path, " ", r.netns, " ", r.service, " ", r.key.host == hostKey("m", "app-01")))
	}
	slices.Sort(got)
	if len(got) != 6 || !slices.Contains(got, "/run/docker.sock 1 dockerd true") {
		t.Errorf("unix endpoints read = %v", got)
	}
	// The history of dependencies keeps those over Unix sockets.
	if _, err := st.refreshDependencies(ctx); err != nil {
		t.Fatal(err)
	}
	if got := queryStrings(t, conn, `SELECT client_service, server_service, port FROM shawk.known_dependencies WHERE proto = 'unix'`); !slices.Equal(got,
		[]string{"app dockerd 0", "app postgres 0", "app sidecar 0", "app ~unresolved 0"}) {
		t.Errorf("known_dependencies = %v", got)
	}
}

// TestPGUnixOwnerPeriods: a client edge whose listener changed hands is a
// row per owner, each over the part of the edge the owner held the
// listener, within 2 minutes; a listener that stays does not make the
// dependency last longer than its client edge.
func TestPGUnixOwnerPeriods(t *testing.T) {
	dsn, conn := migratedDB(t)
	ctx := context.Background()
	st, err := newPGStore(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer st.close()
	now := time.Now().UTC().Truncate(time.Second)
	ago := func(m int) time.Time { return now.Add(-time.Duration(m) * time.Minute) }
	u := newUnixHost(t, st, "h1", now)
	u.listener("old", "/run/s.sock", 1, ago(180), ago(120))
	u.listener("new", "/run/s.sock", 1, ago(120), now)
	u.edge("app", "/run/s.sock", 1, ago(150), ago(30))
	// A listener in another namespace does not matter while the client's
	// namespace has one.
	u.listener("elsewhere", "/run/s.sock", 2, ago(180), now)
	u.write()
	got := queryStrings(t, conn, `SELECT server_service, round(extract(epoch FROM $1 - first_seen) / 60)::int,
	  round(extract(epoch FROM $1 - last_seen) / 60)::int FROM shawk_v1.dependencies`, now)
	if want := []string{"new 122 30", "old 150 118"}; !slices.Equal(got, want) {
		t.Errorf("rows (server, minutes ago first and last) = %v, want %v", got, want)
	}
	fn := queryStrings(t, conn, `SELECT server_service, round(extract(epoch FROM $1 - first_seen) / 60)::int,
	  round(extract(epoch FROM $1 - last_seen) / 60)::int FROM shawk_v1.dependencies_between($2, $1)`, now, ago(240))
	if !slices.Equal(fn, got) {
		t.Errorf("dependencies_between = %v, the view %v", fn, got)
	}
}

// TestPGUnixListenerGone: a client edge that goes on after the last owner
// of its listener closed it keeps its dependency on that owner until the
// edge ends, as the row of a TCP connection spans both its edges: the
// client keeps the connections it opened, or keeps trying.
func TestPGUnixListenerGone(t *testing.T) {
	dsn, conn := migratedDB(t)
	ctx := context.Background()
	st, err := newPGStore(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer st.close()
	now := time.Now().UTC().Truncate(time.Second)
	ago := func(m int) time.Time { return now.Add(-time.Duration(m) * time.Minute) }
	u := newUnixHost(t, st, "h1", now)
	u.listener("server", "/run/s.sock", 1, ago(180), ago(60))
	u.edge("app", "/run/s.sock", 1, ago(150), ago(5))
	u.write()
	q := `SELECT server_service, observed_by, round(extract(epoch FROM $1 - first_seen) / 60)::int,
	  round(extract(epoch FROM $1 - last_seen) / 60)::int`
	got := queryStrings(t, conn, q+` FROM shawk_v1.dependencies`, now)
	if want := []string{"server both 150 5"}; !slices.Equal(got, want) {
		t.Errorf("rows (server, side, minutes ago first and last) = %v, want %v", got, want)
	}
	if fn := queryStrings(t, conn, q+` FROM shawk_v1.dependencies_between($2, $1)`, now, ago(10)); !slices.Equal(fn, got) {
		t.Errorf("dependencies_between of the last 10 minutes = %v, the view %v", fn, got)
	}
}

// TestPGUnixAbstract: an abstract name is reached in the namespace of its
// client only, so a listener of the name in another namespace is not its
// server, while a path is reached from other namespaces.
func TestPGUnixAbstract(t *testing.T) {
	dsn, conn := migratedDB(t)
	ctx := context.Background()
	st, err := newPGStore(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer st.close()
	now := time.Now().UTC().Truncate(time.Second)
	u := newUnixHost(t, st, "h1", now)
	u.listener("ctl", "@ctl", 2, now.Add(-time.Hour), now)
	u.listener("dockerd", "/run/docker.sock", 2, now.Add(-time.Hour), now)
	u.edge("app", "@ctl", 1, now.Add(-30*time.Minute), now)
	u.edge("app", "/run/docker.sock", 1, now.Add(-30*time.Minute), now)
	u.write()
	q := `SELECT path, server_service, observed_by`
	got := queryStrings(t, conn, q+` FROM shawk_v1.dependencies`)
	slices.Sort(got)
	if want := []string{"/run/docker.sock dockerd both", "@ctl <nil> client"}; !slices.Equal(got, want) {
		t.Errorf("dependencies = %v, want %v", got, want)
	}
	fn := queryStrings(t, conn, q+` FROM shawk_v1.dependencies_between(now() - interval '1 hour', now())`)
	slices.Sort(fn)
	if !slices.Equal(fn, got) {
		t.Errorf("dependencies_between = %v, the view %v", fn, got)
	}
}

// TestPGUnixPrune: the edges and listeners of Unix sockets are deleted past
// the retention, and the processes they refer to kept until then.
func TestPGUnixPrune(t *testing.T) {
	dsn, conn := migratedDB(t)
	ctx := context.Background()
	st, err := newPGStore(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer st.close()
	now := time.Now().UTC().Truncate(time.Second)
	old := now.Add(-4 * 365 * 24 * time.Hour)
	gone := newUnixHost(t, st, "gone-01", old)
	gone.edge("app", "/run/a.sock", 1, old, old)
	gone.listener("srv", "/run/a.sock", 1, old, old)
	gone.write()
	live := newUnixHost(t, st, "live-01", now)
	live.edge("app", "/run/old.sock", 1, old, old)
	live.listener("srv", "/run/old.sock", 1, old, old)
	live.edge("app", "/run/new.sock", 1, now, now)
	live.listener("srv", "/run/new.sock", 1, now, now)
	live.write()
	for i := 0; ; i++ {
		n, err := st.prune(ctx, 3*365*24*time.Hour, 1)
		if err != nil {
			t.Fatal(err)
		}
		if n == 0 {
			break
		}
		if i > 30 {
			t.Fatal("prune does not end")
		}
	}
	got := queryStrings(t, conn, `
SELECT 'hosts', string_agg(hostname, ',' ORDER BY hostname) FROM shawk.hosts
UNION ALL SELECT 'edges', string_agg(path, ',') FROM shawk.unix_edges
UNION ALL SELECT 'listeners', string_agg(path, ',') FROM shawk.unix_listeners
UNION ALL SELECT 'processes', string_agg(service_name, ',' ORDER BY service_name) FROM shawk.processes`)
	want := []string{"edges /run/new.sock", "hosts live-01", "listeners /run/new.sock", "processes app,srv"}
	if !slices.Equal(got, want) {
		t.Errorf("after pruning: %v, want %v", got, want)
	}
}

// TestPGUnixJobEdges: the edges of the processes of Slurm jobs to Unix
// sockets are in job_edges, with their names.
func TestPGUnixJobEdges(t *testing.T) {
	dsn, conn := migratedDB(t)
	ctx := context.Background()
	st, err := newPGStore(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer st.close()
	now := time.Now().UTC().Truncate(time.Second)
	u := newUnixHost(t, st, "cn001", now)
	u.edge("slurm/step", "/run/munge/munge.socket.2", 1, now, now)
	u.edge("app", "/run/munge/munge.socket.2", 1, now, now)
	u.write()
	got := queryStrings(t, conn, `SELECT host, unit, role, proto, local_addr, remote_addr, port, path FROM shawk_v1.job_edges`)
	if want := []string{"cn001 slurm/step client unix <nil> <nil> 0 /run/munge/munge.socket.2"}; !slices.Equal(got, want) {
		t.Errorf("job_edges = %v, want %v", got, want)
	}
}

// TestPGUnixWithTCP: the dependencies over TCP and UDP have a NULL path,
// and an agent that does not tell whether it traces Unix sockets keeps that
// unknown.
func TestPGUnixWithTCP(t *testing.T) {
	_, conn := migratedDB(t)
	f := fixture{t, conn}
	f.host("h1", "app", "db")
	f.conn2("h1", "app", "10.0.0.1", "h1", "db", "10.0.0.1", 5432, "now() - interval '1 hour'", "now()")
	got := queryStrings(t, conn, `SELECT client_service, server_service, port, observed_by, path FROM shawk_v1.dependencies`)
	if want := []string{"app db 5432 both <nil>"}; !slices.Equal(got, want) {
		t.Errorf("dependencies = %v, want %v", got, want)
	}
	fn := queryStrings(t, conn, `SELECT client_service, server_service, port, observed_by, path
	  FROM shawk_v1.dependencies_between(now() - interval '1 day', now())`)
	if !slices.Equal(fn, got) {
		t.Errorf("dependencies_between = %v, want %v", fn, got)
	}
	if got := queryStrings(t, conn, `SELECT host, unix_traced FROM shawk_v1.agents`); !slices.Equal(got, []string{"h1 <nil>"}) {
		t.Errorf("agents = %v", got)
	}
}
