package shawkconnector

import (
	"context"
	"slices"
	"testing"
)

// portRulesFixture writes the rules of ports as a connector configured
// with port_agnostic_services [srun] and a range of dynamic_ports for TCP
// on 10.1.0.0/16 would.
func portRulesFixture(t *testing.T, dsn string) {
	t.Helper()
	ctx := context.Background()
	st, err := newPGStore(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer st.close()
	rules := must(parsePortRules([]string{"srun"}, map[string]DynamicPortsConfig{
		"cluster": {Hosts: []string{"10.1.0.0/16"}, Transport: "tcp", Ports: "60001-63000"},
	}))
	if err := st.syncConfig(ctx, nil, nil, rules); err != nil {
		t.Fatal(err)
	}
}

// TestPGDynamicPortsKeepEdgesApart: the edges keep their port, so that two
// pairs of processes between the same two hosts on ports that are both
// aggregated stay apart in dependencies, and are aggregated with port 0 in
// the dependencies between services.
func TestPGDynamicPortsKeepEdgesApart(t *testing.T) {
	dsn, conn := migratedDB(t)
	portRulesFixture(t, dsn)
	f := fixture{t, conn}
	f.host("node01", "srun", "mpi")
	f.host("node02", "slurmstepd", "mpi")
	f.conn2("node02", "slurmstepd", "10.1.0.2", "node01", "srun", "10.1.0.1", 41234,
		"now()-interval '1 hour'", "now()")
	f.conn2("node02", "mpi", "10.1.0.2", "node01", "mpi", "10.1.0.1", 60010,
		"now()-interval '1 hour'", "now()")
	want := []string{"mpi mpi 60010 both", "slurmstepd srun 41234 both"}
	for _, q := range []string{
		`SELECT client_service, server_service, port, observed_by FROM shawk_v1.dependencies`,
		`SELECT client_service, server_service, port, observed_by FROM shawk_v1.dependencies_between(now() - interval '1 day', now())`,
	} {
		if got := queryStrings(t, conn, q); !slices.Equal(got, want) {
			t.Errorf("%s = %q, want %q", q, got, want)
		}
	}
	want = []string{"mpi mpi 0", "slurmstepd srun 0"}
	for _, q := range []string{
		`SELECT client_service, server_service, port FROM shawk.service_dependencies`,
		`SELECT client_service, server_service, port FROM shawk.service_dependencies_between(now() - interval '1 day', now())`,
	} {
		if got := queryStrings(t, conn, q); !slices.Equal(got, want) {
			t.Errorf("%s = %q, want %q", q, got, want)
		}
	}
	got := queryStrings(t, conn, `SELECT source, target, mainstat FROM shawk_v1.graph_edges_between(now() - interval '1 day', now())`)
	if want := []string{"mpi mpi 0/tcp", "slurmstepd srun 0/tcp"}; !slices.Equal(got, want) {
		t.Errorf("graph_edges_between = %q, want %q", got, want)
	}
}

// TestPGPortAgnosticNotNew: a run of srun on a new port, or a port of
// dynamic_ports never seen, is not a new dependency; a new port of another
// service, or a port of the range on a host outside it, is.
func TestPGPortAgnosticNotNew(t *testing.T) {
	dsn, conn := migratedDB(t)
	portRulesFixture(t, dsn)
	f := fixture{t, conn}
	f.host("ctl01", "slurmctld")
	f.host("node01", "srun", "mpi", "sshd")
	f.host("node02", "mpi")
	f.host("login01", "mpi")
	f.conn2("ctl01", "slurmctld", "10.1.0.100", "node01", "srun", "10.1.0.1", 41234,
		"now()-interval '2 days'", "now()-interval '2 days'+interval '1 minute'")
	f.conn2("node02", "mpi", "10.1.0.2", "node01", "mpi", "10.1.0.1", 60010,
		"now()-interval '2 days'", "now()-interval '2 days'+interval '1 minute'")
	f.conn2("ctl01", "slurmctld", "10.1.0.100", "node01", "sshd", "10.1.0.1", 22,
		"now()-interval '2 days'", "now()-interval '2 days'+interval '1 minute'")
	execAll(t, conn, `DELETE FROM shawk.known_dependencies_state`, `SELECT shawk.refresh_known_dependencies(interval '0')`)
	if got := queryStrings(t, conn, `SELECT client_service, server_service, port FROM shawk.known_dependencies`); !slices.Equal(got,
		[]string{"mpi mpi 0", "slurmctld srun 0", "slurmctld sshd 22"}) {
		t.Errorf("known_dependencies = %q", got)
	}
	// Another run of srun and another rank, on other ports; sshd on another
	// port, and a rank on a host outside the range.
	f.conn2("ctl01", "slurmctld", "10.1.0.100", "node01", "srun", "10.1.0.1", 52345,
		"now()-interval '2 minutes'", "now()-interval '1 minute'")
	f.conn2("node02", "mpi", "10.1.0.2", "node01", "mpi", "10.1.0.1", 61234,
		"now()-interval '2 minutes'", "now()-interval '1 minute'")
	f.conn2("ctl01", "slurmctld", "10.1.0.100", "node01", "sshd", "10.1.0.1", 2222,
		"now()-interval '2 minutes'", "now()-interval '1 minute'")
	f.conn2("node02", "mpi", "10.1.0.2", "login01", "mpi", "10.2.0.1", 61234,
		"now()-interval '2 minutes'", "now()-interval '1 minute'")
	got := queryStrings(t, conn, `SELECT change, client_service, server_service, port
		FROM shawk_v1.dependency_changes_between(now() - interval '15 minutes', now())`)
	if want := []string{"appeared mpi mpi 61234", "appeared slurmctld sshd 2222"}; !slices.Equal(got, want) {
		t.Errorf("changes = %q, want %q", got, want)
	}
	// Over the whole history, srun appeared once.
	got = queryStrings(t, conn, `SELECT change, port FROM shawk_v1.dependency_changes WHERE server_service = 'srun'`)
	if want := []string{"appeared 0"}; !slices.Equal(got, want) {
		t.Errorf("changes of srun = %q, want %q", got, want)
	}
}

// TestPGPortRulesSynced: the connector writes its rules of ports, and the
// dependencies known on their ports before become known on port 0, so that
// configuring a rule does not make them new; without rules the tables are
// emptied.
func TestPGPortRulesSynced(t *testing.T) {
	dsn, conn := migratedDB(t)
	execAll(t, conn, `INSERT INTO shawk.known_dependencies VALUES
		('slurmctld', 'srun', 41234, 'tcp', now()-interval '3 days', now()-interval '2 days'),
		('slurmctld', 'srun', 52345, 'tcp', now()-interval '2 days', now()-interval '1 day'),
		('mpi', 'mpi', 60010, 'tcp', now()-interval '3 days', now()-interval '1 day'),
		('mpi', 'mpi', 60010, 'udp', now()-interval '3 days', now()-interval '1 day'),
		('slurmctld', 'sshd', 22, 'tcp', now()-interval '3 days', now()-interval '1 day')`)
	portRulesFixture(t, dsn)
	if got := queryStrings(t, conn, `SELECT service FROM shawk.port_agnostic_services`); !slices.Equal(got, []string{"srun"}) {
		t.Errorf("port_agnostic_services = %q", got)
	}
	if got := queryStrings(t, conn, `SELECT name, proto, addr, port_from, port_to FROM shawk.dynamic_ports`); !slices.Equal(got,
		[]string{"cluster tcp 10.1.0.0/16 60001 63000"}) {
		t.Errorf("dynamic_ports = %q", got)
	}
	got := queryStrings(t, conn, `SELECT client_service, server_service, port, proto,
		round(extract(epoch FROM now() - first_seen) / 86400)::int, round(extract(epoch FROM now() - last_seen) / 86400)::int
		FROM shawk.known_dependencies WHERE port = 0`)
	if want := []string{"mpi mpi 0 tcp 3 1", "slurmctld srun 0 tcp 3 1"}; !slices.Equal(got, want) {
		t.Errorf("known on port 0 = %q, want %q", got, want)
	}
	st, err := newPGStore(context.Background(), dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer st.close()
	if err := st.syncConfig(context.Background(), nil, nil, nil); err != nil {
		t.Fatal(err)
	}
	if got := queryStrings(t, conn, `SELECT count(*) FROM shawk.port_agnostic_services UNION ALL SELECT count(*) FROM shawk.dynamic_ports`); !slices.Equal(got, []string{"0", "0"}) {
		t.Errorf("rules left = %q", got)
	}
}
