package shawkconnector

import (
	"context"
	"slices"
	"testing"
	"time"
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

// TestPGPortAgnosticThroughTranslations: through a translation, a range
// of dynamic_ports is matched with the backend, as in the outputs of the
// connector (TestPortAgnosticThroughTranslations).
func TestPGPortAgnosticThroughTranslations(t *testing.T) {
	c, sink, conn := pgConnectorWith(t, func(cfg *Config) {
		translationConfig(cfg)
		cfg.DynamicPorts = map[string]DynamicPortsConfig{
			"db":  {Hosts: []string{"10.0.1.0/24"}, Transport: "tcp", Ports: "5432-5432"},
			"web": {Hosts: []string{"10.0.1.20"}, Ports: "8080-8080"},
		}
	})
	app, db1, db2, web := translationAgents(time.Now().UTC().Truncate(time.Second))
	for _, a := range []tAgent{db1, db2, web, app} {
		consume(t, c, sink, a)
	}
	c.flush(context.Background())
	got := queryStrings(t, conn, `SELECT client_service, server_service, port
		FROM shawk.service_dependencies_between(now() - interval '1 hour', now()) WHERE client_service = 'shop/app'`)
	if want := []string{"shop/app postgres 0", "shop/app web 0", "shop/app ~unresolved 443"}; !slices.Equal(got, want) {
		t.Errorf("service_dependencies_between = %q, want %q", got, want)
	}
}

// TestPGPortRulesRemoved: a dependency on the ports of a rule, known on port
// 0 only while the rule held, is not new once the rule is removed: the
// change of the rules makes the next refresh rebuild known_dependencies
// from every edge. A connector that writes the same rules again leaves it.
func TestPGPortRulesRemoved(t *testing.T) {
	dsn, conn := migratedDB(t)
	portRulesFixture(t, dsn)
	f := fixture{t, conn}
	f.host("ctl01", "slurmctld")
	f.host("node01", "srun")
	f.conn2("ctl01", "slurmctld", "10.1.0.100", "node01", "srun", "10.1.0.1", 41234,
		"now()-interval '2 days'", "now()-interval '2 days'+interval '1 minute'")
	execAll(t, conn, `SELECT shawk.refresh_known_dependencies(interval '0')`)
	if got := queryStrings(t, conn, `SELECT port FROM shawk.known_dependencies`); !slices.Equal(got, []string{"0"}) {
		t.Fatalf("known ports = %q", got)
	}
	// The same rules again change nothing.
	portRulesFixture(t, dsn)
	if got := queryStrings(t, conn, `SELECT count(*) FROM shawk.known_dependencies_state`); !slices.Equal(got, []string{"1"}) {
		t.Errorf("state after the same rules = %q", got)
	}
	ctx := context.Background()
	st, err := newPGStore(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer st.close()
	if err := st.syncConfig(ctx, nil, nil, must(parsePortRules(nil, nil))); err != nil {
		t.Fatal(err)
	}
	execAll(t, conn, `SELECT shawk.refresh_known_dependencies(interval '0')`)
	if got := queryStrings(t, conn, `SELECT port FROM shawk.known_dependencies`); !slices.Equal(got, []string{"0", "41234"}) {
		t.Errorf("known ports after the rule was removed = %q", got)
	}
	// Another run on the same port is not new without the rule.
	f.conn2("ctl01", "slurmctld", "10.1.0.101", "node01", "srun", "10.1.0.1", 41234,
		"now()-interval '2 minutes'", "now()-interval '1 minute'")
	got := queryStrings(t, conn, `SELECT change, port FROM shawk_v1.dependency_changes_between(now() - interval '15 minutes', now())`)
	if len(got) != 0 {
		t.Errorf("changes = %q", got)
	}
}
