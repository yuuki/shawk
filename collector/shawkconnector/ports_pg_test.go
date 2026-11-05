package shawkconnector

import (
	"context"
	"fmt"
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
// dependencies known before on services of port_agnostic_services become
// known on port 0, so that configuring them does not make the
// dependencies new; ranges of dynamic_ports, which hold for addresses, are
// left to the refresh. Without rules the tables are emptied.
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
	if want := []string{"slurmctld srun 0 tcp 3 1"}; !slices.Equal(got, want) {
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

// TestPGDynamicPortsNewInRange: a dependency on a port of a range of
// dynamic_ports known only on a host outside the range does not hide one
// that is new in it, when the rule is configured after both were seen
// apart.
func TestPGDynamicPortsNewInRange(t *testing.T) {
	dsn, conn := migratedDB(t)
	f := fixture{t, conn}
	f.host("node02", "mpi")
	f.host("login01", "mpi")
	f.host("node01", "mpi")
	f.conn2("node02", "mpi", "10.1.0.2", "login01", "mpi", "10.2.0.1", 60010,
		"now()-interval '2 days'", "now()-interval '2 days'+interval '1 minute'")
	execAll(t, conn, `SELECT shawk.refresh_known_dependencies(interval '0')`)
	portRulesFixture(t, dsn)
	execAll(t, conn, `SELECT shawk.refresh_known_dependencies(interval '0')`)
	if got := queryStrings(t, conn, `SELECT port FROM shawk.known_dependencies`); !slices.Equal(got, []string{"60010"}) {
		t.Errorf("known ports = %q", got)
	}
	f.conn2("node02", "mpi", "10.1.0.2", "node01", "mpi", "10.1.0.1", 60010,
		"now()-interval '2 minutes'", "now()-interval '1 minute'")
	got := queryStrings(t, conn, `SELECT change, port FROM shawk_v1.dependency_changes_between(now() - interval '15 minutes', now())`)
	if want := []string{"appeared 0"}; !slices.Equal(got, want) {
		t.Errorf("changes = %q, want %q", got, want)
	}
}

// TestPGPortRuleKeys: the rules of ports read back from PostgreSQL compare
// equal to those the connector wrote, so that a connector with the same
// configuration logs nothing.
func TestPGPortRuleKeys(t *testing.T) {
	dsn, _ := migratedDB(t)
	ctx := context.Background()
	st, err := newPGStore(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer st.close()
	rules := must(parsePortRules([]string{"srun", "ns/salloc"}, map[string]DynamicPortsConfig{
		"cluster": {Hosts: []string{"10.1.0.0/16", "2001:db8:0:1::/64", "10.2.0.7"}, Transport: "tcp", Ports: "60001-63000"},
		"pmix":    {Ports: "50000-50010"},
	}))
	if err := st.syncConfig(ctx, nil, nil, rules); err != nil {
		t.Fatal(err)
	}
	got, err := st.portRuleKeys(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if want := rules.keys(); !slices.Equal(got, want) {
		t.Errorf("keys = %q, want %q", got, want)
	}
}

// TestPGPortAgnosticSlurmJobs: slurm-job in port_agnostic_services names the
// processes of Slurm jobs (units slurm/*), which keep their own names in
// PostgreSQL, as the connector names them as peers.
func TestPGPortAgnosticSlurmJobs(t *testing.T) {
	dsn, conn := migratedDB(t)
	ctx := context.Background()
	st, err := newPGStore(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer st.close()
	if err := st.syncConfig(ctx, nil, nil, must(parsePortRules([]string{"slurm-job"}, nil))); err != nil {
		t.Fatal(err)
	}
	f := fixture{t, conn}
	f.host("node01", "lmp", "sshd")
	f.host("node02", "lmp")
	execAll(t, conn, `UPDATE shawk.processes SET unit = 'slurm/step' WHERE service_name = 'lmp'`)
	f.conn2("node02", "lmp", "10.1.0.2", "node01", "lmp", "10.1.0.1", 45678, "now()-interval '1 hour'", "now()")
	f.conn2("node02", "lmp", "10.1.0.2", "node01", "sshd", "10.1.0.1", 22, "now()-interval '1 hour'", "now()")
	got := queryStrings(t, conn, `SELECT client_service, server_service, port
		FROM shawk.service_dependencies_between(now() - interval '1 day', now())`)
	if want := []string{"lmp lmp 0", "lmp sshd 22"}; !slices.Equal(got, want) {
		t.Errorf("service_dependencies_between = %q, want %q", got, want)
	}
}

// TestPGKernelChosenPorts: kernel_chosen_ports lists the services that
// listened on ports the kernel chose in the last 30 days and that no rule
// of ports covers, by service, processes of Slurm jobs and protocol. A
// listener on an unspecified address is covered only when the rules cover
// every address its host held meanwhile, but loopback and link-local.
func TestPGKernelChosenPorts(t *testing.T) {
	dsn, conn := migratedDB(t)
	portRulesFixture(t, dsn)
	f := fixture{t, conn}
	f.host("node01", "srun", "sshd", "app")
	f.host("node02")
	f.host("login01", "mpi")
	f.host("node03", "rank")
	f.host("node04", "rank")
	f.host("node05", "rank")
	execAll(t, conn, `INSERT INTO shawk.host_addrs (host_id, addr, first_seen, last_seen) VALUES
		('node01', '10.1.0.1', now() - interval '1 day', now()),
		('node01', '127.0.0.1', now() - interval '1 day', now()),
		('node01', 'fe80::1', now() - interval '1 day', now()),
		('node02', '10.1.0.2', now() - interval '1 day', now()),
		('login01', '10.2.0.1', now() - interval '1 day', now()),
		('node03', '10.1.0.3', now() - interval '1 day', now()),
		('node03', '192.168.1.3', now() - interval '1 day', now()),
		('node04', '10.1.0.4', now() - interval '60 days', now() - interval '50 days'),
		('node04', '10.2.0.4', now() - interval '1 day', now())`,
		// The ranks of jobs and PMIx, processes of Slurm jobs.
		`INSERT INTO shawk.processes (host_id, unit, comm, exe, service_name, first_seen, last_seen) VALUES
		('node01', 'slurm/7/step_0', 'mpi', '', 'mpi', now() - interval '1 day', now()),
		('node01', 'slurm/7/step_0', 'pmix', '', 'pmix', now() - interval '3 days', now()),
		('node02', 'slurm/7/step_0', 'pmix', '', 'pmix', now() - interval '1 day', now())`)
	// owner adds a listener of the process comm of unit on host; chosen is
	// when the kernel last chose its port, NULL if never.
	owner := func(host, unit, comm, proto, addr string, port int, first, last, chosen string) {
		t.Helper()
		execAll(t, conn, fmt.Sprintf(`INSERT INTO shawk.listener_owners
			(host_id, process_id, proto, addr, port, netns, first_seen, last_seen, kernel_chosen_seen)
			VALUES ('%s', (SELECT id FROM shawk.processes WHERE host_id = '%s' AND unit = '%s' AND comm = '%s'),
			        '%s', '%s', %d, 1, %s, %s, %s)`,
			host, host, unit, comm, proto, addr, port, first, last, chosen))
	}
	const hour, now = "now() - interval '1 hour'", "now()"
	// Covered: srun by port_agnostic_services, ranks on the range of
	// node01, also on an unspecified address of a host in the range, whose
	// loopback and link-local addresses the range need not hold.
	owner("node01", "srun.service", "srun", "tcp", "0.0.0.0", 41234, hour, now, now)
	owner("node01", "slurm/7/step_0", "mpi", "tcp", "10.1.0.1", 61000, hour, now, now)
	owner("node01", "slurm/7/step_0", "mpi", "tcp", "::", 62000, hour, now, now)
	// Not covered: PMIx of a job on two hosts, a rank on a host outside the
	// range, UDP outside the range, which is for TCP.
	owner("node01", "slurm/7/step_0", "pmix", "tcp", "0.0.0.0", 45000,
		"now() - interval '3 days'", "now() - interval '2 days'", "now() - interval '2 days'")
	owner("node02", "slurm/7/step_0", "pmix", "tcp", "0.0.0.0", 45001, hour, now, now)
	owner("node02", "slurm/7/step_0", "pmix", "tcp", "0.0.0.0", 45002, hour, now, now)
	owner("login01", "mpi.service", "mpi", "tcp", "0.0.0.0", 61500, hour, now, now)
	owner("node01", "slurm/7/step_0", "mpi", "udp", "10.1.0.1", 61000, hour, now, now)
	// Not covered either: a host with an address outside the range besides
	// one in it, a host whose address in the range is long gone, and a host
	// whose addresses are unknown.
	owner("node03", "rank.service", "rank", "tcp", "0.0.0.0", 61100, hour, now, now)
	owner("node04", "rank.service", "rank", "tcp", "0.0.0.0", 61200, hour, now, now)
	owner("node05", "rank.service", "rank", "tcp", "0.0.0.0", 61300, hour, now, now)
	// Left out: a port bound by its server, and a port the kernel last chose
	// 40 days ago, which the process has bound since.
	owner("node01", "sshd.service", "sshd", "tcp", "0.0.0.0", 22, hour, now, "NULL")
	owner("node01", "app.service", "app", "tcp", "0.0.0.0", 40000,
		"now() - interval '41 days'", now, "now() - interval '40 days'")

	q := `SELECT service, slurm_job, proto, hosts, ports, port_min, port_max,
	             to_char(now() - first_seen, 'DD HH24:MI'), to_char(now() - last_seen, 'DD HH24:MI')
	      FROM shawk_v1.kernel_chosen_ports`
	check := func(name string, want ...string) {
		t.Helper()
		if got := queryStrings(t, conn, q); !slices.Equal(got, want) {
			t.Errorf("kernel_chosen_ports %s = %q, want %q", name, got, want)
		}
	}
	check("",
		"mpi false tcp 1 1 61500 61500 00 01:00 00 00:00",
		"mpi true udp 1 1 61000 61000 00 01:00 00 00:00",
		"pmix true tcp 2 3 45000 45002 03 00:00 00 00:00",
		"rank false tcp 3 3 61100 61300 00 01:00 00 00:00")
	// slurm-job in port_agnostic_services covers the processes of jobs.
	execAll(t, conn, `INSERT INTO shawk.port_agnostic_services VALUES ('slurm-job')`)
	check("with slurm-job",
		"mpi false tcp 1 1 61500 61500 00 01:00 00 00:00",
		"rank false tcp 3 3 61100 61300 00 01:00 00 00:00")
	// A range of the other network of node03 covers its listener.
	execAll(t, conn, `INSERT INTO shawk.dynamic_ports VALUES ('mgmt', 'tcp', '192.168.0.0/16', 61000, 61999)`)
	check("with the other network of node03",
		"mpi false tcp 1 1 61500 61500 00 01:00 00 00:00",
		"rank false tcp 2 2 61200 61300 00 01:00 00 00:00")
}
