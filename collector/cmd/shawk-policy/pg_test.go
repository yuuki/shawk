package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/yuuki/shawk/collector/shawkconnector"
)

// The tests in this file run against PostgreSQL when SHAWK_TEST_POSTGRES_DSN
// is a URL of a role that may create databases and roles, as those of the
// connector: each creates its own database and drops it at the end.

// testDB returns the connection string of a new database with the schema,
// and a connection to it.
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
	name := fmt.Sprintf("shawk_policy_test_%d", time.Now().UnixNano())
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
	if _, err := shawkconnector.Migrate(ctx, conn); err != nil {
		t.Fatal(err)
	}
	return u.String(), conn
}

// pgFleet is a database with a small fleet, observed until end, the start
// of the current hour: app-01 and app-02 run shop/app (app.service), which
// uses the postgres of db-01, a resolver without an agent over UDP, and
// external peers that their agents folded; web-01 uses app-01; app-01 ran
// a job against 10.0.9.9 that ended 95 days ago. gap-01 runs shop/app too,
// and was not observed for an hour 10 days ago.
type pgFleet struct {
	t    *testing.T
	dsn  string
	conn *pgx.Conn
	end  time.Time
}

const day = 24 * time.Hour

func (f *pgFleet) at(ago time.Duration) string {
	return "'" + f.end.Add(-ago).Format(time.RFC3339) + "'::timestamptz"
}

func (f *pgFleet) exec(format string, args ...any) {
	f.t.Helper()
	if _, err := f.conn.Exec(context.Background(), fmt.Sprintf(format, args...)); err != nil {
		f.t.Fatalf("%v\n%s", err, fmt.Sprintf(format, args...))
	}
}

// edge adds an edge of the process of a service on a host.
func (f *pgFleet) edge(host, service, role, proto, local, remote string, port int, first, last time.Duration) {
	f.t.Helper()
	f.exec(`INSERT INTO shawk.edges (host_id, process_id, role, proto, local_addr, remote_addr, port, netns, first_seen, last_seen)
	        VALUES ('%[1]s', (SELECT id FROM shawk.processes WHERE host_id = '%[1]s' AND service_name = '%[2]s'),
	                '%[3]s', '%[4]s', '%[5]s', '%[6]s', %[7]d, 1, %[8]s, %[9]s)`,
		host, service, role, proto, local, remote, port, f.at(first), f.at(last))
}

func newFleet(t *testing.T) *pgFleet {
	t.Helper()
	dsn, conn := testDB(t)
	f := &pgFleet{t, dsn, conn, time.Now().UTC().Truncate(time.Hour)}
	for host, addr := range map[string]string{"app-01": "10.0.0.11", "app-02": "10.0.0.21", "db-01": "10.0.0.10", "web-01": "10.0.0.12",
		"gap-01": "10.0.0.31"} {
		f.exec(`INSERT INTO shawk.hosts VALUES ('%[1]s', 'm-%[1]s', '%[1]s', 'k', 'v', %[2]s, %[3]s)`, host, f.at(100*day), f.at(0))
		f.exec(`INSERT INTO shawk.host_addrs VALUES ('%s', '%s', %s, %s)`, host, addr, f.at(100*day), f.at(0))
		if host != "gap-01" {
			f.exec(`INSERT INTO shawk.agent_sessions (host_id, started_at, last_heartbeat, udp_traced, unix_traced, netns_scope, translations_traced)
			        VALUES ('%s', %s, %s, true, true, 'all', true)`, host, f.at(100*day), f.at(0))
		}
	}
	f.exec(`INSERT INTO shawk.agent_sessions (host_id, started_at, last_heartbeat, udp_traced, unix_traced, netns_scope, translations_traced) VALUES
	        ('gap-01', %s, %s, true, true, 'all', true), ('gap-01', %s, %s, true, true, 'all', true)`,
		f.at(100*day), f.at(10*day), f.at(10*day-time.Hour-3*time.Minute), f.at(0))
	for _, p := range [][3]string{{"app-01", "app.service", "shop/app"}, {"app-02", "app.service", "shop/app"},
		{"gap-01", "app.service", "shop/app"}, {"db-01", "postgresql.service", "shop/postgres"}, {"web-01", "nginx.service", "nginx"},
		{"app-01", "sshd.service", "sshd"}} {
		f.exec(`INSERT INTO shawk.processes (host_id, unit, comm, exe, service_name, first_seen, last_seen)
		        VALUES ('%s', '%s', 'c', '', '%s', %s, %s)`, p[0], p[1], p[2], f.at(100*day), f.at(0))
	}
	for host, addr := range map[string]string{"app-01": "10.0.0.11", "app-02": "10.0.0.21", "gap-01": "10.0.0.31"} {
		f.edge(host, "shop/app", "client", "tcp", addr, "10.0.0.10", 5432, 80*day, 0)
		f.edge("db-01", "shop/postgres", "server", "tcp", "10.0.0.10", addr, 5432, 80*day, 0)
		f.edge(host, "shop/app", "client", "udp", addr, "10.0.0.53", 53, 80*day, 0)
		f.edge(host, "shop/app", "client", "tcp", addr, "0.0.0.0/0", 443, 80*day, day)
	}
	f.edge("web-01", "nginx", "client", "tcp", "10.0.0.12", "10.0.0.11", 8080, 80*day, 0)
	f.edge("app-01", "shop/app", "server", "tcp", "10.0.0.11", "10.0.0.12", 8080, 80*day, 0)
	f.edge("app-01", "shop/app", "client", "tcp", "10.0.0.11", "10.0.9.9", 9000, 99*day, 95*day)
	f.edge("app-01", "sshd", "server", "tcp", "10.0.0.11", "10.0.5.5", 22, 80*day, 2*day)
	// A role that reads the contract only, as Grafana does.
	f.exec(`
DO $$ BEGIN
  IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'shawk_policy_reader') THEN CREATE ROLE shawk_policy_reader NOLOGIN; END IF;
END $$;
GRANT USAGE ON SCHEMA shawk_v1 TO shawk_policy_reader;
GRANT SELECT ON ALL TABLES IN SCHEMA shawk_v1 TO shawk_policy_reader`)
	t.Cleanup(func() { conn.Exec(context.Background(), "DROP OWNED BY shawk_policy_reader") })
	return f
}

// run runs the command over the period that ends at the end of the fleet,
// as the role that reads the contract only, and returns its exit status
// and outputs.
func (f *pgFleet) run(command string, args ...string) (int, string, string) {
	f.t.Helper()
	args = append([]string{command, "-dsn", f.dsn + "?options=-c%20role%3Dshawk_policy_reader", "-until", f.end.Format(time.RFC3339)}, args...)
	var out, errOut bytes.Buffer
	code := run(context.Background(), args, &out, &errOut)
	return code, out.String(), errOut.String()
}

// approve writes a baseline to the database as the connector does.
func (f *pgFleet) approve(file string) {
	f.t.Helper()
	b, err := shawkconnector.ParseBaseline([]byte(strings.TrimRight(file, "\n") + "\nend: {}\n"))
	if err != nil {
		f.t.Fatal(err)
	}
	f.exec(`DELETE FROM shawk.baseline_services`)
	for _, s := range b.Services {
		f.exec(`INSERT INTO shawk.baseline_services VALUES ('%s')`, s.Service)
		for _, d := range s.Dependencies {
			f.exec(`INSERT INTO shawk.baseline_dependencies VALUES ('%s', '%s', %d, '%s')`, s.Service, d.Peer, d.Port, d.Proto)
		}
	}
	f.exec(`INSERT INTO shawk.baseline_state (digest, read_at) VALUES ('%s', %s)
	        ON CONFLICT (singleton) DO UPDATE SET digest = excluded.digest, read_at = excluded.read_at, failed_at = NULL, error = NULL`,
		b.Digest(), f.at(0))
}

var (
	timestamps = regexp.MustCompile(`\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ`)
	columns    = regexp.MustCompile(`  +`)
)

// stable replaces the times of an output, which depend on when the test
// runs, by TIME, and the spaces between the columns of its tables, whose
// widths depend on them, by two.
func stable(s string) string {
	return columns.ReplaceAllString(timestamps.ReplaceAllString(s, "TIME"), "  ")
}

// TestPGRules: the command reads the flows and the verdict of a host as a
// role that reads the contract only, writes the rules that allow what was
// seen, and its exit status tells whether the history is complete.
func TestPGRules(t *testing.T) {
	f := newFleet(t)
	code, out, errOut := f.run("rules", "-host", "app-01")
	_, rules, _ := strings.Cut(stable(out), "\nRules\n")
	want := `DIRECTION  PORTS           PEER                   ADDRESSES  SERVICES  LAST SEEN  NOTES
egress     443/tcp         ~external              0.0.0.0/0  shop/app  TIME       folded peers
egress     5432/tcp        shop/postgres (db-01)  10.0.0.10  shop/app  TIME
egress     53/udp          ~unresolved            10.0.0.53  shop/app  TIME
ingress    22/tcp          ~unresolved            10.0.5.5   sshd      TIME
ingress    8080/tcp        nginx (web-01)         10.0.0.12  shop/app  TIME
ingress    53/udp from 53  ~unresolved            10.0.0.53  shop/app  TIME       the other way of a UDP rule

Seen before the period, and in no rule
DIRECTION  PORT      PEER         ADDRESS   SERVICE   LAST SEEN
egress     9000/tcp  ~unresolved  10.0.9.9  shop/app  TIME

shawk applied nothing. -format nftables writes the rules as a table that rejects nothing and counts
what they do not list (the audit form): load it first. -enforce writes the table that rejects, and
-format systemd -enforce the drop-in of a unit.
`
	if code != exitComplete || errOut != "" || rules != stable(want) ||
		!strings.Contains(out, "Target   host app-01\n") || !strings.Contains(stable(out), "Period  TIME to TIME (90d)\n") ||
		!strings.Contains(out, "Status   COMPLETE: an agent observed the target for the whole period, so the history tells every\n"+
			"         TCP and UDP connection that its sockets made in it\n         (coverage 1; 1 is all of the period)\n") {
		t.Errorf("rules of app-01: exit status %d, stderr %q\n%s\nwant the rules:\n%s", code, errOut, out, want)
	}

	// The table of nftables allows those flows and nothing else.
	code, out, errOut = f.run("rules", "-host", "app-01", "-format", "nftables")
	// It is the audit form unless -enforce asks for the one that rejects.
	wantRules := []string{"egress tcp to 443-443 0.0.0.0/0", "egress tcp to 5432-5432 10.0.0.10/32", "egress udp to 53-53 10.0.0.53/32",
		"ingress tcp to 22-22 10.0.5.5/32", "ingress tcp to 8080-8080 10.0.0.12/32", "ingress udp between 53-53 10.0.0.53/32"}
	if got := parseNftables(t, out); code != exitComplete || errOut != "" || !slices.Equal(got, wantRules) ||
		!strings.Contains(out, "# AUDIT form: it rejects nothing.") || strings.Contains(out, "reject with") {
		t.Errorf("nftables of app-01: exit status %d, stderr %q; it allows %v, want %v\n%s", code, errOut, got, wantRules, out)
	}
	code, out, errOut = f.run("rules", "-host", "app-01", "-format", "nftables", "-enforce")
	if got := parseNftables(t, out); code != exitComplete || errOut != "" || !slices.Equal(got, wantRules) ||
		!strings.Contains(out, "# ENFORCING form: it rejects what no rule lists.") ||
		!strings.Contains(out, "\t\tcounter name \"egress_unlisted\" reject with icmpx admin-prohibited\n") {
		t.Errorf("nftables of app-01 with -enforce: exit status %d, stderr %q; it allows %v, want %v\n%s", code, errOut, got, wantRules, out)
	}
	code, out, _ = f.run("rules", "-host", "app-01", "-format", "nftables", "-ingress", "ports")
	wantRules[3], wantRules[4] = "ingress tcp to 22-22 any", "ingress tcp to 8080-8080 any"
	if got := parseNftables(t, out); code != exitComplete || !slices.Equal(got, wantRules) {
		t.Errorf("nftables of app-01 with -ingress ports: exit status %d; it allows %v, want %v", code, got, wantRules)
	}
	// A longer period holds the job.
	code, out, _ = f.run("rules", "-host", "app-01", "-format", "nftables", "-ingress", "none", "-lookback", "98d")
	if got := parseNftables(t, out); code != exitComplete || !slices.Contains(got, "egress tcp to 9000-9000 10.0.9.9/32") || len(got) != 4 {
		t.Errorf("nftables of app-01 over 98 days: exit status %d; it allows %v", code, got)
	}

	// The drop-in of the unit of the application: sshd is another unit.
	code, out, errOut = f.run("rules", "-host", "app-01", "-unit", "app.service", "-format", "systemd", "-enforce")
	wantAllow := []string{"0.0.0.0/0", "10.0.0.10/32", "10.0.0.12/32", "10.0.0.53/32"}
	if got := parseSystemd(t, out); code != exitComplete || errOut != "" || !slices.Equal(got, wantAllow) ||
		!strings.Contains(out, "# Target   unit app.service of host app-01\n") {
		t.Errorf("the drop-in of app.service: exit status %d, stderr %q; it allows %v, want %v\n%s", code, errOut, got, wantAllow, out)
	}

	code, out, _ = f.run("rules", "-host", "app-01", "-format", "json")
	var r rulesReport
	if err := json.Unmarshal([]byte(out), &r); err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	if code != exitComplete || r.Status != statusComplete || r.Coverage != 1 || len(r.Rules) != 6 || len(r.Before) != 1 || r.Refused ||
		r.Observation == nil || r.Observation.Machines != 1 || !r.Until.Equal(f.end) || !r.Since.Equal(f.end.Add(-90*day)) ||
		r.Rules[1].Peer != "shop/postgres" || !slices.Equal(r.Rules[1].PeerHosts, []string{"db-01"}) || r.NetworkNamespaces != 1 ||
		!r.TranslationsTraced {
		t.Errorf("exit status %d, report = %+v", code, r)
	}
	// A host whose agent folds its peers, as an agent does by default,
	// did not learn every address that the host rewrites its connections
	// to: the rules may lack what the packets leave for, and are not
	// complete, whatever is accepted of the time that was not observed. The
	// audit form is written all the same, and says so.
	f.exec(`UPDATE shawk.agent_sessions SET peer_fold = 'in' WHERE host_id = 'app-02'`)
	code, out, _ = f.run("rules", "-host", "app-02", "-min-coverage", "0.5")
	if code != exitIncomplete || !strings.Contains(out, "         - an agent of the host did not learn every address that the host rewrites its connections\n") {
		t.Errorf("rules of a host whose agent folds its peers: exit status %d\n%s", code, out)
	}
	code, out, errOut = f.run("rules", "-host", "app-02", "-format", "nftables")
	if code != exitIncomplete || errOut != "" || !strings.HasPrefix(out, "#!/usr/sbin/nft -f\n# INCOMPLETE: the history does not tell every connection of the target") ||
		!strings.Contains(out, "\t\tip daddr 10.0.0.10 tcp dport 5432 accept\n") || strings.Contains(out, "reject with") {
		t.Errorf("the audit form of that host: exit status %d, stderr %q\n%s", code, errOut, out)
	}
	code, out, errOut = f.run("rules", "-host", "app-02", "-format", "nftables", "-enforce")
	if code != exitIncomplete || strings.Contains(out, "table inet") || !strings.Contains(errOut, "no file that blocks is written") {
		t.Errorf("the form that rejects of that host: exit status %d, stderr %q\n%s", code, errOut, out)
	}
	// Two machines that report under one name: the rules would be of both.
	f.exec(`INSERT INTO shawk.hosts VALUES ('db-01-twin', 'm-twin', 'db-01', 'k', 'v', %s, %s)`, f.at(100*day), f.at(0))
	f.exec(`INSERT INTO shawk.agent_sessions (host_id, started_at, last_heartbeat, udp_traced, unix_traced, netns_scope, translations_traced)
	        VALUES ('db-01-twin', %s, %s, true, true, 'all', true)`, f.at(100*day), f.at(20*day))
	code, out, _ = f.run("rules", "-host", "db-01")
	if code != exitIncomplete || !strings.Contains(out, "         - 2 machines reported under this host name in the period") ||
		!strings.Contains(out, ", machine db-01-twin\n") {
		t.Errorf("rules of a name of two machines: exit status %d\n%s", code, out)
	}
}

// TestPGRulesIncomplete: from a history that does not tell everything, no
// rules are written unless they are asked for, and the status is never 0.
func TestPGRulesIncomplete(t *testing.T) {
	f := newFleet(t)
	for _, format := range [][]string{{"-format", "nftables", "-enforce"}, {"-format", "systemd", "-enforce", "-unit", "app.service"}} {
		args := append([]string{"-host", "gap-01"}, format...)
		code, out, errOut := f.run("rules", args...)
		if code != exitIncomplete || strings.Contains(out, "accept\n") || strings.Contains(out, "\nIPAddressAllow=") ||
			!strings.Contains(out, "Status   INCOMPLETE: the history does not tell every connection of the target in the period.\n") ||
			!strings.Contains(out, "         - not observed by an agent for 1h of the period\n") ||
			!strings.Contains(stable(out), "\nNot observed\n  TIME to TIME (1h)\n") ||
			!strings.Contains(out, "\nNo file that blocks is written from an incomplete history.") ||
			!strings.Contains(errOut, "the history is INCOMPLETE: no file that blocks is written") {
			t.Errorf("%v of gap-01: exit status %d, stderr %q\n%s", format, code, errOut, out)
		}
		// Asked for, they are written, marked, and the status stays 4.
		code, out, errOut = f.run("rules", append(args, "-allow-incomplete")...)
		if code != exitIncomplete || errOut != "" || !strings.Contains(out, "# INCOMPLETE: written with -allow-incomplete") ||
			!strings.Contains(out, "10.0.0.10") {
			t.Errorf("%v of gap-01 with -allow-incomplete: exit status %d, stderr %q\n%s", format, code, errOut, out)
		}
		// A caller who accepts the gap gets them, with what was accepted.
		code, out, _ = f.run("rules", append(args, "-min-coverage", "0.999")...)
		if code != exitComplete || !strings.Contains(out, "# Status   COMPLETE by -min-coverage 0.999 only: the history tells the connections of 0.999537 of the period\n") ||
			!strings.Contains(out, "#          Accepted as not observed:\n#          - not observed by an agent for 1h of the period\n") ||
			strings.Contains(out, "# INCOMPLETE") {
			t.Errorf("%v of gap-01 with -min-coverage 0.999: exit status %d\n%s", format, code, out)
		}
	}
	// The audit form blocks nothing: it is written, marked, with status 4.
	if code, out, errOut := f.run("rules", "-host", "gap-01", "-format", "nftables"); code != exitIncomplete || errOut != "" ||
		!strings.HasPrefix(out, "#!/usr/sbin/nft -f\n# INCOMPLETE: the history does not tell every connection of the target") ||
		!strings.Contains(out, "# AUDIT form: it rejects nothing.") || strings.Contains(out, "reject with") {
		t.Errorf("the audit form of gap-01: exit status %d, stderr %q\n%s", code, errOut, out)
	}
	// The report lists what the rules would hold, and is not complete either.
	if code, out, _ := f.run("rules", "-host", "gap-01"); code != exitIncomplete || !strings.Contains(out, "\nRules\n") {
		t.Errorf("the report of gap-01: exit status %d\n%s", code, out)
	}
	if code, out, _ := f.run("rules", "-host", "gap-01", "-format", "json"); code != exitIncomplete || !strings.Contains(out, `"status": "INCOMPLETE"`) {
		t.Errorf("the JSON of gap-01: exit status %d\n%s", code, out)
	}
	// A name that nothing knows is never complete, whatever is accepted.
	for _, c := range []struct {
		args []string
		want string
	}{
		{[]string{"-host", "app-O1"}, "no agent ever reported under this name"},
		{[]string{"-host", "app-01", "-unit", "ap.service"}, "no process of the host had this unit in the period"},
		{[]string{"-host", "app-O1", "-min-coverage", "0.000001", "-format", "nftables"}, "no agent ever reported under this name"},
		{[]string{"-host", "app-O1", "-format", "nftables", "-enforce", "-allow-incomplete"}, "No rules are written: nothing is known of the target"},
		{[]string{"-host", "app-01", "-unit", "ap.service", "-format", "systemd", "-enforce", "-allow-incomplete"},
			"No rules are written: nothing is known of the target"},
	} {
		if code, out, _ := f.run("rules", c.args...); code != exitIncomplete || !strings.Contains(out, c.want) || strings.Contains(out, "table inet") {
			t.Errorf("%v: exit status %d\n%s", c.args, code, out)
		}
	}
	// A period that reaches before the agents: nothing was watched then.
	if code, _, _ := f.run("rules", "-host", "app-01", "-lookback", "52w"); code != exitIncomplete {
		t.Errorf("app-01 over a year: exit status %d", code)
	}
	// Without access to the contract the command fails, and writes nothing.
	f.exec(`REVOKE USAGE ON SCHEMA shawk_v1 FROM shawk_policy_reader`)
	if code, out, _ := f.run("rules", "-host", "app-01"); code != exitError || out != "" {
		t.Errorf("without access to shawk_v1: exit status %d\n%s", code, out)
	}
}

// TestPGRulesTools: what the command writes from the database is accepted
// by nft and by systemd-analyze, where they are available.
func TestPGRulesTools(t *testing.T) {
	f := newFleet(t)
	_, table, _ := f.run("rules", "-host", "app-01", "-format", "nftables")
	_, rejecting, _ := f.run("rules", "-host", "app-01", "-format", "nftables", "-enforce")
	_, dropIn, _ := f.run("rules", "-host", "app-01", "-unit", "app.service", "-format", "systemd", "-enforce")
	t.Run("nft", func(t *testing.T) {
		netns := inNetns(t)
		// What was seen, and the other way of the flow of UDP: the answers
		// of the resolver, whenever they come.
		want := []string{"egress tcp to 443-443 0.0.0.0-255.255.255.255", "egress tcp to 5432-5432 10.0.0.10-10.0.0.10",
			"egress udp to 53-53 10.0.0.53-10.0.0.53", "ingress tcp to 22-22 10.0.5.5-10.0.5.5",
			"ingress tcp to 8080-8080 10.0.0.12-10.0.0.12", "ingress udp between 53-53 10.0.0.53-10.0.0.53"}
		for name, text := range map[string]string{"audit": table, "enforce": rejecting} {
			if got := listedSpans(t, loadNftables(t, netns, text), name == "enforce"); !slices.Equal(got, want) {
				t.Errorf("%s: the kernel allows %v, want %v", name, got, want)
			}
		}
	})
	t.Run("systemd-analyze", func(t *testing.T) {
		analyze, err := exec.LookPath("systemd-analyze")
		if err != nil {
			t.Skip("systemd-analyze is not available")
		}
		if problems := verifyDropIn(t, analyze, "app.service", dropIn); len(problems) > 0 {
			t.Errorf("systemd-analyze verify reports %v of\n%s", problems, dropIn)
		}
	})
}

// TestPGBaseline: the command writes the dependencies of services as a
// file that the connector reads, and refuses to from a history that does
// not tell them all.
func TestPGBaseline(t *testing.T) {
	f := newFleet(t)
	code, out, errOut := f.run("baseline", "-service", "nginx")
	want := `# Baseline of dependencies, written by shawk-policy for review. The connector reads it once
# it is approved (baseline_file) and tells the dependencies of these services that are not here.
#
# Period   TIME to TIME (90d)
#
# Service  nginx
# Status   COMPLETE: 1 host that ran it was observed for the whole period (coverage 1; 1 is all of the period)
#   PEER      PORT      HOSTS  NAMED BY  LAST SEEN  ADDRESSES  NOTES
#   shop/app  8080/tcp  1      edge      TIME       10.0.0.11
#
# A peer is a service by its name, as its agent or its listener tells it, a range of peer_cidrs,
# ~unresolved (a private address that shawk cannot name) or ~external (a public address, or peers
# whose addresses the agent folded). Port 0 stands for every port, and kernel-chosen for the ports
# that the kernel chose for a server of the name, which change at each of its runs: for those and
# for no port that a server was given. A dependency that was not used
# in the period is not listed: one used less often than the period, or only when another server
# fails. Dependencies over Unix sockets are not part of a baseline. A process of another name in
# a unit of a service, which has no baseline of its own, is judged by the services of the unit:
# what it connected to is listed with the first of them. Units that unrelated processes share (the
# jobs of Slurm, login sessions) judge nothing. The last line of the file tells that it is whole:
# keep it last, and its counts right (or write ` + "`end: {}`" + `).

services:
  - service: nginx
    dependencies:
      - {peer: shop/app, port: 8080, proto: tcp}
end: {services: 1, dependencies: 1}
`
	if code != exitComplete || errOut != "" || stable(out) != stable(want) {
		t.Errorf("baseline of nginx: exit status %d, stderr %q\n%s\nwant:\n%s", code, errOut, stable(out), stable(want))
	}

	// shop/app runs on a host that was not observed for an hour.
	code, out, errOut = f.run("baseline", "-service", "shop/app", "-service", "nginx")
	if code != exitIncomplete || strings.Contains(out, "services:") ||
		!strings.Contains(out, "Service  shop/app\nStatus   INCOMPLETE: the history does not tell every dependency of the 3 hosts that ran it.\n") ||
		!strings.Contains(out, "         - not observed by an agent\n         not observed enough: gap-01\n") ||
		!strings.Contains(out, "\nNo baseline is written from an incomplete history.") || !strings.Contains(errOut, "no baseline is written") {
		t.Errorf("baseline of shop/app: exit status %d, stderr %q\n%s", code, errOut, out)
	}
	code, out, _ = f.run("baseline", "-service", "shop/app", "-service", "nginx", "-allow-incomplete")
	b, err := shawkconnector.ParseBaseline([]byte(out))
	if code != exitIncomplete || err != nil || !strings.HasPrefix(out, "# INCOMPLETE: written with -allow-incomplete") || len(b.Services) != 2 ||
		fmt.Sprint(b.Services[1]) != "{shop/app [{shop/postgres 5432 tcp false} {~external 443 tcp false} {~unresolved 53 udp false}]}" {
		t.Errorf("baseline of shop/app with -allow-incomplete: exit status %d, %v, %+v\n%s", code, err, b, out)
	}
	code, out, _ = f.run("baseline", "-service", "shop/app", "-min-coverage", "0.999")
	if b, err = shawkconnector.ParseBaseline([]byte(out)); code != exitComplete || err != nil || len(b.Services) != 1 ||
		!strings.Contains(out, "# Status   COMPLETE by -min-coverage 0.999 only: the least observed of the 3 hosts that ran it was observed\n"+
			"#          for 0.999537 of the period (1 is all of it). A dependency of the rest is missing here.\n"+
			"#          Accepted as not observed:\n#          - not observed by an agent\n") {
		t.Errorf("baseline of shop/app with -min-coverage 0.999: exit status %d, %v\n%s", code, err, out)
	}

	// Every service that opened connections; those that only accept are in
	// no baseline.
	code, out, _ = f.run("baseline", "-all", "-min-coverage", "0.999")
	if b, err = shawkconnector.ParseBaseline([]byte(out)); code != exitComplete || err != nil || len(b.Services) != 2 ||
		b.Services[0].Service != "nginx" || b.Services[1].Service != "shop/app" {
		t.Errorf("baseline of every service: exit status %d, %v, %+v", code, err, b)
	}

	// Over a period in which nothing connected, -all finds no service: no
	// file is written, and the status is not that of a complete history.
	if code, out, _ = f.run("baseline", "-all", "-until", f.end.Add(-200*day).Format(time.RFC3339), "-lookback", "1d"); code != exitIncomplete ||
		strings.Contains(out, "services:") || !strings.Contains(out, "\nNo baseline is written: none of the services was seen in the period.\n") {
		t.Errorf("baseline of every service of a period without any: exit status %d\n%s", code, out)
	}

	// A service that no process had is never written: a name mistyped
	// would approve nothing, and a file of no service drops every baseline.
	code, out, _ = f.run("baseline", "-service", "ngimx", "-allow-incomplete")
	if code != exitIncomplete || strings.Contains(out, "services:") || !strings.Contains(out, "Service  ngimx\nStatus   INCOMPLETE: not written\n"+
		"         - no process of this service was seen on any host: check the name\n") ||
		!strings.Contains(out, "\nNo baseline is written: none of the services was seen in the period.\n") {
		t.Errorf("baseline of a service that is not known: exit status %d\n%s", code, out)
	}
	code, out, _ = f.run("baseline", "-service", "ngimx", "-service", "nginx", "-allow-incomplete")
	if b, err = shawkconnector.ParseBaseline([]byte(out)); code != exitIncomplete || err != nil || len(b.Services) != 1 || b.Services[0].Service != "nginx" {
		t.Errorf("baseline of a service that is not known and one that is: exit status %d, %v, %+v", code, err, b)
	}

	// -merge writes the file again with the services asked for replaced,
	// and the others, also one that is asked for and not known, as they are.
	file := filepath.Join(t.TempDir(), "baseline.yaml")
	if err := os.WriteFile(file, []byte(`
services:
  - service: nginx
    dependencies:
      - {peer: old/app, port: 80, proto: tcp}
  - service: batch/report
    dependencies: []
  - service: ngimx
    dependencies:
      - {peer: kept, port: 1, proto: udp}
end: {services: 3, dependencies: 2}
`), 0o600); err != nil {
		t.Fatal(err)
	}
	code, out, _ = f.run("baseline", "-service", "nginx", "-merge", file)
	b, err = shawkconnector.ParseBaseline([]byte(out))
	if code != exitComplete || err != nil || len(b.Services) != 3 || fmt.Sprint(b.Services) !=
		"[{batch/report []} {ngimx [{kept 1 udp false}]} {nginx [{shop/app 8080 tcp false}]}]" ||
		!strings.Contains(out, "# Merged   with "+file+", of which 2 other services are kept as they are\n") {
		t.Errorf("merged baseline: exit status %d, %v, %+v\n%s", code, err, b, out)
	}
	code, out, _ = f.run("baseline", "-service", "nginx", "-service", "ngimx", "-merge", file, "-allow-incomplete")
	if b, err = shawkconnector.ParseBaseline([]byte(out)); code != exitIncomplete || err != nil || fmt.Sprint(b.Services) !=
		"[{batch/report []} {ngimx [{kept 1 udp false}]} {nginx [{shop/app 8080 tcp false}]}]" {
		t.Errorf("merged baseline with a service that is not known: exit status %d, %v, %+v", code, err, b)
	}

	code, out, _ = f.run("baseline", "-service", "nginx", "-json")
	var r baselineReport
	if err := json.Unmarshal([]byte(out), &r); err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	if code != exitComplete || r.Status != statusComplete || len(r.Services) != 1 || len(r.Services[0].Dependencies) != 1 || r.Refused ||
		r.Services[0].Dependencies[0].Peer != "shop/app" || !slices.Equal(r.Services[0].Dependencies[0].Hosts, []string{"web-01"}) ||
		!slices.Equal(r.Services[0].Dependencies[0].Addresses, []string{"10.0.0.11"}) || !strings.HasPrefix(r.File, "services:\n") {
		t.Errorf("exit status %d, report = %+v", code, r)
	}
}

// TestPGDrift: the command tells the dependencies that the baseline does
// not hold, and its exit status tells a drift from none, and from an
// answer that the history cannot give.
func TestPGDrift(t *testing.T) {
	f := newFleet(t)
	// No connector read a baseline: nothing is judged, which is no answer.
	code, out, _ := f.run("drift")
	if code != exitInconclusive || !strings.Contains(out, "Verdict  INCONCLUSIVE: no drift was seen, but nothing tells that there was none\n"+
		"         - no connector read a baseline (baseline_file): nothing is judged\n") {
		t.Errorf("without a baseline: exit status %d\n%s", code, out)
	}
	// Nor did one that only ever failed to read its file: the state of the
	// baseline is there, and no baseline.
	f.exec(`INSERT INTO shawk.baseline_state (failed_at, error) VALUES (%s, 'no services')`, f.at(0))
	code, out, _ = f.run("drift")
	if code != exitInconclusive || !strings.Contains(out, "         - no connector read a baseline (baseline_file): nothing is judged\n") ||
		strings.Contains(out, "Baseline ") {
		t.Errorf("with a baseline that was never read: exit status %d\n%s", code, out)
	}
	f.approve(`
services:
  - service: shop/app
    dependencies:
      - {peer: shop/postgres, port: 5432, proto: tcp}
      - {peer: ~unresolved, port: 53, proto: udp}
      - {peer: ~external, port: 443, proto: tcp}
  - service: nginx
    dependencies:
      - {peer: shop/app, port: 8080, proto: tcp}
`)
	code, out, errOut := f.run("drift")
	if code != exitComplete || errOut != "" || !strings.Contains(stable(out), "Period  TIME to TIME (1h)\nBaseline 2 services with 4 dependencies, read TIME\n\n"+
		"Verdict  CLEAN: 2 services did nothing over TCP or UDP that the baseline does not hold, and every host\n"+
		"  that runs them was observed for the whole period\n") || strings.Contains(out, "Not in the baseline") {
		t.Errorf("without a drift: exit status %d, stderr %q\n%s", code, errOut, out)
	}

	// A release of shop/app on two hosts connects to a host without an
	// agent, and curl runs in the unit of the application on one.
	f.edge("app-01", "shop/app", "client", "tcp", "10.0.0.11", "10.0.7.7", 8443, 20*time.Minute, 0)
	f.edge("app-02", "shop/app", "client", "tcp", "10.0.0.21", "10.0.7.7", 8443, 15*time.Minute, 0)
	f.exec(`INSERT INTO shawk.processes (host_id, unit, comm, exe, service_name, first_seen, last_seen)
	        VALUES ('app-01', 'app.service', 'curl', '', 'curl', %s, %s)`, f.at(10*time.Minute), f.at(0))
	f.edge("app-01", "curl", "client", "tcp", "10.0.0.11", "0.0.0.0/0", 443, 10*time.Minute, 0)
	code, out, errOut = f.run("drift")
	want := `Period   TIME to TIME (1h)
Baseline 2 services with 4 dependencies, read TIME

Verdict  DRIFT: 1 dependency is not in the baseline of 1 service

Not in the baseline
SERVICE   PEER         PORT      HOSTS           NAMED BY  FIRST SEEN  LAST SEEN  ADDRESSES  NOTES
shop/app  ~unresolved  8443/tcp  app-01, app-02  address   TIME        TIME       10.0.7.7
To approve one, add it to the baseline file of the connector, as
  - {peer: ~unresolved, port: 8443, proto: tcp}    under service shop/app
with the counts of the last line of the file (end:), or write the service again:
shawk-policy baseline -service NAME -merge FILE.
~unresolved: a private address that shawk cannot name. It may be a server whose agent is
stopped and whose listener is not known, or one without an agent: see the addresses.

New services without a baseline, which nothing judges
SERVICE  FIRST SEEN  HOSTS
curl     TIME        app-01
A new executable, or a process that names itself anew, is a service of its own. In a unit of a
workload that runs services of the baseline it is judged by them; anywhere else nothing judges it.

Only TCP and UDP are judged, by the name of the server and its port: a server of the same name
at another address is no drift, and ~external does not tell one public address from another.
A process is judged by the baseline of the name it declares, or, without one, by the services of
the baseline in its unit, unless the unit is one that unrelated processes share. A socket without
a known owner (~unknown), and a process that takes the name of another service of the baseline,
are not told apart from what that baseline approves.
`
	if code != exitDrift || errOut != "" || stable(out) != stable(want) {
		t.Errorf("a drift: exit status %d, stderr %q\n%s\nwant:\n%s", code, errOut, stable(out), stable(want))
	}
	// Of the services asked for only: nginx has none, and one without a
	// baseline is no answer.
	if code, out, _ = f.run("drift", "-service", "nginx"); code != exitComplete || !strings.Contains(out, "Verdict  CLEAN: 1 service did nothing") ||
		strings.Contains(out, "curl") {
		t.Errorf("drift of nginx: exit status %d\n%s", code, out)
	}
	if code, out, _ = f.run("drift", "-service", "nginx", "-service", "sshd"); code != exitInconclusive ||
		!strings.Contains(out, "         - no baseline for sshd: not judged\n") {
		t.Errorf("drift of nginx and sshd: exit status %d\n%s", code, out)
	}
	if code, out, _ = f.run("drift", "-service", "shop/app", "-service", "sshd"); code != exitDrift ||
		!strings.Contains(out, "         The drift below may not be all:\n         - no baseline for sshd: not judged\n") {
		t.Errorf("drift of shop/app and sshd: exit status %d\n%s", code, out)
	}
	// A period before the release has none; one in which a host of the
	// service was not observed for an hour cannot tell.
	if code, out, _ = f.run("drift", "-until", f.end.Add(-time.Hour).Format(time.RFC3339)); code != exitComplete {
		t.Errorf("drift before the release: exit status %d\n%s", code, out)
	}
	code, out, _ = f.run("drift", "-until", f.end.Add(-9*day).Format(time.RFC3339), "-lookback", "2d", "-service", "shop/app")
	if code != exitInconclusive || !strings.Contains(out, "         - hosts that run a service were not observed for the whole period, "+
		"so what the service did there is not known: shop/app (1 of its 3 hosts: gap-01 for 1h). A host counts as observed "+
		"for 3m after a report of its agent: a longer stretch without one, as a restart of the host, is not observed\n") {
		t.Errorf("drift over the gap of gap-01: exit status %d\n%s", code, out)
	}

	code, out, _ = f.run("drift", "-json")
	var r driftReport
	if err := json.Unmarshal([]byte(out), &r); err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	if code != exitDrift || r.Verdict != verdictDrift || len(r.Drift) != 1 || r.Drift[0].Service != "shop/app" || r.Drift[0].Port != 8443 ||
		!slices.Equal(r.Drift[0].Hosts, []string{"app-01", "app-02"}) || len(r.NewServices) != 1 || r.NewServices[0].Service != "curl" ||
		r.Baseline == nil || r.Baseline.Services != 2 || !slices.Equal(r.Asked, []string{"nginx", "shop/app"}) || len(r.Reasons) != 0 {
		t.Errorf("exit status %d, report = %+v", code, r)
	}

	// The latest read of the file of the connector failed: the baseline is
	// not that of the file, which the report tells.
	f.exec(`UPDATE shawk.baseline_state SET failed_at = %s, error = 'services[0]: no dependencies'`, f.at(0))
	if code, out, _ = f.run("drift", "-service", "nginx"); code != exitComplete ||
		!strings.Contains(stable(out), "  - the latest read of a baseline_file failed: the baseline is the one read before, at TIME "+
			`("services[0]: no dependencies")`+"\n") {
		t.Errorf("drift with a baseline that is stale: exit status %d\n%s", code, out)
	}
	// A baseline of no service judges nothing: that is no answer either.
	f.approve("services: []\n")
	if code, out, _ = f.run("drift"); code != exitInconclusive || !strings.Contains(out, "         - the baseline holds no service: nothing is judged\n") {
		t.Errorf("with a baseline of no service: exit status %d\n%s", code, out)
	}
	// Approved, the drift is gone.
	f.approve(`
services:
  - service: shop/app
    dependencies:
      - {peer: shop/postgres, port: 5432, proto: tcp}
      - {peer: ~unresolved, port: 0, proto: tcp}
      - {peer: ~unresolved, port: 53, proto: udp}
      - {peer: ~external, port: 443, proto: tcp}
`)
	if code, out, _ = f.run("drift"); code != exitComplete || !strings.Contains(out, "Verdict  CLEAN: 1 service did nothing") {
		t.Errorf("after the approval: exit status %d\n%s", code, out)
	}
}

// TestPGDriftNotObserved: no drift is an answer only where every host that
// runs a service was observed. A host whose agent went silent, with every
// process it reported, still runs its services: the verdict is
// INCONCLUSIVE, and so it is for a service that no host is known to run.
func TestPGDriftNotObserved(t *testing.T) {
	f := newFleet(t)
	f.approve("services:\n  - service: nginx\n    dependencies:\n      - {peer: shop/app, port: 8080, proto: tcp}\n" +
		"  - service: batch/report\n    dependencies: []\n")
	// batch/report runs nowhere that shawk knows.
	code, out, _ := f.run("drift")
	if code != exitInconclusive || !strings.Contains(stable(out), "  - no host is known to run batch/report: no process of it was ever seen "+
		"on a host that is still known, so nothing was there to see what it did. Check its name, or take it out of the baseline\n") {
		t.Errorf("drift with a service that runs nowhere: exit status %d\n%s", code, out)
	}
	if code, out, _ = f.run("drift", "-service", "nginx"); code != exitComplete {
		t.Errorf("drift of nginx: exit status %d\n%s", code, out)
	}
	// The agent of web-01 stopped 3 hours ago: nothing was seen of it in
	// the last hour, and nothing tells what nginx did there.
	f.exec(`UPDATE shawk.agent_sessions SET last_heartbeat = %[1]s WHERE host_id = 'web-01';
	        UPDATE shawk.processes SET last_seen = %[1]s WHERE host_id = 'web-01';
	        UPDATE shawk.edges SET last_seen = %[1]s WHERE host_id = 'web-01'`, f.at(3*time.Hour))
	code, out, _ = f.run("drift", "-service", "nginx")
	if code != exitInconclusive || !strings.Contains(out, "Verdict  INCONCLUSIVE: no drift was seen, but nothing tells that there was none\n"+
		"         - hosts that run a service were not observed for the whole period, so what the service did there is not known: "+
		"nginx (1 of its 1 host: web-01 for 1h). A host counts as observed for 3m after a report of its agent") {
		t.Errorf("drift of a service whose host is silent: exit status %d\n%s", code, out)
	}
	// Past -hosts-lookback no host runs the service, and the host that ran
	// it last is the silent one: it may run there still.
	code, out, _ = f.run("drift", "-service", "nginx", "-hosts-lookback", "2h")
	if code != exitInconclusive || !strings.Contains(stable(out), "  - no process of a service was seen since TIME (-hosts-lookback), and a host "+
		"that ran it last was not observed for the whole period: the service may run there still, so what it did is not known: "+
		"nginx (1 of its 1 host that ran it last: web-01 for 1h). A host counts as observed for 3m after a report of its agent") {
		t.Errorf("drift with -hosts-lookback 2h: exit status %d\n%s", code, out)
	}
	var r driftReport
	code, out, _ = f.run("drift", "-json")
	if err := json.Unmarshal([]byte(out), &r); err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	if code != exitInconclusive || r.Verdict != verdictInconclusive || !slices.Equal(r.Reasons, []string{"not_observed", "no_host"}) ||
		len(r.NotObserved) != 2 || r.NotObserved[1].Service != "nginx" || r.NotObserved[1].UnobservedHosts != 1 ||
		!r.HostsSince.Equal(f.end.Add(-7*day)) {
		t.Errorf("exit status %d, report = %+v", code, r)
	}
}

// TestPGDriftUnit: a process of another name in the unit of a service of
// the baseline is judged as that service, and the report tells which.
func TestPGDriftUnit(t *testing.T) {
	f := newFleet(t)
	f.approve("services:\n  - service: shop/app\n    dependencies:\n      - {peer: shop/postgres, port: 5432, proto: tcp}\n" +
		"      - {peer: ~unresolved, port: 53, proto: udp}\n      - {peer: ~external, port: 443, proto: tcp}\n")
	f.exec(`INSERT INTO shawk.processes (host_id, unit, comm, exe, service_name, first_seen, last_seen) VALUES
	        ('app-01', 'app.service', 'curl', '', 'curl', %[1]s, %[2]s), ('app-01', 'app.service', 'python3', '', '~unknown', %[1]s, %[2]s)`,
		f.at(20*time.Minute), f.at(0))
	f.edge("app-01", "curl", "client", "tcp", "10.0.0.11", "203.0.113.66", 4444, 20*time.Minute, 0)
	f.edge("app-01", "~unknown", "client", "tcp", "10.0.0.11", "203.0.113.66", 4444, 20*time.Minute, 0)
	code, out, _ := f.run("drift")
	if code != exitDrift || !strings.Contains(stable(out), "shop/app  ~external  4444/tcp  app-01  address  TIME  TIME  203.0.113.66  by curl, ~unknown in its unit\n") ||
		!strings.Contains(out, "by NAME in its unit: a process of another name, without a baseline of its own, in a unit that\n") {
		t.Errorf("drift of processes in the unit of shop/app: exit status %d\n%s", code, out)
	}
	// The baseline of the service, written again, holds what they did.
	code, out, _ = f.run("baseline", "-service", "shop/app", "-min-coverage", "0.999")
	if b, err := shawkconnector.ParseBaseline([]byte(out)); code != exitComplete || err != nil ||
		!slices.Contains(b.Services[0].Dependencies, shawkconnector.BaselineDependency{Peer: "~external", Port: 4444, Proto: "tcp"}) ||
		!strings.Contains(out, "      - {peer: ~external, port: 4444, proto: tcp}  # by curl, ~unknown in its unit\n") {
		t.Errorf("baseline of shop/app: exit status %d, %v\n%s", code, err, out)
	}
}

// TestPGBaselineNotes: a dependency on a port that the kernel chose is on
// every port of its server, and says so; a process without a service name
// is in no baseline, and the file is written all the same.
func TestPGBaselineNotes(t *testing.T) {
	f := newFleet(t)
	f.exec(`INSERT INTO shawk.processes (host_id, unit, comm, exe, service_name, first_seen, last_seen)
	        VALUES ('db-01', 'rpc.service', 'rpcd', '', 'rpcd', %[1]s, %[2]s), ('web-01', 'x.service', 'x', '', '', %[1]s, %[2]s)`,
		f.at(100*day), f.at(0))
	f.exec(`INSERT INTO shawk.listener_owners (host_id, process_id, proto, addr, port, netns, first_seen, last_seen, kernel_chosen_seen)
	        SELECT 'db-01', id, 'tcp', '0.0.0.0', 40123, 1, %[1]s, %[2]s, %[2]s FROM shawk.processes WHERE service_name = 'rpcd'`,
		f.at(20*day), f.at(0))
	f.edge("web-01", "nginx", "client", "tcp", "10.0.0.12", "10.0.0.10", 40123, 20*day, 0)
	f.edge("db-01", "rpcd", "server", "tcp", "10.0.0.10", "10.0.0.12", 40123, 20*day, 0)
	f.edge("web-01", "", "client", "tcp", "10.0.0.12", "10.0.0.10", 5432, 20*day, 0)
	code, out, errOut := f.run("baseline", "-all", "-min-coverage", "0.999")
	b, err := shawkconnector.ParseBaseline([]byte(out))
	if code != exitComplete || err != nil || errOut != "" || len(b.Services) != 2 ||
		!strings.Contains(out, "      - {peer: rpcd, port: kernel-chosen, proto: tcp}  # the ports that the kernel chose for a server named rpcd "+
			"(40123 when seen), on any host, and no other port\n") ||
		!strings.Contains(out, "# A process without a service name opened connections in the period (its telemetry has no\n") {
		t.Errorf("baseline of every service: exit status %d, %v, stderr %q\n%s", code, err, errOut, out)
	}
	// The drift tells the port that the kernel chose once, whatever it is.
	f.approve("services:\n  - service: nginx\n    dependencies:\n      - {peer: shop/app, port: 8080, proto: tcp}\n")
	if code, out, _ = f.run("drift"); code != exitDrift ||
		!strings.Contains(stable(out), "nginx  rpcd  kernel-chosen/tcp  web-01  edge  TIME  TIME  10.0.0.10  the ports that the kernel chose for "+
			"a server named rpcd (40123 when seen), on any host, and no other port\n") ||
		!strings.Contains(out, "  - {peer: rpcd, port: kernel-chosen, proto: tcp}    under service nginx\n") {
		t.Errorf("drift on a port that the kernel chose: exit status %d\n%s", code, out)
	}
}

// TestPGDriftNow: without -until the period of a drift ends 5 minutes ago,
// by the clock of the database.
func TestPGDriftNow(t *testing.T) {
	f := newFleet(t)
	f.approve("services:\n  - service: nginx\n    dependencies: []\n")
	var out, errOut bytes.Buffer
	code := run(context.Background(), []string{"drift", "-dsn", f.dsn, "-json", "-lookback", "30m"}, &out, &errOut)
	var r driftReport
	if err := json.Unmarshal(out.Bytes(), &r); err != nil {
		t.Fatalf("%v\n%s\n%s", err, out.String(), errOut.String())
	}
	if ago := time.Since(r.Until); code == exitError || ago < 4*time.Minute || ago > 7*time.Minute || r.Until.Sub(r.Since) != 30*time.Minute {
		t.Errorf("exit status %d, period %s to %s", code, r.Since, r.Until)
	}
}

// TestPGNeedsTheSchema: against a database without the functions of the
// policy, as one that was not migrated, the command fails with what it
// needs, and writes nothing.
func TestPGNeedsTheSchema(t *testing.T) {
	dsn, conn := testDB(t)
	ctx := context.Background()
	for _, drop := range []string{
		`DROP FUNCTION shawk_v1.policy_verdict(text, timestamptz, timestamptz, text, numeric, interval);
		 DROP FUNCTION shawk_v1.baseline_observed(timestamptz, timestamptz, text[], text[]);
		 DROP VIEW shawk_v1.baseline_status`,
		`DROP SCHEMA shawk_v1 CASCADE`,
	} {
		if _, err := conn.Exec(ctx, drop); err != nil {
			t.Fatal(err)
		}
		for _, args := range [][]string{{"rules", "-host", "h"}, {"baseline", "-all"}, {"drift"}} {
			var out, errOut bytes.Buffer
			if code := run(ctx, append(args, "-dsn", dsn), &out, &errOut); code != exitError || out.Len() != 0 ||
				!strings.Contains(errOut.String(), "the database lacks the functions of shawk-policy: it needs the PostgreSQL schema") {
				t.Errorf("%v after %s: exit status %d, stdout %q, stderr %q", args, drop, code, out.String(), errOut.String())
			}
		}
	}
}

// TestPGOrder: what the command writes is ordered by the bytes of the
// names, so that two databases with the same contents and different
// collations (C, or the en_US.UTF-8 of the PostgreSQL image, which sorts
// capitals after small letters and skips ~ and -) give the same files and
// the same lists.
func TestPGOrder(t *testing.T) {
	f := newFleet(t)
	for _, host := range []string{"Zeta-01", "alpha-01", "-dash-01"} {
		f.exec(`INSERT INTO shawk.hosts VALUES ('%[1]s', 'm-%[1]s', '%[1]s', 'k', 'v', %[2]s, %[3]s)`, host, f.at(100*day), f.at(0))
		f.exec(`INSERT INTO shawk.agent_sessions (host_id, started_at, last_heartbeat, udp_traced, unix_traced, netns_scope, translations_traced)
		        VALUES ('%s', %s, %s, true, true, 'all', true)`, host, f.at(100*day), f.at(0))
		for _, service := range []string{"Zeta", "alpha", "~tilde"} {
			f.exec(`INSERT INTO shawk.processes (host_id, unit, comm, exe, service_name, first_seen, last_seen)
			        VALUES ('%s', '%s.service', 'c', '', '%s', %s, %s)`, host, service, service, f.at(100*day), f.at(0))
			f.edge(host, service, "client", "tcp", "10.0.0.1", "10.0.0.9", 80, 20*time.Minute, 0)
			f.edge(host, service, "client", "tcp", "10.0.0.1", "203.0.113.9", 443, 20*time.Minute, 0)
		}
	}
	f.approve("services:\n  - {service: Zeta, dependencies: []}\n  - {service: alpha, dependencies: []}\n  - {service: ~tilde, dependencies: []}\n")
	_, out, _ := f.run("drift")
	_, list, _ := strings.Cut(stable(out), "\nNot in the baseline\n")
	list, _, _ = strings.Cut(list, "To approve one")
	want := `SERVICE  PEER  PORT  HOSTS  NAMED BY  FIRST SEEN  LAST SEEN  ADDRESSES  NOTES
Zeta  ~external  443/tcp  -dash-01, Zeta-01, alpha-01  address  TIME  TIME  203.0.113.9
Zeta  ~unresolved  80/tcp  -dash-01, Zeta-01, alpha-01  address  TIME  TIME  10.0.0.9
alpha  ~external  443/tcp  -dash-01, Zeta-01, alpha-01  address  TIME  TIME  203.0.113.9
alpha  ~unresolved  80/tcp  -dash-01, Zeta-01, alpha-01  address  TIME  TIME  10.0.0.9
~tilde  ~external  443/tcp  -dash-01, Zeta-01, alpha-01  address  TIME  TIME  203.0.113.9
~tilde  ~unresolved  80/tcp  -dash-01, Zeta-01, alpha-01  address  TIME  TIME  10.0.0.9
`
	if list != want {
		t.Errorf("the drift is listed as\n%s\nwant\n%s", list, want)
	}
	_, out, _ = f.run("baseline", "-all", "-lookback", "1h")
	_, file, _ := strings.Cut(out, "\n\nservices:\n")
	wantFile := `  - service: Zeta
    dependencies:
      - {peer: ~external, port: 443, proto: tcp}
      - {peer: ~unresolved, port: 80, proto: tcp}
  - service: alpha
    dependencies:
      - {peer: ~external, port: 443, proto: tcp}
      - {peer: ~unresolved, port: 80, proto: tcp}
`
	if !strings.HasPrefix(file, wantFile) || strings.Index(out, "# Service  Zeta") > strings.Index(out, "# Service  alpha") {
		t.Errorf("the baseline is written as\n%s", out)
	}
	_, out, _ = f.run("rules", "-host", "alpha-01", "-format", "json", "-lookback", "1h")
	var r rulesReport
	if err := json.Unmarshal([]byte(out), &r); err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	if len(r.Rules) != 2 || !slices.Equal(r.Rules[0].Services, []string{"Zeta", "alpha", "~tilde"}) {
		t.Errorf("the rules of alpha-01: %+v", r.Rules)
	}
}

// TestPGBaselineAllThenDrift: what `baseline -all` writes, once approved,
// is no reason for `drift` to say that it cannot tell: a tool that ran
// once in the period, and does not run now on a host that is observed,
// did nothing. The drift is INCONCLUSIVE only when the hosts that ran it
// are not observed.
func TestPGBaselineAllThenDrift(t *testing.T) {
	f := newFleet(t)
	// curl ran once on app-01, 8 days ago, and a monthly job on db-01.
	f.exec(`INSERT INTO shawk.processes (host_id, unit, comm, exe, service_name, first_seen, last_seen)
	        VALUES ('app-01', 'app.service', 'curl', '', 'curl', %[1]s, %[2]s), ('db-01', 'cron.service', 'report', '', 'batch/monthly', %[1]s, %[2]s)`,
		f.at(9*day), f.at(8*day))
	f.edge("app-01", "curl", "client", "tcp", "10.0.0.11", "198.51.100.7", 443, 9*day, 8*day)
	f.edge("db-01", "batch/monthly", "client", "tcp", "10.0.0.10", "10.0.0.77", 25, 9*day, 8*day)
	code, file, _ := f.run("baseline", "-all", "-lookback", "30d", "-min-coverage", "0.9")
	_, yaml, _ := strings.Cut(file, "\n\nservices:\n")
	if code != exitComplete || !strings.Contains(yaml, "  - service: curl\n") || !strings.Contains(yaml, "  - service: batch/monthly\n") {
		t.Fatalf("baseline -all: exit status %d\n%s", code, file)
	}
	f.approve("services:\n" + strings.TrimSuffix(yaml[:strings.Index(yaml, "end: ")], "\n"))
	code, out, _ := f.run("drift")
	if code != exitComplete || !strings.Contains(out, "Verdict  CLEAN: 4 services did nothing") ||
		!strings.Contains(out, "         2 services of the baseline run nowhere now (batch/monthly, curl): no process of them was\n") {
		t.Errorf("drift after approving what baseline -all wrote: exit status %d\n%s", code, out)
	}
	var r driftReport
	_, out, _ = f.run("drift", "-json")
	if err := json.Unmarshal([]byte(out), &r); err != nil || r.Verdict != verdictClean || !slices.Equal(r.NotRunning, []string{"batch/monthly", "curl"}) {
		t.Errorf("as JSON: %v, %+v", err, r)
	}
	// The host that ran curl stops reporting: nothing tells what curl, and
	// shop/app, did there.
	f.exec(`UPDATE shawk.agent_sessions SET last_heartbeat = %s WHERE host_id = 'app-01'`, f.at(3*time.Hour))
	if code, out, _ = f.run("drift", "-service", "curl"); code != exitInconclusive ||
		!strings.Contains(out, "curl (1 of its 1 host that ran it last: app-01 for 1h)") {
		t.Errorf("drift of curl with its host silent: exit status %d\n%s", code, out)
	}
}

// TestPGDriftLastHostSilent: a service of the baseline that runs on a host
// whose agent has been silent for longer than -hosts-lookback has no
// process within it. It is not a service that does nothing: an earlier
// run on a host that is observed does not make the verdict CLEAN.
func TestPGDriftLastHostSilent(t *testing.T) {
	f := newFleet(t)
	f.exec(`INSERT INTO shawk.hosts VALUES ('job-01', 'm-job-01', 'job-01', 'k', 'v', %[1]s, %[2]s);
	        INSERT INTO shawk.agent_sessions (host_id, started_at, last_heartbeat, udp_traced, unix_traced, netns_scope, translations_traced)
	        VALUES ('job-01', %[1]s, %[2]s, true, true, 'all', true);
	        INSERT INTO shawk.processes (host_id, unit, comm, exe, service_name, first_seen, last_seen)
	        VALUES ('job-01', 'report.service', 'report', '', 'batch/report', %[1]s, %[2]s),
	               ('web-01', 'report.service', 'report', '', 'batch/report', %[3]s, %[4]s)`,
		f.at(100*day), f.at(8*day), f.at(200*day), f.at(199*day))
	f.approve("services:\n  - service: batch/report\n    dependencies:\n      - {peer: shop/postgres, port: 5432, proto: tcp}\n")
	code, out, _ := f.run("drift")
	if code != exitInconclusive || !strings.Contains(out, "Verdict  INCONCLUSIVE: no drift was seen, but nothing tells that there was none\n") ||
		!strings.Contains(out, "batch/report (1 of its 1 host that ran it last: job-01 for 1h)") || strings.Contains(out, "so it did nothing") {
		t.Errorf("drift of a service whose last host is silent: exit status %d\n%s", code, out)
	}
	var r driftReport
	_, out, _ = f.run("drift", "-json")
	if err := json.Unmarshal([]byte(out), &r); err != nil || r.Verdict != verdictInconclusive || len(r.NotRunning) != 0 ||
		!slices.Equal(r.Reasons, []string{"last_hosts_not_observed"}) || len(r.NotObserved) != 1 || r.NotObserved[0].IdleHosts != 1 ||
		r.NotObserved[0].UnobservedHosts != 1 || !slices.Equal(r.NotObserved[0].ShortHosts, []string{"job-01"}) {
		t.Errorf("as JSON: %v, %+v", err, r)
	}
	// The agent of the host reports again, and the service is not there:
	// it runs nowhere, and did nothing.
	f.exec(`INSERT INTO shawk.agent_sessions (host_id, started_at, last_heartbeat, udp_traced, unix_traced, netns_scope, translations_traced)
	        VALUES ('job-01', %s, %s, true, true, 'all', true)`, f.at(3*time.Hour), f.at(0))
	if code, out, _ = f.run("drift"); code != exitComplete || !strings.Contains(out, "1 service of the baseline runs nowhere now (batch/report)") {
		t.Errorf("drift once the last host is observed again: exit status %d\n%s", code, out)
	}
}

// TestPGDriftUnits: which unit judges a process without a baseline. A unit
// that unrelated processes share judges nothing, and lists what is next
// to a baseline; a unit of a workload with several services of the
// baseline tells a process once; a container under the unit is judged as
// the unit; and a service that has a baseline, deployed or in the file to
// merge with, is not mixed into the baseline of another.
func TestPGDriftUnits(t *testing.T) {
	f := newFleet(t)
	m := 20 * time.Minute
	for _, p := range [][3]string{
		{"web-01", "slurm/batch", "python3"}, {"web-01", "slurm/batch", "a.out"},
		{"web-01", "user-1000.slice/session.scope", "python3"}, {"web-01", "user-1000.slice/session.scope", "rsync"},
		{"app-01", "app.service", "envoy"}, {"app-01", "app.service", "curl"}, {"app-01", "app.service/podman-0123456789ab", "wget"},
	} {
		f.exec(`INSERT INTO shawk.processes (host_id, unit, comm, exe, service_name, first_seen, last_seen)
		        VALUES ('%s', '%s', 'c', '', '%s', %s, %s)`, p[0], p[1], p[2], f.at(30*day), f.at(0))
	}
	edge := func(host, unit, service, local, remote string, port int) {
		f.exec(`INSERT INTO shawk.edges (host_id, process_id, role, proto, local_addr, remote_addr, port, netns, first_seen, last_seen)
		        SELECT '%[1]s', id, 'client', 'tcp', '%[4]s', '%[5]s', %[6]d, 1, %[7]s, %[7]s FROM shawk.processes
		        WHERE host_id = '%[1]s' AND unit = '%[2]s' AND service_name = '%[3]s'`, host, unit, service, local, remote, port, f.at(m))
	}
	edge("web-01", "slurm/batch", "a.out", "10.0.0.12", "10.0.5.5", 27000)
	edge("web-01", "user-1000.slice/session.scope", "rsync", "10.0.0.12", "10.0.6.6", 873)
	edge("app-01", "app.service", "envoy", "10.0.0.11", "10.0.0.70", 9901)
	edge("app-01", "app.service", "curl", "10.0.0.11", "203.0.113.66", 4444)
	edge("app-01", "app.service/podman-0123456789ab", "wget", "10.0.0.11", "203.0.113.67", 80)
	deployed := "services:\n  - service: shop/app\n    dependencies:\n      - {peer: shop/postgres, port: 5432, proto: tcp}\n" +
		"      - {peer: ~unresolved, port: 53, proto: udp}\n      - {peer: ~external, port: 443, proto: tcp}\n" +
		"  - service: envoy\n    dependencies:\n      - {peer: ~unresolved, port: 9901, proto: tcp}\n" +
		"  - {service: python3, dependencies: []}\n"
	f.approve(deployed)
	code, out, _ := f.run("drift")
	want := `SERVICE  PEER  PORT  HOSTS  NAMED BY  FIRST SEEN  LAST SEEN  ADDRESSES  NOTES
envoy  ~external  80/tcp  app-01  address  TIME  TIME  203.0.113.67  by wget in its unit
envoy  ~external  4444/tcp  app-01  address  TIME  TIME  203.0.113.66  by curl in its unit
`
	_, list, _ := strings.Cut(stable(out), "\nNot in the baseline\n")
	list, _, _ = strings.Cut(list, "To approve one")
	if code != exitDrift || list != want {
		t.Errorf("drift: exit status %d; listed as\n%s\nwant\n%s\n%s", code, list, want, out)
	}
	wantNext := `UNIT  PROCESS  PEER  PORTS  HOSTS  LAST SEEN  SERVICES OF THE BASELINE IN THE UNIT
slurm/batch  a.out  ~unresolved  27000/tcp  web-01  TIME  python3
user-1000.slice/session.scope  rsync  ~unresolved  873/tcp  web-01  TIME  python3
`
	_, next, _ := strings.Cut(stable(out), "\nNext to the baseline, in units that unrelated processes share: not judged, and no drift\n")
	next, _, _ = strings.Cut(next, "The jobs of Slurm")
	if next != wantNext {
		t.Errorf("next to the baseline:\n%s\nwant\n%s", next, wantNext)
	}
	// Asked for a service of the unit, the process is told under it.
	if code, out, _ = f.run("drift", "-service", "shop/app"); code != exitDrift ||
		!strings.Contains(stable(out), "shop/app  ~external  4444/tcp  app-01  address  TIME  TIME  203.0.113.66  by curl in its unit\n") {
		t.Errorf("drift of shop/app: exit status %d\n%s", code, out)
	}
	// Written again without -merge, the baseline of shop/app holds what the
	// processes without a baseline did in its unit, and not the
	// dependencies of envoy, which the deployed baseline has as its own.
	_, out, _ = f.run("baseline", "-service", "shop/app", "-lookback", "1h")
	_, yaml, _ := strings.Cut(out, "\n\nservices:\n")
	wantFile := `  - service: shop/app
    dependencies:
      - {peer: shop/postgres, port: 5432, proto: tcp}
      - {peer: ~external, port: 80, proto: tcp}  # by wget in its unit
      - {peer: ~external, port: 4444, proto: tcp}  # by curl in its unit
      - {peer: ~unresolved, port: 53, proto: udp}
end: {services: 1, dependencies: 4}
`
	if yaml != wantFile {
		t.Errorf("the baseline of shop/app, written again:\n%s\nwant\n%s", yaml, wantFile)
	}
	// Such a file is a part of the baseline that the connector holds, and
	// says so before anything else: deployed alone it would take the
	// baseline of envoy away, and what envoy does would be a drift of
	// shop/app.
	if !strings.Contains(out, "# NOT A WHOLE BASELINE: written against the baseline that the connector holds, which has\n"+
		"# 2 services that are not in this file (envoy, python3). What a service of this file and one\n") ||
		!strings.Contains(out, "-merge FILE writes that file with these services replaced.\n") {
		t.Errorf("the file of one service, written beside a baseline of three, does not tell that it is a part:\n%s", out)
	}
	var part baselineReport
	_, js, _ := f.run("baseline", "-service", "shop/app", "-lookback", "1h", "-json")
	if err := json.Unmarshal([]byte(js), &part); err != nil || !slices.Equal(part.Outside, []string{"envoy", "python3"}) {
		t.Errorf("as JSON: %v, outside %v", err, part.Outside)
	}
	// Merged into the file of that baseline, it is whole, and says nothing
	// of the kind.
	whole := filepath.Join(t.TempDir(), "deployed.yaml")
	if err := os.WriteFile(whole, []byte(deployed+"end: {}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, out, _ = f.run("baseline", "-service", "shop/app", "-lookback", "1h", "-merge", whole); strings.Contains(out, "NOT A WHOLE BASELINE") {
		t.Errorf("the file merged with the whole baseline tells that it is a part:\n%s", out)
	}
	// A service that PostgreSQL holds no baseline of judges the processes
	// of its unit as soon as it is asked for, beside the services that
	// PostgreSQL holds: its first baseline has what they did.
	f.approve("services:\n  - service: envoy\n    dependencies:\n      - {peer: ~unresolved, port: 9901, proto: tcp}\n" +
		"  - {service: python3, dependencies: []}\n")
	_, out, _ = f.run("baseline", "-service", "shop/app", "-lookback", "1h")
	if _, yaml, _ = strings.Cut(out, "\n\nservices:\n"); yaml != wantFile {
		t.Errorf("the first baseline of shop/app, beside that of envoy:\n%s\nwant\n%s", yaml, wantFile)
	}
	// The same from the file to merge with, where PostgreSQL holds no
	// baseline yet: its services have a baseline of their own.
	f.exec(`DELETE FROM shawk.baseline_services; DELETE FROM shawk.baseline_state`)
	file := filepath.Join(t.TempDir(), "baseline.yaml")
	if err := os.WriteFile(file, []byte(deployed+"end: {}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, out, _ = f.run("baseline", "-service", "shop/app", "-lookback", "1h", "-merge", file)
	if b, err := shawkconnector.ParseBaseline([]byte(out)); err != nil || len(b.Services) != 3 ||
		slices.ContainsFunc(b.Services[2].Dependencies, func(d shawkconnector.BaselineDependency) bool { return d.Port == 9901 }) ||
		fmt.Sprint(b.Services[0]) != "{envoy [{~unresolved 9901 tcp false}]}" {
		t.Errorf("the baseline of shop/app merged with the file: %v, %+v\n%s", err, b, out)
	}
	// Without either, the other names of the unit are those of processes
	// without a baseline, and are listed with the service.
	_, out, _ = f.run("baseline", "-service", "shop/app", "-lookback", "1h")
	if !strings.Contains(out, "      - {peer: ~unresolved, port: 9901, proto: tcp}  # by envoy in its unit\n") {
		t.Errorf("the baseline of shop/app without a baseline of envoy anywhere:\n%s", out)
	}
}

// TestPGDriftReplacedHost: a host that was installed again reports under a
// new machine id: the machine of before is gone, not unobserved.
func TestPGDriftReplacedHost(t *testing.T) {
	f := newFleet(t)
	f.approve("services:\n  - service: nginx\n    dependencies:\n      - {peer: shop/app, port: 8080, proto: tcp}\n")
	f.exec(`UPDATE shawk.agent_sessions SET last_heartbeat = %[1]s WHERE host_id = 'web-01';
	        UPDATE shawk.processes SET last_seen = %[1]s WHERE host_id = 'web-01';
	        UPDATE shawk.edges SET last_seen = %[1]s WHERE host_id = 'web-01'`, f.at(2*day))
	if code, out, _ := f.run("drift"); code != exitInconclusive || !strings.Contains(out, "nginx (1 of its 1 host: web-01 for 1h)") {
		t.Errorf("drift with the host of nginx silent for 2 days: exit status %d\n%s", code, out)
	}
	f.exec(`INSERT INTO shawk.hosts VALUES ('web-01-new', 'm-new', 'web-01', 'k', 'v', %[1]s, %[2]s);
	        INSERT INTO shawk.agent_sessions (host_id, started_at, last_heartbeat, udp_traced, unix_traced, netns_scope, translations_traced)
	        VALUES ('web-01-new', %[1]s, %[2]s, true, true, 'all', true);
	        INSERT INTO shawk.processes (host_id, unit, comm, exe, service_name, first_seen, last_seen)
	        VALUES ('web-01-new', 'nginx.service', 'c', '', 'nginx', %[1]s, %[2]s)`, f.at(2*day-20*time.Minute), f.at(0))
	if code, out, _ := f.run("drift"); code != exitComplete || !strings.Contains(out, "Verdict  CLEAN: 1 service did nothing") {
		t.Errorf("drift after the host was installed again: exit status %d\n%s", code, out)
	}
}
