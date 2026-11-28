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
	f.exec(`INSERT INTO shawk.agent_sessions (host_id, started_at, last_heartbeat, udp_traced, unix_traced, netns_scope) VALUES
	        ('gap-01', %s, %s, true, true, 'all'), ('gap-01', %s, %s, true, true, 'all')`,
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
	b, err := shawkconnector.ParseBaseline([]byte(file))
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
	want := `DIRECTION  PORTS     PEER                   ADDRESSES  SERVICES  LAST SEEN  NOTES
egress     443/tcp   ~external              0.0.0.0/0  shop/app  TIME       folded peers
egress     5432/tcp  shop/postgres (db-01)  10.0.0.10  shop/app  TIME
egress     53/udp    ~unresolved            10.0.0.53  shop/app  TIME
ingress    22/tcp    ~unresolved            10.0.5.5   sshd      TIME
ingress    8080/tcp  nginx (web-01)         10.0.0.12  shop/app  TIME

Seen before the period, and in no rule
DIRECTION  PORT      PEER         ADDRESS   SERVICE   LAST SEEN
egress     9000/tcp  ~unresolved  10.0.9.9  shop/app  TIME

shawk applied nothing. -format nftables or -format systemd writes the rules, for review.
`
	if code != exitComplete || errOut != "" || rules != stable(want) ||
		!strings.Contains(out, "Target   host app-01\n") || !strings.Contains(stable(out), "Period  TIME to TIME (90d)\n") ||
		!strings.Contains(out, "Status   COMPLETE: the history tells every TCP and UDP connection of the target in the period\n"+
			"         (coverage 1; 1 is all of the period)\n") {
		t.Errorf("rules of app-01: exit status %d, stderr %q\n%s\nwant the rules:\n%s", code, errOut, out, want)
	}

	// The table of nftables allows those flows and nothing else.
	code, out, errOut = f.run("rules", "-host", "app-01", "-format", "nftables")
	wantRules := []string{"egress tcp 443-443 0.0.0.0/0", "egress tcp 5432-5432 10.0.0.10/32", "egress udp 53-53 10.0.0.53/32",
		"ingress tcp 22-22 10.0.5.5/32", "ingress tcp 8080-8080 10.0.0.12/32"}
	if got := parseNftables(t, out); code != exitComplete || errOut != "" || !slices.Equal(got, wantRules) {
		t.Errorf("nftables of app-01: exit status %d, stderr %q; it allows %v, want %v\n%s", code, errOut, got, wantRules, out)
	}
	code, out, _ = f.run("rules", "-host", "app-01", "-format", "nftables", "-ingress", "ports")
	wantRules[3], wantRules[4] = "ingress tcp 22-22 any", "ingress tcp 8080-8080 any"
	if got := parseNftables(t, out); code != exitComplete || !slices.Equal(got, wantRules) {
		t.Errorf("nftables of app-01 with -ingress ports: exit status %d; it allows %v, want %v", code, got, wantRules)
	}
	// A longer period holds the job.
	code, out, _ = f.run("rules", "-host", "app-01", "-format", "nftables", "-ingress", "none", "-lookback", "98d")
	if got := parseNftables(t, out); code != exitComplete || !slices.Contains(got, "egress tcp 9000-9000 10.0.9.9/32") || len(got) != 4 {
		t.Errorf("nftables of app-01 over 98 days: exit status %d; it allows %v", code, got)
	}

	// The drop-in of the unit of the application: sshd is another unit.
	code, out, errOut = f.run("rules", "-host", "app-01", "-unit", "app.service", "-format", "systemd")
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
	if code != exitComplete || r.Status != statusComplete || r.Coverage != 1 || len(r.Rules) != 5 || len(r.Before) != 1 || r.Refused ||
		r.Observation == nil || !r.Observation.Agent || !r.Until.Equal(f.end) || !r.Since.Equal(f.end.Add(-90*day)) ||
		r.Rules[1].Peer != "shop/postgres" || !slices.Equal(r.Rules[1].PeerHosts, []string{"db-01"}) || r.NetworkNamespaces != 1 ||
		!r.TranslationsTraced {
		t.Errorf("exit status %d, report = %+v", code, r)
	}
	// A host whose agent did not learn its translations: the rules may lack
	// the backends of what it translates itself, which the report tells.
	code, out, _ = f.run("rules", "-host", "gap-01", "-min-coverage", "0.9")
	if code != exitComplete || !strings.Contains(out, "  - the agent of the host did not learn the translations of addresses that the host makes") {
		t.Errorf("rules of a host whose agent traced no translations: exit status %d\n%s", code, out)
	}
}

// TestPGRulesIncomplete: from a history that does not tell everything, no
// rules are written unless they are asked for, and the status is never 0.
func TestPGRulesIncomplete(t *testing.T) {
	f := newFleet(t)
	for _, format := range [][]string{{"-format", "nftables"}, {"-format", "systemd", "-unit", "app.service"}} {
		args := append([]string{"-host", "gap-01"}, format...)
		code, out, errOut := f.run("rules", args...)
		if code != exitIncomplete || strings.Contains(out, "accept") || strings.Contains(out, "IPAddress") ||
			!strings.Contains(out, "Status   INCOMPLETE: the history does not tell every connection of the target in the period.\n") ||
			!strings.Contains(out, "         - not observed by an agent for 1h of the period\n") ||
			!strings.Contains(stable(out), "\nNot observed\n  TIME to TIME (1h)\n") ||
			!strings.Contains(out, "\nNo rules are written from an incomplete history.") ||
			!strings.Contains(errOut, "the history is INCOMPLETE: no rules are written") {
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
		if code != exitComplete || !strings.Contains(out, "#          Accepted with -min-coverage 0.999:\n#          - not observed by an agent for 1h of the period\n") ||
			strings.Contains(out, "# INCOMPLETE") {
			t.Errorf("%v of gap-01 with -min-coverage 0.999: exit status %d\n%s", format, code, out)
		}
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
	_, dropIn, _ := f.run("rules", "-host", "app-01", "-unit", "app.service", "-format", "systemd")
	t.Run("nft", func(t *testing.T) {
		netns := inNetns(t)
		got := listedSpans(t, loadNftables(t, netns, table))
		want := []string{"egress tcp 443-443 0.0.0.0-255.255.255.255", "egress tcp 5432-5432 10.0.0.10-10.0.0.10",
			"egress udp 53-53 10.0.0.53-10.0.0.53", "ingress tcp 22-22 10.0.5.5-10.0.5.5", "ingress tcp 8080-8080 10.0.0.12-10.0.0.12"}
		if !slices.Equal(got, want) {
			t.Errorf("the kernel allows %v, want %v", got, want)
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
#   PEER      PORT      HOSTS  NAMED BY  LAST SEEN  ADDRESSES
#   shop/app  8080/tcp  1      edge      TIME       10.0.0.11
#
# A peer is a service by its name, as its agent or its listener tells it, a range of peer_cidrs,
# ~unresolved (a private address that shawk cannot name) or ~external (a public address, or peers
# whose addresses the agent folded). Port 0 stands for every port. A dependency that was not used
# in the period is not listed: one used less often than the period, or only when another server
# fails. Dependencies over Unix sockets are not part of a baseline.

services:
  - service: nginx
    dependencies:
      - {peer: shop/app, port: 8080, proto: tcp}
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
		fmt.Sprint(b.Services[1]) != "{shop/app [{shop/postgres 5432 tcp} {~external 443 tcp} {~unresolved 53 udp}]}" {
		t.Errorf("baseline of shop/app with -allow-incomplete: exit status %d, %v, %+v\n%s", code, err, b, out)
	}
	code, out, _ = f.run("baseline", "-service", "shop/app", "-min-coverage", "0.999")
	if b, err = shawkconnector.ParseBaseline([]byte(out)); code != exitComplete || err != nil || len(b.Services) != 1 ||
		!strings.Contains(out, "#          Accepted with -min-coverage 0.999:\n#          - not observed by an agent\n") {
		t.Errorf("baseline of shop/app with -min-coverage 0.999: exit status %d, %v\n%s", code, err, out)
	}

	// Every service that opened connections; those that only accept are in
	// no baseline.
	code, out, _ = f.run("baseline", "-all", "-min-coverage", "0.999")
	if b, err = shawkconnector.ParseBaseline([]byte(out)); code != exitComplete || err != nil || len(b.Services) != 2 ||
		b.Services[0].Service != "nginx" || b.Services[1].Service != "shop/app" {
		t.Errorf("baseline of every service: exit status %d, %v, %+v", code, err, b)
	}

	// A service that no process had is never written: a name mistyped
	// would approve nothing, and a file of no service drops every baseline.
	code, out, _ = f.run("baseline", "-service", "ngimx", "-allow-incomplete")
	if code != exitIncomplete || strings.Contains(out, "services:") || !strings.Contains(out, "Service  ngimx\nStatus   INCOMPLETE: not written\n"+
		"         - no process had this service in the period: check the name\n") ||
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
`), 0o600); err != nil {
		t.Fatal(err)
	}
	code, out, _ = f.run("baseline", "-service", "nginx", "-merge", file)
	b, err = shawkconnector.ParseBaseline([]byte(out))
	if code != exitComplete || err != nil || len(b.Services) != 3 || fmt.Sprint(b.Services) !=
		"[{batch/report []} {ngimx [{kept 1 udp}]} {nginx [{shop/app 8080 tcp}]}]" ||
		!strings.Contains(out, "# Merged   with "+file+", of which 2 other services are kept as they are\n") {
		t.Errorf("merged baseline: exit status %d, %v, %+v\n%s", code, err, b, out)
	}
	code, out, _ = f.run("baseline", "-service", "nginx", "-service", "ngimx", "-merge", file, "-allow-incomplete")
	if b, err = shawkconnector.ParseBaseline([]byte(out)); code != exitIncomplete || err != nil || fmt.Sprint(b.Services) !=
		"[{batch/report []} {ngimx [{kept 1 udp}]} {nginx [{shop/app 8080 tcp}]}]" {
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
		"Verdict  CLEAN: 2 services did nothing over TCP or UDP that the baseline does not hold\n") || strings.Contains(out, "Not in the baseline") {
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
SERVICE   PEER         PORT      HOSTS           NAMED BY  FIRST SEEN  LAST SEEN  ADDRESSES
shop/app  ~unresolved  8443/tcp  app-01, app-02  address   TIME        TIME       10.0.7.7
To approve one, add it to the baseline file of the connector, as
  - {peer: ~unresolved, port: 8443, proto: tcp}    under service shop/app
or write the service again: shawk-policy baseline -service NAME -merge FILE.
~unresolved: a private address that shawk cannot name. It may be a server whose agent is
stopped and whose listener is not known, or one without an agent: see the addresses.

New services without a baseline, which nothing judges
SERVICE  FIRST SEEN  HOSTS
curl     TIME        app-01
A new executable, or a process that names itself anew, is a service of its own: the baseline
of the service it runs in does not judge it.

Only TCP and UDP are judged, by the name of the server and its port: a server of the same name
at another address is no drift, and ~external does not tell one public address from another.
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
	if code != exitInconclusive || !strings.Contains(out, "         - hosts were not observed for the whole period, so what their services "+
		"did then is not known: shop/app (gap-01)\n") {
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
		 DROP FUNCTION shawk_v1.baseline_observed(timestamptz, timestamptz, text[]);
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
