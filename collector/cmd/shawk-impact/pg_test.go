package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
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
	name := fmt.Sprintf("shawk_impact_test_%d", time.Now().UnixNano())
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

// The period of the tests: the 90 days before testUntil.
var testUntil = time.Date(2026, 10, 30, 0, 0, 0, 0, time.UTC)

// fleet writes a small fleet over the period of the tests: app-01 uses the
// postgres of db-01 all along, billing of batch-01 on the first of each
// month, and web-01 uses app-01. idle-01 is used by nothing; gap-01 neither,
// but was not observed for an hour.
const fleet = `
INSERT INTO shawk.hosts
SELECT h, 'm', h, 'k', 'v', '2026-07-01T00:00:00Z', '2026-10-30T00:00:00Z'
FROM unnest(ARRAY['db-01', 'app-01', 'web-01', 'batch-01', 'idle-01', 'gap-01']) h;
INSERT INTO shawk.agent_sessions (host_id, started_at, last_heartbeat, udp_traced, unix_traced, netns_scope)
SELECT id, '2026-07-01T00:00:00Z', '2026-10-30T00:00:00Z', true, true, 'all' FROM shawk.hosts WHERE id <> 'gap-01';
INSERT INTO shawk.agent_sessions (host_id, started_at, last_heartbeat, udp_traced, unix_traced, netns_scope) VALUES
  ('gap-01', '2026-07-01T00:00:00Z', '2026-09-01T00:00:00Z', true, true, 'all'),
  ('gap-01', '2026-09-01T01:03:00Z', '2026-10-30T00:00:00Z', true, true, 'all');
INSERT INTO shawk.host_addrs VALUES
  ('db-01', '10.0.0.10', '2026-07-01T00:00:00Z', '2026-10-30T00:00:00Z'),
  ('app-01', '10.0.0.11', '2026-07-01T00:00:00Z', '2026-10-30T00:00:00Z'),
  ('web-01', '10.0.0.12', '2026-07-01T00:00:00Z', '2026-10-30T00:00:00Z'),
  ('batch-01', '10.0.0.13', '2026-07-01T00:00:00Z', '2026-10-30T00:00:00Z');
INSERT INTO shawk.processes (host_id, unit, comm, exe, service_name, first_seen, last_seen) VALUES
  ('db-01', 'postgresql.service', 'postgres', '', 'postgres', '2026-07-01T00:00:00Z', '2026-10-30T00:00:00Z'),
  ('app-01', 'app.service', 'puma', '', 'shop/app', '2026-07-01T00:00:00Z', '2026-10-30T00:00:00Z'),
  ('web-01', 'nginx.service', 'nginx', '', 'nginx', '2026-07-01T00:00:00Z', '2026-10-30T00:00:00Z'),
  ('batch-01', 'billing.service', 'billing', '', 'billing', '2026-07-01T00:00:00Z', '2026-10-30T00:00:00Z');
INSERT INTO shawk.edges (host_id, process_id, role, proto, local_addr, remote_addr, port, netns, first_seen, last_seen)
SELECT e.host, p.id, e.role, 'tcp', e.local::inet, e.remote::inet, e.port, 1, e.first::timestamptz, e.last::timestamptz
FROM (VALUES
  ('app-01', 'client', '10.0.0.11', '10.0.0.10', 5432, '2026-08-01T00:00:00Z', '2026-10-30T00:00:00Z'),
  ('db-01', 'server', '10.0.0.10', '10.0.0.11', 5432, '2026-08-01T00:00:00Z', '2026-10-30T00:00:00Z'),
  ('web-01', 'client', '10.0.0.12', '10.0.0.11', 8080, '2026-08-01T00:00:00Z', '2026-10-30T00:00:00Z'),
  ('app-01', 'server', '10.0.0.11', '10.0.0.12', 8080, '2026-08-01T00:00:00Z', '2026-10-30T00:00:00Z'),
  ('batch-01', 'client', '10.0.0.13', '10.0.0.10', 5432, '2026-08-01T01:00:00Z', '2026-10-01T03:00:00Z'),
  ('db-01', 'server', '10.0.0.10', '10.0.0.13', 5432, '2026-08-01T01:00:00Z', '2026-10-01T03:00:00Z')
) AS e(host, role, local, remote, port, first, last)
JOIN shawk.processes p ON p.host_id = e.host;
-- Every hour for app and web, and two hours on the first of each month for
-- billing.
INSERT INTO shawk.edge_activity
SELECT e.id, m, CASE WHEN e.host_id = 'batch-01' OR e.remote_addr = '10.0.0.13'
                     THEN ('011' || repeat('0', 741))::bit(744) ELSE repeat('1', 744)::bit(744) END
FROM shawk.edges e, unnest(ARRAY['2026-08-01T00:00:00Z', '2026-09-01T00:00:00Z', '2026-10-01T00:00:00Z']::timestamptz[]) m;
`

// reader is a role that reads the contract only, as Grafana does.
const reader = `
DO $$ BEGIN
  IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'shawk_impact_reader') THEN CREATE ROLE shawk_impact_reader NOLOGIN; END IF;
END $$;
GRANT USAGE ON SCHEMA shawk_v1 TO shawk_impact_reader;
GRANT SELECT ON ALL TABLES IN SCHEMA shawk_v1 TO shawk_impact_reader;
`

// impact runs the command over the period of the tests as the role that
// reads the contract only, and returns its exit status and output.
func impact(t *testing.T, dsn string, args ...string) (int, string) {
	t.Helper()
	var out, errOut bytes.Buffer
	args = append([]string{"-dsn", dsn + "?options=-c%20role%3Dshawk_impact_reader", "-until", testUntil.Format(time.RFC3339)}, args...)
	code := run(context.Background(), args, &out, &errOut)
	if errOut.Len() > 0 {
		t.Logf("stderr: %s", errOut.String())
	}
	return code, out.String()
}

// TestPGReport: the command reads the verdict, the dependents and the
// coverage of a target as a role that reads the contract only, and its
// exit status tells the verdict.
func TestPGReport(t *testing.T) {
	dsn, conn := testDB(t)
	ctx := context.Background()
	for _, q := range []string{fleet, reader} {
		if _, err := conn.Exec(ctx, q); err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(func() { conn.Exec(ctx, "DROP OWNED BY shawk_impact_reader") })

	code, out := impact(t, dsn, "-host", "db-01")
	want := `Target   db-01
Period   2026-08-01T00:00:00Z to 2026-10-30T00:00:00Z (90d)

Verdict  UNSAFE: active dependents
         2 dependents used it in the period, and 1 more depends on them (to depth 3)

Dependents
DEPTH  CLIENT            SERVER           PORT      SEEN BY  CADENCE     LAST SEEN             NEXT ACTIVITY
1      app-01 shop/app   db-01 postgres   5432/tcp  both     continuous  2026-10-30T00:00:00Z  now
1      batch-01 billing  db-01 postgres   5432/tcp  both     monthly     2026-10-01T03:00:00Z  about 2026-10-31T01:00:00Z
2      web-01 nginx      app-01 shop/app  8080/tcp  both     continuous  2026-10-30T00:00:00Z  now

Observation of the hosts that tell
HOST   ROLE    OBSERVED  NOT OBSERVED  GAPS  DROPPED FLOWS  NO UDP  NO UNIX  ONE NETNS
db-01  target  100%      0s            0     0s             0s      0s       0s
and 3 clients observed all along

Only TCP, UDP and Unix stream sockets are observed: a host used over RDMA, or by a
host without an agent through a relay, may look unused (docs/design.md, sections 6.3 and 10).
`
	if code != exitUnsafe || out != want {
		t.Errorf("db-01: exit status %d, want %d\n%s\nwant:\n%s", code, exitUnsafe, out, want)
	}

	// The clients of the target only, of the service on its port.
	code, out = impact(t, dsn, "-host", "db-01", "-service", "postgres", "-port", "5432", "-proto", "tcp", "-depth", "1", "-limit", "1")
	if code != exitUnsafe || !strings.Contains(out, "Target   db-01 (service postgres, port 5432, tcp)\n") ||
		!strings.Contains(out, "2 dependents used it in the period\n") || !strings.Contains(out, "and 1 more row (-limit 0 shows all)\n") ||
		strings.Contains(out, "web-01") {
		t.Errorf("postgres on db-01: exit status %d\n%s", code, out)
	}

	code, out = impact(t, dsn, "-host", "idle-01")
	if code != exitSafe || !strings.Contains(out, "Verdict  SAFE\n         nothing used it in the period, and it was watched for 100% of it\n") {
		t.Errorf("idle-01: exit status %d, want %d\n%s", code, exitSafe, out)
	}

	// An hour without an agent: inconclusive, unless the caller accepts it.
	code, out = impact(t, dsn, "-host", "gap-01")
	if code != exitInconclusive || !strings.Contains(out, "Verdict  INCONCLUSIVE: insufficient observation coverage\n") ||
		!strings.Contains(out, "         - not observed for 1h of the period, in 1 gap\n") ||
		!strings.Contains(out, "Not observed\n  2026-09-01T00:03:00Z to 2026-09-01T01:03:00Z (1h)\n") ||
		!strings.Contains(out, "gap-01  target  99.9537%  1h") {
		t.Errorf("gap-01: exit status %d, want %d\n%s", code, exitInconclusive, out)
	}
	code, out = impact(t, dsn, "-host", "gap-01", "-min-coverage", "99.9")
	if code != exitSafe || !strings.Contains(out, "watched for 99.9537% of it\n         Accepted with a coverage of 99.9% at least:\n") {
		t.Errorf("gap-01 with -min-coverage 99.9: exit status %d, want %d\n%s", code, exitSafe, out)
	}
	if code, out = impact(t, dsn, "-host", "gap-01", "-min-coverage", "99.96"); code != exitInconclusive {
		t.Errorf("gap-01 with -min-coverage 99.96: exit status %d, want %d\n%s", code, exitInconclusive, out)
	}

	// A name that nothing knows is never safe.
	code, out = impact(t, dsn, "-host", "db-O1")
	if code != exitInconclusive || !strings.Contains(out, "no agent ever reported as db-O1, and the inventory has no such host: check the name") {
		t.Errorf("db-O1: exit status %d, want %d\n%s", code, exitInconclusive, out)
	}
	// A period before the agents: nothing was watched then.
	if code, out = impact(t, dsn, "-host", "idle-01", "-lookback", "52w"); code != exitInconclusive {
		t.Errorf("idle-01 over a year: exit status %d, want %d\n%s", code, exitInconclusive, out)
	}

	code, out = impact(t, dsn, "-host", "db-01", "-json")
	var r report
	if err := json.Unmarshal([]byte(out), &r); err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	if code != exitUnsafe || r.Verdict != verdictUnsafe || r.Direct != 2 || r.Transitive != 1 || len(r.Dependents) != 3 ||
		r.Coverage != 1 || len(r.Observers) != 4 || r.Observers[0].Host != "db-01" || r.Observers[0].Role != "target" ||
		!r.Until.Equal(testUntil) || !r.Since.Equal(testUntil.Add(-90*24*time.Hour)) {
		t.Errorf("exit status %d, report = %+v", code, r)
	}
	if d := r.Dependents[1]; d.Cadence != "monthly" || d.PeriodSeconds == nil || *d.PeriodSeconds != 30*86400 || d.Runs != 3 ||
		d.NextExpected == nil || !d.NextExpected.Equal(time.Date(2026, 10, 31, 1, 0, 0, 0, time.UTC)) {
		t.Errorf("the dependency of billing = %+v", d)
	}

	// The command writes nothing and reads the contract only.
	if _, err := conn.Exec(ctx, "REVOKE USAGE ON SCHEMA shawk_v1 FROM shawk_impact_reader"); err != nil {
		t.Fatal(err)
	}
	if code, out = impact(t, dsn, "-host", "db-01"); code != exitError || out != "" {
		t.Errorf("without access to shawk_v1: exit status %d, want %d\n%s", code, exitError, out)
	}
}

// TestPGReportNow: without -until the period ends now, by the clock of the
// database, and the connection string may be in a file.
func TestPGReportNow(t *testing.T) {
	dsn, conn := testDB(t)
	ctx := context.Background()
	if _, err := conn.Exec(ctx, `
INSERT INTO shawk.hosts VALUES ('h', 'm', 'idle-01', 'k', 'v', now() - interval '2 days', now());
INSERT INTO shawk.agent_sessions (host_id, started_at, last_heartbeat, udp_traced, unix_traced, netns_scope)
VALUES ('h', now() - interval '2 days', now(), true, true, 'all')`); err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(t.TempDir(), "dsn")
	if err := os.WriteFile(file, []byte(dsn+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	var out, errOut bytes.Buffer
	if code := run(ctx, []string{"-dsn-file", file, "-host", "idle-01", "-lookback", "1d", "-json"}, &out, &errOut); code != exitSafe {
		t.Fatalf("exit status %d, want %d: %s", code, exitSafe, errOut.String())
	}
	var r report
	if err := json.Unmarshal(out.Bytes(), &r); err != nil {
		t.Fatal(err)
	}
	if r.Verdict != verdictSafe || r.Until.Sub(r.Since) != 24*time.Hour || time.Since(r.Until) > time.Minute || time.Until(r.Until) > time.Minute {
		t.Errorf("report = %+v", r)
	}
	// A period that reaches before the agent started is not watched in full.
	out.Reset()
	if code := run(ctx, []string{"-dsn", dsn, "-host", "idle-01", "-lookback", "3d"}, &out, &errOut); code != exitInconclusive {
		t.Errorf("over 3 days: exit status %d, want %d\n%s", code, exitInconclusive, out.String())
	}
	if code := run(ctx, []string{"-dsn-file", filepath.Join(t.TempDir(), "none"), "-host", "idle-01"}, &out, &errOut); code != exitError {
		t.Errorf("without the file of the connection string: exit status %d, want %d", code, exitError)
	}
}
