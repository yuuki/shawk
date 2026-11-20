package shawkconnector

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
)

// The period of the tests of the impact: 90 days, at fixed times, so that
// the hours of activity do not depend on when the tests run.
var (
	impactSince = time.Date(2026, 8, 1, 0, 0, 0, 0, time.UTC)
	impactUntil = impactSince.Add(90 * 24 * time.Hour)
)

// ts formats a time as a timestamptz of SQL.
func ts(t time.Time) string { return "'" + t.UTC().Format(time.RFC3339) + "'::timestamptz" }

// day returns the time d days and h hours into the period of the tests.
func day(d, h int) time.Time {
	return impactSince.Add(time.Duration(d)*24*time.Hour + time.Duration(h)*time.Hour)
}

// span is a stretch of time.
type timeSpan struct{ from, to time.Time }

// multirange formats stretches of time as a multirange of SQL.
func multirange(spans ...timeSpan) string {
	ranges := make([]string, len(spans))
	for i, s := range spans {
		ranges[i] = fmt.Sprintf("[%s,%s)", s.from.Format(time.RFC3339), s.to.Format(time.RFC3339))
	}
	return "'{" + strings.Join(ranges, ",") + "}'::tstzmultirange"
}

// every returns runs of length hours that start every step from from,
// until until.
func every(from, until time.Time, step time.Duration, length int) []timeSpan {
	var out []timeSpan
	for t := from; t.Before(until); t = t.Add(step) {
		end := t.Add(time.Duration(length) * time.Hour)
		if end.After(until) {
			end = until
		}
		out = append(out, timeSpan{t, end})
	}
	return out
}

// at returns runs of length hours that start at the times.
func at(length int, starts ...time.Time) []timeSpan {
	out := make([]timeSpan, len(starts))
	for i, t := range starts {
		out[i] = timeSpan{t, t.Add(time.Duration(length) * time.Hour)}
	}
	return out
}

// TestPGCadence: the cadence of a dependency from the hours it was active
// in, the time in which it was not observed, and the end of the period.
func TestPGCadence(t *testing.T) {
	_, conn := migratedDB(t)
	until := impactUntil
	whole := timeSpan{impactSince, until}
	var weekdays []time.Time
	for d := range 90 {
		if wd := day(d, 0).Weekday(); wd != time.Saturday && wd != time.Sunday {
			weekdays = append(weekdays, day(d, 2))
		}
	}
	for _, c := range []struct {
		name          string
		active, blind []timeSpan
		want          string // cadence, period, next_expected, runs
	}{
		{"no hour recorded", nil, nil, "unknown <nil> <nil> 0"},
		{"active all along", []timeSpan{whole}, nil, "continuous <nil> <nil> 1"},
		// A job of every hour is active in every hour: hours do not tell
		// it from a connection that stays open.
		{"every hour", every(impactSince, until, time.Hour, 1), nil, "continuous <nil> <nil> 1"},
		// Active 23 hours a day: a duty of 0.96.
		{"a pause of an hour every night", every(impactSince, until, 24*time.Hour, 23), nil, "continuous <nil> <nil> 90"},
		{"every 6 hours", every(impactSince, until, 6*time.Hour, 1), nil,
			"periodic 06:00:00 " + until.Format(time.RFC3339) + " 360"},
		{"every day at 2", every(day(0, 2), until, 24*time.Hour, 1), nil,
			"daily 1 day " + day(90, 2).Format(time.RFC3339) + " 90"},
		// 8 hours of every day: a daily batch, not continuous.
		{"working hours", every(day(0, 9), until, 24*time.Hour, 8), nil,
			"daily 1 day " + day(90, 9).Format(time.RFC3339) + " 90"},
		// No run at the weekend: a fifth of the intervals are of 3 days.
		{"every weekday", at(1, weekdays...), nil, "daily 1 day " + day(90, 2).Format(time.RFC3339) + " 64"},
		{"every week", every(day(2, 3), until, 7*24*time.Hour, 2), nil,
			"weekly 7 days " + day(93, 3).Format(time.RFC3339) + " 13"},
		// The first of each month: intervals of 31 and 30 days.
		{"every month", at(3, day(0, 0), day(31, 0), day(61, 0)), nil,
			"monthly 30 days " + day(91, 0).Format(time.RFC3339) + " 3"},
		{"every 10 days", every(day(1, 0), until, 10*24*time.Hour, 1), nil,
			"periodic 10 days " + day(91, 0).Format(time.RFC3339) + " 9"},
		{"once, for 3 hours", at(3, day(40, 0)), nil, "one-off <nil> <nil> 1"},
		{"all along until a month ago", []timeSpan{{impactSince, day(60, 0)}}, nil, "dormant <nil> <nil> 1"},
		{"every day until a month ago", every(day(0, 2), day(60, 0), 24*time.Hour, 1), nil, "dormant <nil> <nil> 60"},
		// A daily job is dormant after two days without a run, not before.
		{"every day until yesterday", every(day(0, 2), day(89, 0), 24*time.Hour, 1), nil,
			"daily 1 day " + day(89, 2).Format(time.RFC3339) + " 89"},
		{"every day until 3 days ago", every(day(0, 2), day(87, 0), 24*time.Hour, 1), nil, "dormant <nil> <nil> 87"},
		// The run of a month is missing, and those left are too few.
		{"twice, a month apart", at(3, day(31, 0), day(61, 0)), nil, "unknown <nil> <nil> 2"},
		{"since 5 hours", []timeSpan{{until.Add(-5 * time.Hour), until}}, nil, "unknown <nil> <nil> 1"},
		{"at odd times", at(2, day(3, 0), day(5, 7), day(40, 1), day(41, 13), day(70, 4), day(85, 0)), nil,
			"irregular <nil> <nil> 6"},
		// Runs of a month with an hour between them are no monthly job.
		{"long runs", []timeSpan{{day(0, 0), day(30, 0)}, {day(30, 1), day(60, 0)}, {day(60, 1), day(89, 12)}}, nil,
			"irregular <nil> <nil> 3"},
		// The host was not observed for two days: the dependency may have
		// been active, so the run goes on.
		{"all along, not observed for two days", []timeSpan{{impactSince, day(40, 0)}, {day(42, 0), until}},
			[]timeSpan{{day(40, 0), day(42, 0)}}, "continuous <nil> <nil> 1"},
		// An hour observed in part tells nothing either.
		{"all along, not observed for two days less minutes", []timeSpan{{impactSince, day(40, 0)}, {day(42, 0), until}},
			[]timeSpan{{day(40, 0).Add(3 * time.Minute), day(42, 0).Add(-20 * time.Minute)}}, "continuous <nil> <nil> 1"},
		// Observed and idle for those two days: two runs, and still active
		// 98% of the time.
		{"all along but for two days", []timeSpan{{impactSince, day(40, 0)}, {day(42, 0), until}}, nil,
			"continuous <nil> <nil> 2"},
		// The agent stopped 10 days ago: the job is not known to have
		// stopped, and its next run was expected then.
		{"every day, not observed since 10 days", every(day(0, 2), day(80, 0), 24*time.Hour, 1),
			[]timeSpan{{day(79, 3), until}}, "daily 1 day " + day(80, 2).Format(time.RFC3339) + " 80"},
		// Active in the 3 hours observed, and maybe all along in between:
		// one run, of which a day was not observed.
		{"observed for 3 hours", []timeSpan{{day(1, 0), day(1, 2)}, {until.Add(-time.Hour), until}},
			[]timeSpan{{day(1, 2), until.Add(-time.Hour)}}, "unknown <nil> <nil> 1"},
		// Active in 2 of the 3 hours observed: two runs.
		{"observed for 3 hours, idle for one", at(1, day(1, 0), until.Add(-time.Hour)),
			[]timeSpan{{day(1, 2), until.Add(-time.Hour)}}, "unknown <nil> <nil> 2"},
	} {
		t.Run(c.name, func(t *testing.T) {
			got := queryStrings(t, conn, fmt.Sprintf(`
SELECT cadence, period::text, to_char(next_expected AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"'), runs
FROM shawk.cadence(%s, %s, %s)`, multirange(c.active...), multirange(c.blind...), ts(until)))
			if len(got) != 1 || got[0] != c.want {
				t.Errorf("cadence = %v, want %s", got, c.want)
			}
		})
	}
}

// TestPGActivityRanges: the hours of a month of activity as ranges are the
// hours of its bits, whatever the bits.
func TestPGActivityRanges(t *testing.T) {
	_, conn := migratedDB(t)
	// 300 months whose bits are set with a probability from 0 to 1, in a
	// session of a time zone half an hour off UTC.
	execAll(t, conn, `SET timezone = 'Asia/Kolkata'`, `SELECT setseed(0.231)`)
	got := queryStrings(t, conn, `
WITH q AS (SELECT g, random() AS p FROM generate_series(1, 300) g),
x AS (
  SELECT q.g, string_agg(CASE WHEN random() < q.p THEN '1' ELSE '0' END, '')::bit(744) AS hours
  FROM q, generate_series(1, 744) GROUP BY q.g
),
y AS (
  SELECT x.hours,
         (SELECT coalesce(range_agg(r), '{}') FROM shawk.activity_ranges('2026-10-01T00:00:00Z', x.hours) r) AS ranges,
         (SELECT coalesce(range_agg(tstzrange('2026-10-01T00:00:00Z'::timestamptz + i * interval '1 hour',
                                              '2026-10-01T00:00:00Z'::timestamptz + (i + 1) * interval '1 hour')), '{}')
          FROM generate_series(0, 743) i WHERE get_bit(x.hours, i) = 1) AS hourly
  FROM x
)
SELECT count(*), count(*) FILTER (WHERE ranges = hourly), min(bit_count(hours)) < 20, max(bit_count(hours)) > 720 FROM y`)
	if !slices.Equal(got, []string{"300 300 true true"}) {
		t.Errorf("months, months whose ranges are their hours, with few bits, with most bits = %v", got)
	}
	execAll(t, conn, `SET timezone = 'UTC'`)
	for _, c := range []struct{ name, hours, want string }{
		{"no hour", "repeat('0', 744)", `{}`},
		{"every hour", "repeat('1', 744)", `{["2026-10-01 00:00:00+00","2026-11-01 00:00:00+00")}`},
		{"the first hour", "'1' || repeat('0', 743)", `{["2026-10-01 00:00:00+00","2026-10-01 01:00:00+00")}`},
		{"the last hour", "repeat('0', 743) || '1'", `{["2026-10-31 23:00:00+00","2026-11-01 00:00:00+00")}`},
		{"the first and the last hour", "'1' || repeat('0', 742) || '1'",
			`{["2026-10-01 00:00:00+00","2026-10-01 01:00:00+00"),["2026-10-31 23:00:00+00","2026-11-01 00:00:00+00")}`},
	} {
		got := queryStrings(t, conn, `SELECT coalesce(range_agg(r), '{}')::text
			FROM shawk.activity_ranges('2026-10-01T00:00:00Z', (`+c.hours+`)::bit(744)) r`)
		if !slices.Equal(got, []string{c.want}) {
			t.Errorf("%s: %v, want %s", c.name, got, c.want)
		}
	}
}

// impactFixture writes the rows of the schema that the impact reads, at
// fixed times.
type impactFixture struct {
	t    *testing.T
	conn *pgx.Conn
}

func (f impactFixture) exec(sql string, args ...any) {
	f.t.Helper()
	if _, err := f.conn.Exec(context.Background(), sql, args...); err != nil {
		f.t.Fatalf("%s: %v", sql, err)
	}
}

// host adds a host that holds an address over the period of the tests and
// before, with a process per service, and no session.
func (f impactFixture) host(name, addr string, services ...string) {
	f.t.Helper()
	f.exec(`INSERT INTO shawk.hosts VALUES ($1, 'm', $1, 'k', 'v', $2, $3)`, name, impactSince.Add(-24*time.Hour), impactUntil)
	if addr != "" {
		f.exec(`INSERT INTO shawk.host_addrs VALUES ($1, $2, $3, $4)`, name, addr, impactSince.Add(-24*time.Hour), impactUntil)
	}
	for _, svc := range services {
		f.exec(`INSERT INTO shawk.processes (host_id, unit, comm, exe, service_name, first_seen, last_seen)
			VALUES ($1, $2 || '.service', $2, '', $2, $3, $4)`, name, svc, impactSince.Add(-24*time.Hour), impactUntil)
	}
}

// observed adds a session of the agent of a host, which traces everything.
func (f impactFixture) observed(host string, from, to time.Time) {
	f.t.Helper()
	f.exec(`INSERT INTO shawk.agent_sessions (host_id, started_at, last_heartbeat, udp_traced, unix_traced, netns_scope)
		VALUES ($1, $2, $3, true, true, 'all')`, host, from, to)
}

// watched adds a host observed over the whole period of the tests.
func (f impactFixture) watched(name, addr string, services ...string) {
	f.t.Helper()
	f.host(name, addr, services...)
	f.observed(name, impactSince.Add(-time.Hour), impactUntil)
}

// listener adds a listener of the process of svc on host on a TCP port,
// seen over the period of the tests.
func (f impactFixture) listener(host, svc string, port int) {
	f.t.Helper()
	f.exec(`INSERT INTO shawk.listeners (host_id, process_id, proto, addr, port, netns, first_seen, last_seen)
		VALUES ($1, (SELECT id FROM shawk.processes WHERE host_id = $1 AND service_name = $2), 'tcp', '0.0.0.0', $3, 1, $4, $5)`,
		host, svc, port, impactSince, impactUntil)
}

// edge adds an edge of the process of svc on host, without activity.
func (f impactFixture) edge(host, svc, role, local, remote string, port int, first, last time.Time) {
	f.t.Helper()
	f.exec(`INSERT INTO shawk.edges (host_id, process_id, role, proto, local_addr, remote_addr, port, netns, first_seen, last_seen)
		VALUES ($1, (SELECT id FROM shawk.processes WHERE host_id = $1 AND service_name = $2), $3, 'tcp', $4, $5, $6, 1, $7, $8)`,
		host, svc, role, local, remote, port, first, last)
}

// active marks the hours of runs of length hours of the edges of svc on
// host on a port, every step from from until until.
func (f impactFixture) active(host, svc string, port int, from, until time.Time, step time.Duration, length int) {
	f.t.Helper()
	f.activeWith(host, svc, port, "", from, until, step, length)
}

// activeWith is active for the edges with a peer only, all if empty.
func (f impactFixture) activeWith(host, svc string, port int, peer string, from, until time.Time, step time.Duration, length int) {
	f.t.Helper()
	f.exec(`
INSERT INTO shawk.edge_activity AS a (edge_id, month, hours)
SELECT e.id, m.month, bit_or(set_bit(repeat('0', 744)::bit(744), floor(extract(epoch FROM h.t - m.month) / 3600)::int, 1))
FROM shawk.edges e
JOIN shawk.processes p ON p.id = e.process_id
CROSS JOIN generate_series($4::timestamptz, $5::timestamptz - interval '1 second', make_interval(secs => $6)) AS s(t)
CROSS JOIN generate_series(0, $7 - 1) AS n
CROSS JOIN LATERAL (SELECT s.t + n * interval '1 hour' AS t) h
CROSS JOIN LATERAL (SELECT date_trunc('month', h.t, 'UTC') AS month) m
WHERE e.host_id = $1 AND p.service_name = $2 AND e.port = $3 AND h.t < $5 AND ($8 = '' OR e.remote_addr = $8::inet)
GROUP BY e.id, m.month
ON CONFLICT (edge_id, month) DO UPDATE SET hours = a.hours | excluded.hours`,
		host, svc, port, from, until, step.Seconds(), length, peer)
}

// both adds both sides of a connection from client to server, active all
// along from first to last.
func (f impactFixture) both(clientHost, clientSvc, clientAddr, serverHost, serverSvc, serverAddr string, port int, first, last time.Time) {
	f.t.Helper()
	f.edge(clientHost, clientSvc, "client", clientAddr, serverAddr, port, first, last)
	f.edge(serverHost, serverSvc, "server", serverAddr, clientAddr, port, first, last)
	f.active(clientHost, clientSvc, port, first, last, time.Hour, 1)
	f.active(serverHost, serverSvc, port, first, last, time.Hour, 1)
}

// impact returns the dependents of a target over the period of the tests:
// "depth client_host client_service client_addr -> server_host
// server_service port observed_by cadence".
func (f impactFixture) impact(target string) []string {
	f.t.Helper()
	rows, err := f.conn.Query(context.Background(), fmt.Sprintf(`
SELECT depth || ' ' || coalesce(client_host, '-') || ' ' || client_service || ' ' || coalesce(host(client_addr), '-')
       || ' -> ' || server_host || ' ' || coalesce(server_service, '-') || ' ' || port || ' ' || observed_by || ' ' || cadence
FROM shawk_v1.impact(%s) ORDER BY 1`, fmt.Sprintf(target, ts(impactSince), ts(impactUntil))))
	if err != nil {
		f.t.Fatal(err)
	}
	out, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil {
		f.t.Fatal(err)
	}
	return out
}

// verdict returns the verdict on a target over the period of the tests:
// "verdict reasons caveats direct transitive coverage".
func (f impactFixture) verdict(target string) string {
	f.t.Helper()
	var out string
	err := f.conn.QueryRow(context.Background(), fmt.Sprintf(`
SELECT verdict || ' ' || reasons::text || ' ' || caveats::text || ' ' || direct || ' ' || transitive || ' ' || coverage
FROM shawk_v1.impact_verdict(%s)`, fmt.Sprintf(target, ts(impactSince), ts(impactUntil)))).Scan(&out)
	if err != nil {
		f.t.Fatal(err)
	}
	return out
}

func checkRows(t *testing.T, what string, got, want []string) {
	t.Helper()
	if !slices.Equal(got, want) {
		t.Errorf("%s:\n%s\nwant:\n%s", what, strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
}

// impactFleet is the fleet of the tests of the dependents: db-01 serves
// postgres and redis, app-01 uses both, web-01 uses app-01, and report-01
// and clients outside the fleet use web-01.
func impactFleet(t *testing.T) impactFixture {
	t.Helper()
	_, conn := migratedDB(t)
	f := impactFixture{t, conn}
	f.watched("db-01", "10.0.0.10", "postgres", "redis", "backup")
	f.watched("app-01", "10.0.0.11", "app")
	f.watched("web-01", "10.0.0.12", "web")
	f.watched("batch-01", "10.0.0.13", "billing")
	f.watched("report-01", "10.0.0.14", "report")
	// app uses postgres and redis all along, and web uses app.
	f.both("app-01", "app", "10.0.0.11", "db-01", "postgres", "10.0.0.10", 5432, impactSince, impactUntil)
	f.both("app-01", "app", "10.0.0.11", "db-01", "redis", "10.0.0.10", 6379, impactSince, impactUntil)
	f.both("web-01", "web", "10.0.0.12", "app-01", "app", "10.0.0.11", 8080, impactSince, impactUntil)
	// app also calls web back: a cycle.
	f.both("app-01", "app", "10.0.0.11", "web-01", "web", "10.0.0.12", 9000, impactSince, impactUntil)
	// billing uses postgres for 2 hours on the first of each month.
	f.edge("batch-01", "billing", "client", "10.0.0.13", "10.0.0.10", 5432, day(0, 1), day(61, 3))
	f.edge("db-01", "postgres", "server", "10.0.0.10", "10.0.0.13", 5432, day(0, 1), day(61, 3))
	for _, d := range []int{0, 31, 61} {
		f.active("batch-01", "billing", 5432, day(d, 1), day(d, 3), time.Hour, 1)
	}
	// report reads web every day at 6.
	f.edge("report-01", "report", "client", "10.0.0.14", "10.0.0.12", 443, day(0, 6), day(89, 7))
	f.edge("web-01", "web", "server", "10.0.0.12", "10.0.0.14", 443, day(0, 6), day(89, 7))
	f.active("report-01", "report", 443, day(0, 6), impactUntil, 24*time.Hour, 1)
	// The clients of web outside the fleet, folded, and a host without an
	// agent that the inventory names, which reads postgres.
	f.edge("web-01", "web", "server", "10.0.0.12", "0.0.0.0/0", 443, impactSince, impactUntil)
	f.exec(`UPDATE shawk.edges SET remote_addr = '0.0.0.0/0' WHERE remote_addr = '0.0.0.0'`)
	f.activeWith("web-01", "web", 443, "0.0.0.0/0", impactSince, impactUntil, time.Hour, 1)
	f.exec(`INSERT INTO shawk.inventory_hosts (host, agent) VALUES ('nas-01', false)`)
	f.exec(`INSERT INTO shawk.inventory_addrs VALUES ('10.0.9.9', 'nas-01')`)
	f.edge("db-01", "postgres", "server", "10.0.0.10", "10.0.9.9", 5432, day(10, 0), day(10, 2))
	// On db-01 itself, backup reads postgres over loopback every night.
	f.edge("db-01", "backup", "client", "127.0.0.1", "127.0.0.1", 5432, day(0, 3), day(89, 4))
	f.edge("db-01", "postgres", "server", "127.0.0.1", "127.0.0.1", 5432, day(0, 3), day(89, 4))
	f.active("db-01", "backup", 5432, day(0, 3), impactUntil, 24*time.Hour, 1)
	return f
}

// TestPGImpact: the dependents of a host are its clients, at depth 1, and
// the clients of its dependents after, each once at the depth it is first
// reached, without the clients on the host itself; those of a service of
// the host include its other services.
func TestPGImpact(t *testing.T) {
	f := impactFleet(t)
	checkRows(t, "dependents of db-01", f.impact(`'db-01', %s, %s`), []string{
		"1 app-01 app - -> db-01 postgres 5432 both continuous",
		"1 app-01 app - -> db-01 redis 6379 both continuous",
		"1 batch-01 billing - -> db-01 postgres 5432 both monthly",
		"1 nas-01 ~unresolved 10.0.9.9 -> db-01 postgres 5432 server unknown",
		"2 web-01 web - -> app-01 app 8080 both continuous",
		"3 - ~external 0.0.0.0 -> web-01 web 443 server continuous",
		"3 report-01 report - -> web-01 web 443 both daily",
	})
	checkRows(t, "dependents of db-01 at depth 1", f.impact(`'db-01', %s, %s, max_depth => 1`), []string{
		"1 app-01 app - -> db-01 postgres 5432 both continuous",
		"1 app-01 app - -> db-01 redis 6379 both continuous",
		"1 batch-01 billing - -> db-01 postgres 5432 both monthly",
		"1 nas-01 ~unresolved 10.0.9.9 -> db-01 postgres 5432 server unknown",
	})
	// redis alone: app, and what depends on app.
	checkRows(t, "dependents of redis on db-01", f.impact(`'db-01', %s, %s, 'redis', max_depth => 2`), []string{
		"1 app-01 app - -> db-01 redis 6379 both continuous",
		"2 web-01 web - -> app-01 app 8080 both continuous",
	})
	// postgres alone: backup, on the host, would break too.
	checkRows(t, "dependents of postgres on db-01", f.impact(`'db-01', %s, %s, 'postgres', max_depth => 1`), []string{
		"1 app-01 app - -> db-01 postgres 5432 both continuous",
		"1 batch-01 billing - -> db-01 postgres 5432 both monthly",
		"1 db-01 backup - -> db-01 postgres 5432 both daily",
		"1 nas-01 ~unresolved 10.0.9.9 -> db-01 postgres 5432 server unknown",
	})
	checkRows(t, "dependents of port 6379 of db-01", f.impact(`'db-01', %s, %s, target_port => 6379, max_depth => 1`), []string{
		"1 app-01 app - -> db-01 redis 6379 both continuous",
	})
	checkRows(t, "dependents of db-01 over UDP", f.impact(`'db-01', %s, %s, target_proto => 'udp'`), nil)
	// web-01: app, report and the clients outside; db-01 depends on
	// nothing, and app is not reported again behind itself.
	checkRows(t, "dependents of web-01", f.impact(`'web-01', %s, %s`), []string{
		"1 - ~external 0.0.0.0 -> web-01 web 443 server continuous",
		"1 app-01 app - -> web-01 web 9000 both continuous",
		"1 report-01 report - -> web-01 web 443 both daily",
	})
	// A host nothing depends on, and a period before the dependencies.
	checkRows(t, "dependents of report-01", f.impact(`'report-01', %s, %s`), nil)
	checkRows(t, "dependents of a host that does not exist", f.impact(`'db-99', %s, %s`), nil)
	if got := queryStrings(t, f.conn, `SELECT count(*) FROM shawk_v1.impact('db-01', '2026-07-01T00:00:00Z', '2026-07-02T00:00:00Z')`); !slices.Equal(got, []string{"0"}) {
		t.Errorf("%v dependents before the dependencies", got)
	}
	if got := queryStrings(t, f.conn, `SELECT count(*) FROM shawk_v1.impact('db-01', '2026-09-02T00:00:00Z', '2026-09-01T00:00:00Z')`); !slices.Equal(got, []string{"0"}) {
		t.Errorf("%v dependents in an empty period", got)
	}
}

// TestPGImpactVerdict: a target with dependents is UNSAFE; without any, it
// is SAFE only if an agent observed it over the whole period, everything
// the target covers, and INCONCLUSIVE otherwise.
func TestPGImpactVerdict(t *testing.T) {
	f := impactFleet(t)
	// Dependents: unsafe, whatever the coverage.
	if got, want := f.verdict(`'db-01', %s, %s`), "UNSAFE {active_dependents} {} 3 3 1.000000"; got != want {
		t.Errorf("db-01: %s, want %s", got, want)
	}
	if got, want := f.verdict(`'db-01', %s, %s, 'redis'`), "UNSAFE {active_dependents} {} 1 3 1.000000"; got != want {
		t.Errorf("redis of db-01: %s, want %s", got, want)
	}
	// Observed all along and used by none but itself.
	f.watched("idle-01", "10.0.1.1", "cron", "sshd")
	f.edge("idle-01", "cron", "client", "127.0.0.1", "127.0.0.1", 22, impactSince, impactUntil)
	f.edge("idle-01", "sshd", "server", "127.0.0.1", "127.0.0.1", 22, impactSince, impactUntil)
	// A connection from its own address, of which only the server side
	// was seen, is its own too.
	f.edge("idle-01", "sshd", "server", "10.0.1.1", "10.0.1.1", 22, impactSince, impactUntil)
	if got, want := f.verdict(`'idle-01', %s, %s`), "SAFE {} {} 0 0 1.000000"; got != want {
		t.Errorf("idle-01: %s, want %s", got, want)
	}
	// Its sshd is used by its cron: unsafe to remove alone.
	if got, want := f.verdict(`'idle-01', %s, %s, 'sshd'`), "UNSAFE {active_dependents} {} 2 0 1.000000"; got != want {
		t.Errorf("sshd of idle-01: %s, want %s", got, want)
	}
	// A service that connects to itself is no dependent of its own.
	f.exec(`UPDATE shawk.processes SET service_name = 'sshd' WHERE host_id = 'idle-01' AND service_name = 'cron'`)
	if got, want := f.verdict(`'idle-01', %s, %s, 'sshd'`), "UNSAFE {active_dependents} {} 1 0 1.000000"; got != want {
		t.Errorf("sshd of idle-01, used by itself and its own address: %s, want %s", got, want)
	}

	for _, c := range []struct {
		name    string
		setup   func(host string)
		target  string // after the host and the period
		verdict string
	}{
		{"not observed for two hours", func(h string) {
			f.host(h, "10.0.2.1")
			f.observed(h, impactSince.Add(-time.Hour), day(30, 0))
			f.observed(h, day(30, 2), impactUntil)
		}, "", "INCONCLUSIVE {not_observed} {} 0 0 0.999097"},
		// Three minutes after a heartbeat are the delay of writes.
		{"a gap within the tolerance", func(h string) {
			f.host(h, "10.0.2.2")
			f.observed(h, impactSince.Add(-time.Hour), day(30, 0))
			f.observed(h, day(30, 0).Add(3*time.Minute), impactUntil)
		}, "", "SAFE {} {} 0 0 1.000000"},
		// Ten seconds beyond the tolerance are a gap, however small it is
		// in 90 days.
		{"a gap of ten seconds", func(h string) {
			f.host(h, "10.0.2.20")
			f.observed(h, impactSince.Add(-time.Hour), day(30, 0))
			f.observed(h, day(30, 0).Add(3*time.Minute+10*time.Second), impactUntil)
		}, "", "INCONCLUSIVE {not_observed} {} 0 0 0.999998"},
		{"a gap that the caller accepts", func(h string) {
			f.host(h, "10.0.2.3")
			f.observed(h, impactSince.Add(-time.Hour), day(30, 0))
			f.observed(h, day(30, 2), impactUntil)
		}, ", min_coverage => 0.999", "SAFE {} {not_observed} 0 0 0.999097"},
		{"a period longer than the history", func(h string) {
			f.host(h, "10.0.2.4")
			f.observed(h, day(45, 0), impactUntil)
		}, "", "INCONCLUSIVE {not_observed} {} 0 0 0.500000"},
		{"an agent that stopped before the period", func(h string) {
			f.host(h, "10.0.2.5")
			f.observed(h, impactSince.Add(-48*time.Hour), impactSince.Add(-24*time.Hour))
		}, "", "INCONCLUSIVE {not_observed} {} 0 0 0.000000"},
		{"an agent that stopped before the period, and a caller that accepts gaps", func(h string) {
			f.host(h, "10.0.2.6")
		}, ", min_coverage => 0.000001", "INCONCLUSIVE {not_observed} {} 0 0 0.000000"},
		{"dropped flows", func(h string) {
			f.watched(h, "10.0.2.7")
			f.exec(`INSERT INTO shawk.partial_observations VALUES ($1, $2, $3, $4, 7)`, h, impactSince.Add(-time.Hour), day(5, 0), day(5, 9))
		}, "", "INCONCLUSIVE {dropped_flows} {} 0 0 0.995833"},
		{"UDP not traced for a day", func(h string) {
			f.host(h, "10.0.2.8")
			f.observed(h, impactSince.Add(-time.Hour), day(89, 0))
			f.exec(`INSERT INTO shawk.agent_sessions (host_id, started_at, last_heartbeat, udp_traced, unix_traced, netns_scope)
				VALUES ($1, $2, $3, false, true, 'all')`, h, day(89, 0), impactUntil)
		}, "", "INCONCLUSIVE {udp_not_traced} {} 0 0 0.988888"},
		{"UDP not traced, of a target of TCP", func(h string) {
			f.host(h, "10.0.2.9")
			f.exec(`INSERT INTO shawk.agent_sessions (host_id, started_at, last_heartbeat, udp_traced, unix_traced, netns_scope)
				VALUES ($1, $2, $3, false, true, 'all')`, h, impactSince, impactUntil)
		}, ", target_proto => 'tcp'", "SAFE {} {} 0 0 1.000000"},
		{"one network namespace", func(h string) {
			f.host(h, "10.0.2.10")
			f.exec(`INSERT INTO shawk.agent_sessions (host_id, started_at, last_heartbeat, udp_traced, unix_traced, netns_scope)
				VALUES ($1, $2, $3, true, true, '4026531840')`, h, impactSince, impactUntil)
		}, "", "INCONCLUSIVE {netns_limited} {} 0 0 0.000000"},
		// The clients of a service over Unix sockets are on its host: they
		// matter to a service, not to the host.
		{"Unix sockets not traced, of a host", func(h string) {
			f.host(h, "10.0.2.11")
			f.exec(`INSERT INTO shawk.agent_sessions (host_id, started_at, last_heartbeat, udp_traced, unix_traced, netns_scope)
				VALUES ($1, $2, $3, true, NULL, 'all')`, h, impactSince, impactUntil)
		}, "", "SAFE {} {} 0 0 1.000000"},
		{"Unix sockets not traced, of a service", func(h string) {
			f.host(h, "10.0.2.12", "postgres")
			f.exec(`INSERT INTO shawk.agent_sessions (host_id, started_at, last_heartbeat, udp_traced, unix_traced, netns_scope)
				VALUES ($1, $2, $3, true, NULL, 'all')`, h, impactSince, impactUntil)
		}, ", 'postgres'", "INCONCLUSIVE {unix_not_traced} {} 0 0 0.000000"},
		{"Unix sockets not traced, of a port", func(h string) {
			f.host(h, "10.0.2.13", "postgres")
			f.listener(h, "postgres", 5432)
			f.exec(`INSERT INTO shawk.agent_sessions (host_id, started_at, last_heartbeat, udp_traced, unix_traced, netns_scope)
				VALUES ($1, $2, $3, true, false, 'all')`, h, impactSince, impactUntil)
		}, ", target_port => 5432", "SAFE {} {} 0 0 1.000000"},
		// A service that the host does not run, or a name mistyped: nothing
		// used it, which tells nothing.
		{"a service the host does not have", func(h string) {
			f.watched(h, "10.0.2.17", "postgres")
		}, ", 'postgress'", "INCONCLUSIVE {unknown_service} {} 0 0 1.000000"},
		{"a service the host had before the period", func(h string) {
			f.watched(h, "10.0.2.18", "postgres")
			f.exec(`UPDATE shawk.processes SET last_seen = $2 WHERE host_id = $1`, h, impactSince.Add(-time.Hour))
		}, ", 'postgres'", "INCONCLUSIVE {unknown_service} {} 0 0 1.000000"},
		{"a service that listens and has no client", func(h string) {
			f.watched(h, "10.0.2.19", "postgres")
			f.listener(h, "postgres", 5432)
		}, ", 'postgres', 5432, 'tcp'", "SAFE {} {} 0 0 1.000000"},
		{"a port nothing listens on", func(h string) {
			f.watched(h, "10.0.2.21", "postgres")
			f.listener(h, "postgres", 5432)
		}, ", target_port => 5433", "INCONCLUSIVE {unknown_port} {} 0 0 1.000000"},
		{"a port of another transport", func(h string) {
			f.watched(h, "10.0.2.22", "postgres")
			f.listener(h, "postgres", 5432)
		}, ", target_port => 5432, target_proto => 'udp'", "INCONCLUSIVE {unknown_port} {} 0 0 1.000000"},
		// A port known from the connections it served, those of the
		// service to itself, of a listener that was not seen.
		{"a port that served without a listener seen", func(h string) {
			f.watched(h, "10.0.2.23", "postgres")
			f.both(h, "postgres", "127.0.0.1", h, "postgres", "127.0.0.1", 5432, day(1, 0), day(2, 0))
		}, ", target_port => 5432", "SAFE {} {} 0 0 1.000000"},
		{"a service and a port that the host does not have, not observed all along", func(h string) {
			f.host(h, "10.0.2.24")
			f.observed(h, day(45, 0), impactUntil)
		}, ", 'postgres', 5432", "INCONCLUSIVE {not_observed,unknown_service,unknown_port} {} 0 0 0.500000"},
		{"a name no agent reported under", func(string) {}, "", "INCONCLUSIVE {unknown_host} {} 0 0 0.000000"},
		{"a host of the inventory without an agent", func(h string) {
			f.exec(`INSERT INTO shawk.inventory_hosts (host, agent) VALUES ($1, false)`, h)
			f.exec(`INSERT INTO shawk.inventory_addrs VALUES ('10.0.2.15', $1)`, h)
		}, "", "INCONCLUSIVE {no_agent} {} 0 0 0.000000"},
		// A node whose machine id changed at a boot: two hosts of one name.
		{"two host ids of one name", func(h string) {
			f.host(h, "10.0.2.16")
			f.observed(h, impactSince.Add(-time.Hour), day(30, 0))
			f.exec(`INSERT INTO shawk.hosts VALUES ($1, 'm2', $2, 'k', 'v', $3, $4)`, h+"-b", h, day(30, 0), impactUntil)
			f.observed(h+"-b", day(30, 0).Add(time.Minute), impactUntil)
		}, "", "SAFE {} {} 0 0 1.000000"},
	} {
		t.Run(c.name, func(t *testing.T) {
			host := "h-" + strings.NewReplacer(" ", "-", ",", "").Replace(c.name)
			c.setup(host)
			if got := f.verdict(`'` + host + `', %s, %s` + c.target); got != c.verdict {
				t.Errorf("verdict = %s, want %s", got, c.verdict)
			}
		})
	}

	// Dependents and a gap: unsafe, and the dependents may not be all.
	f.exec(`DELETE FROM shawk.agent_sessions WHERE host_id = 'db-01'`)
	f.observed("db-01", day(1, 0), impactUntil)
	if got, want := f.verdict(`'db-01', %s, %s`), "UNSAFE {active_dependents} {not_observed} 3 3 0.988888"; got != want {
		t.Errorf("db-01 with a gap: %s, want %s", got, want)
	}

	for _, q := range []string{
		`SELECT * FROM shawk_v1.impact_verdict('db-01', '2026-09-02T00:00:00Z', '2026-09-01T00:00:00Z')`,
		`SELECT * FROM shawk_v1.impact_verdict('db-01', NULL, now())`,
		`SELECT * FROM shawk_v1.impact_verdict('', now() - interval '1 day', now())`,
		`SELECT * FROM shawk_v1.impact_verdict(NULL, now() - interval '1 day', now())`,
		`SELECT * FROM shawk_v1.impact_verdict('db-01', now() - interval '1 day', now(), min_coverage => 0)`,
		`SELECT * FROM shawk_v1.impact_verdict('db-01', now() - interval '1 day', now(), min_coverage => 1.01)`,
		`SELECT * FROM shawk_v1.impact_verdict('db-01', now() - interval '1 day', now(), target_proto => 'TCP')`,
		`SELECT * FROM shawk_v1.impact_verdict('db-01', now() - interval '1 day', now(), target_port => 0)`,
		`SELECT * FROM shawk_v1.impact_verdict('db-01', now() - interval '1 day', now(), target_port => 65536)`,
	} {
		if _, err := f.conn.Exec(context.Background(), q); err == nil {
			t.Errorf("%s: no error", q)
		}
	}
}

// TestPGImpactSeenByClients: a dependency that its client alone saw counts
// for the host that held the address of its server then, and for the
// service that owned a listener on its port; not for another host that
// holds the same address, nor for another service of the host.
func TestPGImpactSeenByClients(t *testing.T) {
	_, conn := migratedDB(t)
	f := impactFixture{t, conn}
	// db-01 was not observed on the day app-01 used its postgres, and
	// listened on 5432 (postgres) and 6379 (redis) around it.
	f.host("db-01", "10.0.0.10", "postgres", "redis")
	f.observed("db-01", impactSince.Add(-time.Hour), day(20, 0))
	f.observed("db-01", day(21, 0), impactUntil)
	for svc, port := range map[string]int{"postgres": 5432, "redis": 6379} {
		f.exec(`INSERT INTO shawk.listener_owners (host_id, process_id, proto, addr, port, netns, first_seen, last_seen)
			VALUES ('db-01', (SELECT id FROM shawk.processes WHERE host_id = 'db-01' AND service_name = $1),
			        'tcp', '0.0.0.0', $2, 1, $3, $4)`, svc, port, impactSince, impactUntil)
	}
	f.watched("app-01", "10.0.0.11", "app", "probe")
	f.edge("app-01", "app", "client", "10.0.0.11", "10.0.0.10", 5432, day(20, 3), day(20, 5))
	f.active("app-01", "app", 5432, day(20, 3), day(20, 5), time.Hour, 1)
	// A probe of a port nothing listens on, which fails.
	f.edge("app-01", "probe", "client", "10.0.0.11", "10.0.0.10", 9999, day(40, 0), day(40, 1))
	// The gateway of the container bridge, which every host holds: app-01
	// connects to its own.
	f.exec(`INSERT INTO shawk.host_addrs VALUES ('db-01', '172.17.0.1', $1, $2), ('app-01', '172.17.0.1', $1, $2)`,
		impactSince.Add(-24*time.Hour), impactUntil)
	f.edge("app-01", "app", "client", "172.17.0.2", "172.17.0.1", 8080, impactSince, impactUntil)
	// An address db-01 held before another host took it.
	f.watched("new-01", "", "x")
	f.exec(`INSERT INTO shawk.host_addrs VALUES ('db-01', '10.0.0.20', $1, $2), ('new-01', '10.0.0.20', $3, $4)`,
		impactSince.Add(-24*time.Hour), day(9, 0), day(10, 0), impactUntil)
	f.edge("app-01", "app", "client", "10.0.0.11", "10.0.0.20", 443, day(50, 0), day(50, 1))

	checkRows(t, "dependents of db-01", f.impact(`'db-01', %s, %s`), []string{
		"1 app-01 app - -> db-01 postgres 5432 client one-off",
		"1 app-01 probe - -> db-01 - 9999 client unknown",
	})
	if got, want := f.verdict(`'db-01', %s, %s`), "UNSAFE {active_dependents} {not_observed} 2 0 0.988912"; got != want {
		t.Errorf("db-01: %s, want %s", got, want)
	}
	checkRows(t, "dependents of postgres on db-01", f.impact(`'db-01', %s, %s, 'postgres'`), []string{
		"1 app-01 app - -> db-01 postgres 5432 client one-off",
	})
	// redis: neither the client of postgres nor the probe of a port
	// without a listener, but the gap leaves it open.
	checkRows(t, "dependents of redis on db-01", f.impact(`'db-01', %s, %s, 'redis'`), nil)
	if got, want := f.verdict(`'db-01', %s, %s, 'redis'`), "INCONCLUSIVE {not_observed} {} 0 0 0.988912"; got != want {
		t.Errorf("redis of db-01: %s, want %s", got, want)
	}
	checkRows(t, "dependents of port 9999 of db-01", f.impact(`'db-01', %s, %s, target_port => 9999`), []string{
		"1 app-01 probe - -> db-01 - 9999 client unknown",
	})
	checkRows(t, "dependents of new-01", f.impact(`'new-01', %s, %s`), []string{
		"1 app-01 app - -> new-01 - 443 client unknown",
	})

	// A host of the inventory without an agent: its clients with an agent
	// are its dependents, whatever its service, of which nothing is known.
	f.exec(`INSERT INTO shawk.inventory_hosts (host, agent) VALUES ('sfa-01', false)`)
	f.exec(`INSERT INTO shawk.inventory_addrs VALUES ('10.0.9.5', 'sfa-01')`)
	if got, want := f.verdict(`'sfa-01', %s, %s`), "INCONCLUSIVE {no_agent} {} 0 0 0.000000"; got != want {
		t.Errorf("sfa-01 without clients: %s, want %s", got, want)
	}
	f.edge("app-01", "app", "client", "10.0.0.11", "10.0.9.5", 2049, impactSince, impactUntil)
	f.active("app-01", "app", 2049, impactSince, impactUntil, time.Hour, 1)
	for _, target := range []string{`'sfa-01', %s, %s`, `'sfa-01', %s, %s, 'nfs'`} {
		checkRows(t, "dependents of "+target, f.impact(target), []string{
			"1 app-01 app - -> sfa-01 - 2049 client continuous",
		})
		if got, want := f.verdict(target), "UNSAFE {active_dependents} {no_agent} 1 0 0.000000"; got != want {
			t.Errorf("%s: %s, want %s", target, got, want)
		}
	}
}

// TestPGImpactOfAService: the clients of a service without an agent, and
// those on its own host over loopback and Unix sockets, are its
// dependents; a client of a socket that no listener serves is not.
func TestPGImpactOfAService(t *testing.T) {
	_, conn := migratedDB(t)
	f := impactFixture{t, conn}
	f.watched("db-01", "10.0.0.10", "postgres", "redis", "app", "probe")
	// A client without an agent, seen by postgres alone.
	f.edge("db-01", "postgres", "server", "10.0.0.10", "10.0.5.5", 5432, impactSince, impactUntil)
	f.active("db-01", "postgres", 5432, impactSince, impactUntil, time.Hour, 1)
	// app, on the host, reads postgres over its Unix socket, and probe
	// tries the socket of nscd, which nothing serves.
	f.exec(`INSERT INTO shawk.unix_listeners (host_id, process_id, path, netns, first_seen, last_seen)
		VALUES ('db-01', (SELECT id FROM shawk.processes WHERE host_id = 'db-01' AND service_name = 'postgres'),
		        '/run/postgresql/.s.PGSQL.5432', 1, $1, $2)`, impactSince, impactUntil)
	for svc, path := range map[string]string{"app": "/run/postgresql/.s.PGSQL.5432", "probe": "/var/run/nscd/socket"} {
		f.exec(`INSERT INTO shawk.unix_edges (host_id, process_id, path, netns, first_seen, last_seen)
			VALUES ('db-01', (SELECT id FROM shawk.processes WHERE host_id = 'db-01' AND service_name = $1), $2, 1, $3, $4)`,
			svc, path, impactSince, impactUntil)
	}
	f.exec(`INSERT INTO shawk.unix_edge_activity
		SELECT e.id, m, repeat('1', 744)::bit(744) FROM shawk.unix_edges e,
		  generate_series('2026-08-01T00:00:00Z'::timestamptz, '2026-10-01T00:00:00Z', interval '1 month') m
		WHERE e.path LIKE '%PGSQL%'`)
	checkRows(t, "dependents of postgres on db-01", f.impact(`'db-01', %s, %s, 'postgres'`), []string{
		"1 - ~unresolved 10.0.5.5 -> db-01 postgres 5432 server continuous",
		"1 db-01 app - -> db-01 postgres 0 both continuous",
	})
	// The host as a whole: its own clients go with it.
	checkRows(t, "dependents of db-01", f.impact(`'db-01', %s, %s`), []string{
		"1 - ~unresolved 10.0.5.5 -> db-01 postgres 5432 server continuous",
	})
	checkRows(t, "dependents of redis on db-01", f.impact(`'db-01', %s, %s, 'redis'`), nil)
	if got, want := f.verdict(`'db-01', %s, %s, 'redis'`), "SAFE {} {} 0 0 1.000000"; got != want {
		t.Errorf("redis of db-01: %s, want %s", got, want)
	}
	checkRows(t, "dependents of db-01 over Unix sockets", f.impact(`'db-01', %s, %s, 'postgres', target_proto => 'unix'`), []string{
		"1 db-01 app - -> db-01 postgres 0 both continuous",
	})
}

// TestPGImpactThroughATranslation: the clients of a virtual address are
// the dependents of the backend that served them.
func TestPGImpactThroughATranslation(t *testing.T) {
	_, conn := migratedDB(t)
	f := impactFixture{t, conn}
	f.watched("db-01", "10.0.1.10", "postgres")
	f.watched("db-02", "10.0.1.11", "postgres")
	f.watched("app-01", "10.0.0.11", "app")
	f.exec(`INSERT INTO shawk.translations VALUES
		('postgres-vip', 'virtual', 'tcp', '10.0.100.1', 5432),
		('postgres-vip', 'backend', 'tcp', '10.0.1.10', 0), ('postgres-vip', 'backend', 'tcp', '10.0.1.11', 0)`)
	// app connects to the virtual address all along; db-01 served it for
	// the first 30 days, db-02 since.
	f.edge("app-01", "app", "client", "10.0.0.11", "10.0.100.1", 5432, impactSince, impactUntil)
	f.active("app-01", "app", 5432, impactSince, impactUntil, time.Hour, 1)
	f.edge("db-01", "postgres", "server", "10.0.1.10", "10.0.0.11", 5432, impactSince, day(30, 0))
	f.active("db-01", "postgres", 5432, impactSince, day(30, 0), time.Hour, 1)
	f.edge("db-02", "postgres", "server", "10.0.1.11", "10.0.0.11", 5432, day(30, 0), impactUntil)
	f.active("db-02", "postgres", 5432, day(30, 0), impactUntil, time.Hour, 1)
	checkRows(t, "dependents of db-02", f.impact(`'db-02', %s, %s`), []string{
		"1 app-01 app - -> db-02 postgres 5432 both continuous",
	})
	checkRows(t, "dependents of db-01", f.impact(`'db-01', %s, %s`), []string{
		"1 app-01 app - -> db-01 postgres 5432 both continuous",
	})
	// Two months after db-01 served its last client, nothing depends on it.
	since := ts(day(31, 0))
	if got := queryStrings(t, conn, `SELECT verdict, direct FROM shawk_v1.impact_verdict('db-01', `+since+`, `+ts(impactUntil)+`)`); !slices.Equal(got, []string{"SAFE 0"}) {
		t.Errorf("db-01 since it was replaced: %v, want SAFE", got)
	}
}

// TestPGImpactCadence: the cadence of a dependent is that of the hours of
// both its sides together; the time in which neither of the hosts that
// saw it was observed tells nothing, and hours that end before it was
// last seen were not all recorded.
func TestPGImpactCadence(t *testing.T) {
	_, conn := migratedDB(t)
	f := impactFixture{t, conn}
	f.watched("db-01", "10.0.0.10", "postgres")
	// a: written before the hours were recorded, and seen since.
	f.watched("a-01", "10.0.0.21", "a")
	f.edge("a-01", "a", "client", "10.0.0.21", "10.0.0.10", 5432, impactSince, impactUntil)
	f.edge("db-01", "postgres", "server", "10.0.0.10", "10.0.0.21", 5432, impactSince, impactUntil)
	// b: its hours end 10 days before it was last seen, as when a
	// connector that does not record them took over.
	f.watched("b-01", "10.0.0.22", "b")
	f.edge("b-01", "b", "client", "10.0.0.22", "10.0.0.10", 5432, impactSince, impactUntil)
	f.active("b-01", "b", 5432, impactSince, day(80, 0), time.Hour, 1)
	// c: the hours of its client stop when the agent of c-01 does, on day
	// 30; those of the server go on.
	f.host("c-01", "10.0.0.23", "c")
	f.observed("c-01", impactSince.Add(-time.Hour), day(30, 0))
	f.edge("c-01", "c", "client", "10.0.0.23", "10.0.0.10", 5432, impactSince, day(30, 0))
	f.active("c-01", "c", 5432, impactSince, day(30, 0), time.Hour, 1)
	f.edge("db-01", "postgres", "server", "10.0.0.10", "10.0.0.23", 5432, impactSince, impactUntil)
	f.activeWith("db-01", "postgres", 5432, "10.0.0.23", day(30, 0), impactUntil, time.Hour, 1)
	// d: seen by its client alone, whose agent stopped on day 30 and came
	// back on day 60: all along as far as it was observed.
	f.host("d-01", "10.0.0.24", "d")
	f.observed("d-01", impactSince.Add(-time.Hour), day(30, 0))
	f.observed("d-01", day(60, 0), impactUntil)
	f.edge("d-01", "d", "client", "10.0.0.24", "10.0.0.99", 5432, impactSince, impactUntil)
	f.active("d-01", "d", 5432, impactSince, day(30, 0), time.Hour, 1)
	f.active("d-01", "d", 5432, day(60, 0), impactUntil, time.Hour, 1)
	f.exec(`INSERT INTO shawk.inventory_hosts (host, agent) VALUES ('nas-01', false)`)
	f.exec(`INSERT INTO shawk.inventory_addrs VALUES ('10.0.0.99', 'nas-01')`)
	// e: as d, but observed and idle in between.
	f.watched("e-01", "10.0.0.25", "e")
	f.edge("e-01", "e", "client", "10.0.0.25", "10.0.0.99", 5432, impactSince, impactUntil)
	f.active("e-01", "e", 5432, impactSince, day(30, 0), time.Hour, 1)
	f.active("e-01", "e", 5432, day(60, 0), impactUntil, time.Hour, 1)

	checkRows(t, "dependents of db-01", f.impact(`'db-01', %s, %s`), []string{
		"1 a-01 a - -> db-01 postgres 5432 both unknown",
		"1 b-01 b - -> db-01 - 5432 client unknown",
		"1 c-01 c - -> db-01 postgres 5432 both continuous",
	})
	checkRows(t, "dependents of nas-01", f.impact(`'nas-01', %s, %s`), []string{
		"1 d-01 d - -> nas-01 - 5432 client continuous",
		"1 e-01 e - -> nas-01 - 5432 client unknown",
	})
	// The same in a session of another time zone: the hours are of UTC.
	f.exec(`SET timezone = 'Asia/Kolkata'`)
	checkRows(t, "dependents of nas-01 read in another time zone", f.impact(`'nas-01', %s, %s`), []string{
		"1 d-01 d - -> nas-01 - 5432 client continuous",
		"1 e-01 e - -> nas-01 - 5432 client unknown",
	})
	got := queryStrings(t, conn, fmt.Sprintf(`SELECT client_service, cadence, period::text, runs,
		to_char(next_expected AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"')
		FROM shawk_v1.impact('nas-01', %s, %s)`, ts(impactSince), ts(impactUntil)))
	checkRows(t, "cadences", got, []string{"d continuous <nil> 1 <nil>", "e unknown <nil> 2 <nil>"})
}

// TestPGCoverage: how much of a period hosts were observed, by name.
func TestPGCoverage(t *testing.T) {
	_, conn := migratedDB(t)
	f := impactFixture{t, conn}
	f.watched("full-01", "10.0.0.1")
	// Observed from day 45, with a gap of a day, dropped flows for 9
	// hours, a day without UDP and Unix sockets, and a day in one network
	// namespace.
	f.host("part-01", "10.0.0.2")
	f.observed("part-01", day(45, 0), day(60, 0))
	f.observed("part-01", day(61, 0), day(88, 0))
	f.exec(`INSERT INTO shawk.agent_sessions (host_id, started_at, last_heartbeat, udp_traced, unix_traced, netns_scope)
		VALUES ('part-01', $1, $2, false, false, 'all'), ('part-01', $2, $3, true, true, '4026531840')`,
		day(88, 0), day(89, 0), impactUntil)
	f.exec(`INSERT INTO shawk.partial_observations VALUES ('part-01', $1, $2, $3, 7), ('part-01', $1, $4, $5, 5)`,
		day(45, 0), day(50, 0), day(50, 9), impactSince.Add(-48*time.Hour), impactSince.Add(-24*time.Hour))
	// Last seen before the period: not among the hosts of the period.
	f.exec(`INSERT INTO shawk.hosts VALUES ('old-01', 'm', 'old-01', 'k', 'v', $1, $1)`, impactSince.Add(-48*time.Hour))
	const cols = `host, agent, observed::text, extract(epoch FROM unobserved)::int, gaps, extract(epoch FROM partly_observed)::int,
		dropped_flows, extract(epoch FROM udp_untraced)::int, extract(epoch FROM unix_untraced)::int,
		extract(epoch FROM netns_limited)::int`
	args := ts(impactSince) + ", " + ts(impactUntil)
	checkRows(t, "coverage of every host", queryStrings(t, conn, `SELECT `+cols+` FROM shawk_v1.coverage(`+args+`)`), []string{
		"full-01 true 1.000000 0 0 0 0 0 0 0",
		// 45 days, and a day less 3 minutes: the tolerance.
		"part-01 true 0.488912 3974220 2 32400 7 86400 86400 86400",
	})
	checkRows(t, "coverage of hosts by name",
		queryStrings(t, conn, `SELECT `+cols+` FROM shawk_v1.coverage(`+args+`, ARRAY['old-01', 'none-01', 'full-01', 'full-01'])`), []string{
			"full-01 true 1.000000 0 0 0 0 0 0 0",
			"none-01 false 0.000000 7776000 1 0 0 0 0 0",
			"old-01 true 0.000000 7776000 1 0 0 0 0 0",
		})
	if got := queryStrings(t, conn, `SELECT count(*) FROM shawk_v1.coverage('2026-09-02T00:00:00Z', '2026-09-01T00:00:00Z')`); !slices.Equal(got, []string{"0"}) {
		t.Errorf("%v rows of an empty period", got)
	}
}

// TestPGImpactAddressTakenOver: an address of the target that a host
// without an agent took since is that host's: its connections are not
// those of the target to itself.
func TestPGImpactAddressTakenOver(t *testing.T) {
	_, conn := migratedDB(t)
	f := impactFixture{t, conn}
	f.watched("db-01", "10.0.0.10", "postgres")
	// db-01 held 10.0.0.50 until day 10, and connected to its own postgres
	// from it; since then another machine, without an agent, uses the
	// address and connects to the same port: the same server edge.
	f.exec(`INSERT INTO shawk.host_addrs VALUES ('db-01', '10.0.0.50', $1, $2)`, impactSince.Add(-24*time.Hour), day(10, 0))
	f.edge("db-01", "postgres", "server", "10.0.0.10", "10.0.0.50", 5432, impactSince, day(10, 0))
	if got, want := f.verdict(`'db-01', %s, %s`), "SAFE {} {} 0 0 1.000000"; got != want {
		t.Errorf("db-01 while it held the address: %s, want %s", got, want)
	}
	f.exec(`UPDATE shawk.edges SET last_seen = $1 WHERE remote_addr = '10.0.0.50'`, day(60, 0))
	checkRows(t, "dependents of db-01", f.impact(`'db-01', %s, %s`), []string{
		"1 - ~unresolved 10.0.0.50 -> db-01 postgres 5432 server unknown",
	})
	if got, want := f.verdict(`'db-01', %s, %s`), "UNSAFE {active_dependents} {} 1 0 1.000000"; got != want {
		t.Errorf("db-01 after another host took the address: %s, want %s", got, want)
	}
}

// TestPGImpactUnknownOwner: the sockets without a known owner of a host
// are dependents, and the clients of the others of the host are not
// theirs; a connection that such a socket accepted counts for every
// service of its host.
func TestPGImpactUnknownOwner(t *testing.T) {
	_, conn := migratedDB(t)
	f := impactFixture{t, conn}
	f.watched("db-01", "10.0.0.10", "postgres", "redis", "~unknown")
	f.listener("db-01", "redis", 6379)
	// A connection to db-01 that a socket without a known owner accepted,
	// as one that predates the agent, and one of such a socket of db-01
	// itself to another.
	f.edge("db-01", "~unknown", "server", "10.0.0.10", "10.0.0.13", 6379, day(1, 0), day(2, 0))
	f.both("db-01", "~unknown", "127.0.0.1", "db-01", "~unknown", "127.0.0.1", 7000, day(1, 0), day(2, 0))
	accepted := "1 - ~unresolved 10.0.0.13 -> db-01 ~unknown 6379 server unknown"
	checkRows(t, "dependents of redis on db-01", f.impact(`'db-01', %s, %s, 'redis'`), []string{
		accepted,
		"1 db-01 ~unknown - -> db-01 ~unknown 7000 both dormant",
	})
	// Its port leaves the other sockets out.
	checkRows(t, "dependents of redis on port 6379 of db-01", f.impact(`'db-01', %s, %s, 'redis', 6379`), []string{accepted})
	checkRows(t, "dependents of port 6379 of db-01", f.impact(`'db-01', %s, %s, target_port => 6379`), []string{accepted})
	if got, want := f.verdict(`'db-01', %s, %s, 'redis'`), "UNSAFE {active_dependents} {} 2 0 1.000000"; got != want {
		t.Errorf("redis of db-01: %s, want %s", got, want)
	}
	// The host as a whole: its own sockets go with it.
	checkRows(t, "dependents of db-01", f.impact(`'db-01', %s, %s`), []string{accepted})
	execAll(t, conn, `DELETE FROM shawk.edges WHERE host_id = 'db-01'`)
	f.watched("app-01", "10.0.0.11", "~unknown")
	f.watched("web-01", "10.0.0.12", "web")
	// A socket of app-01 without a known owner uses postgres, and another
	// one serves web.
	f.both("app-01", "~unknown", "10.0.0.11", "db-01", "postgres", "10.0.0.10", 5432, impactSince, impactUntil)
	f.both("web-01", "web", "10.0.0.12", "app-01", "~unknown", "10.0.0.11", 8080, impactSince, impactUntil)
	checkRows(t, "dependents of db-01", f.impact(`'db-01', %s, %s`), []string{
		"1 app-01 ~unknown - -> db-01 postgres 5432 both continuous",
	})
}
