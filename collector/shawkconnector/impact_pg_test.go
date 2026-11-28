package shawkconnector

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
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
		// Runs of a month with an hour between them are no monthly job, and
		// 12 hours of idle time do not end what was used for 90 days.
		{"long runs", []timeSpan{{day(0, 0), day(30, 0)}, {day(30, 1), day(60, 0)}, {day(60, 1), day(89, 12)}}, nil,
			"continuous <nil> <nil> 3"},
		// Long runs with pauses of weeks: neither continuous nor a job.
		{"long runs, weeks apart", []timeSpan{{day(0, 0), day(10, 0)}, {day(30, 0), day(45, 0)}, {day(70, 0), day(89, 12)}}, nil,
			"irregular <nil> <nil> 3"},
		// Used all along and idle for the last 2 hours: not gone, as far as
		// 2 hours tell. A day later it is.
		{"all along until 2 hours ago", []timeSpan{{impactSince, until.Add(-2 * time.Hour)}}, nil, "continuous <nil> <nil> 1"},
		{"all along until 23 hours ago", []timeSpan{{impactSince, until.Add(-23 * time.Hour)}}, nil, "continuous <nil> <nil> 1"},
		{"all along until 25 hours ago", []timeSpan{{impactSince, until.Add(-25 * time.Hour)}}, nil, "dormant <nil> <nil> 1"},
		{"all along but for two deploys, until 2 hours ago", []timeSpan{{impactSince, day(50, 0)}, {day(50, 2), day(80, 0)},
			{day(80, 2), until.Add(-2 * time.Hour)}}, nil, "continuous <nil> <nil> 3"},
		// The first 20 hours of something new, idle for 2 hours: too recent
		// to tell. Idle for more than a day, it was a one-off.
		{"for 20 hours until 2 hours ago", []timeSpan{{until.Add(-22 * time.Hour), until.Add(-2 * time.Hour)}}, nil,
			"unknown <nil> <nil> 1"},
		{"for 20 hours until 25 hours ago", []timeSpan{{until.Add(-45 * time.Hour), until.Add(-25 * time.Hour)}}, nil,
			"one-off <nil> <nil> 1"},
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
// fixed times, in the shape the connector writes them
// (TestPGImpactFixtureLikeTheConnector): a host holds its addresses while
// an agent reports, a process is seen from the first to the last of its
// edges and listeners, a listener has a row of its owner, and an edge the
// hour it was last seen in.
type impactFixture struct {
	t     *testing.T
	conn  *pgx.Conn
	addrs map[string][]string // the addresses of the hosts
}

func newImpactFixture(t *testing.T, conn *pgx.Conn) impactFixture {
	return impactFixture{t, conn, map[string][]string{}}
}

func (f impactFixture) exec(sql string, args ...any) {
	f.t.Helper()
	if _, err := f.conn.Exec(context.Background(), sql, args...); err != nil {
		f.t.Fatalf("%s: %v", sql, err)
	}
}

// impactNetns is the network namespace of the fixtures.
const impactNetns = 4026531840

// host adds a host with its addresses, which no agent observed yet. Its id
// is its name.
func (f impactFixture) host(name string, addrs ...string) {
	f.t.Helper()
	f.exec(`INSERT INTO shawk.hosts VALUES ($1, 'm', $1, 'k', 'v', $2, $2)`, name, impactSince.Add(-24*time.Hour))
	f.addrs[name] = addrs
}

// session adds a session of the agent of a host from from to to, in which
// it reported the addresses of the host: as the connector, an address
// continues its latest period unless that ended longer ago than the alive
// window. udp, unix and scope are what the agent traced, in SQL; it learns
// translations and folds no peer.
func (f impactFixture) session(host string, from, to time.Time, udp, unix, scope string) {
	f.t.Helper()
	f.exec(`INSERT INTO shawk.agent_sessions (host_id, started_at, last_heartbeat, udp_traced, unix_traced, netns_scope, translations_traced)
		VALUES ($1, $2, $3, `+udp+`, `+unix+`, `+scope+`, true)`, host, from, to)
	f.exec(`UPDATE shawk.hosts SET first_seen = least(first_seen, $2), last_seen = greatest(last_seen, $3) WHERE id = $1`, host, from, to)
	for _, addr := range f.addrs[host] {
		f.held(host, addr, from, to)
	}
}

// held adds a report of an address by the agent of a host from from to to.
func (f impactFixture) held(host, addr string, from, to time.Time) {
	f.t.Helper()
	f.exec(`
WITH latest AS (
  SELECT a.first_seen, a.last_seen FROM shawk.host_addrs a
  WHERE a.host_id = $1 AND a.addr = $2::inet ORDER BY a.first_seen DESC LIMIT 1
),
continued AS (
  UPDATE shawk.host_addrs a SET last_seen = greatest(a.last_seen, $4)
  FROM latest
  WHERE a.host_id = $1 AND a.addr = $2::inet AND a.first_seen = latest.first_seen
    AND $3 <= latest.last_seen + shawk.alive_window()
  RETURNING 1
)
INSERT INTO shawk.host_addrs SELECT $1, $2::inet, $3, $4 WHERE NOT EXISTS (SELECT FROM continued)`, host, addr, from, to)
}

// observed adds a session of the agent of a host, which traces everything.
func (f impactFixture) observed(host string, from, to time.Time) {
	f.t.Helper()
	f.session(host, from, to, "true", "true", "'all'")
}

// watched adds a host observed over the whole period of the tests.
func (f impactFixture) watched(name string, addrs ...string) {
	f.t.Helper()
	f.host(name, addrs...)
	f.observed(name, impactSince.Add(-time.Hour), impactUntil)
}

// process adds the process of svc on host, seen from first to last, or
// extends the times it was seen in, and returns its id. Its unit is named
// after the service, or is the part of svc before a slash.
func (f impactFixture) process(host, svc string, first, last time.Time) int64 {
	f.t.Helper()
	unit := svc
	if u, name, ok := strings.Cut(svc, "/"); ok {
		unit, svc = u, name
	}
	var id int64
	err := f.conn.QueryRow(context.Background(), `
INSERT INTO shawk.processes AS p (host_id, unit, comm, exe, service_name, first_seen, last_seen)
VALUES ($1, $2 || '.service', $3, '', $3, $4, $5)
ON CONFLICT (host_id, unit, comm, service_name, coalesce(user_id, -1)) DO UPDATE SET
  first_seen = least(p.first_seen, excluded.first_seen), last_seen = greatest(p.last_seen, excluded.last_seen)
RETURNING id`, host, unit, svc, first, last).Scan(&id)
	if err != nil {
		f.t.Fatal(err)
	}
	return id
}

// listener adds a listener of the process of svc on host on every address
// of a TCP port, seen from first to last.
func (f impactFixture) listener(host, svc string, port int, first, last time.Time) {
	f.t.Helper()
	id := f.process(host, svc, first, last)
	f.exec(`INSERT INTO shawk.listeners (host_id, process_id, proto, addr, port, netns, first_seen, last_seen)
		VALUES ($1, $2, 'tcp', '0.0.0.0', $3, $4, $5, $6)`, host, id, port, int64(impactNetns), first, last)
	f.exec(`INSERT INTO shawk.listener_owners (host_id, process_id, proto, addr, port, netns, first_seen, last_seen)
		VALUES ($1, $2, 'tcp', '0.0.0.0', $3, $4, $5, $6)`, host, id, port, int64(impactNetns), first, last)
}

// listens adds a listener seen over the period of the tests.
func (f impactFixture) listens(host, svc string, port int) {
	f.t.Helper()
	f.listener(host, svc, port, impactSince, impactUntil)
}

// edge adds an edge of the process of svc on host, seen from first to
// last, with the hour it was last seen in: the one hour that a connector
// records of any edge it writes.
func (f impactFixture) edge(host, svc, role, local, remote string, port int, first, last time.Time) {
	f.t.Helper()
	f.edgeOf(host, svc, role, "tcp", local, remote, port, first, last)
}

// edgeOf is edge for a transport.
func (f impactFixture) edgeOf(host, svc, role, proto, local, remote string, port int, first, last time.Time) {
	f.t.Helper()
	id := f.process(host, svc, first, last)
	f.exec(`
WITH e AS (
  INSERT INTO shawk.edges (host_id, process_id, role, proto, local_addr, remote_addr, port, netns, first_seen, last_seen)
  VALUES ($1, $2, $3, $4, $5::inet, $6::cidr, $7, $8, $9, $10)
  RETURNING id, date_trunc('month', last_seen, 'UTC') AS month, last_seen
)
INSERT INTO shawk.edge_activity
SELECT e.id, e.month, set_bit(repeat('0', 744)::bit(744), floor(extract(epoch FROM e.last_seen - e.month) / 3600)::int, 1) FROM e`,
		host, id, role, proto, local, remote, port, int64(impactNetns), first, last)
}

// unixEdge adds an edge of the process of svc on host to a Unix socket,
// seen over the period of the tests in every hour: one with established
// connections, or one of failed attempts only.
func (f impactFixture) unixEdge(host, svc, path string, established bool) {
	f.t.Helper()
	f.exec(`
WITH e AS (
  INSERT INTO shawk.unix_edges (host_id, process_id, path, netns, first_seen, last_seen, established)
  VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING id
)
INSERT INTO shawk.unix_edge_activity
SELECT e.id, m, repeat('1', 744)::bit(744)
FROM e, generate_series(date_trunc('month', $5::timestamptz, 'UTC'), $6::timestamptz - interval '1 second', interval '1 month') m`,
		host, f.process(host, svc, impactSince, impactUntil), path, int64(impactNetns), impactSince, impactUntil, established)
}

// unixListener adds a listener of the process of svc on host on a Unix
// socket, in a network namespace, seen over the period of the tests.
func (f impactFixture) unixListener(host, svc, path string, netns int64) {
	f.t.Helper()
	f.exec(`INSERT INTO shawk.unix_listeners (host_id, process_id, path, netns, first_seen, last_seen)
		VALUES ($1, $2, $3, $4, $5, $6)`, host, f.process(host, svc, impactSince, impactUntil), path, netns, impactSince, impactUntil)
}

// learned adds a translation that the agent of host learned: client
// connected to virtual on vport, which backend saw on bport from source.
func (f impactFixture) learned(host, client, virtual string, vport int, source, backend string, bport int, first, last time.Time) {
	f.t.Helper()
	f.exec(`INSERT INTO shawk.learned_translations VALUES ($1, 'tcp', $2, $3, $4, $5, $6, $7, $8, $9, $10)`,
		host, int64(impactNetns), client, virtual, vport, source, backend, bport, first, last)
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
WHERE e.host_id = $1 AND p.service_name = split_part($2, '/', 2) || CASE WHEN strpos($2, '/') = 0 THEN $2 ELSE '' END
  AND e.port = $3 AND h.t < $5 AND ($8 = '' OR e.remote_addr = $8::cidr)
GROUP BY e.id, m.month
ON CONFLICT (edge_id, month) DO UPDATE SET hours = a.hours | excluded.hours`,
		host, svc, port, from, until, step.Seconds(), length, peer)
}

// unrecorded removes the hours of the edges of svc on host: edges that a
// connector wrote before it recorded hours.
func (f impactFixture) unrecorded(host, svc string) {
	f.t.Helper()
	f.exec(`DELETE FROM shawk.edge_activity a USING shawk.edges e, shawk.processes p
		WHERE a.edge_id = e.id AND p.id = e.process_id AND e.host_id = $1 AND p.service_name = $2`, host, svc)
}

// both adds both sides of a connection from client to server, active all
// along from first to last.
func (f impactFixture) both(clientHost, clientSvc, clientAddr, serverHost, serverSvc, serverAddr string, port int, first, last time.Time) {
	f.t.Helper()
	f.edge(clientHost, clientSvc, "client", clientAddr, serverAddr, port, first, last)
	f.edge(serverHost, serverSvc, "server", serverAddr, clientAddr, port, first, last)
	f.activeWith(clientHost, clientSvc, port, serverAddr, first, last, time.Hour, 1)
	f.activeWith(serverHost, serverSvc, port, clientAddr, first, last, time.Hour, 1)
}

// impact returns the dependents of a target over the period of the tests:
// "depth client_host client_service client_addr -> server_host
// server_service port observed_by cadence", sorted by bytes.
func (f impactFixture) impact(target string) []string {
	f.t.Helper()
	rows, err := f.conn.Query(context.Background(), fmt.Sprintf(`
SELECT depth || ' ' || coalesce(client_host, '-') || ' ' || client_service || ' ' || coalesce(host(client_addr), '-')
       || ' -> ' || server_host || ' ' || coalesce(server_service, '-') || ' ' || port || ' ' || observed_by || ' ' || coalesce(cadence, '-')
FROM shawk_v1.impact(%s)`, fmt.Sprintf(target, ts(impactSince), ts(impactUntil))))
	if err != nil {
		f.t.Fatal(err)
	}
	out, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil {
		f.t.Fatal(err)
	}
	// Sorted here, not by the database, whose order depends on its
	// collation: C for test/harness/postgres.sh, en_US.utf8 for the postgres
	// image of CI, which sorts "- ~external" after "app-01".
	slices.Sort(out)
	return out
}

// verdict returns the verdict on a target over the period of the tests:
// "verdict reasons caveats direct coverage".
func (f impactFixture) verdict(target string) string {
	f.t.Helper()
	var out string
	err := f.conn.QueryRow(context.Background(), fmt.Sprintf(`
SELECT verdict || ' ' || reasons::text || ' ' || caveats::text || ' ' || direct || ' ' || coverage
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
	f := newImpactFixture(t, conn)
	f.watched("db-01", "10.0.0.10")
	f.watched("app-01", "10.0.0.11")
	f.watched("web-01", "10.0.0.12")
	f.watched("batch-01", "10.0.0.13")
	f.watched("report-01", "10.0.0.14")
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
	checkRows(t, "dependents of db-01", f.impact(`'db-01', %s, %s, cadence_depth => 3`), []string{
		"1 app-01 app - -> db-01 postgres 5432 both continuous",
		"1 app-01 app - -> db-01 redis 6379 both continuous",
		"1 batch-01 billing - -> db-01 postgres 5432 both monthly",
		"1 nas-01 ~unresolved 10.0.9.9 -> db-01 postgres 5432 server one-off",
		"2 web-01 web - -> app-01 app 8080 both continuous",
		"3 - ~external 0.0.0.0 -> web-01 web 443 server continuous",
		"3 report-01 report - -> web-01 web 443 both daily",
	})
	// The cadence is that of the dependents of depth 1 unless asked for:
	// it reads the hours of every dependent.
	checkRows(t, "dependents of db-01, with the cadence of the first depth", f.impact(`'db-01', %s, %s`), []string{
		"1 app-01 app - -> db-01 postgres 5432 both continuous",
		"1 app-01 app - -> db-01 redis 6379 both continuous",
		"1 batch-01 billing - -> db-01 postgres 5432 both monthly",
		"1 nas-01 ~unresolved 10.0.9.9 -> db-01 postgres 5432 server one-off",
		"2 web-01 web - -> app-01 app 8080 both -",
		"3 - ~external 0.0.0.0 -> web-01 web 443 server -",
		"3 report-01 report - -> web-01 web 443 both -",
	})
	if got := queryStrings(t, f.conn, fmt.Sprintf(`SELECT count(*), count(cadence), count(runs) FROM shawk_v1.impact('db-01', %s, %s, cadence_depth => 0)`,
		ts(impactSince), ts(impactUntil))); !slices.Equal(got, []string{"7 0 0"}) {
		t.Errorf("dependents of db-01 without cadences: %v, want 7 0 0", got)
	}
	checkRows(t, "dependents of db-01 at depth 1", f.impact(`'db-01', %s, %s, max_depth => 1`), []string{
		"1 app-01 app - -> db-01 postgres 5432 both continuous",
		"1 app-01 app - -> db-01 redis 6379 both continuous",
		"1 batch-01 billing - -> db-01 postgres 5432 both monthly",
		"1 nas-01 ~unresolved 10.0.9.9 -> db-01 postgres 5432 server one-off",
	})
	// redis alone: app, and what depends on app.
	checkRows(t, "dependents of redis on db-01", f.impact(`'db-01', %s, %s, 'redis', max_depth => 2, cadence_depth => 2`), []string{
		"1 app-01 app - -> db-01 redis 6379 both continuous",
		"2 web-01 web - -> app-01 app 8080 both continuous",
	})
	// postgres alone: backup, on the host, would break too.
	checkRows(t, "dependents of postgres on db-01", f.impact(`'db-01', %s, %s, 'postgres', max_depth => 1`), []string{
		"1 app-01 app - -> db-01 postgres 5432 both continuous",
		"1 batch-01 billing - -> db-01 postgres 5432 both monthly",
		"1 db-01 backup - -> db-01 postgres 5432 both daily",
		"1 nas-01 ~unresolved 10.0.9.9 -> db-01 postgres 5432 server one-off",
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

// TestPGImpactDepth: the dependents are followed to max_depth, which is 10
// at most and 1 at least.
func TestPGImpactDepth(t *testing.T) {
	_, conn := migratedDB(t)
	f := newImpactFixture(t, conn)
	// c-00 is used by c-01, which is used by c-02, and so on to c-13.
	for i := range 14 {
		f.watched(fmt.Sprintf("c-%02d", i), fmt.Sprintf("10.0.3.%d", i))
	}
	for i := range 13 {
		f.both(fmt.Sprintf("c-%02d", i+1), "svc", fmt.Sprintf("10.0.3.%d", i+1), fmt.Sprintf("c-%02d", i), "svc", fmt.Sprintf("10.0.3.%d", i),
			8080, impactSince, impactUntil)
	}
	for depth, want := range map[string]string{"NULL": "3 3", "0": "1 1", "-5": "1 1", "1": "1 1", "7": "7 7", "10": "10 10", "11": "10 10", "100000": "10 10"} {
		got := queryStrings(t, conn, fmt.Sprintf(`SELECT count(*), max(depth) FROM shawk_v1.impact('c-00', %s, %s, max_depth => %s)`,
			ts(impactSince), ts(impactUntil), depth))
		if !slices.Equal(got, []string{want}) {
			t.Errorf("max_depth %s: rows and depth = %v, want %s", depth, got, want)
		}
	}
}

// TestPGImpactPlans: the dependents are computed without nested loops that
// compare every dependency with every other one, which took minutes on a
// fleet of 2000 hosts. The plans of the statements of the functions are
// read with auto_explain, where the role of the tests may load it.
func TestPGImpactPlans(t *testing.T) {
	f := impactFleet(t)
	ctx := context.Background()
	if got := queryStrings(t, f.conn, `SELECT array_to_string(proconfig, ' ') FROM pg_proc WHERE oid = 'shawk.dependents'::regproc`); len(got) != 1 ||
		!strings.Contains(got[0], "enable_nestloop=off") || !strings.Contains(got[0], "jit=off") {
		t.Errorf("settings of shawk.dependents = %v, want nested loops and the JIT compiler off", got)
	}
	if got := queryStrings(t, f.conn, `SELECT array_to_string(proconfig, ' ') FROM pg_proc WHERE oid = 'shawk.dependencies_in'::regproc`); len(got) != 1 ||
		!strings.Contains(got[0], "enable_nestloop=on") {
		t.Errorf("settings of shawk.dependencies_in = %v, want nested loops on", got)
	}
	cfg := f.conn.Config().Copy()
	var plans []string
	cfg.OnNotice = func(_ *pgconn.PgConn, n *pgconn.Notice) {
		if i := strings.Index(n.Message, "{"); i >= 0 && strings.Contains(n.Message, "plan:") {
			plans = append(plans, n.Message[i:])
		}
	}
	conn, err := pgx.ConnectConfig(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close(ctx)
	if _, err := conn.Exec(ctx, `LOAD 'auto_explain'`); err != nil {
		t.Skipf("auto_explain cannot be loaded: %v", err)
	}
	execAll(t, conn, `SET auto_explain.log_min_duration = 0`, `SET auto_explain.log_nested_statements = on`,
		`SET auto_explain.log_format = json`, `SET client_min_messages = log`)
	period := ts(impactSince) + ", " + ts(impactUntil)
	execAll(t, conn, `SELECT * FROM shawk_v1.impact('db-01', `+period+`, max_depth => 5)`,
		`SELECT * FROM shawk_v1.impact_verdict('db-01', `+period+`, 'postgres')`)
	// The nested loops left are those that have no other plan: the
	// lookups of one row at a time, which have no condition of their own.
	// Nor does a join compare ranges, as that of every period of an
	// address with every stretch of its host did, and the addresses that
	// hosts held are read for the period asked for, not for the retention:
	// each scan of them is bound by the time they were last seen.
	var loops func(node map[string]any, text string)
	walked, addrs := 0, 0
	loops = func(node map[string]any, text string) {
		walked++
		if node["Node Type"] == "Nested Loop" && node["Join Filter"] != nil {
			t.Errorf("a nested loop with the condition %v in the plan of:\n%.300s", node["Join Filter"], text)
		}
		if cond := fmt.Sprint(node["Join Filter"], node["Hash Cond"], node["Merge Cond"]); strings.Contains(cond, "@>") || strings.Contains(cond, "&&") {
			t.Errorf("a join on ranges, %v, in the plan of:\n%.300s", cond, text)
		}
		if node["Relation Name"] == "host_addrs" {
			addrs++
			if cond := fmt.Sprint(node["Index Cond"], node["Filter"], node["Recheck Cond"]); !strings.Contains(cond, "last_seen") {
				t.Errorf("a scan of shawk.host_addrs without a bound on last_seen (%v) in the plan of:\n%.300s", cond, text)
			}
		}
		children, _ := node["Plans"].([]any)
		for _, c := range children {
			if m, ok := c.(map[string]any); ok {
				loops(m, text)
			}
		}
	}
	dependents := 0
	for _, raw := range plans {
		var p struct {
			Text string         `json:"Query Text"`
			Plan map[string]any `json:"Plan"`
		}
		if err := json.Unmarshal([]byte(raw), &p); err != nil {
			t.Fatalf("plan: %v\n%.300s", err, raw)
		}
		if strings.Contains(p.Text, "WITH RECURSIVE") && strings.Contains(p.Text, "walk") {
			dependents++
			loops(p.Plan, p.Text)
		}
	}
	if dependents != 2 || walked < 100 || addrs < 4 {
		t.Errorf("%d plans of shawk.dependents with %d nodes and %d scans of shawk.host_addrs among %d plans, want 2 of them",
			dependents, walked, addrs, len(plans))
	}
}

// TestPGImpactVerdict: a target with dependents is UNSAFE; without any, it
// is SAFE only if an agent observed it over the whole period, everything
// the target covers, and INCONCLUSIVE otherwise.
func TestPGImpactVerdict(t *testing.T) {
	f := impactFleet(t)
	// Dependents: unsafe, whatever the coverage.
	if got, want := f.verdict(`'db-01', %s, %s`), "UNSAFE {active_dependents} {} 3 1.000000"; got != want {
		t.Errorf("db-01: %s, want %s", got, want)
	}
	if got, want := f.verdict(`'db-01', %s, %s, 'redis'`), "UNSAFE {active_dependents} {} 1 1.000000"; got != want {
		t.Errorf("redis of db-01: %s, want %s", got, want)
	}
	// Observed all along and used by none but itself.
	f.watched("idle-01", "10.0.1.1")
	f.edge("idle-01", "cron", "client", "127.0.0.1", "127.0.0.1", 22, impactSince, impactUntil)
	f.edge("idle-01", "sshd", "server", "127.0.0.1", "127.0.0.1", 22, impactSince, impactUntil)
	// A client that binds an address of the host and connects to loopback
	// is matched with its server within the host: one of its own too.
	f.edge("idle-01", "cron", "client", "10.0.1.1", "127.0.0.1", 25, impactSince, impactUntil)
	f.edge("idle-01", "postfix", "server", "127.0.0.1", "10.0.1.1", 25, impactSince, impactUntil)
	if got, want := f.verdict(`'idle-01', %s, %s`), "SAFE {} {} 0 1.000000"; got != want {
		t.Errorf("idle-01: %s, want %s", got, want)
	}
	// Its sshd is used by its cron: unsafe to remove alone.
	if got, want := f.verdict(`'idle-01', %s, %s, 'sshd'`), "UNSAFE {active_dependents} {} 1 1.000000"; got != want {
		t.Errorf("sshd of idle-01: %s, want %s", got, want)
	}
	// A service that connects to itself is no dependent of its own.
	f.exec(`UPDATE shawk.processes SET service_name = 'sshd' WHERE host_id = 'idle-01' AND service_name = 'cron'`)
	if got, want := f.verdict(`'idle-01', %s, %s, 'sshd'`), "SAFE {} {} 0 1.000000"; got != want {
		t.Errorf("sshd of idle-01, used by itself: %s, want %s", got, want)
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
		}, "", "INCONCLUSIVE {not_observed} {} 0 0.999097"},
		// Three minutes after a heartbeat are the delay of writes.
		{"a gap within the tolerance", func(h string) {
			f.host(h, "10.0.2.2")
			f.observed(h, impactSince.Add(-time.Hour), day(30, 0))
			f.observed(h, day(30, 0).Add(3*time.Minute), impactUntil)
		}, "", "SAFE {} {} 0 1.000000"},
		// Ten seconds beyond the tolerance are a gap, however small it is
		// in 90 days.
		{"a gap of ten seconds", func(h string) {
			f.host(h, "10.0.2.20")
			f.observed(h, impactSince.Add(-time.Hour), day(30, 0))
			f.observed(h, day(30, 0).Add(3*time.Minute+10*time.Second), impactUntil)
		}, "", "INCONCLUSIVE {not_observed} {} 0 0.999998"},
		// The coverage is compared as it is, not as it is reported.
		{"a gap of ten seconds, of a caller that accepts a little more", func(h string) {
			f.host(h, "10.0.2.25")
			f.observed(h, impactSince.Add(-time.Hour), day(30, 0))
			f.observed(h, day(30, 0).Add(3*time.Minute+10*time.Second), impactUntil)
		}, ", min_coverage => 0.999999", "INCONCLUSIVE {not_observed} {} 0 0.999998"},
		{"a gap that a longer tolerance covers", func(h string) {
			f.host(h, "10.0.2.26")
			f.observed(h, impactSince.Add(-time.Hour), day(30, 0))
			f.observed(h, day(30, 0).Add(10*time.Minute), impactUntil)
		}, ", tolerance => '15 minutes'", "SAFE {} {} 0 1.000000"},
		// A clock an hour behind: the session started half an hour into the
		// period, and what it saw in its last hour is dated before.
		{"a clock behind", func(h string) {
			f.host(h, "10.0.2.27")
			f.observed(h, impactSince.Add(-30*time.Minute), impactUntil)
			f.exec(`UPDATE shawk.agent_sessions SET clock_skew = '1 hour' WHERE host_id = $1`, h)
		}, "", "INCONCLUSIVE {not_observed} {} 0 0.999328"},
		// A clock an hour ahead: the session started half an hour before
		// the period, and the connector does not write times after its own.
		{"a clock ahead", func(h string) {
			f.host(h, "10.0.2.28")
			f.observed(h, impactSince.Add(30*time.Minute), impactUntil)
			f.exec(`UPDATE shawk.agent_sessions SET clock_skew = '-1 hour' WHERE host_id = $1`, h)
		}, "", "SAFE {} {} 0 1.000000"},
		{"a gap that the caller accepts", func(h string) {
			f.host(h, "10.0.2.3")
			f.observed(h, impactSince.Add(-time.Hour), day(30, 0))
			f.observed(h, day(30, 2), impactUntil)
		}, ", min_coverage => 0.999", "SAFE {} {not_observed} 0 0.999097"},
		{"a period longer than the history", func(h string) {
			f.host(h, "10.0.2.4")
			f.observed(h, day(45, 0), impactUntil)
		}, "", "INCONCLUSIVE {not_observed} {} 0 0.500000"},
		{"an agent that stopped before the period", func(h string) {
			f.host(h, "10.0.2.5")
			f.observed(h, impactSince.Add(-48*time.Hour), impactSince.Add(-24*time.Hour))
		}, "", "INCONCLUSIVE {not_observed} {} 0 0.000000"},
		{"an agent that stopped before the period, and a caller that accepts gaps", func(h string) {
			f.host(h, "10.0.2.6")
		}, ", min_coverage => 0.000001", "INCONCLUSIVE {not_observed} {} 0 0.000000"},
		{"dropped flows", func(h string) {
			f.watched(h, "10.0.2.7")
			f.exec(`INSERT INTO shawk.partial_observations VALUES ($1, $2, $3, $4, 7)`, h, impactSince.Add(-time.Hour), day(5, 0), day(5, 9))
		}, "", "INCONCLUSIVE {dropped_flows} {} 0 0.995833"},
		{"UDP not traced for a day", func(h string) {
			f.host(h, "10.0.2.8")
			f.observed(h, impactSince.Add(-time.Hour), day(89, 0))
			f.session(h, day(89, 0), impactUntil, "false", "true", "'all'")
		}, "", "INCONCLUSIVE {udp_not_traced} {} 0 0.988888"},
		// Dropped from an hour before the period to two hours into it.
		{"dropped flows over the start of the period", func(h string) {
			f.watched(h, "10.0.2.29")
			f.exec(`INSERT INTO shawk.partial_observations VALUES ($1, $2, $3, $4, 7)`, h, impactSince.Add(-time.Hour),
				impactSince.Add(-time.Hour), impactSince.Add(2*time.Hour))
		}, "", "INCONCLUSIVE {dropped_flows} {} 0 0.999074"},
		{"UDP not traced, of a target of UDP", func(h string) {
			f.host(h, "10.0.2.30")
			f.session(h, impactSince, impactUntil, "false", "true", "'all'")
		}, ", target_proto => 'udp'", "INCONCLUSIVE {udp_not_traced} {} 0 0.000000"},
		{"UDP not traced, of a target of TCP", func(h string) {
			f.host(h, "10.0.2.9")
			f.session(h, impactSince, impactUntil, "false", "true", "'all'")
		}, ", target_proto => 'tcp'", "SAFE {} {} 0 1.000000"},
		{"one network namespace", func(h string) {
			f.host(h, "10.0.2.10")
			f.session(h, impactSince, impactUntil, "true", "true", "'4026531840'")
		}, "", "INCONCLUSIVE {netns_limited} {} 0 0.000000"},
		// The clients of a service over Unix sockets are on its host: they
		// matter to a service, not to the host.
		{"Unix sockets not traced, of a host", func(h string) {
			f.host(h, "10.0.2.11")
			f.session(h, impactSince, impactUntil, "true", "NULL", "'all'")
		}, "", "SAFE {} {} 0 1.000000"},
		{"Unix sockets not traced, of a service", func(h string) {
			f.host(h, "10.0.2.12")
			f.listens(h, "postgres", 5432)
			f.session(h, impactSince, impactUntil, "true", "NULL", "'all'")
		}, ", 'postgres'", "INCONCLUSIVE {unix_not_traced} {} 0 0.000000"},
		{"Unix sockets not traced, of a port", func(h string) {
			f.host(h, "10.0.2.13")
			f.listens(h, "postgres", 5432)
			f.session(h, impactSince, impactUntil, "true", "false", "'all'")
		}, ", target_port => 5432", "SAFE {} {} 0 1.000000"},
		// A service that the host does not run, or a name mistyped: nothing
		// used it, which tells nothing.
		{"a service the host does not have", func(h string) {
			f.watched(h, "10.0.2.17")
			f.listens(h, "postgres", 5432)
		}, ", 'postgress'", "INCONCLUSIVE {unknown_service} {} 0 1.000000"},
		{"a service the host had before the period", func(h string) {
			f.watched(h, "10.0.2.18")
			f.listener(h, "postgres", 5432, impactSince.Add(-20*24*time.Hour), impactSince.Add(-time.Hour))
		}, ", 'postgres'", "INCONCLUSIVE {unknown_service} {} 0 1.000000"},
		{"a service that listens and has no client", func(h string) {
			f.watched(h, "10.0.2.19")
			f.listens(h, "postgres", 5432)
		}, ", 'postgres', 5432, 'tcp'", "SAFE {} {} 0 1.000000"},
		{"a port nothing listens on", func(h string) {
			f.watched(h, "10.0.2.21")
			f.listens(h, "postgres", 5432)
		}, ", target_port => 5433", "INCONCLUSIVE {unknown_port} {} 0 1.000000"},
		{"a port of another transport", func(h string) {
			f.watched(h, "10.0.2.22")
			f.listens(h, "postgres", 5432)
		}, ", target_port => 5432, target_proto => 'udp'", "INCONCLUSIVE {unknown_port} {} 0 1.000000"},
		// A port known from the connections it served, those of the
		// service to itself, of a listener that was not seen.
		{"a port that served without a listener seen", func(h string) {
			f.watched(h, "10.0.2.23")
			f.both(h, "postgres", "127.0.0.1", h, "postgres", "127.0.0.1", 5432, day(1, 0), day(2, 0))
		}, ", target_port => 5432", "SAFE {} {} 0 1.000000"},
		// A port of another service of the host: no port of the service.
		{"a service and a port of another service", func(h string) {
			f.watched(h, "10.0.2.31")
			f.listens(h, "postgres", 5432)
			f.listens(h, "app", 8080)
		}, ", 'app', 5432", "INCONCLUSIVE {unknown_port} {} 0 1.000000"},
		// A port whose listener has no known owner may be of the service.
		{"a service and a port without a known owner", func(h string) {
			f.watched(h, "10.0.2.32")
			f.listens(h, "app", 8080)
			f.exec(`INSERT INTO shawk.listeners (host_id, process_id, proto, addr, port, netns, first_seen, last_seen)
				VALUES ($1, NULL, 'tcp', '0.0.0.0', 9000, 1, $2, $3)`, h, impactSince, impactUntil)
		}, ", 'app', 9000", "SAFE {} {} 0 1.000000"},
		{"a service and a port that the host does not have, not observed all along", func(h string) {
			f.host(h, "10.0.2.24")
			f.observed(h, day(45, 0), impactUntil)
		}, ", 'postgres', 5432", "INCONCLUSIVE {not_observed,unknown_service,unknown_port} {} 0 0.500000"},
		{"a name no agent reported under", func(string) {}, "", "INCONCLUSIVE {unknown_host} {} 0 0.000000"},
		{"a host of the inventory without an agent", func(h string) {
			f.exec(`INSERT INTO shawk.inventory_hosts (host, agent) VALUES ($1, false)`, h)
			f.exec(`INSERT INTO shawk.inventory_addrs VALUES ('10.0.2.15', $1)`, h)
		}, "", "INCONCLUSIVE {no_agent} {} 0 0.000000"},
		// A node whose machine id changed at a boot: two hosts of one name.
		{"two host ids of one name", func(h string) {
			f.host(h, "10.0.2.16")
			f.observed(h, impactSince.Add(-time.Hour), day(30, 0))
			f.exec(`INSERT INTO shawk.hosts VALUES ($1, 'm2', $2, 'k', 'v', $3, $4)`, h+"-b", h, day(30, 0), impactUntil)
			f.observed(h+"-b", day(30, 0).Add(time.Minute), impactUntil)
		}, "", "SAFE {} {} 0 1.000000"},
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
	if got, want := f.verdict(`'db-01', %s, %s`), "UNSAFE {active_dependents} {not_observed} 3 0.988888"; got != want {
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
		`SELECT * FROM shawk_v1.impact_verdict('db-01', now() - interval '1 day', now(), target_proto => 'unix')`,
		`SELECT * FROM shawk_v1.impact_verdict('db-01', now() - interval '1 day', now(), 'postgres', 5432, 'unix')`,
		`SELECT * FROM shawk_v1.impact_verdict('db-01', now() - interval '1 day', now(), tolerance => '2 hours')`,
		`SELECT * FROM shawk_v1.impact_verdict('db-01', now() - interval '1 day', now(), tolerance => '-1 second')`,
		`SELECT * FROM shawk_v1.impact_verdict('db-01', now() - interval '1 day', now(), tolerance => NULL)`,
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
	f := newImpactFixture(t, conn)
	// db-01 was not observed on the day app-01 used its postgres, and
	// listened on 5432 (postgres) and 6379 (redis) around it.
	f.host("db-01", "10.0.0.10", "172.17.0.1")
	f.observed("db-01", impactSince.Add(-time.Hour), day(20, 0))
	f.observed("db-01", day(21, 0), impactUntil)
	f.listens("db-01", "postgres", 5432)
	f.listens("db-01", "redis", 6379)
	f.watched("app-01", "10.0.0.11", "172.17.0.1")
	f.edge("app-01", "app", "client", "10.0.0.11", "10.0.0.10", 5432, day(20, 3), day(20, 5))
	f.active("app-01", "app", 5432, day(20, 3), day(20, 5), time.Hour, 1)
	// A probe of a port nothing listens on, which fails.
	f.edge("app-01", "probe", "client", "10.0.0.11", "10.0.0.10", 9999, day(40, 0), day(40, 1))
	// The gateway of the container bridge, which every host holds: app-01
	// connects to its own.
	f.edge("app-01", "app", "client", "172.17.0.2", "172.17.0.1", 8080, impactSince, impactUntil)
	// An address db-01 held before another host took it.
	f.watched("new-01")
	f.held("db-01", "10.0.0.20", impactSince.Add(-time.Hour), day(9, 0))
	f.held("new-01", "10.0.0.20", day(10, 0), impactUntil)
	f.edge("app-01", "app", "client", "10.0.0.11", "10.0.0.20", 443, day(50, 0), day(50, 1))

	checkRows(t, "dependents of db-01", f.impact(`'db-01', %s, %s`), []string{
		"1 app-01 app - -> db-01 postgres 5432 client one-off",
		"1 app-01 probe - -> db-01 - 9999 client one-off",
	})
	if got, want := f.verdict(`'db-01', %s, %s`), "UNSAFE {active_dependents} {not_observed} 2 0.988912"; got != want {
		t.Errorf("db-01: %s, want %s", got, want)
	}
	checkRows(t, "dependents of postgres on db-01", f.impact(`'db-01', %s, %s, 'postgres'`), []string{
		"1 app-01 app - -> db-01 postgres 5432 client one-off",
	})
	// redis: neither the client of postgres nor the probe of a port
	// without a listener, but the gap leaves it open.
	checkRows(t, "dependents of redis on db-01", f.impact(`'db-01', %s, %s, 'redis'`), nil)
	if got, want := f.verdict(`'db-01', %s, %s, 'redis'`), "INCONCLUSIVE {not_observed} {} 0 0.988912"; got != want {
		t.Errorf("redis of db-01: %s, want %s", got, want)
	}
	checkRows(t, "dependents of port 9999 of db-01", f.impact(`'db-01', %s, %s, target_port => 9999`), []string{
		"1 app-01 probe - -> db-01 - 9999 client one-off",
	})
	// A port whose owner is not known, used while db-01 was not observed:
	// it may have been of any service of db-01 then.
	f.edge("app-01", "app", "client", "10.0.0.11", "10.0.0.10", 7777, day(20, 6), day(20, 7))
	for _, svc := range []string{"redis", "postgres"} {
		if got := f.impact(`'db-01', %s, %s, '` + svc + `'`); !slices.Contains(got, "1 app-01 app - -> db-01 - 7777 client one-off") {
			t.Errorf("dependents of %s on db-01: %v, want the client of port 7777", svc, got)
		}
	}
	if got, want := f.verdict(`'db-01', %s, %s, 'redis', min_coverage => 0.9`), "UNSAFE {active_dependents} {not_observed} 1 0.988912"; got != want {
		t.Errorf("redis of db-01, with the client of a port without an owner: %s, want %s", got, want)
	}
	f.exec(`DELETE FROM shawk.edges WHERE port = 7777`)
	checkRows(t, "dependents of new-01", f.impact(`'new-01', %s, %s`), []string{
		"1 app-01 app - -> new-01 - 443 client one-off",
	})

	// gone-01 was last observed on day 5, holding an address that heir-01
	// reports since it was first observed, on day 40. In between the
	// address may be of either; since then it is of heir-01.
	f.host("gone-01", "10.0.0.30")
	f.observed("gone-01", impactSince.Add(-time.Hour), day(5, 0))
	f.host("heir-01", "10.0.0.30")
	f.observed("heir-01", day(40, 0), impactUntil)
	f.edge("app-01", "app", "client", "10.0.0.11", "10.0.0.30", 111, day(20, 0), day(20, 1))
	f.edge("app-01", "app", "client", "10.0.0.11", "10.0.0.30", 222, day(60, 0), day(60, 1))
	checkRows(t, "dependents of gone-01", f.impact(`'gone-01', %s, %s`), []string{
		"1 app-01 app - -> gone-01 - 111 client one-off",
	})
	checkRows(t, "dependents of heir-01", f.impact(`'heir-01', %s, %s`), []string{
		"1 app-01 app - -> heir-01 - 111 client one-off",
		"1 app-01 app - -> heir-01 - 222 client one-off",
	})

	// early-01 came and went for a year, and was last observed two days
	// before the period, with two addresses: it may still hold them in the
	// period, not one it reported at an earlier stop, nor one it dropped an
	// hour before it stopped. Only the last report before the period is
	// read, not the history of the year.
	f.host("early-01", "10.0.0.40", "10.0.0.41")
	for d := 360; d > 2; d -= 3 {
		f.observed("early-01", impactSince.Add(-time.Duration(d)*24*time.Hour), impactSince.Add(-time.Duration(d-1)*24*time.Hour))
		f.held("early-01", fmt.Sprintf("10.9.%d.%d", d/100, d%100), impactSince.Add(-time.Duration(d)*24*time.Hour), impactSince.Add(-time.Duration(d-1)*24*time.Hour))
	}
	f.held("early-01", "10.0.0.42", impactSince.Add(-3*24*time.Hour), impactSince.Add(-49*time.Hour))
	for port, addr := range map[int]string{340: "10.0.0.40", 341: "10.0.0.41", 342: "10.0.0.42", 343: "10.9.0.6", 344: "10.9.0.60"} {
		f.edge("app-01", "app", "client", "10.0.0.11", addr, port, day(30, 0), day(30, 1))
	}
	checkRows(t, "dependents of early-01", f.impact(`'early-01', %s, %s`), []string{
		"1 app-01 app - -> early-01 - 340 client one-off",
		"1 app-01 app - -> early-01 - 341 client one-off",
	})
	if got, want := f.verdict(`'early-01', %s, %s`), "UNSAFE {active_dependents} {not_observed} 1 0.000000"; got != want {
		t.Errorf("early-01: %s, want %s", got, want)
	}

	// A host of the inventory without an agent: its clients with an agent
	// are its dependents, whatever its service, of which nothing is known.
	f.exec(`INSERT INTO shawk.inventory_hosts (host, agent) VALUES ('sfa-01', false)`)
	f.exec(`INSERT INTO shawk.inventory_addrs VALUES ('10.0.9.5', 'sfa-01')`)
	if got, want := f.verdict(`'sfa-01', %s, %s`), "INCONCLUSIVE {no_agent} {} 0 0.000000"; got != want {
		t.Errorf("sfa-01 without clients: %s, want %s", got, want)
	}
	f.edge("app-01", "app", "client", "10.0.0.11", "10.0.9.5", 2049, impactSince, impactUntil)
	f.active("app-01", "app", 2049, impactSince, impactUntil, time.Hour, 1)
	for _, target := range []string{`'sfa-01', %s, %s`, `'sfa-01', %s, %s, 'nfs'`} {
		checkRows(t, "dependents of "+target, f.impact(target), []string{
			"1 app-01 app - -> sfa-01 - 2049 client continuous",
		})
		if got, want := f.verdict(target), "UNSAFE {active_dependents} {no_agent} 1 0.000000"; got != want {
			t.Errorf("%s: %s, want %s", target, got, want)
		}
	}
}

// TestPGImpactWhileTheAgentWasDown: a dependency that its client alone saw
// while the agent of its server was stopped counts for the server, whose
// addresses the connector stops refreshing then: for a day, and for good.
// The rows are those the connector writes.
func TestPGImpactWhileTheAgentWasDown(t *testing.T) {
	c, sink, conn := pgConnector(t)
	ctx := context.Background()
	start := impactSince
	end := start.Add(10 * 24 * time.Hour)
	now := start
	c.now = func() time.Time { return now }
	listener := func(svc string, first time.Time) []tListener {
		return []tListener{{proto: "tcp", addr: "0.0.0.0", port: 5432, svc: svc, comm: svc, unit: svc + ".service", first: first, last: now}}
	}
	// billing on app-01 uses db-01 on day 5 and old-01 on day 7, for 2 hours.
	job := func(peer string, from time.Time) []tEdge {
		if now.Before(from) || now.After(from.Add(2*time.Hour+10*time.Minute)) {
			return nil
		}
		last := now
		if to := from.Add(2 * time.Hour); last.After(to) {
			last = to
		}
		return []tEdge{{role: "client", proto: "tcp", local: "10.0.0.11", peer: peer, port: 5432, svc: "billing", comm: "billing",
			unit: "billing.service", opened: 1, first: from, last: last}}
	}
	for ; !now.After(end); now = now.Add(time.Minute) {
		d := int(now.Sub(start) / (24 * time.Hour))
		// The agent of db-01 is stopped on day 5, that of old-01 from day 3.
		if d != 5 {
			segment := start
			if d > 5 {
				segment = start.Add(6 * 24 * time.Hour)
			}
			consume(t, c, sink, tAgent{host: "db-01", machineID: "m-db", addrs: []string{"10.0.0.10"}, time: now, segment: segment,
				listeners: listener("postgres", segment)})
		}
		if d < 3 {
			consume(t, c, sink, tAgent{host: "old-01", machineID: "m-old", addrs: []string{"10.0.0.20"}, time: now, segment: start,
				listeners: listener("mysql", start)})
		}
		app := tAgent{host: "app-01", machineID: "m-app", addrs: []string{"10.0.0.11"}, time: now, segment: start}
		app.edges = append(job("10.0.0.10", start.Add(5*24*time.Hour+3*time.Hour)), job("10.0.0.20", start.Add(7*24*time.Hour))...)
		consume(t, c, sink, app)
		if now.Minute()%10 == 0 {
			c.flush(ctx)
		}
	}
	c.flush(ctx)
	// The address of db-01 has a period before and one after the day.
	if got := queryStrings(t, conn, `SELECT count(*) FROM shawk.host_addrs a JOIN shawk.hosts h ON h.id = a.host_id
		WHERE h.hostname = 'db-01'`); !slices.Equal(got, []string{"2"}) {
		t.Fatalf("%v periods of the address of db-01, want 2", got)
	}
	period := ts(start) + ", " + ts(end)
	impact := func(host string) []string {
		return queryStrings(t, conn, `SELECT client_host, client_service, server_host, server_service, port, observed_by
			FROM shawk_v1.impact('`+host+`', `+period+`)`)
	}
	verdict := func(target string) []string {
		return queryStrings(t, conn, `SELECT verdict, reasons::text, caveats::text, direct FROM shawk_v1.impact_verdict(`+target+`)`)
	}
	checkRows(t, "dependents of db-01", impact("db-01"), []string{"app-01 billing db-01 postgres 5432 client"})
	checkRows(t, "dependents of old-01", impact("old-01"), []string{"app-01 billing old-01 mysql 5432 client"})
	// Whatever the coverage that the caller accepts.
	for _, target := range []string{`'db-01', ` + period, `'db-01', ` + period + `, min_coverage => 0.85`,
		`'old-01', ` + period + `, min_coverage => 0.25`, `'db-01', ` + period + `, target_port => 5432, min_coverage => 0.85`} {
		checkRows(t, "verdict on "+target, verdict(target), []string{"UNSAFE {active_dependents} {not_observed} 1"})
	}
	checkRows(t, "dependents of app-01", impact("app-01"), nil)
}

// TestPGImpactOfAService: the clients of a service without an agent, and
// those on its own host over loopback and Unix sockets, are its
// dependents. A client of a Unix socket without a server counts for the
// services that listen on its name in other namespaces, and for every
// service when no listener of the name is known, unless its attempts all
// failed.
func TestPGImpactOfAService(t *testing.T) {
	_, conn := migratedDB(t)
	f := newImpactFixture(t, conn)
	f.watched("db-01", "10.0.0.10")
	// A client without an agent, seen by postgres alone.
	f.edge("db-01", "postgres", "server", "10.0.0.10", "10.0.5.5", 5432, impactSince, impactUntil)
	f.active("db-01", "postgres", 5432, impactSince, impactUntil, time.Hour, 1)
	f.listens("db-01", "redis", 6379)
	// app, on the host, reads postgres over its Unix socket, and probe
	// tries the socket of nscd, which nothing serves.
	const socket = "/run/postgresql/.s.PGSQL.5432"
	f.unixListener("db-01", "postgres", socket, impactNetns)
	f.unixEdge("db-01", "app", socket, true)
	f.unixEdge("db-01", "probe", "/var/run/nscd/socket", false)
	checkRows(t, "dependents of postgres on db-01", f.impact(`'db-01', %s, %s, 'postgres'`), []string{
		"1 - ~unresolved 10.0.5.5 -> db-01 postgres 5432 server continuous",
		"1 db-01 app - -> db-01 postgres 0 both continuous",
	})
	// The host as a whole: its own clients go with it.
	checkRows(t, "dependents of db-01", f.impact(`'db-01', %s, %s`), []string{
		"1 - ~unresolved 10.0.5.5 -> db-01 postgres 5432 server continuous",
	})
	checkRows(t, "dependents of redis on db-01", f.impact(`'db-01', %s, %s, 'redis'`), nil)
	if got, want := f.verdict(`'db-01', %s, %s, 'redis'`), "SAFE {} {} 0 1.000000"; got != want {
		t.Errorf("redis of db-01: %s, want %s", got, want)
	}
	checkRows(t, "dependents of db-01 over Unix sockets", f.impact(`'db-01', %s, %s, 'postgres', target_proto => 'unix'`), []string{
		"1 db-01 app - -> db-01 postgres 0 both continuous",
	})

	// The socket of mysql is served in two containers, neither in the
	// namespace of its client: the client is that of mysql, not of redis.
	f.unixListener("db-01", "mysql", "/run/mysqld/mysqld.sock", 4026532001)
	f.unixListener("db-01", "mysql", "/run/mysqld/mysqld.sock", 4026532002)
	f.unixEdge("db-01", "report", "/run/mysqld/mysqld.sock", true)
	checkRows(t, "dependents of mysql on db-01", f.impact(`'db-01', %s, %s, 'mysql'`), []string{
		"1 db-01 report - -> db-01 mysql 0 client continuous",
	})
	checkRows(t, "dependents of redis on db-01, with a client of mysql", f.impact(`'db-01', %s, %s, 'redis'`), nil)
	// A socket whose listener was never seen, with connections: it may be
	// of any service. Also one that a connector wrote without telling.
	f.unixEdge("db-01", "worker", "/run/queue.sock", true)
	f.unixEdge("db-01", "legacy", "/run/old.sock", true)
	f.exec(`UPDATE shawk.unix_edges SET established = NULL WHERE path = '/run/old.sock'`)
	unowned := []string{
		"1 db-01 legacy - -> db-01 ~unknown 0 client continuous",
		"1 db-01 worker - -> db-01 ~unknown 0 client continuous",
	}
	checkRows(t, "dependents of redis on db-01, with sockets without a listener", f.impact(`'db-01', %s, %s, 'redis'`), unowned)
	if got, want := f.verdict(`'db-01', %s, %s, 'redis'`), "UNSAFE {active_dependents} {} 2 1.000000"; got != want {
		t.Errorf("redis of db-01, with sockets without a listener: %s, want %s", got, want)
	}
	// Not for the service of the client itself, nor for the host.
	checkRows(t, "dependents of worker on db-01", f.impact(`'db-01', %s, %s, 'worker'`), unowned[:1])
	checkRows(t, "dependents of db-01, with sockets without a listener", f.impact(`'db-01', %s, %s`), []string{
		"1 - ~unresolved 10.0.5.5 -> db-01 postgres 5432 server continuous",
	})
}

// TestPGImpactUnixAttempts: the connector tells the edges of Unix sockets
// with established connections from those of failed attempts only: the
// processes that try a socket nothing serves are no dependents of the
// services of their host, and those connected to a socket whose listener
// was not seen are.
func TestPGImpactUnixAttempts(t *testing.T) {
	c, sink, conn := pgConnector(t)
	ctx := context.Background()
	start := impactSince
	now := start
	c.now = func() time.Time { return now }
	traced := true
	// established tells, per socket, since when its client has an open
	// connection.
	send := func(established map[string]time.Time) {
		a := tAgent{host: "db-01", machineID: "m-db", addrs: []string{"10.0.0.10"}, time: now, segment: start, unixTraced: &traced,
			listeners: []tListener{{proto: "tcp", addr: "0.0.0.0", port: 6379, svc: "redis", comm: "redis", unit: "redis.service", first: start, last: now}}}
		for svc, path := range map[string]string{"cron": "/var/run/nscd/socket", "worker": "/run/queue.sock"} {
			e := tEdge{role: "client", proto: "unix", path: path, svc: svc, comm: svc, unit: svc + ".service", first: start, last: now}
			if since, ok := established[path]; ok && !now.Before(since) {
				e.opened, e.count = 1, 1
			} else {
				e.failed = int64(now.Sub(start)/time.Minute) + 1
			}
			a.edges = append(a.edges, e)
		}
		consume(t, c, sink, a)
	}
	flags := func() []string {
		c.flush(ctx)
		return queryStrings(t, conn, `SELECT path, established FROM shawk.unix_edges ORDER BY path`)
	}
	dependents := func() []string {
		return queryStrings(t, conn, `SELECT client_service, server_service, observed_by FROM shawk_v1.impact('db-01', $1, $2, 'redis')`, start, now)
	}
	for ; now.Before(start.Add(2 * time.Hour)); now = now.Add(time.Minute) {
		send(map[string]time.Time{"/run/queue.sock": start})
	}
	checkRows(t, "edges", flags(), []string{"/run/queue.sock true", "/var/run/nscd/socket false"})
	checkRows(t, "dependents of redis", dependents(), []string{"worker ~unknown client"})
	if got := queryStrings(t, conn, `SELECT verdict, reasons::text, caveats::text FROM shawk_v1.impact_verdict('db-01', $1, $2, 'redis')`,
		start, now); !slices.Equal(got, []string{"UNSAFE {active_dependents} {}"}) {
		t.Errorf("verdict on redis: %v", got)
	}
	// The worker is gone, by a connector that knows nothing of before: the
	// attempts of cron alone leave redis without dependents.
	execAll(t, conn, `DELETE FROM shawk.unix_edges WHERE path = '/run/queue.sock'`)
	if got := queryStrings(t, conn, `SELECT verdict, reasons::text, caveats::text FROM shawk_v1.impact_verdict('db-01', $1, $2, 'redis')`,
		start, now); !slices.Equal(got, []string{"SAFE {} {}"}) {
		t.Errorf("verdict on redis without the worker: %v", got)
	}
	// A connection of cron is established an hour later, and attempts fail
	// again after: the edge stays one with connections.
	for ; now.Before(start.Add(3 * time.Hour)); now = now.Add(time.Minute) {
		send(map[string]time.Time{"/var/run/nscd/socket": start.Add(150 * time.Minute)})
	}
	checkRows(t, "edges once cron connected", flags(), []string{"/run/queue.sock false", "/var/run/nscd/socket true"})
	c.changes = newChanges(c.cfg.IdleTTL, c.cfg.JobUsers)
	for ; now.Before(start.Add(4 * time.Hour)); now = now.Add(time.Minute) {
		send(nil)
	}
	checkRows(t, "edges once cron fails again", flags(), []string{"/run/queue.sock false", "/var/run/nscd/socket true"})
	checkRows(t, "dependents of redis once cron connected", dependents(), []string{"cron ~unknown client"})
}

// TestPGImpactOfAPort: the clients of a port are all but the process that
// serves it: another unit of the same service on the host is a dependent.
func TestPGImpactOfAPort(t *testing.T) {
	_, conn := migratedDB(t)
	f := newImpactFixture(t, conn)
	f.watched("db-01", "10.0.0.10")
	// Two clusters of PostgreSQL, both named postgres: the new one, on
	// 5433, replicates from the old one, on 5432, over loopback.
	f.listens("db-01", "postgresql@14-main/postgres", 5432)
	f.listens("db-01", "postgresql@16-main/postgres", 5433)
	f.edge("db-01", "postgresql@16-main/postgres", "client", "127.0.0.1", "127.0.0.1", 5432, impactSince, impactUntil)
	f.edge("db-01", "postgresql@14-main/postgres", "server", "127.0.0.1", "127.0.0.1", 5432, impactSince, impactUntil)
	// The old cluster also connects to itself.
	f.edge("db-01", "postgresql@14-main/postgres", "client", "10.0.0.10", "10.0.0.10", 5432, impactSince, impactUntil)
	f.edge("db-01", "postgresql@14-main/postgres", "server", "10.0.0.10", "10.0.0.10", 5432, impactSince, impactUntil)
	if got, want := f.verdict(`'db-01', %s, %s, target_port => 5432`), "UNSAFE {active_dependents} {} 1 1.000000"; got != want {
		t.Errorf("port 5432 of db-01: %s, want %s", got, want)
	}
	if got, want := f.verdict(`'db-01', %s, %s, target_port => 5433`), "SAFE {} {} 0 1.000000"; got != want {
		t.Errorf("port 5433 of db-01: %s, want %s", got, want)
	}
	// The service is both clusters, and the host all of it.
	for _, target := range []string{`'db-01', %s, %s, 'postgres'`, `'db-01', %s, %s, 'postgres', 5432`, `'db-01', %s, %s`} {
		if got, want := f.verdict(target), "SAFE {} {} 0 1.000000"; got != want {
			t.Errorf("%s: %s, want %s", target, got, want)
		}
	}
}

// TestPGImpactOwnAddress: a connection from an address of the target is
// that of a dependent unless a client on the target explains it, and also
// then when the target replaced the address of a client outside it by its
// own (a NodePort with masquerade): the translation that its agent learned
// tells the client, and where the agent learned none, the verdict tells
// that it cannot know.
func TestPGImpactOwnAddress(t *testing.T) {
	_, conn := migratedDB(t)
	f := newImpactFixture(t, conn)
	// node-a holds the address of its bridge and of a pod, which serves, in
	// its own network namespace, connections that the kernel masqueraded:
	// their peer is the bridge.
	f.watched("node-a", "10.0.0.10", "10.244.1.1", "10.244.1.7")
	f.listens("node-a", "web", 8080)
	f.edge("node-a", "web", "server", "10.244.1.7", "10.244.1.1", 8080, impactSince, impactUntil)
	f.active("node-a", "web", 8080, impactSince, impactUntil, time.Hour, 1)
	f.exec(`UPDATE shawk.edges SET netns = 4026532001 WHERE role = 'server'`)
	// No client on the node explains them: a dependent, at the address of
	// the node. Also when the inventory gives the node that address.
	masqueraded := []string{"1 - ~unresolved 10.244.1.1 -> node-a web 8080 server continuous"}
	checkRows(t, "dependents of node-a", f.impact(`'node-a', %s, %s`), masqueraded)
	if got, want := f.verdict(`'node-a', %s, %s`), "UNSAFE {active_dependents} {} 1 1.000000"; got != want {
		t.Errorf("node-a: %s, want %s", got, want)
	}
	f.exec(`INSERT INTO shawk.inventory_hosts (host) VALUES ('node-a')`)
	f.exec(`INSERT INTO shawk.inventory_addrs VALUES ('10.244.1.1', 'node-a')`)
	checkRows(t, "dependents of node-a, in the inventory", f.impact(`'node-a', %s, %s`), []string{
		"1 node-a ~unresolved 10.244.1.1 -> node-a web 8080 server continuous",
	})
	f.exec(`DELETE FROM shawk.inventory_hosts`)

	// The kubelet of the node probes the pod from the same address, in the
	// namespace of the host: the one edge of the pod for that peer now has
	// a client on the node. The agent learns translations and folds no
	// peer, and learned none: no client outside the node was masqueraded.
	f.edge("node-a", "kubelet", "client", "10.244.1.1", "10.244.1.7", 8080, impactSince, impactUntil)
	checkRows(t, "dependents of node-a, probed by its kubelet", f.impact(`'node-a', %s, %s`), nil)
	if got, want := f.verdict(`'node-a', %s, %s`), "SAFE {} {} 0 1.000000"; got != want {
		t.Errorf("node-a, probed by its kubelet: %s, want %s", got, want)
	}
	// The pod alone is used by the kubelet.
	if got, want := f.verdict(`'node-a', %s, %s, 'web'`), "UNSAFE {active_dependents} {} 1 1.000000"; got != want {
		t.Errorf("web of node-a: %s, want %s", got, want)
	}

	// The agent learned that a client outside connected to the NodePort,
	// which the pod saw from the bridge: a dependent, although the edge of
	// the pod has a client on the node.
	f.learned("node-a", "203.0.113.50", "10.0.0.10", 30080, "10.244.1.1", "10.244.1.7", 8080, day(10, 0), day(20, 0))
	outside := []string{"1 - ~external 203.0.113.50 -> node-a ~relay 30080 server unknown"}
	checkRows(t, "dependents of node-a, with the translation", f.impact(`'node-a', %s, %s`), outside)
	if got, want := f.verdict(`'node-a', %s, %s`), "UNSAFE {active_dependents} {} 1 1.000000"; got != want {
		t.Errorf("node-a, with the translation: %s, want %s", got, want)
	}
	checkRows(t, "dependents of port 30080 of node-a", f.impact(`'node-a', %s, %s, target_port => 30080`), outside)
	// The client outside is one of the port of the pod too, to which the
	// node relays it: also when the client that explains the edge of the
	// pod is a process of the unit that serves the port, a helper of the
	// service in the namespace of the host, which is part of that target.
	f.exec(`UPDATE shawk.edges SET process_id = (SELECT process_id FROM shawk.edges WHERE role = 'server') WHERE role = 'client'`)
	for _, target := range []string{`'node-a', %s, %s`, `'node-a', %s, %s, 'web'`, `'node-a', %s, %s, target_port => 30080`,
		`'node-a', %s, %s, target_port => 8080`, `'node-a', %s, %s, 'web', 8080`} {
		checkRows(t, "dependents of "+target+", probed by the service itself", f.impact(target), outside)
		want := "UNSAFE {active_dependents} {} 1 1.000000"
		if strings.Contains(target, "30080") {
			// No socket listens on the port that the kernel translates.
			want = "UNSAFE {active_dependents} {unknown_port} 1 1.000000"
		}
		if got := f.verdict(target); got != want {
			t.Errorf("%s, probed by the service itself: %s, want %s", target, got, want)
		}
	}
	// Not of another port of the node.
	f.listens("node-a", "sshd", 22)
	if got, want := f.verdict(`'node-a', %s, %s, target_port => 22`), "SAFE {} {} 0 1.000000"; got != want {
		t.Errorf("port 22 of node-a: %s, want %s", got, want)
	}
	f.exec(`UPDATE shawk.edges SET process_id = (SELECT id FROM shawk.processes WHERE service_name = 'kubelet') WHERE role = 'client'`)
	// A port that the node publishes without replacing the address of the
	// client: the pod sees the client, whose row it is, once.
	f.edge("node-a", "web", "server", "10.244.1.7", "198.51.100.7", 8080, day(1, 0), day(2, 0))
	f.learned("node-a", "198.51.100.7", "10.0.0.10", 30080, "198.51.100.7", "10.244.1.7", 8080, day(1, 0), day(2, 0))
	checkRows(t, "dependents of node-a, with a client that kept its address", f.impact(`'node-a', %s, %s`), []string{
		"1 - ~external 198.51.100.7 -> node-a web 8080 server one-off",
		outside[0],
	})
	f.exec(`DELETE FROM shawk.edges WHERE remote_addr = '198.51.100.7'`)
	f.exec(`DELETE FROM shawk.learned_translations`)

	// An agent that folds the peers outside its internal ranges does not
	// learn their translations, nor does one that traces none, and a
	// connector before this one did not tell: the clients outside that the
	// node masqueraded would show nowhere, so the verdict is not SAFE.
	for name, set := range map[string]string{
		"folds external peers":  `peer_fold = 'in'`,
		"traces no translation": `translations_traced = false`,
		"does not tell":         `translations_traced = NULL`,
	} {
		f.exec(`UPDATE shawk.agent_sessions SET peer_fold = 'none', translations_traced = true`)
		f.exec(`UPDATE shawk.agent_sessions SET ` + set)
		if got, want := f.verdict(`'node-a', %s, %s`), "INCONCLUSIVE {masquerade_not_traced} {} 0 0.000000"; got != want {
			t.Errorf("node-a, of an agent that %s: %s, want %s", name, got, want)
		}
		if got, want := f.verdict(`'node-a', %s, %s, target_proto => 'udp'`), "SAFE {} {} 0 1.000000"; got != want {
			t.Errorf("node-a over UDP, of an agent that %s: %s, want %s", name, got, want)
		}
		// The pod alone has the kubelet as a dependent, with the caveat;
		// its port, used by none but the pod itself, is not SAFE either.
		if got, want := f.verdict(`'node-a', %s, %s, 'web'`), "UNSAFE {active_dependents} {masquerade_not_traced} 1 0.000000"; got != want {
			t.Errorf("web of node-a, of an agent that %s: %s, want %s", name, got, want)
		}
		f.exec(`UPDATE shawk.processes SET service_name = 'web', unit = 'web.service' WHERE service_name = 'kubelet'`)
		for _, target := range []string{`'node-a', %s, %s, 'web'`, `'node-a', %s, %s, target_port => 8080`} {
			if got, want := f.verdict(target), "INCONCLUSIVE {masquerade_not_traced} {} 0 0.000000"; got != want {
				t.Errorf("%s, used by the pod itself, of an agent that %s: %s, want %s", target, name, got, want)
			}
		}
		f.exec(`UPDATE shawk.processes SET service_name = 'kubelet', unit = 'kubelet.service' WHERE comm = 'kubelet'`)
	}
	// For the time of the edge of the pod only, and only while the agent
	// did not learn: the pod is gone after day 30, and the agent learns
	// from day 20.
	f.exec(`UPDATE shawk.edges SET last_seen = $1`, day(30, 0))
	f.exec(`DELETE FROM shawk.agent_sessions`)
	f.session("node-a", impactSince.Add(-time.Hour), day(20, 0), "true", "true", "'all'")
	f.exec(`UPDATE shawk.agent_sessions SET peer_fold = 'in'`)
	f.session("node-a", day(20, 0), impactUntil, "true", "true", "'all'")
	if got, want := f.verdict(`'node-a', %s, %s`), "INCONCLUSIVE {masquerade_not_traced} {} 0 0.777777"; got != want {
		t.Errorf("node-a, of an agent that folded for 20 days: %s, want %s", got, want)
	}
	if got, want := f.verdict(`'node-a', %s, %s, min_coverage => 0.7`), "SAFE {} {masquerade_not_traced} 0 0.777777"; got != want {
		t.Errorf("node-a, of a caller that accepts it: %s, want %s", got, want)
	}

	// A server in the namespace of its client is reached by nothing that
	// the host masqueraded: a host that talks to itself over its own
	// address is its own, whatever its agent folds.
	f.exec(`UPDATE shawk.edges SET netns = $1, last_seen = $2`, int64(impactNetns), impactUntil)
	f.exec(`UPDATE shawk.agent_sessions SET peer_fold = 'all', translations_traced = NULL`)
	if got, want := f.verdict(`'node-a', %s, %s`), "SAFE {} {} 0 1.000000"; got != want {
		t.Errorf("node-a, with the pod in the namespace of the host: %s, want %s", got, want)
	}
}

// TestPGImpactMasqueradedBehindAProbe: the rows that the connector writes
// for a node whose pod is probed by its kubelet and used from outside
// through a NodePort with masquerade, which the pod sees as one peer, the
// bridge of the node. The client outside is a dependent by the translation
// that the agent learned; an agent that folds its peers learns none, and
// the verdict is then not SAFE.
func TestPGImpactMasqueradedBehindAProbe(t *testing.T) {
	for _, folds := range []bool{false, true} {
		c, sink, conn := pgConnector(t)
		start := impactSince
		now := start
		c.now = func() time.Time { return now }
		traced := true
		for ; now.Before(start.Add(3 * time.Hour)); now = now.Add(time.Minute) {
			pod := tEdge{role: "server", proto: "tcp", local: "10.244.1.7", peer: "10.244.1.1", port: 8080, svc: "web", comm: "web",
				unit: "web.service", netns: "4026532001", count: 1, first: start, last: now}
			probe := tEdge{role: "client", proto: "tcp", local: "10.244.1.1", peer: "10.244.1.7", port: 8080, svc: "kubelet", comm: "kubelet",
				unit: "kubelet.service", opened: 1, first: start, last: now}
			a := tAgent{host: "node-a", machineID: "m-a", addrs: []string{"10.0.0.10", "10.244.1.1", "10.244.1.7"}, time: now, segment: start,
				unixTraced: &traced, translationsTraced: &traced, edges: []tEdge{pod, probe}}
			if folds {
				a.fold = "in"
			} else {
				a.translations = []tTranslation{{proto: "tcp", client: "203.0.113.50", virtual: "10.0.0.10", vport: 30080,
					source: "10.244.1.1", backend: "10.244.1.7", bport: 8080, first: start, last: now}}
			}
			consume(t, c, sink, a)
		}
		c.flush(context.Background())
		// One row of the dependencies, of the kubelet and the pod.
		checkRows(t, "dependencies", queryStrings(t, conn, `SELECT client_host, client_service, server_host, server_service, observed_by
			FROM shawk_v1.dependencies_between($1, $2)`, start, now), []string{"node-a kubelet node-a web both"})
		dependents := queryStrings(t, conn, `SELECT host(client_addr), server_host, server_service, port, observed_by
			FROM shawk_v1.impact('node-a', $1, $2)`, start, now)
		verdict := queryStrings(t, conn, `SELECT verdict, reasons::text, caveats::text, direct FROM shawk_v1.impact_verdict('node-a', $1, $2)`, start, now)
		if folds {
			checkRows(t, "dependents of node-a, of an agent that folds", dependents, nil)
			checkRows(t, "verdict on node-a, of an agent that folds", verdict, []string{"INCONCLUSIVE {masquerade_not_traced} {} 0"})
		} else {
			checkRows(t, "dependents of node-a", dependents, []string{"203.0.113.50 node-a ~relay 30080 server"})
			checkRows(t, "verdict on node-a", verdict, []string{"UNSAFE {active_dependents} {} 1"})
		}
	}
}

// TestPGImpactOfARelay: the clients whose connections a host relays in the
// kernel are its dependents, although no process of it accepts them and
// the dependency is that of the client on the backend.
func TestPGImpactOfARelay(t *testing.T) {
	_, conn := migratedDB(t)
	f := newImpactFixture(t, conn)
	// lvs-01 holds a virtual address, and forwards its port 5432 to db-01.
	f.watched("lvs-01", "10.0.0.5", "10.0.0.100")
	f.listens("lvs-01", "sshd", 22)
	f.watched("db-01", "10.0.1.10")
	f.watched("app-01", "10.0.0.11")
	// app connects to the virtual address, and postgres sees app: the
	// agent of lvs-01 learned the translation.
	f.edge("app-01", "app", "client", "10.0.0.11", "10.0.0.100", 5432, impactSince, impactUntil)
	f.active("app-01", "app", 5432, impactSince, impactUntil, time.Hour, 1)
	f.edge("db-01", "postgres", "server", "10.0.1.10", "10.0.0.11", 5432, impactSince, impactUntil)
	f.learned("lvs-01", "10.0.0.11", "10.0.0.100", 5432, "10.0.0.11", "10.0.1.10", 5432, impactSince, impactUntil)
	// A client without an agent, through the same address.
	f.edge("db-01", "postgres", "server", "10.0.1.10", "10.0.5.5", 5432, day(3, 0), day(4, 0))
	f.learned("lvs-01", "10.0.5.5", "10.0.0.100", 5432, "10.0.5.5", "10.0.1.10", 5432, day(3, 0), day(4, 0))
	// keepalived, on lvs-01, checks db-01 itself, and a process of lvs-01
	// uses its own virtual address: its own clients.
	f.both("lvs-01", "keepalived", "10.0.0.5", "db-01", "postgres", "10.0.1.10", 5432, impactSince, impactUntil)
	f.edge("lvs-01", "probe", "client", "10.0.0.5", "10.0.0.100", 5432, impactSince, impactUntil)
	f.learned("lvs-01", "10.0.0.5", "10.0.0.100", 5432, "10.0.0.5", "10.0.1.10", 5432, impactSince, impactUntil)

	relayed := []string{
		"1 - ~unresolved 10.0.5.5 -> lvs-01 ~relay 5432 server unknown",
		"1 app-01 app - -> lvs-01 ~relay 5432 both continuous",
	}
	checkRows(t, "dependents of lvs-01", f.impact(`'lvs-01', %s, %s`), relayed)
	if got, want := f.verdict(`'lvs-01', %s, %s`), "UNSAFE {active_dependents} {} 2 1.000000"; got != want {
		t.Errorf("lvs-01: %s, want %s", got, want)
	}
	// Which of its services keeps the translations is not known: they
	// count for each, and for the port, not for another port.
	checkRows(t, "dependents of keepalived on lvs-01", f.impact(`'lvs-01', %s, %s, 'keepalived'`), relayed)
	checkRows(t, "dependents of port 5432 of lvs-01", f.impact(`'lvs-01', %s, %s, target_port => 5432`), relayed)
	if got, want := f.verdict(`'lvs-01', %s, %s, target_port => 22`), "SAFE {} {} 0 1.000000"; got != want {
		t.Errorf("port 22 of lvs-01: %s, want %s", got, want)
	}
	// The backend keeps its dependents, lvs-01 among them.
	checkRows(t, "dependents of db-01", f.impact(`'db-01', %s, %s, max_depth => 1`), []string{
		"1 - ~unresolved 10.0.5.5 -> db-01 postgres 5432 server one-off",
		"1 app-01 app - -> db-01 postgres 5432 both continuous",
		"1 lvs-01 keepalived - -> db-01 postgres 5432 both continuous",
		"1 lvs-01 probe - -> db-01 postgres 5432 both continuous",
	})

	// A gateway that masquerades the connections of other hosts to the
	// outside: they need it too.
	f.watched("gw-01", "10.0.0.1", "198.51.100.1")
	f.learned("gw-01", "10.0.0.11", "203.0.113.9", 443, "198.51.100.1", "203.0.113.9", 443, day(1, 0), day(2, 0))
	// So does a container of gw-01 itself, whose address the host does not
	// report as its own: the agent saw its client edge on the host, so it
	// is no dependent of it.
	f.edge("gw-01", "curl", "client", "172.17.0.3", "203.0.113.9", 443, day(1, 0), day(2, 0))
	f.learned("gw-01", "172.17.0.3", "203.0.113.9", 443, "198.51.100.1", "203.0.113.9", 443, day(1, 0), day(2, 0))
	checkRows(t, "dependents of gw-01", f.impact(`'gw-01', %s, %s`), []string{
		"1 - ~unresolved 10.0.0.11 -> gw-01 ~relay 443 server unknown",
	})
	// A host that publishes the port of a container of its own: the
	// client is that of the container, once.
	f.watched("docker-01", "10.0.0.30")
	f.edge("docker-01", "web", "server", "172.17.0.2", "10.0.7.7", 80, impactSince, impactUntil)
	f.active("docker-01", "web", 80, impactSince, impactUntil, time.Hour, 1)
	f.learned("docker-01", "10.0.7.7", "10.0.0.30", 8080, "10.0.7.7", "172.17.0.2", 80, impactSince, impactUntil)
	checkRows(t, "dependents of docker-01", f.impact(`'docker-01', %s, %s`), []string{
		"1 - ~unresolved 10.0.7.7 -> docker-01 web 80 server continuous",
	})

	// A director whose translation the configuration gives, with its own
	// address as the source: db-01 sees its clients from that address, and
	// the health checks of the director from it too, which explain the
	// edge. The clients behind the source are still there, as far as db-01
	// can tell.
	f.watched("fnat-01", "10.0.0.6", "10.0.100.2")
	f.exec(`INSERT INTO shawk.translations VALUES
		('fnat', 'virtual', 'tcp', '10.0.100.2', 5432), ('fnat', 'backend', 'tcp', '10.0.1.10', 0), ('fnat', 'source', 'tcp', '10.0.0.6', 0)`)
	f.both("fnat-01", "keepalived", "10.0.0.6", "db-01", "postgres", "10.0.1.10", 5432, impactSince, impactUntil)
	checkRows(t, "dependents of fnat-01", f.impact(`'fnat-01', %s, %s`), []string{
		"1 - ~unresolved 10.0.0.6 -> fnat-01 ~relay 5432 server unknown",
	})
	// The same for a backend on the host of the virtual address, on
	// another port, which a process of its own unit explains: the clients
	// behind the source are those of the port of the backend too.
	f.watched("fnat-03", "10.0.0.8", "10.0.100.3")
	f.exec(`INSERT INTO shawk.translations VALUES
		('local', 'virtual', 'tcp', '10.0.100.3', 443), ('local', 'backend', 'tcp', '10.0.0.8', 8443), ('local', 'source', 'tcp', '10.0.0.8', 0)`)
	f.listens("fnat-03", "web", 8443)
	f.both("fnat-03", "web", "10.0.0.8", "fnat-03", "web", "10.0.0.8", 8443, impactSince, impactUntil)
	for _, target := range []string{`'fnat-03', %s, %s`, `'fnat-03', %s, %s, target_port => 443`, `'fnat-03', %s, %s, target_port => 8443`,
		`'fnat-03', %s, %s, 'web', 8443`} {
		checkRows(t, "dependents of "+target, f.impact(target), []string{"1 - ~unresolved 10.0.0.8 -> fnat-03 ~relay 443 server unknown"})
	}
	if got, want := f.verdict(`'fnat-01', %s, %s`), "UNSAFE {active_dependents} {} 1 1.000000"; got != want {
		t.Errorf("fnat-01: %s, want %s", got, want)
	}
	// Not without the virtual address, which a standby does not hold.
	f.watched("fnat-02", "10.0.0.7")
	f.both("fnat-02", "keepalived", "10.0.0.7", "db-01", "postgres", "10.0.1.10", 5432, impactSince, impactUntil)
	checkRows(t, "dependents of fnat-02", f.impact(`'fnat-02', %s, %s`), nil)
}

// TestPGImpactThroughATranslation: the clients of a virtual address are
// the dependents of the backend that served them.
func TestPGImpactThroughATranslation(t *testing.T) {
	_, conn := migratedDB(t)
	f := newImpactFixture(t, conn)
	f.watched("db-01", "10.0.1.10")
	f.watched("db-02", "10.0.1.11")
	f.watched("app-01", "10.0.0.11")
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
	// The balancer has no agent: the inventory gives it the virtual
	// address. app depends on it, and so may a client that a backend saw
	// alone.
	f.exec(`INSERT INTO shawk.inventory_hosts (host, agent) VALUES ('lb-01', false)`)
	f.exec(`INSERT INTO shawk.inventory_addrs VALUES ('10.0.100.1', 'lb-01')`)
	f.edge("db-02", "postgres", "server", "10.0.1.11", "10.0.7.7", 5432, day(40, 0), day(41, 0))
	f.edge("db-02", "postgres", "server", "10.0.1.11", "10.0.7.8", 6432, day(40, 0), day(41, 0))
	checkRows(t, "dependents of lb-01", f.impact(`'lb-01', %s, %s`), []string{
		"1 - ~unresolved 10.0.7.7 -> lb-01 ~relay 5432 server unknown",
		"1 app-01 app - -> lb-01 ~relay 5432 client continuous",
	})
	if got, want := f.verdict(`'lb-01', %s, %s`), "UNSAFE {active_dependents} {no_agent} 2 0.000000"; got != want {
		t.Errorf("lb-01: %s, want %s", got, want)
	}
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
	f := newImpactFixture(t, conn)
	f.watched("db-01", "10.0.0.10")
	// a: written before the hours were recorded, and seen since.
	f.watched("a-01", "10.0.0.21")
	f.edge("a-01", "a", "client", "10.0.0.21", "10.0.0.10", 5432, impactSince, impactUntil)
	f.edge("db-01", "postgres", "server", "10.0.0.10", "10.0.0.21", 5432, impactSince, impactUntil)
	f.unrecorded("a-01", "a")
	f.unrecorded("db-01", "postgres")
	// b: its hours end 10 days before it was last seen, as when a
	// connector that does not record them took over.
	f.watched("b-01", "10.0.0.22")
	f.edge("b-01", "b", "client", "10.0.0.22", "10.0.0.10", 5432, impactSince, impactUntil)
	f.active("b-01", "b", 5432, impactSince, day(80, 0), time.Hour, 1)
	// c: the hours of its client stop when the agent of c-01 does, on day
	// 30; those of the server go on.
	f.host("c-01", "10.0.0.23")
	f.observed("c-01", impactSince.Add(-time.Hour), day(30, 0))
	f.edge("c-01", "c", "client", "10.0.0.23", "10.0.0.10", 5432, impactSince, day(30, 0))
	f.active("c-01", "c", 5432, impactSince, day(30, 0), time.Hour, 1)
	f.edge("db-01", "postgres", "server", "10.0.0.10", "10.0.0.23", 5432, impactSince, impactUntil)
	f.activeWith("db-01", "postgres", 5432, "10.0.0.23", day(30, 0), impactUntil, time.Hour, 1)
	// d: seen by its client alone, whose agent stopped on day 30 and came
	// back on day 60: all along as far as it was observed.
	f.host("d-01", "10.0.0.24")
	f.observed("d-01", impactSince.Add(-time.Hour), day(30, 0))
	f.observed("d-01", day(60, 0), impactUntil)
	f.edge("d-01", "d", "client", "10.0.0.24", "10.0.0.99", 5432, impactSince, impactUntil)
	f.active("d-01", "d", 5432, impactSince, day(30, 0), time.Hour, 1)
	f.active("d-01", "d", 5432, day(60, 0), impactUntil, time.Hour, 1)
	f.exec(`INSERT INTO shawk.inventory_hosts (host, agent) VALUES ('nas-01', false)`)
	f.exec(`INSERT INTO shawk.inventory_addrs VALUES ('10.0.0.99', 'nas-01')`)
	// e: as d, but observed and idle in between.
	f.watched("e-01", "10.0.0.25")
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
	f := newImpactFixture(t, conn)
	f.watched("full-01", "10.0.0.1")
	// Observed from day 45, with a gap of a day, dropped flows for 9
	// hours, a day without UDP and Unix sockets, and a day in one network
	// namespace.
	f.host("part-01", "10.0.0.2")
	f.observed("part-01", day(45, 0), day(60, 0))
	f.observed("part-01", day(61, 0), day(88, 0))
	f.session("part-01", day(88, 0), day(89, 0), "false", "false", "'all'")
	f.session("part-01", day(89, 0), impactUntil, "true", "true", "'4026531840'")
	f.exec(`INSERT INTO shawk.partial_observations VALUES ('part-01', $1, $2, $3, 7), ('part-01', $1, $4, $5, 5)`,
		day(45, 0), day(50, 0), day(50, 9), impactSince.Add(-48*time.Hour), impactSince.Add(-24*time.Hour))
	// Last seen before the period: not among the hosts of the period.
	f.exec(`INSERT INTO shawk.hosts VALUES ('old-01', 'm', 'old-01', 'k', 'v', $1, $1)`, impactSince.Add(-48*time.Hour))
	const cols = `host, agent, observed::text, extract(epoch FROM unobserved)::int, gaps, extract(epoch FROM partly_observed)::int,
		dropped_flows, extract(epoch FROM udp_untraced)::int, extract(epoch FROM unix_untraced)::int,
		extract(epoch FROM netns_limited)::int, extract(epoch FROM before_retention)::int`
	const gapCols = `host, to_char(gap_start AT TIME ZONE 'UTC', 'MM-DD"T"HH24:MI'), to_char(gap_end AT TIME ZONE 'UTC', 'MM-DD"T"HH24:MI'), cause`
	args := ts(impactSince) + ", " + ts(impactUntil)
	checkRows(t, "coverage of every host", queryStrings(t, conn, `SELECT `+cols+` FROM shawk_v1.coverage(`+args+`)`), []string{
		"full-01 true 1.000000 0 0 0 0 0 0 0 0",
		// 45 days, and a day less 3 minutes: the tolerance.
		"part-01 true 0.488912 3974220 2 32400 7 86400 86400 86400 0",
	})
	checkRows(t, "coverage of hosts by name",
		queryStrings(t, conn, `SELECT `+cols+` FROM shawk_v1.coverage(`+args+`, ARRAY['old-01', 'none-01', 'full-01', 'full-01'])`), []string{
			"full-01 true 1.000000 0 0 0 0 0 0 0 0",
			"none-01 false 0.000000 7776000 1 0 0 0 0 0 0",
			"old-01 true 0.000000 7776000 1 0 0 0 0 0 0",
		})
	// The gaps, also of the names that were not seen in the period.
	checkRows(t, "gaps",
		queryStrings(t, conn, `SELECT `+gapCols+` FROM shawk_v1.coverage_gaps(`+args+`, ARRAY['old-01', 'none-01', 'full-01', 'part-01'])`), []string{
			"none-01 08-01T00:00 10-30T00:00 agent",
			"old-01 08-01T00:00 10-30T00:00 agent",
			"part-01 08-01T00:00 09-15T00:00 agent",
			"part-01 09-30T00:03 10-01T00:00 agent",
		})
	// A connector that keeps 30 days pruned: the 60 days before tell
	// nothing, of the hosts observed then either.
	execAll(t, conn, `SELECT shawk.prune(`+ts(day(60, 0))+`)`, `SELECT shawk.prune(`+ts(day(50, 0))+`)`)
	checkRows(t, "coverage of every host after a prune", queryStrings(t, conn, `SELECT `+cols+` FROM shawk_v1.coverage(`+args+`)`), []string{
		"full-01 true 0.333333 5184000 1 0 0 0 0 0 5184000",
		"part-01 true 0.322245 5270220 2 0 0 86400 86400 86400 5184000",
	})
	checkRows(t, "gaps after a prune",
		queryStrings(t, conn, `SELECT `+gapCols+` FROM shawk_v1.coverage_gaps(`+args+`, ARRAY['full-01', 'part-01'])`), []string{
			"full-01 08-01T00:00 09-30T00:00 retention",
			"part-01 08-01T00:00 09-30T00:00 retention",
			"part-01 09-30T00:03 10-01T00:00 agent",
		})
	if got := queryStrings(t, conn, `SELECT count(*) FROM shawk_v1.coverage('2026-09-02T00:00:00Z', '2026-09-01T00:00:00Z')`); !slices.Equal(got, []string{"0"}) {
		t.Errorf("%v rows of an empty period", got)
	}
}

// TestPGImpactBeforeTheRetention: a period that starts before the retention
// of the connector is not observed before it, although the session of an
// agent that never stopped spans it: the dependencies last seen then are
// deleted.
func TestPGImpactBeforeTheRetention(t *testing.T) {
	_, conn := migratedDB(t)
	f := newImpactFixture(t, conn)
	for host, addr := range map[string]string{"db-01": "10.0.0.10", "batch-01": "10.0.0.13"} {
		f.host(host, addr)
		f.observed(host, impactSince.Add(-100*24*time.Hour), impactUntil)
	}
	f.listener("db-01", "postgres", 5432, impactSince.Add(-100*24*time.Hour), impactUntil)
	// billing used postgres for 2 hours on day 20.
	f.both("batch-01", "billing", "10.0.0.13", "db-01", "postgres", "10.0.0.10", 5432, day(20, 0), day(20, 2))
	if got, want := f.verdict(`'db-01', %s, %s`), "UNSAFE {active_dependents} {} 1 1.000000"; got != want {
		t.Errorf("db-01 before the prune: %s, want %s", got, want)
	}
	// A connector that keeps 30 days prunes.
	execAll(t, conn, `SELECT shawk.prune(`+ts(day(60, 0))+`)`)
	if got := queryStrings(t, conn, `SELECT (SELECT count(*) FROM shawk.edges), (SELECT count(*) FROM shawk.agent_sessions)`); !slices.Equal(got, []string{"0 2"}) {
		t.Fatalf("edges and sessions left after the prune: %v, want 0 2", got)
	}
	if got, want := f.verdict(`'db-01', %s, %s`), "INCONCLUSIVE {before_retention} {} 0 0.333333"; got != want {
		t.Errorf("db-01 after the prune: %s, want %s", got, want)
	}
	if got, want := f.verdict(`'db-01', %s, %s, 'postgres', 5432`), "INCONCLUSIVE {before_retention} {} 0 0.333333"; got != want {
		t.Errorf("postgres of db-01 after the prune: %s, want %s", got, want)
	}
	checkRows(t, "what the verdict on db-01 tells of the period",
		queryStrings(t, conn, fmt.Sprintf(`SELECT unobserved::text, gaps FROM shawk_v1.impact_verdict('db-01', %s, %s)`, ts(impactSince), ts(impactUntil))),
		[]string{"60 days 1"})
	// The period within the retention is observed.
	if got := queryStrings(t, conn, fmt.Sprintf(`SELECT verdict, reasons::text, coverage::text FROM shawk_v1.impact_verdict('db-01', %s, %s)`,
		ts(day(60, 0)), ts(impactUntil))); !slices.Equal(got, []string{"SAFE {} 1.000000"}) {
		t.Errorf("db-01 within the retention: %v, want SAFE", got)
	}
	// A prune of rows left with an earlier cutoff does not move it back.
	execAll(t, conn, `SELECT shawk.prune(`+ts(day(10, 0))+`)`)
	if got := queryStrings(t, conn, `SELECT to_char(pruned_before AT TIME ZONE 'UTC', 'MM-DD') FROM shawk.retention`); !slices.Equal(got, []string{"09-30"}) {
		t.Errorf("pruned before %v, want 09-30", got)
	}
}

// migrateTo applies the migrations up to a version to an empty database,
// as Migrate does: the schema of a connector before the ones after.
func migrateTo(t *testing.T, conn *pgx.Conn, version int) {
	t.Helper()
	ctx := context.Background()
	execAll(t, conn, `CREATE SCHEMA IF NOT EXISTS shawk`, `CREATE TABLE IF NOT EXISTS shawk.schema_migrations (
		version integer PRIMARY KEY, name text NOT NULL, applied_at timestamptz NOT NULL DEFAULT now())`)
	for _, m := range must(Migrations()) {
		if m.Version > version {
			break
		}
		if _, err := conn.Exec(ctx, m.SQL); err != nil {
			t.Fatalf("migration %s: %v", m.Name, err)
		}
		if _, err := conn.Exec(ctx, `INSERT INTO shawk.schema_migrations (version, name) VALUES ($1, $2)`, m.Version, m.Name); err != nil {
			t.Fatal(err)
		}
	}
}

// TestPGImpactRetentionAfterAnUpgrade: a database that a connector before
// this version pruned has no record of the cutoff. The migration starts
// from the oldest time an edge still kept was last seen, so that a period
// longer than the retention is not SAFE right after the upgrade, before
// any prune and without one.
func TestPGImpactRetentionAfterAnUpgrade(t *testing.T) {
	_, conn := testDB(t)
	migrateTo(t, conn, 3)
	// db-01 was observed all along. billing used its postgres on day 20,
	// and its own backup reads it over loopback until day 70.
	for _, q := range []string{
		`INSERT INTO shawk.hosts VALUES ('db-01', 'm', 'db-01', 'k', 'v', $1, $2), ('batch-01', 'm', 'batch-01', 'k', 'v', $1, $2)`,
		`INSERT INTO shawk.agent_sessions (host_id, started_at, last_heartbeat, udp_traced, unix_traced, netns_scope)
		 VALUES ('db-01', $1, $2, true, true, 'all'), ('batch-01', $1, $2, true, true, 'all')`,
		`INSERT INTO shawk.host_addrs VALUES ('db-01', '10.0.0.10', $1, $2), ('batch-01', '10.0.0.13', $1, $2)`,
	} {
		if _, err := conn.Exec(context.Background(), q, impactSince.Add(-100*24*time.Hour), impactUntil); err != nil {
			t.Fatal(err)
		}
	}
	execAll(t, conn, `INSERT INTO shawk.processes (host_id, unit, comm, service_name, first_seen, last_seen) VALUES
		('db-01', 'postgres.service', 'postgres', 'postgres', `+ts(impactSince)+`, `+ts(impactUntil)+`),
		('db-01', 'backup.service', 'backup', 'backup', `+ts(impactSince)+`, `+ts(impactUntil)+`),
		('batch-01', 'billing.service', 'billing', 'billing', `+ts(impactSince)+`, `+ts(impactUntil)+`)`,
		`INSERT INTO shawk.edges (host_id, process_id, role, proto, local_addr, remote_addr, port, netns, first_seen, last_seen)
		 SELECT e.host, p.id, e.role, 'tcp', e.local::inet, e.remote::inet, 5432, 1, `+ts(day(20, 0))+`, e.last::timestamptz
		 FROM (VALUES ('batch-01', 'billing', 'client', '10.0.0.13', '10.0.0.10', `+ts(day(20, 2))+`),
		              ('db-01', 'postgres', 'server', '10.0.0.10', '10.0.0.13', `+ts(day(20, 2))+`),
		              ('db-01', 'backup', 'client', '127.0.0.1', '127.0.0.1', `+ts(day(70, 0))+`),
		              ('db-01', 'postgres', 'server', '127.0.0.1', '127.0.0.1', `+ts(day(70, 0))+`)) AS e(host, svc, role, local, remote, last)
		 JOIN shawk.processes p ON p.host_id = e.host AND p.service_name = e.svc`,
		// The connector of that version keeps 30 days.
		`SELECT shawk.prune(`+ts(day(60, 0))+`)`)
	if got := queryStrings(t, conn, `SELECT count(*) FROM shawk.edges`); !slices.Equal(got, []string{"2"}) {
		t.Fatalf("%v edges left by the prune, want 2", got)
	}
	if _, err := Migrate(context.Background(), conn); err != nil {
		t.Fatal(err)
	}
	if got := queryStrings(t, conn, `SELECT to_char(pruned_before AT TIME ZONE 'UTC', 'MM-DD') FROM shawk.retention`); !slices.Equal(got, []string{"10-10"}) {
		t.Errorf("retention after the migration: %v, want 10-10, the day the oldest edge left was last seen", got)
	}
	verdict := func(since time.Time) []string {
		return queryStrings(t, conn, `SELECT verdict, reasons::text, coverage::text FROM shawk_v1.impact_verdict('db-01', $1, $2)`, since, impactUntil)
	}
	checkRows(t, "db-01 over 90 days, right after the upgrade", verdict(impactSince), []string{"INCONCLUSIVE {before_retention} 0.222222"})
	checkRows(t, "db-01 over the last 20 days", verdict(day(70, 0)), []string{"SAFE {} 1.000000"})
	// The next prune records its own cutoff, a later one.
	execAll(t, conn, `SELECT shawk.prune(`+ts(day(75, 0))+`)`)
	checkRows(t, "db-01 over the last 20 days, after a prune", verdict(day(70, 0)), []string{"INCONCLUSIVE {before_retention} 0.750000"})

	// A database without edges has nothing to start from: no record.
	_, conn = testDB(t)
	migrateTo(t, conn, 3)
	if _, err := Migrate(context.Background(), conn); err != nil {
		t.Fatal(err)
	}
	if got := queryStrings(t, conn, `SELECT count(*) FROM shawk.retention`); !slices.Equal(got, []string{"0"}) {
		t.Errorf("%v records of the retention of an empty database, want none", got)
	}
}

// TestPGImpactClockBehind: the edges keep the times of the agent: with a
// clock 2 hours behind, the last 2 hours of the history of a host are not
// written yet, whatever the heartbeat of its session.
func TestPGImpactClockBehind(t *testing.T) {
	_, conn := migratedDB(t)
	f := newImpactFixture(t, conn)
	f.host("db-01", "10.0.0.10")
	f.observed("db-01", impactUntil.Add(-30*24*time.Hour-2*time.Hour), impactUntil)
	f.exec(`UPDATE shawk.agent_sessions SET clock_skew = '2 hours'`)
	// A client without an agent uses postgres all along, up to now: by the
	// clock of the agent, up to 2 hours ago.
	f.edge("db-01", "postgres", "server", "10.0.0.10", "10.0.5.5", 5432, impactUntil.Add(-30*24*time.Hour-2*time.Hour), impactUntil.Add(-2*time.Hour))
	verdict := func(lookback string) []string {
		return queryStrings(t, conn, fmt.Sprintf(`SELECT verdict, reasons::text, caveats::text, direct, coverage::text
			FROM shawk_v1.impact_verdict('db-01', %s - interval '%s', %s)`, ts(impactUntil), lookback, ts(impactUntil)))
	}
	checkRows(t, "the last hour", verdict("1 hour"), []string{"INCONCLUSIVE {not_observed} {} 0 0.000000"})
	checkRows(t, "the last 3 hours", verdict("3 hours"), []string{"UNSAFE {active_dependents} {not_observed} 1 0.350000"})
	checkRows(t, "the last 7 days", verdict("7 days"), []string{"UNSAFE {active_dependents} {not_observed} 1 0.988392"})
}

// TestPGImpactUnknownOwner: the sockets without a known owner of a host
// are dependents, and the clients of the others of the host are not
// theirs; a connection that such a socket accepted counts for every
// service of its host.
func TestPGImpactUnknownOwner(t *testing.T) {
	_, conn := migratedDB(t)
	f := newImpactFixture(t, conn)
	f.watched("db-01", "10.0.0.10")
	f.listens("db-01", "redis", 6379)
	// A connection to db-01 that a socket without a known owner accepted,
	// as one that predates the agent, and one of such a socket of db-01
	// itself to another.
	f.edge("db-01", "~unknown", "server", "10.0.0.10", "10.0.0.13", 6379, day(1, 0), day(2, 0))
	f.both("db-01", "~unknown", "127.0.0.1", "db-01", "~unknown", "127.0.0.1", 7000, day(1, 0), day(2, 0))
	accepted := "1 - ~unresolved 10.0.0.13 -> db-01 ~unknown 6379 server one-off"
	checkRows(t, "dependents of redis on db-01", f.impact(`'db-01', %s, %s, 'redis'`), []string{
		accepted,
		"1 db-01 ~unknown - -> db-01 ~unknown 7000 both dormant",
	})
	// Its port leaves the other sockets out.
	checkRows(t, "dependents of redis on port 6379 of db-01", f.impact(`'db-01', %s, %s, 'redis', 6379`), []string{accepted})
	checkRows(t, "dependents of port 6379 of db-01", f.impact(`'db-01', %s, %s, target_port => 6379`), []string{accepted})
	if got, want := f.verdict(`'db-01', %s, %s, 'redis'`), "UNSAFE {active_dependents} {} 2 1.000000"; got != want {
		t.Errorf("redis of db-01: %s, want %s", got, want)
	}
	// The host as a whole: its own sockets go with it.
	checkRows(t, "dependents of db-01", f.impact(`'db-01', %s, %s`), []string{accepted})
	execAll(t, conn, `DELETE FROM shawk.edges WHERE host_id = 'db-01'`)
	f.watched("app-01", "10.0.0.11")
	f.watched("web-01", "10.0.0.12")
	// A socket of app-01 without a known owner uses postgres, and another
	// one serves web.
	f.both("app-01", "~unknown", "10.0.0.11", "db-01", "postgres", "10.0.0.10", 5432, impactSince, impactUntil)
	f.both("web-01", "web", "10.0.0.12", "app-01", "~unknown", "10.0.0.11", 8080, impactSince, impactUntil)
	checkRows(t, "dependents of db-01", f.impact(`'db-01', %s, %s`), []string{
		"1 app-01 ~unknown - -> db-01 postgres 5432 both continuous",
	})
}

// impactDump returns the rows of the tables that the impact reads, with
// the names of the hosts rather than their ids, which a fixture does not
// hash. @ stands for a time, formatted.
func impactDump(t *testing.T, conn *pgx.Conn) []string {
	t.Helper()
	at := regexp.MustCompile(`@([a-z_.]+)`)
	var out []string
	for _, q := range []string{
		`SELECT 'host', h.hostname, @h.first_seen, @h.last_seen FROM shawk.hosts h`,
		`SELECT 'session', h.hostname, @s.started_at, @s.last_heartbeat, s.udp_traced, s.unix_traced, s.netns_scope, s.clock_skew::text,
		        s.translations_traced, s.peer_fold
		 FROM shawk.agent_sessions s JOIN shawk.hosts h ON h.id = s.host_id`,
		`SELECT 'addr', h.hostname, host(a.addr), @a.first_seen, @a.last_seen
		 FROM shawk.host_addrs a JOIN shawk.hosts h ON h.id = a.host_id`,
		`SELECT 'process', h.hostname, p.unit, p.comm, p.service_name, @p.first_seen, @p.last_seen
		 FROM shawk.processes p JOIN shawk.hosts h ON h.id = p.host_id`,
		`SELECT 'edge', h.hostname, p.service_name, e.role, e.proto, host(e.local_addr), text(e.remote_addr), e.port, e.netns,
		        @e.first_seen, @e.last_seen,
		        (SELECT string_agg(r::text, ' ' ORDER BY r)
		         FROM shawk.edge_activity a CROSS JOIN LATERAL shawk.activity_ranges(a.month, a.hours) r WHERE a.edge_id = e.id)
		 FROM shawk.edges e JOIN shawk.processes p ON p.id = e.process_id JOIN shawk.hosts h ON h.id = e.host_id`,
		`SELECT 'listener', h.hostname, p.service_name, l.proto, host(l.addr), l.port, l.netns, @l.first_seen, @l.last_seen
		 FROM shawk.listeners l JOIN shawk.processes p ON p.id = l.process_id JOIN shawk.hosts h ON h.id = l.host_id`,
		`SELECT 'owner', h.hostname, p.service_name, l.proto, host(l.addr), l.port, l.netns, @l.first_seen, @l.last_seen
		 FROM shawk.listener_owners l JOIN shawk.processes p ON p.id = l.process_id JOIN shawk.hosts h ON h.id = l.host_id`,
		`SELECT 'translation', h.hostname, l.proto, l.netns, host(l.client_addr), host(l.virtual_addr), l.virtual_port,
		        host(l.source_addr), host(l.backend_addr), l.backend_port, @l.first_seen, @l.last_seen
		 FROM shawk.learned_translations l JOIN shawk.hosts h ON h.id = l.host_id`,
	} {
		rows := queryStrings(t, conn, at.ReplaceAllString(q, `to_char($1 AT TIME ZONE 'UTC', 'MM-DD"T"HH24:MI:SS')`))
		slices.Sort(rows)
		out = append(out, rows...)
	}
	return out
}

// TestPGImpactFixtureLikeTheConnector: the rows that the fixtures of the
// tests of the impact write are those that the connector writes for the
// same history: an agent that stops for a day, a listener, both sides of
// a connection and its translation.
func TestPGImpactFixtureLikeTheConnector(t *testing.T) {
	start := impactSince
	stopped, back, end := start.Add(48*time.Hour), start.Add(72*time.Hour), start.Add(96*time.Hour)
	used := timeSpan{start.Add(26 * time.Hour), start.Add(29*time.Hour + 30*time.Minute)}

	// The history, through the connector: a request of each agent every
	// minute, which a connector writes every 10 minutes.
	c, sink, conn := pgConnector(t)
	ctx := context.Background()
	now := start
	c.now = func() time.Time { return now }
	traced := true
	for ; !now.After(end); now = now.Add(time.Minute) {
		var edges []tEdge
		if !now.Before(used.from) && !now.After(used.to) {
			edges = []tEdge{{proto: "tcp", port: 5432, count: 1, first: used.from, last: now}}
		}
		if !now.After(stopped) || !now.Before(back) {
			segment := start
			if !now.Before(back) {
				segment = back
			}
			db := tAgent{host: "db-01", machineID: "m-db", addrs: []string{"10.0.0.10"}, time: now, segment: segment,
				unixTraced: new(bool), translationsTraced: &traced,
				listeners: []tListener{{proto: "tcp", addr: "0.0.0.0", port: 5432, svc: "postgres", comm: "postgres",
					unit: "postgres.service", first: segment, last: now}}}
			*db.unixTraced = true
			for _, e := range edges {
				e.role, e.local, e.peer, e.svc, e.comm, e.unit = "server", "10.0.0.10", "10.0.0.11", "postgres", "postgres", "postgres.service"
				db.edges = append(db.edges, e)
				db.translations = []tTranslation{{proto: "tcp", client: "10.0.0.11", virtual: "10.0.0.100", vport: 5432,
					backend: "10.0.0.10", bport: 5432, first: e.first, last: e.last}}
			}
			consume(t, c, sink, db)
		}
		app := tAgent{host: "app-01", machineID: "m-app", addrs: []string{"10.0.0.11"}, time: now, segment: start, unixTraced: new(bool),
			translationsTraced: &traced}
		*app.unixTraced = true
		for _, e := range edges {
			e.role, e.local, e.peer, e.svc, e.comm, e.unit = "client", "10.0.0.11", "10.0.0.10", "app", "app", "app.service"
			app.edges = append(app.edges, e)
		}
		consume(t, c, sink, app)
		if now.Minute()%10 == 0 {
			c.flush(ctx)
		}
	}
	c.flush(ctx)
	written := impactDump(t, conn)

	// The same history, by the fixture.
	_, conn = migratedDB(t)
	f := newImpactFixture(t, conn)
	f.exec(`DELETE FROM shawk.hosts`)
	f.host("db-01", "10.0.0.10")
	f.host("app-01", "10.0.0.11")
	f.exec(`UPDATE shawk.hosts SET first_seen = $1, last_seen = $1`, start)
	f.observed("db-01", start, stopped)
	f.observed("db-01", back, end)
	f.observed("app-01", start, end)
	f.listener("db-01", "postgres", 5432, start, stopped)
	f.exec(`UPDATE shawk.listeners SET last_seen = $1`, end)
	f.exec(`UPDATE shawk.listener_owners SET last_seen = $1`, end)
	f.exec(`UPDATE shawk.processes SET last_seen = $1`, end)
	f.both("app-01", "app", "10.0.0.11", "db-01", "postgres", "10.0.0.10", 5432, used.from, used.to)
	f.learned("db-01", "10.0.0.11", "10.0.0.100", 5432, "10.0.0.11", "10.0.0.10", 5432, used.from, used.to)
	checkRows(t, "rows of the fixture, against those of the connector", impactDump(t, conn), written)
	if len(written) != 15 {
		t.Errorf("%d rows of the connector, want 15:\n%s", len(written), strings.Join(written, "\n"))
	}
}
