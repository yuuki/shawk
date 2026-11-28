-- What removing a host or a service would break (§6.3 of docs/design.md):
-- the clients that used it in a period, those that depend on them in turn,
-- how often each was active, how much of the period the hosts that tell
-- were observed, and a verdict. Everything is computed here, in the
-- contract, so that Grafana, psql and shawk-impact give the same answer.
--
-- The functions read the dependencies of the period only
-- (shawk_v1.dependencies_between), and the edges, the months of activity,
-- the sessions and the addresses of the hosts they find there through
-- their indexes.

-- Helpers -------------------------------------------------------------------

-- The period [since, until) as a multirange, empty if it does not end
-- after it starts.
CREATE FUNCTION shawk.period(since timestamptz, until timestamptz) RETURNS tstzmultirange
LANGUAGE sql IMMUTABLE AS $$
  SELECT CASE WHEN since < until THEN tstzmultirange(tstzrange(since, until)) ELSE '{}'::tstzmultirange END
$$;

-- The total length of the ranges of a multirange.
CREATE FUNCTION shawk.duration(m tstzmultirange) RETURNS interval
LANGUAGE sql IMMUTABLE AS $$
  SELECT coalesce(sum(upper(r) - lower(r)), interval '0') FROM unnest(m) AS r
$$;

-- The hours of a month of activity (shawk.edge_activity) as ranges, one
-- per stretch of hours that follow each other. A stretch starts at a bit
-- set after one that is not and ends before the next bit that is not set:
-- at the bits that differ from the bit before them, which are the bits set
-- in hours # (hours >> 1), taken in pairs; a stretch that reaches the last
-- bit ends with the bits. The positions of those bits are read from the
-- lengths of what is between them, so that the cost grows with the
-- stretches rather than with the hours.
CREATE FUNCTION shawk.activity_ranges(month timestamptz, hours bit) RETURNS SETOF tstzrange
LANGUAGE sql STABLE AS $$
  SELECT tstzrange(month + min(t.i) * interval '1 hour',
                   month + (CASE WHEN count(*) = 2 THEN max(t.i) ELSE length(hours) END) * interval '1 hour')
  FROM (
    SELECT p.k, (sum(length(p.zeros)) OVER (ORDER BY p.k) + p.k - 1)::integer AS i, count(*) OVER () AS parts
    FROM unnest(string_to_array((hours # (hours >> 1))::text, '1')) WITH ORDINALITY AS p(zeros, k)
  ) t
  WHERE t.k < t.parts
  GROUP BY (t.k + 1) / 2
$$;

-- How often a dependency was active (§6.3). active are the hours in which
-- it was reported active, blind the time in which no agent that reports it
-- observed its host, both cut to the period, and until the end of the
-- period.
--
-- A run is a stretch of active hours that follow each other; blind time
-- between two active hours does not end a run, since the dependency may
-- have been active in it. The gap of two runs is the time between the end
-- of one and the start of the next, their interval the time between their
-- starts. idle is the time observed since the end of the last run, and
-- duty the part of the time observed since the start of the first run in
-- which the dependency was active. The dependency has ended when it is
-- idle for longer than a day and than twice its longest gap: before that,
-- its next run may still come. The first rule that holds gives the
-- cadence:
--
--   unknown     no run: no hour was recorded;
--   continuous  not ended, observed for a day at least since the first
--               run, and a duty of 0.9 at least;
--   one-off     ended, after one run shorter than a day;
--   dormant     ended, after a longer run or several;
--   unknown     one run or two: too recent to tell, or one interval,
--               which tells no period;
--   daily, weekly, monthly, periodic
--               two thirds of the intervals at least are within 25% of
--               their median, and the median run lasts half of it at
--               most: daily for a median of 20 to 28 hours, weekly for 6
--               to 8 days, monthly for 27 to 32 days, periodic otherwise;
--   irregular   anything else.
--
-- A dependency of the last four cadences has a period, the median
-- interval, and next_expected, the start of its last run plus the period:
-- an estimate, not a schedule. runs is the number of runs, and last_active
-- the end of the last one. A job whose cycle is longer than the period
-- asked for has one run in it: one-off, or dormant.
--
-- The runs are read in one pass over the stretches in the order they
-- start, so that the cost grows with the hours of activity, not with
-- their square: an active stretch belongs to the run of the last stretch
-- of active or blind time that starts no later than it.
CREATE FUNCTION shawk.cadence(active tstzmultirange, blind tstzmultirange, until timestamptz)
RETURNS TABLE (cadence text, period interval, next_expected timestamptz, runs integer, last_active timestamptz)
LANGUAGE sql STABLE AS $$
WITH b AS (
  -- An hour that was not observed in full tells nothing: the blind time,
  -- widened to whole hours.
  SELECT coalesce(range_agg(tstzrange(date_trunc('hour', lower(x), 'UTC'),
                                      date_trunc('hour', upper(x) - interval '1 microsecond', 'UTC') + interval '1 hour')),
                  '{}'::tstzmultirange) AS blind
  FROM unnest(cadence.blind) AS x
),
run AS (
  SELECT min(q.s) AS s, max(q.e) AS e
  FROM (
    SELECT u.s, u.e, u.hours, count(*) FILTER (WHERE NOT u.hours) OVER (ORDER BY u.s, u.hours) AS stretch
    FROM (
      SELECT lower(g) AS s, NULL::timestamptz AS e, false AS hours
      FROM b CROSS JOIN LATERAL unnest(cadence.active + b.blind) AS g
      UNION ALL
      SELECT lower(x), upper(x), true FROM unnest(cadence.active) AS x
    ) u
  ) q
  WHERE q.hours
  GROUP BY q.stretch
),
r AS (
  SELECT run.s, run.e,
         extract(epoch FROM run.e - run.s) AS len,
         extract(epoch FROM run.s - lag(run.s) OVER (ORDER BY run.s)) AS step,
         extract(epoch FROM run.s - lag(run.e) OVER (ORDER BY run.s)) AS gap
  FROM run
),
stat AS (
  SELECT count(*)::integer AS n, min(r.s) AS first_start, max(r.s) AS last_start, max(r.e) AS last_end,
         max(r.len) AS len, coalesce(max(r.gap), 0) AS max_gap,
         percentile_disc(0.5) WITHIN GROUP (ORDER BY r.step) AS step,
         percentile_disc(0.5) WITHIN GROUP (ORDER BY r.len) AS median_len
  FROM r
),
m AS (
  SELECT stat.*,
         -- The time observed since the end of the last run, and since the
         -- start of the first; the time active since then.
         extract(epoch FROM shawk.duration(tstzmultirange(tstzrange(least(stat.last_end, until), until)) - b.blind)) AS idle,
         extract(epoch FROM shawk.duration(tstzmultirange(tstzrange(least(stat.first_start, until), until)) - b.blind)) AS observed,
         extract(epoch FROM shawk.duration(cadence.active * tstzmultirange(tstzrange(least(stat.first_start, until), until)))) AS on_time,
         (SELECT 3 * count(*) FILTER (WHERE r.step BETWEEN 0.75 * stat.step AND 1.25 * stat.step) >= 2 * count(*)
          FROM r WHERE r.step IS NOT NULL) AS regular
  FROM stat CROSS JOIN b
),
c AS (
  SELECT e.*,
         CASE
           WHEN e.n = 0 THEN 'unknown'
           WHEN NOT e.ended AND e.observed >= 86400 AND e.on_time >= 0.9 * e.observed THEN 'continuous'
           WHEN e.ended AND e.n = 1 AND e.len < 86400 THEN 'one-off'
           WHEN e.ended THEN 'dormant'
           WHEN e.n <= 2 THEN 'unknown'
           WHEN e.regular AND 2 * e.median_len <= e.step THEN
             CASE WHEN e.step BETWEEN 20 * 3600 AND 28 * 3600 THEN 'daily'
                  WHEN e.step BETWEEN 6 * 86400 AND 8 * 86400 THEN 'weekly'
                  WHEN e.step BETWEEN 27 * 86400 AND 32 * 86400 THEN 'monthly'
                  ELSE 'periodic' END
           ELSE 'irregular'
         END AS cadence
  FROM (SELECT m.*, m.idle > greatest(86400, 2 * m.max_gap) AS ended FROM m) e
)
SELECT c.cadence,
       CASE WHEN c.cadence IN ('daily', 'weekly', 'monthly', 'periodic')
            THEN justify_hours(make_interval(secs => c.step)) END,
       CASE WHEN c.cadence IN ('daily', 'weekly', 'monthly', 'periodic')
            THEN c.last_start + make_interval(secs => c.step) END,
       c.n, c.last_end
FROM c
$$;

-- How each host of hosts was observed in [since, until], by name as
-- unobserved_by_name(): the time in which an agent of the name observed,
-- in which it dropped flows, and in which it did not trace UDP or Unix
-- sockets, or traced one network namespace only. agent tells whether an
-- agent of the name ever reported, and pruned is the part of the period
-- before the retention (shawk.retention), which is not observed whatever
-- the sessions say: its dependencies are deleted. translations_untold is
-- the time in which the translations that the agent learned do not name
-- every client that its host masqueraded: it does not trace them (or the
-- connector did not tell), or it folds the peers outside its internal
-- ranges, whose translations it does not learn.
--
-- observed is the time for which the history tells what the host was used
-- for. A session counts from its start, by the clock of the connector
-- (started_at is by the clock of the agent, clock_skew behind), to its
-- last heartbeat, with the tolerance for the delay of the writes of an
-- agent that goes on. The edges keep the times of the agent: with a clock
-- behind, what the agent saw up to the heartbeat is dated up to clock_skew
-- before it, so the session ends that much earlier. A clock ahead does not
-- shorten it: the connector does not write times after its own.
CREATE FUNCTION shawk.observation(since timestamptz, until timestamptz, hosts text[], tolerance interval)
RETURNS TABLE (host text, agent boolean, observed tstzmultirange, pruned tstzmultirange,
               dropped tstzmultirange, dropped_flows bigint,
               udp_untraced tstzmultirange, unix_untraced tstzmultirange, netns_limited tstzmultirange,
               translations_untold tstzmultirange)
LANGUAGE sql STABLE SET search_path = pg_catalog, pg_temp AS $$
WITH ids AS (
  SELECT h.id, h.hostname FROM shawk.hosts h WHERE h.hostname = ANY (observation.hosts)
),
-- Only the sessions that meet the period, as in unobserved_by_name().
s AS (
  SELECT i.hostname, a.udp_traced, a.unix_traced, a.netns_scope, a.last_heartbeat,
         a.peer_fold <> 'none' OR a.translations_traced IS NOT TRUE AS translations_untold,
         least(a.started_at + a.clock_skew, a.last_heartbeat - greatest(a.clock_skew, interval '0')) AS started,
         a.last_heartbeat - greatest(a.clock_skew, interval '0') AS ended
  FROM ids i
  JOIN shawk.agent_sessions a ON a.host_id = i.id
  WHERE a.last_heartbeat > observation.since - observation.tolerance
    AND least(a.started_at + a.clock_skew, a.last_heartbeat) < observation.until
),
-- The tolerance is no time traced, so that the session that follows one
-- is not taken for it.
ses AS (
  SELECT s.hostname,
         range_agg(tstzrange(s.started, s.ended + observation.tolerance)) AS observed,
         range_agg(tstzrange(s.started, s.last_heartbeat)) FILTER (WHERE NOT s.udp_traced) AS udp_untraced,
         range_agg(tstzrange(s.started, s.last_heartbeat)) FILTER (WHERE s.unix_traced IS NOT TRUE) AS unix_untraced,
         range_agg(tstzrange(s.started, s.last_heartbeat)) FILTER (WHERE s.netns_scope <> 'all') AS netns_limited,
         range_agg(tstzrange(s.started, s.last_heartbeat)) FILTER (WHERE s.translations_untold) AS translations_untold
  FROM s GROUP BY s.hostname
),
par AS (
  SELECT i.hostname, range_agg(tstzrange(p.period_start, p.period_end)) AS dropped, sum(p.dropped_flows)::bigint AS dropped_flows
  FROM ids i
  JOIN shawk.partial_observations p ON p.host_id = i.id
  WHERE p.period_end > observation.since AND p.period_start < observation.until
  GROUP BY i.hostname
),
w AS (
  SELECT shawk.period(observation.since, observation.until) AS period,
         coalesce((SELECT tstzmultirange(tstzrange(NULL, r.pruned_before)) FROM shawk.retention r), '{}') AS pruned
)
SELECT n.host,
       EXISTS (SELECT FROM ids i WHERE i.hostname = n.host),
       coalesce(ses.observed, '{}') * w.period - w.pruned,
       w.period * w.pruned,
       coalesce(par.dropped, '{}') * w.period,
       coalesce(par.dropped_flows, 0),
       coalesce(ses.udp_untraced, '{}') * w.period,
       coalesce(ses.unix_untraced, '{}') * w.period,
       coalesce(ses.netns_limited, '{}') * w.period,
       coalesce(ses.translations_untold, '{}') * w.period
FROM (SELECT DISTINCT u.host FROM unnest(observation.hosts) AS u(host) WHERE u.host IS NOT NULL) n
CROSS JOIN w
LEFT JOIN ses ON ses.hostname = n.host
LEFT JOIN par ON par.hostname = n.host
$$;

-- Contract ------------------------------------------------------------------

-- How much of [since, until] each host of hosts was observed, by name:
-- every host that reported since `since` when hosts is NULL. observed is
-- the part of the period, from 0 to 1, for which the history tells what
-- the host was used for: an agent of the name observed, and the time is
-- within the retention. unobserved is the rest, in `gaps` gaps (those of
-- coverage_gaps()), of which before_retention precedes the retention;
-- partly_observed the time in which the agent dropped flows
-- (partly_observed()), and dropped_flows how many. udp_untraced,
-- unix_untraced and netns_limited are the time observed without UDP,
-- without Unix sockets (or by an agent that does not tell), or in one
-- network namespace only. agent is false for a name no agent ever
-- reported under, within the retention.
--
-- The time observed is not that of unobserved_by_name(): a session ends
-- earlier by the time the clock of its host is behind, and nothing is
-- observed before the retention (shawk.observation).
CREATE FUNCTION shawk_v1.coverage(since timestamptz, until timestamptz, hosts text[] DEFAULT NULL,
                                  tolerance interval DEFAULT '3 minutes')
RETURNS TABLE (host text, agent boolean, observed numeric, unobserved interval, gaps integer,
               partly_observed interval, dropped_flows bigint,
               udp_untraced interval, unix_untraced interval, netns_limited interval, before_retention interval)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
  SELECT o.host, o.agent,
         -- Cut, not rounded: 1 is a host observed all along.
         trunc(extract(epoch FROM shawk.duration(o.observed)) / extract(epoch FROM coverage.until - coverage.since), 6),
         shawk.duration(g.gaps), (SELECT count(*)::integer FROM unnest(g.gaps)),
         shawk.duration(o.dropped), o.dropped_flows,
         shawk.duration(o.udp_untraced), shawk.duration(o.unix_untraced), shawk.duration(o.netns_limited),
         shawk.duration(o.pruned)
  FROM shawk.observation(coverage.since, coverage.until,
         coalesce(coverage.hosts,
                  ARRAY(SELECT h.hostname FROM shawk.hosts h GROUP BY h.hostname HAVING max(h.last_seen) >= coverage.since)),
         coverage.tolerance) o
  CROSS JOIN LATERAL (
    SELECT shawk.period(coverage.since, coverage.until) - o.observed AS gaps
  ) g
  WHERE coverage.since < coverage.until
$$;

-- The gaps of coverage(): the stretches of [since, until] for which the
-- history does not tell what a host of hosts was used for, by name, each
-- with its cause: retention for the time before the retention, agent for
-- the time in which no agent of the name observed. Unlike
-- unobserved_by_name(), a name that no agent reported under has a gap, the
-- whole period. The rows are in the order of the hosts, their names
-- compared by bytes, and of the gaps of each.
CREATE FUNCTION shawk_v1.coverage_gaps(since timestamptz, until timestamptz, hosts text[],
                                       tolerance interval DEFAULT '3 minutes')
RETURNS TABLE (host text, gap_start timestamptz, gap_end timestamptz, cause text)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
  SELECT o.host, lower(g.gap), upper(g.gap), g.cause
  FROM shawk.observation(coverage_gaps.since, coverage_gaps.until, coverage_gaps.hosts, coverage_gaps.tolerance) o
  CROSS JOIN LATERAL (
    SELECT x AS gap, 'retention' AS cause FROM unnest(o.pruned) AS x
    UNION ALL
    SELECT x, 'agent' FROM unnest(shawk.period(coverage_gaps.since, coverage_gaps.until) - o.observed - o.pruned) AS x
  ) g
  WHERE coverage_gaps.since < coverage_gaps.until
  ORDER BY o.host COLLATE "C", lower(g.gap)
$$;

-- shawk_v1.dependencies_between() for shawk.dependents(), with the plans it
-- has on its own: nested loops are on within it, whatever its caller sets.
CREATE FUNCTION shawk.dependencies_in(since timestamptz, until timestamptz)
RETURNS TABLE (
  client_host text, client_service text, client_unit text, client_addr inet,
  server_host text, server_service text, server_unit text, server_addr inet,
  port integer, proto text, first_seen timestamptz, last_seen timestamptz,
  observed_by text, client_observed_until timestamptz, server_observed_until timestamptz,
  virtual_addr inet, virtual_port integer, translation text, path text)
LANGUAGE sql STABLE ROWS 100000 SET search_path = pg_catalog, pg_temp SET enable_nestloop = on AS $$
  SELECT * FROM shawk_v1.dependencies_between(dependencies_in.since, dependencies_in.until)
$$;

-- The dependencies that make the dependents of a target (shawk_v1.impact),
-- one row per dependency of the period (shawk_v1.dependencies_between)
-- that makes its client a dependent, with the depth, and the dependent,
-- its server and the port as impact() reports them: cli_host, cli_service,
-- cli_addr, srv_host, srv_service and dep_port. gid numbers the rows of
-- impact(), in their order. The other columns are those of the
-- dependency, which find its edges; a client that the target relays
-- (srv_service ~relay) has the virtual address and port as those of its
-- server.
--
-- The function joins the dependencies of the period with each other, and
-- they are the rows of a function, of which the planner knows nothing: it
-- would join a few rows it expects in nested loops, which take minutes
-- over the hundreds of thousands there are. Nested loops are off, so that
-- the joins hash: the time grows with the dependencies, not their square.
-- The costs of a plan without nested loops are beyond every threshold of
-- the JIT compiler, which then takes seconds for nothing: it is off too.
CREATE FUNCTION shawk.dependents(target_host text, since timestamptz, until timestamptz,
                                 target_service text, target_port integer, target_proto text, max_depth integer)
RETURNS TABLE (
  gid bigint, depth integer, cli_host text, cli_service text, cli_addr inet,
  srv_host text, srv_service text, dep_port integer, proto text,
  first_seen timestamptz, last_seen timestamptz, observed_by text,
  client_host text, client_service text, client_unit text, client_addr inet,
  server_host text, server_service text, server_unit text, server_addr inet,
  port integer, virtual_addr inet, virtual_port integer, path text)
LANGUAGE sql STABLE ROWS 10000 SET search_path = pg_catalog, pg_temp SET enable_nestloop = off SET jit = off AS $$
WITH RECURSIVE
-- The depth asked for, from 1 to 10, and whether the whole host is the
-- target: values, not rows to join, so that the joins below are those of
-- the dependencies alone.
arg AS (
  SELECT least(greatest(coalesce(dependents.max_depth, 3), 1), 10) AS max_depth,
         dependents.target_service IS NULL AND dependents.target_port IS NULL AS whole_host
),
-- The host ids of the target, none if no agent reported under its name.
t AS (
  SELECT h.id FROM shawk.hosts h WHERE h.hostname = dependents.target_host
),
-- The time in which the agents of the target would not have seen a client
-- of it: not observed, or observed in part.
tb AS (
  SELECT shawk.period(dependents.since, dependents.until) - o.observed + o.dropped + o.netns_limited AS blind, o.udp_untraced
  FROM shawk.observation(dependents.since, dependents.until, ARRAY[dependents.target_host], interval '3 minutes') o
),
d AS MATERIALIZED (
  SELECT row_number() OVER () AS id, x.*
  FROM shawk.dependencies_in(dependents.since, dependents.until) x
  WHERE dependents.since < dependents.until
),
-- The periods in which the agents of a name reported addresses
-- (shawk.host_addrs: a period starts anew after the alive window, so an
-- agent that stops ends the periods of all the addresses of its host). Not
-- the history of the retention, which may be millions of periods where
-- hosts or pods come and go: those that meet the period asked for, and of
-- each host the addresses of its last report before the period, which it
-- may still hold in it. They are found from the last heartbeat of the host
-- before the period, through the indexes of the sessions and of the
-- addresses.
hp AS MATERIALIZED (
  SELECT h.hostname, a.addr, a.first_seen, a.last_seen
  FROM shawk.host_addrs a
  JOIN shawk.hosts h ON h.id = a.host_id
  WHERE a.last_seen >= dependents.since - shawk.alive_window()
    AND a.first_seen <= dependents.until + shawk.alive_window()
  UNION
  SELECT h.hostname, a.addr, a.first_seen, a.last_seen
  FROM shawk.hosts h
  CROSS JOIN LATERAL (
    SELECT max(s.last_heartbeat) AS at
    FROM shawk.agent_sessions s
    WHERE s.host_id = h.id AND s.last_heartbeat < dependents.since - shawk.alive_window()
  ) b
  CROSS JOIN LATERAL (
    SELECT a.addr, a.first_seen, a.last_seen
    FROM shawk.host_addrs a
    WHERE a.host_id = h.id
      AND a.last_seen >= b.at - shawk.alive_window() AND a.last_seen <= b.at + shawk.alive_window()
    OFFSET 0
  ) a
),
-- The stretches in which the agents of a name reported any address, when
-- the name was seen, numbered in order: a period starts a stretch when it
-- starts later than the alive window after every period before it ended.
-- Read in one pass over the periods of a name in the order they start,
-- not by comparing every period with every stretch.
hq AS (
  SELECT y.hostname, y.addr, y.first_seen, y.last_seen,
         sum(y.starts) OVER (PARTITION BY y.hostname ORDER BY y.first_seen, y.last_seen, y.addr) AS stretch
  FROM (
    SELECT hp.*,
           coalesce(hp.first_seen > max(hp.last_seen) OVER (PARTITION BY hp.hostname ORDER BY hp.first_seen, hp.last_seen, hp.addr
                                                         ROWS BETWEEN UNBOUNDED PRECEDING AND 1 PRECEDING) + shawk.alive_window(),
                    true)::integer AS starts
    FROM hp
  ) y
),
-- Each stretch with when it started and ended, when the stretch before it
-- ended (with the alive window) and when the next one started.
hs AS (
  SELECT x.hostname, x.stretch, x.seen_from, x.seen_until,
         lag(x.seen_until) OVER w + shawk.alive_window() AS before, lead(x.seen_from) OVER w AS after
  FROM (
    SELECT hq.hostname, hq.stretch, min(hq.first_seen) AS seen_from, max(hq.last_seen) AS seen_until
    FROM hq GROUP BY hq.hostname, hq.stretch
  ) x
  WINDOW w AS (PARTITION BY x.hostname ORDER BY x.stretch)
),
-- The periods of an address in the order they started, numbered by the
-- runs of periods of one name, and when a run of another name started
-- after each run (taken) and ended before it (released). Periods that
-- start together are in the order of their names by bytes ("C"), so that
-- the runs do not change with the collation of the database.
ho AS (
  SELECT y.hostname, y.addr, y.first_seen, y.last_seen, y.stretch,
         sum(y.other) OVER (PARTITION BY y.addr ORDER BY y.first_seen, y.hostname COLLATE "C") AS run
  FROM (
    SELECT hq.*,
           (hq.hostname IS DISTINCT FROM lag(hq.hostname) OVER (PARTITION BY hq.addr
                                                                 ORDER BY hq.first_seen, hq.hostname COLLATE "C"))::integer AS other
    FROM hq
  ) y
),
hr AS (
  SELECT x.addr, x.run, lead(x.starts) OVER w AS taken, lag(x.ends) OVER w AS released
  FROM (SELECT ho.addr, ho.run, min(ho.first_seen) AS starts, max(ho.last_seen) AS ends FROM ho GROUP BY ho.addr, ho.run) x
  WINDOW w AS (PARTITION BY x.addr ORDER BY x.run)
),
-- When each name held each address, as far as the data tells. While its
-- agents report, a host holds the addresses they report. While none
-- reports, it may still hold those of the last report before, and already
-- hold those of the first report after: a period that ends with a stretch
-- goes on to the next stretch of the name, and one that starts with a
-- stretch goes back to the stretch before, but not beyond the time a host
-- of another name reported the address. The inventory gives its addresses
-- to its hosts at all times.
ha AS MATERIALIZED (
  SELECT ho.addr, ho.hostname,
         CASE WHEN ho.first_seen <= hs.seen_from + shawk.alive_window()
              THEN least(ho.first_seen - shawk.alive_window(),
                         greatest(coalesce(hs.before, '-infinity'), coalesce(hr.released, '-infinity')))
              ELSE ho.first_seen - shawk.alive_window() END AS held_from,
         CASE WHEN ho.last_seen >= hs.seen_until - shawk.alive_window()
              THEN greatest(ho.last_seen + shawk.alive_window(),
                            least(coalesce(hs.after, 'infinity'), coalesce(hr.taken, 'infinity')))
              ELSE ho.last_seen + shawk.alive_window() END AS held_until
  FROM ho
  JOIN hs ON hs.hostname = ho.hostname AND hs.stretch = ho.stretch
  JOIN hr ON hr.addr = ho.addr AND hr.run = ho.run
  UNION ALL
  SELECT i.addr, i.host, '-infinity', 'infinity' FROM shawk.inventory_addrs i
),
-- The hosts that may have served a dependency that its client alone saw:
-- the host of the client for loopback, else those that held the address
-- of the server while the dependency was active in the period.
cand AS (
  SELECT d.id, d.client_host, d.server_addr, d.port, d.proto, d.last_seen, d.client_host AS host
  FROM d
  WHERE d.server_host IS NULL AND d.proto <> 'unix'
    AND (d.server_addr << inet '127.0.0.0/8' OR d.server_addr = inet '::1')
  UNION ALL
  SELECT d.id, d.client_host, d.server_addr, d.port, d.proto, d.last_seen, ha.hostname
  FROM d
  JOIN ha ON ha.addr = d.server_addr
  WHERE d.server_host IS NULL AND d.proto <> 'unix'
    AND NOT (d.server_addr << inet '127.0.0.0/8' OR d.server_addr = inet '::1')
    AND ha.held_until >= greatest(d.first_seen, dependents.since)
    AND ha.held_from <= least(d.last_seen, dependents.until)
),
-- Their service: the latest known owner of a listener on the port, the
-- first by bytes ("C") of those last seen together. An address the host of
-- the client holds too is its own: the gateway of a container bridge,
-- which every host has.
srv AS (
  SELECT DISTINCT ON (c.id, c.host) c.id, c.host, l.service, l.unit
  FROM (SELECT cand.*, bool_or(cand.host = cand.client_host) OVER (PARTITION BY cand.id) AS own FROM cand) c
  LEFT JOIN LATERAL (
    SELECT p.service_name AS service, p.unit
    FROM shawk.hosts h
    JOIN shawk.listener_owners l ON l.host_id = h.id
    JOIN shawk.processes p ON p.id = l.process_id
    WHERE h.hostname = c.host AND l.proto = c.proto AND l.port = c.port
      AND l.addr IN (c.server_addr, inet '0.0.0.0', inet '::')
      AND l.last_seen >= dependents.since - interval '15 minutes'
      AND l.first_seen <= c.last_seen + interval '15 minutes'
    ORDER BY l.last_seen DESC, p.service_name COLLATE "C", p.unit COLLATE "C" LIMIT 1
  ) l ON true
  WHERE NOT c.own OR c.host = c.client_host
  ORDER BY c.id, c.host, l.service COLLATE "C"
),
-- The services that the client of a Unix socket without a server may have
-- reached: the owners of the listeners of the name on its host in the
-- period, in whatever namespace and at whatever time (a name served in
-- several namespaces, a client that keeps trying after its server
-- stopped); if no listener of the name is known, any service of the host
-- (~unknown) when a connection of the client was established, or when the
-- connector that wrote the edge did not tell. Failed attempts at a name
-- that nothing is known to serve, as those of every process at the socket
-- of nscd on a host without it, reach no service.
ux AS (
  SELECT d.id, o.service, o.unit
  FROM d
  CROSS JOIN LATERAL (
    SELECT DISTINCT p.service_name AS service, p.unit
    FROM shawk.hosts h
    JOIN shawk.unix_listeners l ON l.host_id = h.id
    JOIN shawk.processes p ON p.id = l.process_id
    WHERE h.hostname = d.client_host AND l.path = d.path
      AND l.last_seen >= dependents.since - interval '15 minutes'
      AND l.first_seen <= dependents.until + interval '15 minutes'
  ) o
  WHERE d.proto = 'unix' AND d.server_host IS NULL
),
uu AS (
  SELECT d.id
  FROM d
  WHERE d.proto = 'unix' AND d.server_host IS NULL
    AND d.id NOT IN (SELECT ux.id FROM ux)
    AND EXISTS (
      SELECT FROM shawk.hosts h
      JOIN shawk.unix_edges e ON e.host_id = h.id
      JOIN shawk.processes p ON p.id = e.process_id
      WHERE h.hostname = d.client_host AND e.path = d.path
        AND p.service_name = d.client_service AND p.unit = d.client_unit
        AND e.last_seen >= dependents.since - interval '15 minutes'
        AND e.first_seen <= dependents.until + interval '15 minutes'
        AND e.established IS NOT FALSE)
),
-- The dependencies with the host, service and unit of their server: those
-- that an agent saw the server of, those that the client alone saw, with
-- a row per host that may have served them, and those over Unix sockets
-- without a server. A dependency that reaches no known host is left out.
-- cli_host names a client without an agent as the inventory does.
r AS MATERIALIZED (
  SELECT x.id, x.client_host, x.client_service, x.client_unit, x.client_addr,
         x.server_host, x.server_service, x.server_unit, x.server_addr, x.port, x.proto,
         x.first_seen, x.last_seen, x.observed_by, x.virtual_addr, x.virtual_port, x.path,
         x.srv_host, x.srv_service, x.srv_unit, coalesce(x.client_host, ci.host) AS cli_host
  FROM (
    SELECT d.*, d.server_host AS srv_host, d.server_service AS srv_service, d.server_unit AS srv_unit
    FROM d WHERE d.server_host IS NOT NULL
    UNION ALL
    SELECT d.*, s.host, s.service, s.unit
    FROM d JOIN srv s ON s.id = d.id
    UNION ALL
    SELECT d.*, d.client_host, ux.service, ux.unit
    FROM d JOIN ux ON ux.id = d.id
    UNION ALL
    SELECT d.*, d.client_host, '~unknown', NULL
    FROM d JOIN uu ON uu.id = d.id
  ) x
  LEFT JOIN shawk.inventory_addrs ci ON x.client_host IS NULL AND ci.addr = x.client_addr
),
-- The connections that the target relayed in the kernel, as its agents
-- learned them from conntrack (shawk.learned_translations): a load
-- balancer, a NAT gateway, a node that forwards to the pods of others. No
-- process of the target accepted them, and the dependency is that of the
-- client on the backend, so the target shows nowhere else. Not those of
-- its own clients (an address it holds, or the address of a client edge
-- of its own), nor those to a backend that it serves itself when the
-- server edge has the address of the client, and so the client: a
-- published port. When the target also replaced the address of the client
-- by one of its own (masquerade, as for a NodePort), the server edge has
-- the address of the target, which a process of the target may use too (a
-- kubelet that probes the pod): the edge then looks like the target's own,
-- and the translation alone tells the client outside it.
lt AS (
  SELECT l.proto, l.client_addr, l.virtual_addr, l.virtual_port, l.backend_port,
         min(l.first_seen) AS first_seen, max(l.last_seen) AS last_seen
  FROM (
    -- backend_port is the port of a backend on the target itself, an
    -- address it holds or one a socket of it serves on: the client is one
    -- of that port too, NULL for a backend elsewhere.
    SELECT x.proto, x.client_addr, x.virtual_addr, x.virtual_port, x.source_addr, x.backend_addr, x.host_id,
           x.first_seen, x.last_seen,
           CASE WHEN EXISTS (SELECT FROM ha
                             WHERE ha.hostname = dependents.target_host AND ha.addr = x.backend_addr
                               AND ha.held_until >= x.first_seen AND ha.held_from <= x.last_seen)
                  OR EXISTS (SELECT FROM shawk.edges e
                             WHERE e.host_id = x.host_id AND e.role = 'server' AND e.proto = x.proto
                               AND e.local_addr = x.backend_addr AND e.port = x.backend_port)
                THEN x.backend_port END AS backend_port
    FROM shawk.learned_translations x
  ) l
  WHERE l.host_id IN (SELECT t.id FROM t)
    AND l.last_seen >= dependents.since AND l.first_seen <= dependents.until
    AND NOT (l.client_addr << inet '127.0.0.0/8' OR l.client_addr = inet '::1')
    AND NOT EXISTS (SELECT FROM ha
                    WHERE ha.hostname = dependents.target_host AND ha.addr = l.client_addr
                      AND ha.held_until >= l.first_seen AND ha.held_from <= l.last_seen)
    AND NOT EXISTS (SELECT FROM shawk.edges e
                    WHERE e.host_id = l.host_id AND e.role = 'client' AND e.proto = l.proto
                      AND e.local_addr = l.client_addr AND e.remote_addr = l.virtual_addr AND e.port = l.virtual_port)
    AND NOT (l.source_addr = l.client_addr
             AND EXISTS (SELECT FROM shawk.edges e
                         WHERE e.host_id = l.host_id AND e.role = 'server' AND e.proto = l.proto
                           AND e.local_addr = l.backend_addr AND e.port = l.backend_port
                           AND e.remote_addr = l.client_addr
                           AND e.last_seen >= dependents.since - interval '15 minutes'
                           AND e.first_seen <= dependents.until + interval '15 minutes'))
  GROUP BY l.proto, l.client_addr, l.virtual_addr, l.virtual_port, l.backend_port
),
-- The clients that the target relayed, each once per virtual address and
-- port: those of the connections above, by the name that an agent on the
-- client gives it, if any; those that reached a backend through a virtual
-- address that the target held (a translation of the configuration, or
-- one that another host learned); and those that the backends of a
-- translation of the configuration saw, when the target held its virtual
-- address, since they may have come through it: the clients that a
-- backend saw alone, and, through a translation with sources, whatever a
-- backend saw from a source, also when a client with an agent explains
-- the edge, since the backend cannot tell the clients behind a source
-- apart. They are clients of the target on the virtual address and port,
-- of no process of it: ~relay. Of the rows of a client, one is kept: the
-- first by who saw it (both sides, the client, the server), then the one
-- first seen; of those first seen together, the one last seen latest,
-- then the first by the name of its server by bytes ("C"), so that the
-- same data gives the same row.
relay AS (
  SELECT -row_number() OVER () AS id, y.*
  FROM (
    SELECT DISTINCT ON (x.client_host, x.client_service, x.client_unit, x.client_addr, x.server_addr, x.port, x.proto, x.backend_port)
           x.client_host, x.client_service, x.client_unit, x.client_addr,
           x.server_host, NULL::text AS server_service, NULL::text AS server_unit, x.server_addr, x.port, x.proto,
           x.first_seen, x.last_seen, x.observed_by, NULL::inet AS virtual_addr, NULL::integer AS virtual_port, NULL::text AS path,
           dependents.target_host AS srv_host, '~relay'::text AS srv_service, NULL::text AS srv_unit,
           coalesce(x.client_host, ci.host) AS cli_host, x.backend_port
    FROM (
      SELECT c.client_host, c.client_service, c.client_unit, lt.client_addr,
             CASE WHEN c.client_host IS NULL THEN dependents.target_host END AS server_host,
             lt.virtual_addr AS server_addr, lt.virtual_port AS port, lt.proto, lt.first_seen, lt.last_seen,
             CASE WHEN c.client_host IS NULL THEN 'server' ELSE 'both' END AS observed_by, lt.backend_port
      FROM lt
      LEFT JOIN (
        SELECT DISTINCT d.client_host, d.client_service, d.client_unit, d.client_addr, d.proto,
               coalesce(d.virtual_addr, d.server_addr) AS addr, coalesce(d.virtual_port, d.port) AS port
        FROM d WHERE d.client_host IS NOT NULL AND d.proto <> 'unix'
      ) c ON c.client_addr = lt.client_addr AND c.addr = lt.virtual_addr AND c.port = lt.virtual_port AND c.proto = lt.proto
      UNION ALL
      SELECT d.client_host, d.client_service, d.client_unit, d.client_addr, NULL,
             d.virtual_addr, d.virtual_port, d.proto, d.first_seen, d.last_seen, 'client', NULL
      FROM d
      JOIN ha ON ha.addr = d.virtual_addr AND ha.hostname = dependents.target_host
      WHERE d.virtual_addr IS NOT NULL
        AND d.server_host IS DISTINCT FROM dependents.target_host
        AND ha.held_until >= greatest(d.first_seen, dependents.since)
        AND ha.held_from <= least(d.last_seen, dependents.until)
      UNION ALL
      SELECT NULL, NULL, NULL, d.client_addr, d.server_host,
             v.addr::inet, CASE WHEN v.port = 0 THEN d.port ELSE v.port END, d.proto, d.first_seen, d.last_seen, 'server',
             CASE WHEN d.server_host = dependents.target_host THEN d.port END
      FROM shawk.translations v
      JOIN ha ON ha.addr = v.addr::inet AND ha.hostname = dependents.target_host
      JOIN shawk.translations b ON b.name = v.name AND b.proto = v.proto AND b.side = 'backend'
      JOIN d ON d.proto = b.proto AND d.server_addr <<= b.addr AND b.port IN (0, d.port)
      WHERE v.side = 'virtual'
        AND (b.port <> 0 OR v.port IN (0, d.port))
        AND d.server_host IS NOT NULL
        AND ha.held_until >= greatest(d.first_seen, dependents.since)
        AND ha.held_from <= least(d.last_seen, dependents.until)
        AND CASE WHEN EXISTS (SELECT FROM shawk.translations x
                              WHERE x.name = v.name AND x.proto = v.proto AND x.side = 'source')
                 THEN EXISTS (SELECT FROM shawk.translations x
                              WHERE x.name = v.name AND x.proto = v.proto AND x.side = 'source' AND d.client_addr <<= x.addr)
                 ELSE d.client_host IS NULL AND d.server_host <> dependents.target_host END
    ) x
    LEFT JOIN shawk.inventory_addrs ci ON x.client_host IS NULL AND ci.addr = x.client_addr
    WHERE x.client_host IS DISTINCT FROM dependents.target_host
    ORDER BY x.client_host, x.client_service, x.client_unit, x.client_addr, x.server_addr, x.port, x.proto, x.backend_port,
             x.observed_by COLLATE "C", x.first_seen, x.last_seen DESC, x.server_host COLLATE "C"
  ) y
),
-- The dependencies on the target. Those of a service are on the service,
-- on a socket of its host without a known owner (~unknown) or on what its
-- host relays (~relay), either of which may be the service's; and, when
-- the target was not observed while the dependency was active, or never,
-- on a port of the host whose owner is not known.
--
-- A client is no dependent if it is part of the target, which only what
-- an agent saw on the target itself tells: a process on the host, or a
-- peer on loopback, when the whole host is the target; a process of the
-- service, when a service is; the process that serves the port, by its
-- unit, when a port alone is. An address of the target tells nothing: a
-- host that translates addresses is the source of the clients behind it.
direct AS (
  SELECT r.*
  FROM r
  WHERE r.srv_host = dependents.target_host
    AND (dependents.target_service IS NULL
         OR r.srv_service IN (dependents.target_service, '~unknown')
         OR (r.srv_service IS NULL
             AND (NOT EXISTS (SELECT FROM t)
                  OR EXISTS (SELECT FROM tb
                             WHERE tstzrange(greatest(r.first_seen, dependents.since),
                                             greatest(least(r.last_seen, dependents.until), greatest(r.first_seen, dependents.since)), '[]')
                                   && (tb.blind + CASE WHEN r.proto = 'udp' THEN tb.udp_untraced ELSE '{}' END)))))
    AND (dependents.target_port IS NULL OR r.port = dependents.target_port)
    AND (dependents.target_proto IS NULL OR r.proto = dependents.target_proto)
    AND NOT CASE
      WHEN (SELECT arg.whole_host FROM arg) THEN
        r.client_host IS NOT DISTINCT FROM dependents.target_host
        OR (r.client_host IS NULL AND (r.client_addr << inet '127.0.0.0/8' OR r.client_addr = inet '::1'))
      WHEN dependents.target_service IS NOT NULL THEN
        r.client_host IS NOT DISTINCT FROM dependents.target_host
        AND r.client_service IS NOT DISTINCT FROM dependents.target_service
      ELSE
        r.client_host IS NOT DISTINCT FROM dependents.target_host
        AND r.client_service IS NOT DISTINCT FROM r.srv_service
        AND r.client_unit IS NOT DISTINCT FROM r.srv_unit
        AND r.client_service IS DISTINCT FROM '~unknown'
    END
  UNION ALL
  -- A client that the target relays to a backend of its own is one of the
  -- port of the backend as of the virtual port it connected to.
  SELECT y.id, y.client_host, y.client_service, y.client_unit, y.client_addr,
         y.server_host, y.server_service, y.server_unit, y.server_addr, y.port, y.proto,
         y.first_seen, y.last_seen, y.observed_by, y.virtual_addr, y.virtual_port, y.path,
         y.srv_host, y.srv_service, y.srv_unit, y.cli_host
  FROM relay y
  WHERE (dependents.target_port IS NULL OR dependents.target_port IN (y.port, y.backend_port))
    AND (dependents.target_proto IS NULL OR y.proto = dependents.target_proto)
),
-- The dependents with an agent, by the depths they are reached at. The
-- sockets without a known owner of a host (~unknown) are no service: their
-- clients are not those of the socket that used the target.
g AS MATERIALIZED (
  SELECT DISTINCT r.srv_host, r.srv_service, r.client_host, r.client_service
  FROM r
  WHERE r.client_host IS NOT NULL AND r.client_service <> '~unknown' AND r.srv_service IS NOT NULL
    AND NOT (r.client_host = r.srv_host AND r.client_service = r.srv_service)
),
walk (depth, host, service) AS (
  SELECT 1, x.client_host, x.client_service FROM direct x
  WHERE x.client_host IS NOT NULL AND x.client_service <> '~unknown'
  UNION
  SELECT w.depth + 1, g.client_host, g.client_service
  FROM walk w
  JOIN g ON g.srv_host = w.host AND g.srv_service = w.service
  WHERE w.depth < (SELECT arg.max_depth FROM arg)
    AND NOT (g.client_host = dependents.target_host
             AND ((SELECT arg.whole_host FROM arg) OR g.client_service IS NOT DISTINCT FROM dependents.target_service))
),
node AS MATERIALIZED (
  SELECT w.host, w.service, min(w.depth) AS depth FROM walk w GROUP BY w.host, w.service
),
-- The dependencies reported: those on the target, and those on a dependent
-- of the depth before of clients not yet reached.
hit AS (
  SELECT 1 AS depth, x.* FROM direct x
  UNION ALL
  SELECT n.depth + 1, r.*
  FROM node n
  JOIN r ON r.srv_host = n.host AND r.srv_service = n.service
  WHERE n.depth < (SELECT arg.max_depth FROM arg)
    AND NOT (r.client_host IS NOT DISTINCT FROM n.host AND r.client_service IS NOT DISTINCT FROM n.service)
    AND NOT (r.cli_host IS NOT DISTINCT FROM dependents.target_host
             AND ((SELECT arg.whole_host FROM arg) OR r.client_service IS NOT DISTINCT FROM dependents.target_service))
    AND NOT EXISTS (SELECT FROM node nc
                    WHERE nc.host = r.client_host AND nc.service = r.client_service AND nc.depth <= n.depth)
    AND r.id NOT IN (SELECT x.id FROM direct x)
)
SELECT dense_rank() OVER (ORDER BY x.depth, x.cli_host COLLATE "C", x.cli_service COLLATE "C", x.cli_addr,
                                   x.srv_host COLLATE "C", x.srv_service COLLATE "C", x.dep_port, x.proto COLLATE "C"),
       x.depth, x.cli_host, x.cli_service, x.cli_addr, x.srv_host, x.srv_service, x.dep_port, x.proto,
       x.first_seen, x.last_seen, x.observed_by,
       x.client_host, x.client_service, x.client_unit, x.client_addr,
       x.server_host, x.server_service, x.server_unit, x.server_addr,
       x.port, x.virtual_addr, x.virtual_port, x.path
FROM (
  SELECT h.*,
         coalesce(h.client_service, shawk_v1.peer_class(h.client_addr)) AS cli_service,
         CASE WHEN h.client_host IS NULL THEN h.client_addr END AS cli_addr,
         shawk.dependency_port(coalesce(h.srv_service, shawk_v1.peer_class(h.server_addr)), h.server_unit,
                               h.server_addr, h.port, h.proto) AS dep_port
  FROM hit h
) x
$$;

-- The dependents of a host in [since, until]: the clients that used it,
-- at depth 1, and those that used a dependent of the depth before, up to
-- max_depth (1 to 10). target_service, target_port and target_proto narrow
-- the target to a service of the host, a port and a transport.
--
-- A row is the dependency of a client (client_host and client_service) on
-- a server (server_host and server_service) on a port: 0 under the rules
-- of ports, as in the dependencies between services. A client without an
-- agent has client_addr, the name of its address as its service
-- (peer_class) and the host the inventory gives its address, if any; one
-- with an agent has no client_addr. observed_by tells which sides saw it.
--
-- The rows are in the order of depth, client_host (the clients without a
-- host last), client_service, client_addr, server_host, server_service,
-- port and proto. Names are compared by bytes ("C"), whatever the
-- collation of the database: the same data gives the same rows in the
-- same order.
--
-- The server of a dependency that its client alone saw is the host that
-- held the address then, the host of the client for loopback and for an
-- address the client holds too, or the host the inventory gives the
-- address; its service is the latest known owner of a listener on the
-- port, NULL if none. A host whose agents did not report then held the
-- address if it was among the last they reported before or the first they
-- reported after, and no host of another name reported it in between: a
-- host that is used while its agent is stopped keeps its dependents.
--
-- The clients of a host are also those it relays in the kernel, with the
-- server_service ~relay and the virtual address and port they connected
-- to: a load balancer, a NAT gateway, a node that forwards to the pods of
-- other nodes. They are the clients of the translations its agents
-- learned, unless the client or the backend is on the host itself; those
-- that reached a backend through a virtual address the host held; and
-- those that the backends of a translation of the configuration saw
-- alone, when the host held its virtual address.
--
-- The dependents of a service of a host are the clients of the service;
-- those of a socket of the host without a known owner (~unknown) and
-- those the host relays (~relay), either of which may be of any service;
-- those of a port of the host whose owner is not known, seen by clients
-- alone, while the host was not observed (or dropped flows, or traced one
-- namespace), or when no agent ever reported under its name; and, over
-- Unix sockets, the clients of a name without a server in their
-- namespace, for the services that listened on the name in the period,
-- or for every service (~unknown) when no listener of the name is known
-- and a connection was established.
--
-- A client is a dependent of the target unless it is part of it, which
-- only an agent on the target tells: a process on the target, or a peer
-- on loopback, when the whole host is the target; a process of the
-- service, when a service is; the process that serves the port, by its
-- unit, when a port alone is. A connection from an address of the target
-- that no process on it made is that of a dependent: the target may
-- translate the addresses of the clients behind it.
--
-- A dependent with an agent is followed: the clients of its service on
-- its host are dependents of the next depth, unless they are part of the
-- target or already dependents of a lesser depth, so that a dependent
-- with an agent is reported once, at the depth it is first reached; one
-- without an agent is reported with each server it uses. The dependencies
-- of the period are followed at most once per depth.
--
-- cadence, period, next_expected and runs are those of shawk.cadence() over
-- the hours of activity of its edges (shawk.edge_activity), with the time
-- in which none of the hosts that saw it was observed as blind. The
-- cadence is unknown when the hours end before the dependency was last
-- seen: activity that a connector did not record. They are NULL for the
-- dependents deeper than cadence_depth, 1 by default: the cadence reads
-- the hours of every edge of a dependent, which is a fraction of a
-- millisecond each and minutes for the tens of thousands of dependents
-- that a hub has at depth 3, where the dependents of depth 1 are those
-- that decide.
CREATE FUNCTION shawk_v1.impact(target_host text, since timestamptz, until timestamptz,
                                target_service text DEFAULT NULL, target_port integer DEFAULT NULL,
                                target_proto text DEFAULT NULL, max_depth integer DEFAULT 3,
                                cadence_depth integer DEFAULT 1)
RETURNS TABLE (
  depth integer, client_host text, client_service text, client_addr inet,
  server_host text, server_service text, port integer, proto text,
  first_seen timestamptz, last_seen timestamptz, observed_by text,
  cadence text, period interval, next_expected timestamptz, runs integer)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
WITH sel AS MATERIALIZED (
  SELECT * FROM shawk.dependents(impact.target_host, impact.since, impact.until, impact.target_service,
                                 impact.target_port, impact.target_proto, impact.max_depth)
),
grp AS (
  SELECT s.gid, s.depth, s.cli_host, s.cli_service, s.cli_addr, s.srv_host, s.srv_service, s.dep_port, s.proto,
         min(s.first_seen) AS first_seen, max(s.last_seen) AS last_seen,
         bool_or(s.observed_by IN ('both', 'client')) AS by_client,
         bool_or(s.observed_by IN ('both', 'server')) AS by_server,
         -- The hosts whose agents saw it: one of each side at most, or
         -- the last by bytes ("C") of the backends that saw a client of
         -- a relay.
         max(s.client_host COLLATE "C") AS client_agent, max(s.server_host COLLATE "C") AS server_agent
  FROM sel s
  GROUP BY s.gid, s.depth, s.cli_host, s.cli_service, s.cli_addr, s.srv_host, s.srv_service, s.dep_port, s.proto
),
-- The hours of activity of the edges of each dependent, by month: the
-- client edges and the server edges of its dependencies, found by their
-- hosts, addresses, port and process. The edges of each dependency are
-- read through the index of their key (OFFSET 0 keeps the planner from
-- joining all the edges of a process instead).
keys AS (
  SELECT DISTINCT s.gid, s.proto, s.client_host, s.client_service, s.client_unit, s.client_addr,
         s.server_host, s.server_service, s.server_unit, s.server_addr, s.port, s.virtual_addr, s.virtual_port, s.path
  FROM sel s
  WHERE s.depth <= coalesce(impact.cadence_depth, 1)
),
months AS (
  SELECT k.gid, a.month, a.hours
  FROM keys k
  JOIN shawk.hosts h ON h.hostname = k.client_host
  CROSS JOIN LATERAL (
    SELECT a.month, a.hours
    FROM shawk.edges e
    JOIN shawk.processes p ON p.id = e.process_id
    JOIN shawk.edge_activity a ON a.edge_id = e.id
    WHERE e.host_id = h.id AND e.role = 'client' AND e.proto = k.proto AND e.local_addr = k.client_addr
      AND e.remote_addr = coalesce(k.virtual_addr, k.server_addr) AND e.port = coalesce(k.virtual_port, k.port)
      AND p.service_name = k.client_service AND p.unit = k.client_unit
      AND a.month > impact.since - interval '31 days' AND a.month < impact.until
    OFFSET 0
  ) a
  WHERE k.proto <> 'unix'
  UNION ALL
  SELECT k.gid, a.month, a.hours
  FROM keys k
  JOIN shawk.hosts h ON h.hostname = k.server_host
  CROSS JOIN LATERAL (
    SELECT a.month, a.hours
    FROM shawk.edges e
    JOIN shawk.processes p ON p.id = e.process_id
    JOIN shawk.edge_activity a ON a.edge_id = e.id
    WHERE e.host_id = h.id AND e.role = 'server' AND e.proto = k.proto AND e.local_addr = k.server_addr
      AND e.remote_addr = k.client_addr AND e.port = k.port
      AND p.service_name = k.server_service AND p.unit = k.server_unit
      AND a.month > impact.since - interval '31 days' AND a.month < impact.until
    OFFSET 0
  ) a
  WHERE k.proto <> 'unix'
  UNION ALL
  SELECT k.gid, a.month, a.hours
  FROM keys k
  JOIN shawk.hosts h ON h.hostname = k.client_host
  CROSS JOIN LATERAL (
    SELECT a.month, a.hours
    FROM shawk.unix_edges e
    JOIN shawk.processes p ON p.id = e.process_id
    JOIN shawk.unix_edge_activity a ON a.edge_id = e.id
    WHERE e.host_id = h.id AND e.path = k.path
      AND p.service_name = k.client_service AND p.unit = k.client_unit
      AND a.month > impact.since - interval '31 days' AND a.month < impact.until
    OFFSET 0
  ) a
  WHERE k.proto = 'unix'
),
active AS (
  SELECT b.gid, range_agg(r) AS hours
  FROM (SELECT months.gid, months.month, bit_or(months.hours) AS hours FROM months GROUP BY months.gid, months.month) b
  CROSS JOIN LATERAL shawk.activity_ranges(b.month, b.hours) AS r
  GROUP BY b.gid
),
-- When the hosts that saw the dependents were observed.
obs AS (
  SELECT o.host, o.observed
  FROM shawk.observation(impact.since, impact.until,
         ARRAY(SELECT g.client_agent FROM grp g WHERE g.depth <= coalesce(impact.cadence_depth, 1)
               UNION
               SELECT g.server_agent FROM grp g WHERE g.depth <= coalesce(impact.cadence_depth, 1)), interval '3 minutes') o
),
-- The cadences, of the dependents up to cadence_depth.
cad AS (
  SELECT g.gid,
         CASE WHEN c.last_active < least(g.last_seen, impact.until) - interval '2 minutes' THEN 'unknown' ELSE c.cadence END AS cadence,
         CASE WHEN c.last_active >= least(g.last_seen, impact.until) - interval '2 minutes' THEN c.period END AS period,
         CASE WHEN c.last_active >= least(g.last_seen, impact.until) - interval '2 minutes' THEN c.next_expected END AS next_expected,
         c.runs
  FROM grp g
  CROSS JOIN (SELECT shawk.period(impact.since, impact.until) AS period) w
  LEFT JOIN active a ON a.gid = g.gid
  LEFT JOIN obs oc ON g.by_client AND oc.host = g.client_agent
  LEFT JOIN obs os ON g.by_server AND os.host = g.server_agent
  CROSS JOIN LATERAL shawk.cadence(
    coalesce(a.hours, '{}') * w.period,
    w.period - (coalesce(oc.observed, '{}') + coalesce(os.observed, '{}')),
    impact.until) c
  WHERE g.depth <= coalesce(impact.cadence_depth, 1)
)
SELECT g.depth, g.cli_host, g.cli_service, g.cli_addr, g.srv_host, g.srv_service, g.dep_port, g.proto,
       g.first_seen, g.last_seen,
       CASE WHEN g.by_client AND g.by_server THEN 'both' WHEN g.by_client THEN 'client' ELSE 'server' END,
       c.cadence, c.period, c.next_expected, c.runs
FROM grp g
LEFT JOIN cad c ON c.gid = g.gid
ORDER BY g.depth, g.cli_host COLLATE "C", g.cli_service COLLATE "C", g.cli_addr,
         g.srv_host COLLATE "C", g.srv_service COLLATE "C", g.dep_port, g.proto COLLATE "C"
$$;

-- Whether a host, or a service or port of it, can be removed, from what
-- was observed in [since, until]. One row:
--
--   UNSAFE        it has dependents (impact() at depth 1): reasons is
--                 {active_dependents};
--   INCONCLUSIVE  no dependent was seen, but the target was not watched
--                 enough to tell that there was none: coverage is below
--                 min_coverage, or no agent ever reported under the name.
--                 reasons tell what was missing;
--   SAFE          no dependent was seen, and the target was watched.
--
-- coverage is the part of the period, from 0 to 1, for which the history
-- tells all that the target covers: an agent of the target observed
-- (not_observed otherwise), within the retention (before_retention),
-- without dropped flows (dropped_flows), in every network namespace
-- (netns_limited), with UDP unless target_proto is another transport
-- (udp_not_traced), with Unix sockets when the target is a service
-- without a port (unix_not_traced), and, when a pod or a container of the
-- target accepted connections from an address of the host itself, with
-- the translations that tell the clients the host masqueraded
-- (masquerade_not_traced: the agent does not trace them, or folds the
-- peers outside its internal ranges, whose translations it does not
-- learn). A target that no agent reported under
-- has a coverage of 0: unknown_host, or no_agent for a host of the
-- inventory, whose clients without an agent nothing would tell.
-- min_coverage is 1 by default: any gap makes the verdict INCONCLUSIVE.
-- tolerance is the delay of writes, as in coverage(): 1 hour at most.
--
-- A service that no process of the host had in the period
-- (unknown_service), and a port that no socket listened on nor served
-- there, or none of the service when both are given (unknown_port), are
-- INCONCLUSIVE too, whatever the coverage: nothing used what shawk does
-- not know of, a name or a port mistyped included. target_proto unix is
-- for a service without a port: the clients of a Unix socket are on its
-- host.
--
-- direct counts the dependents, those of depth 1 of impact(): the verdict
-- does not follow them, which impact() does. caveats are the shortfalls of
-- the coverage that did not decide the verdict, with which the dependents
-- listed may not be all. unobserved, gaps and partly_observed are those of
-- coverage() for the target.
CREATE FUNCTION shawk_v1.impact_verdict(target_host text, since timestamptz, until timestamptz,
                                        target_service text DEFAULT NULL, target_port integer DEFAULT NULL,
                                        target_proto text DEFAULT NULL, min_coverage numeric DEFAULT 1,
                                        tolerance interval DEFAULT '3 minutes')
RETURNS TABLE (verdict text, reasons text[], caveats text[], direct bigint,
               coverage numeric, unobserved interval, gaps integer, partly_observed interval)
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
  period tstzmultirange;
  o record;
  missing tstzmultirange;
  blind tstzmultirange;
  covered numeric;
  shortfalls text[];
  inventoried boolean;
  unknown boolean := false;
  masqueraded tstzmultirange;
BEGIN
  IF since IS NULL OR until IS NULL OR since >= until THEN
    RAISE EXCEPTION 'the period is empty: % to %', since, until USING ERRCODE = 'invalid_parameter_value';
  END IF;
  IF target_host IS NULL OR target_host = '' THEN
    RAISE EXCEPTION 'no target host' USING ERRCODE = 'invalid_parameter_value';
  END IF;
  IF min_coverage IS NULL OR min_coverage <= 0 OR min_coverage > 1 THEN
    RAISE EXCEPTION 'min_coverage is above 0, up to 1: %', min_coverage USING ERRCODE = 'invalid_parameter_value';
  END IF;
  IF target_proto NOT IN ('tcp', 'udp', 'unix') THEN
    RAISE EXCEPTION 'target_proto is tcp, udp or unix: %', target_proto USING ERRCODE = 'invalid_parameter_value';
  END IF;
  IF target_port < 1 OR target_port > 65535 THEN
    RAISE EXCEPTION 'target_port is from 1 to 65535: %', target_port USING ERRCODE = 'invalid_parameter_value';
  END IF;
  -- The clients of a Unix socket are on its host, and a socket has no
  -- port: only a service has dependents over Unix sockets.
  IF target_proto = 'unix' AND (target_service IS NULL OR target_port IS NOT NULL) THEN
    RAISE EXCEPTION 'target_proto unix is for a target_service, without a target_port'
      USING ERRCODE = 'invalid_parameter_value';
  END IF;
  -- The tolerance is the delay of writes: one that hides gaps of hours is
  -- a mistake.
  IF tolerance IS NULL OR tolerance < interval '0' OR tolerance > interval '1 hour' THEN
    RAISE EXCEPTION 'tolerance is from 0 to 1 hour: %', tolerance USING ERRCODE = 'invalid_parameter_value';
  END IF;
  period := shawk.period(since, until);

  SELECT count(DISTINCT (i.cli_host, i.cli_service, i.cli_addr)) INTO direct
  FROM shawk.dependents(target_host, since, until, target_service, target_port, target_proto, 1) i;

  SELECT * INTO o FROM shawk.observation(since, until, ARRAY[target_host], tolerance);
  inventoried := EXISTS (SELECT FROM shawk.inventory_hosts h WHERE h.host = target_host);
  missing := period - o.observed;
  blind := missing + o.dropped + o.netns_limited;
  shortfalls := CASE WHEN NOT o.agent AND inventoried THEN ARRAY['no_agent']
                     WHEN NOT o.agent THEN ARRAY['unknown_host']
                     WHEN NOT isempty(missing - o.pruned) THEN ARRAY['not_observed']
                     ELSE '{}'::text[] END;
  IF o.agent AND NOT isempty(o.pruned) THEN
    shortfalls := shortfalls || 'before_retention'::text;
  END IF;
  IF NOT isempty(o.dropped) THEN
    shortfalls := shortfalls || 'dropped_flows'::text;
  END IF;
  IF NOT isempty(o.netns_limited) THEN
    shortfalls := shortfalls || 'netns_limited'::text;
  END IF;
  IF (target_proto IS NULL OR target_proto = 'udp') AND NOT isempty(o.udp_untraced) THEN
    blind := blind + o.udp_untraced;
    shortfalls := shortfalls || 'udp_not_traced'::text;
  END IF;
  IF target_service IS NOT NULL AND target_port IS NULL AND (target_proto IS NULL OR target_proto = 'unix')
     AND NOT isempty(o.unix_untraced) THEN
    blind := blind + o.unix_untraced;
    shortfalls := shortfalls || 'unix_not_traced'::text;
  END IF;
  -- A socket of the target that accepted connections from an address of
  -- the host itself, in a network namespace in which no client of the host
  -- has that address: a pod or a container reached over the bridge. Its
  -- clients on the host may be part of the target, but the same edge is
  -- that of the clients outside the host whose address the host replaced
  -- by its own (masquerade, as for a NodePort), which only the
  -- translations that the agent learned tell: they are dependents
  -- (~relay). While the agent did not learn them all, nothing tells that
  -- there was none.
  IF NOT isempty(o.translations_untold) THEN
    SELECT coalesce(range_agg(tstzrange(greatest(s.first_seen, since),
                                        greatest(least(s.last_seen, until), greatest(s.first_seen, since)), '[]')), '{}')
    INTO masqueraded
    FROM shawk.hosts h
    JOIN shawk.edges s ON s.host_id = h.id AND s.role = 'server'
    JOIN shawk.processes p ON p.id = s.process_id
    WHERE h.hostname = target_host
      AND s.last_seen >= since AND s.first_seen <= until
      AND (target_proto IS NULL OR s.proto = target_proto)
      AND (target_port IS NULL OR s.port = target_port)
      AND (target_service IS NULL OR p.service_name IN (target_service, '~unknown'))
      AND NOT (s.remote_addr << inet '127.0.0.0/8' OR s.remote_addr = inet '::1')
      AND EXISTS (SELECT FROM shawk.hosts h2
                  JOIN shawk.host_addrs a ON a.host_id = h2.id
                  WHERE h2.hostname = target_host AND a.addr = s.remote_addr
                    AND a.last_seen >= s.first_seen - shawk.alive_window()
                    AND a.first_seen <= s.last_seen + shawk.alive_window())
      AND NOT EXISTS (SELECT FROM shawk.edges c
                      WHERE c.role = 'client' AND c.proto = s.proto AND c.remote_addr = s.local_addr AND c.port = s.port
                        AND c.local_addr = s.remote_addr AND c.host_id = s.host_id AND c.netns = s.netns);
    masqueraded := masqueraded * o.translations_untold;
    IF NOT isempty(masqueraded) THEN
      blind := blind + masqueraded;
      shortfalls := shortfalls || 'masquerade_not_traced'::text;
    END IF;
  END IF;

  -- What the agent of the host does not know of was not seen to be used,
  -- which tells nothing: a service or a port that is not there, or is
  -- misspelt.
  IF o.agent AND target_service IS NOT NULL AND NOT EXISTS (
       SELECT FROM shawk.hosts h
       JOIN shawk.processes p ON p.host_id = h.id
       WHERE h.hostname = target_host AND p.service_name = target_service
         AND p.last_seen >= since - interval '15 minutes') THEN
    unknown := true;
    shortfalls := shortfalls || 'unknown_service'::text;
  END IF;
  -- A port counts if a socket listened on it or served on it in the
  -- period: a socket of the service, or one without a known owner, when a
  -- service is given too.
  IF o.agent AND target_port IS NOT NULL
     AND NOT EXISTS (
       SELECT FROM shawk.hosts h
       JOIN shawk.listener_owners l ON l.host_id = h.id
       JOIN shawk.processes p ON p.id = l.process_id
       WHERE h.hostname = target_host AND l.port = target_port
         AND (target_proto IS NULL OR l.proto = target_proto)
         AND (target_service IS NULL OR p.service_name IN (target_service, '~unknown'))
         AND l.last_seen >= since - interval '15 minutes')
     AND NOT EXISTS (
       SELECT FROM shawk.hosts h
       JOIN shawk.listeners l ON l.host_id = h.id
       WHERE h.hostname = target_host AND l.port = target_port AND l.process_id IS NULL
         AND (target_proto IS NULL OR l.proto = target_proto)
         AND l.last_seen >= since - interval '15 minutes')
     AND NOT EXISTS (
       SELECT FROM shawk.hosts h
       JOIN shawk.edges e ON e.host_id = h.id AND e.role = 'server'
       JOIN shawk.processes p ON p.id = e.process_id
       WHERE h.hostname = target_host AND e.port = target_port
         AND (target_proto IS NULL OR e.proto = target_proto)
         AND (target_service IS NULL OR p.service_name IN (target_service, '~unknown'))
         AND e.last_seen >= since - interval '15 minutes') THEN
    unknown := true;
    shortfalls := shortfalls || 'unknown_port'::text;
  END IF;

  -- The coverage is compared as it is and reported cut, not rounded, so
  -- that 1 is a target watched all along.
  covered := 1 - extract(epoch FROM shawk.duration(blind)) / extract(epoch FROM until - since);
  coverage := trunc(covered, 6);
  unobserved := shawk.duration(missing);
  gaps := (SELECT count(*) FROM unnest(missing));
  partly_observed := shawk.duration(o.dropped);
  IF direct > 0 THEN
    verdict := 'UNSAFE';
    reasons := ARRAY['active_dependents'];
    caveats := shortfalls;
  ELSIF NOT o.agent OR unknown OR covered < min_coverage THEN
    verdict := 'INCONCLUSIVE';
    reasons := shortfalls;
    caveats := '{}';
  ELSE
    verdict := 'SAFE';
    reasons := '{}';
    caveats := shortfalls;
  END IF;
  RETURN NEXT;
END
$$;
