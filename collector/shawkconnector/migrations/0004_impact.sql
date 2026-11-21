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
-- which the dependency was active. The first rule that holds gives the
-- cadence:
--
--   unknown     no run: no hour was recorded;
--   continuous  idle for an hour at most, observed for a day at least
--               since the first run, and a duty of 0.9 at least;
--   unknown     one run, idle for an hour at most: too recent to tell;
--   one-off     one run, shorter than a day, that ended;
--   dormant     one run of a day at least that ended, or several runs and
--               idle for longer than a day and than twice the longest gap;
--   unknown     two runs: one interval tells no period;
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
-- the end of the last one.
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
  SELECT lower(a.hours) AS s, upper(a.hours) AS e
  FROM b
  CROSS JOIN LATERAL unnest(active + b.blind) AS g
  CROSS JOIN LATERAL (SELECT tstzmultirange(g) * active AS hours) a
  WHERE NOT isempty(a.hours)
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
         extract(epoch FROM shawk.duration(active * tstzmultirange(tstzrange(least(stat.first_start, until), until)))) AS on_time,
         (SELECT 3 * count(*) FILTER (WHERE r.step BETWEEN 0.75 * stat.step AND 1.25 * stat.step) >= 2 * count(*)
          FROM r WHERE r.step IS NOT NULL) AS regular
  FROM stat CROSS JOIN b
),
c AS (
  SELECT m.*,
         CASE
           WHEN m.n = 0 THEN 'unknown'
           WHEN m.idle <= 3600 AND m.observed >= 86400 AND m.on_time >= 0.9 * m.observed THEN 'continuous'
           WHEN m.n = 1 AND m.idle <= 3600 THEN 'unknown'
           WHEN m.n = 1 AND m.len < 86400 THEN 'one-off'
           WHEN m.n = 1 THEN 'dormant'
           WHEN m.idle > greatest(86400, 2 * m.max_gap) THEN 'dormant'
           WHEN m.n = 2 THEN 'unknown'
           WHEN m.regular AND 2 * m.median_len <= m.step THEN
             CASE WHEN m.step BETWEEN 20 * 3600 AND 28 * 3600 THEN 'daily'
                  WHEN m.step BETWEEN 6 * 86400 AND 8 * 86400 THEN 'weekly'
                  WHEN m.step BETWEEN 27 * 86400 AND 32 * 86400 THEN 'monthly'
                  ELSE 'periodic' END
           ELSE 'irregular'
         END AS cadence
  FROM m
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
-- the sessions say: its dependencies are deleted.
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
               udp_untraced tstzmultirange, unix_untraced tstzmultirange, netns_limited tstzmultirange)
LANGUAGE sql STABLE SET search_path = pg_catalog, pg_temp AS $$
WITH ids AS (
  SELECT h.id, h.hostname FROM shawk.hosts h WHERE h.hostname = ANY (observation.hosts)
),
-- Only the sessions that meet the period, as in unobserved_by_name().
s AS (
  SELECT i.hostname, a.udp_traced, a.unix_traced, a.netns_scope, a.last_heartbeat,
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
         range_agg(tstzrange(s.started, s.last_heartbeat)) FILTER (WHERE s.netns_scope <> 'all') AS netns_limited
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
       coalesce(ses.netns_limited, '{}') * w.period
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
-- whole period.
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
  ORDER BY o.host, lower(g.gap)
$$;

-- The dependencies that make the dependents of a target (shawk_v1.impact),
-- one row per dependency of the period (shawk_v1.dependencies_between)
-- that makes its client a dependent, with the depth, and the dependent,
-- its server and the port as impact() reports them: cli_host, cli_service,
-- cli_addr, srv_host, srv_service and dep_port. gid numbers the rows of
-- impact(). The other columns are those of the dependency, which find its
-- edges.
CREATE FUNCTION shawk.dependents(target_host text, since timestamptz, until timestamptz,
                                 target_service text, target_port integer, target_proto text, max_depth integer)
RETURNS TABLE (
  gid bigint, depth integer, cli_host text, cli_service text, cli_addr inet,
  srv_host text, srv_service text, dep_port integer, proto text,
  first_seen timestamptz, last_seen timestamptz, observed_by text,
  client_host text, client_service text, client_unit text, client_addr inet,
  server_host text, server_service text, server_unit text, server_addr inet,
  port integer, virtual_addr inet, virtual_port integer, path text)
LANGUAGE sql STABLE SET search_path = pg_catalog, pg_temp AS $$
WITH RECURSIVE
arg AS (
  SELECT least(greatest(coalesce(dependents.max_depth, 3), 1), 10) AS max_depth,
         dependents.target_service IS NULL AND dependents.target_port IS NULL AS whole_host
),
-- The host ids of the target, none if no agent reported under its name.
t AS (
  SELECT h.id FROM shawk.hosts h WHERE h.hostname = dependents.target_host
),
d AS MATERIALIZED (
  SELECT row_number() OVER () AS id, x.*
  FROM shawk_v1.dependencies_between(dependents.since, dependents.until) x
  WHERE dependents.since < dependents.until
),
-- The periods in which the agents of a name reported addresses, and the
-- stretches in which they reported any: when the name was seen. A period
-- starts anew after the alive window (shawk.host_addrs), so that an agent
-- that stops ends the periods of all the addresses of its host.
hp AS (
  SELECT h.hostname, a.addr, a.first_seen, a.last_seen
  FROM shawk.host_addrs a
  JOIN shawk.hosts h ON h.id = a.host_id
),
hs AS (
  SELECT s.hostname, s.seen, lag(upper(s.seen)) OVER w AS before, lead(lower(s.seen)) OVER w AS after
  FROM (
    SELECT hp.hostname,
           unnest(range_agg(tstzrange(hp.first_seen, hp.last_seen + shawk.alive_window(), '[]'))) AS seen
    FROM hp GROUP BY hp.hostname
  ) s
  WINDOW w AS (PARTITION BY s.hostname ORDER BY s.seen)
),
-- The periods of an address in the order they started, numbered by the
-- runs of periods of one name, and when a run of another name started
-- after each run (taken) and ended before it (released).
ho AS (
  SELECT y.hostname, y.addr, y.first_seen, y.last_seen,
         sum(y.other) OVER (PARTITION BY y.addr ORDER BY y.first_seen, y.hostname) AS run
  FROM (
    SELECT hp.*,
           (hp.hostname IS DISTINCT FROM lag(hp.hostname) OVER (PARTITION BY hp.addr ORDER BY hp.first_seen, hp.hostname))::integer AS other
    FROM hp
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
         CASE WHEN ho.first_seen <= lower(hs.seen) + shawk.alive_window()
              THEN least(ho.first_seen - shawk.alive_window(),
                         greatest(coalesce(hs.before, '-infinity'), coalesce(hr.released, '-infinity')))
              ELSE ho.first_seen - shawk.alive_window() END AS held_from,
         CASE WHEN ho.last_seen >= upper(hs.seen) - 2 * shawk.alive_window()
              THEN greatest(ho.last_seen + shawk.alive_window(),
                            least(coalesce(hs.after, 'infinity'), coalesce(hr.taken, 'infinity')))
              ELSE ho.last_seen + shawk.alive_window() END AS held_until
  FROM ho
  JOIN hs ON hs.hostname = ho.hostname AND hs.seen @> ho.first_seen
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
-- Their service: the latest known owner of a listener on the port. An
-- address the host of the client holds too is its own: the gateway of a
-- container bridge, which every host has.
srv AS (
  SELECT DISTINCT ON (c.id, c.host) c.id, c.host, l.service
  FROM (SELECT cand.*, bool_or(cand.host = cand.client_host) OVER (PARTITION BY cand.id) AS own FROM cand) c
  LEFT JOIN LATERAL (
    SELECT p.service_name AS service
    FROM shawk.hosts h
    JOIN shawk.listener_owners l ON l.host_id = h.id
    JOIN shawk.processes p ON p.id = l.process_id
    WHERE h.hostname = c.host AND l.proto = c.proto AND l.port = c.port
      AND l.addr IN (c.server_addr, inet '0.0.0.0', inet '::')
      AND l.last_seen >= dependents.since - interval '15 minutes'
      AND l.first_seen <= c.last_seen + interval '15 minutes'
    ORDER BY l.last_seen DESC, p.service_name LIMIT 1
  ) l ON true
  WHERE NOT c.own OR c.host = c.client_host
  ORDER BY c.id, c.host, l.service
),
-- The dependencies with the host and service of their server, also of
-- those that the client alone saw, and the host the inventory gives a
-- client without an agent. A dependency seen by its client alone may have
-- several rows, one per host that held the address of its server.
r AS MATERIALIZED (
  SELECT d.*,
         CASE WHEN d.proto = 'unix' OR d.server_host IS NOT NULL THEN d.server_host ELSE s.host END AS srv_host,
         CASE WHEN d.proto = 'unix' OR d.server_host IS NOT NULL THEN d.server_service ELSE s.service END AS srv_service,
         coalesce(d.client_host, ci.host) AS cli_host
  FROM d
  LEFT JOIN srv s ON s.id = d.id
  LEFT JOIN shawk.inventory_addrs ci ON d.client_host IS NULL AND ci.addr = d.client_addr
),
-- The dependencies on the target, without those of its own clients. A
-- connection that a socket without a known owner accepted (~unknown) may
-- be of any service of the host: it counts for the one asked for.
direct AS (
  SELECT r.*
  FROM r CROSS JOIN arg
  WHERE r.srv_host = dependents.target_host
    AND (dependents.target_service IS NULL OR r.srv_service IN (dependents.target_service, '~unknown')
         OR (r.srv_service IS NULL AND NOT EXISTS (SELECT FROM t)))
    AND (dependents.target_port IS NULL OR r.port = dependents.target_port)
    AND (dependents.target_proto IS NULL OR r.proto = dependents.target_proto)
    AND NOT CASE
      WHEN arg.whole_host THEN
        r.cli_host IS NOT DISTINCT FROM dependents.target_host
        OR (r.cli_host IS NULL
            AND (r.client_addr << inet '127.0.0.0/8' OR r.client_addr = inet '::1'
                 -- An address the target held when the dependency was
                 -- last seen: one that another host took since is that
                 -- host's.
                 OR EXISTS (SELECT FROM shawk.host_addrs a
                            WHERE a.host_id IN (SELECT t.id FROM t) AND a.addr = r.client_addr
                              AND a.first_seen <= r.last_seen + shawk.alive_window()
                              AND a.last_seen >= least(r.last_seen, dependents.until) - shawk.alive_window())))
      -- The service itself, as a client of its own port.
      ELSE r.client_host IS NOT DISTINCT FROM dependents.target_host
           AND r.client_service IS NOT DISTINCT FROM coalesce(dependents.target_service, r.srv_service)
           AND r.client_service IS DISTINCT FROM '~unknown'
    END
),
-- The dependents with an agent, by the depths they are reached at. The
-- sockets without a known owner of a host (~unknown) are no service: their
-- clients are not those of the socket that used the target.
walk (depth, host, service) AS (
  SELECT 1, x.client_host, x.client_service FROM direct x
  WHERE x.client_host IS NOT NULL AND x.client_service <> '~unknown'
  UNION
  SELECT w.depth + 1, r.client_host, r.client_service
  FROM walk w
  JOIN r ON r.srv_host = w.host AND r.srv_service = w.service
  CROSS JOIN arg
  WHERE w.depth < arg.max_depth
    AND r.client_host IS NOT NULL AND r.client_service <> '~unknown'
    AND NOT (r.client_host = w.host AND r.client_service = w.service)
    AND NOT (r.client_host = dependents.target_host
             AND (arg.whole_host OR r.client_service IS NOT DISTINCT FROM dependents.target_service))
),
node AS (
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
  CROSS JOIN arg
  LEFT JOIN node nc ON nc.host = r.client_host AND nc.service = r.client_service
  WHERE n.depth < arg.max_depth
    AND NOT (r.client_host IS NOT DISTINCT FROM n.host AND r.client_service IS NOT DISTINCT FROM n.service)
    AND NOT (r.cli_host IS NOT DISTINCT FROM dependents.target_host
             AND (arg.whole_host OR r.client_service IS NOT DISTINCT FROM dependents.target_service))
    AND (nc.depth IS NULL OR nc.depth = n.depth + 1)
    AND r.id NOT IN (SELECT x.id FROM direct x)
)
SELECT dense_rank() OVER (ORDER BY x.depth, x.cli_host, x.cli_service, x.cli_addr, x.srv_host, x.srv_service,
                                   x.dep_port, x.proto),
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
-- The server of a dependency that its client alone saw is the host that
-- held the address then, the host of the client for loopback and for an
-- address the client holds too, or the host the inventory gives the
-- address; its service is the latest known owner of a listener on the
-- port, NULL if none. A host whose agents did not report then held the
-- address if it was among the last they reported before or the first they
-- reported after, and no host of another name reported it in between: a
-- host that is used while its agent is stopped keeps its dependents. Such a dependency counts for a service of a host
-- only if that service owned the port, except on a target without an
-- agent, of which nothing else is known. A connection that a socket
-- without a known owner accepted (~unknown) counts for every service of
-- its host.
--
-- A client is a dependent of the target unless it is part of it: a client
-- on the target itself when the whole host is the target, the service
-- itself otherwise. A dependent with an agent is followed: the clients of
-- its service on its host are dependents of the next depth, unless they
-- are part of the target or already dependents of a lesser depth, so that
-- a dependent with an agent is reported once, at the depth it is first
-- reached; one without an agent is reported with each server it uses. The
-- dependencies of the period are followed at most once per depth.
--
-- cadence, period, next_expected and runs are those of shawk.cadence() over
-- the hours of activity of its edges (shawk.edge_activity), with the time
-- in which none of the hosts that saw it was observed as blind. The
-- cadence is unknown when the hours end before the dependency was last
-- seen: activity that a connector did not record.
CREATE FUNCTION shawk_v1.impact(target_host text, since timestamptz, until timestamptz,
                                target_service text DEFAULT NULL, target_port integer DEFAULT NULL,
                                target_proto text DEFAULT NULL, max_depth integer DEFAULT 3)
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
         -- The hosts whose agents saw it: one of each side at most.
         max(s.client_host) AS client_agent, max(s.server_host) AS server_agent
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
         ARRAY(SELECT g.client_agent FROM grp g UNION SELECT g.server_agent FROM grp g), interval '3 minutes') o
)
SELECT g.depth, g.cli_host, g.cli_service, g.cli_addr, g.srv_host, g.srv_service, g.dep_port, g.proto,
       g.first_seen, g.last_seen,
       CASE WHEN g.by_client AND g.by_server THEN 'both' WHEN g.by_client THEN 'client' ELSE 'server' END,
       CASE WHEN c.last_active < least(g.last_seen, impact.until) - interval '2 minutes' THEN 'unknown' ELSE c.cadence END,
       CASE WHEN c.last_active >= least(g.last_seen, impact.until) - interval '2 minutes' THEN c.period END,
       CASE WHEN c.last_active >= least(g.last_seen, impact.until) - interval '2 minutes' THEN c.next_expected END,
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
ORDER BY g.depth, g.cli_host, g.cli_service, g.cli_addr, g.srv_host, g.srv_service, g.dep_port, g.proto
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
-- coverage is the part of the period, from 0 to 1, in which an agent of
-- the target observed all that the target covers: observed (not_observed
-- otherwise, or before_retention for the part of the period whose
-- dependencies are deleted), without dropped flows (dropped_flows), in every network
-- namespace (netns_limited), with UDP unless target_proto is another
-- transport (udp_not_traced), and with Unix sockets when the target is a
-- service without a port (unix_not_traced). A target that no agent reported
-- under has a coverage of 0: unknown_host, or no_agent for a host of the
-- inventory, whose clients without an agent nothing would tell.
-- min_coverage is 1 by default: any gap makes the verdict INCONCLUSIVE.
--
-- A service that no process of the host had in the period
-- (unknown_service), and a port that nothing listened on nor served there
-- (unknown_port), are INCONCLUSIVE too, whatever the coverage: nothing
-- used what shawk does not know of, a name or a port mistyped included.
--
-- direct and transitive count the dependents of depth 1 and of the depths
-- after; caveats are the shortfalls of the coverage that did not decide
-- the verdict, with which the dependents listed may not be all. unobserved,
-- gaps and partly_observed are those of coverage() for the target.
CREATE FUNCTION shawk_v1.impact_verdict(target_host text, since timestamptz, until timestamptz,
                                        target_service text DEFAULT NULL, target_port integer DEFAULT NULL,
                                        target_proto text DEFAULT NULL, min_coverage numeric DEFAULT 1,
                                        max_depth integer DEFAULT 3, tolerance interval DEFAULT '3 minutes')
RETURNS TABLE (verdict text, reasons text[], caveats text[], direct bigint, transitive bigint,
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
  -- The tolerance is the delay of writes: one that hides gaps of hours is
  -- a mistake.
  IF tolerance IS NULL OR tolerance < interval '0' OR tolerance > interval '1 hour' THEN
    RAISE EXCEPTION 'tolerance is from 0 to 1 hour: %', tolerance USING ERRCODE = 'invalid_parameter_value';
  END IF;
  period := shawk.period(since, until);

  SELECT count(DISTINCT (i.cli_host, i.cli_service, i.cli_addr)) FILTER (WHERE i.depth = 1),
         count(DISTINCT (i.cli_host, i.cli_service, i.cli_addr)) FILTER (WHERE i.depth > 1)
  INTO direct, transitive
  FROM shawk.dependents(target_host, since, until, target_service, target_port, target_proto, max_depth) i;

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
  IF o.agent AND target_port IS NOT NULL
     AND NOT EXISTS (
       SELECT FROM shawk.hosts h
       JOIN shawk.listeners l ON l.host_id = h.id
       WHERE h.hostname = target_host AND l.port = target_port
         AND (target_proto IS NULL OR l.proto = target_proto)
         AND l.last_seen >= since - interval '15 minutes')
     AND NOT EXISTS (
       SELECT FROM shawk.hosts h
       JOIN shawk.edges e ON e.host_id = h.id AND e.role = 'server'
       WHERE h.hostname = target_host AND e.port = target_port
         AND (target_proto IS NULL OR e.proto = target_proto)
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
