-- Least-privilege rules and the baseline of the dependencies of services
-- (§6.4 of docs/design.md): what a host, or a unit of it, connected to and
-- accepted connections from in a period, with what the history does not
-- tell of it; the dependencies that an operator approved for a service; and
-- those of a period that are not among them. Everything is computed here,
-- in the contract, so that Grafana, psql, the connector and shawk-policy
-- give the same answer: the command only writes the rules.
--
-- Where a function returns its rows, or the items of an array, in an
-- order, or keeps the first of them, the order is that of the bytes of
-- the names (COLLATE "C"), whatever the collation of the database: the
-- same contents give the same lists, files and choices in a database of
-- en_US.UTF-8, which sorts capitals after small letters and skips marks
-- such as ~ and -, as in one of C.

-- The baseline ---------------------------------------------------------------

-- The services whose dependencies an operator approved, written by the
-- connector from its baseline_file (§5.9), which it reads every write
-- interval and replaces in one transaction when its contents change. A
-- service that is not here has no baseline: its dependencies are not
-- judged. One that is here without dependencies is approved to have none.
CREATE TABLE shawk.baseline_services (
  service text PRIMARY KEY CHECK (service <> '')  -- as service_name: [namespace/]name
);

-- The dependencies approved for a service: the server by its name as
-- baseline_observed() names it (a service, a range of peer_cidrs,
-- ~unresolved or ~external), its port (0: every port) and the transport.
-- kernel_chosen narrows port 0 to the ports that the kernel chose for a
-- server of the name (`port: kernel-chosen` in the file): a server that
-- listens on such a port has another one at its next run, and approving
-- every port of every server of its name for it would approve too much.
-- Dependencies over Unix sockets, which have neither a port nor a network,
-- are not part of a baseline.
CREATE TABLE shawk.baseline_dependencies (
  service       text NOT NULL REFERENCES shawk.baseline_services ON DELETE CASCADE,
  peer          text NOT NULL CHECK (peer <> ''),
  port          integer NOT NULL CHECK (port BETWEEN 0 AND 65535),
  proto         text NOT NULL CHECK (proto IN ('tcp', 'udp')),
  kernel_chosen boolean NOT NULL DEFAULT false CHECK (NOT kernel_chosen OR port = 0),
  PRIMARY KEY (service, peer, port, proto, kernel_chosen)
);

-- When the baseline was read, as shawk.inventory_state: read_at is the
-- latest time a connector read the contents above from a valid file;
-- while the file cannot be read or is invalid the contents stay, and
-- failed_at and error tell the latest failure since. One row at most.
CREATE TABLE shawk.baseline_state (
  singleton boolean PRIMARY KEY DEFAULT true CHECK (singleton),
  digest    text,                          -- NULL until a valid file was read
  read_at   timestamptz,
  failed_at timestamptz,                   -- NULL unless the latest read failed
  error     text
);

-- Units ----------------------------------------------------------------------

-- Whether a unit is one that unrelated processes share, by its kind: the
-- unit says nothing of what runs in it, so a baseline of one of its
-- processes does not judge the others (§6.4). These are the names that
-- the agent gives to what is not a workload of its own (§4.1): no unit;
-- the steps of the Slurm jobs of every user (slurm/batch, slurm/step,
-- ...); login sessions (session.scope, user-1000.slice/session.scope);
-- transient units of systemd-run (run.scope, run.service); and the
-- manager of a user (user@1000.service), but not the units that the user
-- named under it.
CREATE FUNCTION shawk.shared_unit(unit text) RETURNS boolean
LANGUAGE sql IMMUTABLE PARALLEL SAFE AS $$
  SELECT unit = '' OR unit LIKE 'slurm/%' OR unit ~ '(^|/)session\.scope$' OR unit ~ '^run\.(scope|service)$'
      OR unit ~ '^user@[0-9]+\.service$'
$$;

-- Names ----------------------------------------------------------------------

-- The dependencies of TCP and UDP active in [since, until]
-- (shawk_v1.dependencies_between) with the names of their two sides and
-- the port of the dependency between services (shawk.dependency_port):
-- what a baseline lists.
--
-- A side without a service is named by peer_class, as in the dependencies
-- between services. The server of a dependency that its client alone saw
-- is first named after the service that listens at its address and port
-- (shawk_v1.service_endpoints, the last known endpoints of each host, as
-- the connector names peers), or, for a virtual address of a translation
-- of the configuration, at one of its backends: a server whose agent
-- stopped, or folds its clients, keeps its name, so that a stopped agent
-- does not make the dependencies on its host look like new ones on
-- ~unresolved. An endpoint at a loopback address, or at an address that
-- several hosts hold, names the server only on the host of the client.
-- Among several, one on the host of the client wins, then one observed on
-- a socket, then the most recently seen. named_by tells where the name of
-- the server comes from: edge (an agent saw the server side), endpoint, or
-- address (peer_class).
--
-- kernel_chosen tells that the server listened on the port because the
-- kernel chose it (shawk.listener_owners.kernel_chosen_seen, within the
-- period): the port is another one at the next run of the server.
--
-- judged_service is the service whose baseline judges the dependency
-- (§6.4). Without `judged` it is the service of the client. With `judged`,
-- the services that have a baseline, the rows are those of the processes
-- that a baseline judges, one row per dependency:
--
--   - a process whose service is in `judged` is judged as that service
--     (judges holds it alone);
--   - any other process is judged by its unit: by the services of
--     `judged` that run in its unit on its host, or in a unit above it
--     (a container that a service runs in a cgroup of its own, as for the
--     rules), where a process of the service was seen since members_since
--     (at the latest 15 minutes before the period, which is also what
--     NULL means). judges holds those services, in the order of their
--     bytes: the dependency is in the baseline when one of them approves
--     it, and judged_service, under which it is told once, is the first
--     of them (the first that is in of_services, if given).
--
-- A name is what a process declares (§4.1), and the unit is what it
-- cannot leave: a process that an approved service starts, or that takes
-- another name within its unit, is not out of every baseline for it. But
-- a unit that unrelated processes share by its kind (shawk.shared_unit:
-- the Slurm jobs of every user, login sessions, transient units, no unit
-- at all) says nothing of what runs in it, and judges nothing: a process
-- there is judged by the baseline of its own name, or by none. With
-- `shared`, the rows are those that this leaves out instead: the
-- dependencies of the processes without a baseline of their own in such a
-- unit in which services of `judged` run, with those services in judges
-- and no judged_service (baseline_unjudged).
--
-- The names are made for the rows that the caller reads only: those of a
-- host on either side (of_host), of clients with an agent (clients_only)
-- and of the services of of_services (judged_service), rather than for
-- the hundreds of thousands of dependencies of a period of months.
--
-- The dependencies of the period are read by shawk.dependencies_in(), in
-- which nested loops are on: its edges and endpoints are read through
-- indexes, a host at a time. Here they are off, as in policy_flows(): the
-- planner knows nothing of the rows of a function, expects one, and would
-- join the dependencies with the servers that an endpoint names in a
-- nested loop, which reads every such server once per dependency, a
-- quarter of an hour for a fleet of which some agents are stopped. The
-- joins hash instead, and the time grows with the number of dependencies.
-- The JIT compiler is off: the costs of these plans start it, and it takes
-- 2 seconds to compile what then runs for one.
CREATE FUNCTION shawk.named_dependencies(since timestamptz, until timestamptz, of_host text DEFAULT NULL,
                                         clients_only boolean DEFAULT false, of_services text[] DEFAULT NULL,
                                         judged text[] DEFAULT NULL, members_since timestamptz DEFAULT NULL,
                                         shared boolean DEFAULT false)
RETURNS TABLE (
  client_host text, client_service text, client_unit text, client_addr inet,
  server_host text, server_service text, server_unit text, server_addr inet,
  port integer, proto text, first_seen timestamptz, last_seen timestamptz, observed_by text,
  virtual_addr inet, virtual_port integer,
  client_name text, server_name text, named_by text, dependency_port integer,
  kernel_chosen boolean, judged_service text, judges text[])
LANGUAGE sql STABLE ROWS 100000 SET search_path = pg_catalog, pg_temp SET enable_nestloop = off SET jit = off AS $$
WITH
-- The services of of_services and of judged, as rows: a hash finds a
-- service among thousands, where an array is read through for every row.
os AS MATERIALIZED (
  SELECT DISTINCT s.service FROM unnest(named_dependencies.of_services) AS s(service) WHERE s.service IS NOT NULL
),
js AS MATERIALIZED (
  SELECT DISTINCT s.service FROM unnest(named_dependencies.judged) AS s(service) WHERE s.service IS NOT NULL
),
d0 AS MATERIALIZED (
  SELECT row_number() OVER () AS id,
         x.client_host, x.client_service, x.client_unit, x.client_addr,
         x.server_host, x.server_service, x.server_unit, x.server_addr,
         x.port, x.proto, x.first_seen, x.last_seen, x.observed_by, x.virtual_addr, x.virtual_port
  FROM shawk.dependencies_in(named_dependencies.since, named_dependencies.until) x
  WHERE x.proto <> 'unix'
    AND (named_dependencies.of_host IS NULL
         OR x.client_host = named_dependencies.of_host OR x.server_host = named_dependencies.of_host)
    AND (NOT named_dependencies.clients_only OR x.client_host IS NOT NULL)
    AND (named_dependencies.judged IS NOT NULL OR named_dependencies.of_services IS NULL
         OR x.client_service IN (SELECT os.service FROM os))
),
-- The units in which a service of judged runs, by host: not those that
-- unrelated processes share by their kind, or those alone with `shared`.
um AS MATERIALIZED (
  SELECT DISTINCT h.hostname AS host, p.unit, p.service_name AS service
  FROM shawk.processes p
  JOIN shawk.hosts h ON h.id = p.host_id
  WHERE named_dependencies.judged IS NOT NULL
    AND p.service_name IN (SELECT js.service FROM js)
    AND shawk.shared_unit(p.unit) = named_dependencies.shared
    AND p.last_seen >= least(coalesce(named_dependencies.members_since, named_dependencies.since - interval '15 minutes'),
                             named_dependencies.since - interval '15 minutes')
    AND p.first_seen <= named_dependencies.until
),
-- The dependencies of the processes whose own service is not in judged,
-- each with the services of judged that run in its unit, or in a unit
-- above it, on its host. A process without a unit has none: an empty
-- name has no part, so it is next to nothing, with `shared` too.
mate AS MATERIALIZED (
  SELECT x.id, array_agg(DISTINCT um.service COLLATE "C" ORDER BY um.service COLLATE "C") AS judges
  FROM d0 x
  CROSS JOIN LATERAL (
    SELECT array_to_string(p.parts[1:i], '/') AS unit
    FROM (SELECT string_to_array(x.client_unit, '/') AS parts) p
    CROSS JOIN LATERAL generate_series(1, cardinality(p.parts)) AS i
  ) above
  JOIN um ON um.host = x.client_host AND um.unit = above.unit
  WHERE named_dependencies.judged IS NOT NULL
    AND x.client_service NOT IN (SELECT js.service FROM js)
    AND x.client_host IN (SELECT um.host FROM um)
    AND shawk.shared_unit(x.client_unit) = named_dependencies.shared
  GROUP BY x.id
),
d AS MATERIALIZED (
  SELECT j.*
  FROM (
    SELECT x.*, x.client_service AS judged_service, ARRAY[x.client_service] AS judges
    FROM d0 x
    WHERE NOT named_dependencies.shared
      AND (named_dependencies.judged IS NULL
           OR (x.client_service IN (SELECT js.service FROM js)
               AND (named_dependencies.of_services IS NULL OR x.client_service IN (SELECT os.service FROM os))))
    UNION ALL
    SELECT x.*,
           CASE WHEN NOT named_dependencies.shared THEN
             (SELECT u.service FROM unnest(m.judges) WITH ORDINALITY AS u(service, n)
              WHERE named_dependencies.of_services IS NULL OR u.service = ANY (named_dependencies.of_services)
              ORDER BY u.n LIMIT 1) END,
           m.judges
    FROM d0 x
    JOIN mate m ON m.id = x.id
    WHERE named_dependencies.of_services IS NULL OR m.judges && named_dependencies.of_services
  ) j
),
-- The rows whose server no agent saw, of clients with an agent.
u AS MATERIALIZED (
  SELECT d.id, d.client_host, d.server_addr, d.port, d.proto,
         d.server_addr << inet '127.0.0.0/8' OR d.server_addr = inet '::1'
           OR d.server_addr IN (SELECT s.addr FROM shawk.shared_addrs s) AS host_local
  FROM d
  WHERE d.server_service IS NULL AND d.client_host IS NOT NULL
),
ep AS MATERIALIZED (
  SELECT e.addr, e.port, e.proto, e.host, e.service, e.last_seen, e.exact, e.slurm_job
  FROM shawk_v1.service_endpoints e
  WHERE EXISTS (SELECT FROM u)
),
-- The backends of the rows whose server is a virtual address of a
-- translation of the configuration: few, and found before the endpoints
-- are read, so that the endpoints are not read once per row.
vb AS MATERIALIZED (
  SELECT u.id, u.proto, b.addr, CASE WHEN b.port = 0 THEN u.port ELSE b.port END AS port
  FROM shawk.translations v
  JOIN u ON u.proto = v.proto AND u.server_addr = v.addr AND v.port IN (0, u.port)
  JOIN shawk.translations b ON b.side = 'backend' AND b.name = v.name AND b.proto = v.proto
  WHERE v.side = 'virtual'
),
cand AS (
  SELECT u.id, ep.service, ep.slurm_job, 0 AS via, ep.host = u.client_host AS own, ep.exact, ep.last_seen
  FROM u
  JOIN ep ON ep.addr = u.server_addr AND ep.port = u.port AND ep.proto = u.proto
  WHERE ep.host = u.client_host OR NOT u.host_local
  UNION ALL
  SELECT vb.id, ep.service, ep.slurm_job, 1, false, ep.exact, ep.last_seen
  FROM vb
  JOIN ep ON ep.proto = vb.proto AND ep.port = vb.port AND ep.addr <<= vb.addr
),
pick AS MATERIALIZED (
  SELECT DISTINCT ON (c.id) c.id, c.service, c.slurm_job
  FROM cand c
  ORDER BY c.id, c.via, c.own DESC, c.exact DESC, c.last_seen DESC, c.service COLLATE "C"
),
-- The ports that the kernel chose for a listener in the period, by host:
-- few, read through their index.
kc AS MATERIALIZED (
  SELECT DISTINCT h.hostname, o.proto, o.port
  FROM shawk.listener_owners o
  JOIN shawk.hosts h ON h.id = o.host_id
  WHERE o.kernel_chosen_seen >= named_dependencies.since
)
SELECT d.client_host, d.client_service, d.client_unit, d.client_addr,
       d.server_host, d.server_service, d.server_unit, d.server_addr,
       d.port, d.proto, d.first_seen, d.last_seen, d.observed_by,
       d.virtual_addr, d.virtual_port,
       coalesce(d.client_service, shawk_v1.peer_class(d.client_addr)),
       n.server_name,
       CASE WHEN d.server_service IS NOT NULL THEN 'edge' WHEN p.id IS NOT NULL THEN 'endpoint' ELSE 'address' END,
       -- The port of shawk.dependency_port(), read from its tables here
       -- rather than by a call of it per row.
       CASE WHEN n.server_name IN (SELECT a.service FROM shawk.port_agnostic_services a)
              OR ((d.server_unit LIKE 'slurm/%' OR p.slurm_job)
                  AND EXISTS (SELECT FROM shawk.port_agnostic_services a WHERE a.service = 'slurm-job'))
              OR EXISTS (SELECT FROM shawk.dynamic_ports r
                         WHERE r.proto = d.proto AND d.port BETWEEN r.port_from AND r.port_to AND d.server_addr <<= r.addr)
            THEN 0 ELSE d.port END,
       kc.hostname IS NOT NULL,
       d.judged_service, d.judges
FROM d
LEFT JOIN pick p ON p.id = d.id
LEFT JOIN kc ON kc.hostname = d.server_host AND kc.proto = d.proto AND kc.port = d.port
CROSS JOIN LATERAL (
  SELECT coalesce(d.server_service, p.service, shawk_v1.peer_class(d.server_addr)) AS server_name
) n
$$;

-- Observation ----------------------------------------------------------------

-- How each machine of ids (shawk.hosts.id) was observed in [since, until]
-- for what a policy or a baseline lists, the connections of TCP and UDP
-- of its processes. It is shawk.observation() of 0005_impact.sql by
-- machine rather than by host name: two machines that report under one
-- name (clones, or nodes all named localhost) are two rows, and the time
-- that one of them was observed tells nothing of the other.
--
-- covered is the part of the period, from 0 to 1, for which the history
-- tells them all, and shortfalls why it does not, as impact_verdict()
-- names them: not_observed, before_retention, dropped_flows, netns_limited
-- and udp_not_traced. missing is the time without an agent, with that
-- before the retention (pruned), in `gaps` gaps; unobserved,
-- partly_observed (dropped flows), udp_untraced, netns_limited and
-- before_retention are how long each lasted.
--
-- A session counts as observed for `tolerance` after its last heartbeat,
-- as in coverage(): the restart of an agent, or its latest report, which
-- is not written yet. tolerated is that time within the period, in
-- tolerated_gaps stretches: no agent reported in it, and the verdicts
-- that count it as observed say so.
--
-- translations_untold tells that a session of the machine in the period
-- did not learn every translation of addresses that the machine makes:
-- an agent that traces none, or that folds the peers outside its internal
-- ranges (§3.6, the default), which does not learn a translation to a
-- backend outside them (§3.7).
CREATE FUNCTION shawk.machine_shortfalls(since timestamptz, until timestamptz, ids text[], tolerance interval)
RETURNS TABLE (host_id text, host text, covered numeric, shortfalls text[],
               unobserved interval, gaps integer, partly_observed interval,
               udp_untraced interval, netns_limited interval, before_retention interval,
               tolerated interval, tolerated_gaps integer, translations_untold boolean,
               missing tstzmultirange, pruned tstzmultirange)
LANGUAGE sql STABLE SET search_path = pg_catalog, pg_temp AS $$
WITH i AS (
  SELECT h.id, h.hostname
  FROM shawk.hosts h
  WHERE h.id IN (SELECT u.id FROM unnest(machine_shortfalls.ids) AS u(id))
),
-- Only the sessions that meet the period, with the times of
-- shawk.observation(): a session ends earlier by the time the clock of
-- its host is behind.
s AS (
  SELECT a.host_id, a.udp_traced, a.netns_scope, a.last_heartbeat,
         a.peer_fold <> 'none' OR a.translations_traced IS NOT TRUE AS translations_untold,
         least(a.started_at + a.clock_skew, a.last_heartbeat - greatest(a.clock_skew, interval '0')) AS started,
         a.last_heartbeat - greatest(a.clock_skew, interval '0') AS ended
  FROM i
  JOIN shawk.agent_sessions a ON a.host_id = i.id
  WHERE a.last_heartbeat > machine_shortfalls.since - machine_shortfalls.tolerance
    AND least(a.started_at + a.clock_skew, a.last_heartbeat) < machine_shortfalls.until
),
ses AS (
  SELECT s.host_id,
         range_agg(tstzrange(s.started, s.ended + machine_shortfalls.tolerance)) AS observed,
         range_agg(tstzrange(s.started, s.ended)) AS reported,
         range_agg(tstzrange(s.started, s.last_heartbeat)) FILTER (WHERE NOT s.udp_traced) AS udp_untraced,
         range_agg(tstzrange(s.started, s.last_heartbeat)) FILTER (WHERE s.netns_scope <> 'all') AS netns_limited,
         range_agg(tstzrange(s.started, s.last_heartbeat)) FILTER (WHERE s.translations_untold) AS translations_untold
  FROM s GROUP BY s.host_id
),
par AS (
  SELECT i.id AS host_id, range_agg(tstzrange(p.period_start, p.period_end)) AS dropped
  FROM i
  JOIN shawk.partial_observations p ON p.host_id = i.id
  WHERE p.period_end > machine_shortfalls.since AND p.period_start < machine_shortfalls.until
  GROUP BY i.id
),
w AS (
  SELECT shawk.period(machine_shortfalls.since, machine_shortfalls.until) AS period,
         coalesce((SELECT tstzmultirange(tstzrange(NULL, r.pruned_before)) FROM shawk.retention r), '{}') AS pruned
),
o AS (
  SELECT i.id, i.hostname, w.period,
         coalesce(ses.observed, '{}') * w.period - w.pruned AS observed,
         coalesce(ses.reported, '{}') * w.period - w.pruned AS reported,
         w.period * w.pruned AS pruned,
         coalesce(par.dropped, '{}') * w.period AS dropped,
         coalesce(ses.udp_untraced, '{}') * w.period AS udp_untraced,
         coalesce(ses.netns_limited, '{}') * w.period AS netns_limited,
         coalesce(ses.translations_untold, '{}') * w.period AS translations_untold
  FROM i
  CROSS JOIN w
  LEFT JOIN ses ON ses.host_id = i.id
  LEFT JOIN par ON par.host_id = i.id
)
SELECT o.id, o.hostname,
       1 - extract(epoch FROM shawk.duration(m.missing + o.dropped + o.netns_limited + o.udp_untraced))
           / extract(epoch FROM machine_shortfalls.until - machine_shortfalls.since),
       array_remove(ARRAY[
         CASE WHEN NOT isempty(m.missing - o.pruned) THEN 'not_observed' END,
         CASE WHEN NOT isempty(o.pruned) THEN 'before_retention' END,
         CASE WHEN NOT isempty(o.dropped) THEN 'dropped_flows' END,
         CASE WHEN NOT isempty(o.netns_limited) THEN 'netns_limited' END,
         CASE WHEN NOT isempty(o.udp_untraced) THEN 'udp_not_traced' END], NULL),
       shawk.duration(m.missing), (SELECT count(*)::integer FROM unnest(m.missing)), shawk.duration(o.dropped),
       shawk.duration(o.udp_untraced), shawk.duration(o.netns_limited), shawk.duration(o.pruned),
       shawk.duration(o.observed - o.reported), (SELECT count(*)::integer FROM unnest(o.observed - o.reported)),
       NOT isempty(o.translations_untold),
       m.missing, o.pruned
FROM o
CROSS JOIN LATERAL (SELECT o.period - o.observed AS missing) m
$$;

-- The machines of each host name of hosts in [since, until]: the ids
-- under the name that an agent session of the period reported for.
CREATE FUNCTION shawk.machines_of(since timestamptz, until timestamptz, hosts text[], tolerance interval)
RETURNS TABLE (host text, host_id text)
LANGUAGE sql STABLE SET search_path = pg_catalog, pg_temp AS $$
  SELECT h.hostname, h.id
  FROM shawk.hosts h
  WHERE h.hostname = ANY (machines_of.hosts)
    AND EXISTS (
      SELECT FROM shawk.agent_sessions a
      WHERE a.host_id = h.id
        AND a.last_heartbeat > machines_of.since - machines_of.tolerance
        AND least(a.started_at + a.clock_skew, a.last_heartbeat) < machines_of.until)
$$;

-- machine_shortfalls() by host name, for what is asked by name (the rules
-- of a host): machines counts the machines of the name in the period
-- (machines_of), covered is that of the least observed of them, shortfalls
-- are those of them all, and unobserved, gaps, partly_observed,
-- udp_untraced, netns_limited, before_retention, tolerated and
-- tolerated_gaps are each the largest among them. Further shortfalls:
-- unknown_host (no agent ever reported under the name), no_agent (the same
-- for a host of the inventory), not_observed for a name without a machine
-- in the period, and several_machines when it has more than one: what is
-- listed for the name is then of several machines at once.
CREATE FUNCTION shawk.host_shortfalls(since timestamptz, until timestamptz, hosts text[], tolerance interval)
RETURNS TABLE (host text, agent boolean, machines integer, covered numeric, shortfalls text[],
               unobserved interval, gaps integer, partly_observed interval,
               udp_untraced interval, netns_limited interval, before_retention interval,
               tolerated interval, tolerated_gaps integer, translations_untold boolean)
LANGUAGE sql STABLE SET search_path = pg_catalog, pg_temp AS $$
WITH n AS (
  SELECT DISTINCT u.host FROM unnest(host_shortfalls.hosts) AS u(host) WHERE u.host IS NOT NULL
),
m AS MATERIALIZED (
  SELECT x.*
  FROM shawk.machine_shortfalls(host_shortfalls.since, host_shortfalls.until,
         ARRAY(SELECT o.host_id
               FROM shawk.machines_of(host_shortfalls.since, host_shortfalls.until, host_shortfalls.hosts,
                                      host_shortfalls.tolerance) o),
         host_shortfalls.tolerance) x
),
agg AS (
  SELECT m.host, count(*)::integer AS machines, min(m.covered) AS covered, bool_or(m.translations_untold) AS untold,
         max(m.unobserved) AS unobserved, max(m.gaps) AS gaps, max(m.partly_observed) AS partly_observed,
         max(m.udp_untraced) AS udp_untraced, max(m.netns_limited) AS netns_limited,
         max(m.before_retention) AS before_retention,
         max(m.tolerated) AS tolerated, max(m.tolerated_gaps) AS tolerated_gaps
  FROM m GROUP BY m.host
),
codes AS (
  SELECT m.host, array_agg(DISTINCT c.code) AS codes
  FROM m CROSS JOIN LATERAL unnest(m.shortfalls) AS c(code)
  GROUP BY m.host
),
w AS (
  SELECT shawk.period(host_shortfalls.since, host_shortfalls.until) AS period,
         coalesce((SELECT tstzmultirange(tstzrange(NULL, r.pruned_before)) FROM shawk.retention r), '{}') AS pruned
)
SELECT n.host, k.agent, coalesce(agg.machines, 0), coalesce(agg.covered, 0),
       -- In the order that the commands tell them.
       ARRAY(SELECT c FROM unnest(ARRAY['unknown_host', 'no_agent', 'several_machines', 'not_observed', 'before_retention',
                                        'dropped_flows', 'netns_limited', 'udp_not_traced']) AS c
             WHERE c = ANY (
               coalesce(codes.codes, '{}')
               || CASE WHEN k.agent THEN '{}'::text[]
                       WHEN EXISTS (SELECT FROM shawk.inventory_hosts i WHERE i.host = n.host) THEN ARRAY['no_agent']
                       ELSE ARRAY['unknown_host'] END
               || CASE WHEN agg.machines > 1 THEN ARRAY['several_machines'] ELSE '{}' END
               || CASE WHEN k.agent AND agg.machines IS NULL AND NOT isempty(w.period - w.pruned) THEN ARRAY['not_observed']
                       ELSE '{}' END
               || CASE WHEN k.agent AND agg.machines IS NULL AND NOT isempty(w.period * w.pruned)
                       THEN ARRAY['before_retention'] ELSE '{}' END)),
       coalesce(agg.unobserved, shawk.duration(w.period)), coalesce(agg.gaps, 1),
       coalesce(agg.partly_observed, interval '0'),
       coalesce(agg.udp_untraced, interval '0'), coalesce(agg.netns_limited, interval '0'),
       coalesce(agg.before_retention, shawk.duration(w.period * w.pruned)),
       coalesce(agg.tolerated, interval '0'), coalesce(agg.tolerated_gaps, 0), coalesce(agg.untold, false)
FROM n
CROSS JOIN w
CROSS JOIN LATERAL (SELECT EXISTS (SELECT FROM shawk.hosts h WHERE h.hostname = n.host) AS agent) k
LEFT JOIN agg ON agg.host = n.host
LEFT JOIN codes ON codes.host = n.host
$$;

-- The arguments that the verdicts below share, checked as impact_verdict()
-- checks them.
CREATE FUNCTION shawk.check_period(since timestamptz, until timestamptz, min_coverage numeric, tolerance interval)
RETURNS void LANGUAGE plpgsql IMMUTABLE AS $$
BEGIN
  IF since IS NULL OR until IS NULL OR since >= until THEN
    RAISE EXCEPTION 'the period is empty: % to %', since, until USING ERRCODE = 'invalid_parameter_value';
  END IF;
  IF min_coverage IS NULL OR min_coverage <= 0 OR min_coverage > 1 THEN
    RAISE EXCEPTION 'min_coverage is above 0, up to 1: %', min_coverage USING ERRCODE = 'invalid_parameter_value';
  END IF;
  IF tolerance IS NULL OR tolerance < interval '0' OR tolerance > interval '1 hour' THEN
    RAISE EXCEPTION 'tolerance is from 0 to 1 hour: %', tolerance USING ERRCODE = 'invalid_parameter_value';
  END IF;
END
$$;

-- Rules ----------------------------------------------------------------------

-- What a host connected to and accepted connections from, over TCP and
-- UDP: the flows that least-privilege rules of the host allow. target_unit
-- narrows them to the processes of a unit (shawk.unit) and of the units
-- under it (`<unit>/...`: a container that the unit runs in a cgroup of
-- its own, which a limit of systemd on the unit holds too), with those of
-- the sockets of the host without a known owner, which may be its own:
-- the service ~unknown without a unit, not a process of another unit that
-- gives itself that name.
--
-- A row is an address and a port that the sockets of the host saw: of the
-- server for egress (the host connected), the address of the client and
-- the port of the host for ingress (it accepted). They are those of the
-- edges of the host, not of the dependencies matched from them: a
-- firewall of the host sees what its sockets see, a virtual address or
-- the address of a relay included. peer_addr is a network (0.0.0.0/0 or
-- ::/0) for the peers that the agent folded, whose addresses it did not
-- keep. in_period is false for a flow last seen before the period: it is
-- not part of the rules, and is listed so that a job rarer than the period
-- is not left out without a word.
--
-- port_from and port_to are the ports to allow: the port, or, under the
-- rules of ports (§5.3), the range of dynamic_ports that holds it, or
-- every port for a server of port_agnostic_services, which listens on
-- another port at every run. kernel_chosen tells that the server listened
-- on a port the kernel chose in the period, which no rule of ports covers
-- unless the two differ: a rule pinned to it breaks at the next run.
--
-- translated marks the backend that the host itself translates a
-- connection of its own to, in the network namespace of the socket (DNAT
-- in its kernel, learned from conntrack): the packets leave the host for
-- the backend, and what filters after the translation must allow it
-- beside the address the socket connected to.
--
-- peer is the name of the other side, as baseline_observed() names it,
-- and peer_host its host, for a peer whose agent saw the connection; they
-- tell the reviewer what a rule is for and pin nothing.
--
-- The edges of the host are joined with its dependencies, which are the
-- rows of a function, of which the planner knows nothing: it would join
-- the few rows it expects in nested loops, which take a quarter of a
-- minute for a host with thousands of clients. As in shawk.dependents(),
-- nested loops are off, so that the joins hash, and so is the JIT
-- compiler, which the costs of such a plan start for nothing.
CREATE FUNCTION shawk_v1.policy_flows(target_host text, since timestamptz, until timestamptz,
                                      target_unit text DEFAULT NULL)
RETURNS TABLE (
  direction text, in_period boolean, service text, unit text, proto text,
  peer_addr inet, port integer, port_from integer, port_to integer,
  peer text, peer_host text, translated boolean, kernel_chosen boolean,
  first_seen timestamptz, last_seen timestamptz)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp SET enable_nestloop = off SET jit = off AS $$
WITH
-- The host ids of the name, as values: the edges and the translations of
-- the host are then read through their indexes, whatever joins them.
t AS MATERIALIZED (
  SELECT ARRAY(SELECT h.id FROM shawk.hosts h WHERE h.hostname = policy_flows.target_host) AS ids
),
e AS MATERIALIZED (
  SELECT e.id, e.host_id, e.process_id, e.role, e.proto, e.local_addr, e.remote_addr, e.port, e.netns,
         e.first_seen, e.last_seen, p.service_name AS service, p.unit,
         e.last_seen >= policy_flows.since AS in_period
  FROM shawk.edges e
  JOIN shawk.processes p ON p.id = e.process_id
  WHERE e.host_id = ANY ((SELECT t.ids FROM t)::text[])
    AND policy_flows.since < policy_flows.until
    AND e.first_seen <= policy_flows.until
    AND (policy_flows.target_unit IS NULL OR p.unit = policy_flows.target_unit
         OR starts_with(p.unit, policy_flows.target_unit || '/')
         OR (p.service_name = '~unknown' AND p.unit = ''))
),
nd AS MATERIALIZED (
  SELECT d.*
  FROM shawk.named_dependencies(policy_flows.since, policy_flows.until, policy_flows.target_host) d
  WHERE EXISTS (SELECT FROM e WHERE e.in_period)
),
-- The names of the servers of the client edges, the ports of their
-- dependencies, and whether the kernel chose the port of a server.
eg AS MATERIALIZED (
  SELECT e.id,
         string_agg(DISTINCT d.server_name COLLATE "C", ', ') AS peer,
         string_agg(DISTINCT d.server_host COLLATE "C", ', ') AS peer_host,
         bool_or(d.dependency_port = 0) AS any_port,
         bool_or(d.kernel_chosen) AS kernel_chosen
  FROM e
  JOIN nd d
    ON  d.client_host = policy_flows.target_host AND d.proto = e.proto AND d.client_addr = e.local_addr
    AND coalesce(d.virtual_addr, d.server_addr) = e.remote_addr AND coalesce(d.virtual_port, d.port) = e.port
    AND d.client_service = e.service AND d.client_unit = e.unit
  WHERE e.role = 'client' AND e.in_period
  GROUP BY e.id
),
-- The names of the clients of the server edges.
ig AS MATERIALIZED (
  SELECT e.id,
         string_agg(DISTINCT d.client_name COLLATE "C", ', ') AS peer,
         string_agg(DISTINCT d.client_host COLLATE "C", ', ') AS peer_host
  FROM e
  JOIN nd d
    ON  d.server_host = policy_flows.target_host AND d.proto = e.proto AND d.server_addr = e.local_addr
    AND d.port = e.port AND d.client_addr = e.remote_addr
    AND d.server_service = e.service AND d.server_unit = e.unit
  WHERE e.role = 'server' AND e.in_period
  GROUP BY e.id
),
-- The backends that the host translated its own connections to, in the
-- network namespace of their socket.
tr AS (
  SELECT DISTINCT e.id, l.backend_addr, l.backend_port
  FROM shawk.learned_translations l
  JOIN e
    ON  l.host_id = e.host_id AND l.proto = e.proto AND l.netns = e.netns AND l.client_addr = e.local_addr
    AND l.virtual_addr = e.remote_addr AND l.virtual_port = e.port
  WHERE l.host_id = ANY ((SELECT t.ids FROM t)::text[])
    AND e.role = 'client' AND e.in_period
    AND l.last_seen >= policy_flows.since - interval '15 minutes'
    AND l.first_seen <= policy_flows.until + interval '15 minutes'
    AND (l.backend_addr <> e.remote_addr OR l.backend_port <> e.port)
),
f AS (
  SELECT 'egress' AS direction, e.in_period, e.service, e.unit, e.proto, e.remote_addr AS peer_addr, e.port,
         r.port_from, r.port_to,
         CASE WHEN r.port_from IS NULL AND coalesce(eg.any_port, false) THEN true ELSE false END AS any_port,
         coalesce(eg.peer, shawk_v1.peer_class(e.remote_addr)) AS peer, eg.peer_host,
         false AS translated, coalesce(eg.kernel_chosen, false) AS kernel_chosen, e.first_seen, e.last_seen
  FROM e
  LEFT JOIN eg ON eg.id = e.id
  LEFT JOIN LATERAL (
    SELECT min(r.port_from) AS port_from, max(r.port_to) AS port_to
    FROM shawk.dynamic_ports r
    WHERE r.proto = e.proto AND e.port BETWEEN r.port_from AND r.port_to AND e.remote_addr <<= r.addr
  ) r ON true
  WHERE e.role = 'client'
  UNION ALL
  SELECT 'egress', true, e.service, e.unit, e.proto, tr.backend_addr, tr.backend_port,
         NULL, NULL, false,
         coalesce(eg.peer, shawk_v1.peer_class(tr.backend_addr)), eg.peer_host,
         true, false, e.first_seen, e.last_seen
  FROM tr
  JOIN e ON e.id = tr.id
  LEFT JOIN eg ON eg.id = e.id
  UNION ALL
  SELECT 'ingress', e.in_period, e.service, e.unit, e.proto, e.remote_addr, e.port,
         r.port_from, r.port_to,
         r.port_from IS NULL AND shawk.dependency_port(e.service, e.unit, e.local_addr, e.port, e.proto) = 0,
         coalesce(ig.peer, shawk_v1.peer_class(e.remote_addr)), ig.peer_host,
         false,
         EXISTS (SELECT FROM shawk.listener_owners o
                 WHERE o.host_id = e.host_id AND o.proto = e.proto AND o.port = e.port AND o.process_id = e.process_id
                   AND o.kernel_chosen_seen >= policy_flows.since),
         e.first_seen, e.last_seen
  FROM e
  LEFT JOIN ig ON ig.id = e.id
  LEFT JOIN LATERAL (
    SELECT min(r.port_from) AS port_from, max(r.port_to) AS port_to
    FROM shawk.dynamic_ports r
    WHERE r.proto = e.proto AND e.port BETWEEN r.port_from AND r.port_to AND e.local_addr <<= r.addr
  ) r ON true
  WHERE e.role = 'server'
)
SELECT f.direction, f.in_period, f.service, f.unit, f.proto, f.peer_addr, f.port,
       CASE WHEN f.any_port THEN 1 ELSE coalesce(f.port_from, f.port) END,
       CASE WHEN f.any_port THEN 65535 ELSE coalesce(f.port_to, f.port) END,
       f.peer, f.peer_host, f.translated, bool_or(f.kernel_chosen), min(f.first_seen), max(f.last_seen)
FROM f
GROUP BY 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12
ORDER BY f.direction COLLATE "C", f.in_period DESC, f.proto COLLATE "C", f.port, f.peer_addr,
         f.service COLLATE "C", f.unit COLLATE "C", f.peer COLLATE "C"
$$;

-- Whether the history tells every flow of policy_flows() over [since,
-- until], one row:
--
--   COMPLETE    an agent observed the one machine of the host name for
--               min_coverage of the period, all that the flows cover, and
--               learned the translations of addresses that the host makes;
--               caveats tell the shortfalls that min_coverage accepted;
--   INCOMPLETE  it did not, or the target is not known: no agent ever
--               reported under the name of the host (unknown_host, or
--               no_agent for a host of the inventory), no process of the
--               host had the unit in the period (unknown_unit), several
--               machines reported under the name in the period
--               (several_machines: the flows are of them all, and the
--               coverage of the least observed), or an agent of the host
--               did not learn every translation (translations_not_learned:
--               one that traces none, or that folds the peers outside its
--               internal ranges, §3.6, which is the default: a connection
--               that the host rewrites to a backend outside them leaves
--               the host for an address that the flows lack, and nothing
--               tells whether the host rewrites any). reasons tell what is
--               missing. Rules made from the flows would deny what was not
--               seen. min_coverage accepts time that was not observed, and
--               none of the other reasons.
--
-- coverage is the part of the period, from 0 to 1 and cut rather than
-- rounded, in which an agent of the host observed (not_observed
-- otherwise), within the retention (before_retention), without dropped
-- flows (dropped_flows), in every network namespace (netns_limited) and
-- with UDP (udp_not_traced): that of the least observed machine of the
-- name. unobserved, gaps, partly_observed, udp_untraced, netns_limited
-- and before_retention tell how long each lasted, the longest among the
-- machines of the name (policy_gaps() lists the gaps). machines counts
-- the machines of the name in the period.
-- tolerated is the time, in tolerated_gaps stretches, that counts as
-- observed although no agent reported in it, because it is within
-- `tolerance` of a report: the restart of an agent, or its latest report
-- not written yet.
--
-- network_namespaces counts the network namespaces of the sockets of the
-- flows in the period: more than one tells a host of containers, whose
-- forwarded connections rules of the host itself do not see. unix_sockets
-- tells whether the target used or served Unix sockets in the period.
-- translations_traced is false with translations_not_learned.
CREATE FUNCTION shawk_v1.policy_verdict(target_host text, since timestamptz, until timestamptz,
                                        target_unit text DEFAULT NULL, min_coverage numeric DEFAULT 1,
                                        tolerance interval DEFAULT '3 minutes')
RETURNS TABLE (status text, reasons text[], caveats text[], coverage numeric,
               unobserved interval, gaps integer, partly_observed interval,
               network_namespaces integer, unix_sockets boolean, translations_traced boolean,
               machines integer, tolerated interval, tolerated_gaps integer,
               udp_untraced interval, netns_limited interval, before_retention interval)
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
  o record;
  shortfalls text[];
  -- The shortfalls that no min_coverage accepts.
  refused boolean := false;
BEGIN
  PERFORM shawk.check_period(since, until, min_coverage, tolerance);
  IF target_host IS NULL OR target_host = '' THEN
    RAISE EXCEPTION 'no target host' USING ERRCODE = 'invalid_parameter_value';
  END IF;
  IF target_unit = '' THEN
    RAISE EXCEPTION 'target_unit is empty' USING ERRCODE = 'invalid_parameter_value';
  END IF;

  SELECT * INTO o FROM shawk.host_shortfalls(since, until, ARRAY[target_host], tolerance);
  shortfalls := o.shortfalls;
  IF NOT o.agent OR o.machines > 1 THEN
    refused := true;
  END IF;
  -- A unit that no process of the host had was not seen to connect, which
  -- tells nothing: its name may be misspelt.
  IF o.agent AND target_unit IS NOT NULL AND NOT EXISTS (
       SELECT FROM shawk.hosts h
       JOIN shawk.processes p ON p.host_id = h.id
       WHERE h.hostname = target_host AND (p.unit = target_unit OR starts_with(p.unit, target_unit || '/'))
         AND p.last_seen >= since - interval '15 minutes' AND p.first_seen <= until) THEN
    refused := true;
    shortfalls := shortfalls || 'unknown_unit'::text;
  END IF;
  IF o.translations_untold THEN
    refused := true;
    shortfalls := shortfalls || 'translations_not_learned'::text;
  END IF;

  coverage := trunc(o.covered, 6);
  unobserved := o.unobserved;
  gaps := o.gaps;
  partly_observed := o.partly_observed;
  machines := o.machines;
  tolerated := o.tolerated;
  tolerated_gaps := o.tolerated_gaps;
  udp_untraced := o.udp_untraced;
  netns_limited := o.netns_limited;
  before_retention := o.before_retention;
  translations_traced := NOT o.translations_untold;
  SELECT count(DISTINCT e.netns)::integer INTO network_namespaces
  FROM shawk.hosts h
  JOIN shawk.edges e ON e.host_id = h.id
  JOIN shawk.processes p ON p.id = e.process_id
  WHERE h.hostname = target_host AND e.last_seen >= since AND e.first_seen <= until
    AND (target_unit IS NULL OR p.unit = target_unit OR starts_with(p.unit, target_unit || '/'));
  unix_sockets := EXISTS (
      SELECT FROM shawk.hosts h
      JOIN shawk.unix_edges e ON e.host_id = h.id
      JOIN shawk.processes p ON p.id = e.process_id
      WHERE h.hostname = target_host AND e.last_seen >= since AND e.first_seen <= until
        AND (target_unit IS NULL OR p.unit = target_unit OR starts_with(p.unit, target_unit || '/')))
    OR EXISTS (
      SELECT FROM shawk.hosts h
      JOIN shawk.unix_listeners l ON l.host_id = h.id
      JOIN shawk.processes p ON p.id = l.process_id
      WHERE h.hostname = target_host AND l.last_seen >= since AND l.first_seen <= until
        AND (target_unit IS NULL OR p.unit = target_unit OR starts_with(p.unit, target_unit || '/')));
  IF refused OR o.covered < min_coverage THEN
    status := 'INCOMPLETE';
    reasons := shortfalls;
    caveats := '{}';
  ELSE
    status := 'COMPLETE';
    reasons := '{}';
    caveats := shortfalls;
  END IF;
  RETURN NEXT;
END
$$;

-- The gaps of policy_verdict(): the stretches of [since, until] for which
-- the history does not tell the flows of a machine of the host name, each
-- with its cause: retention for the time before the retention, agent for
-- the time in which no agent of the machine observed. machine is the id
-- of the machine (shawk_v1.agents.host_id), NULL for a name without a
-- machine in the period, whose gap is the whole period.
CREATE FUNCTION shawk_v1.policy_gaps(target_host text, since timestamptz, until timestamptz,
                                     tolerance interval DEFAULT '3 minutes')
RETURNS TABLE (machine text, gap_start timestamptz, gap_end timestamptz, cause text)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
WITH m AS MATERIALIZED (
  SELECT x.host_id, x.missing, x.pruned
  FROM shawk.machine_shortfalls(policy_gaps.since, policy_gaps.until,
         ARRAY(SELECT o.host_id
               FROM shawk.machines_of(policy_gaps.since, policy_gaps.until, ARRAY[policy_gaps.target_host],
                                      policy_gaps.tolerance) o),
         policy_gaps.tolerance) x
  WHERE policy_gaps.since < policy_gaps.until
),
w AS (
  SELECT shawk.period(policy_gaps.since, policy_gaps.until) AS period,
         coalesce((SELECT tstzmultirange(tstzrange(NULL, r.pruned_before)) FROM shawk.retention r), '{}') AS pruned
),
r AS (
  SELECT m.host_id, m.missing, m.pruned FROM m
  UNION ALL
  SELECT NULL, w.period, w.period * w.pruned
  FROM w
  WHERE policy_gaps.since < policy_gaps.until AND NOT EXISTS (SELECT FROM m)
)
SELECT r.host_id, lower(g.gap), upper(g.gap), g.cause
FROM r
CROSS JOIN LATERAL (
  SELECT x AS gap, 'retention' AS cause FROM unnest(r.pruned) AS x
  UNION ALL
  SELECT x, 'agent' FROM unnest(r.missing - r.pruned) AS x
) g
ORDER BY r.host_id COLLATE "C", lower(g.gap)
$$;

-- Baselines ------------------------------------------------------------------

-- The dependencies of services in [since, until] as a baseline lists
-- them: one row per service, server, port and transport, of the services
-- of `services` (every service if NULL). The client is a process on a
-- host with an agent; the server is named as shawk.named_dependencies()
-- names it, and the port is that of the dependencies between services, 0
-- under the rules of ports (§5.3). Dependencies over Unix sockets are left
-- out.
--
-- service is the service that a baseline judges the dependency as
-- (named_dependencies, judged_service): the service of the client, or,
-- with `judged`, the services that a baseline is to hold, the first
-- service of `judged` that runs in the unit of a client whose own service
-- is not in `judged`. processes lists up to 20 such other services of the
-- clients of a row. Without `judged`, the services of `services` are, so
-- that the baseline of a service lists what its drift is judged on; with
-- neither, every service is its own.
--
-- A server that listened on a port the kernel chose, which no rule of
-- ports covers, has port 0 with kernel_chosen: its port is another one at
-- its next run, and a baseline that pinned it would tell a drift then.
-- The row stands for the ports that the kernel chose for a server of the
-- name, and for no other port (shawk.baseline_dependencies.kernel_chosen).
-- ports are up to 20 of the ports of the servers of a row, as their
-- sockets had them.
--
-- hosts are the hosts of the clients, addrs up to 50 of the addresses they
-- connected to (a network for folded peers), and named_by the best
-- evidence of the name of the server among its rows: edge, endpoint or
-- address.
CREATE FUNCTION shawk_v1.baseline_observed(since timestamptz, until timestamptz, services text[] DEFAULT NULL,
                                           judged text[] DEFAULT NULL)
RETURNS TABLE (service text, peer text, port integer, proto text,
               first_seen timestamptz, last_seen timestamptz, hosts text[], addrs inet[], named_by text,
               kernel_chosen boolean, ports integer[], processes text[])
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
  SELECT d.judged_service, d.server_name, CASE WHEN k.chosen THEN 0 ELSE d.dependency_port END, d.proto,
         min(d.first_seen), max(d.last_seen),
         array_agg(DISTINCT d.client_host COLLATE "C" ORDER BY d.client_host COLLATE "C"),
         (array_agg(DISTINCT coalesce(d.virtual_addr, d.server_addr) ORDER BY coalesce(d.virtual_addr, d.server_addr)))[1:50],
         CASE WHEN bool_or(d.named_by = 'edge') THEN 'edge' WHEN bool_or(d.named_by = 'endpoint') THEN 'endpoint'
              ELSE 'address' END,
         k.chosen,
         (array_agg(DISTINCT coalesce(d.virtual_port, d.port) ORDER BY coalesce(d.virtual_port, d.port)))[1:20],
         coalesce((array_agg(DISTINCT d.client_service COLLATE "C" ORDER BY d.client_service COLLATE "C")
                   FILTER (WHERE d.client_service <> d.judged_service))[1:20], '{}')
  FROM shawk.named_dependencies(baseline_observed.since, baseline_observed.until, NULL, true, baseline_observed.services,
                                coalesce(baseline_observed.judged, baseline_observed.services)) d
  -- A port that a rule of ports covers is every port by that rule,
  -- whoever chose it.
  CROSS JOIN LATERAL (SELECT d.kernel_chosen AND d.dependency_port <> 0 AS chosen) k
  WHERE baseline_observed.since < baseline_observed.until
  GROUP BY 1, 2, 3, 4, k.chosen
  ORDER BY d.judged_service COLLATE "C", d.server_name COLLATE "C", 3, d.proto COLLATE "C", k.chosen
$$;

-- Whether the history tells every dependency of each service of
-- `services` over [since, until], one row per service: the observation
-- (shawk.machine_shortfalls) of every machine that runs the service.
--
--   COMPLETE    every such machine was observed for min_coverage of the
--               period;
--   INCOMPLETE  one was not (short_hosts lists up to 20 of their hosts,
--               the least observed first, short_seconds how long each
--               was not observed, and unobserved_hosts counts them), or
--               no machine is known for the service (unknown_service):
--               nothing is known to tell that it did nothing.
--
-- A machine runs the service when a process of it was last seen there
-- since hosts_since, and by the end of the period. hosts_since is NULL
-- for the dependencies of a period, which are of the machines that ran
-- the service within it (from 15 minutes before it). It is earlier for a
-- drift: the question is then what the service did in the period, on the
-- machines that have it, and a machine whose agent went silent before the
-- period, with all its processes, must count as not observed rather than
-- be forgotten with them. A hosts_since that is later than 15 minutes
-- before the period is taken as that: a machine that ran the service in
-- the period runs it, whatever the caller remembers.
--
-- With hosts_since, a service that no machine runs is told apart by the
-- machines that ran it before: when one of them was observed for
-- min_coverage of the period, the service does not run, and nothing of it
-- was missed: COMPLETE, with the caveat not_running, and idle_hosts
-- counts those machines. When none was, or no process of the service was
-- ever seen, it is unknown_service.
--
-- A machine whose last report is before the first report of another
-- machine of the same host name was replaced by it (a host that was
-- installed again has a new machine id): it is gone, not unobserved, and
-- is left out.
--
-- coverage is that of the least observed machine. One that ran the
-- service for a part of the period counts over the whole period: what it
-- did before its agent first reported is not known. hosts counts the
-- hosts by name.
CREATE FUNCTION shawk_v1.baseline_verdict(services text[], since timestamptz, until timestamptz,
                                          min_coverage numeric DEFAULT 1, tolerance interval DEFAULT '3 minutes',
                                          hosts_since timestamptz DEFAULT NULL)
RETURNS TABLE (service text, status text, reasons text[], caveats text[],
               hosts integer, coverage numeric, short_hosts text[], unobserved_hosts integer,
               short_seconds integer[], idle_hosts integer)
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
  -- Since when a process of a service was seen on the machines that run it.
  ran_since timestamptz := least(coalesce(hosts_since, since - interval '15 minutes'), since - interval '15 minutes');
BEGIN
  PERFORM shawk.check_period(since, until, min_coverage, tolerance);
  RETURN QUERY
  WITH asked AS (
    SELECT DISTINCT u.service FROM unnest(services) AS u(service) WHERE u.service IS NOT NULL
  ),
  -- The machines that had a process of a service, with when it was last
  -- seen there.
  had AS MATERIALIZED (
    SELECT p.service_name AS service, h.hostname AS host, h.id AS host_id, max(p.last_seen) AS last_seen
    FROM shawk.processes p
    JOIN shawk.hosts h ON h.id = p.host_id
    WHERE p.service_name IN (SELECT a.service FROM asked a) AND p.first_seen <= until
      AND (hosts_since IS NOT NULL OR p.last_seen >= ran_since)
    GROUP BY p.service_name, h.hostname, h.id
  ),
  -- The first and the last report of every machine of the names of
  -- those machines: one that reported last before another of its name
  -- reported first was replaced.
  span AS MATERIALIZED (
    SELECT h.hostname AS host, h.id AS host_id, min(a.started_at) AS first_report, max(a.last_heartbeat) AS last_report
    FROM shawk.hosts h
    JOIN shawk.agent_sessions a ON a.host_id = h.id
    WHERE h.hostname IN (SELECT had.host FROM had)
    GROUP BY h.hostname, h.id
  ),
  sh AS MATERIALIZED (
    SELECT had.service, had.host, had.host_id, had.last_seen >= ran_since AS runs
    FROM had
    WHERE NOT EXISTS (
      SELECT FROM span mine
      JOIN span other ON other.host = mine.host AND other.host_id <> mine.host_id AND other.first_report > mine.last_report
      WHERE mine.host_id = had.host_id)
  ),
  ob AS MATERIALIZED (
    SELECT * FROM shawk.machine_shortfalls(since, until, ARRAY(SELECT DISTINCT sh.host_id FROM sh), tolerance)
  ),
  -- The hosts of each service by name, each with the coverage of the
  -- least observed of its machines that run the service.
  byhost AS (
    SELECT sh.service, sh.host, min(ob.covered) AS covered, max(ob.unobserved) AS unobserved
    FROM sh
    JOIN ob ON ob.host_id = sh.host_id
    WHERE sh.runs
    GROUP BY sh.service, sh.host
  ),
  short AS (
    SELECT b.service, b.host, b.unobserved, row_number() OVER (PARTITION BY b.service ORDER BY b.covered, b.host COLLATE "C") AS n
    FROM byhost b
    WHERE b.covered < min_coverage
  ),
  per AS (
    SELECT b.service,
           count(*)::integer AS hosts,
           min(b.covered) AS covered,
           (count(*) FILTER (WHERE b.covered < min_coverage))::integer AS unobserved_hosts
    FROM byhost b
    GROUP BY b.service
  ),
  listed AS (
    SELECT s.service, array_agg(s.host ORDER BY s.n) AS short_hosts,
           array_agg(extract(epoch FROM s.unobserved)::integer ORDER BY s.n) AS short_seconds
    FROM short s
    WHERE s.n <= 20
    GROUP BY s.service
  ),
  -- The machines that ran a service before, and were observed for the
  -- period: the service does not run there, and nothing of it was missed.
  idle AS (
    SELECT sh.service, count(DISTINCT sh.host)::integer AS hosts
    FROM sh
    JOIN ob ON ob.host_id = sh.host_id
    WHERE NOT sh.runs AND ob.covered >= min_coverage
    GROUP BY sh.service
  ),
  -- The shortfalls of the machines of each service, and whether one of
  -- the machines that has it is below min_coverage.
  codes AS (
    SELECT x.service,
           coalesce(array_agg(x.code ORDER BY x.code COLLATE "C") FILTER (WHERE x.short), '{}') AS short_codes,
           coalesce(array_agg(x.code ORDER BY x.code COLLATE "C") FILTER (WHERE NOT x.short), '{}') AS other_codes
    FROM (
      SELECT sh.service, c.code, bool_or(ob.covered < min_coverage) AS short
      FROM sh
      JOIN ob ON ob.host_id = sh.host_id
      CROSS JOIN LATERAL unnest(ob.shortfalls) AS c(code)
      WHERE sh.runs
      GROUP BY sh.service, c.code
    ) x
    GROUP BY x.service
  )
  SELECT a.service,
         CASE WHEN per.service IS NULL AND idle.hosts > 0 THEN 'COMPLETE'
              WHEN per.service IS NULL OR per.covered < min_coverage THEN 'INCOMPLETE' ELSE 'COMPLETE' END,
         CASE WHEN per.service IS NULL AND idle.hosts > 0 THEN '{}'::text[]
              WHEN per.service IS NULL THEN ARRAY['unknown_service']
              WHEN per.covered < min_coverage THEN coalesce(codes.short_codes, '{}') ELSE '{}'::text[] END,
         CASE WHEN per.service IS NULL AND idle.hosts > 0 THEN ARRAY['not_running']
              WHEN per.service IS NULL THEN '{}'::text[]
              WHEN per.covered < min_coverage THEN coalesce(codes.other_codes, '{}')
              ELSE coalesce(codes.short_codes, '{}') || coalesce(codes.other_codes, '{}') END,
         coalesce(per.hosts, 0),
         trunc(coalesce(per.covered, CASE WHEN idle.hosts > 0 THEN 1 ELSE 0 END), 6),
         coalesce(listed.short_hosts, '{}'::text[]),
         coalesce(per.unobserved_hosts, 0),
         coalesce(listed.short_seconds, '{}'::integer[]),
         coalesce(idle.hosts, 0)
  FROM asked a
  LEFT JOIN per ON per.service = a.service
  LEFT JOIN listed ON listed.service = a.service
  LEFT JOIN idle ON idle.service = a.service
  LEFT JOIN codes ON codes.service = a.service
  ORDER BY a.service COLLATE "C";
END
$$;

-- The baseline that the connector read: one row per service and approved
-- dependency, and one row without a dependency (peer, port and proto
-- NULL) for a service approved to have none. kernel_chosen tells a
-- dependency on the ports that the kernel chose for a server of the name,
-- and no other: its port is 0, which then does not stand for every port.
CREATE VIEW shawk_v1.baseline AS
SELECT s.service, d.peer, d.port, d.proto, d.kernel_chosen
FROM shawk.baseline_services s
LEFT JOIN shawk.baseline_dependencies d ON d.service = s.service;

-- When the baseline was last read from a valid file (read_at, NULL if
-- never), the latest failure since (failed_at, error), and how many
-- services and dependencies it holds. No row before a connector with
-- baseline_file read it.
CREATE VIEW shawk_v1.baseline_status AS
SELECT st.read_at, st.failed_at, st.error,
       (SELECT count(*) FROM shawk.baseline_services) AS services,
       (SELECT count(*) FROM shawk.baseline_dependencies) AS dependencies
FROM shawk.baseline_state st;

-- The drift: the dependencies of baseline_observed() in [since, until]
-- of the services that have a baseline (of those of `services` if not
-- NULL) that are not in it. A service without a baseline is not judged
-- and has no row, unless its process is in a unit that runs services that
-- have one, on its host, and that unrelated processes do not share by its
-- kind: it is then judged by those services together
-- (named_dependencies: a dependency that one of them approves is no
-- drift, and one that none approves is told once, under the first of
-- them; members_since tells since when a process of a service must have
-- been seen in the unit), and processes lists it.
-- baseline_new_services() lists the services that are new.
--
-- A dependency is in the baseline of a service when the baseline has its
-- server and transport with its port, or with port 0, which stands for
-- every port: the port of the dependency between services, or the port
-- of the server itself, so that a rule of ports added or removed after
-- the baseline was approved does not make a drift of what it holds. A
-- dependency on a port that the kernel chose is also in a baseline that
-- has its server and transport with kernel_chosen, which approves the
-- ports that the kernel chose and no other.
CREATE FUNCTION shawk_v1.baseline_drift(since timestamptz, until timestamptz, services text[] DEFAULT NULL,
                                        members_since timestamptz DEFAULT NULL)
RETURNS TABLE (service text, peer text, port integer, proto text,
               first_seen timestamptz, last_seen timestamptz, hosts text[], addrs inet[], named_by text,
               kernel_chosen boolean, ports integer[], processes text[])
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
  SELECT d.judged_service, d.server_name, CASE WHEN k.chosen THEN 0 ELSE d.dependency_port END, d.proto,
         min(d.first_seen), max(d.last_seen),
         array_agg(DISTINCT d.client_host COLLATE "C" ORDER BY d.client_host COLLATE "C"),
         (array_agg(DISTINCT coalesce(d.virtual_addr, d.server_addr) ORDER BY coalesce(d.virtual_addr, d.server_addr)))[1:50],
         CASE WHEN bool_or(d.named_by = 'edge') THEN 'edge' WHEN bool_or(d.named_by = 'endpoint') THEN 'endpoint'
              ELSE 'address' END,
         k.chosen,
         (array_agg(DISTINCT coalesce(d.virtual_port, d.port) ORDER BY coalesce(d.virtual_port, d.port)))[1:20],
         coalesce((array_agg(DISTINCT d.client_service COLLATE "C" ORDER BY d.client_service COLLATE "C")
                   FILTER (WHERE d.client_service <> d.judged_service))[1:20], '{}')
  FROM shawk.named_dependencies(baseline_drift.since, baseline_drift.until, NULL, true, baseline_drift.services,
                                ARRAY(SELECT s.service FROM shawk.baseline_services s), baseline_drift.members_since) d
  CROSS JOIN LATERAL (SELECT d.kernel_chosen AND d.dependency_port <> 0 AS chosen) k
  WHERE baseline_drift.since < baseline_drift.until
    AND NOT EXISTS (
      SELECT FROM shawk.baseline_dependencies b
      WHERE b.service = ANY (d.judges) AND b.peer = d.server_name AND b.proto = d.proto
        AND ((NOT b.kernel_chosen AND b.port IN (0, d.port, d.dependency_port)) OR (b.kernel_chosen AND d.kernel_chosen)))
  GROUP BY 1, 2, 3, 4, k.chosen
  ORDER BY d.judged_service COLLATE "C", d.server_name COLLATE "C", 3, d.proto COLLATE "C", k.chosen
$$;

-- The services without a baseline that were first seen in [since, until]
-- and opened connections: a new executable, or a process that names
-- itself anew, is a service of its own (§4.1). One in a unit that runs
-- services that have a baseline is judged by them (baseline_drift),
-- unless the unit is one that unrelated processes share
-- (shawk.shared_unit); another is judged by no baseline, and is told here
-- once, when it appears. first_seen is the earliest time a process of
-- the service was seen on any host, within the retention, and hosts its
-- hosts. The processes of Slurm jobs, which their users name, and the
-- sockets without a known owner are left out.
CREATE FUNCTION shawk_v1.baseline_new_services(since timestamptz, until timestamptz)
RETURNS TABLE (service text, first_seen timestamptz, hosts text[])
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
  SELECT p.service_name, min(p.first_seen), array_agg(DISTINCT h.hostname COLLATE "C" ORDER BY h.hostname COLLATE "C")
  FROM shawk.processes p
  JOIN shawk.hosts h ON h.id = p.host_id
  WHERE p.unit NOT LIKE 'slurm/%' AND p.service_name <> '~unknown'
  GROUP BY p.service_name
  HAVING min(p.first_seen) >= baseline_new_services.since AND min(p.first_seen) <= baseline_new_services.until
     AND NOT EXISTS (SELECT FROM shawk.baseline_services s WHERE s.service = p.service_name)
     AND bool_or(EXISTS (SELECT FROM shawk.edges e WHERE e.process_id = p.id AND e.role = 'client'))
  ORDER BY p.service_name COLLATE "C"
$$;

-- What no baseline judges although it is next to one: the dependencies in
-- [since, until] of the processes without a baseline of their own in a
-- unit that unrelated processes share by its kind (shawk.shared_unit: the
-- Slurm jobs of every user, login sessions, transient units) and in which
-- services of the baseline run on the same host (a process of one was
-- seen there since members_since). Such a unit says nothing of what runs
-- in it, so these are no drift of those services; they are listed, so
-- that what is next to a baseline and out of it is not silent. One row
-- per unit, process and server, at most max_rows of them in the order of
-- the bytes of their names; total counts them all. services are the
-- services of the baseline of the unit, ports up to 20 of the ports, and
-- hosts the hosts of the processes.
CREATE FUNCTION shawk_v1.baseline_unjudged(since timestamptz, until timestamptz, members_since timestamptz DEFAULT NULL,
                                           max_rows integer DEFAULT 100)
RETURNS TABLE (unit text, process text, peer text, proto text, ports integer[], hosts text[], services text[],
               first_seen timestamptz, last_seen timestamptz, total bigint)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
  SELECT g.*, count(*) OVER ()
  FROM (
    SELECT d.client_unit, d.client_service, d.server_name, d.proto,
           (array_agg(DISTINCT coalesce(d.virtual_port, d.port) ORDER BY coalesce(d.virtual_port, d.port)))[1:20],
           array_agg(DISTINCT d.client_host COLLATE "C" ORDER BY d.client_host COLLATE "C"),
           ARRAY(SELECT DISTINCT j.service COLLATE "C"
                 FROM jsonb_array_elements(jsonb_agg(to_jsonb(d.judges))) AS a(services),
                      jsonb_array_elements_text(a.services) AS j(service)
                 ORDER BY 1),
           min(d.first_seen), max(d.last_seen)
    FROM shawk.named_dependencies(baseline_unjudged.since, baseline_unjudged.until, NULL, true, NULL,
                                  ARRAY(SELECT s.service FROM shawk.baseline_services s), baseline_unjudged.members_since,
                                  true) d
    WHERE baseline_unjudged.since < baseline_unjudged.until
    GROUP BY d.client_unit, d.client_service, d.server_name, d.proto
  ) g
  ORDER BY g.client_unit COLLATE "C", g.client_service COLLATE "C", g.server_name COLLATE "C", g.proto COLLATE "C"
  LIMIT greatest(baseline_unjudged.max_rows, 0)
$$;
