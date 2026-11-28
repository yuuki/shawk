-- Least-privilege rules and the baseline of the dependencies of services
-- (§6.4 of docs/design.md): what a host, or a unit of it, connected to and
-- accepted connections from in a period, with what the history does not
-- tell of it; the dependencies that an operator approved for a service; and
-- those of a period that are not among them. Everything is computed here,
-- in the contract, so that Grafana, psql, the connector and shawk-policy
-- give the same answer: the command only writes the rules.

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
-- Dependencies over Unix sockets, which have neither a port nor a network,
-- are not part of a baseline.
CREATE TABLE shawk.baseline_dependencies (
  service text NOT NULL REFERENCES shawk.baseline_services ON DELETE CASCADE,
  peer    text NOT NULL CHECK (peer <> ''),
  port    integer NOT NULL CHECK (port BETWEEN 0 AND 65535),
  proto   text NOT NULL CHECK (proto IN ('tcp', 'udp')),
  PRIMARY KEY (service, peer, port, proto)
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
CREATE FUNCTION shawk.named_dependencies(since timestamptz, until timestamptz)
RETURNS TABLE (
  client_host text, client_service text, client_unit text, client_addr inet,
  server_host text, server_service text, server_unit text, server_addr inet,
  port integer, proto text, first_seen timestamptz, last_seen timestamptz, observed_by text,
  virtual_addr inet, virtual_port integer,
  client_name text, server_name text, named_by text, dependency_port integer)
LANGUAGE sql STABLE ROWS 100000 SET search_path = pg_catalog, pg_temp AS $$
WITH d AS MATERIALIZED (
  SELECT row_number() OVER () AS id, x.*
  FROM shawk_v1.dependencies_between(named_dependencies.since, named_dependencies.until) x
  WHERE x.proto <> 'unix'
),
-- The rows whose server no agent saw, of clients with an agent.
u AS (
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
cand AS (
  SELECT u.id, ep.service, ep.slurm_job, 0 AS via, ep.host = u.client_host AS own, ep.exact, ep.last_seen
  FROM u
  JOIN ep ON ep.addr = u.server_addr AND ep.port = u.port AND ep.proto = u.proto
  WHERE ep.host = u.client_host OR NOT u.host_local
  UNION ALL
  SELECT u.id, ep.service, ep.slurm_job, 1, false, ep.exact, ep.last_seen
  FROM u
  JOIN shawk.translations v
    ON v.side = 'virtual' AND v.proto = u.proto AND v.addr = u.server_addr AND v.port IN (0, u.port)
  JOIN shawk.translations b ON b.side = 'backend' AND b.name = v.name AND b.proto = v.proto
  JOIN ep ON ep.proto = u.proto AND ep.addr <<= b.addr AND ep.port = CASE WHEN b.port = 0 THEN u.port ELSE b.port END
),
pick AS (
  SELECT DISTINCT ON (c.id) c.id, c.service, c.slurm_job
  FROM cand c
  ORDER BY c.id, c.via, c.own DESC, c.exact DESC, c.last_seen DESC, c.service
)
SELECT d.client_host, d.client_service, d.client_unit, d.client_addr,
       d.server_host, d.server_service, d.server_unit, d.server_addr,
       d.port, d.proto, d.first_seen, d.last_seen, d.observed_by,
       d.virtual_addr, d.virtual_port,
       coalesce(d.client_service, shawk_v1.peer_class(d.client_addr)),
       n.server_name,
       CASE WHEN d.server_service IS NOT NULL THEN 'edge' WHEN p.id IS NOT NULL THEN 'endpoint' ELSE 'address' END,
       shawk.dependency_port(n.server_name, coalesce(d.server_unit, CASE WHEN p.slurm_job THEN 'slurm/' END),
                             d.server_addr, d.port, d.proto)
FROM d
LEFT JOIN pick p ON p.id = d.id
CROSS JOIN LATERAL (
  SELECT coalesce(d.server_service, p.service, shawk_v1.peer_class(d.server_addr)) AS server_name
) n
$$;

-- How each host of hosts was observed in [since, until] for what a policy
-- or a baseline lists, the connections of TCP and UDP of its processes:
-- covered is the part of the period, from 0 to 1, for which the history
-- tells them all, and shortfalls why it does not, as impact_verdict()
-- names them: unknown_host (no agent ever reported under the name),
-- no_agent (the same for a host of the inventory), not_observed,
-- before_retention, dropped_flows, netns_limited and udp_not_traced.
CREATE FUNCTION shawk.host_shortfalls(since timestamptz, until timestamptz, hosts text[], tolerance interval)
RETURNS TABLE (host text, agent boolean, covered numeric, shortfalls text[],
               unobserved interval, gaps integer, partly_observed interval)
LANGUAGE sql STABLE SET search_path = pg_catalog, pg_temp AS $$
  SELECT o.host, o.agent,
         1 - extract(epoch FROM shawk.duration(m.missing + o.dropped + o.netns_limited + o.udp_untraced))
             / extract(epoch FROM host_shortfalls.until - host_shortfalls.since),
         array_remove(ARRAY[
           CASE WHEN NOT o.agent AND EXISTS (SELECT FROM shawk.inventory_hosts i WHERE i.host = o.host) THEN 'no_agent'
                WHEN NOT o.agent THEN 'unknown_host'
                WHEN NOT isempty(m.missing - o.pruned) THEN 'not_observed' END,
           CASE WHEN o.agent AND NOT isempty(o.pruned) THEN 'before_retention' END,
           CASE WHEN NOT isempty(o.dropped) THEN 'dropped_flows' END,
           CASE WHEN NOT isempty(o.netns_limited) THEN 'netns_limited' END,
           CASE WHEN NOT isempty(o.udp_untraced) THEN 'udp_not_traced' END], NULL),
         shawk.duration(m.missing), (SELECT count(*)::integer FROM unnest(m.missing)), shawk.duration(o.dropped)
  FROM shawk.observation(host_shortfalls.since, host_shortfalls.until, host_shortfalls.hosts, host_shortfalls.tolerance) o
  CROSS JOIN LATERAL (
    SELECT shawk.period(host_shortfalls.since, host_shortfalls.until) - o.observed AS missing
  ) m
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
-- narrows them to the processes of a unit (shawk.unit), with those of the
-- sockets of the host without a known owner (service ~unknown), which may
-- be its own.
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
CREATE FUNCTION shawk_v1.policy_flows(target_host text, since timestamptz, until timestamptz,
                                      target_unit text DEFAULT NULL)
RETURNS TABLE (
  direction text, in_period boolean, service text, unit text, proto text,
  peer_addr inet, port integer, port_from integer, port_to integer,
  peer text, peer_host text, translated boolean, kernel_chosen boolean,
  first_seen timestamptz, last_seen timestamptz)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
WITH e AS MATERIALIZED (
  SELECT e.id, e.host_id, e.process_id, e.role, e.proto, e.local_addr, e.remote_addr, e.port, e.netns,
         e.first_seen, e.last_seen, p.service_name AS service, p.unit,
         e.last_seen >= policy_flows.since AS in_period
  FROM shawk.hosts h
  JOIN shawk.edges e ON e.host_id = h.id
  JOIN shawk.processes p ON p.id = e.process_id
  WHERE h.hostname = policy_flows.target_host
    AND policy_flows.since < policy_flows.until
    AND e.first_seen <= policy_flows.until
    AND (policy_flows.target_unit IS NULL OR p.unit = policy_flows.target_unit OR p.service_name = '~unknown')
),
nd AS MATERIALIZED (
  SELECT d.*
  FROM shawk.named_dependencies(policy_flows.since, policy_flows.until) d
  WHERE (d.client_host = policy_flows.target_host OR d.server_host = policy_flows.target_host)
    AND EXISTS (SELECT FROM e WHERE e.in_period)
),
-- The names of the servers of the client edges, the ports of their
-- dependencies, and whether the kernel chose the port of a server.
eg AS (
  SELECT e.id,
         string_agg(DISTINCT d.server_name, ', ') AS peer,
         string_agg(DISTINCT d.server_host, ', ') AS peer_host,
         bool_or(d.dependency_port = 0) AS any_port,
         bool_or(EXISTS (SELECT FROM shawk.hosts sh
                         JOIN shawk.listener_owners o ON o.host_id = sh.id
                         WHERE sh.hostname = d.server_host AND o.proto = d.proto AND o.port = d.port
                           AND o.kernel_chosen_seen >= policy_flows.since)) AS kernel_chosen
  FROM e
  JOIN nd d
    ON  d.client_host = policy_flows.target_host AND d.proto = e.proto AND d.client_addr = e.local_addr
    AND coalesce(d.virtual_addr, d.server_addr) = e.remote_addr AND coalesce(d.virtual_port, d.port) = e.port
    AND d.client_service = e.service AND d.client_unit = e.unit
  WHERE e.role = 'client' AND e.in_period
  GROUP BY e.id
),
-- The names of the clients of the server edges.
ig AS (
  SELECT e.id,
         string_agg(DISTINCT d.client_name, ', ') AS peer,
         string_agg(DISTINCT d.client_host, ', ') AS peer_host
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
  FROM e
  JOIN shawk.learned_translations l
    ON  l.host_id = e.host_id AND l.proto = e.proto AND l.netns = e.netns AND l.client_addr = e.local_addr
    AND l.virtual_addr = e.remote_addr AND l.virtual_port = e.port
  WHERE e.role = 'client' AND e.in_period
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
ORDER BY 1, 2 DESC, 5, 7, 6, 3, 4, 10
$$;

-- Whether the history tells every flow of policy_flows() over [since,
-- until], one row:
--
--   COMPLETE    an agent of the host observed for min_coverage of the
--               period, all that the flows cover; caveats tell the
--               shortfalls that min_coverage accepted;
--   INCOMPLETE  it did not, or the target is not known: no agent ever
--               reported under the name of the host (unknown_host, or
--               no_agent for a host of the inventory), or no process of
--               the host had the unit in the period (unknown_unit).
--               reasons tell what is missing. Rules made from the flows
--               would deny what was not seen.
--
-- coverage is the part of the period, from 0 to 1 and cut rather than
-- rounded, in which an agent of the host observed (not_observed
-- otherwise), within the retention (before_retention), without dropped
-- flows (dropped_flows), in every network namespace (netns_limited) and
-- with UDP (udp_not_traced). unobserved, gaps and partly_observed are
-- those of coverage() for the host.
--
-- network_namespaces counts the network namespaces of the sockets of the
-- flows in the period: more than one tells a host of containers, whose
-- forwarded connections rules of the host itself do not see. unix_sockets
-- tells whether the target used or served Unix sockets in the period.
CREATE FUNCTION shawk_v1.policy_verdict(target_host text, since timestamptz, until timestamptz,
                                        target_unit text DEFAULT NULL, min_coverage numeric DEFAULT 1,
                                        tolerance interval DEFAULT '3 minutes')
RETURNS TABLE (status text, reasons text[], caveats text[], coverage numeric,
               unobserved interval, gaps integer, partly_observed interval,
               network_namespaces integer, unix_sockets boolean)
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
  o record;
  shortfalls text[];
  unknown boolean := false;
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
  -- A unit that no process of the host had was not seen to connect, which
  -- tells nothing: its name may be misspelt.
  IF o.agent AND target_unit IS NOT NULL AND NOT EXISTS (
       SELECT FROM shawk.hosts h
       JOIN shawk.processes p ON p.host_id = h.id
       WHERE h.hostname = target_host AND p.unit = target_unit
         AND p.last_seen >= since - interval '15 minutes' AND p.first_seen <= until) THEN
    unknown := true;
    shortfalls := shortfalls || 'unknown_unit'::text;
  END IF;

  coverage := trunc(o.covered, 6);
  unobserved := o.unobserved;
  gaps := o.gaps;
  partly_observed := o.partly_observed;
  SELECT count(DISTINCT e.netns)::integer INTO network_namespaces
  FROM shawk.hosts h
  JOIN shawk.edges e ON e.host_id = h.id
  JOIN shawk.processes p ON p.id = e.process_id
  WHERE h.hostname = target_host AND e.last_seen >= since AND e.first_seen <= until
    AND (target_unit IS NULL OR p.unit = target_unit);
  unix_sockets := EXISTS (
      SELECT FROM shawk.hosts h
      JOIN shawk.unix_edges e ON e.host_id = h.id
      JOIN shawk.processes p ON p.id = e.process_id
      WHERE h.hostname = target_host AND e.last_seen >= since AND e.first_seen <= until
        AND (target_unit IS NULL OR p.unit = target_unit))
    OR EXISTS (
      SELECT FROM shawk.hosts h
      JOIN shawk.unix_listeners l ON l.host_id = h.id
      JOIN shawk.processes p ON p.id = l.process_id
      WHERE h.hostname = target_host AND l.last_seen >= since AND l.first_seen <= until
        AND (target_unit IS NULL OR p.unit = target_unit));
  IF NOT o.agent OR unknown OR o.covered < min_coverage THEN
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

-- Baselines ------------------------------------------------------------------

-- The dependencies of services in [since, until] as a baseline lists
-- them: one row per client service, server, port and transport, of the
-- services of `services` (every service if NULL). The client is a process
-- on a host with an agent, by its service name; the server is named as
-- shawk.named_dependencies() names it, and the port is that of the
-- dependencies between services, 0 under the rules of ports (§5.3).
-- Dependencies over Unix sockets are left out.
--
-- hosts are the hosts of the clients, addrs up to 50 of the addresses they
-- connected to (a network for folded peers), and named_by the best
-- evidence of the name of the server among its rows: edge, endpoint or
-- address.
CREATE FUNCTION shawk_v1.baseline_observed(since timestamptz, until timestamptz, services text[] DEFAULT NULL)
RETURNS TABLE (service text, peer text, port integer, proto text,
               first_seen timestamptz, last_seen timestamptz, hosts text[], addrs inet[], named_by text)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
  SELECT d.client_service, d.server_name, d.dependency_port, d.proto,
         min(d.first_seen), max(d.last_seen),
         array_agg(DISTINCT d.client_host ORDER BY d.client_host),
         (array_agg(DISTINCT coalesce(d.virtual_addr, d.server_addr) ORDER BY coalesce(d.virtual_addr, d.server_addr)))[1:50],
         CASE WHEN bool_or(d.named_by = 'edge') THEN 'edge' WHEN bool_or(d.named_by = 'endpoint') THEN 'endpoint'
              ELSE 'address' END
  FROM shawk.named_dependencies(baseline_observed.since, baseline_observed.until) d
  WHERE d.client_host IS NOT NULL
    AND baseline_observed.since < baseline_observed.until
    AND (baseline_observed.services IS NULL OR d.client_service = ANY (baseline_observed.services))
  GROUP BY 1, 2, 3, 4
  ORDER BY 1, 2, 3, 4
$$;

-- Whether the history tells every dependency of each service of
-- `services` over [since, until], one row per service: the verdict of
-- policy_verdict() over every host that ran a process of the service in
-- the period.
--
--   COMPLETE    every such host was observed for min_coverage of the
--               period;
--   INCOMPLETE  one was not (short_hosts lists up to 20 of them, the
--               least observed first), or no process had the service in
--               the period (unknown_service).
--
-- coverage is that of the least observed host. A host that ran the
-- service for a part of the period counts over the whole period: what it
-- did before its agent first reported is not known.
CREATE FUNCTION shawk_v1.baseline_verdict(services text[], since timestamptz, until timestamptz,
                                          min_coverage numeric DEFAULT 1, tolerance interval DEFAULT '3 minutes')
RETURNS TABLE (service text, status text, reasons text[], caveats text[],
               hosts integer, coverage numeric, short_hosts text[])
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
BEGIN
  PERFORM shawk.check_period(since, until, min_coverage, tolerance);
  RETURN QUERY
  WITH asked AS (
    SELECT DISTINCT u.service FROM unnest(services) AS u(service) WHERE u.service IS NOT NULL
  ),
  sh AS MATERIALIZED (
    SELECT DISTINCT p.service_name AS service, h.hostname AS host
    FROM shawk.processes p
    JOIN shawk.hosts h ON h.id = p.host_id
    WHERE p.service_name IN (SELECT a.service FROM asked a)
      AND p.last_seen >= since - interval '15 minutes' AND p.first_seen <= until
  ),
  ob AS MATERIALIZED (
    SELECT * FROM shawk.host_shortfalls(since, until, ARRAY(SELECT DISTINCT sh.host FROM sh), tolerance)
  ),
  per AS (
    SELECT sh.service,
           count(*)::integer AS hosts,
           min(ob.covered) AS covered,
           (array_agg(sh.host ORDER BY ob.covered, sh.host) FILTER (WHERE ob.covered < min_coverage))[1:20] AS short_hosts
    FROM sh
    JOIN ob ON ob.host = sh.host
    GROUP BY sh.service
  ),
  -- The shortfalls of the hosts of each service, and whether one of the
  -- hosts that has it is below min_coverage.
  codes AS (
    SELECT x.service,
           coalesce(array_agg(x.code ORDER BY x.code) FILTER (WHERE x.short), '{}') AS short_codes,
           coalesce(array_agg(x.code ORDER BY x.code) FILTER (WHERE NOT x.short), '{}') AS other_codes
    FROM (
      SELECT sh.service, c.code, bool_or(ob.covered < min_coverage) AS short
      FROM sh
      JOIN ob ON ob.host = sh.host
      CROSS JOIN LATERAL unnest(ob.shortfalls) AS c(code)
      GROUP BY sh.service, c.code
    ) x
    GROUP BY x.service
  )
  SELECT a.service,
         CASE WHEN per.service IS NULL OR per.covered < min_coverage THEN 'INCOMPLETE' ELSE 'COMPLETE' END,
         CASE WHEN per.service IS NULL THEN ARRAY['unknown_service']
              WHEN per.covered < min_coverage THEN coalesce(codes.short_codes, '{}') ELSE '{}'::text[] END,
         CASE WHEN per.service IS NULL THEN '{}'::text[]
              WHEN per.covered < min_coverage THEN coalesce(codes.other_codes, '{}')
              ELSE coalesce(codes.short_codes, '{}') || coalesce(codes.other_codes, '{}') END,
         coalesce(per.hosts, 0),
         trunc(coalesce(per.covered, 0), 6),
         coalesce(per.short_hosts, '{}'::text[])
  FROM asked a
  LEFT JOIN per ON per.service = a.service
  LEFT JOIN codes ON codes.service = a.service
  ORDER BY a.service;
END
$$;

-- The baseline that the connector read: one row per service and approved
-- dependency, and one row without a dependency (peer, port and proto
-- NULL) for a service approved to have none.
CREATE VIEW shawk_v1.baseline AS
SELECT s.service, d.peer, d.port, d.proto
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
-- and has no row: baseline_new_services() lists those that are new.
--
-- A dependency is in the baseline of its service when the baseline has
-- its server and transport with its port, or with port 0, which stands
-- for every port: the port of the dependency between services, or the
-- port of the server itself, so that a rule of ports added or removed
-- after the baseline was approved does not make a drift of what it holds.
CREATE FUNCTION shawk_v1.baseline_drift(since timestamptz, until timestamptz, services text[] DEFAULT NULL)
RETURNS TABLE (service text, peer text, port integer, proto text,
               first_seen timestamptz, last_seen timestamptz, hosts text[], addrs inet[], named_by text)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
  SELECT d.client_service, d.server_name, d.dependency_port, d.proto,
         min(d.first_seen), max(d.last_seen),
         array_agg(DISTINCT d.client_host ORDER BY d.client_host),
         (array_agg(DISTINCT coalesce(d.virtual_addr, d.server_addr) ORDER BY coalesce(d.virtual_addr, d.server_addr)))[1:50],
         CASE WHEN bool_or(d.named_by = 'edge') THEN 'edge' WHEN bool_or(d.named_by = 'endpoint') THEN 'endpoint'
              ELSE 'address' END
  FROM shawk.named_dependencies(baseline_drift.since, baseline_drift.until) d
  WHERE d.client_host IS NOT NULL
    AND baseline_drift.since < baseline_drift.until
    AND EXISTS (SELECT FROM shawk.baseline_services s WHERE s.service = d.client_service)
    AND (baseline_drift.services IS NULL OR d.client_service = ANY (baseline_drift.services))
    AND NOT EXISTS (
      SELECT FROM shawk.baseline_dependencies b
      WHERE b.service = d.client_service AND b.peer = d.server_name AND b.proto = d.proto
        AND b.port IN (0, d.port, d.dependency_port))
  GROUP BY 1, 2, 3, 4
  ORDER BY 1, 2, 3, 4
$$;

-- The services without a baseline that were first seen in [since, until]
-- and opened connections: a new executable, or a process that names
-- itself anew, is a service of its own (§4.1) and is judged by no
-- baseline. first_seen is the earliest time a process of the service was
-- seen on any host, within the retention, and hosts its hosts. The
-- processes of Slurm jobs, which their users name, and the sockets
-- without a known owner are left out.
CREATE FUNCTION shawk_v1.baseline_new_services(since timestamptz, until timestamptz)
RETURNS TABLE (service text, first_seen timestamptz, hosts text[])
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
  SELECT p.service_name, min(p.first_seen), array_agg(DISTINCT h.hostname ORDER BY h.hostname)
  FROM shawk.processes p
  JOIN shawk.hosts h ON h.id = p.host_id
  WHERE p.unit NOT LIKE 'slurm/%' AND p.service_name <> '~unknown'
  GROUP BY p.service_name
  HAVING min(p.first_seen) >= baseline_new_services.since AND min(p.first_seen) <= baseline_new_services.until
     AND NOT EXISTS (SELECT FROM shawk.baseline_services s WHERE s.service = p.service_name)
     AND bool_or(EXISTS (SELECT FROM shawk.edges e WHERE e.process_id = p.id AND e.role = 'client'))
  ORDER BY 1
$$;
