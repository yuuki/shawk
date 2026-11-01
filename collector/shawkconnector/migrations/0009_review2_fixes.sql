-- Fixes from a second adversarial review of the schema.

-- The version of the schema, which a connector that does not migrate checks
-- before it writes. It runs with the rights of its owner: the history of
-- migrations belongs to shawk-migrate.
CREATE FUNCTION shawk.schema_version() RETURNS integer
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
  SELECT coalesce(max(version), 0) FROM shawk.schema_migrations
$$;

-- host_addrs keeps one row per period a host held an address in, rather
-- than one row from the first to the last time: an address that moved to
-- another host and came back (a VIP that failed over and back, a reused
-- pod or DHCP address) was taken as held by both hosts at once for the
-- whole retention, and as never moved. The connector starts a new period
-- when an address was not seen for longer than the alive window.
ALTER TABLE shawk.host_addrs DROP CONSTRAINT host_addrs_pkey;
ALTER TABLE shawk.host_addrs ADD PRIMARY KEY (host_id, addr, first_seen);

-- service_endpoints: an address moved away from a host when another host
-- started a period of it after the latest period of this host ended.
CREATE OR REPLACE VIEW shawk_v1.service_endpoints AS
WITH latest AS (
  SELECT host_id, max(last_seen) AS last_seen FROM shawk.listeners GROUP BY host_id
),
current_addrs AS (
  SELECT a.host_id, a.addr, a.last_seen
  FROM shawk.host_addrs a
  JOIN (SELECT host_id, max(last_seen) AS last_seen FROM shawk.host_addrs GROUP BY host_id) m
    ON m.host_id = a.host_id
  WHERE a.last_seen >= m.last_seen - shawk.alive_window()
),
s AS (
  SELECT l.addr, l.port, l.proto, l.host_id, p.service_name AS service, l.last_seen, true AS exact
  FROM shawk.listeners l
  JOIN shawk.processes p ON p.id = l.process_id
  JOIN latest ON latest.host_id = l.host_id
  WHERE l.addr NOT IN (inet '0.0.0.0', inet '::')
    AND l.last_seen >= latest.last_seen - interval '1 hour'
  UNION ALL
  SELECT a.addr, l.port, l.proto, l.host_id, p.service_name, l.last_seen, false
  FROM shawk.listeners l
  JOIN shawk.processes p ON p.id = l.process_id
  JOIN latest ON latest.host_id = l.host_id
  JOIN current_addrs a ON a.host_id = l.host_id
   AND (l.addr = inet '::' OR family(a.addr) = 4)
  WHERE l.addr IN (inet '0.0.0.0', inet '::')
    AND l.last_seen >= latest.last_seen - interval '1 hour'
  UNION ALL
  SELECT e.local_addr, e.port, e.proto, e.host_id, p.service_name, e.last_seen, true
  FROM latest
  CROSS JOIN LATERAL (
    SELECT DISTINCT ON (e.local_addr, e.port, e.proto, e.process_id) e.*
    FROM shawk.edges e
    WHERE e.role = 'server' AND e.host_id = latest.host_id
      AND e.last_seen >= latest.last_seen - interval '7 days'
    ORDER BY e.local_addr, e.port, e.proto, e.process_id, e.last_seen DESC
  ) e
  JOIN shawk.processes p ON p.id = e.process_id
),
newest AS (
  SELECT addr, max(first_seen) AS first_seen FROM shawk.host_addrs GROUP BY addr
),
moved AS (
  SELECT mine.host_id, mine.addr
  FROM (SELECT host_id, addr, max(last_seen) AS last_seen FROM shawk.host_addrs GROUP BY host_id, addr) mine
  JOIN newest ON newest.addr = mine.addr
  WHERE newest.first_seen > mine.last_seen + shawk.alive_window()
    AND NOT (mine.addr << inet '127.0.0.0/8' OR mine.addr = inet '::1')
)
SELECT s.addr, s.port, s.proto, h.hostname AS host, s.host_id, s.service, max(s.last_seen) AS last_seen,
       bool_or(s.exact) AS exact
FROM s
JOIN shawk.hosts h ON h.id = s.host_id
LEFT JOIN moved ON moved.host_id = s.host_id AND moved.addr = s.addr
WHERE h.last_seen > now() - interval '30 days'
  AND moved.host_id IS NULL
GROUP BY s.addr, s.port, s.proto, h.hostname, s.host_id, s.service;

-- agent_addrs: an agent is alive by its heartbeat, which the connector
-- writes only from the request that closes an interval. last_heartbeat is
-- added for the connector, which judges the agent by it and the address by
-- last_seen.
CREATE OR REPLACE VIEW shawk_v1.agent_addrs AS
SELECT a.addr, h.hostname AS host, a.host_id, a.last_seen, s.udp_traced, s.netns_scope, s.last_heartbeat
FROM shawk.host_addrs a
JOIN shawk.hosts h ON h.id = a.host_id
CROSS JOIN LATERAL (
  SELECT s.udp_traced, s.netns_scope, s.last_heartbeat FROM shawk.agent_sessions s
  WHERE s.host_id = a.host_id ORDER BY s.last_heartbeat DESC LIMIT 1
) s
WHERE a.last_seen > now() - shawk.alive_window()
  AND s.last_heartbeat > now() - shawk.alive_window();

-- Named address ranges of peers, written by the connector from its
-- peer_cidrs, so that PostgreSQL names a peer without a known service like
-- the connector names it in service.peer.name.
CREATE TABLE shawk.peer_cidrs (
  prefix cidr PRIMARY KEY,
  name   text NOT NULL
);

-- The name of a peer without a known service: the narrowest range of
-- peer_cidrs that holds it, ~unresolved for an address not routed on the
-- Internet, ~external otherwise. Prometheus has the same names in
-- service.peer.name (except ~other, which folds peers beyond max_peers).
CREATE FUNCTION shawk_v1.peer_class(addr inet) RETURNS text
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
  SELECT coalesce(
    (SELECT c.name FROM shawk.peer_cidrs c WHERE addr <<= c.prefix
     ORDER BY masklen(c.prefix) DESC, c.prefix LIMIT 1),
    CASE WHEN addr <<= inet '10.0.0.0/8' OR addr <<= inet '172.16.0.0/12' OR addr <<= inet '192.168.0.0/16'
           OR addr <<= inet '127.0.0.0/8' OR addr <<= inet '169.254.0.0/16' OR addr <<= inet '100.64.0.0/10'
           OR addr <<= inet 'fc00::/7' OR addr <<= inet 'fe80::/10' OR addr = inet '::1'
           OR addr = inet '0.0.0.0' OR addr = inet '::'
         THEN '~unresolved' ELSE '~external' END)
$$;

-- dependencies_between: edges were filtered by period before the client and
-- server sides were matched. The sides of one connection are reported by
-- different agents at different times, so at the edges of the period one
-- side could be left out, and the other came out alone, named after its
-- address. Edges are now taken with a margin of 15 minutes, matched, and
-- the matched rows filtered by the period.
CREATE OR REPLACE FUNCTION shawk_v1.dependencies_between(since timestamptz, until timestamptz)
RETURNS TABLE (
  client_host text, client_service text, client_unit text, client_addr inet,
  server_host text, server_service text, server_unit text, server_addr inet,
  port integer, proto text, first_seen timestamptz, last_seen timestamptz,
  observed_by text, client_observed_until timestamptz, server_observed_until timestamptz)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
WITH shared AS (SELECT addr FROM shawk.shared_addrs),
e AS (
  SELECT e.*, p.service_name, p.unit, h.hostname,
         CASE WHEN e.remote_addr << inet '127.0.0.0/8' OR e.remote_addr = inet '::1'
                THEN e.host_id || '/' || e.netns::text
              WHEN e.local_addr IN (SELECT addr FROM shared) OR e.remote_addr IN (SELECT addr FROM shared)
                THEN e.host_id
              ELSE '' END AS scope
  FROM shawk.edges e
  JOIN shawk.processes p ON p.id = e.process_id
  JOIN shawk.hosts h ON h.id = e.host_id
  WHERE e.last_seen >= since - interval '15 minutes' AND e.first_seen <= until + interval '15 minutes'
),
observed AS (
  SELECT host_id, max(last_heartbeat) AS observed_until
  FROM shawk.agent_sessions GROUP BY host_id
),
d AS (
  SELECT
    c.hostname AS client_host, c.service_name AS client_service, c.unit AS client_unit,
    coalesce(c.local_addr, s.remote_addr) AS client_addr,
    s.hostname AS server_host, s.service_name AS server_service, s.unit AS server_unit,
    coalesce(c.remote_addr, s.local_addr) AS server_addr,
    coalesce(c.port, s.port) AS port, coalesce(c.proto, s.proto) AS proto,
    least(c.first_seen, s.first_seen) AS first_seen, greatest(c.last_seen, s.last_seen) AS last_seen,
    CASE WHEN c.id IS NOT NULL AND s.id IS NOT NULL THEN 'both'
         WHEN c.id IS NOT NULL THEN 'client'
         ELSE 'server' END AS observed_by,
    co.observed_until AS client_observed_until, so.observed_until AS server_observed_until
  FROM (SELECT * FROM e WHERE role = 'client') c
  FULL JOIN (SELECT * FROM e WHERE role = 'server') s
    ON  c.local_addr = s.remote_addr
    AND c.remote_addr = s.local_addr
    AND c.port = s.port
    AND c.proto = s.proto
    AND c.scope = s.scope
  LEFT JOIN observed co ON co.host_id = c.host_id
  LEFT JOIN observed so ON so.host_id = s.host_id
)
SELECT * FROM d WHERE d.last_seen >= since AND d.first_seen <= until
$$;

-- Dependencies between services: a peer without a known service is named
-- by peer_class, like in Prometheus, rather than by its address, so that a
-- service that talks to rotating addresses (a cloud API, the clients of a
-- public server) is one dependency rather than one per address.
CREATE OR REPLACE VIEW shawk.service_dependencies AS
SELECT
  coalesce(client_service, shawk_v1.peer_class(client_addr)) AS client_service,
  coalesce(server_service, shawk_v1.peer_class(server_addr)) AS server_service,
  port,
  proto,
  min(first_seen)                             AS first_seen,
  max(last_seen)                              AS last_seen,
  max(client_observed_until)                  AS client_observed_until,
  max(server_observed_until)                  AS server_observed_until,
  array_agg(DISTINCT client_host) FILTER (WHERE client_host IS NOT NULL) AS client_hosts,
  array_agg(DISTINCT server_host) FILTER (WHERE server_host IS NOT NULL) AS server_hosts
FROM shawk_v1.dependencies
GROUP BY 1, 2, 3, 4;

CREATE OR REPLACE FUNCTION shawk.service_dependencies_between(since timestamptz, until timestamptz)
RETURNS TABLE (
  client_service text, server_service text, port integer, proto text,
  first_seen timestamptz, last_seen timestamptz,
  client_observed_until timestamptz, server_observed_until timestamptz,
  client_hosts text[], server_hosts text[])
LANGUAGE sql STABLE SET search_path = pg_catalog, pg_temp AS $$
SELECT
  coalesce(d.client_service, shawk_v1.peer_class(d.client_addr)),
  coalesce(d.server_service, shawk_v1.peer_class(d.server_addr)),
  d.port, d.proto,
  min(d.first_seen), max(d.last_seen),
  max(d.client_observed_until), max(d.server_observed_until),
  array_agg(DISTINCT d.client_host) FILTER (WHERE d.client_host IS NOT NULL),
  array_agg(DISTINCT d.server_host) FILTER (WHERE d.server_host IS NOT NULL)
FROM shawk_v1.dependencies_between(since, until) d
GROUP BY 1, 2, 3, 4
$$;

-- The dependencies between services ever seen, with when they were first
-- and last seen. A dependency is new when it was never seen before, not
-- when it comes back on new edges (a new container, an hourly job): edges
-- are kept per process, address and network namespace, and a dependency
-- idle for a while comes back on edges first seen then. The connector
-- brings the table up to date every few minutes.
CREATE TABLE shawk.known_dependencies (
  client_service text NOT NULL,
  server_service text NOT NULL,
  port           integer NOT NULL,
  proto          text NOT NULL,
  first_seen     timestamptz NOT NULL,
  last_seen      timestamptz NOT NULL,
  PRIMARY KEY (client_service, server_service, port, proto)
);
CREATE INDEX known_dependencies_last_seen ON shawk.known_dependencies (last_seen);

CREATE TABLE shawk.known_dependencies_state (
  id              boolean PRIMARY KEY DEFAULT true CHECK (id),
  refreshed_until timestamptz NOT NULL
);

-- Adds the dependencies active since the last refresh to
-- known_dependencies, with a margin of an hour for edges written late: by
-- an agent whose clock is behind, or after the database was down (the
-- refresh fails meanwhile, so the next one covers the outage). One
-- connector at a time refreshes, at most once per min_interval; it returns
-- the rows upserted.
CREATE FUNCTION shawk.refresh_known_dependencies(min_interval interval DEFAULT '4 minutes') RETURNS bigint
LANGUAGE plpgsql SET search_path = pg_catalog, pg_temp AS $$
DECLARE
  w timestamptz;
  t timestamptz := now();
  n bigint;
BEGIN
  IF NOT pg_try_advisory_xact_lock(1936220536) THEN  -- 0x73686178
    RETURN 0;
  END IF;
  SELECT refreshed_until INTO w FROM shawk.known_dependencies_state;
  IF w IS NOT NULL AND w > t - min_interval THEN
    RETURN 0;
  END IF;
  INSERT INTO shawk.known_dependencies AS k (client_service, server_service, port, proto, first_seen, last_seen)
  SELECT d.client_service, d.server_service, d.port, d.proto, d.first_seen, d.last_seen
  FROM shawk.service_dependencies_between(coalesce(w - interval '1 hour', '-infinity'), t) d
  ON CONFLICT (client_service, server_service, port, proto) DO UPDATE SET
    first_seen = least(k.first_seen, excluded.first_seen),
    last_seen  = greatest(k.last_seen, excluded.last_seen);
  GET DIAGNOSTICS n = ROW_COUNT;
  INSERT INTO shawk.known_dependencies_state (refreshed_until) VALUES (t)
  ON CONFLICT (id) DO UPDATE SET refreshed_until = excluded.refreshed_until;
  RETURN n;
END
$$;

-- dependency_changes_between: a dependency appeared when it was first seen
-- in the period and was not known before it; the dependencies of the
-- period are evaluated once.
CREATE OR REPLACE FUNCTION shawk_v1.dependency_changes_between(since timestamptz, until timestamptz)
RETURNS TABLE ("time" timestamptz, change text, client_service text, server_service text, port integer, proto text)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
WITH d AS MATERIALIZED (
  SELECT * FROM shawk.service_dependencies_between(since, until)
)
SELECT d.first_seen, 'appeared', d.client_service, d.server_service, d.port, d.proto
FROM d
WHERE d.first_seen BETWEEN since AND until
  AND NOT EXISTS (
    SELECT FROM shawk.known_dependencies k
    WHERE k.client_service = d.client_service AND k.server_service = d.server_service
      AND k.port = d.port AND k.proto = d.proto AND k.first_seen < since)
UNION ALL
SELECT d.last_seen, 'disappeared', d.client_service, d.server_service, d.port, d.proto
FROM d
WHERE d.last_seen BETWEEN since AND until
  AND greatest(d.client_observed_until, d.server_observed_until) > d.last_seen + interval '15 minutes'
$$;

-- prune: it waits for a migration in progress, which holds the advisory
-- lock of migrations, rather than taking the locks of tables in another
-- order and deadlocking with it; and it deletes known dependencies too.
CREATE OR REPLACE FUNCTION shawk.prune(cutoff timestamptz, max_rows integer DEFAULT 10000) RETURNS bigint
LANGUAGE plpgsql AS $$
DECLARE
  n bigint;
  total bigint := 0;
BEGIN
  PERFORM pg_advisory_xact_lock_shared(1936220535);  -- 0x73686177, see Migrate

  DELETE FROM shawk.edges WHERE last_seen < cutoff AND id IN (
    SELECT id FROM shawk.edges WHERE last_seen < cutoff LIMIT max_rows);
  GET DIAGNOSTICS n = ROW_COUNT; total := total + n;

  DELETE FROM shawk.listeners WHERE last_seen < cutoff AND ctid IN (
    SELECT ctid FROM shawk.listeners WHERE last_seen < cutoff LIMIT max_rows);
  GET DIAGNOSTICS n = ROW_COUNT; total := total + n;

  DELETE FROM shawk.host_addrs WHERE last_seen < cutoff AND ctid IN (
    SELECT ctid FROM shawk.host_addrs WHERE last_seen < cutoff LIMIT max_rows);
  GET DIAGNOSTICS n = ROW_COUNT; total := total + n;

  DELETE FROM shawk.agent_sessions WHERE last_heartbeat < cutoff AND ctid IN (
    SELECT ctid FROM shawk.agent_sessions WHERE last_heartbeat < cutoff LIMIT max_rows);
  GET DIAGNOSTICS n = ROW_COUNT; total := total + n;

  DELETE FROM shawk.known_dependencies WHERE last_seen < cutoff AND ctid IN (
    SELECT ctid FROM shawk.known_dependencies WHERE last_seen < cutoff LIMIT max_rows);
  GET DIAGNOSTICS n = ROW_COUNT; total := total + n;

  DELETE FROM shawk.processes p WHERE p.last_seen < cutoff
    AND NOT EXISTS (SELECT FROM shawk.edges e WHERE e.process_id = p.id)
    AND NOT EXISTS (SELECT FROM shawk.listeners l WHERE l.process_id = p.id)
    AND p.id IN (
      SELECT p2.id FROM shawk.processes p2
      WHERE p2.last_seen < cutoff
        AND NOT EXISTS (SELECT FROM shawk.edges e WHERE e.process_id = p2.id)
        AND NOT EXISTS (SELECT FROM shawk.listeners l WHERE l.process_id = p2.id)
      LIMIT max_rows);
  GET DIAGNOSTICS n = ROW_COUNT; total := total + n;

  DELETE FROM shawk.hosts h WHERE h.last_seen < cutoff
    AND NOT EXISTS (SELECT FROM shawk.agent_sessions s WHERE s.host_id = h.id)
    AND NOT EXISTS (SELECT FROM shawk.host_addrs a WHERE a.host_id = h.id)
    AND NOT EXISTS (SELECT FROM shawk.processes p WHERE p.host_id = h.id)
    AND NOT EXISTS (SELECT FROM shawk.edges e WHERE e.host_id = h.id)
    AND NOT EXISTS (SELECT FROM shawk.listeners l WHERE l.host_id = h.id)
    AND h.id IN (SELECT h2.id FROM shawk.hosts h2 WHERE h2.last_seen < cutoff LIMIT max_rows);
  GET DIAGNOSTICS n = ROW_COUNT; total := total + n;

  RETURN total;
END
$$;

-- The dependencies seen so far are known.
SELECT shawk.refresh_known_dependencies();
