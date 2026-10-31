-- Fixes from an adversarial review of the schema.

-- Processes of one unit with the same comm but different service names
-- (OTEL_SERVICE_NAME) are different processes; they were merged and their
-- edges renamed after whichever was written last.
ALTER TABLE shawk.processes DROP CONSTRAINT processes_host_id_unit_comm_key;
ALTER TABLE shawk.processes ADD CONSTRAINT processes_host_id_unit_comm_service_name_key
  UNIQUE (host_id, unit, comm, service_name);

-- unobserved(): since 0004 a session starts by the clock of the agent and
-- its heartbeat is by the clock of the connector; with an agent clock ahead
-- by more than the tolerance the range was inverted and the function
-- failed for every host. The start is converted with the clock skew.
CREATE OR REPLACE FUNCTION shawk_v1.unobserved(since timestamptz, until timestamptz,
                                               tolerance interval DEFAULT '3 minutes')
RETURNS TABLE (host text, gap_start timestamptz, gap_end timestamptz)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
  SELECT h.hostname, lower(g), upper(g)
  FROM shawk.hosts h
  CROSS JOIN LATERAL unnest(
    tstzmultirange(tstzrange(since, until))
    - coalesce((SELECT range_agg(tstzrange(least(s.started_at + s.clock_skew, s.last_heartbeat),
                                           s.last_heartbeat + tolerance))
                FROM shawk.agent_sessions s WHERE s.host_id = h.id),
               '{}'::tstzmultirange)
  ) AS g
  WHERE h.last_seen >= since;
$$;

-- shared_addrs: an address is shared when two hosts held it at the same
-- time for more than 10 minutes. The former rule (periods widened by the
-- alive window) also caught an address reused by another host within 5
-- minutes, for the whole retention, and joined all pairs of holders, which
-- is quadratic in the hosts of a container bridge.
CREATE OR REPLACE VIEW shawk.shared_addrs AS
SELECT DISTINCT a.addr
FROM shawk.host_addrs a
WHERE EXISTS (
  SELECT FROM shawk.host_addrs b
  WHERE b.addr = a.addr AND b.host_id <> a.host_id
    AND least(a.last_seen, b.last_seen) - greatest(a.first_seen, b.first_seen) > interval '10 minutes');

-- service_endpoints:
--   - a listener on an unspecified address is expanded to the current
--     addresses of its host only (those of its latest report), not to
--     addresses it gave up long ago;
--   - server edges are read per host through an index instead of a scan of
--     all edges;
--   - exact tells whether the address was observed on a socket rather than
--     inferred from a listener on an unspecified address; the connector
--     prefers exact endpoints.
CREATE INDEX edges_server_host ON shawk.edges (host_id, last_seen) WHERE role = 'server';

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
-- An address moved away from a host when another host started to hold it
-- after this one last did: the newest first_seen of its holders is later
-- than the last_seen of this host (beyond the alive window; never true for
-- the host itself). One aggregate per address, instead of all pairs of its
-- holders.
newest AS (
  SELECT addr, max(first_seen) AS first_seen FROM shawk.host_addrs GROUP BY addr
),
moved AS (
  SELECT mine.host_id, mine.addr
  FROM shawk.host_addrs mine
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

-- agent_addrs: what the latest session says the agent traces, so that the
-- connector does not count on an agent that traces no UDP, or one network
-- namespace only, to record the other side of an edge.
CREATE OR REPLACE VIEW shawk_v1.agent_addrs AS
SELECT a.addr, h.hostname AS host, a.host_id, a.last_seen, s.udp_traced, s.netns_scope
FROM shawk.host_addrs a
JOIN shawk.hosts h ON h.id = a.host_id
CROSS JOIN LATERAL (
  SELECT s.udp_traced, s.netns_scope FROM shawk.agent_sessions s
  WHERE s.host_id = a.host_id ORDER BY s.last_heartbeat DESC LIMIT 1
) s
WHERE a.last_seen > now() - shawk.alive_window();

-- prune: the outer conditions are repeated, so that a row refreshed by a
-- concurrent write while the delete waited for its lock is kept (the
-- subquery is not evaluated again).
CREATE OR REPLACE FUNCTION shawk.prune(cutoff timestamptz, max_rows integer DEFAULT 10000) RETURNS bigint
LANGUAGE plpgsql AS $$
DECLARE
  n bigint;
  total bigint := 0;
BEGIN
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

-- graph_nodes_between evaluated the dependencies of the period twice.
CREATE OR REPLACE FUNCTION shawk_v1.graph_nodes_between(since timestamptz, until timestamptz)
RETURNS TABLE (id text, title text, subtitle text, mainstat bigint, first_seen timestamptz, last_seen timestamptz)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
WITH d AS MATERIALIZED (
  SELECT * FROM shawk.service_dependencies_between(since, until)
)
SELECT
  n.service,
  n.service,
  coalesce(array_to_string((array_agg(DISTINCT n.host ORDER BY n.host))[1:3], ', '), ''),
  count(DISTINCT n.host),
  min(n.first_seen),
  max(n.last_seen)
FROM (
  SELECT d.client_service AS service, unnest(coalesce(d.client_hosts, '{NULL}'::text[])) AS host, d.first_seen, d.last_seen
  FROM d
  UNION ALL
  SELECT d.server_service, unnest(coalesce(d.server_hosts, '{NULL}'::text[])), d.first_seen, d.last_seen
  FROM d
) n
GROUP BY n.service
$$;
