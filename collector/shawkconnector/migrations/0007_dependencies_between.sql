-- Functions that filter edges by period before matching them, so that
-- dashboards and alerts over a recent window do not match the edges of the
-- whole history like the views do. They return what the views
-- dependencies, graph_edges and graph_nodes return for the dependencies
-- active in [since, until]. They run with the rights of their owner, so
-- that readers need no access to the tables.

CREATE FUNCTION shawk_v1.dependencies_between(since timestamptz, until timestamptz)
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
  WHERE e.last_seen >= since AND e.first_seen <= until
),
observed AS (
  SELECT host_id, max(last_heartbeat) AS observed_until
  FROM shawk.agent_sessions GROUP BY host_id
)
SELECT
  c.hostname, c.service_name, c.unit, coalesce(c.local_addr, s.remote_addr),
  s.hostname, s.service_name, s.unit, coalesce(c.remote_addr, s.local_addr),
  coalesce(c.port, s.port), coalesce(c.proto, s.proto),
  least(c.first_seen, s.first_seen), greatest(c.last_seen, s.last_seen),
  CASE WHEN c.id IS NOT NULL AND s.id IS NOT NULL THEN 'both'
       WHEN c.id IS NOT NULL THEN 'client'
       ELSE 'server' END,
  co.observed_until, so.observed_until
FROM (SELECT * FROM e WHERE role = 'client') c
FULL JOIN (SELECT * FROM e WHERE role = 'server') s
  ON  c.local_addr = s.remote_addr
  AND c.remote_addr = s.local_addr
  AND c.port = s.port
  AND c.proto = s.proto
  AND c.scope = s.scope
LEFT JOIN observed co ON co.host_id = c.host_id
LEFT JOIN observed so ON so.host_id = s.host_id
$$;

-- Dependencies between services in [since, until], like
-- shawk.service_dependencies. Internal: called by the functions below,
-- with the rights of their owner.
CREATE FUNCTION shawk.service_dependencies_between(since timestamptz, until timestamptz)
RETURNS TABLE (
  client_service text, server_service text, port integer, proto text,
  first_seen timestamptz, last_seen timestamptz,
  client_observed_until timestamptz, server_observed_until timestamptz,
  client_hosts text[], server_hosts text[])
LANGUAGE sql STABLE SET search_path = pg_catalog, pg_temp AS $$
SELECT
  coalesce(d.client_service, host(d.client_addr)),
  coalesce(d.server_service, host(d.server_addr)),
  d.port, d.proto,
  min(d.first_seen), max(d.last_seen),
  max(d.client_observed_until), max(d.server_observed_until),
  array_agg(DISTINCT d.client_host) FILTER (WHERE d.client_host IS NOT NULL),
  array_agg(DISTINCT d.server_host) FILTER (WHERE d.server_host IS NOT NULL)
FROM shawk_v1.dependencies_between(since, until) d
GROUP BY 1, 2, 3, 4
$$;

CREATE FUNCTION shawk_v1.graph_edges_between(since timestamptz, until timestamptz)
RETURNS TABLE (id text, source text, target text, mainstat text, first_seen timestamptz, last_seen timestamptz)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
SELECT
  d.client_service || ' -> ' || d.server_service,
  d.client_service,
  d.server_service,
  string_agg(d.port::text || '/' || d.proto, ', ' ORDER BY d.port, d.proto),
  min(d.first_seen),
  max(d.last_seen)
FROM shawk.service_dependencies_between(since, until) d
GROUP BY d.client_service, d.server_service
$$;

CREATE FUNCTION shawk_v1.graph_nodes_between(since timestamptz, until timestamptz)
RETURNS TABLE (id text, title text, subtitle text, mainstat bigint, first_seen timestamptz, last_seen timestamptz)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
SELECT
  n.service,
  n.service,
  coalesce(array_to_string((array_agg(DISTINCT n.host ORDER BY n.host))[1:3], ', '), ''),
  count(DISTINCT n.host),
  min(n.first_seen),
  max(n.last_seen)
FROM (
  SELECT d.client_service AS service, unnest(coalesce(d.client_hosts, '{NULL}'::text[])) AS host, d.first_seen, d.last_seen
  FROM shawk.service_dependencies_between(since, until) d
  UNION ALL
  SELECT d.server_service, unnest(coalesce(d.server_hosts, '{NULL}'::text[])), d.first_seen, d.last_seen
  FROM shawk.service_dependencies_between(since, until) d
) n
GROUP BY n.service
$$;

-- Dependencies between services that appeared (first seen) or disappeared
-- (last seen while a host that saw them kept observing for 15 minutes) in
-- [since, until], considering the edges active in that period.
CREATE FUNCTION shawk_v1.dependency_changes_between(since timestamptz, until timestamptz)
RETURNS TABLE ("time" timestamptz, change text, client_service text, server_service text, port integer, proto text)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
SELECT d.first_seen, 'appeared', d.client_service, d.server_service, d.port, d.proto
FROM shawk.service_dependencies_between(since, until) d
WHERE d.first_seen BETWEEN since AND until
UNION ALL
SELECT d.last_seen, 'disappeared', d.client_service, d.server_service, d.port, d.proto
FROM shawk.service_dependencies_between(since, until) d
WHERE d.last_seen BETWEEN since AND until
  AND greatest(d.client_observed_until, d.server_observed_until) > d.last_seen + interval '15 minutes'
$$;
