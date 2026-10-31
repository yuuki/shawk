-- shawk schema version 1.
--
-- The tables in the schema shawk are internal; only the shawk connector
-- writes them. The views and functions in the schema shawk_v1 are the
-- contract for dashboards, alerts and other readers.
-- Requires PostgreSQL 14 or later (multiranges and the CYCLE clause).

CREATE SCHEMA IF NOT EXISTS shawk;
CREATE SCHEMA IF NOT EXISTS shawk_v1;

CREATE TABLE shawk.hosts (
  id            text PRIMARY KEY,          -- hash of the machine id and the host name
  machine_id    text NOT NULL,             -- host.id; matches the data of OBI
  hostname      text NOT NULL,
  kernel        text NOT NULL,
  agent_version text NOT NULL,
  first_seen    timestamptz NOT NULL,
  last_seen     timestamptz NOT NULL
);

-- Periods in which an agent observed its host. An agent starts a new
-- session when it starts, or when it could not send for longer than its
-- idle TTL.
CREATE TABLE shawk.agent_sessions (
  host_id        text NOT NULL REFERENCES shawk.hosts,
  started_at     timestamptz NOT NULL,     -- shawk.agent.segment.start
  last_heartbeat timestamptz NOT NULL,     -- observations up to here are written
  udp_traced     boolean NOT NULL,
  netns_scope    text NOT NULL,            -- 'all' or the inode of the traced netns
  dropped_flows  bigint NOT NULL DEFAULT 0,
  PRIMARY KEY (host_id, started_at)
);
CREATE INDEX agent_sessions_heartbeat ON shawk.agent_sessions (host_id, last_heartbeat);

CREATE TABLE shawk.host_addrs (
  host_id    text NOT NULL REFERENCES shawk.hosts,
  addr       inet NOT NULL,
  first_seen timestamptz NOT NULL,
  last_seen  timestamptz NOT NULL,
  PRIMARY KEY (host_id, addr)
);
CREATE INDEX host_addrs_addr ON shawk.host_addrs (addr, last_seen);

CREATE TABLE shawk.processes (
  id           bigserial PRIMARY KEY,
  host_id      text NOT NULL REFERENCES shawk.hosts,
  unit         text NOT NULL,
  comm         text NOT NULL,
  exe          text NOT NULL DEFAULT '',
  service_name text NOT NULL,              -- as the job label: [namespace/]name
  first_seen   timestamptz NOT NULL,
  last_seen    timestamptz NOT NULL,
  UNIQUE (host_id, unit, comm)
);

-- A dependency observed on a host: a bundled flow between a local process
-- and a remote address. port is the service port.
CREATE TABLE shawk.edges (
  id          bigserial PRIMARY KEY,
  host_id     text NOT NULL REFERENCES shawk.hosts,
  process_id  bigint NOT NULL REFERENCES shawk.processes,
  role        text NOT NULL CHECK (role IN ('client', 'server')),
  proto       text NOT NULL CHECK (proto IN ('tcp', 'udp')),
  local_addr  inet NOT NULL,
  remote_addr inet NOT NULL,
  port        integer NOT NULL,
  netns       bigint NOT NULL,
  first_seen  timestamptz NOT NULL,
  last_seen   timestamptz NOT NULL,
  UNIQUE (host_id, role, proto, local_addr, remote_addr, port, netns, process_id)
);
CREATE INDEX edges_client ON shawk.edges (proto, remote_addr, port) WHERE role = 'client';
CREATE INDEX edges_server ON shawk.edges (proto, local_addr, port) WHERE role = 'server';
CREATE INDEX edges_last_seen ON shawk.edges (last_seen);
CREATE INDEX edges_first_seen ON shawk.edges (first_seen);

CREATE TABLE shawk.listeners (
  host_id    text NOT NULL REFERENCES shawk.hosts,
  process_id bigint REFERENCES shawk.processes,  -- NULL if the owner is unknown
  proto      text NOT NULL,
  addr       inet NOT NULL,
  port       integer NOT NULL,
  netns      bigint NOT NULL,
  first_seen timestamptz NOT NULL,
  last_seen  timestamptz NOT NULL,
  PRIMARY KEY (host_id, proto, addr, port, netns)
);

-- How long an agent can be silent and still be alive: a few write
-- intervals of the connector.
CREATE FUNCTION shawk.alive_window() RETURNS interval
LANGUAGE sql IMMUTABLE AS $$ SELECT interval '5 minutes' $$;

-- Loopback addresses are only meaningful within a host and a network
-- namespace; scope tells them apart when edges are matched.
CREATE FUNCTION shawk.addr_scope(addr inet, host_id text, netns bigint) RETURNS text
LANGUAGE sql IMMUTABLE AS $$
  SELECT CASE WHEN addr << inet '127.0.0.0/8' OR addr = inet '::1'
              THEN host_id || '/' || netns::text ELSE '' END
$$;

-- The latest session of every host.
CREATE VIEW shawk_v1.agents AS
SELECT DISTINCT ON (h.id)
  h.hostname        AS host,
  h.id              AS host_id,
  h.machine_id,
  h.kernel,
  h.agent_version,
  s.started_at,
  s.last_heartbeat,
  s.udp_traced,
  s.netns_scope,
  s.dropped_flows,
  s.last_heartbeat > now() - shawk.alive_window() AS alive
FROM shawk.hosts h
JOIN shawk.agent_sessions s ON s.host_id = h.id
ORDER BY h.id, s.last_heartbeat DESC;

-- Dependencies: the client and server edges of a connection matched by
-- their addresses and port into one row. A dependency seen on one side
-- only has no agent on the other side, or a NAT or load balancer between.
CREATE VIEW shawk_v1.dependencies AS
WITH e AS (
  SELECT e.*, p.service_name, p.unit, h.hostname,
         shawk.addr_scope(e.remote_addr, e.host_id, e.netns) AS scope
  FROM shawk.edges e
  JOIN shawk.processes p ON p.id = e.process_id
  JOIN shawk.hosts h ON h.id = e.host_id
),
observed AS (
  SELECT host_id, max(last_heartbeat) AS observed_until
  FROM shawk.agent_sessions GROUP BY host_id
)
SELECT
  c.hostname                                    AS client_host,
  c.service_name                                AS client_service,
  c.unit                                        AS client_unit,
  coalesce(c.local_addr, s.remote_addr)         AS client_addr,
  s.hostname                                    AS server_host,
  s.service_name                                AS server_service,
  s.unit                                        AS server_unit,
  coalesce(c.remote_addr, s.local_addr)         AS server_addr,
  coalesce(c.port, s.port)                      AS port,
  coalesce(c.proto, s.proto)                    AS proto,
  least(c.first_seen, s.first_seen)             AS first_seen,
  greatest(c.last_seen, s.last_seen)            AS last_seen,
  CASE WHEN c.id IS NOT NULL AND s.id IS NOT NULL THEN 'both'
       WHEN c.id IS NOT NULL THEN 'client'
       ELSE 'server' END                        AS observed_by,
  co.observed_until                             AS client_observed_until,
  so.observed_until                             AS server_observed_until
FROM (SELECT * FROM e WHERE role = 'client') c
FULL JOIN (SELECT * FROM e WHERE role = 'server') s
  ON  c.local_addr = s.remote_addr
  AND c.remote_addr = s.local_addr
  AND c.port = s.port
  AND c.proto = s.proto
  AND c.scope = s.scope
LEFT JOIN observed co ON co.host_id = c.host_id
LEFT JOIN observed so ON so.host_id = s.host_id;

-- Dependencies between services, with the address standing in for a peer
-- without a known service.
CREATE VIEW shawk.service_dependencies AS
SELECT
  coalesce(client_service, host(client_addr)) AS client_service,
  coalesce(server_service, host(server_addr)) AS server_service,
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

-- Edges of the dependency map in the format of the Grafana Node Graph.
CREATE VIEW shawk_v1.graph_edges AS
SELECT
  client_service || ' -> ' || server_service  AS id,
  client_service                              AS source,
  server_service                              AS target,
  string_agg(port::text || '/' || proto, ', ' ORDER BY port, proto) AS mainstat,
  min(first_seen)                             AS first_seen,
  max(last_seen)                              AS last_seen
FROM shawk.service_dependencies
GROUP BY client_service, server_service;

-- Nodes of the dependency map: the services and their hosts.
CREATE VIEW shawk_v1.graph_nodes AS
SELECT
  service                                     AS id,
  service                                     AS title,
  coalesce(array_to_string((array_agg(DISTINCT host ORDER BY host))[1:3], ', '), '') AS subtitle,
  count(DISTINCT host)                        AS mainstat,
  min(first_seen)                             AS first_seen,
  max(last_seen)                              AS last_seen
FROM (
  SELECT client_service AS service, unnest(coalesce(client_hosts, '{NULL}'::text[])) AS host, first_seen, last_seen
  FROM shawk.service_dependencies
  UNION ALL
  SELECT server_service, unnest(coalesce(server_hosts, '{NULL}'::text[])), first_seen, last_seen
  FROM shawk.service_dependencies
) n
GROUP BY service;

-- Dependencies between services that appeared or disappeared. A
-- dependency disappeared when a host that saw it kept observing for 15
-- minutes after its last activity.
CREATE VIEW shawk_v1.dependency_changes AS
SELECT first_seen AS time, 'appeared' AS change, client_service, server_service, port, proto
FROM shawk.service_dependencies
UNION ALL
SELECT last_seen, 'disappeared', client_service, server_service, port, proto
FROM shawk.service_dependencies
WHERE greatest(client_observed_until, server_observed_until) > last_seen + interval '15 minutes';

-- Addresses and ports services accept connections on, used by the shawk
-- connector to name the peers of client edges. A listener on an
-- unspecified address listens on every address of its host.
CREATE VIEW shawk_v1.service_endpoints AS
SELECT addr, port, proto, host, host_id, service, max(last_seen) AS last_seen
FROM (
  SELECT l.addr, l.port, l.proto, h.hostname AS host, l.host_id, p.service_name AS service, l.last_seen
  FROM shawk.listeners l
  JOIN shawk.processes p ON p.id = l.process_id
  JOIN shawk.hosts h ON h.id = l.host_id
  WHERE l.addr NOT IN (inet '0.0.0.0', inet '::')
  UNION ALL
  SELECT a.addr, l.port, l.proto, h.hostname, l.host_id, p.service_name, least(l.last_seen, a.last_seen)
  FROM shawk.listeners l
  JOIN shawk.processes p ON p.id = l.process_id
  JOIN shawk.hosts h ON h.id = l.host_id
  JOIN shawk.host_addrs a ON a.host_id = l.host_id
   AND (l.addr = inet '::' OR family(a.addr) = 4)
  WHERE l.addr IN (inet '0.0.0.0', inet '::')
  UNION ALL
  SELECT e.local_addr, e.port, e.proto, h.hostname, e.host_id, p.service_name, e.last_seen
  FROM shawk.edges e
  JOIN shawk.processes p ON p.id = e.process_id
  JOIN shawk.hosts h ON h.id = e.host_id
  WHERE e.role = 'server'
) s
WHERE last_seen > now() - interval '7 days'
GROUP BY addr, port, proto, host, host_id, service;

-- Addresses of hosts whose agent is alive, used by the shawk connector to
-- mark the server side of edges whose client side has its own agent.
CREATE VIEW shawk_v1.agent_addrs AS
SELECT a.addr, h.hostname AS host, a.host_id, a.last_seen
FROM shawk.host_addrs a
JOIN shawk.hosts h ON h.id = a.host_id
WHERE a.last_seen > now() - shawk.alive_window();

-- The periods in [since, until] in which a host was not observed.
-- tolerance covers the delay of writes; use two or three times the
-- write_interval of the connector. It runs with the rights of its owner,
-- so that readers need no access to the tables.
CREATE FUNCTION shawk_v1.unobserved(since timestamptz, until timestamptz,
                                    tolerance interval DEFAULT '3 minutes')
RETURNS TABLE (host text, gap_start timestamptz, gap_end timestamptz)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
  SELECT h.hostname, lower(g), upper(g)
  FROM shawk.hosts h
  CROSS JOIN LATERAL unnest(
    tstzmultirange(tstzrange(since, until))
    - coalesce((SELECT range_agg(tstzrange(s.started_at, s.last_heartbeat + tolerance))
                FROM shawk.agent_sessions s WHERE s.host_id = h.id),
               '{}'::tstzmultirange)
  ) AS g
  WHERE h.last_seen >= since;
$$;
