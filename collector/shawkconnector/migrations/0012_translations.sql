-- Translations of addresses (#107).
--
-- A relay without an agent may rewrite the addresses of the connections it
-- forwards: a load balancer, a keepalived/LVS virtual address, a TCP proxy.
-- The client connects to a virtual address; the server sees its own
-- address, and as the client either the address of the client (DNAT) or an
-- address of the relay (SNAT, a proxy). The two sides of such connections
-- do not have the same addresses, so dependencies ended at the virtual
-- address, on one side only.
--
-- The connector writes the translations of its configuration here. A
-- translation has rows on three sides; every row of a side combines with
-- every row of the others:
--
--   virtual  an address clients connect to (a single address), and its port
--            (0: every port);
--   backend  the addresses of the servers it forwards to (a range), and
--            their port (0: the port the client connected to);
--   source   the addresses the servers see the clients at (a range); a
--            translation without sources keeps the address of the client.
--
-- The tables connectors of the previous schema write are unchanged, so that
-- they still write during an upgrade.
CREATE TABLE shawk.translations (
  name  text NOT NULL,
  side  text NOT NULL CHECK (side IN ('virtual', 'backend', 'source')),
  proto text NOT NULL CHECK (proto IN ('tcp', 'udp')),
  addr  cidr NOT NULL,
  port  integer NOT NULL DEFAULT 0 CHECK (port BETWEEN 0 AND 65535),
  PRIMARY KEY (name, side, proto, addr, port)
);

-- dependencies_between matches the edges that their addresses do not match
-- through the translations:
--
--   - a client edge whose server address is a virtual address of a
--     translation, and that matches no server edge by address, is matched
--     with the server edges at its backends, on the port of the backend (or
--     the port of the client edge), and with times that overlap (within 2
--     minutes, for the clocks of the hosts and the intervals of the agents);
--   - through a translation that keeps the address of the client, the
--     server edge has the address of the client (in the same scope);
--     through one with sources, it has an address of a source, and is
--     matched with every client edge to the translation: the server cannot
--     tell the clients behind a relay apart. Such a server edge also stays
--     on a row of its own, since clients without an agent may be behind the
--     relay too;
--   - a matched row is the dependency of the client on the server: the
--     address and port of the server, and the period both edges were
--     active in, since the server edge may serve other clients (behind a
--     relay) and the client edge other servers (the other backends) over
--     another period. The last columns tell the virtual address and port
--     the client connected to and the name of the translation; they are
--     NULL on rows matched by address;
--   - an edge keeps a row of its own unless its matched rows cover its
--     period (in the period asked for, with one of them in it): a client
--     edge also reached backends without an agent, or before their agents
--     started, and a server edge served the client directly.
--
-- The result has columns more, so the function is dropped and created
-- again; the SQL functions that call it name its columns.
DROP FUNCTION shawk_v1.dependencies_between(timestamptz, timestamptz);

CREATE FUNCTION shawk_v1.dependencies_between(since timestamptz, until timestamptz)
RETURNS TABLE (
  client_host text, client_service text, client_unit text, client_addr inet,
  server_host text, server_service text, server_unit text, server_addr inet,
  port integer, proto text, first_seen timestamptz, last_seen timestamptz,
  observed_by text, client_observed_until timestamptz, server_observed_until timestamptz,
  virtual_addr inet, virtual_port integer, translation text)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
WITH shared AS (SELECT addr FROM shawk.shared_addrs),
e AS (
  SELECT e.id, e.host_id, e.role, e.proto, e.local_addr, e.remote_addr, e.port, e.netns,
         e.first_seen, e.last_seen, p.service_name, p.unit, h.hostname,
         -- The scope in which the addresses of the edge identify its other
         -- side: the host and network namespace for loopback, the host for
         -- shared addresses, everywhere ('') otherwise.
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
-- Client edges to a virtual address that match no server edge by address,
-- read through the index of client edges. client_scope is the scope of the
-- address of the client alone, which is all the two sides of a connection
-- through a translation share.
cv AS (
  SELECT DISTINCT ON (c.id, v.name)
         c.id, c.host_id, c.proto, c.local_addr, c.remote_addr, c.port, c.first_seen, c.last_seen,
         p.service_name, p.unit, h.hostname, v.name AS translation,
         CASE WHEN c.local_addr << inet '127.0.0.0/8' OR c.local_addr = inet '::1'
                THEN c.host_id || '/' || c.netns::text
              WHEN c.local_addr IN (SELECT addr FROM shared)
                THEN c.host_id
              ELSE '' END AS client_scope
  FROM shawk.translations v
  JOIN shawk.edges c
    ON c.role = 'client' AND c.proto = v.proto AND c.remote_addr = v.addr AND v.port IN (0, c.port)
  JOIN shawk.processes p ON p.id = c.process_id
  JOIN shawk.hosts h ON h.id = c.host_id
  WHERE v.side = 'virtual'
    AND c.last_seen >= since - interval '15 minutes' AND c.first_seen <= until + interval '15 minutes'
    AND NOT EXISTS (
      SELECT FROM shawk.edges s
      WHERE s.role = 'server' AND s.proto = c.proto AND s.local_addr = c.remote_addr AND s.port = c.port
        AND s.remote_addr = c.local_addr
        AND s.last_seen >= since - interval '15 minutes' AND s.first_seen <= until + interval '15 minutes'
        AND CASE WHEN s.remote_addr << inet '127.0.0.0/8' OR s.remote_addr = inet '::1'
                    THEN s.host_id || '/' || s.netns::text
                  WHEN s.local_addr IN (SELECT addr FROM shared) OR s.remote_addr IN (SELECT addr FROM shared)
                    THEN s.host_id
                  ELSE '' END
          = CASE WHEN c.remote_addr << inet '127.0.0.0/8' OR c.remote_addr = inet '::1'
                    THEN c.host_id || '/' || c.netns::text
                  WHEN c.local_addr IN (SELECT addr FROM shared) OR c.remote_addr IN (SELECT addr FROM shared)
                    THEN c.host_id
                  ELSE '' END)
  ORDER BY c.id, v.name
),
-- The backends of the translations, with the ports of their virtual
-- addresses and their sources; exact tells that the backend is a single
-- address.
bk AS (
  SELECT b.name, b.proto, b.addr, b.port,
         masklen(b.addr) = CASE family(b.addr) WHEN 4 THEN 32 ELSE 128 END AS exact,
         ARRAY(SELECT v.port FROM shawk.translations v
               WHERE v.name = b.name AND v.side = 'virtual' AND v.proto = b.proto) AS virtual_ports,
         ARRAY(SELECT x.addr FROM shawk.translations x
               WHERE x.name = b.name AND x.side = 'source' AND x.proto = b.proto) AS sources
  FROM shawk.translations b
  WHERE b.side = 'backend'
),
-- Server edges at the address of a backend, read through the index of
-- server edges: a single address by equality, a range by its bounds.
sa AS (
  SELECT s.*, b.addr::inet AS backend
  FROM (SELECT DISTINCT proto, addr FROM bk WHERE exact) b
  JOIN shawk.edges s ON s.role = 'server' AND s.proto = b.proto AND s.local_addr = b.addr
  WHERE s.last_seen >= since - interval '15 minutes' AND s.first_seen <= until + interval '15 minutes'
  UNION ALL
  SELECT s.*, r.addr::inet
  FROM (SELECT DISTINCT proto, addr FROM bk WHERE NOT exact) r
  JOIN shawk.edges s
    ON  s.role = 'server' AND s.proto = r.proto AND s.local_addr <<= r.addr
    AND s.local_addr >= r.addr
    AND s.local_addr <= set_masklen(broadcast(r.addr), CASE family(r.addr) WHEN 4 THEN 32 ELSE 128 END)
  WHERE s.last_seen >= since - interval '15 minutes' AND s.first_seen <= until + interval '15 minutes'
),
-- Server edges at a backend, on its port or on the port of a virtual
-- address, from a source if the translation has any. fixed tells that the
-- backend has the port of the edge, rather than the port the client
-- connected to.
sb AS (
  SELECT DISTINCT ON (sa.id, bk.name)
         sa.id, sa.host_id, sa.proto, sa.local_addr, sa.remote_addr, sa.port, sa.first_seen, sa.last_seen,
         p.service_name, p.unit, h.hostname, bk.name AS translation,
         bk.port <> 0 AS fixed, cardinality(bk.sources) > 0 AS snat,
         CASE WHEN sa.remote_addr << inet '127.0.0.0/8' OR sa.remote_addr = inet '::1'
                THEN sa.host_id || '/' || sa.netns::text
              WHEN sa.remote_addr IN (SELECT addr FROM shared)
                THEN sa.host_id
              ELSE '' END AS client_scope
  FROM sa
  JOIN bk ON bk.addr = sa.backend AND bk.proto = sa.proto AND bk.port IN (0, sa.port)
  JOIN shawk.processes p ON p.id = sa.process_id
  JOIN shawk.hosts h ON h.id = sa.host_id
  WHERE (bk.port <> 0 OR 0 = ANY (bk.virtual_ports) OR sa.port = ANY (bk.virtual_ports))
    AND (cardinality(bk.sources) = 0 OR sa.remote_addr <<= ANY (bk.sources))
  ORDER BY sa.id, bk.name, bk.port <> 0 DESC
),
-- The client and server edges matched through a translation: on the port
-- of the backend or the port of the client edge, with times that overlap;
-- through a translation without sources, with the address of the client.
-- p_first and p_last are the period both were active in.
translated AS (
  SELECT cv.id AS cid, cv.host_id AS c_host_id, cv.hostname AS c_hostname, cv.service_name AS c_service,
         cv.unit AS c_unit, cv.local_addr AS c_local, cv.remote_addr AS c_remote, cv.port AS c_port,
         cv.first_seen AS c_first, cv.last_seen AS c_last,
         sb.id AS sid, sb.host_id AS s_host_id, sb.hostname AS s_hostname, sb.service_name AS s_service,
         sb.unit AS s_unit, sb.local_addr AS s_local, sb.port AS s_port,
         sb.first_seen AS s_first, sb.last_seen AS s_last,
         cv.proto, cv.translation, false AS snat,
         least(greatest(cv.first_seen, sb.first_seen), least(cv.last_seen, sb.last_seen)) AS p_first,
         greatest(greatest(cv.first_seen, sb.first_seen), least(cv.last_seen, sb.last_seen)) AS p_last
  FROM cv JOIN sb
    ON  sb.translation = cv.translation AND sb.proto = cv.proto
    AND sb.remote_addr = cv.local_addr AND sb.client_scope = cv.client_scope
  WHERE NOT sb.snat
    AND (sb.fixed OR sb.port = cv.port)
    AND cv.first_seen <= sb.last_seen + interval '2 minutes'
    AND sb.first_seen <= cv.last_seen + interval '2 minutes'
  UNION ALL
  SELECT cv.id, cv.host_id, cv.hostname, cv.service_name, cv.unit, cv.local_addr, cv.remote_addr, cv.port,
         cv.first_seen, cv.last_seen,
         sb.id, sb.host_id, sb.hostname, sb.service_name, sb.unit, sb.local_addr, sb.port,
         sb.first_seen, sb.last_seen,
         cv.proto, cv.translation, true,
         least(greatest(cv.first_seen, sb.first_seen), least(cv.last_seen, sb.last_seen)),
         greatest(greatest(cv.first_seen, sb.first_seen), least(cv.last_seen, sb.last_seen))
  FROM cv JOIN sb ON sb.translation = cv.translation AND sb.proto = cv.proto
  WHERE sb.snat
    AND (sb.fixed OR sb.port = cv.port)
    AND cv.first_seen <= sb.last_seen + interval '2 minutes'
    AND sb.first_seen <= cv.last_seen + interval '2 minutes'
),
-- The edges that their rows matched through translations cover: a client
-- edge, or a server edge through a translation without sources, whose
-- period the periods of its rows cover, within the margin. They need no row
-- of their own; another edge keeps its row, since it was active when its
-- other side was not observed (the client edge with other backends, the
-- server edge with other clients). A server edge from a source always
-- keeps its row: the clients behind the relay may have no agent. In
-- [since, until], the edge is covered there, and one of its rows is in it.
covered AS (
  SELECT t.cid AS id
  FROM translated t
  GROUP BY t.cid, t.c_first, t.c_last
  HAVING bool_or(t.p_last >= since AND t.p_first <= until)
     AND CASE WHEN greatest(t.c_first, since) > least(t.c_last, until) THEN true
              ELSE range_agg(tstzrange(t.p_first - interval '2 minutes', t.p_last + interval '2 minutes', '[]'))
                     @> tstzrange(greatest(t.c_first, since), least(t.c_last, until), '[]') END
  UNION ALL
  SELECT t.sid
  FROM translated t
  WHERE NOT t.snat
  GROUP BY t.sid, t.s_first, t.s_last
  HAVING bool_or(t.p_last >= since AND t.p_first <= until)
     AND CASE WHEN greatest(t.s_first, since) > least(t.s_last, until) THEN true
              ELSE range_agg(tstzrange(t.p_first - interval '2 minutes', t.p_last + interval '2 minutes', '[]'))
                     @> tstzrange(greatest(t.s_first, since), least(t.s_last, until), '[]') END
),
d AS (
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
  so.observed_until                             AS server_observed_until,
  NULL::inet                                    AS virtual_addr,
  NULL::integer                                 AS virtual_port,
  NULL::text                                    AS translation
FROM (SELECT * FROM e WHERE role = 'client') c
FULL JOIN (SELECT * FROM e WHERE role = 'server') s
  ON  c.local_addr = s.remote_addr
  AND c.remote_addr = s.local_addr
  AND c.port = s.port
  AND c.proto = s.proto
  AND c.scope = s.scope
LEFT JOIN observed co ON co.host_id = c.host_id
LEFT JOIN observed so ON so.host_id = s.host_id
-- An edge whose rows below cover it needs no row of its own.
WHERE NOT (s.id IS NULL AND c.id IN (SELECT id FROM covered))
  AND NOT (c.id IS NULL AND s.id IN (SELECT id FROM covered))
UNION ALL
SELECT
  t.c_hostname, t.c_service, t.c_unit, t.c_local,
  t.s_hostname, t.s_service, t.s_unit, t.s_local,
  t.s_port, t.proto, t.p_first, t.p_last,
  'both', co.observed_until, so.observed_until,
  t.c_remote, t.c_port, t.translation
FROM translated t
LEFT JOIN observed co ON co.host_id = t.c_host_id
LEFT JOIN observed so ON so.host_id = t.s_host_id
)
SELECT * FROM d WHERE d.last_seen >= since AND d.first_seen <= until
$$;

-- dependencies: the same over all edges. It is kept apart from the
-- function, so that either can change without dropping the views that
-- depend on it.
CREATE OR REPLACE VIEW shawk_v1.dependencies AS
WITH shared AS (SELECT addr FROM shawk.shared_addrs),
e AS (
  SELECT e.id, e.host_id, e.role, e.proto, e.local_addr, e.remote_addr, e.port, e.netns,
         e.first_seen, e.last_seen, p.service_name, p.unit, h.hostname,
         -- The scope in which the addresses of the edge identify its other
         -- side: the host and network namespace for loopback, the host for
         -- shared addresses, everywhere ('') otherwise.
         CASE WHEN e.remote_addr << inet '127.0.0.0/8' OR e.remote_addr = inet '::1'
                THEN e.host_id || '/' || e.netns::text
              WHEN e.local_addr IN (SELECT addr FROM shared) OR e.remote_addr IN (SELECT addr FROM shared)
                THEN e.host_id
              ELSE '' END AS scope
  FROM shawk.edges e
  JOIN shawk.processes p ON p.id = e.process_id
  JOIN shawk.hosts h ON h.id = e.host_id
),
observed AS (
  SELECT host_id, max(last_heartbeat) AS observed_until
  FROM shawk.agent_sessions GROUP BY host_id
),
-- Client edges to a virtual address that match no server edge by address,
-- read through the index of client edges. client_scope is the scope of the
-- address of the client alone, which is all the two sides of a connection
-- through a translation share.
cv AS (
  SELECT DISTINCT ON (c.id, v.name)
         c.id, c.host_id, c.proto, c.local_addr, c.remote_addr, c.port, c.first_seen, c.last_seen,
         p.service_name, p.unit, h.hostname, v.name AS translation,
         CASE WHEN c.local_addr << inet '127.0.0.0/8' OR c.local_addr = inet '::1'
                THEN c.host_id || '/' || c.netns::text
              WHEN c.local_addr IN (SELECT addr FROM shared)
                THEN c.host_id
              ELSE '' END AS client_scope
  FROM shawk.translations v
  JOIN shawk.edges c
    ON c.role = 'client' AND c.proto = v.proto AND c.remote_addr = v.addr AND v.port IN (0, c.port)
  JOIN shawk.processes p ON p.id = c.process_id
  JOIN shawk.hosts h ON h.id = c.host_id
  WHERE v.side = 'virtual'
    AND NOT EXISTS (
      SELECT FROM shawk.edges s
      WHERE s.role = 'server' AND s.proto = c.proto AND s.local_addr = c.remote_addr AND s.port = c.port
        AND s.remote_addr = c.local_addr
        AND CASE WHEN s.remote_addr << inet '127.0.0.0/8' OR s.remote_addr = inet '::1'
                    THEN s.host_id || '/' || s.netns::text
                  WHEN s.local_addr IN (SELECT addr FROM shared) OR s.remote_addr IN (SELECT addr FROM shared)
                    THEN s.host_id
                  ELSE '' END
          = CASE WHEN c.remote_addr << inet '127.0.0.0/8' OR c.remote_addr = inet '::1'
                    THEN c.host_id || '/' || c.netns::text
                  WHEN c.local_addr IN (SELECT addr FROM shared) OR c.remote_addr IN (SELECT addr FROM shared)
                    THEN c.host_id
                  ELSE '' END)
  ORDER BY c.id, v.name
),
-- The backends of the translations, with the ports of their virtual
-- addresses and their sources; exact tells that the backend is a single
-- address.
bk AS (
  SELECT b.name, b.proto, b.addr, b.port,
         masklen(b.addr) = CASE family(b.addr) WHEN 4 THEN 32 ELSE 128 END AS exact,
         ARRAY(SELECT v.port FROM shawk.translations v
               WHERE v.name = b.name AND v.side = 'virtual' AND v.proto = b.proto) AS virtual_ports,
         ARRAY(SELECT x.addr FROM shawk.translations x
               WHERE x.name = b.name AND x.side = 'source' AND x.proto = b.proto) AS sources
  FROM shawk.translations b
  WHERE b.side = 'backend'
),
-- Server edges at the address of a backend, read through the index of
-- server edges: a single address by equality, a range by its bounds.
sa AS (
  SELECT s.*, b.addr::inet AS backend
  FROM (SELECT DISTINCT proto, addr FROM bk WHERE exact) b
  JOIN shawk.edges s ON s.role = 'server' AND s.proto = b.proto AND s.local_addr = b.addr
  UNION ALL
  SELECT s.*, r.addr::inet
  FROM (SELECT DISTINCT proto, addr FROM bk WHERE NOT exact) r
  JOIN shawk.edges s
    ON  s.role = 'server' AND s.proto = r.proto AND s.local_addr <<= r.addr
    AND s.local_addr >= r.addr
    AND s.local_addr <= set_masklen(broadcast(r.addr), CASE family(r.addr) WHEN 4 THEN 32 ELSE 128 END)
),
-- Server edges at a backend, on its port or on the port of a virtual
-- address, from a source if the translation has any. fixed tells that the
-- backend has the port of the edge, rather than the port the client
-- connected to.
sb AS (
  SELECT DISTINCT ON (sa.id, bk.name)
         sa.id, sa.host_id, sa.proto, sa.local_addr, sa.remote_addr, sa.port, sa.first_seen, sa.last_seen,
         p.service_name, p.unit, h.hostname, bk.name AS translation,
         bk.port <> 0 AS fixed, cardinality(bk.sources) > 0 AS snat,
         CASE WHEN sa.remote_addr << inet '127.0.0.0/8' OR sa.remote_addr = inet '::1'
                THEN sa.host_id || '/' || sa.netns::text
              WHEN sa.remote_addr IN (SELECT addr FROM shared)
                THEN sa.host_id
              ELSE '' END AS client_scope
  FROM sa
  JOIN bk ON bk.addr = sa.backend AND bk.proto = sa.proto AND bk.port IN (0, sa.port)
  JOIN shawk.processes p ON p.id = sa.process_id
  JOIN shawk.hosts h ON h.id = sa.host_id
  WHERE (bk.port <> 0 OR 0 = ANY (bk.virtual_ports) OR sa.port = ANY (bk.virtual_ports))
    AND (cardinality(bk.sources) = 0 OR sa.remote_addr <<= ANY (bk.sources))
  ORDER BY sa.id, bk.name, bk.port <> 0 DESC
),
-- The client and server edges matched through a translation: on the port
-- of the backend or the port of the client edge, with times that overlap;
-- through a translation without sources, with the address of the client.
-- p_first and p_last are the period both were active in.
translated AS (
  SELECT cv.id AS cid, cv.host_id AS c_host_id, cv.hostname AS c_hostname, cv.service_name AS c_service,
         cv.unit AS c_unit, cv.local_addr AS c_local, cv.remote_addr AS c_remote, cv.port AS c_port,
         cv.first_seen AS c_first, cv.last_seen AS c_last,
         sb.id AS sid, sb.host_id AS s_host_id, sb.hostname AS s_hostname, sb.service_name AS s_service,
         sb.unit AS s_unit, sb.local_addr AS s_local, sb.port AS s_port,
         sb.first_seen AS s_first, sb.last_seen AS s_last,
         cv.proto, cv.translation, false AS snat,
         least(greatest(cv.first_seen, sb.first_seen), least(cv.last_seen, sb.last_seen)) AS p_first,
         greatest(greatest(cv.first_seen, sb.first_seen), least(cv.last_seen, sb.last_seen)) AS p_last
  FROM cv JOIN sb
    ON  sb.translation = cv.translation AND sb.proto = cv.proto
    AND sb.remote_addr = cv.local_addr AND sb.client_scope = cv.client_scope
  WHERE NOT sb.snat
    AND (sb.fixed OR sb.port = cv.port)
    AND cv.first_seen <= sb.last_seen + interval '2 minutes'
    AND sb.first_seen <= cv.last_seen + interval '2 minutes'
  UNION ALL
  SELECT cv.id, cv.host_id, cv.hostname, cv.service_name, cv.unit, cv.local_addr, cv.remote_addr, cv.port,
         cv.first_seen, cv.last_seen,
         sb.id, sb.host_id, sb.hostname, sb.service_name, sb.unit, sb.local_addr, sb.port,
         sb.first_seen, sb.last_seen,
         cv.proto, cv.translation, true,
         least(greatest(cv.first_seen, sb.first_seen), least(cv.last_seen, sb.last_seen)),
         greatest(greatest(cv.first_seen, sb.first_seen), least(cv.last_seen, sb.last_seen))
  FROM cv JOIN sb ON sb.translation = cv.translation AND sb.proto = cv.proto
  WHERE sb.snat
    AND (sb.fixed OR sb.port = cv.port)
    AND cv.first_seen <= sb.last_seen + interval '2 minutes'
    AND sb.first_seen <= cv.last_seen + interval '2 minutes'
),
-- The edges that their rows matched through translations cover: a client
-- edge, or a server edge through a translation without sources, whose
-- period the periods of its rows cover, within the margin. They need no row
-- of their own; another edge keeps its row, since it was active when its
-- other side was not observed (the client edge with other backends, the
-- server edge with other clients). A server edge from a source always
-- keeps its row: the clients behind the relay may have no agent.
covered AS (
  SELECT t.cid AS id
  FROM translated t
  GROUP BY t.cid, t.c_first, t.c_last
  HAVING range_agg(tstzrange(t.p_first - interval '2 minutes', t.p_last + interval '2 minutes', '[]'))
           @> tstzrange(t.c_first, t.c_last, '[]')
  UNION ALL
  SELECT t.sid
  FROM translated t
  WHERE NOT t.snat
  GROUP BY t.sid, t.s_first, t.s_last
  HAVING range_agg(tstzrange(t.p_first - interval '2 minutes', t.p_last + interval '2 minutes', '[]'))
           @> tstzrange(t.s_first, t.s_last, '[]')
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
  so.observed_until                             AS server_observed_until,
  NULL::inet                                    AS virtual_addr,
  NULL::integer                                 AS virtual_port,
  NULL::text                                    AS translation
FROM (SELECT * FROM e WHERE role = 'client') c
FULL JOIN (SELECT * FROM e WHERE role = 'server') s
  ON  c.local_addr = s.remote_addr
  AND c.remote_addr = s.local_addr
  AND c.port = s.port
  AND c.proto = s.proto
  AND c.scope = s.scope
LEFT JOIN observed co ON co.host_id = c.host_id
LEFT JOIN observed so ON so.host_id = s.host_id
-- An edge whose rows below cover it needs no row of its own.
WHERE NOT (s.id IS NULL AND c.id IN (SELECT id FROM covered))
  AND NOT (c.id IS NULL AND s.id IN (SELECT id FROM covered))
UNION ALL
SELECT
  t.c_hostname, t.c_service, t.c_unit, t.c_local,
  t.s_hostname, t.s_service, t.s_unit, t.s_local,
  t.s_port, t.proto, t.p_first, t.p_last,
  'both', co.observed_until, so.observed_until,
  t.c_remote, t.c_port, t.translation
FROM translated t
LEFT JOIN observed co ON co.host_id = t.c_host_id
LEFT JOIN observed so ON so.host_id = t.s_host_id;
