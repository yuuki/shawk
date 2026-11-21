-- Fixes of views and functions of the contract (shawk_v1). Each object
-- below replaces the one of 0001_schema.sql or 0002_edge_protocols.sql of
-- the same name, with the same columns:
--
--   - shawk_v1.dependencies_between() and shawk_v1.dependencies: an edge
--     with a loopback address on either side is matched within its host and
--     network namespace, on both sides of a connection alike, so that a
--     client that binds an address of its host and connects to 127.0.0.1
--     matches its server (docs/design.md §6.2). An edge matched through a
--     translation and by address keeps a row of its own for the part of its
--     period that neither covers, and its row matched by address has the
--     period of the other edge on the server side as on the client side
--     (§5.4).
--   - shawk_v1.planned_stops: the states with MAINT that follow each other
--     are those read while the one before was fresh, so that a reservation
--     after a stale gap counts its 30 days from its own start (§5.7).

-- The dependencies active in [since, until]: the client and server edges
-- of a connection matched into one row. Edges are taken with a margin of
-- 15 minutes, matched, and the matched rows filtered by the period: the
-- sides of one connection are reported by different agents at different
-- times, so that at the edges of the period one side would otherwise be
-- left out and the other come out alone. A dependency seen on one side only
-- has no agent on the other side, or a NAT or load balancer between that no
-- translation describes.
--
-- Edges are matched by their addresses and port, in the scope in which the
-- addresses identify the other side: the host and network namespace for a
-- loopback address on either side, the host for shared addresses,
-- everywhere otherwise. The edges that their addresses do not match are
-- matched through translations:
--
--   - a client edge whose server address is a virtual address of a
--     translation is matched with the server edges at its backends, on the
--     port of the backend (or the port of the client edge), and with times
--     that overlap (within 2 minutes, for the clocks of the hosts and the
--     intervals of the agents); not over the periods in which a server edge
--     at the virtual address matches it by address (a relay that runs an
--     agent), whose row then has the period of that server edge;
--   - through a translation that keeps the address of the client, the
--     server edge has the address of the client (in the same scope);
--     through one with sources, it has an address of a source, and is
--     matched with every client edge to the translation: the server cannot
--     tell the clients behind a relay apart. Such a server edge also stays
--     on a row of its own, since clients without an agent may be behind the
--     relay too;
--   - learned translations match a client edge and a server edge like the
--     translations of the configuration, which come first, with the
--     translation '~learned';
--   - a matched row is the dependency of the client on the server: the
--     address and port of the server, and the period both edges were
--     active in, since the server edge may serve other clients (behind a
--     relay) and the client edge other servers (the other backends) over
--     another period. The last columns tell the virtual address and port
--     the client connected to and the name of the translation; they are
--     NULL on rows matched by address;
--   - an edge keeps a row of its own if its matched rows, through
--     translations and by address, leave a part of its period (in the
--     period asked for, a part in it): a client edge also reached backends
--     without an agent, or before their agents started, and a server edge
--     served the client directly. The row runs from the start of the edge
--     to the end of the last part left. The row of an edge matched through
--     translations that is also matched by address has the period of the
--     other edge (a relay that runs an agent served the client edge then;
--     the client reached the server edge directly then), or the period
--     both were active in if both are matched through translations;
--   - on these rows, the observation of a side whose edge outlives the row
--     is NULL: it tells nothing of the end of the row, which is for the
--     other side to tell, so that a stopped agent does not make the
--     dependency look removed.
--
-- The client edges of Unix sockets (unix_edges) are matched with the
-- owners of the listeners of their names (unix_listeners) whose periods
-- overlap them, within 2 minutes:
--
--   - a matched row is the dependency of the client on the owner over the
--     part of the period of the client edge that the owner held the
--     listener, within the margin, except that the row of the first owner
--     starts with the client edge and that of the last owner ends with it,
--     as the row of a TCP connection spans both its edges: a client keeps
--     the connections it opened, or keeps trying, after the listener closed.
--     A row never lasts longer than its client edge, so that a listener that
--     stays does not make its former clients look active. Both sides are
--     observed by the agent of the host, so both observed_until are its
--     latest heartbeat;
--   - a client edge that matches no owner is a row of its own, observed by
--     the client: a socket whose listener was not seen, such as one that
--     refused the connections, or one whose name is ambiguous;
--   - addresses are NULL and the port is 0; path, the last column, is the
--     name of the socket, NULL on the rows of TCP and UDP.
--
-- client_observed_until and server_observed_until are the latest heartbeats
-- of the hosts: an old last_seen with a recent observed_until means no
-- longer used; both old means no longer observed.
CREATE OR REPLACE FUNCTION shawk_v1.dependencies_between(since timestamptz, until timestamptz)
RETURNS TABLE (
  client_host text, client_service text, client_unit text, client_addr inet,
  server_host text, server_service text, server_unit text, server_addr inet,
  port integer, proto text, first_seen timestamptz, last_seen timestamptz,
  observed_by text, client_observed_until timestamptz, server_observed_until timestamptz,
  virtual_addr inet, virtual_port integer, translation text, path text)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
WITH shared AS (SELECT addr FROM shawk.shared_addrs),
e AS (
  SELECT e.id, e.host_id, e.role, e.proto, e.local_addr, e.remote_addr, e.port, e.netns,
         e.first_seen, e.last_seen, p.service_name, p.unit, h.hostname,
         -- The scope in which the addresses of the edge identify its other
         -- side: the host and network namespace for a loopback address on
         -- either side, as both sides of a connection have the same
         -- addresses, the host for shared addresses, everywhere ('')
         -- otherwise.
         CASE WHEN e.local_addr << inet '127.0.0.0/8' OR e.local_addr = inet '::1'
                OR e.remote_addr << inet '127.0.0.0/8' OR e.remote_addr = inet '::1'
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
-- The client edges of Unix sockets, and the owners of the listeners of
-- their names on their hosts that overlap them: those in the namespace of
-- the client if any, else, for a path, those of the only namespace that has
-- any. An abstract name (@) is reached in the namespace of its client only.
-- earliest and latest tell the first and the last owner of each edge.
ue AS (
  SELECT u.id, u.host_id, u.path, u.netns, u.first_seen, u.last_seen, p.service_name, p.unit, h.hostname
  FROM shawk.unix_edges u
  JOIN shawk.processes p ON p.id = u.process_id
  JOIN shawk.hosts h ON h.id = u.host_id
  WHERE u.last_seen >= since - interval '15 minutes' AND u.first_seen <= until + interval '15 minutes'
),
uo AS (
  SELECT x.edge_id, x.process_id, x.first_seen, x.last_seen,
         row_number() OVER (PARTITION BY x.edge_id ORDER BY x.first_seen, x.process_id) = 1 AS earliest,
         row_number() OVER (PARTITION BY x.edge_id ORDER BY x.last_seen DESC, x.process_id) = 1 AS latest
  FROM (
    SELECT ue.id AS edge_id, l.process_id, l.first_seen, l.last_seen, l.netns = ue.netns AS in_netns,
           left(ue.path, 1) = '@' AS abstract,
           bool_or(l.netns = ue.netns) OVER w AS any_in_netns,
           min(l.netns) OVER w = max(l.netns) OVER w AS one_netns
    FROM ue
    JOIN shawk.unix_listeners l
      ON  l.host_id = ue.host_id AND l.path = ue.path
      AND l.first_seen <= ue.last_seen + interval '2 minutes'
      AND ue.first_seen <= l.last_seen + interval '2 minutes'
    WINDOW w AS (PARTITION BY ue.id)
  ) x
  WHERE x.in_netns OR (NOT x.any_in_netns AND x.one_netns AND NOT x.abstract)
),
-- Client edges to a virtual address, read through the index of client
-- edges. client_scope is the scope of the address of the client alone,
-- which is all the two sides of a connection through a translation share.
-- direct is when server edges at the virtual address matched the client
-- edge by address, within the margin: a relay that runs an agent served
-- it then, rather than the backends.
cv AS (
  SELECT DISTINCT ON (c.id, v.name)
         c.id, c.host_id, c.proto, c.local_addr, c.remote_addr, c.port, c.first_seen, c.last_seen,
         p.service_name, p.unit, h.hostname, v.name AS translation,
         CASE WHEN c.local_addr << inet '127.0.0.0/8' OR c.local_addr = inet '::1'
                THEN c.host_id || '/' || c.netns::text
              WHEN c.local_addr IN (SELECT addr FROM shared)
                THEN c.host_id
              ELSE '' END AS client_scope,
         (SELECT range_agg(tstzrange(least(s.first_seen, s.last_seen) - interval '2 minutes',
                                     greatest(s.first_seen, s.last_seen) + interval '2 minutes', '[]'))
          FROM shawk.edges s
          WHERE s.role = 'server' AND s.proto = c.proto AND s.local_addr = c.remote_addr AND s.port = c.port
            AND s.remote_addr = c.local_addr
            AND s.last_seen >= since - interval '15 minutes' AND s.first_seen <= until + interval '15 minutes'
            AND CASE WHEN s.local_addr << inet '127.0.0.0/8' OR s.local_addr = inet '::1'
                        OR s.remote_addr << inet '127.0.0.0/8' OR s.remote_addr = inet '::1'
                        THEN s.host_id || '/' || s.netns::text
                      WHEN s.local_addr IN (SELECT addr FROM shared) OR s.remote_addr IN (SELECT addr FROM shared)
                        THEN s.host_id
                      ELSE '' END
              = CASE WHEN c.local_addr << inet '127.0.0.0/8' OR c.local_addr = inet '::1'
                        OR c.remote_addr << inet '127.0.0.0/8' OR c.remote_addr = inet '::1'
                        THEN c.host_id || '/' || c.netns::text
                      WHEN c.local_addr IN (SELECT addr FROM shared) OR c.remote_addr IN (SELECT addr FROM shared)
                        THEN c.host_id
                      ELSE '' END) AS direct
  FROM shawk.translations v
  JOIN shawk.edges c
    ON c.role = 'client' AND c.proto = v.proto AND c.remote_addr = v.addr AND v.port IN (0, c.port)
  JOIN shawk.processes p ON p.id = c.process_id
  JOIN shawk.hosts h ON h.id = c.host_id
  WHERE v.side = 'virtual'
    AND c.last_seen >= since - interval '15 minutes' AND c.first_seen <= until + interval '15 minutes'
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
-- Learned translations (shawk.learned_translations): a client edge c and a
-- server edge s match the rows of hosts that translated the connections
-- of the client of c to its server address and port into the backend of
-- s, seen from the peer of s; a loopback client or virtual address is in
-- the host and namespace of the row, a shared client address on its host,
-- and any other anywhere, and so are the backend and the source. A client
-- edge to a virtual address of a static translation is matched through it
-- only. The rows that overlap c and s, within 2 minutes, are combined: the
-- period of the pair is the part of those of c and s that their span
-- covers.
lc AS (
  SELECT c.id, c.proto, c.first_seen AS c_first, c.last_seen AS c_last,
         l.host_id AS l_host, l.netns AS l_netns, l.source_addr, l.backend_addr, l.backend_port,
         l.first_seen AS l_first, l.last_seen AS l_last
  FROM shawk.learned_translations l
  JOIN shawk.edges c
    ON  c.role = 'client' AND c.proto = l.proto AND c.remote_addr = l.virtual_addr AND c.port = l.virtual_port
    AND c.local_addr = l.client_addr
  -- Every learned row of the edges in the period, not only those in it, so
  -- that a pair has the span of its rows, as in the view.
  WHERE CASE WHEN c.local_addr << inet '127.0.0.0/8' OR c.local_addr = inet '::1'
                  OR c.remote_addr << inet '127.0.0.0/8' OR c.remote_addr = inet '::1'
               THEN c.host_id = l.host_id AND c.netns = l.netns
             WHEN c.local_addr IN (SELECT addr FROM shared) THEN c.host_id = l.host_id
             ELSE true END
    AND c.first_seen <= l.last_seen + interval '2 minutes'
    AND l.first_seen <= c.last_seen + interval '2 minutes'
    AND c.last_seen >= since - interval '15 minutes' AND c.first_seen <= until + interval '15 minutes'
    AND NOT EXISTS (
      SELECT FROM shawk.translations v
      WHERE v.side = 'virtual' AND v.proto = c.proto AND v.addr = c.remote_addr AND v.port IN (0, c.port))
),
lp AS (
  SELECT lc.id AS cid, s.id AS sid, min(lc.l_first) AS l_first, max(lc.l_last) AS l_last
  FROM lc
  JOIN shawk.edges s
    ON  s.role = 'server' AND s.proto = lc.proto AND s.local_addr = lc.backend_addr AND s.port = lc.backend_port
    AND s.remote_addr = lc.source_addr
  WHERE CASE WHEN s.local_addr << inet '127.0.0.0/8' OR s.local_addr = inet '::1'
                  OR s.remote_addr << inet '127.0.0.0/8' OR s.remote_addr = inet '::1'
               THEN s.host_id = lc.l_host AND s.netns = lc.l_netns
             WHEN s.local_addr IN (SELECT addr FROM shared) OR s.remote_addr IN (SELECT addr FROM shared)
               THEN s.host_id = lc.l_host
             ELSE true END
    AND s.first_seen <= lc.l_last + interval '2 minutes'
    AND lc.l_first <= s.last_seen + interval '2 minutes'
    AND s.first_seen <= lc.c_last + interval '2 minutes'
    AND lc.c_first <= s.last_seen + interval '2 minutes'
    AND s.last_seen >= since - interval '15 minutes' AND s.first_seen <= until + interval '15 minutes'
  GROUP BY lc.id, s.id
),
-- The client and server edges a translation may match: on the port of the
-- backend or the port of the client edge, with times that overlap; through
-- a translation without sources, with the address of the client. p_first
-- and p_last are the period both were active in.
pairs AS (
  SELECT cv.id AS cid, cv.host_id AS c_host_id, cv.hostname AS c_hostname, cv.service_name AS c_service,
         cv.unit AS c_unit, cv.local_addr AS c_local, cv.remote_addr AS c_remote, cv.port AS c_port,
         cv.first_seen AS c_first, cv.last_seen AS c_last, cv.direct,
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
         cv.first_seen, cv.last_seen, cv.direct,
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
  UNION ALL
  SELECT c.id, c.host_id, hc.hostname, pc.service_name, pc.unit, c.local_addr, c.remote_addr, c.port,
         c.first_seen, c.last_seen,
         -- direct, as for the client edges of static translations.
         (SELECT range_agg(tstzrange(least(d.first_seen, d.last_seen) - interval '2 minutes',
                                     greatest(d.first_seen, d.last_seen) + interval '2 minutes', '[]'))
          FROM shawk.edges d
          WHERE d.role = 'server' AND d.proto = c.proto AND d.local_addr = c.remote_addr AND d.port = c.port
            AND d.remote_addr = c.local_addr
            AND d.last_seen >= since - interval '15 minutes' AND d.first_seen <= until + interval '15 minutes'
            AND CASE WHEN d.local_addr << inet '127.0.0.0/8' OR d.local_addr = inet '::1'
                        OR d.remote_addr << inet '127.0.0.0/8' OR d.remote_addr = inet '::1'
                        THEN d.host_id || '/' || d.netns::text
                      WHEN d.local_addr IN (SELECT addr FROM shared) OR d.remote_addr IN (SELECT addr FROM shared)
                        THEN d.host_id
                      ELSE '' END
              = CASE WHEN c.local_addr << inet '127.0.0.0/8' OR c.local_addr = inet '::1'
                        OR c.remote_addr << inet '127.0.0.0/8' OR c.remote_addr = inet '::1'
                        THEN c.host_id || '/' || c.netns::text
                      WHEN c.local_addr IN (SELECT addr FROM shared) OR c.remote_addr IN (SELECT addr FROM shared)
                        THEN c.host_id
                      ELSE '' END),
         s.id, s.host_id, hs.hostname, ps.service_name, ps.unit, s.local_addr, s.port,
         s.first_seen, s.last_seen,
         c.proto, '~learned'::text, s.remote_addr <> c.local_addr,
         least(greatest(c.first_seen, s.first_seen, lp.l_first), least(c.last_seen, s.last_seen, lp.l_last)),
         greatest(greatest(c.first_seen, s.first_seen, lp.l_first), least(c.last_seen, s.last_seen, lp.l_last))
  FROM lp
  JOIN shawk.edges c ON c.id = lp.cid
  JOIN shawk.processes pc ON pc.id = c.process_id
  JOIN shawk.hosts hc ON hc.id = c.host_id
  JOIN shawk.edges s ON s.id = lp.sid
  JOIN shawk.processes ps ON ps.id = s.process_id
  JOIN shawk.hosts hs ON hs.id = s.host_id
),
-- The pairs matched through a translation: not those that a relay with an
-- agent served all along, which the client edge matches by address.
translated AS (
  SELECT * FROM pairs t
  WHERE t.direct IS NULL OR NOT t.direct @> tstzrange(t.p_first, t.p_last, '[]')
),
-- What is left of the period of an edge matched through translations
-- that its matched rows do not cover, within the margin: a client edge
-- also reached backends without an agent, or before their agents started,
-- and a server edge through a translation without sources served the
-- client directly. A server edge from a source keeps its own row whole,
-- since clients without an agent may be behind the relay.
rest AS (
  SELECT t.cid AS id,
         tstzmultirange(tstzrange(least(t.c_first, t.c_last), greatest(t.c_first, t.c_last), '[]'))
           - range_agg(tstzrange(t.p_first - interval '2 minutes', t.p_last + interval '2 minutes', '[]')) AS rest
  FROM translated t
  GROUP BY t.cid, t.c_first, t.c_last
  UNION ALL
  SELECT t.sid,
         tstzmultirange(tstzrange(least(t.s_first, t.s_last), greatest(t.s_first, t.s_last), '[]'))
           - range_agg(tstzrange(t.p_first - interval '2 minutes', t.p_last + interval '2 minutes', '[]'))
  FROM translated t
  WHERE NOT t.snat
  GROUP BY t.sid, t.s_first, t.s_last
),
-- The periods in which the edges of rest were matched by address, within
-- the margin, as in the rows below: a client edge by a relay that runs an
-- agent, a server edge by a client that reached it directly.
by_addr AS (
  SELECT r.id,
         range_agg(tstzrange(least(y.first_seen, y.last_seen) - interval '2 minutes',
                             greatest(y.first_seen, y.last_seen) + interval '2 minutes', '[]')) AS matched
  FROM rest r
  JOIN e x ON x.id = r.id
  JOIN e y
    ON  y.role <> x.role AND y.proto = x.proto AND y.port = x.port
    AND y.local_addr = x.remote_addr AND y.remote_addr = x.local_addr AND y.scope = x.scope
  GROUP BY r.id
),
-- The row of its own of an edge matched through translations: from the
-- start of the edge, so that a side that stops observing does not make its
-- other side look new, to the end of the last part left that no row by
-- address covers either. It is shown if such a part is left, in [since,
-- until]. by_addr tells that the edge also has rows matched by address.
own AS (
  SELECT x.id, upper(x.rest) AS last_seen, x.by_addr,
         EXISTS (SELECT FROM unnest(x.rest) AS g WHERE g && tstzrange(since, until, '[]')) AS shown
  FROM (SELECT r.id, r.rest - coalesce(a.matched, '{}') AS rest, a.id IS NOT NULL AS by_addr
        FROM rest r LEFT JOIN by_addr a ON a.id = r.id) x
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
  r.first_seen,
  r.last_seen,
  CASE WHEN c.id IS NOT NULL AND s.id IS NOT NULL THEN 'both'
       WHEN c.id IS NOT NULL THEN 'client'
       ELSE 'server' END                        AS observed_by,
  CASE WHEN oc.id IS NOT NULL AND c.last_seen > r.last_seen + interval '2 minutes' THEN NULL
       ELSE co.observed_until END               AS client_observed_until,
  CASE WHEN os.id IS NOT NULL AND s.last_seen > r.last_seen + interval '2 minutes' THEN NULL
       ELSE so.observed_until END               AS server_observed_until,
  NULL::inet                                    AS virtual_addr,
  NULL::integer                                 AS virtual_port,
  NULL::text                                    AS translation,
  NULL::text                                    AS path
FROM (SELECT * FROM e WHERE role = 'client') c
FULL JOIN (SELECT * FROM e WHERE role = 'server') s
  ON  c.local_addr = s.remote_addr
  AND c.remote_addr = s.local_addr
  AND c.port = s.port
  AND c.proto = s.proto
  AND c.scope = s.scope
LEFT JOIN observed co ON co.host_id = c.host_id
LEFT JOIN observed so ON so.host_id = s.host_id
-- An edge matched through translations keeps a row of its own if its
-- matched rows below leave a part of it. Matched by address as well, its
-- row has the period of the other edge, which was matched by address only
-- (a relay that runs an agent served the client edge then; the client
-- reached the server edge directly then), or the period both were active
-- in if both were matched through translations, and the part that neither
-- covers is a row of its own below. As on the rows below, the observation
-- of a side whose edge outlives the row tells nothing of the end of the
-- row.
LEFT JOIN own oc ON oc.id = c.id
LEFT JOIN own os ON os.id = s.id
CROSS JOIN LATERAL (
  SELECT CASE WHEN c.id IS NULL OR s.id IS NULL OR (oc.id IS NULL AND os.id IS NULL)
                THEN least(c.first_seen, s.first_seen)
              WHEN os.id IS NULL THEN s.first_seen
              WHEN oc.id IS NULL THEN c.first_seen
              ELSE least(greatest(c.first_seen, s.first_seen), least(c.last_seen, s.last_seen)) END AS first_seen,
         CASE WHEN s.id IS NULL AND oc.id IS NOT NULL THEN oc.last_seen
              WHEN c.id IS NULL AND os.id IS NOT NULL THEN os.last_seen
              WHEN c.id IS NULL OR s.id IS NULL OR (oc.id IS NULL AND os.id IS NULL)
                THEN greatest(c.last_seen, s.last_seen)
              WHEN os.id IS NULL THEN s.last_seen
              WHEN oc.id IS NULL THEN c.last_seen
              ELSE greatest(greatest(c.first_seen, s.first_seen), least(c.last_seen, s.last_seen)) END AS last_seen
) r
WHERE NOT (s.id IS NULL AND oc.id IS NOT NULL AND NOT oc.shown)
  AND NOT (c.id IS NULL AND os.id IS NOT NULL AND NOT os.shown)
UNION ALL
-- The observation of a side whose edge outlives the row tells nothing of
-- the end of the row: the client edge went on to other backends, or the
-- server edge served other clients.
SELECT
  t.c_hostname, t.c_service, t.c_unit, t.c_local,
  t.s_hostname, t.s_service, t.s_unit, t.s_local,
  t.s_port, t.proto, t.p_first, t.p_last, 'both',
  CASE WHEN t.c_last <= t.p_last + interval '2 minutes' THEN co.observed_until END,
  CASE WHEN t.s_last <= t.p_last + interval '2 minutes' THEN so.observed_until END,
  t.c_remote, t.c_port, t.translation, NULL::text
FROM translated t
LEFT JOIN observed co ON co.host_id = t.c_host_id
LEFT JOIN observed so ON so.host_id = t.s_host_id
UNION ALL
-- The row of its own of an edge matched through translations and by
-- address, for the part of its period that neither covers: a client edge
-- that a relay with an agent served for a while also reached backends
-- without an agent, a server edge that served a client directly and
-- through a translation also served it when its agent did not run.
SELECT
  CASE WHEN x.role = 'client' THEN x.hostname END,
  CASE WHEN x.role = 'client' THEN x.service_name END,
  CASE WHEN x.role = 'client' THEN x.unit END,
  CASE WHEN x.role = 'client' THEN x.local_addr ELSE x.remote_addr END,
  CASE WHEN x.role = 'server' THEN x.hostname END,
  CASE WHEN x.role = 'server' THEN x.service_name END,
  CASE WHEN x.role = 'server' THEN x.unit END,
  CASE WHEN x.role = 'client' THEN x.remote_addr ELSE x.local_addr END,
  x.port, x.proto, x.first_seen, o.last_seen, x.role,
  CASE WHEN x.role = 'client' AND x.last_seen <= o.last_seen + interval '2 minutes' THEN ob.observed_until END,
  CASE WHEN x.role = 'server' AND x.last_seen <= o.last_seen + interval '2 minutes' THEN ob.observed_until END,
  NULL::inet, NULL::integer, NULL::text, NULL::text
FROM own o
JOIN e x ON x.id = o.id
LEFT JOIN observed ob ON ob.host_id = x.host_id
WHERE o.by_addr AND o.shown
UNION ALL
-- The dependencies over Unix sockets.
SELECT
  u.hostname, u.service_name, u.unit, NULL::inet,
  CASE WHEN o.edge_id IS NOT NULL THEN u.hostname END, ps.service_name, ps.unit, NULL::inet,
  0, 'unix'::text,
  CASE WHEN o.edge_id IS NULL OR o.earliest THEN u.first_seen
       ELSE greatest(u.first_seen, o.first_seen - interval '2 minutes') END,
  CASE WHEN o.edge_id IS NULL OR o.latest THEN u.last_seen
       ELSE least(u.last_seen, o.last_seen + interval '2 minutes') END,
  CASE WHEN o.edge_id IS NULL THEN 'client' ELSE 'both' END,
  ob.observed_until,
  CASE WHEN o.edge_id IS NOT NULL THEN ob.observed_until END,
  NULL::inet, NULL::integer, NULL::text, u.path
FROM ue u
LEFT JOIN uo o ON o.edge_id = u.id
LEFT JOIN shawk.processes ps ON ps.id = o.process_id
LEFT JOIN observed ob ON ob.host_id = u.host_id
)
SELECT * FROM d WHERE d.last_seen >= since AND d.first_seen <= until
$$;

-- The same over the whole history, as shawk_v1.dependencies of
-- 0001_schema.sql: its matching is kept the same as that of the function.
CREATE OR REPLACE VIEW shawk_v1.dependencies AS
WITH shared AS (SELECT addr FROM shawk.shared_addrs),
e AS (
  SELECT e.id, e.host_id, e.role, e.proto, e.local_addr, e.remote_addr, e.port, e.netns,
         e.first_seen, e.last_seen, p.service_name, p.unit, h.hostname,
         -- The scope in which the addresses of the edge identify its other
         -- side: the host and network namespace for a loopback address on
         -- either side, as both sides of a connection have the same
         -- addresses, the host for shared addresses, everywhere ('')
         -- otherwise.
         CASE WHEN e.local_addr << inet '127.0.0.0/8' OR e.local_addr = inet '::1'
                OR e.remote_addr << inet '127.0.0.0/8' OR e.remote_addr = inet '::1'
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
-- The client edges of Unix sockets, and the owners of the listeners of
-- their names on their hosts that overlap them: those in the namespace of
-- the client if any, else, for a path, those of the only namespace that has
-- any. An abstract name (@) is reached in the namespace of its client only.
-- earliest and latest tell the first and the last owner of each edge.
ue AS (
  SELECT u.id, u.host_id, u.path, u.netns, u.first_seen, u.last_seen, p.service_name, p.unit, h.hostname
  FROM shawk.unix_edges u
  JOIN shawk.processes p ON p.id = u.process_id
  JOIN shawk.hosts h ON h.id = u.host_id
),
uo AS (
  SELECT x.edge_id, x.process_id, x.first_seen, x.last_seen,
         row_number() OVER (PARTITION BY x.edge_id ORDER BY x.first_seen, x.process_id) = 1 AS earliest,
         row_number() OVER (PARTITION BY x.edge_id ORDER BY x.last_seen DESC, x.process_id) = 1 AS latest
  FROM (
    SELECT ue.id AS edge_id, l.process_id, l.first_seen, l.last_seen, l.netns = ue.netns AS in_netns,
           left(ue.path, 1) = '@' AS abstract,
           bool_or(l.netns = ue.netns) OVER w AS any_in_netns,
           min(l.netns) OVER w = max(l.netns) OVER w AS one_netns
    FROM ue
    JOIN shawk.unix_listeners l
      ON  l.host_id = ue.host_id AND l.path = ue.path
      AND l.first_seen <= ue.last_seen + interval '2 minutes'
      AND ue.first_seen <= l.last_seen + interval '2 minutes'
    WINDOW w AS (PARTITION BY ue.id)
  ) x
  WHERE x.in_netns OR (NOT x.any_in_netns AND x.one_netns AND NOT x.abstract)
),
-- Client edges to a virtual address, read through the index of client
-- edges. client_scope is the scope of the address of the client alone,
-- which is all the two sides of a connection through a translation share.
-- direct is when server edges at the virtual address matched the client
-- edge by address, within the margin: a relay that runs an agent served
-- it then, rather than the backends.
cv AS (
  SELECT DISTINCT ON (c.id, v.name)
         c.id, c.host_id, c.proto, c.local_addr, c.remote_addr, c.port, c.first_seen, c.last_seen,
         p.service_name, p.unit, h.hostname, v.name AS translation,
         CASE WHEN c.local_addr << inet '127.0.0.0/8' OR c.local_addr = inet '::1'
                THEN c.host_id || '/' || c.netns::text
              WHEN c.local_addr IN (SELECT addr FROM shared)
                THEN c.host_id
              ELSE '' END AS client_scope,
         (SELECT range_agg(tstzrange(least(s.first_seen, s.last_seen) - interval '2 minutes',
                                     greatest(s.first_seen, s.last_seen) + interval '2 minutes', '[]'))
          FROM shawk.edges s
          WHERE s.role = 'server' AND s.proto = c.proto AND s.local_addr = c.remote_addr AND s.port = c.port
            AND s.remote_addr = c.local_addr
            AND CASE WHEN s.local_addr << inet '127.0.0.0/8' OR s.local_addr = inet '::1'
                        OR s.remote_addr << inet '127.0.0.0/8' OR s.remote_addr = inet '::1'
                        THEN s.host_id || '/' || s.netns::text
                      WHEN s.local_addr IN (SELECT addr FROM shared) OR s.remote_addr IN (SELECT addr FROM shared)
                        THEN s.host_id
                      ELSE '' END
              = CASE WHEN c.local_addr << inet '127.0.0.0/8' OR c.local_addr = inet '::1'
                        OR c.remote_addr << inet '127.0.0.0/8' OR c.remote_addr = inet '::1'
                        THEN c.host_id || '/' || c.netns::text
                      WHEN c.local_addr IN (SELECT addr FROM shared) OR c.remote_addr IN (SELECT addr FROM shared)
                        THEN c.host_id
                      ELSE '' END) AS direct
  FROM shawk.translations v
  JOIN shawk.edges c
    ON c.role = 'client' AND c.proto = v.proto AND c.remote_addr = v.addr AND v.port IN (0, c.port)
  JOIN shawk.processes p ON p.id = c.process_id
  JOIN shawk.hosts h ON h.id = c.host_id
  WHERE v.side = 'virtual'
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
-- Learned translations (shawk.learned_translations): a client edge c and a
-- server edge s match the rows of hosts that translated the connections
-- of the client of c to its server address and port into the backend of
-- s, seen from the peer of s; a loopback client or virtual address is in
-- the host and namespace of the row, a shared client address on its host,
-- and any other anywhere, and so are the backend and the source. A client
-- edge to a virtual address of a static translation is matched through it
-- only. The rows that overlap c and s, within 2 minutes, are combined: the
-- period of the pair is the part of those of c and s that their span
-- covers.
lc AS (
  SELECT c.id, c.proto, c.first_seen AS c_first, c.last_seen AS c_last,
         l.host_id AS l_host, l.netns AS l_netns, l.source_addr, l.backend_addr, l.backend_port,
         l.first_seen AS l_first, l.last_seen AS l_last
  FROM shawk.learned_translations l
  JOIN shawk.edges c
    ON  c.role = 'client' AND c.proto = l.proto AND c.remote_addr = l.virtual_addr AND c.port = l.virtual_port
    AND c.local_addr = l.client_addr
  WHERE CASE WHEN c.local_addr << inet '127.0.0.0/8' OR c.local_addr = inet '::1'
                  OR c.remote_addr << inet '127.0.0.0/8' OR c.remote_addr = inet '::1'
               THEN c.host_id = l.host_id AND c.netns = l.netns
             WHEN c.local_addr IN (SELECT addr FROM shared) THEN c.host_id = l.host_id
             ELSE true END
    AND c.first_seen <= l.last_seen + interval '2 minutes'
    AND l.first_seen <= c.last_seen + interval '2 minutes'
    AND NOT EXISTS (
      SELECT FROM shawk.translations v
      WHERE v.side = 'virtual' AND v.proto = c.proto AND v.addr = c.remote_addr AND v.port IN (0, c.port))
),
lp AS (
  SELECT lc.id AS cid, s.id AS sid, min(lc.l_first) AS l_first, max(lc.l_last) AS l_last
  FROM lc
  JOIN shawk.edges s
    ON  s.role = 'server' AND s.proto = lc.proto AND s.local_addr = lc.backend_addr AND s.port = lc.backend_port
    AND s.remote_addr = lc.source_addr
  WHERE CASE WHEN s.local_addr << inet '127.0.0.0/8' OR s.local_addr = inet '::1'
                  OR s.remote_addr << inet '127.0.0.0/8' OR s.remote_addr = inet '::1'
               THEN s.host_id = lc.l_host AND s.netns = lc.l_netns
             WHEN s.local_addr IN (SELECT addr FROM shared) OR s.remote_addr IN (SELECT addr FROM shared)
               THEN s.host_id = lc.l_host
             ELSE true END
    AND s.first_seen <= lc.l_last + interval '2 minutes'
    AND lc.l_first <= s.last_seen + interval '2 minutes'
    AND s.first_seen <= lc.c_last + interval '2 minutes'
    AND lc.c_first <= s.last_seen + interval '2 minutes'
  GROUP BY lc.id, s.id
),
-- The client and server edges a translation may match: on the port of the
-- backend or the port of the client edge, with times that overlap; through
-- a translation without sources, with the address of the client. p_first
-- and p_last are the period both were active in.
pairs AS (
  SELECT cv.id AS cid, cv.host_id AS c_host_id, cv.hostname AS c_hostname, cv.service_name AS c_service,
         cv.unit AS c_unit, cv.local_addr AS c_local, cv.remote_addr AS c_remote, cv.port AS c_port,
         cv.first_seen AS c_first, cv.last_seen AS c_last, cv.direct,
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
         cv.first_seen, cv.last_seen, cv.direct,
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
  UNION ALL
  SELECT c.id, c.host_id, hc.hostname, pc.service_name, pc.unit, c.local_addr, c.remote_addr, c.port,
         c.first_seen, c.last_seen,
         -- direct, as for the client edges of static translations.
         (SELECT range_agg(tstzrange(least(d.first_seen, d.last_seen) - interval '2 minutes',
                                     greatest(d.first_seen, d.last_seen) + interval '2 minutes', '[]'))
          FROM shawk.edges d
          WHERE d.role = 'server' AND d.proto = c.proto AND d.local_addr = c.remote_addr AND d.port = c.port
            AND d.remote_addr = c.local_addr
            AND CASE WHEN d.local_addr << inet '127.0.0.0/8' OR d.local_addr = inet '::1'
                        OR d.remote_addr << inet '127.0.0.0/8' OR d.remote_addr = inet '::1'
                        THEN d.host_id || '/' || d.netns::text
                      WHEN d.local_addr IN (SELECT addr FROM shared) OR d.remote_addr IN (SELECT addr FROM shared)
                        THEN d.host_id
                      ELSE '' END
              = CASE WHEN c.local_addr << inet '127.0.0.0/8' OR c.local_addr = inet '::1'
                        OR c.remote_addr << inet '127.0.0.0/8' OR c.remote_addr = inet '::1'
                        THEN c.host_id || '/' || c.netns::text
                      WHEN c.local_addr IN (SELECT addr FROM shared) OR c.remote_addr IN (SELECT addr FROM shared)
                        THEN c.host_id
                      ELSE '' END),
         s.id, s.host_id, hs.hostname, ps.service_name, ps.unit, s.local_addr, s.port,
         s.first_seen, s.last_seen,
         c.proto, '~learned'::text, s.remote_addr <> c.local_addr,
         least(greatest(c.first_seen, s.first_seen, lp.l_first), least(c.last_seen, s.last_seen, lp.l_last)),
         greatest(greatest(c.first_seen, s.first_seen, lp.l_first), least(c.last_seen, s.last_seen, lp.l_last))
  FROM lp
  JOIN shawk.edges c ON c.id = lp.cid
  JOIN shawk.processes pc ON pc.id = c.process_id
  JOIN shawk.hosts hc ON hc.id = c.host_id
  JOIN shawk.edges s ON s.id = lp.sid
  JOIN shawk.processes ps ON ps.id = s.process_id
  JOIN shawk.hosts hs ON hs.id = s.host_id
),
-- The pairs matched through a translation: not those that a relay with an
-- agent served all along, which the client edge matches by address.
translated AS (
  SELECT * FROM pairs t
  WHERE t.direct IS NULL OR NOT t.direct @> tstzrange(t.p_first, t.p_last, '[]')
),
-- What is left of the period of an edge matched through translations
-- that its matched rows do not cover, within the margin: a client edge
-- also reached backends without an agent, or before their agents started,
-- and a server edge through a translation without sources served the
-- client directly. A server edge from a source keeps its own row whole,
-- since clients without an agent may be behind the relay.
rest AS (
  SELECT t.cid AS id,
         tstzmultirange(tstzrange(least(t.c_first, t.c_last), greatest(t.c_first, t.c_last), '[]'))
           - range_agg(tstzrange(t.p_first - interval '2 minutes', t.p_last + interval '2 minutes', '[]')) AS rest
  FROM translated t
  GROUP BY t.cid, t.c_first, t.c_last
  UNION ALL
  SELECT t.sid,
         tstzmultirange(tstzrange(least(t.s_first, t.s_last), greatest(t.s_first, t.s_last), '[]'))
           - range_agg(tstzrange(t.p_first - interval '2 minutes', t.p_last + interval '2 minutes', '[]'))
  FROM translated t
  WHERE NOT t.snat
  GROUP BY t.sid, t.s_first, t.s_last
),
-- The periods in which the edges of rest were matched by address, within
-- the margin, as in the rows below: a client edge by a relay that runs an
-- agent, a server edge by a client that reached it directly.
by_addr AS (
  SELECT r.id,
         range_agg(tstzrange(least(y.first_seen, y.last_seen) - interval '2 minutes',
                             greatest(y.first_seen, y.last_seen) + interval '2 minutes', '[]')) AS matched
  FROM rest r
  JOIN e x ON x.id = r.id
  JOIN e y
    ON  y.role <> x.role AND y.proto = x.proto AND y.port = x.port
    AND y.local_addr = x.remote_addr AND y.remote_addr = x.local_addr AND y.scope = x.scope
  GROUP BY r.id
),
-- The row of its own of an edge matched through translations: from the
-- start of the edge, so that a side that stops observing does not make its
-- other side look new, to the end of the last part left that no row by
-- address covers either. It is shown if such a part is left. by_addr tells
-- that the edge also has rows matched by address.
own AS (
  SELECT x.id, upper(x.rest) AS last_seen, x.by_addr, NOT isempty(x.rest) AS shown
  FROM (SELECT r.id, r.rest - coalesce(a.matched, '{}') AS rest, a.id IS NOT NULL AS by_addr
        FROM rest r LEFT JOIN by_addr a ON a.id = r.id) x
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
  r.first_seen,
  r.last_seen,
  CASE WHEN c.id IS NOT NULL AND s.id IS NOT NULL THEN 'both'
       WHEN c.id IS NOT NULL THEN 'client'
       ELSE 'server' END                        AS observed_by,
  CASE WHEN oc.id IS NOT NULL AND c.last_seen > r.last_seen + interval '2 minutes' THEN NULL
       ELSE co.observed_until END               AS client_observed_until,
  CASE WHEN os.id IS NOT NULL AND s.last_seen > r.last_seen + interval '2 minutes' THEN NULL
       ELSE so.observed_until END               AS server_observed_until,
  NULL::inet                                    AS virtual_addr,
  NULL::integer                                 AS virtual_port,
  NULL::text                                    AS translation,
  NULL::text                                    AS path
FROM (SELECT * FROM e WHERE role = 'client') c
FULL JOIN (SELECT * FROM e WHERE role = 'server') s
  ON  c.local_addr = s.remote_addr
  AND c.remote_addr = s.local_addr
  AND c.port = s.port
  AND c.proto = s.proto
  AND c.scope = s.scope
LEFT JOIN observed co ON co.host_id = c.host_id
LEFT JOIN observed so ON so.host_id = s.host_id
-- An edge matched through translations keeps a row of its own if its
-- matched rows below leave a part of it. Matched by address as well, its
-- row has the period of the other edge, which was matched by address only
-- (a relay that runs an agent served the client edge then; the client
-- reached the server edge directly then), or the period both were active
-- in if both were matched through translations, and the part that neither
-- covers is a row of its own below. As on the rows below, the observation
-- of a side whose edge outlives the row tells nothing of the end of the
-- row.
LEFT JOIN own oc ON oc.id = c.id
LEFT JOIN own os ON os.id = s.id
CROSS JOIN LATERAL (
  SELECT CASE WHEN c.id IS NULL OR s.id IS NULL OR (oc.id IS NULL AND os.id IS NULL)
                THEN least(c.first_seen, s.first_seen)
              WHEN os.id IS NULL THEN s.first_seen
              WHEN oc.id IS NULL THEN c.first_seen
              ELSE least(greatest(c.first_seen, s.first_seen), least(c.last_seen, s.last_seen)) END AS first_seen,
         CASE WHEN s.id IS NULL AND oc.id IS NOT NULL THEN oc.last_seen
              WHEN c.id IS NULL AND os.id IS NOT NULL THEN os.last_seen
              WHEN c.id IS NULL OR s.id IS NULL OR (oc.id IS NULL AND os.id IS NULL)
                THEN greatest(c.last_seen, s.last_seen)
              WHEN os.id IS NULL THEN s.last_seen
              WHEN oc.id IS NULL THEN c.last_seen
              ELSE greatest(greatest(c.first_seen, s.first_seen), least(c.last_seen, s.last_seen)) END AS last_seen
) r
WHERE NOT (s.id IS NULL AND oc.id IS NOT NULL AND NOT oc.shown)
  AND NOT (c.id IS NULL AND os.id IS NOT NULL AND NOT os.shown)
UNION ALL
-- The observation of a side whose edge outlives the row tells nothing of
-- the end of the row: the client edge went on to other backends, or the
-- server edge served other clients.
SELECT
  t.c_hostname, t.c_service, t.c_unit, t.c_local,
  t.s_hostname, t.s_service, t.s_unit, t.s_local,
  t.s_port, t.proto, t.p_first, t.p_last, 'both',
  CASE WHEN t.c_last <= t.p_last + interval '2 minutes' THEN co.observed_until END,
  CASE WHEN t.s_last <= t.p_last + interval '2 minutes' THEN so.observed_until END,
  t.c_remote, t.c_port, t.translation, NULL::text
FROM translated t
LEFT JOIN observed co ON co.host_id = t.c_host_id
LEFT JOIN observed so ON so.host_id = t.s_host_id
UNION ALL
-- The row of its own of an edge matched through translations and by
-- address, for the part of its period that neither covers: a client edge
-- that a relay with an agent served for a while also reached backends
-- without an agent, a server edge that served a client directly and
-- through a translation also served it when its agent did not run.
SELECT
  CASE WHEN x.role = 'client' THEN x.hostname END,
  CASE WHEN x.role = 'client' THEN x.service_name END,
  CASE WHEN x.role = 'client' THEN x.unit END,
  CASE WHEN x.role = 'client' THEN x.local_addr ELSE x.remote_addr END,
  CASE WHEN x.role = 'server' THEN x.hostname END,
  CASE WHEN x.role = 'server' THEN x.service_name END,
  CASE WHEN x.role = 'server' THEN x.unit END,
  CASE WHEN x.role = 'client' THEN x.remote_addr ELSE x.local_addr END,
  x.port, x.proto, x.first_seen, o.last_seen, x.role,
  CASE WHEN x.role = 'client' AND x.last_seen <= o.last_seen + interval '2 minutes' THEN ob.observed_until END,
  CASE WHEN x.role = 'server' AND x.last_seen <= o.last_seen + interval '2 minutes' THEN ob.observed_until END,
  NULL::inet, NULL::integer, NULL::text, NULL::text
FROM own o
JOIN e x ON x.id = o.id
LEFT JOIN observed ob ON ob.host_id = x.host_id
WHERE o.by_addr AND o.shown
UNION ALL
-- The dependencies over Unix sockets.
SELECT
  u.hostname, u.service_name, u.unit, NULL::inet,
  CASE WHEN o.edge_id IS NOT NULL THEN u.hostname END, ps.service_name, ps.unit, NULL::inet,
  0, 'unix'::text,
  CASE WHEN o.edge_id IS NULL OR o.earliest THEN u.first_seen
       ELSE greatest(u.first_seen, o.first_seen - interval '2 minutes') END,
  CASE WHEN o.edge_id IS NULL OR o.latest THEN u.last_seen
       ELSE least(u.last_seen, o.last_seen + interval '2 minutes') END,
  CASE WHEN o.edge_id IS NULL THEN 'client' ELSE 'both' END,
  ob.observed_until,
  CASE WHEN o.edge_id IS NOT NULL THEN ob.observed_until END,
  NULL::inet, NULL::integer, NULL::text, u.path
FROM ue u
LEFT JOIN uo o ON o.edge_id = u.id
LEFT JOIN shawk.processes ps ON ps.id = o.process_id
LEFT JOIN observed ob ON ob.host_id = u.host_id;

-- Hosts in a planned stop now, until when at the latest, as
-- shawk_v1.planned_stops of 0001_schema.sql: in a maintenance window until
-- its end, or in a planned state of their latest read from Slurm until it
-- becomes stale. A stale state, DOWN or DRAIN stop nothing: alerts on
-- stopped agents exclude these hosts only. A MAINT reservation (which may
-- be unlimited) stops them for 30 days at most, as the longest window of
-- the maintenance_file, counted from the first of the states with MAINT
-- that follow each other, whatever their other flags and reasons. A state
-- follows the one before if it was read while that one was fresh: a
-- reservation read after a gap in which the states became stale, such as
-- one of a node left out of the file for a while, counts from its own
-- start. The states read in the last 31 days suffice to find it: the first
-- of them follows one read before.
CREATE OR REPLACE VIEW shawk_v1.planned_stops AS
SELECT w.hostname AS host, 'maintenance'::text AS cause, lower(w.period) AS since, upper(w.period) AS until, w.reason
FROM shawk.maintenance_periods w
WHERE w.period @> now()
UNION ALL
SELECT s.hostname, s.cause, s.since, s.last_seen + shawk.node_state_max_age(), s.reason
FROM (
  SELECT DISTINCT ON (r.hostname) r.hostname, r.first_seen, r.cause, r.last_seen, r.reason,
         CASE WHEN r.cause = 'maintenance'
              THEN min(r.first_seen) FILTER (WHERE r.cause = 'maintenance') OVER (PARTITION BY r.hostname, r.run)
              ELSE r.first_seen END AS since
  FROM (
    SELECT n.*,
           -- states with MAINT that follow each other share a run (with
           -- the state before them, which the minimum leaves out); one read
           -- after the state before became stale starts a run
           count(*) FILTER (WHERE n.cause IS DISTINCT FROM 'maintenance' OR n.after_stale)
             OVER (PARTITION BY n.hostname ORDER BY n.first_seen) AS run
    FROM (
      SELECT n.hostname, n.first_seen, n.last_seen, n.reason, shawk.planned_state(n.state) AS cause,
             lag(n.last_seen) OVER (PARTITION BY n.hostname ORDER BY n.first_seen)
               + shawk.node_state_max_age() < n.first_seen AS after_stale
      FROM shawk.node_states n
      WHERE n.last_seen > now() - interval '31 days'
    ) n
  ) r
  ORDER BY r.hostname, r.first_seen DESC
) s
WHERE s.last_seen + shawk.node_state_max_age() > now()
  AND s.cause IS NOT NULL
  AND (s.cause <> 'maintenance' OR s.since > now() - interval '30 days');
