-- Translations of addresses learned by the agents of the hosts that make
-- them (#107, phase 2).
--
-- The agent of a host that translates addresses (DNAT of Docker published
-- ports and of kube-proxy, IPVS with net.ipv4.vs.conntrack=1, SNAT and
-- masquerade) learns its translations from conntrack and sends them; the
-- connector writes them here, with the times of the agent, like edges. A
-- row tells that the client connected to the virtual address and port, and
-- that the backend saw the connection from the source on the backend port:
-- the source is the client unless the host replaced its address.
--
-- The views match edges through them like static translations (migration
-- 12); their result keeps its columns, so the function and the view are
-- replaced in place, and the views and functions on them follow.
CREATE TABLE shawk.learned_translations (
  host_id      text    NOT NULL REFERENCES shawk.hosts,
  proto        text    NOT NULL CHECK (proto IN ('tcp', 'udp')),
  netns        bigint  NOT NULL,
  client_addr  inet    NOT NULL,
  virtual_addr inet    NOT NULL,
  virtual_port integer NOT NULL CHECK (virtual_port BETWEEN 0 AND 65535),
  source_addr  inet    NOT NULL,
  backend_addr inet    NOT NULL,
  backend_port integer NOT NULL CHECK (backend_port BETWEEN 0 AND 65535),
  first_seen   timestamptz NOT NULL,
  last_seen    timestamptz NOT NULL,
  PRIMARY KEY (host_id, proto, netns, client_addr, virtual_addr, virtual_port, source_addr, backend_addr, backend_port)
);
CREATE INDEX learned_translations_client ON shawk.learned_translations (proto, virtual_addr, virtual_port, client_addr);
CREATE INDEX learned_translations_server ON shawk.learned_translations (proto, backend_addr, backend_port, source_addr);
CREATE INDEX learned_translations_last_seen ON shawk.learned_translations (last_seen);

-- The retention covers the learned translations, and keeps a host while it
-- has some.
CREATE OR REPLACE FUNCTION shawk.prune(cutoff timestamptz, max_rows integer DEFAULT 10000) RETURNS bigint
LANGUAGE plpgsql AS $$
DECLARE
  n bigint;
  total bigint := 0;
  -- Without grants.sql run again after this migration, the role of the
  -- connector may not read the learned translations: the retention goes on
  -- without them, and keeps the hosts.
  -- (has_table_privilege with a list is true if any of them is held.)
  learned boolean := has_table_privilege('shawk.learned_translations', 'SELECT')
                     AND has_table_privilege('shawk.learned_translations', 'DELETE');
BEGIN
  PERFORM pg_advisory_xact_lock_shared(1936220535);  -- 0x73686177, see Migrate

  DELETE FROM shawk.edges WHERE last_seen < cutoff AND id IN (
    SELECT id FROM shawk.edges WHERE last_seen < cutoff LIMIT max_rows);
  GET DIAGNOSTICS n = ROW_COUNT; total := total + n;

  DELETE FROM shawk.listeners WHERE last_seen < cutoff AND ctid IN (
    SELECT ctid FROM shawk.listeners WHERE last_seen < cutoff LIMIT max_rows);
  GET DIAGNOSTICS n = ROW_COUNT; total := total + n;

  DELETE FROM shawk.listener_owners WHERE last_seen < cutoff AND ctid IN (
    SELECT ctid FROM shawk.listener_owners WHERE last_seen < cutoff LIMIT max_rows);
  GET DIAGNOSTICS n = ROW_COUNT; total := total + n;

  DELETE FROM shawk.host_addrs WHERE last_seen < cutoff AND ctid IN (
    SELECT ctid FROM shawk.host_addrs WHERE last_seen < cutoff LIMIT max_rows);
  GET DIAGNOSTICS n = ROW_COUNT; total := total + n;

  DELETE FROM shawk.agent_sessions WHERE last_heartbeat < cutoff AND ctid IN (
    SELECT ctid FROM shawk.agent_sessions WHERE last_heartbeat < cutoff LIMIT max_rows);
  GET DIAGNOSTICS n = ROW_COUNT; total := total + n;

  DELETE FROM shawk.partial_observations WHERE period_end < cutoff AND ctid IN (
    SELECT ctid FROM shawk.partial_observations WHERE period_end < cutoff LIMIT max_rows);
  GET DIAGNOSTICS n = ROW_COUNT; total := total + n;

  IF learned THEN
    DELETE FROM shawk.learned_translations WHERE last_seen < cutoff AND ctid IN (
      SELECT ctid FROM shawk.learned_translations WHERE last_seen < cutoff LIMIT max_rows);
    GET DIAGNOSTICS n = ROW_COUNT; total := total + n;
  END IF;

  DELETE FROM shawk.known_dependencies WHERE last_seen < cutoff AND ctid IN (
    SELECT ctid FROM shawk.known_dependencies WHERE last_seen < cutoff LIMIT max_rows);
  GET DIAGNOSTICS n = ROW_COUNT; total := total + n;

  DELETE FROM shawk.processes p WHERE p.last_seen < cutoff
    AND NOT EXISTS (SELECT FROM shawk.edges e WHERE e.process_id = p.id)
    AND NOT EXISTS (SELECT FROM shawk.listeners l WHERE l.process_id = p.id)
    AND NOT EXISTS (SELECT FROM shawk.listener_owners o WHERE o.process_id = p.id)
    AND p.id IN (
      SELECT p2.id FROM shawk.processes p2
      WHERE p2.last_seen < cutoff
        AND NOT EXISTS (SELECT FROM shawk.edges e WHERE e.process_id = p2.id)
        AND NOT EXISTS (SELECT FROM shawk.listeners l WHERE l.process_id = p2.id)
        AND NOT EXISTS (SELECT FROM shawk.listener_owners o WHERE o.process_id = p2.id)
      LIMIT max_rows);
  GET DIAGNOSTICS n = ROW_COUNT; total := total + n;

  IF learned THEN
    DELETE FROM shawk.hosts h WHERE h.last_seen < cutoff
      AND NOT EXISTS (SELECT FROM shawk.agent_sessions s WHERE s.host_id = h.id)
      AND NOT EXISTS (SELECT FROM shawk.partial_observations o WHERE o.host_id = h.id)
      AND NOT EXISTS (SELECT FROM shawk.host_addrs a WHERE a.host_id = h.id)
      AND NOT EXISTS (SELECT FROM shawk.processes p WHERE p.host_id = h.id)
      AND NOT EXISTS (SELECT FROM shawk.edges e WHERE e.host_id = h.id)
      AND NOT EXISTS (SELECT FROM shawk.listeners l WHERE l.host_id = h.id)
      AND NOT EXISTS (SELECT FROM shawk.listener_owners o WHERE o.host_id = h.id)
      AND NOT EXISTS (SELECT FROM shawk.learned_translations t WHERE t.host_id = h.id)
      AND h.id IN (SELECT h2.id FROM shawk.hosts h2 WHERE h2.last_seen < cutoff LIMIT max_rows);
    GET DIAGNOSTICS n = ROW_COUNT; total := total + n;
  END IF;

  RETURN total;
END
$$;

CREATE OR REPLACE FUNCTION shawk_v1.dependencies_between(since timestamptz, until timestamptz)
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
            AND CASE WHEN s.remote_addr << inet '127.0.0.0/8' OR s.remote_addr = inet '::1'
                        THEN s.host_id || '/' || s.netns::text
                      WHEN s.local_addr IN (SELECT addr FROM shared) OR s.remote_addr IN (SELECT addr FROM shared)
                        THEN s.host_id
                      ELSE '' END
              = CASE WHEN c.remote_addr << inet '127.0.0.0/8' OR c.remote_addr = inet '::1'
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
-- s, seen from the peer of s; the client address is loopback in the host
-- and namespace of the row, shared on its host, anywhere otherwise, and so
-- are the backend and the source. A client edge to a virtual address of a
-- static translation is matched through it only. The rows that overlap c
-- and s, within 2 minutes, are combined: the period of the pair is the
-- part of those of c and s that their span covers.
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
            AND CASE WHEN d.remote_addr << inet '127.0.0.0/8' OR d.remote_addr = inet '::1'
                        THEN d.host_id || '/' || d.netns::text
                      WHEN d.local_addr IN (SELECT addr FROM shared) OR d.remote_addr IN (SELECT addr FROM shared)
                        THEN d.host_id
                      ELSE '' END
              = CASE WHEN c.remote_addr << inet '127.0.0.0/8' OR c.remote_addr = inet '::1'
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
-- The row of its own of an edge matched through translations: from the
-- start of the edge, so that a side that stops observing does not make its
-- other side look new, to the end of the last part left. It is shown if a
-- part is left, in [since, until].
own AS (
  SELECT x.id, upper(x.rest) AS last_seen,
         EXISTS (SELECT FROM unnest(x.rest) AS g WHERE g && tstzrange(since, until, '[]')) AS shown
  FROM rest x
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
  CASE WHEN oc.id IS NOT NULL AND s.id IS NOT NULL THEN s.first_seen
       ELSE least(c.first_seen, s.first_seen) END AS first_seen,
  CASE WHEN oc.id IS NOT NULL AND s.id IS NULL THEN oc.last_seen
       WHEN os.id IS NOT NULL THEN os.last_seen
       WHEN oc.id IS NOT NULL THEN s.last_seen
       ELSE greatest(c.last_seen, s.last_seen) END AS last_seen,
  CASE WHEN c.id IS NOT NULL AND s.id IS NOT NULL THEN 'both'
       WHEN c.id IS NOT NULL THEN 'client'
       ELSE 'server' END                        AS observed_by,
  CASE WHEN oc.id IS NOT NULL
        AND c.last_seen > coalesce(s.last_seen, oc.last_seen) + interval '2 minutes' THEN NULL
       ELSE co.observed_until END               AS client_observed_until,
  CASE WHEN os.id IS NOT NULL AND s.last_seen > os.last_seen + interval '2 minutes' THEN NULL
       ELSE so.observed_until END               AS server_observed_until,
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
-- An edge matched through translations keeps a row of its own if its
-- matched rows below leave a part of it; a server edge that a client edge
-- also matched through a translation matches by address over its own
-- period, since the client edge also reached the backends. As on the rows
-- below, the observation of a side whose edge outlives the row tells
-- nothing of the end of the row.
LEFT JOIN own oc ON oc.id = c.id
LEFT JOIN own os ON os.id = s.id AND c.id IS NULL
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
  t.c_remote, t.c_port, t.translation
FROM translated t
LEFT JOIN observed co ON co.host_id = t.c_host_id
LEFT JOIN observed so ON so.host_id = t.s_host_id
)
SELECT * FROM d WHERE d.last_seen >= since AND d.first_seen <= until
$$;

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
            AND CASE WHEN s.remote_addr << inet '127.0.0.0/8' OR s.remote_addr = inet '::1'
                        THEN s.host_id || '/' || s.netns::text
                      WHEN s.local_addr IN (SELECT addr FROM shared) OR s.remote_addr IN (SELECT addr FROM shared)
                        THEN s.host_id
                      ELSE '' END
              = CASE WHEN c.remote_addr << inet '127.0.0.0/8' OR c.remote_addr = inet '::1'
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
-- s, seen from the peer of s; the client address is loopback in the host
-- and namespace of the row, shared on its host, anywhere otherwise, and so
-- are the backend and the source. A client edge to a virtual address of a
-- static translation is matched through it only. The rows that overlap c
-- and s, within 2 minutes, are combined: the period of the pair is the
-- part of those of c and s that their span covers.
lc AS (
  SELECT c.id, c.proto, c.first_seen AS c_first, c.last_seen AS c_last,
         l.host_id AS l_host, l.netns AS l_netns, l.source_addr, l.backend_addr, l.backend_port,
         l.first_seen AS l_first, l.last_seen AS l_last
  FROM shawk.learned_translations l
  JOIN shawk.edges c
    ON  c.role = 'client' AND c.proto = l.proto AND c.remote_addr = l.virtual_addr AND c.port = l.virtual_port
    AND c.local_addr = l.client_addr
  WHERE CASE WHEN c.local_addr << inet '127.0.0.0/8' OR c.local_addr = inet '::1'
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
            AND CASE WHEN d.remote_addr << inet '127.0.0.0/8' OR d.remote_addr = inet '::1'
                        THEN d.host_id || '/' || d.netns::text
                      WHEN d.local_addr IN (SELECT addr FROM shared) OR d.remote_addr IN (SELECT addr FROM shared)
                        THEN d.host_id
                      ELSE '' END
              = CASE WHEN c.remote_addr << inet '127.0.0.0/8' OR c.remote_addr = inet '::1'
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
-- The row of its own of an edge matched through translations: from the
-- start of the edge, so that a side that stops observing does not make its
-- other side look new, to the end of the last part left. It is shown if a
-- part is left.
own AS (
  SELECT x.id, upper(x.rest) AS last_seen, NOT isempty(x.rest) AS shown FROM rest x
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
  CASE WHEN oc.id IS NOT NULL AND s.id IS NOT NULL THEN s.first_seen
       ELSE least(c.first_seen, s.first_seen) END AS first_seen,
  CASE WHEN oc.id IS NOT NULL AND s.id IS NULL THEN oc.last_seen
       WHEN os.id IS NOT NULL THEN os.last_seen
       WHEN oc.id IS NOT NULL THEN s.last_seen
       ELSE greatest(c.last_seen, s.last_seen) END AS last_seen,
  CASE WHEN c.id IS NOT NULL AND s.id IS NOT NULL THEN 'both'
       WHEN c.id IS NOT NULL THEN 'client'
       ELSE 'server' END                        AS observed_by,
  CASE WHEN oc.id IS NOT NULL
        AND c.last_seen > coalesce(s.last_seen, oc.last_seen) + interval '2 minutes' THEN NULL
       ELSE co.observed_until END               AS client_observed_until,
  CASE WHEN os.id IS NOT NULL AND s.last_seen > os.last_seen + interval '2 minutes' THEN NULL
       ELSE so.observed_until END               AS server_observed_until,
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
-- An edge matched through translations keeps a row of its own if its
-- matched rows below leave a part of it; a server edge that a client edge
-- also matched through a translation matches by address over its own
-- period, since the client edge also reached the backends. As on the rows
-- below, the observation of a side whose edge outlives the row tells
-- nothing of the end of the row.
LEFT JOIN own oc ON oc.id = c.id
LEFT JOIN own os ON os.id = s.id AND c.id IS NULL
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
  t.c_remote, t.c_port, t.translation
FROM translated t
LEFT JOIN observed co ON co.host_id = t.c_host_id
LEFT JOIN observed so ON so.host_id = t.s_host_id;
