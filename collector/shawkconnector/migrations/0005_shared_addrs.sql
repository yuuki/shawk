-- Addresses that several hosts held at overlapping times, such as the
-- gateway of a container bridge (172.17.0.1 on every Docker host). An edge
-- with such an address is matched with edges of the same host only. The
-- periods are widened by the alive window, since a host writes its
-- addresses once per write interval.
CREATE VIEW shawk.shared_addrs AS
SELECT DISTINCT a.addr
FROM shawk.host_addrs a
JOIN shawk.host_addrs b
  ON b.addr = a.addr AND b.host_id > a.host_id
 AND b.first_seen <= a.last_seen + shawk.alive_window()
 AND a.first_seen <= b.last_seen + shawk.alive_window();

-- The scope in which the addresses of an edge identify its other side:
-- the host and network namespace for loopback, the host for shared
-- addresses, everywhere ('') otherwise.
CREATE OR REPLACE VIEW shawk_v1.dependencies AS
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

-- Replaced by the scope above.
DROP FUNCTION shawk.addr_scope(inet, text, bigint);
