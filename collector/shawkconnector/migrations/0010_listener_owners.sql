-- One row per owner of a listener (#98). The listeners table kept only the
-- latest owner of a listener, so the processes that listened on a port
-- before it changed hands were lost. A listener whose owner is unknown has a
-- row of its own.
ALTER TABLE shawk.listeners DROP CONSTRAINT listeners_pkey;
CREATE UNIQUE INDEX listeners_owner
  ON shawk.listeners (host_id, proto, addr, port, netns, (coalesce(process_id, 0)));

-- service_endpoints: from the latest owner of each listener, as before.
CREATE OR REPLACE VIEW shawk_v1.service_endpoints AS
WITH latest AS (
  SELECT host_id, max(last_seen) AS last_seen FROM shawk.listeners GROUP BY host_id
),
-- The latest known owner of every listener.
owned AS (
  SELECT DISTINCT ON (l.host_id, l.proto, l.addr, l.port, l.netns) l.*
  FROM shawk.listeners l
  WHERE l.process_id IS NOT NULL
  ORDER BY l.host_id, l.proto, l.addr, l.port, l.netns, l.last_seen DESC
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
  FROM owned l
  JOIN shawk.processes p ON p.id = l.process_id
  JOIN latest ON latest.host_id = l.host_id
  WHERE l.addr NOT IN (inet '0.0.0.0', inet '::')
    AND l.last_seen >= latest.last_seen - interval '1 hour'
  UNION ALL
  SELECT a.addr, l.port, l.proto, l.host_id, p.service_name, l.last_seen, false
  FROM owned l
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
