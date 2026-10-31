-- service_endpoints returns the last known endpoints of each host instead
-- of those seen in the last 7 days, so that a host whose agent stopped
-- keeps its names:
--
--   - listeners open at the latest listener report of the host, within an
--     hour (times of the agent are compared with times of the same agent);
--   - server edges of the 7 days before that report;
--   - hosts that reported in the last 30 days;
--   - not an address another host started to hold after this host last
--     did (beyond the alive window, and not loopback), so that a reused
--     address takes the name of its new holder.
CREATE OR REPLACE VIEW shawk_v1.service_endpoints AS
WITH latest AS (
  SELECT host_id, max(last_seen) AS last_seen FROM shawk.listeners GROUP BY host_id
),
s AS (
  SELECT l.addr, l.port, l.proto, l.host_id, p.service_name AS service, l.last_seen
  FROM shawk.listeners l
  JOIN shawk.processes p ON p.id = l.process_id
  JOIN latest ON latest.host_id = l.host_id
  WHERE l.addr NOT IN (inet '0.0.0.0', inet '::')
    AND l.last_seen >= latest.last_seen - interval '1 hour'
  UNION ALL
  SELECT a.addr, l.port, l.proto, l.host_id, p.service_name, least(l.last_seen, a.last_seen)
  FROM shawk.listeners l
  JOIN shawk.processes p ON p.id = l.process_id
  JOIN latest ON latest.host_id = l.host_id
  JOIN shawk.host_addrs a ON a.host_id = l.host_id
   AND (l.addr = inet '::' OR family(a.addr) = 4)
  WHERE l.addr IN (inet '0.0.0.0', inet '::')
    AND l.last_seen >= latest.last_seen - interval '1 hour'
  UNION ALL
  SELECT e.local_addr, e.port, e.proto, e.host_id, p.service_name, e.last_seen
  FROM shawk.edges e
  JOIN shawk.processes p ON p.id = e.process_id
  JOIN latest ON latest.host_id = e.host_id
  WHERE e.role = 'server'
    AND e.last_seen >= latest.last_seen - interval '7 days'
)
SELECT s.addr, s.port, s.proto, h.hostname AS host, s.host_id, s.service, max(s.last_seen) AS last_seen
FROM s
JOIN shawk.hosts h ON h.id = s.host_id
WHERE h.last_seen > now() - interval '30 days'
  AND NOT EXISTS (
    SELECT FROM shawk.host_addrs mine
    JOIN shawk.host_addrs other ON other.addr = mine.addr AND other.host_id <> mine.host_id
    WHERE mine.host_id = s.host_id AND mine.addr = s.addr
      AND NOT (s.addr << inet '127.0.0.0/8' OR s.addr = inet '::1')
      AND other.first_seen > mine.last_seen + shawk.alive_window())
GROUP BY s.addr, s.port, s.proto, h.hostname, s.host_id, s.service;
