-- The endpoints of the processes of Slurm jobs (docs/design.md §5.3): the
-- connector names them slurm-job as peers, as it forwards them to
-- Prometheus, while PostgreSQL keeps their names. The views gain the
-- column slurm_job, after the others.

-- Addresses and ports services accept connections on, used by the shawk
-- connector to name the peers of client edges. They are the last known
-- endpoints of each host, so that a host whose agent stopped keeps its
-- names:
--
--   - listeners open at the latest listener report of the host, within an
--     hour (times of the agent are compared with times of the same agent);
--     a listener on an unspecified address is expanded to the current
--     addresses of its host (those of its latest report);
--   - server edges of the 7 days before that report, read per host through
--     an index;
--   - of hosts that reported in the last 30 days;
--   - not an address another host started a period of after the latest
--     period of this host ended (beyond the alive window, and not
--     loopback), so that a reused address takes the name of its new holder.
--
-- exact tells whether the address was observed on a socket rather than
-- inferred from a listener on an unspecified address; the connector prefers
-- exact endpoints. slurm_job tells that a process of a Slurm job (unit
-- slurm/*) serves it, which the connector names slurm-job as a peer.
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
  SELECT l.addr, l.port, l.proto, l.host_id, p.service_name AS service, l.last_seen, true AS exact,
         p.unit LIKE 'slurm/%' AS slurm_job
  FROM shawk.listeners l
  JOIN shawk.processes p ON p.id = l.process_id
  JOIN latest ON latest.host_id = l.host_id
  WHERE l.addr NOT IN (inet '0.0.0.0', inet '::')
    AND l.last_seen >= latest.last_seen - interval '1 hour'
  UNION ALL
  SELECT a.addr, l.port, l.proto, l.host_id, p.service_name, l.last_seen, false, p.unit LIKE 'slurm/%'
  FROM shawk.listeners l
  JOIN shawk.processes p ON p.id = l.process_id
  JOIN latest ON latest.host_id = l.host_id
  JOIN current_addrs a ON a.host_id = l.host_id
   AND (l.addr = inet '::' OR family(a.addr) = 4)
  WHERE l.addr IN (inet '0.0.0.0', inet '::')
    AND l.last_seen >= latest.last_seen - interval '1 hour'
  UNION ALL
  SELECT e.local_addr, e.port, e.proto, e.host_id, p.service_name, e.last_seen, true, p.unit LIKE 'slurm/%'
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
       bool_or(s.exact) AS exact, bool_or(s.slurm_job) AS slurm_job
FROM s
JOIN shawk.hosts h ON h.id = s.host_id
LEFT JOIN moved ON moved.host_id = s.host_id AND moved.addr = s.addr
WHERE h.last_seen > now() - interval '30 days'
  AND moved.host_id IS NULL
GROUP BY s.addr, s.port, s.proto, h.hostname, s.host_id, s.service;

-- The client sides of recent connections, used by the shawk connector to
-- name the peer of a server edge after the client service, when the client
-- host runs an agent. slurm_job tells that the client is a process of a
-- Slurm job (unit slurm/*).
CREATE OR REPLACE VIEW shawk_v1.client_endpoints AS
SELECT e.local_addr AS client_addr, e.remote_addr AS server_addr, e.port, e.proto,
       h.hostname AS host, e.host_id, p.service_name AS service, e.last_seen,
       p.unit LIKE 'slurm/%' AS slurm_job
FROM shawk.edges e
JOIN shawk.processes p ON p.id = e.process_id
JOIN shawk.hosts h ON h.id = e.host_id
WHERE e.role = 'client'
  AND e.last_seen > now() - interval '1 hour';

