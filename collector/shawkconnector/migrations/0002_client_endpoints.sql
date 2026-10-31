-- The client sides of recent connections, used by the shawk connector to
-- name the peer of a server edge after the client service, when the client
-- host runs an agent.
CREATE VIEW shawk_v1.client_endpoints AS
SELECT e.local_addr AS client_addr, e.remote_addr AS server_addr, e.port, e.proto,
       h.hostname AS host, e.host_id, p.service_name AS service, e.last_seen
FROM shawk.edges e
JOIN shawk.processes p ON p.id = e.process_id
JOIN shawk.hosts h ON h.id = e.host_id
WHERE e.role = 'client'
  AND e.last_seen > now() - interval '1 hour';
