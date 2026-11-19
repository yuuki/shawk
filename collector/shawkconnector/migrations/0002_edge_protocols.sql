-- The wire protocols of TCP edges: the application protocol, or the
-- version of TLS, that the first payload of their connections showed, which
-- agents classify with -classify-protocols (§3.9 of docs/design.md).
-- Prometheus does not have them, so that they add no series.

-- When the connections of an edge first and last showed a wire protocol:
-- the request of a client (TLS: the highest version it offers), the answer
-- or the greeting of a server (TLS: the version it chose). The rows go with
-- their edge, and are pruned like it. The values are those the agents send
-- (wireProtocols of the connector).
CREATE TABLE shawk.edge_protocols (
  edge_id    bigint NOT NULL REFERENCES shawk.edges ON DELETE CASCADE,
  protocol   text NOT NULL CHECK (protocol IN ('unknown', 'tls', 'tls_1_0', 'tls_1_1', 'tls_1_2', 'tls_1_3',
                                               'http1', 'http2_grpc', 'ssh', 'postgres', 'mysql', 'redis',
                                               'slurm_rpc')),
  first_seen timestamptz NOT NULL,
  last_seen  timestamptz NOT NULL,
  PRIMARY KEY (edge_id, protocol)
);
CREATE INDEX edge_protocols_last_seen ON shawk.edge_protocols (last_seen);

-- The wire protocols of the TCP edges, one row per edge and protocol, with
-- the host, service and unit of the side that observed it (role) and the
-- addresses of the client and of the server whichever side that was:
-- client_addr is the network 0.0.0.0/0 or ::/0 for the clients a server
-- folded (§3.6), and server_addr that of the servers a client folded. A
-- client tells the highest version of TLS it offers, a server the version
-- it chose. An edge without rows had no connection classified: its agent
-- does not classify, or its connections predate the agent or the first
-- payload was not read (docs/design.md §3.9).
CREATE VIEW shawk_v1.edge_protocols AS
SELECT h.hostname AS host, e.host_id, p.service_name AS service, p.unit, e.role, e.proto,
       CASE WHEN e.role = 'client' THEN e.local_addr ELSE e.remote_addr END AS client_addr,
       CASE WHEN e.role = 'client' THEN e.remote_addr ELSE e.local_addr END AS server_addr,
       e.port, e.netns, w.protocol, w.first_seen, w.last_seen
FROM shawk.edge_protocols w
JOIN shawk.edges e ON e.id = w.edge_id
JOIN shawk.processes p ON p.id = e.process_id
JOIN shawk.hosts h ON h.id = e.host_id;

-- shawk.prune() of 0001_schema.sql, which also deletes the wire protocols
-- last seen before the cutoff, of edges seen since.
CREATE OR REPLACE FUNCTION shawk.prune(cutoff timestamptz, max_rows integer DEFAULT 10000) RETURNS bigint
LANGUAGE plpgsql AS $$
DECLARE
  n bigint;
  total bigint := 0;
BEGIN
  PERFORM pg_advisory_xact_lock_shared(1936220535);  -- 0x73686177, see Migrate

  DELETE FROM shawk.edge_protocols WHERE last_seen < cutoff AND ctid IN (
    SELECT ctid FROM shawk.edge_protocols WHERE last_seen < cutoff LIMIT max_rows);
  GET DIAGNOSTICS n = ROW_COUNT; total := total + n;

  DELETE FROM shawk.edges WHERE last_seen < cutoff AND id IN (
    SELECT id FROM shawk.edges WHERE last_seen < cutoff LIMIT max_rows);
  GET DIAGNOSTICS n = ROW_COUNT; total := total + n;

  DELETE FROM shawk.unix_edges WHERE last_seen < cutoff AND id IN (
    SELECT id FROM shawk.unix_edges WHERE last_seen < cutoff LIMIT max_rows);
  GET DIAGNOSTICS n = ROW_COUNT; total := total + n;

  DELETE FROM shawk.listeners WHERE last_seen < cutoff AND ctid IN (
    SELECT ctid FROM shawk.listeners WHERE last_seen < cutoff LIMIT max_rows);
  GET DIAGNOSTICS n = ROW_COUNT; total := total + n;

  DELETE FROM shawk.listener_owners WHERE last_seen < cutoff AND ctid IN (
    SELECT ctid FROM shawk.listener_owners WHERE last_seen < cutoff LIMIT max_rows);
  GET DIAGNOSTICS n = ROW_COUNT; total := total + n;

  DELETE FROM shawk.unix_listeners WHERE last_seen < cutoff AND ctid IN (
    SELECT ctid FROM shawk.unix_listeners WHERE last_seen < cutoff LIMIT max_rows);
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

  DELETE FROM shawk.learned_translations WHERE last_seen < cutoff AND ctid IN (
    SELECT ctid FROM shawk.learned_translations WHERE last_seen < cutoff LIMIT max_rows);
  GET DIAGNOSTICS n = ROW_COUNT; total := total + n;

  DELETE FROM shawk.known_dependencies WHERE last_seen < cutoff AND ctid IN (
    SELECT ctid FROM shawk.known_dependencies WHERE last_seen < cutoff LIMIT max_rows);
  GET DIAGNOSTICS n = ROW_COUNT; total := total + n;

  DELETE FROM shawk.processes p WHERE p.last_seen < cutoff
    AND NOT EXISTS (SELECT FROM shawk.edges e WHERE e.process_id = p.id)
    AND NOT EXISTS (SELECT FROM shawk.unix_edges e WHERE e.process_id = p.id)
    AND NOT EXISTS (SELECT FROM shawk.listeners l WHERE l.process_id = p.id)
    AND NOT EXISTS (SELECT FROM shawk.listener_owners o WHERE o.process_id = p.id)
    AND NOT EXISTS (SELECT FROM shawk.unix_listeners u WHERE u.process_id = p.id)
    AND p.id IN (
      SELECT p2.id FROM shawk.processes p2
      WHERE p2.last_seen < cutoff
        AND NOT EXISTS (SELECT FROM shawk.edges e WHERE e.process_id = p2.id)
        AND NOT EXISTS (SELECT FROM shawk.unix_edges e WHERE e.process_id = p2.id)
        AND NOT EXISTS (SELECT FROM shawk.listeners l WHERE l.process_id = p2.id)
        AND NOT EXISTS (SELECT FROM shawk.listener_owners o WHERE o.process_id = p2.id)
        AND NOT EXISTS (SELECT FROM shawk.unix_listeners u WHERE u.process_id = p2.id)
      LIMIT max_rows);
  GET DIAGNOSTICS n = ROW_COUNT; total := total + n;

  DELETE FROM shawk.hosts h WHERE h.last_seen < cutoff
    AND NOT EXISTS (SELECT FROM shawk.agent_sessions s WHERE s.host_id = h.id)
    AND NOT EXISTS (SELECT FROM shawk.partial_observations o WHERE o.host_id = h.id)
    AND NOT EXISTS (SELECT FROM shawk.host_addrs a WHERE a.host_id = h.id)
    AND NOT EXISTS (SELECT FROM shawk.processes p WHERE p.host_id = h.id)
    AND NOT EXISTS (SELECT FROM shawk.edges e WHERE e.host_id = h.id)
    AND NOT EXISTS (SELECT FROM shawk.unix_edges e WHERE e.host_id = h.id)
    AND NOT EXISTS (SELECT FROM shawk.listeners l WHERE l.host_id = h.id)
    AND NOT EXISTS (SELECT FROM shawk.listener_owners o WHERE o.host_id = h.id)
    AND NOT EXISTS (SELECT FROM shawk.unix_listeners u WHERE u.host_id = h.id)
    AND NOT EXISTS (SELECT FROM shawk.learned_translations t WHERE t.host_id = h.id)
    AND h.id IN (SELECT h2.id FROM shawk.hosts h2 WHERE h2.last_seen < cutoff LIMIT max_rows);
  GET DIAGNOSTICS n = ROW_COUNT; total := total + n;

  RETURN total;
END
$$;
