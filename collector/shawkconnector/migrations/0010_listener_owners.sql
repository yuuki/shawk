-- The owners of every listener (#98). shawk.listeners keeps the latest
-- owner of a listener only, so the processes that listened on a port before
-- it changed hands were lost. It is kept as it is, so that connectors of the
-- previous schema still write during an upgrade; the connector records here
-- every known owner of a listener as well, from this migration on.
CREATE TABLE shawk.listener_owners (
  host_id    text NOT NULL REFERENCES shawk.hosts,
  process_id bigint NOT NULL REFERENCES shawk.processes,
  proto      text NOT NULL,
  addr       inet NOT NULL,
  port       integer NOT NULL,
  netns      bigint NOT NULL,
  first_seen timestamptz NOT NULL,
  last_seen  timestamptz NOT NULL,
  PRIMARY KEY (host_id, proto, addr, port, netns, process_id)
);
CREATE INDEX listener_owners_process ON shawk.listener_owners (process_id);
CREATE INDEX listener_owners_last_seen ON shawk.listener_owners (last_seen);

-- prune: the owners go with the retention, and processes and hosts once
-- nothing refers to them.
CREATE OR REPLACE FUNCTION shawk.prune(cutoff timestamptz, max_rows integer DEFAULT 10000) RETURNS bigint
LANGUAGE plpgsql AS $$
DECLARE
  n bigint;
  total bigint := 0;
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

  DELETE FROM shawk.hosts h WHERE h.last_seen < cutoff
    AND NOT EXISTS (SELECT FROM shawk.agent_sessions s WHERE s.host_id = h.id)
    AND NOT EXISTS (SELECT FROM shawk.host_addrs a WHERE a.host_id = h.id)
    AND NOT EXISTS (SELECT FROM shawk.processes p WHERE p.host_id = h.id)
    AND NOT EXISTS (SELECT FROM shawk.edges e WHERE e.host_id = h.id)
    AND NOT EXISTS (SELECT FROM shawk.listeners l WHERE l.host_id = h.id)
    AND NOT EXISTS (SELECT FROM shawk.listener_owners o WHERE o.host_id = h.id)
    AND h.id IN (SELECT h2.id FROM shawk.hosts h2 WHERE h2.last_seen < cutoff LIMIT max_rows);
  GET DIAGNOSTICS n = ROW_COUNT; total := total + n;

  RETURN total;
END
$$;
