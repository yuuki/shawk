-- Retention: shawk.prune deletes rows last seen before a cutoff, at most
-- max_rows per table and call, so that the shawk connector can call it
-- repeatedly in short transactions. Processes and hosts are deleted once
-- nothing refers to them. Sessions are deleted too, so unobserved() reports
-- the time before the cutoff as not observed.

CREATE INDEX edges_process ON shawk.edges (process_id);
CREATE INDEX listeners_process ON shawk.listeners (process_id);
CREATE INDEX listeners_last_seen ON shawk.listeners (last_seen);
CREATE INDEX host_addrs_last_seen ON shawk.host_addrs (last_seen);
CREATE INDEX agent_sessions_last_heartbeat ON shawk.agent_sessions (last_heartbeat);
CREATE INDEX processes_last_seen ON shawk.processes (last_seen);

CREATE FUNCTION shawk.prune(cutoff timestamptz, max_rows integer DEFAULT 10000) RETURNS bigint
LANGUAGE plpgsql AS $$
DECLARE
  n bigint;
  total bigint := 0;
BEGIN
  DELETE FROM shawk.edges WHERE id IN (
    SELECT id FROM shawk.edges WHERE last_seen < cutoff LIMIT max_rows);
  GET DIAGNOSTICS n = ROW_COUNT; total := total + n;

  DELETE FROM shawk.listeners WHERE ctid IN (
    SELECT ctid FROM shawk.listeners WHERE last_seen < cutoff LIMIT max_rows);
  GET DIAGNOSTICS n = ROW_COUNT; total := total + n;

  DELETE FROM shawk.host_addrs WHERE ctid IN (
    SELECT ctid FROM shawk.host_addrs WHERE last_seen < cutoff LIMIT max_rows);
  GET DIAGNOSTICS n = ROW_COUNT; total := total + n;

  DELETE FROM shawk.agent_sessions WHERE ctid IN (
    SELECT ctid FROM shawk.agent_sessions WHERE last_heartbeat < cutoff LIMIT max_rows);
  GET DIAGNOSTICS n = ROW_COUNT; total := total + n;

  DELETE FROM shawk.processes WHERE id IN (
    SELECT p.id FROM shawk.processes p
    WHERE p.last_seen < cutoff
      AND NOT EXISTS (SELECT FROM shawk.edges e WHERE e.process_id = p.id)
      AND NOT EXISTS (SELECT FROM shawk.listeners l WHERE l.process_id = p.id)
    LIMIT max_rows);
  GET DIAGNOSTICS n = ROW_COUNT; total := total + n;

  DELETE FROM shawk.hosts WHERE id IN (
    SELECT h.id FROM shawk.hosts h
    WHERE h.last_seen < cutoff
      AND NOT EXISTS (SELECT FROM shawk.agent_sessions s WHERE s.host_id = h.id)
      AND NOT EXISTS (SELECT FROM shawk.host_addrs a WHERE a.host_id = h.id)
      AND NOT EXISTS (SELECT FROM shawk.processes p WHERE p.host_id = h.id)
      AND NOT EXISTS (SELECT FROM shawk.edges e WHERE e.host_id = h.id)
      AND NOT EXISTS (SELECT FROM shawk.listeners l WHERE l.host_id = h.id)
    LIMIT max_rows);
  GET DIAGNOSTICS n = ROW_COUNT; total := total + n;

  RETURN total;
END
$$;
