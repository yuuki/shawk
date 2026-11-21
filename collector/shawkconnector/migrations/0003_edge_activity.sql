-- The hours in which edges were active (§5.1 and §6.3 of docs/design.md).
-- An edge keeps when it was first and last seen only, so that a job that
-- runs once a month and a connection that never closes look the same
-- between those times. These tables keep the history in between, by hour:
-- the cadence of a dependency is read from them (0004_impact.sql).

-- The hours of a month in which an edge was active: bit i of hours, from
-- the left, is the hour that starts i hours after month, the start of a
-- month in UTC. The connector sets the hour of every time at which an
-- agent reported the edge active, by the clock of the agent like
-- first_seen and last_seen; a bit that is not set tells nothing of an hour
-- in which the host was not observed, or which precedes the first bit of
-- the edge (an edge written before this table). A month has up to 744
-- hours; the bits past its end stay 0. The rows go with their edge, and
-- the months before the retention are pruned on their own.
CREATE TABLE shawk.edge_activity (
  edge_id bigint NOT NULL REFERENCES shawk.edges ON DELETE CASCADE,
  month   timestamptz NOT NULL CHECK (month = date_trunc('month', month, 'UTC')),
  hours   bit(744) NOT NULL,
  PRIMARY KEY (edge_id, month)
);
CREATE INDEX edge_activity_month ON shawk.edge_activity (month);

-- The same for the client edges of Unix sockets.
CREATE TABLE shawk.unix_edge_activity (
  edge_id bigint NOT NULL REFERENCES shawk.unix_edges ON DELETE CASCADE,
  month   timestamptz NOT NULL CHECK (month = date_trunc('month', month, 'UTC')),
  hours   bit(744) NOT NULL,
  PRIMARY KEY (edge_id, month)
);
CREATE INDEX unix_edge_activity_month ON shawk.unix_edge_activity (month);

-- How far back the history is whole: the latest cutoff shawk.prune() was
-- called with. An edge last seen before it is deleted, but the session of
-- an agent that goes on is kept whole, so that the sessions alone would
-- tell that a host was observed, and unused, in a time whose dependencies
-- are gone. What reads the history as evidence that something was not used
-- (0004_impact.sql) takes the time before the cutoff as not observed. No
-- row until the first prune.
CREATE TABLE shawk.retention (
  singleton     boolean PRIMARY KEY DEFAULT true CHECK (singleton),
  pruned_before timestamptz NOT NULL
);

-- shawk.prune() of 0002_edge_protocols.sql, which also records its cutoff
-- (shawk.retention), first, so that no reader takes the history for whole
-- while it is deleted, and deletes the months of activity that ended
-- before the cutoff, of edges seen since: a month has at most 31 days. They
-- are deleted after their edges, in the order the connector writes them,
-- like the wire protocols; the months of the edges deleted go with them
-- (ON DELETE CASCADE), which ROW_COUNT does not count.
CREATE OR REPLACE FUNCTION shawk.prune(cutoff timestamptz, max_rows integer DEFAULT 10000) RETURNS bigint
LANGUAGE plpgsql AS $$
DECLARE
  n bigint;
  total bigint := 0;
BEGIN
  PERFORM pg_advisory_xact_lock_shared(1936220535);  -- 0x73686177, see Migrate

  INSERT INTO shawk.retention AS r (pruned_before) VALUES (cutoff)
  ON CONFLICT (singleton) DO UPDATE SET pruned_before = excluded.pruned_before
  WHERE r.pruned_before < excluded.pruned_before;

  DELETE FROM shawk.edges WHERE last_seen < cutoff AND id IN (
    SELECT id FROM shawk.edges WHERE last_seen < cutoff LIMIT max_rows);
  GET DIAGNOSTICS n = ROW_COUNT; total := total + n;

  DELETE FROM shawk.edge_activity WHERE month < cutoff - interval '31 days' AND ctid IN (
    SELECT ctid FROM shawk.edge_activity WHERE month < cutoff - interval '31 days' LIMIT max_rows);
  GET DIAGNOSTICS n = ROW_COUNT; total := total + n;

  DELETE FROM shawk.edge_protocols WHERE last_seen < cutoff AND ctid IN (
    SELECT ctid FROM shawk.edge_protocols WHERE last_seen < cutoff LIMIT max_rows);
  GET DIAGNOSTICS n = ROW_COUNT; total := total + n;

  DELETE FROM shawk.unix_edges WHERE last_seen < cutoff AND id IN (
    SELECT id FROM shawk.unix_edges WHERE last_seen < cutoff LIMIT max_rows);
  GET DIAGNOSTICS n = ROW_COUNT; total := total + n;

  DELETE FROM shawk.unix_edge_activity WHERE month < cutoff - interval '31 days' AND ctid IN (
    SELECT ctid FROM shawk.unix_edge_activity WHERE month < cutoff - interval '31 days' LIMIT max_rows);
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
