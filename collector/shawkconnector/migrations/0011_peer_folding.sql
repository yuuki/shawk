-- Folded peers and partly observed periods (#96).
--
-- An agent may fold the peers outside its internal ranges into one peer per
-- local endpoint. The edges of a folded peer have the network 0.0.0.0/0 or
-- ::/0 as remote_addr; inet holds it as it is, and the views name it like
-- any peer without a service (peer_class gives ~external), so no table or
-- view changes for it. Since a network never equals an address, a folded
-- edge never matches an edge of another host in dependencies.
--
-- The columns are added at the end of the table and nullable, and the
-- tables connectors of the previous schema write are otherwise unchanged,
-- so that they still write during an upgrade.

-- What the agent of a session folds: 'none', 'in' (the peers of its
-- servers) or 'all' (of its clients too), and the ranges of peers it keeps
-- exact besides its own addresses. NULL when not known: written by a
-- connector of the previous version.
--
-- counters_started is when the counters of the agent started, by the clock
-- of the agent as it sends it: the same for every session of one run of the
-- agent, so that its dropped flows are compared within the run. NULL when
-- not known; the drops a run counted before its first session with it are
-- then recorded from the start of that session.
ALTER TABLE shawk.agent_sessions
  ADD COLUMN peer_fold        text,
  ADD COLUMN peer_internal    cidr[],
  ADD COLUMN counters_started timestamptz;

-- Periods in which an agent observed its host but dropped flows because its
-- flow table was full: dependencies active then may be missing. Times are by
-- the clock of the connector, like heartbeats. The connector records a
-- period when the dropped flows of a run of the agent grow between two
-- heartbeats, and extends the latest period of the host when the next one
-- meets it.
CREATE TABLE shawk.partial_observations (
  host_id       text NOT NULL REFERENCES shawk.hosts,
  started_at    timestamptz NOT NULL,     -- of the session
  period_start  timestamptz NOT NULL,
  period_end    timestamptz NOT NULL,
  dropped_flows bigint NOT NULL,          -- flow updates dropped in the period
  PRIMARY KEY (host_id, started_at, period_start)
);
CREATE INDEX partial_observations_period_end ON shawk.partial_observations (period_end);

CREATE OR REPLACE VIEW shawk_v1.agents AS
SELECT DISTINCT ON (h.id)
  h.hostname        AS host,
  h.id              AS host_id,
  h.machine_id,
  h.kernel,
  h.agent_version,
  s.started_at,
  s.last_heartbeat,
  s.udp_traced,
  s.netns_scope,
  s.dropped_flows,
  s.last_heartbeat > now() - shawk.alive_window() AS alive,
  s.clock_skew,     -- how far the clock of the host is behind the connector
  s.peer_fold,      -- what the agent folds: none, in or all; NULL if not known
  s.peer_internal   -- the ranges of peers the agent keeps exact
FROM shawk.hosts h
JOIN shawk.agent_sessions s ON s.host_id = h.id
ORDER BY h.id, s.last_heartbeat DESC;

-- agent_addrs: what the agent folds, so that a connector tells hosts whose
-- agent folds the connections of other hosts that run an agent.
CREATE OR REPLACE VIEW shawk_v1.agent_addrs AS
SELECT a.addr, h.hostname AS host, a.host_id, a.last_seen, s.udp_traced, s.netns_scope, s.last_heartbeat,
       s.peer_fold, s.peer_internal
FROM shawk.host_addrs a
JOIN shawk.hosts h ON h.id = a.host_id
CROSS JOIN LATERAL (
  SELECT s.udp_traced, s.netns_scope, s.last_heartbeat, s.peer_fold, s.peer_internal FROM shawk.agent_sessions s
  WHERE s.host_id = a.host_id ORDER BY s.last_heartbeat DESC LIMIT 1
) s
WHERE a.last_seen > now() - shawk.alive_window()
  AND s.last_heartbeat > now() - shawk.alive_window();

-- The periods in [since, until] in which a host was observed but its agent
-- dropped flows, cut to [since, until], with the flow updates dropped in
-- each. A dependency may be missing from such a period although it was
-- used; unobserved() gives the periods in which a host was not observed at
-- all. It runs with the rights of its owner, so that readers need no access
-- to the tables.
CREATE FUNCTION shawk_v1.partly_observed(since timestamptz, until timestamptz)
RETURNS TABLE (host text, gap_start timestamptz, gap_end timestamptz, dropped_flows bigint)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
  SELECT h.hostname, greatest(p.period_start, since), least(p.period_end, until), p.dropped_flows
  FROM shawk.partial_observations p
  JOIN shawk.hosts h ON h.id = p.host_id
  WHERE p.period_end > since AND p.period_start < until;
$$;

-- prune: partly observed periods go with the retention, like the sessions
-- they belong to, and hosts once nothing refers to them.
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

  DELETE FROM shawk.partial_observations WHERE period_end < cutoff AND ctid IN (
    SELECT ctid FROM shawk.partial_observations WHERE period_end < cutoff LIMIT max_rows);
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
    AND NOT EXISTS (SELECT FROM shawk.partial_observations o WHERE o.host_id = h.id)
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
