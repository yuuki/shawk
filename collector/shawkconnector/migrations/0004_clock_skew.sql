-- Heartbeats are written with the clock of the shawk connector, and the
-- difference to the clock of the agent is kept, so that a wrong clock of a
-- host does not make it look dead or alive.
ALTER TABLE shawk.agent_sessions ADD COLUMN clock_skew interval NOT NULL DEFAULT '0';

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
  s.clock_skew      -- how far the clock of the host is behind the connector
FROM shawk.hosts h
JOIN shawk.agent_sessions s ON s.host_id = h.id
ORDER BY h.id, s.last_heartbeat DESC;
