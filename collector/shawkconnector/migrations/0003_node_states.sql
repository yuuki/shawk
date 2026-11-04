-- Node states and maintenance windows: why hosts were not observed, and
-- which stopped agents are planned (docs/design.md §5.7).
--
-- The shawk connector writes them from its node_states_file, which a cron
-- job generates from Slurm (scontrol show nodes --json) and which lists the
-- maintenance windows registered explicitly. They are kept as periods with
-- times, apart from the hosts, so that the reason of a past gap is the state
-- at that time, not today's.

-- Tables ------------------------------------------------------------------

-- The states of nodes as read from Slurm: one row per period in which a
-- host kept a state and reason, from the first read with them (first_seen)
-- to the latest (last_seen), by the time the file says the states were
-- read. A state not read again within node_state_max_age() is stale: it
-- explains nothing after that, and the next read starts a new period.
CREATE TABLE shawk.node_states (
  hostname   text NOT NULL,              -- host.name of the agent
  first_seen timestamptz NOT NULL,
  last_seen  timestamptz NOT NULL,
  state      text[] NOT NULL,            -- the flags of Slurm, upper case and sorted: {IDLE,POWERED_DOWN}
  reason     text NOT NULL DEFAULT '',   -- the reason of Slurm, if any
  PRIMARY KEY (hostname, first_seen),
  CHECK (last_seen >= first_seen)
);
CREATE INDEX node_states_last_seen ON shawk.node_states (last_seen);

-- Maintenance windows registered explicitly, one row per period in which
-- a window (a host and a start) was registered. A row counts from when a
-- connector wrote it (registered_at) if that is after its start, so that
-- registering a window afterwards does not make a past failure planned. A
-- window removed from the file is deleted before it starts and ends when
-- it was removed while in progress; a row that ended is kept as it was. A
-- window registered again after its row ended, e.g. after a file read
-- while it lacked the window, gets a new row from then: the time in
-- between is not planned, and nothing is lost for good.
CREATE TABLE shawk.maintenance_windows (
  hostname      text NOT NULL,           -- host.name of the agent
  starts_at     timestamptz NOT NULL,    -- as registered
  ends_at       timestamptz NOT NULL,
  reason        text NOT NULL DEFAULT '',
  registered_at timestamptz NOT NULL,
  PRIMARY KEY (hostname, starts_at, registered_at),
  CHECK (ends_at >= starts_at AND ends_at >= registered_at)
);
CREATE INDEX maintenance_windows_ends_at ON shawk.maintenance_windows (ends_at);

-- Helpers -----------------------------------------------------------------

-- How long a state read from Slurm holds without being read again: a few
-- runs of the cron job (every minute) and write intervals of the connector.
CREATE FUNCTION shawk.node_state_max_age() RETURNS interval
LANGUAGE sql IMMUTABLE AS $$ SELECT interval '5 minutes' $$;

-- The planned stop a state of Slurm stands for: maintenance for a node in a
-- reservation with the flag MAINT, power_saving for a node of power saving
-- powered down, powering down or powering up, NULL otherwise. Power saving
-- is judged by the flags a node may have besides (a job may wait for a
-- node that powers up, ALLOCATED or MIXED), not by those it may not: DOWN
-- (which also follows failed boots and a ResumeTimeout), DRAIN (jobs keep
-- running on a draining node), FAIL, NOT_RESPONDING and flags unknown here
-- are never planned. Powering up ends as the node is up, when its agent is
-- expected back, or at the ResumeTimeout of Slurm, when the node is DOWN.
CREATE FUNCTION shawk.planned_state(state text[]) RETURNS text
LANGUAGE sql IMMUTABLE AS $$
  SELECT CASE
    WHEN state && '{MAINT,MAINTENANCE}'::text[] THEN 'maintenance'
    WHEN state && '{POWERED_DOWN,POWERING_DOWN,POWERING_UP}'::text[]
         AND state <@ '{IDLE,ALLOCATED,MIXED,CLOUD,POWER_DOWN,POWERED_DOWN,POWERING_DOWN,POWERING_UP}'::text[]
      THEN 'power_saving'
  END
$$;

-- The periods in which each host had a state: from its first read until
-- the next state, and no longer than node_state_max_age() after its last
-- read.
CREATE VIEW shawk.node_state_periods AS
SELECT s.hostname,
       tstzrange(s.first_seen,
                 least(s.last_seen + shawk.node_state_max_age(),
                       lead(s.first_seen) OVER (PARTITION BY s.hostname ORDER BY s.first_seen)),
                 '[)') AS period,
       s.state, s.reason
FROM shawk.node_states s;

-- The maintenance windows, from when they were registered.
CREATE VIEW shawk.maintenance_periods AS
SELECT w.hostname, tstzrange(least(greatest(w.starts_at, w.registered_at), w.ends_at), w.ends_at, '[)') AS period,
       w.reason
FROM shawk.maintenance_windows w
WHERE greatest(w.starts_at, w.registered_at) < w.ends_at;

-- Contract ----------------------------------------------------------------

-- Hosts in a planned stop now, until when at the latest: in a maintenance
-- window until its end, or in a planned state of their latest read from
-- Slurm until it becomes stale. A stale state, DOWN or DRAIN stop nothing:
-- alerts on stopped agents exclude these hosts only. A MAINT reservation
-- (which may be unlimited) stops them for 30 days at most, as the longest
-- window of the maintenance_file, counted from the first of the states
-- with MAINT that follow each other, whatever their other flags and
-- reasons. The states read in the last 31 days suffice to find it: the
-- first of them follows one read before.
CREATE VIEW shawk_v1.planned_stops AS
SELECT w.hostname AS host, 'maintenance'::text AS cause, lower(w.period) AS since, upper(w.period) AS until, w.reason
FROM shawk.maintenance_periods w
WHERE w.period @> now()
UNION ALL
SELECT s.hostname, s.cause, s.since, s.last_seen + shawk.node_state_max_age(), s.reason
FROM (
  SELECT DISTINCT ON (r.hostname) r.hostname, r.first_seen, r.cause, r.last_seen, r.reason,
         CASE WHEN r.cause = 'maintenance'
              THEN min(r.first_seen) FILTER (WHERE r.cause = 'maintenance') OVER (PARTITION BY r.hostname, r.run)
              ELSE r.first_seen END AS since
  FROM (
    SELECT n.hostname, n.first_seen, n.last_seen, n.reason, shawk.planned_state(n.state) AS cause,
           -- states with MAINT that follow each other share a run (with
           -- the state before them, which the minimum leaves out)
           count(*) FILTER (WHERE shawk.planned_state(n.state) IS DISTINCT FROM 'maintenance')
             OVER (PARTITION BY n.hostname ORDER BY n.first_seen) AS run
    FROM shawk.node_states n
    WHERE n.last_seen > now() - interval '31 days'
  ) r
  ORDER BY r.hostname, r.first_seen DESC
) s
WHERE s.last_seen + shawk.node_state_max_age() > now()
  AND s.cause IS NOT NULL
  AND (s.cause <> 'maintenance' OR s.since > now() - interval '30 days');

-- The periods of unobserved_by_name(since, until, tolerance), cut by what
-- Slurm and the maintenance windows tell about them: cause is maintenance
-- or power_saving for a planned stop and NULL otherwise; node_state is the
-- state of Slurm then ('+' between flags, NULL if none was read or it was
-- stale) and reason the reason of Slurm or of the maintenance window. A
-- maintenance window takes precedence over the state. The gaps are those of
-- host names, as the states and windows are: a node that power saving
-- boots often may get a new host id at every boot, and the old ids would
-- report gaps although the name was observed. unobserved() and
-- unobserved_by_name() do not change: the gaps stay recorded whatever
-- their reasons.
CREATE FUNCTION shawk_v1.unobserved_reasons(since timestamptz, until timestamptz,
                                            tolerance interval DEFAULT '3 minutes')
RETURNS TABLE (host text, gap_start timestamptz, gap_end timestamptz,
               cause text, node_state text, reason text)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
  WITH gaps AS (
    SELECT u.host, tstzmultirange(tstzrange(u.gap_start, u.gap_end)) AS gap,
           coalesce((SELECT range_agg(w.period) FROM shawk.maintenance_periods w
                     WHERE w.hostname = u.host AND w.period && tstzrange(u.gap_start, u.gap_end)),
                    '{}'::tstzmultirange) AS maint
    FROM shawk_v1.unobserved_by_name(unobserved_reasons.since, unobserved_reasons.until,
                                     unobserved_reasons.tolerance) u
  ),
  states AS (
    SELECT g.host, g.gap - g.maint AS rest, p.period, p.state, p.reason
    FROM gaps g
    JOIN shawk.node_state_periods p ON p.hostname = g.host AND (g.gap - g.maint) && p.period
  )
  SELECT g.host, lower(m), upper(m), 'maintenance',
         NULL::text,
         (SELECT string_agg(DISTINCT w.reason, '; ') FROM shawk.maintenance_periods w
          WHERE w.hostname = g.host AND w.period && m AND w.reason <> '')
  FROM gaps g CROSS JOIN LATERAL unnest(g.gap * g.maint) AS m
  UNION ALL
  SELECT s.host, lower(r), upper(r), shawk.planned_state(s.state),
         array_to_string(s.state, '+'), nullif(s.reason, '')
  FROM states s CROSS JOIN LATERAL unnest(s.rest * tstzmultirange(s.period)) AS r
  UNION ALL
  SELECT g.host, lower(r), upper(r), NULL, NULL, NULL
  FROM gaps g CROSS JOIN LATERAL unnest(
    g.gap - g.maint
    - coalesce((SELECT range_agg(p.period) FROM shawk.node_state_periods p
                WHERE p.hostname = g.host AND p.period && g.gap),
               '{}'::tstzmultirange)) AS r
$$;

-- Retention ---------------------------------------------------------------

-- Deletes the states last read, and the maintenance windows ended, before a
-- cutoff, at most max_rows per table, as shawk.prune() does for the other
-- tables; the connector calls both.
CREATE FUNCTION shawk.prune_node_states(cutoff timestamptz, max_rows integer DEFAULT 10000) RETURNS bigint
LANGUAGE plpgsql AS $$
DECLARE
  n bigint;
  total bigint := 0;
BEGIN
  PERFORM pg_advisory_xact_lock_shared(1936220535);  -- 0x73686177, see Migrate

  DELETE FROM shawk.node_states WHERE last_seen < cutoff AND ctid IN (
    SELECT ctid FROM shawk.node_states WHERE last_seen < cutoff LIMIT max_rows);
  GET DIAGNOSTICS n = ROW_COUNT; total := total + n;

  DELETE FROM shawk.maintenance_windows WHERE ends_at < cutoff AND ctid IN (
    SELECT ctid FROM shawk.maintenance_windows WHERE ends_at < cutoff LIMIT max_rows);
  GET DIAGNOSTICS n = ROW_COUNT; total := total + n;

  RETURN total;
END
$$;
