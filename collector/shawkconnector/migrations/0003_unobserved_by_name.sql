-- The gaps of host names (docs/design.md §4.1, §6.2), for nodes whose
-- machine id changes at every boot.

-- The periods in [since, until] in which no host of a name was observed:
-- unobserved() over the sessions of all the host ids with the same host
-- name. A host whose machine id changes at every boot (a stateless node
-- with an empty /etc/machine-id) becomes a new host id each time, and
-- unobserved() reports the time after the last heartbeat of each old id as
-- a gap although the name was observed throughout. Two machines that share
-- a name hide each other's gaps here; unobserved() tells them apart.
CREATE FUNCTION shawk_v1.unobserved_by_name(since timestamptz, until timestamptz,
                                            tolerance interval DEFAULT '3 minutes')
RETURNS TABLE (host text, gap_start timestamptz, gap_end timestamptz)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
  WITH names AS (
    SELECT h.hostname FROM shawk.hosts h GROUP BY h.hostname HAVING max(h.last_seen) >= since
  ),
  -- Only the sessions that meet [since, until], so that a short period does
  -- not aggregate the sessions of the whole retention; an old host id whose
  -- tolerance reaches into the period still counts.
  observed AS (
    SELECT h.hostname,
           range_agg(tstzrange(least(s.started_at + s.clock_skew, s.last_heartbeat),
                               s.last_heartbeat + tolerance)) AS observed
    FROM shawk.agent_sessions s
    JOIN shawk.hosts h ON h.id = s.host_id
    WHERE s.last_heartbeat > since - tolerance
      AND least(s.started_at + s.clock_skew, s.last_heartbeat) < until
    GROUP BY h.hostname
  )
  SELECT n.hostname, lower(g), upper(g)
  FROM names n
  LEFT JOIN observed o ON o.hostname = n.hostname
  CROSS JOIN LATERAL unnest(
    tstzmultirange(tstzrange(since, until)) - coalesce(o.observed, '{}'::tstzmultirange)
  ) AS g;
$$;
