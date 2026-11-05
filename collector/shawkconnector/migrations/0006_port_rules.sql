-- Rules of ports, written by the connector from its port_agnostic_services
-- and dynamic_ports. srun and salloc listen on a port chosen anew at every
-- run unless SrunPortRange is set, and slurmctld and slurmstepd connect to
-- it, so that every run would be a new dependency between services. The
-- edges keep their port: the direct match of shawk_v1.dependencies tells
-- the connections of different processes between two hosts apart by it.
-- The dependencies between services, and what appeared and disappeared,
-- are aggregated without the port (port 0) by these rules.

-- Tables ------------------------------------------------------------------

-- Services whose dependencies are aggregated without their port, by their
-- name as in service_name and peer_class.
CREATE TABLE shawk.port_agnostic_services (
  service text PRIMARY KEY
);

-- Ranges of ports by host and protocol, such as the SrunPortRange of a
-- Slurm cluster: a dependency on a server whose address is in addr and
-- whose port is in [port_from, port_to] is aggregated without its port. A
-- range for every host has the rows 0.0.0.0/0 and ::/0.
CREATE TABLE shawk.dynamic_ports (
  name      text NOT NULL,
  proto     text NOT NULL CHECK (proto IN ('tcp', 'udp')),
  addr      cidr NOT NULL,
  port_from integer NOT NULL CHECK (port_from BETWEEN 1 AND 65535),
  port_to   integer NOT NULL CHECK (port_to BETWEEN port_from AND 65535),
  PRIMARY KEY (name, proto, addr, port_from, port_to)
);

-- Helpers -----------------------------------------------------------------

-- The port of a dependency between services: 0 for a server service of
-- port_agnostic_services (slurm-job there names the processes of Slurm
-- jobs, units slurm/*, as the connector names them as peers) or a server
-- address and port in a range of dynamic_ports, the port otherwise. It
-- runs with the rights of its owner, as peer_class, since the views of the
-- contract call it with the rights of their reader.
CREATE FUNCTION shawk.dependency_port(server_service text, server_unit text, server_addr inet, port integer, proto text)
RETURNS integer
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
  SELECT CASE
    WHEN EXISTS (SELECT FROM shawk.port_agnostic_services a
                 WHERE a.service = dependency_port.server_service
                    OR (a.service = 'slurm-job' AND dependency_port.server_unit LIKE 'slurm/%'))
      OR EXISTS (SELECT FROM shawk.dynamic_ports r
                 WHERE r.proto = dependency_port.proto
                   AND dependency_port.port BETWEEN r.port_from AND r.port_to
                   AND dependency_port.server_addr <<= r.addr)
    THEN 0 ELSE dependency_port.port END
$$;

-- Dependencies between services in [since, until]: a peer without a known
-- service is named by peer_class, like in Prometheus, so that a service
-- that talks to rotating addresses (a cloud API, the clients of a public
-- server) is one dependency rather than one per address, and the port is
-- that of dependency_port. Called by the functions below, with the rights
-- of their owner.
CREATE OR REPLACE FUNCTION shawk.service_dependencies_between(since timestamptz, until timestamptz)
RETURNS TABLE (
  client_service text, server_service text, port integer, proto text,
  first_seen timestamptz, last_seen timestamptz,
  client_observed_until timestamptz, server_observed_until timestamptz,
  client_hosts text[], server_hosts text[])
LANGUAGE sql STABLE SET search_path = pg_catalog, pg_temp AS $$
SELECT
  n.client_service,
  n.server_service,
  shawk.dependency_port(n.server_service, d.server_unit, d.server_addr, d.port, d.proto),
  d.proto,
  min(d.first_seen), max(d.last_seen),
  max(d.client_observed_until), max(d.server_observed_until),
  array_agg(DISTINCT d.client_host) FILTER (WHERE d.client_host IS NOT NULL),
  array_agg(DISTINCT d.server_host) FILTER (WHERE d.server_host IS NOT NULL)
FROM shawk_v1.dependencies_between(since, until) d
CROSS JOIN LATERAL (
  SELECT coalesce(d.client_service, shawk_v1.peer_class(d.client_addr)) AS client_service,
         coalesce(d.server_service, shawk_v1.peer_class(d.server_addr)) AS server_service
) n
GROUP BY 1, 2, 3, 4
$$;

-- Dependencies between services over the whole history, as
-- service_dependencies_between.
CREATE OR REPLACE VIEW shawk.service_dependencies AS
SELECT
  n.client_service,
  n.server_service,
  shawk.dependency_port(n.server_service, d.server_unit, d.server_addr, d.port, d.proto) AS port,
  d.proto,
  min(d.first_seen)                             AS first_seen,
  max(d.last_seen)                              AS last_seen,
  max(d.client_observed_until)                  AS client_observed_until,
  max(d.server_observed_until)                  AS server_observed_until,
  array_agg(DISTINCT d.client_host) FILTER (WHERE d.client_host IS NOT NULL) AS client_hosts,
  array_agg(DISTINCT d.server_host) FILTER (WHERE d.server_host IS NOT NULL) AS server_hosts
FROM shawk_v1.dependencies d
CROSS JOIN LATERAL (
  SELECT coalesce(d.client_service, shawk_v1.peer_class(d.client_addr)) AS client_service,
         coalesce(d.server_service, shawk_v1.peer_class(d.server_addr)) AS server_service
) n
GROUP BY 1, 2, 3, 4;

-- Maintenance -------------------------------------------------------------

-- Adds the dependencies of known_dependencies on services of
-- port_agnostic_services to it under port 0, so that a dependency known
-- before its service was configured is not new under it, even once its
-- edges are gone. Ranges of dynamic_ports are not applied here: they hold
-- for addresses, which known_dependencies does not have, and a dependency
-- known only outside a range would hide one that is new in it. The
-- connector calls it when it changes the rules, and clears
-- known_dependencies_state, so that the next refresh rebuilds the table
-- from every edge kept under the new rules. It takes the lock of
-- refresh_known_dependencies, so that the two do not upsert the same rows
-- in different orders. It returns the rows upserted.
CREATE FUNCTION shawk.aggregate_known_dependencies() RETURNS bigint
LANGUAGE plpgsql SET search_path = pg_catalog, pg_temp AS $$
DECLARE
  n bigint;
BEGIN
  PERFORM pg_advisory_xact_lock(1936220536);  -- 0x73686178, see refresh_known_dependencies
  INSERT INTO shawk.known_dependencies AS k (client_service, server_service, port, proto, first_seen, last_seen)
  SELECT d.client_service, d.server_service, 0, d.proto, min(d.first_seen), max(d.last_seen)
  FROM shawk.known_dependencies d
  WHERE d.port <> 0
    AND EXISTS (SELECT FROM shawk.port_agnostic_services a WHERE a.service = d.server_service)
  GROUP BY d.client_service, d.server_service, d.proto
  ON CONFLICT (client_service, server_service, port, proto) DO UPDATE SET
    first_seen = least(k.first_seen, excluded.first_seen),
    last_seen  = greatest(k.last_seen, excluded.last_seen);
  GET DIAGNOSTICS n = ROW_COUNT;
  RETURN n;
END
$$;
