-- The hosts expected in a cluster, which the shawk connector writes from
-- its inventory_file, and the contract over them: the hosts with their
-- addresses, and those whose agent never reported.

-- Tables ------------------------------------------------------------------

-- The static inventory of hosts (docs/design.md, section 5.6): the hosts
-- expected in a cluster whose hosts are known in advance, with all their
-- addresses, including hosts that cannot run an agent (storage appliances,
-- switches, BMCs). The connector writes it from its inventory_file, which
-- it reads every write interval, and replaces the rows in one transaction
-- when the contents change, so that readers see either the old inventory
-- or the new one. A host is named as its agent sends host.name.
CREATE TABLE shawk.inventory_hosts (
  host       text PRIMARY KEY,
  slurm_node text UNIQUE,                  -- the NodeName of the host in Slurm; NULL if none
  roles      text[] NOT NULL DEFAULT '{}', -- free text of the operator, sorted
  agent      boolean NOT NULL DEFAULT true -- an agent is expected to run on the host
);

-- Every address of every host of the inventory. An address belongs to one
-- host at most, so that an address maps to a host without ambiguity.
CREATE TABLE shawk.inventory_addrs (
  addr inet PRIMARY KEY CHECK (masklen(addr) = CASE family(addr) WHEN 4 THEN 32 ELSE 128 END),
  host text NOT NULL REFERENCES shawk.inventory_hosts ON DELETE CASCADE
);
CREATE INDEX inventory_addrs_host ON shawk.inventory_addrs (host);

-- When the inventory was read. read_at is the latest time a connector read
-- the contents above from a valid file; when the file cannot be read or is
-- invalid the contents stay, and failed_at and error tell the latest
-- failure since. digest identifies the contents, so that a connector
-- writes them only when they change. One row at most.
CREATE TABLE shawk.inventory_state (
  singleton boolean PRIMARY KEY DEFAULT true CHECK (singleton),
  digest    text,                          -- NULL until a valid file was read
  read_at   timestamptz,
  failed_at timestamptz,                   -- NULL unless the latest read failed
  error     text
);

-- Contract ----------------------------------------------------------------

-- The hosts of the inventory with their addresses.
CREATE VIEW shawk_v1.inventory AS
SELECT h.host, h.slurm_node, h.roles, h.agent,
       coalesce(array_agg(a.addr ORDER BY a.addr) FILTER (WHERE a.addr IS NOT NULL), '{}') AS addrs
FROM shawk.inventory_hosts h
LEFT JOIN shawk.inventory_addrs a ON a.host = h.host
GROUP BY h.host;

-- The host of every address of the inventory, one row per address: join
-- an address on addr to name its host.
CREATE VIEW shawk_v1.inventory_addrs AS
SELECT a.addr, a.host, h.slurm_node, h.roles, h.agent
FROM shawk.inventory_addrs a
JOIN shawk.inventory_hosts h ON h.host = a.host;

-- When the inventory was read, the latest failure since, and how many
-- hosts it has. No row when no connector has an inventory_file.
CREATE VIEW shawk_v1.inventory_status AS
SELECT s.read_at, s.failed_at, s.error,
       (SELECT count(*) FROM shawk.inventory_hosts) AS hosts
FROM shawk.inventory_state s;

-- The hosts of the inventory expected to run an agent (agent is true)
-- whose agent never reported, within the retention: no host has their
-- name. seen_as names the hosts whose agents reported an address of the
-- inventory host, as an agent whose host.name differs from the inventory
-- (a short name instead of the FQDN) would.
CREATE FUNCTION shawk_v1.never_observed()
RETURNS TABLE (host text, slurm_node text, roles text[], seen_as text[])
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
  SELECT i.host, i.slurm_node, i.roles,
         coalesce((SELECT array_agg(DISTINCT h.hostname ORDER BY h.hostname)
                   FROM shawk.inventory_addrs ia
                   JOIN shawk.host_addrs a ON a.addr = ia.addr
                   JOIN shawk.hosts h ON h.id = a.host_id
                   WHERE ia.host = i.host), '{}')
  FROM shawk.inventory_hosts i
  WHERE i.agent
    AND NOT EXISTS (SELECT FROM shawk.hosts h WHERE h.hostname = i.host)
  ORDER BY i.host;
$$;
