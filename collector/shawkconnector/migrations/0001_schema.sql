-- The PostgreSQL schema of shawk.
--
-- The tables, views and functions in the schema shawk are internal: only
-- the shawk connector writes them. The views and functions in the schema
-- shawk_v1 are the contract for dashboards, alerts and other readers; the
-- functions of the contract run with the rights of their owner, so that
-- readers need no access to the tables.
--
-- Observations (edges, listeners, processes, learned translations) carry
-- the times of the agent that made them. Whether a host is alive is judged
-- by the clock of the connector: heartbeats, the last_seen of hosts and of
-- their addresses, and the periods of partial observation are the times of
-- receipt, and each session keeps the difference to the clock of its agent
-- as clock_skew.
--
-- Requires PostgreSQL 14 or later (multiranges).

CREATE SCHEMA IF NOT EXISTS shawk;
CREATE SCHEMA IF NOT EXISTS shawk_v1;

-- Tables ------------------------------------------------------------------

CREATE TABLE shawk.hosts (
  id            text PRIMARY KEY,          -- hash of the machine id and the host name
  machine_id    text NOT NULL,             -- host.id; matches the data of OBI
  hostname      text NOT NULL,
  kernel        text NOT NULL,
  agent_version text NOT NULL,
  first_seen    timestamptz NOT NULL,
  last_seen     timestamptz NOT NULL
);

-- Periods in which an agent observed its host. An agent starts a new
-- session when it starts, or when it could not send for longer than its
-- idle TTL. started_at is by the clock of the agent, last_heartbeat by the
-- clock of the connector.
--
-- counters_started is when the counters of the agent started, by the clock
-- of the agent as it sends it: the same for every session of one run of the
-- agent, so that its dropped flows are compared within the run. It is NULL
-- when the agent does not send it; the session then stands for the run.
CREATE TABLE shawk.agent_sessions (
  host_id          text NOT NULL REFERENCES shawk.hosts,
  started_at       timestamptz NOT NULL,     -- shawk.agent.segment.start
  last_heartbeat   timestamptz NOT NULL,     -- observations up to here are written
  udp_traced       boolean NOT NULL,
  netns_scope      text NOT NULL,            -- 'all' or the inode of the traced netns
  dropped_flows    bigint NOT NULL DEFAULT 0,
  clock_skew       interval NOT NULL DEFAULT '0',  -- how far the clock of the host is behind the connector
  peer_fold        text NOT NULL DEFAULT 'none',   -- the peers the agent folds: none, in (of its servers) or all
  peer_internal    cidr[],                   -- the ranges of peers it keeps exact; NULL if it does not tell
  counters_started timestamptz,
  PRIMARY KEY (host_id, started_at)
);
CREATE INDEX agent_sessions_heartbeat ON shawk.agent_sessions (host_id, last_heartbeat);
CREATE INDEX agent_sessions_last_heartbeat ON shawk.agent_sessions (last_heartbeat);

-- Periods in which an agent observed its host but dropped flows because its
-- flow table was full: dependencies active then may be missing. The
-- connector records a period when the dropped flows of a run of the agent
-- grow between two heartbeats, and extends the latest period of the host
-- when the next one meets it.
CREATE TABLE shawk.partial_observations (
  host_id       text NOT NULL REFERENCES shawk.hosts,
  started_at    timestamptz NOT NULL,     -- of the session
  period_start  timestamptz NOT NULL,
  period_end    timestamptz NOT NULL,
  dropped_flows bigint NOT NULL,          -- flow updates dropped in the period
  PRIMARY KEY (host_id, started_at, period_start)
);
CREATE INDEX partial_observations_period_end ON shawk.partial_observations (period_end);

-- The addresses of a host, one row per period it held an address in: an
-- address that moves to another host and comes back (a VIP that fails over
-- and back, a reused pod or DHCP address) is not held in between. The
-- connector starts a new period when an address was not seen for longer
-- than the alive window.
CREATE TABLE shawk.host_addrs (
  host_id    text NOT NULL REFERENCES shawk.hosts,
  addr       inet NOT NULL,
  first_seen timestamptz NOT NULL,
  last_seen  timestamptz NOT NULL,
  PRIMARY KEY (host_id, addr, first_seen)
);
CREATE INDEX host_addrs_addr ON shawk.host_addrs (addr, last_seen);
CREATE INDEX host_addrs_last_seen ON shawk.host_addrs (last_seen);

-- Processes of one unit with the same comm but different service names
-- (OTEL_SERVICE_NAME) are different processes.
CREATE TABLE shawk.processes (
  id           bigserial PRIMARY KEY,
  host_id      text NOT NULL REFERENCES shawk.hosts,
  unit         text NOT NULL,
  comm         text NOT NULL,
  exe          text NOT NULL DEFAULT '',
  service_name text NOT NULL,              -- as the job label: [namespace/]name
  first_seen   timestamptz NOT NULL,
  last_seen    timestamptz NOT NULL,
  UNIQUE (host_id, unit, comm, service_name)
);
CREATE INDEX processes_last_seen ON shawk.processes (last_seen);

-- A dependency observed on a host: a bundled flow between a local process
-- and a remote address. port is the service port. The remote address of
-- the peers an agent folded is the network 0.0.0.0/0 or ::/0, which never
-- equals an address, so a folded edge never matches an edge of another
-- host.
CREATE TABLE shawk.edges (
  id          bigserial PRIMARY KEY,
  host_id     text NOT NULL REFERENCES shawk.hosts,
  process_id  bigint NOT NULL REFERENCES shawk.processes,
  role        text NOT NULL CHECK (role IN ('client', 'server')),
  proto       text NOT NULL CHECK (proto IN ('tcp', 'udp')),
  local_addr  inet NOT NULL,
  remote_addr inet NOT NULL,
  port        integer NOT NULL,
  netns       bigint NOT NULL,
  first_seen  timestamptz NOT NULL,
  last_seen   timestamptz NOT NULL,
  UNIQUE (host_id, role, proto, local_addr, remote_addr, port, netns, process_id)
);
CREATE INDEX edges_client ON shawk.edges (proto, remote_addr, port) WHERE role = 'client';
CREATE INDEX edges_server ON shawk.edges (proto, local_addr, port) WHERE role = 'server';
CREATE INDEX edges_server_host ON shawk.edges (host_id, last_seen) WHERE role = 'server';
CREATE INDEX edges_last_seen ON shawk.edges (last_seen);
CREATE INDEX edges_first_seen ON shawk.edges (first_seen);
CREATE INDEX edges_process ON shawk.edges (process_id);

-- The listening sockets of a host with their latest owner, which is NULL
-- while it is unknown; service_endpoints reads them.
CREATE TABLE shawk.listeners (
  host_id    text NOT NULL REFERENCES shawk.hosts,
  process_id bigint REFERENCES shawk.processes,  -- NULL if the owner is unknown
  proto      text NOT NULL,
  addr       inet NOT NULL,
  port       integer NOT NULL,
  netns      bigint NOT NULL,
  first_seen timestamptz NOT NULL,
  last_seen  timestamptz NOT NULL,
  PRIMARY KEY (host_id, proto, addr, port, netns)
);
CREATE INDEX listeners_process ON shawk.listeners (process_id);
CREATE INDEX listeners_last_seen ON shawk.listeners (last_seen);

-- Every known owner of a listener, so that the processes that listened on a
-- port before it changed hands are kept.
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

-- Named address ranges of peers, written by the connector from its
-- peer_cidrs, so that PostgreSQL names a peer without a known service like
-- the connector names it in service.peer.name.
CREATE TABLE shawk.peer_cidrs (
  prefix cidr PRIMARY KEY,
  name   text NOT NULL
);

-- Translations of addresses by relays without an agent: a load balancer, a
-- keepalived/LVS virtual address, a TCP proxy. The client connects to a
-- virtual address; the server sees its own address, and as the client
-- either the address of the client (DNAT) or an address of the relay (SNAT,
-- a proxy), so the two sides of such connections do not have the same
-- addresses.
--
-- The connector writes the translations of its configuration here. A
-- translation has rows on three sides; every row of a side combines with
-- every row of the others:
--
--   virtual  an address clients connect to (a single address), and its port
--            (0: every port);
--   backend  the addresses of the servers it forwards to (a range), and
--            their port (0: the port the client connected to);
--   source   the addresses the servers see the clients at (a range); a
--            translation without sources keeps the address of the client.
CREATE TABLE shawk.translations (
  name  text NOT NULL,
  side  text NOT NULL CHECK (side IN ('virtual', 'backend', 'source')),
  proto text NOT NULL CHECK (proto IN ('tcp', 'udp')),
  addr  cidr NOT NULL,
  port  integer NOT NULL DEFAULT 0 CHECK (port BETWEEN 0 AND 65535),
  PRIMARY KEY (name, side, proto, addr, port)
);

-- Translations of addresses learned by the agents of the hosts that make
-- them from conntrack: DNAT of Docker published ports and of kube-proxy,
-- IPVS with net.ipv4.vs.conntrack=1, SNAT and masquerade. A row tells that
-- the client connected to the virtual address and port, and that the
-- backend saw the connection from the source on the backend port: the
-- source is the client unless the host replaced its address. The times are
-- those of the agent, like those of edges.
CREATE TABLE shawk.learned_translations (
  host_id      text    NOT NULL REFERENCES shawk.hosts,
  proto        text    NOT NULL CHECK (proto IN ('tcp', 'udp')),
  netns        bigint  NOT NULL,
  client_addr  inet    NOT NULL,
  virtual_addr inet    NOT NULL,
  virtual_port integer NOT NULL CHECK (virtual_port BETWEEN 0 AND 65535),
  source_addr  inet    NOT NULL,
  backend_addr inet    NOT NULL,
  backend_port integer NOT NULL CHECK (backend_port BETWEEN 0 AND 65535),
  first_seen   timestamptz NOT NULL,
  last_seen    timestamptz NOT NULL,
  PRIMARY KEY (host_id, proto, netns, client_addr, virtual_addr, virtual_port, source_addr, backend_addr, backend_port)
);
CREATE INDEX learned_translations_client ON shawk.learned_translations (proto, virtual_addr, virtual_port, client_addr);
CREATE INDEX learned_translations_server ON shawk.learned_translations (proto, backend_addr, backend_port, source_addr);
CREATE INDEX learned_translations_last_seen ON shawk.learned_translations (last_seen);

-- The dependencies between services ever seen, with when they were first
-- and last seen. A dependency is new when it was never seen before, not
-- when it comes back on new edges (a new container, an hourly job): edges
-- are kept per process, address and network namespace, and a dependency
-- idle for a while comes back on edges first seen then. The connector
-- brings the table up to date every few minutes
-- (refresh_known_dependencies).
CREATE TABLE shawk.known_dependencies (
  client_service text NOT NULL,
  server_service text NOT NULL,
  port           integer NOT NULL,
  proto          text NOT NULL,
  first_seen     timestamptz NOT NULL,
  last_seen      timestamptz NOT NULL,
  PRIMARY KEY (client_service, server_service, port, proto)
);
CREATE INDEX known_dependencies_last_seen ON shawk.known_dependencies (last_seen);

CREATE TABLE shawk.known_dependencies_state (
  id              boolean PRIMARY KEY DEFAULT true CHECK (id),
  refreshed_until timestamptz NOT NULL
);

-- Helpers -----------------------------------------------------------------

-- How long an agent can be silent and still be alive: a few write
-- intervals of the connector.
CREATE FUNCTION shawk.alive_window() RETURNS interval
LANGUAGE sql IMMUTABLE AS $$ SELECT interval '5 minutes' $$;

-- The version of the schema and the history of its migrations, which a
-- connector that does not migrate checks before it writes, as shawk-migrate
-- does. They run with the rights of their owner: the history of migrations
-- (shawk.schema_migrations, created by shawk-migrate) belongs to the owner.
-- A schema with schema_version() but without schema_history() was created
-- before the migrations were consolidated into this one.
CREATE FUNCTION shawk.schema_version() RETURNS integer
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
  SELECT coalesce(max(version), 0) FROM shawk.schema_migrations
$$;

CREATE FUNCTION shawk.schema_history() RETURNS TABLE (version integer, name text)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
  SELECT m.version, m.name FROM shawk.schema_migrations m ORDER BY m.version
$$;

-- The name of a peer without a known service: the narrowest range of
-- peer_cidrs that holds it, ~unresolved for an address not routed on the
-- Internet, ~external otherwise, including the networks of folded peers.
-- Prometheus has the same names in service.peer.name (except ~other, which
-- folds peers beyond max_peers).
CREATE FUNCTION shawk_v1.peer_class(addr inet) RETURNS text
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
  SELECT coalesce(
    (SELECT c.name FROM shawk.peer_cidrs c WHERE addr <<= c.prefix
     ORDER BY masklen(c.prefix) DESC, c.prefix LIMIT 1),
    CASE WHEN addr <<= inet '10.0.0.0/8' OR addr <<= inet '172.16.0.0/12' OR addr <<= inet '192.168.0.0/16'
           OR addr <<= inet '127.0.0.0/8' OR addr <<= inet '169.254.0.0/16' OR addr <<= inet '100.64.0.0/10'
           OR addr <<= inet 'fc00::/7' OR addr <<= inet 'fe80::/10' OR addr = inet '::1'
           OR addr = inet '0.0.0.0' OR addr = inet '::'
         THEN '~unresolved' ELSE '~external' END)
$$;

-- Addresses that several hosts held at the same time for more than 10
-- minutes, such as the gateway of a container bridge (172.17.0.1 on every
-- Docker host). An edge with such an address is matched with edges of the
-- same host only. An address reused by another host soon after is not
-- shared.
CREATE VIEW shawk.shared_addrs AS
SELECT DISTINCT a.addr
FROM shawk.host_addrs a
WHERE EXISTS (
  SELECT FROM shawk.host_addrs b
  WHERE b.addr = a.addr AND b.host_id <> a.host_id
    AND least(a.last_seen, b.last_seen) - greatest(a.first_seen, b.first_seen) > interval '10 minutes');

-- Dependencies ------------------------------------------------------------

-- The dependencies active in [since, until]: the client and server edges
-- of a connection matched into one row. Edges are taken with a margin of
-- 15 minutes, matched, and the matched rows filtered by the period: the
-- sides of one connection are reported by different agents at different
-- times, so that at the edges of the period one side would otherwise be
-- left out and the other come out alone. A dependency seen on one side only
-- has no agent on the other side, or a NAT or load balancer between that no
-- translation describes.
--
-- Edges are matched by their addresses and port, in the scope in which the
-- addresses identify the other side: the host and network namespace for
-- loopback, the host for shared addresses, everywhere otherwise. The edges
-- that their addresses do not match are matched through translations:
--
--   - a client edge whose server address is a virtual address of a
--     translation is matched with the server edges at its backends, on the
--     port of the backend (or the port of the client edge), and with times
--     that overlap (within 2 minutes, for the clocks of the hosts and the
--     intervals of the agents); not over the periods in which a server edge
--     at the virtual address matches it by address (a relay that runs an
--     agent), whose row then has the period of that server edge;
--   - through a translation that keeps the address of the client, the
--     server edge has the address of the client (in the same scope);
--     through one with sources, it has an address of a source, and is
--     matched with every client edge to the translation: the server cannot
--     tell the clients behind a relay apart. Such a server edge also stays
--     on a row of its own, since clients without an agent may be behind the
--     relay too;
--   - learned translations match a client edge and a server edge like the
--     translations of the configuration, which come first, with the
--     translation '~learned';
--   - a matched row is the dependency of the client on the server: the
--     address and port of the server, and the period both edges were
--     active in, since the server edge may serve other clients (behind a
--     relay) and the client edge other servers (the other backends) over
--     another period. The last columns tell the virtual address and port
--     the client connected to and the name of the translation; they are
--     NULL on rows matched by address;
--   - an edge keeps a row of its own if its matched rows leave a part of
--     its period (in the period asked for, a part in it): a client edge also
--     reached backends without an agent, or before their agents started,
--     and a server edge served the client directly. The row runs from the
--     start of the edge to the end of the last part left;
--   - on these rows, the observation of a side whose edge outlives the row
--     is NULL: it tells nothing of the end of the row, which is for the
--     other side to tell, so that a stopped agent does not make the
--     dependency look removed.
--
-- client_observed_until and server_observed_until are the latest heartbeats
-- of the hosts: an old last_seen with a recent observed_until means no
-- longer used; both old means no longer observed.
CREATE FUNCTION shawk_v1.dependencies_between(since timestamptz, until timestamptz)
RETURNS TABLE (
  client_host text, client_service text, client_unit text, client_addr inet,
  server_host text, server_service text, server_unit text, server_addr inet,
  port integer, proto text, first_seen timestamptz, last_seen timestamptz,
  observed_by text, client_observed_until timestamptz, server_observed_until timestamptz,
  virtual_addr inet, virtual_port integer, translation text)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
WITH shared AS (SELECT addr FROM shawk.shared_addrs),
e AS (
  SELECT e.id, e.host_id, e.role, e.proto, e.local_addr, e.remote_addr, e.port, e.netns,
         e.first_seen, e.last_seen, p.service_name, p.unit, h.hostname,
         -- The scope in which the addresses of the edge identify its other
         -- side: the host and network namespace for loopback, the host for
         -- shared addresses, everywhere ('') otherwise.
         CASE WHEN e.remote_addr << inet '127.0.0.0/8' OR e.remote_addr = inet '::1'
                THEN e.host_id || '/' || e.netns::text
              WHEN e.local_addr IN (SELECT addr FROM shared) OR e.remote_addr IN (SELECT addr FROM shared)
                THEN e.host_id
              ELSE '' END AS scope
  FROM shawk.edges e
  JOIN shawk.processes p ON p.id = e.process_id
  JOIN shawk.hosts h ON h.id = e.host_id
  WHERE e.last_seen >= since - interval '15 minutes' AND e.first_seen <= until + interval '15 minutes'
),
observed AS (
  SELECT host_id, max(last_heartbeat) AS observed_until
  FROM shawk.agent_sessions GROUP BY host_id
),
-- Client edges to a virtual address, read through the index of client
-- edges. client_scope is the scope of the address of the client alone,
-- which is all the two sides of a connection through a translation share.
-- direct is when server edges at the virtual address matched the client
-- edge by address, within the margin: a relay that runs an agent served
-- it then, rather than the backends.
cv AS (
  SELECT DISTINCT ON (c.id, v.name)
         c.id, c.host_id, c.proto, c.local_addr, c.remote_addr, c.port, c.first_seen, c.last_seen,
         p.service_name, p.unit, h.hostname, v.name AS translation,
         CASE WHEN c.local_addr << inet '127.0.0.0/8' OR c.local_addr = inet '::1'
                THEN c.host_id || '/' || c.netns::text
              WHEN c.local_addr IN (SELECT addr FROM shared)
                THEN c.host_id
              ELSE '' END AS client_scope,
         (SELECT range_agg(tstzrange(least(s.first_seen, s.last_seen) - interval '2 minutes',
                                     greatest(s.first_seen, s.last_seen) + interval '2 minutes', '[]'))
          FROM shawk.edges s
          WHERE s.role = 'server' AND s.proto = c.proto AND s.local_addr = c.remote_addr AND s.port = c.port
            AND s.remote_addr = c.local_addr
            AND s.last_seen >= since - interval '15 minutes' AND s.first_seen <= until + interval '15 minutes'
            AND CASE WHEN s.remote_addr << inet '127.0.0.0/8' OR s.remote_addr = inet '::1'
                        THEN s.host_id || '/' || s.netns::text
                      WHEN s.local_addr IN (SELECT addr FROM shared) OR s.remote_addr IN (SELECT addr FROM shared)
                        THEN s.host_id
                      ELSE '' END
              = CASE WHEN c.remote_addr << inet '127.0.0.0/8' OR c.remote_addr = inet '::1'
                        THEN c.host_id || '/' || c.netns::text
                      WHEN c.local_addr IN (SELECT addr FROM shared) OR c.remote_addr IN (SELECT addr FROM shared)
                        THEN c.host_id
                      ELSE '' END) AS direct
  FROM shawk.translations v
  JOIN shawk.edges c
    ON c.role = 'client' AND c.proto = v.proto AND c.remote_addr = v.addr AND v.port IN (0, c.port)
  JOIN shawk.processes p ON p.id = c.process_id
  JOIN shawk.hosts h ON h.id = c.host_id
  WHERE v.side = 'virtual'
    AND c.last_seen >= since - interval '15 minutes' AND c.first_seen <= until + interval '15 minutes'
  ORDER BY c.id, v.name
),
-- The backends of the translations, with the ports of their virtual
-- addresses and their sources; exact tells that the backend is a single
-- address.
bk AS (
  SELECT b.name, b.proto, b.addr, b.port,
         masklen(b.addr) = CASE family(b.addr) WHEN 4 THEN 32 ELSE 128 END AS exact,
         ARRAY(SELECT v.port FROM shawk.translations v
               WHERE v.name = b.name AND v.side = 'virtual' AND v.proto = b.proto) AS virtual_ports,
         ARRAY(SELECT x.addr FROM shawk.translations x
               WHERE x.name = b.name AND x.side = 'source' AND x.proto = b.proto) AS sources
  FROM shawk.translations b
  WHERE b.side = 'backend'
),
-- Server edges at the address of a backend, read through the index of
-- server edges: a single address by equality, a range by its bounds.
sa AS (
  SELECT s.*, b.addr::inet AS backend
  FROM (SELECT DISTINCT proto, addr FROM bk WHERE exact) b
  JOIN shawk.edges s ON s.role = 'server' AND s.proto = b.proto AND s.local_addr = b.addr
  WHERE s.last_seen >= since - interval '15 minutes' AND s.first_seen <= until + interval '15 minutes'
  UNION ALL
  SELECT s.*, r.addr::inet
  FROM (SELECT DISTINCT proto, addr FROM bk WHERE NOT exact) r
  JOIN shawk.edges s
    ON  s.role = 'server' AND s.proto = r.proto AND s.local_addr <<= r.addr
    AND s.local_addr >= r.addr
    AND s.local_addr <= set_masklen(broadcast(r.addr), CASE family(r.addr) WHEN 4 THEN 32 ELSE 128 END)
  WHERE s.last_seen >= since - interval '15 minutes' AND s.first_seen <= until + interval '15 minutes'
),
-- Server edges at a backend, on its port or on the port of a virtual
-- address, from a source if the translation has any. fixed tells that the
-- backend has the port of the edge, rather than the port the client
-- connected to.
sb AS (
  SELECT DISTINCT ON (sa.id, bk.name)
         sa.id, sa.host_id, sa.proto, sa.local_addr, sa.remote_addr, sa.port, sa.first_seen, sa.last_seen,
         p.service_name, p.unit, h.hostname, bk.name AS translation,
         bk.port <> 0 AS fixed, cardinality(bk.sources) > 0 AS snat,
         CASE WHEN sa.remote_addr << inet '127.0.0.0/8' OR sa.remote_addr = inet '::1'
                THEN sa.host_id || '/' || sa.netns::text
              WHEN sa.remote_addr IN (SELECT addr FROM shared)
                THEN sa.host_id
              ELSE '' END AS client_scope
  FROM sa
  JOIN bk ON bk.addr = sa.backend AND bk.proto = sa.proto AND bk.port IN (0, sa.port)
  JOIN shawk.processes p ON p.id = sa.process_id
  JOIN shawk.hosts h ON h.id = sa.host_id
  WHERE (bk.port <> 0 OR 0 = ANY (bk.virtual_ports) OR sa.port = ANY (bk.virtual_ports))
    AND (cardinality(bk.sources) = 0 OR sa.remote_addr <<= ANY (bk.sources))
  ORDER BY sa.id, bk.name, bk.port <> 0 DESC
),
-- Learned translations (shawk.learned_translations): a client edge c and a
-- server edge s match the rows of hosts that translated the connections
-- of the client of c to its server address and port into the backend of
-- s, seen from the peer of s; the client address is loopback in the host
-- and namespace of the row, shared on its host, anywhere otherwise, and so
-- are the backend and the source. A client edge to a virtual address of a
-- static translation is matched through it only. The rows that overlap c
-- and s, within 2 minutes, are combined: the period of the pair is the
-- part of those of c and s that their span covers.
lc AS (
  SELECT c.id, c.proto, c.first_seen AS c_first, c.last_seen AS c_last,
         l.host_id AS l_host, l.netns AS l_netns, l.source_addr, l.backend_addr, l.backend_port,
         l.first_seen AS l_first, l.last_seen AS l_last
  FROM shawk.learned_translations l
  JOIN shawk.edges c
    ON  c.role = 'client' AND c.proto = l.proto AND c.remote_addr = l.virtual_addr AND c.port = l.virtual_port
    AND c.local_addr = l.client_addr
  -- Every learned row of the edges in the period, not only those in it, so
  -- that a pair has the span of its rows, as in the view.
  WHERE CASE WHEN c.local_addr << inet '127.0.0.0/8' OR c.local_addr = inet '::1'
               THEN c.host_id = l.host_id AND c.netns = l.netns
             WHEN c.local_addr IN (SELECT addr FROM shared) THEN c.host_id = l.host_id
             ELSE true END
    AND c.first_seen <= l.last_seen + interval '2 minutes'
    AND l.first_seen <= c.last_seen + interval '2 minutes'
    AND c.last_seen >= since - interval '15 minutes' AND c.first_seen <= until + interval '15 minutes'
    AND NOT EXISTS (
      SELECT FROM shawk.translations v
      WHERE v.side = 'virtual' AND v.proto = c.proto AND v.addr = c.remote_addr AND v.port IN (0, c.port))
),
lp AS (
  SELECT lc.id AS cid, s.id AS sid, min(lc.l_first) AS l_first, max(lc.l_last) AS l_last
  FROM lc
  JOIN shawk.edges s
    ON  s.role = 'server' AND s.proto = lc.proto AND s.local_addr = lc.backend_addr AND s.port = lc.backend_port
    AND s.remote_addr = lc.source_addr
  WHERE CASE WHEN s.local_addr << inet '127.0.0.0/8' OR s.local_addr = inet '::1'
                  OR s.remote_addr << inet '127.0.0.0/8' OR s.remote_addr = inet '::1'
               THEN s.host_id = lc.l_host AND s.netns = lc.l_netns
             WHEN s.local_addr IN (SELECT addr FROM shared) OR s.remote_addr IN (SELECT addr FROM shared)
               THEN s.host_id = lc.l_host
             ELSE true END
    AND s.first_seen <= lc.l_last + interval '2 minutes'
    AND lc.l_first <= s.last_seen + interval '2 minutes'
    AND s.first_seen <= lc.c_last + interval '2 minutes'
    AND lc.c_first <= s.last_seen + interval '2 minutes'
    AND s.last_seen >= since - interval '15 minutes' AND s.first_seen <= until + interval '15 minutes'
  GROUP BY lc.id, s.id
),
-- The client and server edges a translation may match: on the port of the
-- backend or the port of the client edge, with times that overlap; through
-- a translation without sources, with the address of the client. p_first
-- and p_last are the period both were active in.
pairs AS (
  SELECT cv.id AS cid, cv.host_id AS c_host_id, cv.hostname AS c_hostname, cv.service_name AS c_service,
         cv.unit AS c_unit, cv.local_addr AS c_local, cv.remote_addr AS c_remote, cv.port AS c_port,
         cv.first_seen AS c_first, cv.last_seen AS c_last, cv.direct,
         sb.id AS sid, sb.host_id AS s_host_id, sb.hostname AS s_hostname, sb.service_name AS s_service,
         sb.unit AS s_unit, sb.local_addr AS s_local, sb.port AS s_port,
         sb.first_seen AS s_first, sb.last_seen AS s_last,
         cv.proto, cv.translation, false AS snat,
         least(greatest(cv.first_seen, sb.first_seen), least(cv.last_seen, sb.last_seen)) AS p_first,
         greatest(greatest(cv.first_seen, sb.first_seen), least(cv.last_seen, sb.last_seen)) AS p_last
  FROM cv JOIN sb
    ON  sb.translation = cv.translation AND sb.proto = cv.proto
    AND sb.remote_addr = cv.local_addr AND sb.client_scope = cv.client_scope
  WHERE NOT sb.snat
    AND (sb.fixed OR sb.port = cv.port)
    AND cv.first_seen <= sb.last_seen + interval '2 minutes'
    AND sb.first_seen <= cv.last_seen + interval '2 minutes'
  UNION ALL
  SELECT cv.id, cv.host_id, cv.hostname, cv.service_name, cv.unit, cv.local_addr, cv.remote_addr, cv.port,
         cv.first_seen, cv.last_seen, cv.direct,
         sb.id, sb.host_id, sb.hostname, sb.service_name, sb.unit, sb.local_addr, sb.port,
         sb.first_seen, sb.last_seen,
         cv.proto, cv.translation, true,
         least(greatest(cv.first_seen, sb.first_seen), least(cv.last_seen, sb.last_seen)),
         greatest(greatest(cv.first_seen, sb.first_seen), least(cv.last_seen, sb.last_seen))
  FROM cv JOIN sb ON sb.translation = cv.translation AND sb.proto = cv.proto
  WHERE sb.snat
    AND (sb.fixed OR sb.port = cv.port)
    AND cv.first_seen <= sb.last_seen + interval '2 minutes'
    AND sb.first_seen <= cv.last_seen + interval '2 minutes'
  UNION ALL
  SELECT c.id, c.host_id, hc.hostname, pc.service_name, pc.unit, c.local_addr, c.remote_addr, c.port,
         c.first_seen, c.last_seen,
         -- direct, as for the client edges of static translations.
         (SELECT range_agg(tstzrange(least(d.first_seen, d.last_seen) - interval '2 minutes',
                                     greatest(d.first_seen, d.last_seen) + interval '2 minutes', '[]'))
          FROM shawk.edges d
          WHERE d.role = 'server' AND d.proto = c.proto AND d.local_addr = c.remote_addr AND d.port = c.port
            AND d.remote_addr = c.local_addr
            AND d.last_seen >= since - interval '15 minutes' AND d.first_seen <= until + interval '15 minutes'
            AND CASE WHEN d.remote_addr << inet '127.0.0.0/8' OR d.remote_addr = inet '::1'
                        THEN d.host_id || '/' || d.netns::text
                      WHEN d.local_addr IN (SELECT addr FROM shared) OR d.remote_addr IN (SELECT addr FROM shared)
                        THEN d.host_id
                      ELSE '' END
              = CASE WHEN c.remote_addr << inet '127.0.0.0/8' OR c.remote_addr = inet '::1'
                        THEN c.host_id || '/' || c.netns::text
                      WHEN c.local_addr IN (SELECT addr FROM shared) OR c.remote_addr IN (SELECT addr FROM shared)
                        THEN c.host_id
                      ELSE '' END),
         s.id, s.host_id, hs.hostname, ps.service_name, ps.unit, s.local_addr, s.port,
         s.first_seen, s.last_seen,
         c.proto, '~learned'::text, s.remote_addr <> c.local_addr,
         least(greatest(c.first_seen, s.first_seen, lp.l_first), least(c.last_seen, s.last_seen, lp.l_last)),
         greatest(greatest(c.first_seen, s.first_seen, lp.l_first), least(c.last_seen, s.last_seen, lp.l_last))
  FROM lp
  JOIN shawk.edges c ON c.id = lp.cid
  JOIN shawk.processes pc ON pc.id = c.process_id
  JOIN shawk.hosts hc ON hc.id = c.host_id
  JOIN shawk.edges s ON s.id = lp.sid
  JOIN shawk.processes ps ON ps.id = s.process_id
  JOIN shawk.hosts hs ON hs.id = s.host_id
),
-- The pairs matched through a translation: not those that a relay with an
-- agent served all along, which the client edge matches by address.
translated AS (
  SELECT * FROM pairs t
  WHERE t.direct IS NULL OR NOT t.direct @> tstzrange(t.p_first, t.p_last, '[]')
),
-- What is left of the period of an edge matched through translations
-- that its matched rows do not cover, within the margin: a client edge
-- also reached backends without an agent, or before their agents started,
-- and a server edge through a translation without sources served the
-- client directly. A server edge from a source keeps its own row whole,
-- since clients without an agent may be behind the relay.
rest AS (
  SELECT t.cid AS id,
         tstzmultirange(tstzrange(least(t.c_first, t.c_last), greatest(t.c_first, t.c_last), '[]'))
           - range_agg(tstzrange(t.p_first - interval '2 minutes', t.p_last + interval '2 minutes', '[]')) AS rest
  FROM translated t
  GROUP BY t.cid, t.c_first, t.c_last
  UNION ALL
  SELECT t.sid,
         tstzmultirange(tstzrange(least(t.s_first, t.s_last), greatest(t.s_first, t.s_last), '[]'))
           - range_agg(tstzrange(t.p_first - interval '2 minutes', t.p_last + interval '2 minutes', '[]'))
  FROM translated t
  WHERE NOT t.snat
  GROUP BY t.sid, t.s_first, t.s_last
),
-- The row of its own of an edge matched through translations: from the
-- start of the edge, so that a side that stops observing does not make its
-- other side look new, to the end of the last part left. It is shown if a
-- part is left, in [since, until].
own AS (
  SELECT x.id, upper(x.rest) AS last_seen,
         EXISTS (SELECT FROM unnest(x.rest) AS g WHERE g && tstzrange(since, until, '[]')) AS shown
  FROM rest x
),
d AS (
SELECT
  c.hostname                                    AS client_host,
  c.service_name                                AS client_service,
  c.unit                                        AS client_unit,
  coalesce(c.local_addr, s.remote_addr)         AS client_addr,
  s.hostname                                    AS server_host,
  s.service_name                                AS server_service,
  s.unit                                        AS server_unit,
  coalesce(c.remote_addr, s.local_addr)         AS server_addr,
  coalesce(c.port, s.port)                      AS port,
  coalesce(c.proto, s.proto)                    AS proto,
  CASE WHEN oc.id IS NOT NULL AND s.id IS NOT NULL THEN s.first_seen
       ELSE least(c.first_seen, s.first_seen) END AS first_seen,
  CASE WHEN oc.id IS NOT NULL AND s.id IS NULL THEN oc.last_seen
       WHEN os.id IS NOT NULL THEN os.last_seen
       WHEN oc.id IS NOT NULL THEN s.last_seen
       ELSE greatest(c.last_seen, s.last_seen) END AS last_seen,
  CASE WHEN c.id IS NOT NULL AND s.id IS NOT NULL THEN 'both'
       WHEN c.id IS NOT NULL THEN 'client'
       ELSE 'server' END                        AS observed_by,
  CASE WHEN oc.id IS NOT NULL
        AND c.last_seen > coalesce(s.last_seen, oc.last_seen) + interval '2 minutes' THEN NULL
       ELSE co.observed_until END               AS client_observed_until,
  CASE WHEN os.id IS NOT NULL AND s.last_seen > os.last_seen + interval '2 minutes' THEN NULL
       ELSE so.observed_until END               AS server_observed_until,
  NULL::inet                                    AS virtual_addr,
  NULL::integer                                 AS virtual_port,
  NULL::text                                    AS translation
FROM (SELECT * FROM e WHERE role = 'client') c
FULL JOIN (SELECT * FROM e WHERE role = 'server') s
  ON  c.local_addr = s.remote_addr
  AND c.remote_addr = s.local_addr
  AND c.port = s.port
  AND c.proto = s.proto
  AND c.scope = s.scope
LEFT JOIN observed co ON co.host_id = c.host_id
LEFT JOIN observed so ON so.host_id = s.host_id
-- An edge matched through translations keeps a row of its own if its
-- matched rows below leave a part of it; a server edge that a client edge
-- also matched through a translation matches by address over its own
-- period, since the client edge also reached the backends. As on the rows
-- below, the observation of a side whose edge outlives the row tells
-- nothing of the end of the row.
LEFT JOIN own oc ON oc.id = c.id
LEFT JOIN own os ON os.id = s.id AND c.id IS NULL
WHERE NOT (s.id IS NULL AND oc.id IS NOT NULL AND NOT oc.shown)
  AND NOT (c.id IS NULL AND os.id IS NOT NULL AND NOT os.shown)
UNION ALL
-- The observation of a side whose edge outlives the row tells nothing of
-- the end of the row: the client edge went on to other backends, or the
-- server edge served other clients.
SELECT
  t.c_hostname, t.c_service, t.c_unit, t.c_local,
  t.s_hostname, t.s_service, t.s_unit, t.s_local,
  t.s_port, t.proto, t.p_first, t.p_last, 'both',
  CASE WHEN t.c_last <= t.p_last + interval '2 minutes' THEN co.observed_until END,
  CASE WHEN t.s_last <= t.p_last + interval '2 minutes' THEN so.observed_until END,
  t.c_remote, t.c_port, t.translation
FROM translated t
LEFT JOIN observed co ON co.host_id = t.c_host_id
LEFT JOIN observed so ON so.host_id = t.s_host_id
)
SELECT * FROM d WHERE d.last_seen >= since AND d.first_seen <= until
$$;

-- Dependencies between services in [since, until]: a peer without a known
-- service is named by peer_class, like in Prometheus, so that a service
-- that talks to rotating addresses (a cloud API, the clients of a public
-- server) is one dependency rather than one per address. Called by the
-- functions below, with the rights of their owner.
CREATE FUNCTION shawk.service_dependencies_between(since timestamptz, until timestamptz)
RETURNS TABLE (
  client_service text, server_service text, port integer, proto text,
  first_seen timestamptz, last_seen timestamptz,
  client_observed_until timestamptz, server_observed_until timestamptz,
  client_hosts text[], server_hosts text[])
LANGUAGE sql STABLE SET search_path = pg_catalog, pg_temp AS $$
SELECT
  coalesce(d.client_service, shawk_v1.peer_class(d.client_addr)),
  coalesce(d.server_service, shawk_v1.peer_class(d.server_addr)),
  d.port, d.proto,
  min(d.first_seen), max(d.last_seen),
  max(d.client_observed_until), max(d.server_observed_until),
  array_agg(DISTINCT d.client_host) FILTER (WHERE d.client_host IS NOT NULL),
  array_agg(DISTINCT d.server_host) FILTER (WHERE d.server_host IS NOT NULL)
FROM shawk_v1.dependencies_between(since, until) d
GROUP BY 1, 2, 3, 4
$$;

-- Edges of the dependency map in [since, until], in the format of the
-- Grafana Node Graph.
CREATE FUNCTION shawk_v1.graph_edges_between(since timestamptz, until timestamptz)
RETURNS TABLE (id text, source text, target text, mainstat text, first_seen timestamptz, last_seen timestamptz)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
SELECT
  d.client_service || ' -> ' || d.server_service,
  d.client_service,
  d.server_service,
  string_agg(d.port::text || '/' || d.proto, ', ' ORDER BY d.port, d.proto),
  min(d.first_seen),
  max(d.last_seen)
FROM shawk.service_dependencies_between(since, until) d
GROUP BY d.client_service, d.server_service
$$;

-- Nodes of the dependency map in [since, until]: the services and their
-- hosts.
CREATE FUNCTION shawk_v1.graph_nodes_between(since timestamptz, until timestamptz)
RETURNS TABLE (id text, title text, subtitle text, mainstat bigint, first_seen timestamptz, last_seen timestamptz)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
WITH d AS MATERIALIZED (
  SELECT * FROM shawk.service_dependencies_between(since, until)
)
SELECT
  n.service,
  n.service,
  coalesce(array_to_string((array_agg(DISTINCT n.host ORDER BY n.host))[1:3], ', '), ''),
  count(DISTINCT n.host),
  min(n.first_seen),
  max(n.last_seen)
FROM (
  SELECT d.client_service AS service, unnest(coalesce(d.client_hosts, '{NULL}'::text[])) AS host, d.first_seen, d.last_seen
  FROM d
  UNION ALL
  SELECT d.server_service, unnest(coalesce(d.server_hosts, '{NULL}'::text[])), d.first_seen, d.last_seen
  FROM d
) n
GROUP BY n.service
$$;

-- Dependencies between services that appeared or disappeared in [since,
-- until]. A dependency appeared when it was first seen in the period and
-- was not known before it (known_dependencies); it disappeared when it was
-- last seen in the period while a host that saw it kept observing for 15
-- minutes after.
CREATE FUNCTION shawk_v1.dependency_changes_between(since timestamptz, until timestamptz)
RETURNS TABLE ("time" timestamptz, change text, client_service text, server_service text, port integer, proto text)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
WITH d AS MATERIALIZED (
  SELECT * FROM shawk.service_dependencies_between(since, until)
)
SELECT d.first_seen, 'appeared', d.client_service, d.server_service, d.port, d.proto
FROM d
WHERE d.first_seen BETWEEN since AND until
  AND NOT EXISTS (
    SELECT FROM shawk.known_dependencies k
    WHERE k.client_service = d.client_service AND k.server_service = d.server_service
      AND k.port = d.port AND k.proto = d.proto AND k.first_seen < since)
UNION ALL
SELECT d.last_seen, 'disappeared', d.client_service, d.server_service, d.port, d.proto
FROM d
WHERE d.last_seen BETWEEN since AND until
  AND greatest(d.client_observed_until, d.server_observed_until) > d.last_seen + interval '15 minutes'
$$;

-- The same over the whole history, for readers who look up a dependency
-- across all time. They are views of their own rather than the functions
-- above called over all time, so that the conditions of a query on them
-- reach the tables: a function that runs with the rights of its owner is
-- not inlined, and computes every dependency before the query filters
-- them. Their matching must be kept the same as that of the functions.
-- Dashboards and alerts use the functions over a period, which do not
-- match the edges of the whole history.
CREATE VIEW shawk_v1.dependencies AS
WITH shared AS (SELECT addr FROM shawk.shared_addrs),
e AS (
  SELECT e.id, e.host_id, e.role, e.proto, e.local_addr, e.remote_addr, e.port, e.netns,
         e.first_seen, e.last_seen, p.service_name, p.unit, h.hostname,
         -- The scope in which the addresses of the edge identify its other
         -- side: the host and network namespace for loopback, the host for
         -- shared addresses, everywhere ('') otherwise.
         CASE WHEN e.remote_addr << inet '127.0.0.0/8' OR e.remote_addr = inet '::1'
                THEN e.host_id || '/' || e.netns::text
              WHEN e.local_addr IN (SELECT addr FROM shared) OR e.remote_addr IN (SELECT addr FROM shared)
                THEN e.host_id
              ELSE '' END AS scope
  FROM shawk.edges e
  JOIN shawk.processes p ON p.id = e.process_id
  JOIN shawk.hosts h ON h.id = e.host_id
),
observed AS (
  SELECT host_id, max(last_heartbeat) AS observed_until
  FROM shawk.agent_sessions GROUP BY host_id
),
-- Client edges to a virtual address, read through the index of client
-- edges. client_scope is the scope of the address of the client alone,
-- which is all the two sides of a connection through a translation share.
-- direct is when server edges at the virtual address matched the client
-- edge by address, within the margin: a relay that runs an agent served
-- it then, rather than the backends.
cv AS (
  SELECT DISTINCT ON (c.id, v.name)
         c.id, c.host_id, c.proto, c.local_addr, c.remote_addr, c.port, c.first_seen, c.last_seen,
         p.service_name, p.unit, h.hostname, v.name AS translation,
         CASE WHEN c.local_addr << inet '127.0.0.0/8' OR c.local_addr = inet '::1'
                THEN c.host_id || '/' || c.netns::text
              WHEN c.local_addr IN (SELECT addr FROM shared)
                THEN c.host_id
              ELSE '' END AS client_scope,
         (SELECT range_agg(tstzrange(least(s.first_seen, s.last_seen) - interval '2 minutes',
                                     greatest(s.first_seen, s.last_seen) + interval '2 minutes', '[]'))
          FROM shawk.edges s
          WHERE s.role = 'server' AND s.proto = c.proto AND s.local_addr = c.remote_addr AND s.port = c.port
            AND s.remote_addr = c.local_addr
            AND CASE WHEN s.remote_addr << inet '127.0.0.0/8' OR s.remote_addr = inet '::1'
                        THEN s.host_id || '/' || s.netns::text
                      WHEN s.local_addr IN (SELECT addr FROM shared) OR s.remote_addr IN (SELECT addr FROM shared)
                        THEN s.host_id
                      ELSE '' END
              = CASE WHEN c.remote_addr << inet '127.0.0.0/8' OR c.remote_addr = inet '::1'
                        THEN c.host_id || '/' || c.netns::text
                      WHEN c.local_addr IN (SELECT addr FROM shared) OR c.remote_addr IN (SELECT addr FROM shared)
                        THEN c.host_id
                      ELSE '' END) AS direct
  FROM shawk.translations v
  JOIN shawk.edges c
    ON c.role = 'client' AND c.proto = v.proto AND c.remote_addr = v.addr AND v.port IN (0, c.port)
  JOIN shawk.processes p ON p.id = c.process_id
  JOIN shawk.hosts h ON h.id = c.host_id
  WHERE v.side = 'virtual'
  ORDER BY c.id, v.name
),
-- The backends of the translations, with the ports of their virtual
-- addresses and their sources; exact tells that the backend is a single
-- address.
bk AS (
  SELECT b.name, b.proto, b.addr, b.port,
         masklen(b.addr) = CASE family(b.addr) WHEN 4 THEN 32 ELSE 128 END AS exact,
         ARRAY(SELECT v.port FROM shawk.translations v
               WHERE v.name = b.name AND v.side = 'virtual' AND v.proto = b.proto) AS virtual_ports,
         ARRAY(SELECT x.addr FROM shawk.translations x
               WHERE x.name = b.name AND x.side = 'source' AND x.proto = b.proto) AS sources
  FROM shawk.translations b
  WHERE b.side = 'backend'
),
-- Server edges at the address of a backend, read through the index of
-- server edges: a single address by equality, a range by its bounds.
sa AS (
  SELECT s.*, b.addr::inet AS backend
  FROM (SELECT DISTINCT proto, addr FROM bk WHERE exact) b
  JOIN shawk.edges s ON s.role = 'server' AND s.proto = b.proto AND s.local_addr = b.addr
  UNION ALL
  SELECT s.*, r.addr::inet
  FROM (SELECT DISTINCT proto, addr FROM bk WHERE NOT exact) r
  JOIN shawk.edges s
    ON  s.role = 'server' AND s.proto = r.proto AND s.local_addr <<= r.addr
    AND s.local_addr >= r.addr
    AND s.local_addr <= set_masklen(broadcast(r.addr), CASE family(r.addr) WHEN 4 THEN 32 ELSE 128 END)
),
-- Server edges at a backend, on its port or on the port of a virtual
-- address, from a source if the translation has any. fixed tells that the
-- backend has the port of the edge, rather than the port the client
-- connected to.
sb AS (
  SELECT DISTINCT ON (sa.id, bk.name)
         sa.id, sa.host_id, sa.proto, sa.local_addr, sa.remote_addr, sa.port, sa.first_seen, sa.last_seen,
         p.service_name, p.unit, h.hostname, bk.name AS translation,
         bk.port <> 0 AS fixed, cardinality(bk.sources) > 0 AS snat,
         CASE WHEN sa.remote_addr << inet '127.0.0.0/8' OR sa.remote_addr = inet '::1'
                THEN sa.host_id || '/' || sa.netns::text
              WHEN sa.remote_addr IN (SELECT addr FROM shared)
                THEN sa.host_id
              ELSE '' END AS client_scope
  FROM sa
  JOIN bk ON bk.addr = sa.backend AND bk.proto = sa.proto AND bk.port IN (0, sa.port)
  JOIN shawk.processes p ON p.id = sa.process_id
  JOIN shawk.hosts h ON h.id = sa.host_id
  WHERE (bk.port <> 0 OR 0 = ANY (bk.virtual_ports) OR sa.port = ANY (bk.virtual_ports))
    AND (cardinality(bk.sources) = 0 OR sa.remote_addr <<= ANY (bk.sources))
  ORDER BY sa.id, bk.name, bk.port <> 0 DESC
),
-- Learned translations (shawk.learned_translations): a client edge c and a
-- server edge s match the rows of hosts that translated the connections
-- of the client of c to its server address and port into the backend of
-- s, seen from the peer of s; the client address is loopback in the host
-- and namespace of the row, shared on its host, anywhere otherwise, and so
-- are the backend and the source. A client edge to a virtual address of a
-- static translation is matched through it only. The rows that overlap c
-- and s, within 2 minutes, are combined: the period of the pair is the
-- part of those of c and s that their span covers.
lc AS (
  SELECT c.id, c.proto, c.first_seen AS c_first, c.last_seen AS c_last,
         l.host_id AS l_host, l.netns AS l_netns, l.source_addr, l.backend_addr, l.backend_port,
         l.first_seen AS l_first, l.last_seen AS l_last
  FROM shawk.learned_translations l
  JOIN shawk.edges c
    ON  c.role = 'client' AND c.proto = l.proto AND c.remote_addr = l.virtual_addr AND c.port = l.virtual_port
    AND c.local_addr = l.client_addr
  WHERE CASE WHEN c.local_addr << inet '127.0.0.0/8' OR c.local_addr = inet '::1'
               THEN c.host_id = l.host_id AND c.netns = l.netns
             WHEN c.local_addr IN (SELECT addr FROM shared) THEN c.host_id = l.host_id
             ELSE true END
    AND c.first_seen <= l.last_seen + interval '2 minutes'
    AND l.first_seen <= c.last_seen + interval '2 minutes'
    AND NOT EXISTS (
      SELECT FROM shawk.translations v
      WHERE v.side = 'virtual' AND v.proto = c.proto AND v.addr = c.remote_addr AND v.port IN (0, c.port))
),
lp AS (
  SELECT lc.id AS cid, s.id AS sid, min(lc.l_first) AS l_first, max(lc.l_last) AS l_last
  FROM lc
  JOIN shawk.edges s
    ON  s.role = 'server' AND s.proto = lc.proto AND s.local_addr = lc.backend_addr AND s.port = lc.backend_port
    AND s.remote_addr = lc.source_addr
  WHERE CASE WHEN s.local_addr << inet '127.0.0.0/8' OR s.local_addr = inet '::1'
                  OR s.remote_addr << inet '127.0.0.0/8' OR s.remote_addr = inet '::1'
               THEN s.host_id = lc.l_host AND s.netns = lc.l_netns
             WHEN s.local_addr IN (SELECT addr FROM shared) OR s.remote_addr IN (SELECT addr FROM shared)
               THEN s.host_id = lc.l_host
             ELSE true END
    AND s.first_seen <= lc.l_last + interval '2 minutes'
    AND lc.l_first <= s.last_seen + interval '2 minutes'
    AND s.first_seen <= lc.c_last + interval '2 minutes'
    AND lc.c_first <= s.last_seen + interval '2 minutes'
  GROUP BY lc.id, s.id
),
-- The client and server edges a translation may match: on the port of the
-- backend or the port of the client edge, with times that overlap; through
-- a translation without sources, with the address of the client. p_first
-- and p_last are the period both were active in.
pairs AS (
  SELECT cv.id AS cid, cv.host_id AS c_host_id, cv.hostname AS c_hostname, cv.service_name AS c_service,
         cv.unit AS c_unit, cv.local_addr AS c_local, cv.remote_addr AS c_remote, cv.port AS c_port,
         cv.first_seen AS c_first, cv.last_seen AS c_last, cv.direct,
         sb.id AS sid, sb.host_id AS s_host_id, sb.hostname AS s_hostname, sb.service_name AS s_service,
         sb.unit AS s_unit, sb.local_addr AS s_local, sb.port AS s_port,
         sb.first_seen AS s_first, sb.last_seen AS s_last,
         cv.proto, cv.translation, false AS snat,
         least(greatest(cv.first_seen, sb.first_seen), least(cv.last_seen, sb.last_seen)) AS p_first,
         greatest(greatest(cv.first_seen, sb.first_seen), least(cv.last_seen, sb.last_seen)) AS p_last
  FROM cv JOIN sb
    ON  sb.translation = cv.translation AND sb.proto = cv.proto
    AND sb.remote_addr = cv.local_addr AND sb.client_scope = cv.client_scope
  WHERE NOT sb.snat
    AND (sb.fixed OR sb.port = cv.port)
    AND cv.first_seen <= sb.last_seen + interval '2 minutes'
    AND sb.first_seen <= cv.last_seen + interval '2 minutes'
  UNION ALL
  SELECT cv.id, cv.host_id, cv.hostname, cv.service_name, cv.unit, cv.local_addr, cv.remote_addr, cv.port,
         cv.first_seen, cv.last_seen, cv.direct,
         sb.id, sb.host_id, sb.hostname, sb.service_name, sb.unit, sb.local_addr, sb.port,
         sb.first_seen, sb.last_seen,
         cv.proto, cv.translation, true,
         least(greatest(cv.first_seen, sb.first_seen), least(cv.last_seen, sb.last_seen)),
         greatest(greatest(cv.first_seen, sb.first_seen), least(cv.last_seen, sb.last_seen))
  FROM cv JOIN sb ON sb.translation = cv.translation AND sb.proto = cv.proto
  WHERE sb.snat
    AND (sb.fixed OR sb.port = cv.port)
    AND cv.first_seen <= sb.last_seen + interval '2 minutes'
    AND sb.first_seen <= cv.last_seen + interval '2 minutes'
  UNION ALL
  SELECT c.id, c.host_id, hc.hostname, pc.service_name, pc.unit, c.local_addr, c.remote_addr, c.port,
         c.first_seen, c.last_seen,
         -- direct, as for the client edges of static translations.
         (SELECT range_agg(tstzrange(least(d.first_seen, d.last_seen) - interval '2 minutes',
                                     greatest(d.first_seen, d.last_seen) + interval '2 minutes', '[]'))
          FROM shawk.edges d
          WHERE d.role = 'server' AND d.proto = c.proto AND d.local_addr = c.remote_addr AND d.port = c.port
            AND d.remote_addr = c.local_addr
            AND CASE WHEN d.remote_addr << inet '127.0.0.0/8' OR d.remote_addr = inet '::1'
                        THEN d.host_id || '/' || d.netns::text
                      WHEN d.local_addr IN (SELECT addr FROM shared) OR d.remote_addr IN (SELECT addr FROM shared)
                        THEN d.host_id
                      ELSE '' END
              = CASE WHEN c.remote_addr << inet '127.0.0.0/8' OR c.remote_addr = inet '::1'
                        THEN c.host_id || '/' || c.netns::text
                      WHEN c.local_addr IN (SELECT addr FROM shared) OR c.remote_addr IN (SELECT addr FROM shared)
                        THEN c.host_id
                      ELSE '' END),
         s.id, s.host_id, hs.hostname, ps.service_name, ps.unit, s.local_addr, s.port,
         s.first_seen, s.last_seen,
         c.proto, '~learned'::text, s.remote_addr <> c.local_addr,
         least(greatest(c.first_seen, s.first_seen, lp.l_first), least(c.last_seen, s.last_seen, lp.l_last)),
         greatest(greatest(c.first_seen, s.first_seen, lp.l_first), least(c.last_seen, s.last_seen, lp.l_last))
  FROM lp
  JOIN shawk.edges c ON c.id = lp.cid
  JOIN shawk.processes pc ON pc.id = c.process_id
  JOIN shawk.hosts hc ON hc.id = c.host_id
  JOIN shawk.edges s ON s.id = lp.sid
  JOIN shawk.processes ps ON ps.id = s.process_id
  JOIN shawk.hosts hs ON hs.id = s.host_id
),
-- The pairs matched through a translation: not those that a relay with an
-- agent served all along, which the client edge matches by address.
translated AS (
  SELECT * FROM pairs t
  WHERE t.direct IS NULL OR NOT t.direct @> tstzrange(t.p_first, t.p_last, '[]')
),
-- What is left of the period of an edge matched through translations
-- that its matched rows do not cover, within the margin: a client edge
-- also reached backends without an agent, or before their agents started,
-- and a server edge through a translation without sources served the
-- client directly. A server edge from a source keeps its own row whole,
-- since clients without an agent may be behind the relay.
rest AS (
  SELECT t.cid AS id,
         tstzmultirange(tstzrange(least(t.c_first, t.c_last), greatest(t.c_first, t.c_last), '[]'))
           - range_agg(tstzrange(t.p_first - interval '2 minutes', t.p_last + interval '2 minutes', '[]')) AS rest
  FROM translated t
  GROUP BY t.cid, t.c_first, t.c_last
  UNION ALL
  SELECT t.sid,
         tstzmultirange(tstzrange(least(t.s_first, t.s_last), greatest(t.s_first, t.s_last), '[]'))
           - range_agg(tstzrange(t.p_first - interval '2 minutes', t.p_last + interval '2 minutes', '[]'))
  FROM translated t
  WHERE NOT t.snat
  GROUP BY t.sid, t.s_first, t.s_last
),
-- The row of its own of an edge matched through translations: from the
-- start of the edge, so that a side that stops observing does not make its
-- other side look new, to the end of the last part left. It is shown if a
-- part is left.
own AS (
  SELECT x.id, upper(x.rest) AS last_seen, NOT isempty(x.rest) AS shown FROM rest x
)
SELECT
  c.hostname                                    AS client_host,
  c.service_name                                AS client_service,
  c.unit                                        AS client_unit,
  coalesce(c.local_addr, s.remote_addr)         AS client_addr,
  s.hostname                                    AS server_host,
  s.service_name                                AS server_service,
  s.unit                                        AS server_unit,
  coalesce(c.remote_addr, s.local_addr)         AS server_addr,
  coalesce(c.port, s.port)                      AS port,
  coalesce(c.proto, s.proto)                    AS proto,
  CASE WHEN oc.id IS NOT NULL AND s.id IS NOT NULL THEN s.first_seen
       ELSE least(c.first_seen, s.first_seen) END AS first_seen,
  CASE WHEN oc.id IS NOT NULL AND s.id IS NULL THEN oc.last_seen
       WHEN os.id IS NOT NULL THEN os.last_seen
       WHEN oc.id IS NOT NULL THEN s.last_seen
       ELSE greatest(c.last_seen, s.last_seen) END AS last_seen,
  CASE WHEN c.id IS NOT NULL AND s.id IS NOT NULL THEN 'both'
       WHEN c.id IS NOT NULL THEN 'client'
       ELSE 'server' END                        AS observed_by,
  CASE WHEN oc.id IS NOT NULL
        AND c.last_seen > coalesce(s.last_seen, oc.last_seen) + interval '2 minutes' THEN NULL
       ELSE co.observed_until END               AS client_observed_until,
  CASE WHEN os.id IS NOT NULL AND s.last_seen > os.last_seen + interval '2 minutes' THEN NULL
       ELSE so.observed_until END               AS server_observed_until,
  NULL::inet                                    AS virtual_addr,
  NULL::integer                                 AS virtual_port,
  NULL::text                                    AS translation
FROM (SELECT * FROM e WHERE role = 'client') c
FULL JOIN (SELECT * FROM e WHERE role = 'server') s
  ON  c.local_addr = s.remote_addr
  AND c.remote_addr = s.local_addr
  AND c.port = s.port
  AND c.proto = s.proto
  AND c.scope = s.scope
LEFT JOIN observed co ON co.host_id = c.host_id
LEFT JOIN observed so ON so.host_id = s.host_id
-- An edge matched through translations keeps a row of its own if its
-- matched rows below leave a part of it; a server edge that a client edge
-- also matched through a translation matches by address over its own
-- period, since the client edge also reached the backends. As on the rows
-- below, the observation of a side whose edge outlives the row tells
-- nothing of the end of the row.
LEFT JOIN own oc ON oc.id = c.id
LEFT JOIN own os ON os.id = s.id AND c.id IS NULL
WHERE NOT (s.id IS NULL AND oc.id IS NOT NULL AND NOT oc.shown)
  AND NOT (c.id IS NULL AND os.id IS NOT NULL AND NOT os.shown)
UNION ALL
-- The observation of a side whose edge outlives the row tells nothing of
-- the end of the row: the client edge went on to other backends, or the
-- server edge served other clients.
SELECT
  t.c_hostname, t.c_service, t.c_unit, t.c_local,
  t.s_hostname, t.s_service, t.s_unit, t.s_local,
  t.s_port, t.proto, t.p_first, t.p_last, 'both',
  CASE WHEN t.c_last <= t.p_last + interval '2 minutes' THEN co.observed_until END,
  CASE WHEN t.s_last <= t.p_last + interval '2 minutes' THEN so.observed_until END,
  t.c_remote, t.c_port, t.translation
FROM translated t
LEFT JOIN observed co ON co.host_id = t.c_host_id
LEFT JOIN observed so ON so.host_id = t.s_host_id;

-- Dependencies between services over the whole history, as
-- service_dependencies_between.
CREATE VIEW shawk.service_dependencies AS
SELECT
  coalesce(client_service, shawk_v1.peer_class(client_addr)) AS client_service,
  coalesce(server_service, shawk_v1.peer_class(server_addr)) AS server_service,
  port,
  proto,
  min(first_seen)                             AS first_seen,
  max(last_seen)                              AS last_seen,
  max(client_observed_until)                  AS client_observed_until,
  max(server_observed_until)                  AS server_observed_until,
  array_agg(DISTINCT client_host) FILTER (WHERE client_host IS NOT NULL) AS client_hosts,
  array_agg(DISTINCT server_host) FILTER (WHERE server_host IS NOT NULL) AS server_hosts
FROM shawk_v1.dependencies
GROUP BY 1, 2, 3, 4;

-- Edges of the dependency map in the format of the Grafana Node Graph.
CREATE VIEW shawk_v1.graph_edges AS
SELECT
  client_service || ' -> ' || server_service  AS id,
  client_service                              AS source,
  server_service                              AS target,
  string_agg(port::text || '/' || proto, ', ' ORDER BY port, proto) AS mainstat,
  min(first_seen)                             AS first_seen,
  max(last_seen)                              AS last_seen
FROM shawk.service_dependencies
GROUP BY client_service, server_service;

-- Nodes of the dependency map: the services and their hosts.
CREATE VIEW shawk_v1.graph_nodes AS
SELECT
  service                                     AS id,
  service                                     AS title,
  coalesce(array_to_string((array_agg(DISTINCT host ORDER BY host))[1:3], ', '), '') AS subtitle,
  count(DISTINCT host)                        AS mainstat,
  min(first_seen)                             AS first_seen,
  max(last_seen)                              AS last_seen
FROM (
  SELECT client_service AS service, unnest(coalesce(client_hosts, '{NULL}'::text[])) AS host, first_seen, last_seen
  FROM shawk.service_dependencies
  UNION ALL
  SELECT server_service, unnest(coalesce(server_hosts, '{NULL}'::text[])), first_seen, last_seen
  FROM shawk.service_dependencies
) n
GROUP BY service;

-- Dependencies between services that appeared or disappeared. A
-- dependency disappeared when a host that saw it kept observing for 15
-- minutes after its last activity.
CREATE VIEW shawk_v1.dependency_changes AS
SELECT first_seen AS time, 'appeared' AS change, client_service, server_service, port, proto
FROM shawk.service_dependencies
UNION ALL
SELECT last_seen, 'disappeared', client_service, server_service, port, proto
FROM shawk.service_dependencies
WHERE greatest(client_observed_until, server_observed_until) > last_seen + interval '15 minutes';

-- Agents ------------------------------------------------------------------

-- The latest session of every host, and whether its agent is alive.
CREATE VIEW shawk_v1.agents AS
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
  s.peer_fold,      -- the peers the agent folds: none, in or all
  s.peer_internal   -- the ranges of peers the agent keeps exact
FROM shawk.hosts h
JOIN shawk.agent_sessions s ON s.host_id = h.id
ORDER BY h.id, s.last_heartbeat DESC;

-- The periods in [since, until] in which a host was not observed.
-- tolerance covers the delay of writes; use two or three times the
-- write_interval of the connector. A session starts by the clock of the
-- agent and its heartbeat is by the clock of the connector, so the start is
-- converted with the clock skew.
CREATE FUNCTION shawk_v1.unobserved(since timestamptz, until timestamptz,
                                    tolerance interval DEFAULT '3 minutes')
RETURNS TABLE (host text, gap_start timestamptz, gap_end timestamptz)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
  SELECT h.hostname, lower(g), upper(g)
  FROM shawk.hosts h
  CROSS JOIN LATERAL unnest(
    tstzmultirange(tstzrange(since, until))
    - coalesce((SELECT range_agg(tstzrange(least(s.started_at + s.clock_skew, s.last_heartbeat),
                                           s.last_heartbeat + tolerance))
                FROM shawk.agent_sessions s WHERE s.host_id = h.id),
               '{}'::tstzmultirange)
  ) AS g
  WHERE h.last_seen >= since;
$$;

-- The periods in [since, until] in which a host was observed but its agent
-- dropped flows, cut to [since, until], with the flow updates dropped in
-- each. A dependency may be missing from such a period although it was
-- used; unobserved() gives the periods in which a host was not observed at
-- all.
CREATE FUNCTION shawk_v1.partly_observed(since timestamptz, until timestamptz)
RETURNS TABLE (host text, gap_start timestamptz, gap_end timestamptz, dropped_flows bigint)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
  SELECT h.hostname, greatest(p.period_start, since), least(p.period_end, until), p.dropped_flows
  FROM shawk.partial_observations p
  JOIN shawk.hosts h ON h.id = p.host_id
  WHERE p.period_end > since AND p.period_start < until;
$$;

-- Views the connector reads to name peers -----------------------------------

-- Addresses and ports services accept connections on, used by the shawk
-- connector to name the peers of client edges. They are the last known
-- endpoints of each host, so that a host whose agent stopped keeps its
-- names:
--
--   - listeners open at the latest listener report of the host, within an
--     hour (times of the agent are compared with times of the same agent);
--     a listener on an unspecified address is expanded to the current
--     addresses of its host (those of its latest report);
--   - server edges of the 7 days before that report, read per host through
--     an index;
--   - of hosts that reported in the last 30 days;
--   - not an address another host started a period of after the latest
--     period of this host ended (beyond the alive window, and not
--     loopback), so that a reused address takes the name of its new holder.
--
-- exact tells whether the address was observed on a socket rather than
-- inferred from a listener on an unspecified address; the connector prefers
-- exact endpoints.
CREATE VIEW shawk_v1.service_endpoints AS
WITH latest AS (
  SELECT host_id, max(last_seen) AS last_seen FROM shawk.listeners GROUP BY host_id
),
current_addrs AS (
  SELECT a.host_id, a.addr, a.last_seen
  FROM shawk.host_addrs a
  JOIN (SELECT host_id, max(last_seen) AS last_seen FROM shawk.host_addrs GROUP BY host_id) m
    ON m.host_id = a.host_id
  WHERE a.last_seen >= m.last_seen - shawk.alive_window()
),
s AS (
  SELECT l.addr, l.port, l.proto, l.host_id, p.service_name AS service, l.last_seen, true AS exact
  FROM shawk.listeners l
  JOIN shawk.processes p ON p.id = l.process_id
  JOIN latest ON latest.host_id = l.host_id
  WHERE l.addr NOT IN (inet '0.0.0.0', inet '::')
    AND l.last_seen >= latest.last_seen - interval '1 hour'
  UNION ALL
  SELECT a.addr, l.port, l.proto, l.host_id, p.service_name, l.last_seen, false
  FROM shawk.listeners l
  JOIN shawk.processes p ON p.id = l.process_id
  JOIN latest ON latest.host_id = l.host_id
  JOIN current_addrs a ON a.host_id = l.host_id
   AND (l.addr = inet '::' OR family(a.addr) = 4)
  WHERE l.addr IN (inet '0.0.0.0', inet '::')
    AND l.last_seen >= latest.last_seen - interval '1 hour'
  UNION ALL
  SELECT e.local_addr, e.port, e.proto, e.host_id, p.service_name, e.last_seen, true
  FROM latest
  CROSS JOIN LATERAL (
    SELECT DISTINCT ON (e.local_addr, e.port, e.proto, e.process_id) e.*
    FROM shawk.edges e
    WHERE e.role = 'server' AND e.host_id = latest.host_id
      AND e.last_seen >= latest.last_seen - interval '7 days'
    ORDER BY e.local_addr, e.port, e.proto, e.process_id, e.last_seen DESC
  ) e
  JOIN shawk.processes p ON p.id = e.process_id
),
newest AS (
  SELECT addr, max(first_seen) AS first_seen FROM shawk.host_addrs GROUP BY addr
),
moved AS (
  SELECT mine.host_id, mine.addr
  FROM (SELECT host_id, addr, max(last_seen) AS last_seen FROM shawk.host_addrs GROUP BY host_id, addr) mine
  JOIN newest ON newest.addr = mine.addr
  WHERE newest.first_seen > mine.last_seen + shawk.alive_window()
    AND NOT (mine.addr << inet '127.0.0.0/8' OR mine.addr = inet '::1')
)
SELECT s.addr, s.port, s.proto, h.hostname AS host, s.host_id, s.service, max(s.last_seen) AS last_seen,
       bool_or(s.exact) AS exact
FROM s
JOIN shawk.hosts h ON h.id = s.host_id
LEFT JOIN moved ON moved.host_id = s.host_id AND moved.addr = s.addr
WHERE h.last_seen > now() - interval '30 days'
  AND moved.host_id IS NULL
GROUP BY s.addr, s.port, s.proto, h.hostname, s.host_id, s.service;

-- The client sides of recent connections, used by the shawk connector to
-- name the peer of a server edge after the client service, when the client
-- host runs an agent.
CREATE VIEW shawk_v1.client_endpoints AS
SELECT e.local_addr AS client_addr, e.remote_addr AS server_addr, e.port, e.proto,
       h.hostname AS host, e.host_id, p.service_name AS service, e.last_seen
FROM shawk.edges e
JOIN shawk.processes p ON p.id = e.process_id
JOIN shawk.hosts h ON h.id = e.host_id
WHERE e.role = 'client'
  AND e.last_seen > now() - interval '1 hour';

-- Addresses of hosts whose agent is alive, with what the latest session
-- says the agent traces and folds, used by the shawk connector to mark the
-- peers of edges whose other side has its own agent. An agent is alive by
-- its heartbeat, which the connector writes only from the request that
-- closes an interval; the address by last_seen.
CREATE VIEW shawk_v1.agent_addrs AS
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

-- Maintenance -------------------------------------------------------------

-- Adds the dependencies active since the last refresh to
-- known_dependencies, with a margin of an hour for edges written late: by
-- an agent whose clock is behind, or after the database was down (the
-- refresh fails meanwhile, so the next one covers the outage). One
-- connector at a time refreshes, at most once per min_interval; it returns
-- the rows upserted.
CREATE FUNCTION shawk.refresh_known_dependencies(min_interval interval DEFAULT '4 minutes') RETURNS bigint
LANGUAGE plpgsql SET search_path = pg_catalog, pg_temp AS $$
DECLARE
  w timestamptz;
  t timestamptz := now();
  n bigint;
BEGIN
  IF NOT pg_try_advisory_xact_lock(1936220536) THEN  -- 0x73686178
    RETURN 0;
  END IF;
  SELECT refreshed_until INTO w FROM shawk.known_dependencies_state;
  IF w IS NOT NULL AND w > t - min_interval THEN
    RETURN 0;
  END IF;
  INSERT INTO shawk.known_dependencies AS k (client_service, server_service, port, proto, first_seen, last_seen)
  SELECT d.client_service, d.server_service, d.port, d.proto, d.first_seen, d.last_seen
  FROM shawk.service_dependencies_between(coalesce(w - interval '1 hour', '-infinity'), t) d
  ON CONFLICT (client_service, server_service, port, proto) DO UPDATE SET
    first_seen = least(k.first_seen, excluded.first_seen),
    last_seen  = greatest(k.last_seen, excluded.last_seen);
  GET DIAGNOSTICS n = ROW_COUNT;
  INSERT INTO shawk.known_dependencies_state (refreshed_until) VALUES (t)
  ON CONFLICT (id) DO UPDATE SET refreshed_until = excluded.refreshed_until;
  RETURN n;
END
$$;

-- Retention: deletes rows last seen before a cutoff, at most max_rows per
-- table and call, so that the shawk connector can call it repeatedly in
-- short transactions. Processes and hosts are deleted once nothing refers
-- to them. Sessions are deleted too, so unobserved() reports the time
-- before the cutoff as not observed.
--
-- It waits for a migration in progress, which holds the advisory lock of
-- migrations, rather than taking the locks of tables in another order and
-- deadlocking with it. The outer conditions of every delete are repeated,
-- so that a row refreshed by a concurrent write while the delete waited
-- for its lock is kept (the subquery is not evaluated again).
CREATE FUNCTION shawk.prune(cutoff timestamptz, max_rows integer DEFAULT 10000) RETURNS bigint
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

  DELETE FROM shawk.learned_translations WHERE last_seen < cutoff AND ctid IN (
    SELECT ctid FROM shawk.learned_translations WHERE last_seen < cutoff LIMIT max_rows);
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
    AND NOT EXISTS (SELECT FROM shawk.learned_translations t WHERE t.host_id = h.id)
    AND h.id IN (SELECT h2.id FROM shawk.hosts h2 WHERE h2.last_seen < cutoff LIMIT max_rows);
  GET DIAGNOSTICS n = ROW_COUNT; total := total + n;

  RETURN total;
END
$$;
