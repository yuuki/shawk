# Dependencies through translations of addresses: design proposal

Status: phase 1 (§3.1–§3.4, static translations in the configuration of
the connector) is implemented (2026-11-02, branch
`claude/translations-107`); phases 2 (§3.5, translations learned from
conntrack) and 3 (§3.6, docker-proxy) are not. It answers issue #107. The
design is in `docs/design.md` §5.4, §6, §7 and §10. Two adversarial
reviews changed the implementation (§10).

## 1. Problem

Dependencies are recorded by socket addresses. When a connection goes
through one of the following, the client records an address that no agent
owns, a *virtual address*:

- DNAT: Docker published ports, kube-proxy (iptables, IPVS),
  keepalived/LVS virtual addresses;
- a TCP proxy without an agent;
- a cloud or hardware load balancer.

A client C connects to the virtual address V on port Pv, and the relay
forwards to the backend B on port Pr. The two sides record:

| side | edge (local, peer, port) | name of the peer by `peer_class()` |
|---|---|---|
| client | (C, V, Pv) | the range of V (`~unresolved`, ...) |
| server, DNAT only | (B, C, Pr) | the range of C: no client edge (C, B, Pr) |
| server, SNAT or a proxy | (B, S, Pr), S an address of the relay | the range of S |

`shawk_v1.dependencies` has a one-sided row for each. The dependency map
ends at the virtual address, so *who still uses this database?* has no
answer for the clients that reach it through a VIP. This is §5.2 of the
paper, and `docs/design.md` §10 listed it as a limitation.

## 2. Approach

- Keep the mapping from a virtual address and port to the addresses and
  ports of the backends (a *translation*) in PostgreSQL. The views, and
  the connector when it names peers, match through it the edges that their
  addresses do not match.
- Translations come from three sources: first static ones in the
  configuration of the connector, which change neither the agent nor the
  kernel (the issue notes that this can come first); then translations
  that the agents of the hosts that translate learn from conntrack; then
  docker-proxy.
- There are two kinds. A translation that keeps the address of the client
  (DNAT) matches one client edge with one server edge, by the address of
  the client. One that replaces it (SNAT, a proxy) cannot tell the clients
  apart on the server: every client edge to the virtual address is matched
  with every server edge from the relay.

## 3. Design

### 3.1 Configuration (phase 1)

`translations` in the configuration of the connector, a map by name, so
that configuration files of the collector merge by name, as `peer_cidrs`
does:

```yaml
connectors:
  shawk:
    translations:
      postgres-vip:                 # a keepalived VIP, LVS NAT
        virtual: [10.0.100.1:5432]
        backends: [10.0.1.10, 10.0.1.11]
        transport: tcp
      web-lb:                       # a load balancer that replaces the client addresses
        virtual: ["10.0.100.2:80", "[2001:db8::2]:80"]
        backends: [10.0.1.0/24:8080]
        sources: [10.0.100.250]
```

- `virtual`: the addresses clients connect to, with a port, or without one
  for every port. Not ranges (§5).
- `backends`: the addresses or ranges of the servers the relay forwards
  to, with their port, or without one for the port the client connected
  to. Backends that come and go are written as a range.
- `sources`: the ranges the servers see the clients at, when the relay
  replaces their addresses. Empty when the servers see the addresses of the
  clients (DNAT).
- `transport`: `tcp`, `udp`, or empty for both.
- Checks: a virtual address and port belongs to one translation at most (a
  virtual address without a port overlaps every port), so that a client
  edge reaches one translation; a backend with a port needs virtual
  addresses with a port (every port is not forwarded to one).
- With LVS direct routing the backends hold the virtual address and accept
  the connections on it; as several hosts hold it at once, the edges do not
  match by address. The virtual address is then its own backend.

### 3.2 PostgreSQL

- **Table:** `shawk.translations(name, side, proto, addr, port)`, one row
  per element of a translation; `side` is `virtual`, `backend` or
  `source`. The connector writes it from its configuration with
  `peer_cidrs`, in one transaction in READ COMMITTED under an advisory
  lock, deleting the rows that went and inserting the new ones, so that
  the views see the old rows or the new ones, and two connectors that
  write at once leave the configuration of one of them.
- **Matching** (`dependencies`, `dependencies_between`):
  1. Edges are matched by address as before (the FULL JOIN of client and
     server edges).
  2. A client edge to a virtual address is matched with the server edges at
     the backends: on the port of the backend, or that of the client edge;
     through a translation without sources, with the address of the client
     as peer, in the same scope (loopback within a host and network
     namespace, an address held by several hosts within the host); through
     one with sources, from a source; and when their periods overlap,
     within 2 minutes for the clocks of the hosts and the intervals of the
     agents.
  3. Not over the periods in which a server edge at the virtual address
     matches the client edge by address (a relay that runs an agent, such
     as HAProxy): the row matched by address then has the period of that
     server edge, since the client edge also reached the backends.
  4. A matched row is the dependency of the client on the server: the
     address and port of the server, and the period both edges were active
     in. A client edge to a virtual address bundles its connections to
     every backend, and a server edge from a source those of every client
     of the relay, so the union of the two periods would make a former
     backend look current. A former backend kept in its translation is
     matched over the period it served.
  5. The new last columns `virtual_addr`, `virtual_port` and
     `translation` tell what the client connected to; they are NULL on the
     other rows.
  6. A server edge from a source keeps a row of its own besides its
     matched rows, since clients without an agent may be behind the relay;
     its range can be named in `peer_cidrs`. Another matched edge keeps a
     row of its own if its matched rows, within the margin, leave a part of
     its period (in a period asked for, a part in it): a client edge may
     also have reached backends without an agent, or before their agents
     started, and a server edge served the client directly. That row runs
     from the start of the edge, so that a side that stops observing does
     not make the other look new, to the end of the last part left.
  7. On these rows, the observation (`client_observed_until`,
     `server_observed_until`) of a side whose edge outlives the row is
     NULL: whether the dependency ended there is for the other side to
     tell, so that a stopped agent does not make it look removed.
- **Contract:** `dependencies_between` returns more columns, so it is
  dropped and created again; the SQL functions that call it name its
  columns. `dependencies` gets them at its end with `CREATE OR REPLACE`.
  The views and functions built on them (services, map, changes,
  `known_dependencies`) follow unchanged.

### 3.3 Names of peers (Prometheus)

- **Client edge:** to a virtual address, it is named after the service at
  a backend, with the `server.port` of the backend, as PostgreSQL matches
  it, and `shawk.peer.agent` of the host of the backend. A service
  observed on a socket at the virtual address and port within the alive
  window (a relay that runs an agent) comes first; a listener on an
  unspecified address of a host that holds the address, which DNAT may
  bypass (docker-proxy), does not. Among the backends seen within 5
  minutes of the most recently seen one, one observed on a socket wins,
  then one whose agent records the server side, then the first by service,
  port and host, so that the choice does not change with every report of
  the backends. The endpoints in a range of backends are looked up once
  per write interval.
- **Server edge behind a translation without sources:** it is named after
  the client service whose client edge to a virtual address has the
  address of its peer. That client connected to the virtual address, which
  its agent keeps exact, so it counts the connections
  (`shawk.peer.agent` true) even if it folds the address of the server.
- **Server edge behind sources:** the peer is the relay, named after its
  address, with `shawk.peer.agent` false even when an agent holds that
  address (an IPVS director, a node that does SNAT): no agent records the
  connections it forwards.
- **Warnings:** the connector warns about the agent of a backend that
  folds a client of a translation without sources, and about an agent
  with `-fold-external=all` that folds the virtual address it connects to,
  naming that address.

### 3.4 Counting (§7 of the design)

- DNAT: the peer of the server side is the client; with an agent, it has
  `shawk_peer_agent="true"`, and only the client side counts, as before.
- SNAT: the peer of the server side is the relay, with
  `shawk_peer_agent="false"`, so the server side counts, and so do the
  clients that run an agent. The dependencies differ (`src=app` and
  `src=<the relay>`), so each is right, but their sum into the server
  counts those clients twice. The server cannot tell its clients apart.

### 3.5 Phase 2: translations learned on the hosts that make them

- **Scope:** Docker published ports (iptables or nftables DNAT),
  kube-proxy (iptables, nftables, IPVS), LVS directors: translations that
  change too often to be written down.
- **Kernel:** trace `__nf_conntrack_confirm` (module nf_conntrack; fentry
  with the BTF of the module, else a kprobe) and read the tuples of both
  directions of the connections it confirms with NAT
  (`status & IPS_NAT_MASK`). It runs once per new connection, and by then
  DNAT (PREROUTING, OUTPUT) and SNAT (POSTROUTING) are both done. Drop the
  ephemeral ports, bundle by (client, virtual address, virtual port →
  source, backend, backend port), and read the two maps at every interval
  as for flows. Reading the conntrack table over netlink would need
  `CAP_NET_ADMIN`, which the unit of the agent does not grant; BPF needs
  no new capability.
- **IPVS:** with `net.ipv4.vs.conntrack=1` (kube-proxy in IPVS mode sets
  it), IPVS rewrites the reply tuple of conntrack before the confirmation.
  Without it, `ip_vs_conn` would have to be traced too; to be decided.
- **OTLP:** `shawk.translation.first_seen` and `shawk.translation.last_seen`
  with the transport, the client address, the virtual address and port,
  the source, the backend address and port, and the netns.
- **PostgreSQL:** `shawk.learned_translations(host_id, proto, client_addr,
  virtual_addr, virtual_port, source_addr, backend_addr, backend_port,
  first_seen, last_seen)`. It is exact per client, so that SNAT is matched
  one to one too (kube-proxy masquerading to the address of the node). The
  views use it like static translations, over its period; it goes with the
  retention.
- **Tests:** namespaces and iptables DNAT (`make test-root`, the virtual
  machines), and the compatibility test against the BTF of Rocky Linux 9.

### 3.6 Phase 3: docker-proxy

- A connection to a published port on loopback, or hairpinned, goes
  through the userland proxy of Docker. docker-proxy shows up as a service
  of the host, with a server edge from the client (127.0.0.1:8080) and a
  client edge to the container (172.17.0.1 → 172.17.0.2:80).
- Which published port goes to which container and port is on the command
  line of docker-proxy (`-host-port`, `-container-ip`, `-container-port`)
  and in the state of Docker (`NetworkSettings.Ports` of `config.v2.json`),
  which the agent reads since #104.
- The agent would send it as a translation, by the path of phase 2, and
  the views would treat the edges of docker-proxy as those of a relay: out
  of the matching by address, matched through the translation, so that the
  client is linked to the service of the container.

## 4. Limitations

- Translations are static in phase 1: Kubernetes services and Docker
  published ports need phase 2, and docker-proxy phase 3.
- Behind sources, every client of the relay is matched with every server
  edge from it, which makes as many rows as clients times backends (a
  million for a thousand of each, seconds to read), and the server side is
  counted besides the clients (§3.4).
- An agent of a backend that folds its clients must keep the sources, or
  the clients of a translation without sources, in its internal ranges,
  and an agent with `-fold-external=all` the virtual addresses it connects
  to: a folded edge has no address to match.
- The connectors must have the same translations: the last one to write
  them wins, as for `peer_cidrs`.

## 5. Alternatives not taken

| alternative | why not |
|---|---|
| Virtual addresses as ranges | The server side looks the client edge up by client, virtual address and port, so it needs the virtual address itself; and the addresses of a range, such as ClusterIPs, have different backends each. |
| The union of the two periods for a matched row | A former backend would look current (§3.2, 4). |
| Dropping the own row of a server edge from a source once matched | The clients without an agent behind the relay would disappear (§3.2, 6). |
| Precedence of a match by address per edge | It depends on the period asked for, and a relay replaced by one without an agent hides the current dependency (§10). |
| The virtual port as the `port` of a matched row | *Who uses postgres on 5432* would not be answered by the port of the server; the client side in Prometheus takes the port of the backend instead. |
| Users writing `shawk.translations` themselves | The tables of `shawk` are internal and may change in a migration; what cannot be written down is learned in phase 2. A table writable from outside the configuration can come later. |
| `dependencies` defined as `dependencies_between('-infinity', 'infinity')` | One definition, but every migration that changes the result of the function would have to drop and create the view and those on it. The two are kept apart, and tests check that they return the same rows. |

## 6. Compatibility, migration and documents

- **Migration 12:** the table `shawk.translations`; `dependencies_between`
  dropped and created again; `dependencies` with three columns more. Run
  `grants.sql` again. A view or a `BEGIN ATOMIC` function of a user that
  depends on `dependencies_between` must be dropped before and created
  after.
- **Order of upgrades:** the agent does not change. A connector of the
  previous version writes no translations, so the views match as before;
  the tables it writes are unchanged.
- **Contract:** three columns more at the end of `dependencies` and
  `dependencies_between`. With translations, one-sided rows become `both`
  rows, and observations may be NULL on the rows of translations.
- **Documents:** `docs/design.md` §5.2 (names of peers), §5.4 (new), §6.1,
  §6.2, §7, §10; README; CHANGELOG; the commented example in
  `packaging/collector/config.yaml`.

## 7. Tests

- **Connector:** `translate_test.go`: parsing and checks, the YAML of the
  collector and the packaged example, the names of both sides, the port of
  the backend, the range cache, the precedence of a relay with an agent and
  of a listener on an unspecified address, folding agents and their
  warnings, the choice among backends, the server side behind a relay that
  an agent holds.
- **PostgreSQL:** `translate_pg_test.go`: DNAT and SNAT, port
  translation, periods that do not overlap, former backends, the own rows
  of matched edges and their periods, services, map and
  `known_dependencies`, the view against the function, a changed
  configuration, concurrent writes (also under REPEATABLE READ), the
  precedence of a match by address over periods, shared addresses, LVS
  direct routing, stopped agents and disappearing dependencies, failovers,
  edges with their times out of order. Each condition was removed in turn
  to check that a test fails.
- **e2e:** `test/e2e/run.sh`: iptables in the namespace of app translates a
  virtual address to another port of db, as kube-proxy does for a Service
  on the host of its client.
- **Performance** (a million synthetic edges, PostgreSQL 16, `work_mem`
  4 MB, no JIT): without translations, the view and the function take the
  time of their previous definitions within noise (all history 3.3 s; 6
  hours 0.39–0.47 s). With 20 translations, a thousand clients each and
  100,000 matched pairs, 6 hours take 1.3–1.5 s; what is added grows with
  the pairs. Matching by address keeps its FULL JOIN, and the edges near
  translations are read through the indexes of edges (`edges_client`,
  `edges_server`; a range of backends by its bounds, `>=` and the
  broadcast address with the mask of a host). A first version that joined
  the pairs back with all edges was twice as slow without translations,
  and with misestimated CTEs chose nested loops that did not finish in
  10 minutes.

## 8. Phases

1. **Phase 1 (this branch):** §3.1–§3.4, documents, CHANGELOG.
2. **Phase 2:** §3.5; kernel and agent, tested in the virtual machines.
3. **Phase 3:** §3.6, by the path of phase 2.

## 9. Decisions

1. Phase 1 alone makes the first pull request. Recommended: yes (phases 2
   and 3 change BPF and the agent, and need their own verification).
2. A server edge from a source keeps a row of its own besides its matched
   rows. Recommended: yes (implemented).
3. The `port` of a matched row, and the `server.port` of the client side
   in Prometheus, are those of the backend. Recommended: yes (implemented).
4. Whether phase 2 traces conntrack by default (e.g. `-learn-translations`).
   Recommended: yes; hosts that do not translate record nothing.

Open: 1 and 4.

## 10. Adversarial reviews and responses

**First review (2026-11-02).**

1. A matched edge lost its own row also over the time its matched rows do
   not cover, and in a period, a match within the margin of 15 minutes but
   outside the period hid the edge entirely. Fixed: own rows (§3.2, 6).
2. A server edge named through a translation was counted on both sides
   when the agent of the client folds the address of the backend
   (`-fold-external=all`). Fixed (§3.3).
3. Two connectors writing different translations at once left a mix, so
   that a DNAT translation got the sources of another and became SNAT;
   `peer_cidrs` had the same flaw. Fixed: advisory lock.
4. `shawk.peer.agent` of a client edge depended on the order of maps among
   tied backends. Fixed: ties by host.
5. The `server.port` of the client side moved with every report between
   backends on different ports. Fixed: choice among current backends.
6. No warning when the agent of a backend folds a client reached through a
   translation. Fixed.
7. LVS direct routing needs the virtual address as the backend; documented
   and tested.

**Second review (2026-11-03).**

1. A matched row ends with the edge of one side but carried the
   observation of both, so that a stopped agent raised a *disappeared*
   alert. Fixed: NULL observations (§3.2, 7).
2. The precedence of a match by address was decided per edge, and in a
   period by the server edges in it, so that widening the period dropped a
   current dependency; the connector gave precedence to any endpoint at the
   virtual address. Fixed: per period (§3.2, 3), and only a service
   observed on a socket recently in the connector (§3.3).
3. Behind sources, the server side had `shawk.peer.agent` true when an
   agent holds the address of the relay, so that the connections of
   clients without an agent were counted nowhere. Fixed (§3.3).
4. The own row of a matched edge spanned the whole edge for any gap, so
   that a failover made a one-sided dependency look current. Fixed: it ends
   with the last part left.
5. The connector named a client edge after docker-proxy, listening on
   every address of the host, while PostgreSQL matched it through the
   translation. Fixed with 2.
6. The view failed on an edge with `first_seen` after `last_seen`. Fixed.
7. The warning about an agent that folds the virtual address named the
   backend. Fixed.

Also from the second review: the configuration is written in READ
COMMITTED (under a database default of REPEATABLE READ the write failed)
and in one transaction with `peer_cidrs`; the number of rows behind sources
is documented (§4). Left as they are: the range cache may be one write
interval old, and an agent whose clock is ahead anchors the window of the
choice among backends, as it does for the other names.
