# Dependencies through translations of addresses: design proposal

Status: phase 1 (§3.1–§3.4, static translations in the configuration of
the connector) is implemented (2026-11-02, branch
`claude/translations-107`, pull request #130). Phase 2 (§3.5, translations
learned from conntrack) is implemented (2026-11-03, branch
`claude/learned-translations-107`); phase 3 (§3.6, docker-proxy) is not. It answers issue #107. The design is in
`docs/design.md` §5.4, §6, §7 and §10. Two adversarial reviews changed the
implementation of phase 1 (§10).

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

#### 3.5.1 Scope

- Docker published ports (iptables or nftables DNAT, and the masquerade of
  a container that leaves with the address of its host), kube-proxy
  (iptables, nftables, and IPVS with `net.ipv4.vs.conntrack=1`, which
  kube-proxy sets), LVS directors with that sysctl, and any DNAT, SNAT or
  REDIRECT rule: translations that change too often to be written down.
- One hop: the agent of the host that translates learns the translation;
  a connection translated on two hosts (a container behind the masquerade
  of its host to a published port of another host) is matched for neither
  hop, since the client edge and the server edge share no address with the
  same row. Chaining rows is left for later.
- Not covered: IPVS without `conntrack=1` (§9, 5; #139), datapaths without
  netfilter conntrack (the kube-proxy replacement of Cilium, eBPF load
  balancers), docker-proxy (phase 3), proxies and load balancers that
  terminate the connection (phase 1).
- Transparent proxies that REDIRECT to themselves (the sidecars of Istio
  and Linkerd) are learned like any translation (§9, 8). A sidecar
  connects to the server from the address of its pod, so the server edge
  matches the client edge of the application by address, which comes
  first: the application depends on the server, and the inbound edge of
  the sidecar keeps a row of its own. Where the server is not reached at
  the address the application connected to (a ClusterIP), the application
  depends on the sidecar.

#### 3.5.2 Kernel

Two kprobes on functions of the module nf_conntrack, which see every
connection that conntrack tracks, whatever made the translation:

| program | attached to | when it runs |
|---|---|---|
| `shawk_ct_confirm` | `__nf_conntrack_confirm(struct sk_buff *)` | once per new entry, when its first packet leaves the last hook (POSTROUTING or INPUT): DNAT (PREROUTING, OUTPUT) and SNAT (POSTROUTING, INPUT) are both done, and IPVS has rewritten the reply tuple |
| `shawk_ct_destroy` | `nf_ct_destroy(struct nf_conntrack *)`, else `destroy_conntrack` (upstream before 5.19; Rocky Linux 9.6 has the new name) | once per entry, when its last reference goes, including entries that lost a race at confirmation and were never inserted |

- **kprobe rather than fentry.** fentry needs BPF trampolines, which arm64
  has only since 6.0 (not in RHEL 9); the functions run once per
  connection, not per packet, so the cost of a kprobe (about 100 ns on
  x86_64) is small next to that of creating the entry. One program serves
  every kernel. The object is shared by x86_64 and arm64, so the register
  of the first argument is found by CO-RE (`di` or `regs[0]` of
  `struct pt_regs`). The fields of `struct nf_conn` are read with CO-RE;
  cilium/ebpf relocates against the BTF of vmlinux and of every loaded
  module, whatever the attach target.
- **What is a translation.** At confirmation the entry holds the original
  tuple (client C:c → virtual V:Pv) and the reply tuple (backend B:Pb →
  source S:s). It is a translation if V ≠ B or Pv ≠ Pb (DNAT, REDIRECT,
  IPVS) or C ≠ S (SNAT, masquerade). A change of the source port alone
  (a null binding that avoids a clash) is none. The tuples are compared
  rather than `status & IPS_NAT_MASK`, because IPVS rewrites the reply
  tuple without setting those bits. Only TCP and UDP are kept.
- **Key** (`struct shawk_xlat_key`, 80 bytes): client C, virtual V, Pv,
  source S, backend B, Pb, the inode of the network namespace of the entry,
  and the protocol. The ports of the client (c) and of the source (s) are
  ephemeral and dropped, as in flows. IPv4 addresses are IPv4-mapped.
- **Maps:**
  - `xlats` (hash, key → `{conns, live, gen}`, capacity `-max-flows`):
    `conns` counts the entries confirmed since the key was added, `live`
    the entries alive now that the programs saw confirmed, and `gen` is
    the time the key was added, which tells it from a former key deleted by
    user space.
  - `xlat_conns` (hash, the address of the entry → `{key, gen}`, capacity
    four times `-max-flows`, preallocated, as tracing programs before 6.1
    require; about 140 bytes a slot, 9 MiB at the default): the entries
    counted in `live`. The confirm program inserts the entry, with the key
    and its generation, and increments `conns` and `live`; the destroy
    program deletes it and decrements `live` of its key if the key still
    has that generation. An entry that does not fit is counted in `conns`
    but not in `live`, and in `xlat_drops`.
  - The maps are not flipped like flows: `live` must persist across
    intervals.
- **Missed probes.** A kprobe is skipped while another BPF program, or a
  map update by a system call (`bpf_disable_instrumentation`), runs on the
  CPU, e.g. when a softirq frees an entry during an update of the agent.
  - A missed confirmation: the connection is not learned (its key is
    learned with the next one).
  - A missed destroy leaves the entry in `xlat_conns`. conntrack reuses the
    memory of entries (`SLAB_TYPESAFE_BY_RCU`), so the address is soon
    confirmed again as another entry, translated or not: the confirm
    program then finds the stale entry, decrements the key it holds and
    removes or replaces it, at the cost of one lookup per new entry. Until
    then that key looks live.
  - The same entry confirmed twice (an unconfirmed entry shared by clones
    of a packet, a bridged broadcast) has the same key and generation, and
    is counted once, in `conns` too.
  - The losers of a race at confirmation (parallel DNS queries with the
    same tuple) are confirmed, counted, and destroyed at once; they count
    in `conns`, which only tells that the key is in use.
- **Why `live`.** A connection is confirmed once. A client that keeps a
  pool of long-lived connections to a virtual address opens no new ones,
  and a translation seen only at confirmation would end minutes after the
  pool opened while both edges go on (§3.5.6). With `live`, a translation
  is seen at every interval in which a connection through it is open, as
  edges are. An entry of conntrack outlives its connection by its timeout
  (TCP `TIME_WAIT` 2 minutes, UDP 30 seconds to 2 minutes), within the
  margin of the views; an established TCP entry whose peer vanished
  without a reset stays for 5 days, during which the matched rows are
  still bounded by the edges.
- **Filters**, in the confirm program: the network namespace of
  `-netns`; with folding (`-fold-external` `in` or `all`, §3.6 of the
  design), a translation whose source, client or backend is outside the
  internal ranges (which hold the addresses of the host) is dropped: the
  server sees the source as its peer and folds it, and a client or a server
  outside the ranges is taken to run no agent, so that no edge would match;
  with `all`, also one whose virtual address is outside them, which the
  client folds. This keeps out of the table the clients of the Internet of
  a published port or a NodePort (whose source is the address of the
  node when kube-proxy masquerades), and the destinations on the Internet
  of a masquerade.
- **Attaching.** nf_conntrack is a module on most distributions, loaded
  when a rule needs it, which may be after the agent starts (Docker, a
  first `iptables -t nat`). The programs are a collection of their own,
  sharing the maps, as the UDP programs are. While the module is not
  loaded (`/sys/module/nf_conntrack` is missing), the tracer looks for it
  every minute; a load that fails with the module there is tried again
  after twice as long each time, up to an hour, since every attempt
  creates the maps. The agent logs the first failure.
  The kprobes of a module that is unloaded and loaded again are not
  re-armed; the agent must then be restarted (documented, rare: a module
  in use by NAT rules cannot be unloaded).
- **Capabilities.** kprobes need `CAP_PERFMON` and `CAP_BPF`, which the
  unit already grants, and the system call `perf_event_open`, which the
  seccomp filter of the unit must allow (`SystemCallFilter`; it is not in
  `@system-service`). `test/packaging/agent-unit.sh` checks that the
  agent learns translations under the unit. Reading the table of conntrack
  over netlink would need `CAP_NET_ADMIN` in every namespace.
- **Not seen:** entries confirmed before the agent started, until their
  client opens a new connection: after a restart of the agent, a pool of
  long-lived connections through a translation is matched until its
  learned row ends, and then shows as a client row and a server row,
  until a new connection.

#### 3.5.3 Tracer and agent

- `tracer.Options.LearnTranslations` loads the programs. `Collect` reads
  `xlats` after the flows: a key is active in the interval if it is new,
  has another generation, `conns` changed since the last read, or
  `live > 0`. A key neither for a whole interval is deleted from the map,
  and from the last values the tracer keeps. A confirmation between the
  read of an idle key and its delete (the walk of the map and the deletes
  after it) is lost with the key: that connection is not learned, nor
  kept live, and if the key is added again its other generation keeps the
  destroy of that entry from decrementing the new count.
- `Snapshot.Translations` holds the active keys (`Translation`: transport,
  netns, client, virtual and its port, source, backend and its port);
  `Snapshot.TranslationDrops` the cumulative `xlat_drops`.
- The agent flag `-learn-translations` (default `true`, §9, 4) turns it
  off. The agent keeps a series per translation with its first and last
  seen times, expired after the idle TTL like edges.

#### 3.5.4 OTLP

- `shawk.translation.first_seen` and `shawk.translation.last_seen`: gauges
  of Unix seconds, with the attributes `network.transport`, `shawk.netns`,
  `shawk.translation.client.address`, `shawk.translation.virtual.address`,
  `shawk.translation.virtual.port`, `shawk.translation.source.address`,
  `shawk.translation.backend.address` and
  `shawk.translation.backend.port`. They come after the listeners and
  before the edges in the requests of an interval, so that the connector
  knows the translations of a host before it names the edges of the same
  host (kube-proxy translates on the host of the client). They count
  towards `-max-series-per-request`. Through a batch processor of the
  collector, or for translations of another host, the order is not kept:
  a client edge may then be named without its translation for an
  interval.
- Of the agent: `shawk.agent.translations.traced` (0 or 1) and
  `shawk.agent.translations.dropped` (cumulative), forwarded to Prometheus
  with the other metrics of the agent.
- A connector of the previous version ignores metrics it does not know:
  it writes and names as before.

#### 3.5.5 Connector and PostgreSQL

- **Input:** the connector reads the series into the batch of the host
  (`translationID`: the attributes above), skips the data that changes no
  span, as for edges, and writes them with the edges of the host.
- **Table** (migration 13):

  ```sql
  CREATE TABLE shawk.learned_translations (
    host_id      text    NOT NULL REFERENCES shawk.hosts,  -- the host that translates
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
    PRIMARY KEY (host_id, proto, netns, client_addr, virtual_addr, virtual_port,
                 source_addr, backend_addr, backend_port));
  CREATE INDEX learned_translations_client ON shawk.learned_translations (proto, virtual_addr, virtual_port, client_addr);
  CREATE INDEX learned_translations_server ON shawk.learned_translations (proto, backend_addr, backend_port, source_addr);
  CREATE INDEX learned_translations_last_seen ON shawk.learned_translations (last_seen);
  ```

  Times are those of the agent, like the times of edges; one row per key,
  `first_seen` the least and `last_seen` the greatest written.
- **Retention:** `shawk.prune` deletes the rows last seen before the
  cutoff, and keeps a host while it has rows.
- **Matching** (`dependencies`, `dependencies_between`), besides §3.2:
  1. A client edge c matches a learned row l if they have the transport,
     `c.local_addr = l.client_addr`, `c.remote_addr = l.virtual_addr` and
     `c.port = l.virtual_port`, and are in the same scope: a loopback
     client address in the host and namespace of l, a shared one on the
     host of l, any host otherwise.
  2. A server edge s matches l if `s.local_addr = l.backend_addr`,
     `s.port = l.backend_port` and `s.remote_addr = l.source_addr`, in the
     same scope: a loopback backend or source in the host and namespace of
     l, a shared one (a container bridge) on the host of l, any host
     otherwise.
  3. c and s are matched through the rows they both match whose periods
     overlap theirs, each within 2 minutes; rows of several hosts (two
     directors in turn) are combined into one pair. The period of the
     pair is the part of the periods of c and s that the span of those
     rows covers (the least first and the greatest last seen), so that a
     former backend ends with its rows, as with static translations it
     ends with its edges (§3.2, 4).
  4. A client edge whose server address and port are a virtual address of
     a static translation (with that port, or without a port) is matched
     through the static translation only: the configuration, written by an
     operator, comes first. A static 10.0.100.1:5432 leaves a learned
     translation of 10.0.100.1:80 alone.
  5. As with static translations: a match by address takes precedence
     over its periods (§3.2, 3); edges keep rows of their own for the
     parts their matched rows leave (§3.2, 6); a server edge from a source
     other than the client (SNAT) keeps its whole row, since the source
     may also forward clients that are not learned (another host, before
     the agent started); observations are NULL on the side whose edge
     outlives the row (§3.2, 7).
  6. `virtual_addr` and `virtual_port` are those of the client edge, and
     `translation` is `~learned`. The connector rejects names of the
     configuration that start with `~`, which phase 1 accepted (§3.5.8).
- **Contract:** the result of `dependencies_between` keeps its columns, so
  the function is replaced in place (`CREATE OR REPLACE`), and so is the
  view; the functions and views on them follow unchanged.
- **Names of peers** (Prometheus), besides §3.3; the resolver keeps the
  learned translations this connector saw in the idle TTL, and those that
  PostgreSQL has with `last_seen` in the idle TTL, read with the endpoints.
  Static translations come first, as in PostgreSQL: learned rows are used
  only for an edge that no static translation names or marks as behind a
  relay.
  1. A client edge whose virtual address has no static translation and
     matches learned rows in the scope of rule 1 is named after the best
     service at their backends (§3.3), with the port of the backend and
     `shawk.peer.agent` of its host. A backend at a loopback or a shared
     address (a container bridge) is looked up on the host of the row only
     (and for loopback, the endpoint must be on that host): another host
     has a container at the same address. A service at the virtual address
     comes first only if this connector saw its server edge from this
     client recently, as a match by address comes first in PostgreSQL: a
     container that reaches a published port of its host goes through
     docker-proxy, which serves the address, while the clients of other
     hosts go to the container. If the source is the client (DNAT) and the agent of the backend
     folds the address of the client, the warning of §3.3 applies.
  2. A server edge whose client is not found by address and that matches
     learned rows with the source equal to the client (DNAT) in the scope
     of rule 2 is named after the best client service whose client edge has
     the client, virtual address and port of a row, and counts as a
     translation without sources does (`shawk.peer.agent` of the client). A
     client at a loopback or shared address is looked up on the host of the
     row only.
  3. A server edge behind a learned SNAT (the source is another address
     than the client) keeps its name and `shawk.peer.agent` as before phase
     2: it bundles every client the source forwards or masquerades, so a
     name after one of them would move between them and attribute the
     others to it. Its host translated the connections, and its agent sees
     the clients on it, which count them; unlike a relay of a static
     translation, whose host records none of them (§3.3), this keeps the
     counts of §7 for the common case of containers that leave with the
     address of their host.

#### 3.5.6 Counting (§7 of the design)

- DNAT: as §3.4.
- SNAT learned (names 3): as before phase 2. The server edge has
  `shawk_peer_agent` of the host of the source, which translated the
  connections: true if it runs an agent. Containers on that host that leave
  with its address are counted by their client edges. Clients that it
  forwards from other hosts (a NodePort of kube-proxy with
  `externalTrafficPolicy: Cluster`) and that run no agent are counted on
  neither side, as before; they keep their rows in PostgreSQL (rule 5).
  Learned rows would tell them apart, which is left for later.
- A relay of a static translation with sources keeps §3.4, even if its host
  also learns the translations (names, static first).

#### 3.5.7 Performance

- **Kernel:** two kprobes per connection tracked by conntrack, not per
  packet; one hash lookup per confirmation, and an update per confirmation
  of a translated entry; one lookup per destroyed entry. `xlat_conns` takes
  about 140 bytes per slot (9 MiB at the default 65,536 slots), allocated
  once nf_conntrack is loaded: that is most hosts of RHEL 9, whose
  firewalld loads it, and every host with Docker or kube-proxy. A host that
  keeps more live translated entries (`nf_conntrack_count`) needs a larger
  `-max-flows`; the entries that do not fit count at their confirmation
  only, so a translation used only by long-lived connections that do not
  fit may end early.
- **Agent:** one walk of `xlats` (at most `-max-flows` keys) per interval.
- **PostgreSQL** (a million synthetic edges, 1,000 hosts, PostgreSQL 16,
  `work_mem` 4 MB, no JIT): without learned rows, the view and the function
  take the time of migration 12 within noise (all history 2.1–2.3 s, 6
  hours 0.37–0.42 s). With 100,000 learned rows that match 100,000 pairs
  (12,500 of them in the 6 hours), all history takes 4.9–5.1 s and 6 hours
  0.70–0.73 s. `direct` is computed per pair through the index of server
  edges: a first version computed it per client edge in a CTE that the
  planner inlined into a nested loop over every pair, and did not finish
  in 10 minutes.

#### 3.5.8 Compatibility

- Migration 13 adds the table and replaces `dependencies_between`,
  `dependencies` and `shawk.prune` in place; run `grants.sql` again, so
  that the connector role writes the new table (the views keep their
  grants).
- The unit of the agent allows `perf_event_open`; a unit copied from an
  older package learns no translations and logs why.
- A configuration with a translation whose name starts with `~` is
  rejected.
- Any order of upgrades: an agent of the previous version sends no
  translations; a connector of the previous version ignores them; the
  views of migration 13 without learned rows return what migration 12
  returned.

#### 3.5.9 Tests

- **Tracer** (`make test-root`, the virtual machines): network namespaces,
  veth pairs and NAT rules written over netlink (nftables), since the
  virtual machines have no iptables: DNAT in OUTPUT (IPv4 and IPv6), SNAT
  in POSTROUTING; a host that forwards between a client and a container
  (DNAT in PREROUTING over TCP and UDP, confirmed in POSTROUTING, REDIRECT
  confirmed in INPUT, MASQUERADE); `live` while connections are open and
  after their entries go, a connection opened and closed within an
  interval, no translation without NAT, the netns filter and the fold
  filter, the module loaded after the tracer starts and the backoff of
  failed loads, a missed destroy released by the next entry at its
  address, a key that gets a connection while it is deleted as idle, and
  an error reading the translations that keeps the flows. The virtual
  machines load the modules of nf_conntrack, nf_tables with NAT,
  masquerade and redirect, and veth (Rocky Linux 9: kernel-modules-core;
  upstream: the modules package of the mainline build).
- **Compatibility:** `TestKernelCompatibility` checks the kprobe targets,
  their parameters and the CO-RE relocations of the programs against the
  BTF of the Rocky Linux 9.6 kernel and of its module nf_conntrack
  (`scripts/fetch-module-btf.sh`); the virtual machines of upstream 5.14
  and 5.15 attach the destroy program to `destroy_conntrack`.
- **Packaging:** under the packaged unit, the agent learns a REDIRECT of
  OUTPUT and sends it (`test/packaging/agent-unit.sh`).
- **Agent and OTLP:** the series, their order in the requests, the idle
  TTL, the golden request.
- **Connector:** parsing and bounds, the skip of unchanged spans, the names
  of both sides (DNAT, SNAT, the scopes of loopback and shared clients and
  backends, the precedence of static translations and of a service that
  served the client at the virtual address, former backends), the
  warnings, the privileges on the table.
- **PostgreSQL:** each condition of the matching of §3.5.5 has a test that
  fails without it (21 mutations of migration 13); the view against the
  function, also over a period that leaves out a row of the pair; prune,
  also without the privileges.
- **e2e:** the case of phase 1 (DNAT in the namespace of app) without a
  translation in the configuration, matched through the learned one, and a
  second port with a static translation, which comes first.

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
- Phase 2 learns one hop (§3.5.1): a connection translated on two hosts is
  not matched (the cheap next step for hosts with containers: join a pure
  SNAT row, whose virtual address is its backend, with the DNAT row of the
  next host by the source, virtual address and port); nor is one through IPVS without `conntrack=1`; nor, until
  their client opens another, are connections confirmed before the agent
  started.
- Learned SNAT of clients forwarded from other hosts leaves those without
  an agent uncounted in Prometheus, as before phase 2 (§3.5.6).
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
| Learning from `status & IPS_NAT_MASK` | IPVS rewrites the reply tuple without setting the bits (§3.5.2). |
| fentry, with a kprobe only where trampolines are missing | Two programs for each hook, and arm64 before 6.0 (RHEL 9) needs the kprobe anyway; the hooks run once per connection (§3.5.2). |
| Reading the table of conntrack over netlink, or `/proc/net/nf_conntrack` | `CAP_NET_ADMIN` in every namespace, a walk of every entry at every interval, and the procfs file is often compiled out. |
| A learned translation seen only at confirmation | Long-lived connections would lose their match minutes after they opened (§3.5.2, why `live`). |
| Learned rows not bounding the matched period | A client pinned to one backend by long-lived connections would look current on every backend it ever reached. |
| Learned SNAT named as a relay (`shawk.peer.agent` false) | Containers that leave with the address of their host would be counted twice, where they are counted once before phase 2 (§3.5.5, names 3). |
| A translation name per host that translates | Two directors in turn would make two rows of one dependency; the host is in `shawk.learned_translations`. |
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

1. **Phase 1 (pull request #130):** §3.1–§3.4, documents, CHANGELOG.
2. **Phase 2 (this branch):** §3.5; kernel, agent, connector and views,
   tested in the virtual machines and the e2e test.
3. **Phase 3:** §3.6, by the path of phase 2.

## 9. Decisions

All decided as recommended (2026-11-03).

1. Phase 1 alone makes the first pull request: yes (phases 2 and 3 change
   BPF and the agent, and need their own verification). Done: #130.
2. A server edge from a source keeps a row of its own besides its matched
   rows: yes.
3. The `port` of a matched row, and the `server.port` of the client side
   in Prometheus, are those of the backend: yes.
4. Phase 2 traces conntrack by default: yes, `-learn-translations`
   defaults to `true`; hosts that do not translate record nothing, and the
   programs load only once nf_conntrack is loaded.
5. IPVS without `net.ipv4.vs.conntrack=1` (an LVS director configured by
   hand), which would need a kprobe on `ip_vs_conn_new` of the module
   ip_vs: not in phase 2 (kube-proxy sets the sysctl; such a director is
   written as a static translation); follow-up issue #139.
6. A static translation of a virtual address takes precedence over learned
   rows for it: yes (the operator wrote it; the views stay as in phase 1
   where it exists).
7. Learned SNAT is learned too (masquerade, not only DNAT): yes; a
   container that reaches another host leaves with the address of its
   host, the most common case on hosts with containers. With folding, the
   destinations and clients on the Internet are not learned (§3.5.2,
   filters); without it, the table grows with them, up to `-max-flows`.
8. Transparent proxies that REDIRECT to themselves (sidecars) are learned
   as any translation: yes; dropping translations to a loopback backend
   would lose REDIRECT to local services as well. A sidecar that connects
   from the address of its pod to the address the application connected
   to leaves the application depending on the server (a match by address
   first, §3.5.1); through a ClusterIP, the application depends on the
   sidecar, one hop.

## 10. Adversarial reviews and responses

**Review of the design of phase 2 (2026-11-03).**

1. The seccomp filter of the unit did not allow `perf_event_open`, so the
   kprobes never attached under it. Fixed: the unit allows it, and the
   test of the unit checks that translations are learned (§3.5.2).
2. Missed probes are known (a kprobe is skipped while a map update of a
   system call runs on the CPU), and a missed destroy, with the memory of
   entries reused, corrupted the count of another key. Fixed: the entry
   keeps its key, and a stale entry is released when its address is
   confirmed again (§3.5.2).
3. The connector looked a loopback or shared backend up on any host
   (another host's container at 172.17.0.5, a sidecar on 127.0.0.1).
   Fixed: on the host of the row (§3.5.5, names).
4. A key deleted by user space and added again was decremented by the
   destroy of an entry counted in the former key. Fixed: generations.
5. With folding, the clients of the Internet of a NodePort (source: the
   node) and the destinations of a masquerade were still learned. Fixed:
   the client and the backend are filtered too.
6. Learned SNAT would have overridden the relay of a static translation
   in the connector (agentless clients counted nowhere). Fixed: static
   translations first in the connector too.
7. Transparent proxies were not discussed. Decision 8.
8. A server edge behind learned SNAT was named after one of its clients.
   Fixed: its name is kept (§3.5.5, names 3).
9. Also: `conns` counted an entry confirmed twice; names starting with
   `~` were not rejected; the order of the series is not kept through a
   batch processor; rule 4 now says which port; the datapaths without
   conntrack and the two-hop step are noted.

Not taken: the destroy program would have resolved its CO-RE relocations
against vmlinux only on kernels with `destroy_conntrack`. cilium/ebpf
v0.22 relocates against the BTF of every loaded module, whatever the
attach target.

**First review of the implementation of phase 2 (2026-11-03).**

1. The connector named a client edge after any backend learned in the
   idle TTL: a published port re-pointed to another container, whose former
   address became another service, named the client after that service.
   Fixed: the learned backends seen within 5 minutes of the most recent
   one, as for endpoints; the same for the clients of a server edge.
2. Decision 8 said that a client depends on its sidecar; the match by
   address of the connection of the sidecar comes first. Documented, with
   a test.
3. Two CPUs that confirm the same entry at once counted it twice, and its
   translation stayed live for good. Fixed: the entry is inserted first
   (`BPF_NOEXIST`). A race, not reproduced by a test; the tests in the
   virtual machines check that nothing else changed.
4. A load that keeps failing with nf_conntrack loaded created the large
   maps every minute. Fixed: the wait doubles up to an hour.
5. A server edge through a learned DNAT whose virtual address the agent of
   the client folds was taken as counted by the client. Fixed: as for
   static translations.
6. A key deleted as idle that got a connection between the walk and the
   delete lost it. Fixed: it is taken out with its values and put back.
   Also: the warning of a full table names both capacities, and the
   learned rows are looked up only when there are some.

**Second review of the implementation of phase 2 (2026-11-03).**

1. The agent sends a translation for its idle TTL after its last use, and
   the connector took every request as a new sighting, so the fix of 1
   above did not hold within one connector. Fixed: a translation is as old
   as its last seen time before the request.
2. Without `grants.sql` run again after migration 13, the writes of every
   host that sends translations, the names of peers and the retention of
   all connectors failed. Fixed: the connector checks its privileges on
   the table (every 10 minutes) and leaves the learned translations out,
   with a warning; `shawk.prune` skips them, and the hosts; `grants.sql`
   sets default privileges for the tables of later migrations.
3. The e2e test no longer covered static translations. Fixed: a second
   port of the virtual address has one, which comes first.
4. An error reading the translations lost the flows of the interval.
   Fixed: it is logged, and the snapshot keeps its flows.
5. The documents said the load is retried every minute. Fixed.
6. A network namespace out of range was accepted. Fixed.

**Third review of the implementation of phase 2 (2026-11-03).**

1. With docker-proxy (the default of Docker), a container that reaches a
   published port of its host goes through docker-proxy, whose server edge
   at the address of the host is recent; the connector named the clients
   of other hosts, whose connections the host DNATs to the container,
   after docker-proxy, while PostgreSQL matched them with the container.
   Fixed: through a learned translation, a service at the virtual address
   comes first only if its server edge from this client was seen.
2. `has_table_privilege` with a list of privileges is true if any is held:
   a role that may only read the table failed the writes of its hosts and
   the retention. Fixed: one call per privilege.
3. A missed destroy was released only by a translated entry at its
   address; most entries translate nothing. Fixed: any entry confirmed at
   that address releases it; tested in the virtual machines by detaching
   the destroy program.
4. Over a period that left out the row of the first of two directors, the
   function started the matched row at the failover, the view before.
   Fixed: the function takes every learned row of the edges in the period.
5. Many conditions of the matching, and of the names, survived their
   removal, and the tests of the tracer covered OUTPUT and POSTROUTING on
   loopback only, while this section said more. Fixed: tests of each
   condition and of a host that forwards, UDP, REDIRECT, MASQUERADE and
   IPv6; the test of the unit checks a learned translation.

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
