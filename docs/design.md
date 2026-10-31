# Design of shawk

shawk keeps the **record of network dependencies** of a fleet: which process
talks to which network service on every host, since when, until when, and
how much. It answers the questions asked before changing a system — *who
still uses this database? what appeared after the deployment? did anything
use this host in the last 90 days, and were we watching?* — in Grafana, from
PostgreSQL and Prometheus.

It is built on the socket-based tracing method with in-kernel flow bundling
proposed in

> Yuuki Tsubouchi, Masahiro Furukawa, Ryosuke Matsumoto. *Low Overhead TCP/UDP
> Socket-based Tracing for Discovering Network Services Dependencies.* Journal of
> Information Processing, Vol. 30, pp. 260–268, 2022.

## 1. Why

The paper is motivated by changes whose impact administrators cannot
predict: platform migrations where old and new systems coexist, and clients
such as batch jobs that talk to a server only once a day or a week, which
sampling-based tracing misses. Answering those needs

- **completeness**: every process, every TCP/UDP service, including
  middleware and third-party software that cannot be instrumented;
- **always-on tracing** with low overhead, so that rare dependencies are
  observed;
- **long retention with known coverage**, so that "nobody used it in the
  last 90 days" is a statement backed by data, and "not observed" is not
  mistaken for "not used".

Existing eBPF service maps focus on the present state and on Kubernetes,
and application-layer instrumentation such as OBI (OpenTelemetry eBPF
Instrumentation) sees only the protocols it parses. shawk focuses on history
and coverage, for any TCP/UDP protocol, on VMs and on-premises hosts (the
primary target is Rocky Linux 9, kernel 5.14), and runs beside OBI (§9).

## 2. Architecture

```
 every host
   eBPF ─ shawk agent ── OTLP (edges with addresses) ──→ [collector] otlp/shawk ─→ shawk connector
   OBI (application) ─── OTLP ─────────────────────────→ [collector] otlp ─→ OBI pipelines

 shawk connector ─┬─→ PostgreSQL (relations, observation segments)
                  └─→ aggregated metrics without addresses ─→ Prometheus
 OBI pipelines ─→ Prometheus, trace store

 PostgreSQL + Prometheus (+ traces) ─→ Grafana
```

- The **agent** on each host traces flows with eBPF, resolves the process
  and service of each flow, and sends every 15 seconds all live series of
  its host as cumulative OTLP metrics (§4). It keeps no database and opens
  no port.
- The **shawk connector** is a component of the OpenTelemetry Collector, run
  in a collector built with the OpenTelemetry Collector Builder (§5). It
  writes the relations of every host to PostgreSQL, names the peer of every
  edge, and forwards aggregated metrics without addresses to Prometheus. Only
  the connector holds database credentials.
- **PostgreSQL is the truth of whether a dependency exists** (§6),
  **Prometheus of how much flows** (§7). They are joined by names
  (`service.name`, `service.peer.name`, `server.port`, `network.transport`,
  `host.id`), never by a cross-database join.
- **Grafana** is the user interface: dashboards and alerts are shipped as
  examples in `packaging/` (§8).

shawk promises two contracts: the views and functions of the PostgreSQL
schema `shawk_v1`, and the names and labels of its metrics in Prometheus.
The OTLP between agent and connector and the configuration of the connector
are internal; agent and connector are released together.

`shawk flows` shows the flows of the local host live, for debugging,
without a collector.

## 3. Tracing

### 3.1 What is recorded

A **bundled flow** is identified by

| field | meaning |
|---|---|
| direction | `out`: the local process opened the connection (client). `in`: it accepted it (server). |
| local / remote address | IPv4 is stored as IPv4-mapped IPv6 in the kernel |
| port | the **service port**: the remote port of an outgoing flow, the local port of an incoming flow |
| protocol | TCP or UDP |
| network namespace | inode number |
| cgroup id, comm | the identity of the local process |

The client's ephemeral port is dropped, so all connections between the same
pair of addresses to the same service collapse into one entry. The number of
records transferred to user space is proportional to the number of
*dependencies*, not of connections or messages (the key idea of the paper).
Unlike the original implementation, the process identity is part of the key;
the paper notes that without it, different clients on one host cannot be
distinguished (§5.3).

Per flow and interval the kernel accumulates: established connections,
failed connection attempts, connections open at the end of the interval,
bytes sent/received, UDP datagrams, retransmissions and smoothed RTT samples.
They cover the edge weights listed in §2.4 of the paper (throughput, RTT,
messages, errors and connections), except that TCP messages are not counted
since there is no hook on the data path; failed connection attempts and
retransmissions stand for errors, and open connections are added.

### 3.2 TCP: tracepoints and socket iterators only

| hook | role |
|---|---|
| `tp_btf/inet_sock_set_state` CLOSE→SYN_SENT | **active open**. Runs inside `connect(2)`, so the current task is the client. The flow key and the owner are stored in the socket local storage (`BPF_MAP_TYPE_SK_STORAGE`). |
| SYN_SENT→ESTABLISHED / →CLOSE | count an established / failed outgoing connection |
| SYN_RECV→ESTABLISHED | **passive open**; counts an incoming connection |
| *→CLOSE | account the remaining bytes of the connection |
| `iter/tcp` (every interval) | account byte deltas of long-lived connections, sample RTT, count open connections, list listening sockets, **adopt** connections established before the agent started |
| `iter/task_file` | find the owners of adopted connections and of listening sockets |

A socket iterator walks only the network namespace of the thread that opens
it, so the agent opens the TCP and UDP iterators inside every network
namespace of the host (found through `/proc/*/ns/net` and `/run/netns`).

Bytes are not counted on the send/receive path. They are read from the
cumulative counters of `struct tcp_sock` (`bytes_acked`, `bytes_received`,
`total_retrans`) at close and at every scan, and the difference to the last
accounted value is added to the flow. The iterator and the tracepoint do not
interleave on a socket where the TCP iterator locks each socket (Linux 5.19+
and RHEL 9 by backport); on older kernels, a connection closing during a scan
may rarely be counted twice. Atomic exchange is avoided because the arm64 JIT
supports it only since Linux 5.18. The direction of a
connection is decided once, when it is opened, and kept in the socket local
storage.

Consequences compared with the original implementation (kprobes on
`tcp_v4_connect`, `inet_csk_accept`, `tcp_sendmsg`, `tcp_cleanup_rbuf`):

* **No per-message overhead for TCP.** In the paper, the streaming method was
  cheapest for persistent connections because it traced only connection
  establishment, and the bundling method paid on every message. shawk gets
  both: per-connection cost for short-lived connections, zero per-message cost
  for persistent ones.
* **Stable ABI for TCP.** `inet_sock_set_state` is a tracepoint; no kernel
  function signature is assumed (e.g. `inet_csk_accept` changed in Linux
  6.10). The UDP hooks are fentry programs on kernel functions, whose
  signatures can change.
* **Works without BPF trampolines** (fentry/fexit), e.g. on kernels that
  restrict ftrace, or on arm64 before Linux 6.0.
* **Connections that predate the agent are found** (DB connection pools,
  gRPC channels). The original streaming mode never saw them.
* **IPv6** is handled, and so are **MPTCP listeners**: Go listens with MPTCP
  by default since 1.24; its listening socket is an MPTCP socket whose TCP
  subflows carry the traffic, so MPTCP listeners are reported as TCP
  listeners. MPTCP *clients* are not fully handled (see limitations).

The owner of an incoming connection is a holder of its listening socket.
The passive open records the cgroup of the accepted socket, which it
inherits from the listener and thus from the process that created the
listener. User space matches it against the holders that `iter/task_file`
found, so that programs sharing a port with `SO_REUSEPORT` are told apart; a
socket-activated service is preferred to systemd, which created its
listener, and the parent to forked workers. When no holder matches (the
listener was closed or replaced since the last scan), the cgroup still names
the service and another scan is requested.

### 3.3 UDP

UDP has no connection, so datagrams are bundled per message as in the paper:
`fentry/ip_send_skb`, `fentry/ip6_send_skb` and `fentry/skb_consume_udp`,
which run in process context. Ports cannot tell clients from servers:
resolvers bind random source ports anywhere in 1024-65535, and servers may
listen in the ephemeral range. The direction is therefore decided per socket
by its first datagram and kept in the socket local storage:

* a socket that receives first is a server, and one that sends first is a
  client;
* a socket that sends first on the port of a known server socket (e.g. the
  per-client connected sockets of a QUIC server) is a server;
* bound, unconnected sockets that exist when the agent starts are marked as
  servers, since their first datagram afterwards may be a reply.

A client socket that existed before the agent started and receives before it
sends again is recorded as a server with its own port.

UDP needs BPF trampolines. On kernels without them the agent keeps tracing
TCP and reports that UDP is not traced.

### 3.4 Reading flows without losing updates

Bundled flows are written into one of two hash maps selected through an
`ARRAY_OF_MAPS`. At every interval user space walks the sockets (so that the
traffic of long-lived connections lands in the closing interval), flips the
active index, and drains the inactive map after an RCU grace period: storing
the inactive map again in the `ARRAY_OF_MAPS` makes the kernel wait until
every program that read the old index has finished, so no program writes to
the map being read.

### 3.5 Kernel requirements and features used

The target is Rocky Linux 9 (5.14 with RHEL's backports) and upstream
Linux with BTF (`CONFIG_DEBUG_INFO_BTF`). The features the programs use
require upstream 5.14 or later:

| feature | since |
|---|---|
| BTF-enabled tracepoints (`tp_btf`) | 5.5 |
| ring buffer (cgroup events) | 5.8 |
| BPF iterators `tcp`, `udp`, `task_file` | 5.8 / 5.9 |
| socket local storage in tracing programs | 5.11 |
| `bpf_sock_from_file`, `bpf_get_current_task_btf` | 5.11 |
| cgroup pointer in `sock_cgroup_data` (else the owner of accepted connections is resolved in user space only) | 5.15, RHEL 9 |
| TCP iterator that locks each socket (else rare double counting) | 5.19, RHEL 9 |
| fentry (UDP only) | 5.5 on x86_64, 6.0 on arm64 |

What is tested: the programs are loaded and exercised on Ubuntu kernels
(6.8 to 7.0) in CI, and checked statically against the BTF of the Rocky
Linux 9.6 kernel. They have not run on an actual Rocky Linux kernel, on
upstream 5.14 to 5.18, or on arm64.

All struct accesses use CO-RE. `TestKernelCompatibility` checks every
attach target, helper and CO-RE relocation against the BTF of the Rocky Linux
9.6 kernel (`scripts/fetch-kernel-btf.sh`); for example `sk_userlocks` is a
plain byte in recent kernels but a 4-bit bitfield at a different offset in
5.14.

## 4. The agent

### 4.1 Identity of processes and services

- `shawk.unit` is derived from the cgroup path (`nginx.service`,
  `docker-0123456789ab`, `user-1000.slice/session.scope`, ...). Names that
  change on every run (login sessions, transient units) are normalized so
  that a cron job accumulates under one name. Since the cgroup of a
  short-lived job is often removed before the end of the interval,
  `tp_btf/cgroup_mkdir` reports the path of every cgroup when it is created,
  and the agent keeps it for an hour.
- `service.name` follows the order of OBI, so that both name a service the
  same way: `OTEL_SERVICE_NAME`, then `service.name` in
  `OTEL_RESOURCE_ATTRIBUTES` of the process (only the `OTEL_` variables of
  `/proc/PID/environ` are read; the rest is discarded as soon as it is
  read), then the base name of the executable, then comm.
  `-service-name-fallback=unit` uses the unit instead of the executable.
  `service.namespace` is read from `OTEL_RESOURCE_ATTRIBUTES`.
- Services that share an executable on a host (`ruby`, `python`, `java`,
  `php-fpm`) share a name unless they set `OTEL_SERVICE_NAME`, e.g. with
  `Environment=` in a systemd drop-in. PostgreSQL still tells them apart by
  unit.
- When a process exits before `/proc` is read, the latest identity seen for
  the same unit and comm is used.
- The host is identified by `host.id` (`/etc/machine-id`, else
  `/var/lib/dbus/machine-id`) and `host.name`. In PostgreSQL a host is the
  hash of both, so that VMs cloned with the same machine id stay apart.

### 4.2 What is sent

Every edge (a bundled flow with its process identity) is a series with the
attributes `service.name`, `service.namespace`, `process.executable.name`,
`process.executable.path`, `process.command`, `shawk.unit`, `shawk.role`
(`client` or `server`), `network.transport`, `network.local.address`,
`network.peer.address`, `server.port` (the service port, whatever the role)
and `shawk.netns`. The PID is not an attribute, so a restarted process
continues the same series.

| metric | type, unit | |
|---|---|---|
| `shawk.connection.opened` | Counter, `{connection}` | established connections (TCP) |
| `shawk.connection.failed` | Counter, `{connection}` | failed attempts (TCP client side only) |
| `shawk.connection.count` | UpDownCounter, `{connection}` | connections open at the end of the interval (TCP) |
| `shawk.network.io` | Counter, `By` | bytes, with `network.io.direction` |
| `shawk.udp.datagrams` | Counter, `{datagram}` | UDP datagrams, with `network.io.direction` |
| `shawk.tcp.retransmits` | Counter, `{segment}` | segments the local socket retransmitted |
| `shawk.tcp.rtt` | Histogram without buckets, `s` | smoothed RTT samples (sum and count) |
| `shawk.edge.first_seen`, `shawk.edge.last_seen` | Gauge, `s` | Unix time of the first and last activity |

Listening sockets are sent as `shawk.listener.first_seen` and
`shawk.listener.last_seen` with the transport, address, port, netns and
process attributes. The agent itself sends `shawk.agent.up` (with
`shawk.netns.scope`), `shawk.agent.segment.start`, `shawk.agent.udp.traced`,
`shawk.agent.flows.dropped`, `shawk.agent.export.failures`, and with
`-bpf-stats` the run count and time of each BPF program. The resource
carries `host.id`, `host.name`, `host.ip` (addresses of the interfaces and of
the live series, including containers), `os.version`, and
`service.name=shawk-agent` with `service.version`.

### 4.3 How it is sent

- **One request per interval.** Every 15 seconds the agent sends all live
  series of the host in one OTLP request (gRPC or HTTP/protobuf, gzip).
- **Cumulative.** Counters are totals since the series started, so a failed
  request is made up for by the next one. Requests are not retried.
- **Idle TTL.** A series with no activity (connections, bytes, datagrams or
  open connections) for `-idle-ttl` (15 minutes) is dropped; if it
  reappears, its counters start again from zero. This bounds the series of
  a host by its recent dependencies.
- **Observation segments.** `shawk.agent.segment.start` is the time from
  which every dependency active on the host has reached the connector. It
  is the start of the agent; when requests fail for longer than the idle TTL
  minus a minute, edges that ended meanwhile may have been dropped unsent,
  so the request that succeeds afterwards carries now minus the idle TTL:
  edges active since then are still being sent.

## 5. The shawk connector

### 5.1 Writes to PostgreSQL

For every request (one host), the connector accumulates the changes of
hosts, segments, addresses, processes, edges and listeners. Every
`write_interval` (1 minute) it writes the changes of each host in one
transaction. Edges and listeners are upserted with
`first_seen = least(...)` and `last_seen = greatest(...)`, so replays and
reordering give the same result and several connectors do not conflict. An
edge whose `last_seen` alone advances is written once per interval, and an
idle edge that agents keep sending until its TTL is not written again.

The segment of the request is upserted into `agent_sessions` with
`last_heartbeat` set to the time of the request: observations up to there
are written. While the database is down, changes accumulate (in proportion
to the number of edges, not to time) and are written when it returns. A
crash of the connector loses at most one write interval, which agents send
again while the edges are within their TTL.

Rows last seen longer ago than `retention` (3 years by default) are deleted
every hour by `shawk.prune()`, in batches of short transactions; processes
and hosts go once nothing refers to them. Sessions are deleted with them,
so `unobserved()` reports the time before the retention as not observed.

### 5.2 Names of peers

The connector loads `shawk_v1.service_endpoints`,
`shawk_v1.client_endpoints` and `shawk_v1.agent_addrs` every write interval,
and adds what it learns from requests at once.

| role | peer | `service.peer.name` |
|---|---|---|
| client | a service listens on the peer address and port | the service (`[namespace/]name`) |
| server | a client edge has the same addresses and port | the client service |
| either | unknown, in a range of `peer_cidrs` | the name of the narrowest range |
| either | unknown, private address | `~unresolved` |
| either | unknown, public address | `~external` |

`shawk.peer.agent` tells whether the peer address belongs to a host whose
agent is alive (or is loopback): the other side of the edge is then
recorded too, which the counting convention of §7 relies on.

Loopback peers are looked up on the same host only. Among several services
on an endpoint, one on the same host, then the most recently seen, wins.
Names are the best guess at the time of aggregation; PostgreSQL is the
truth of attribution. A new server may show as `~unresolved` until its
listener is written (up to one write interval).

### 5.3 Metrics to Prometheus

Edge metrics are reduced to `service.peer.name`, `shawk.peer.agent`, `shawk.role`,
`server.port`, `network.transport` and, for bytes and datagrams,
`network.io.direction`, and summed into **one resource per host and local
service**: `service.name` and `service.namespace` of the resource are those
of the local process, so Prometheus labels the series with the same `job`
as the metrics of OBI for the service. `service.instance.id` is the host
name, and `host.id` and `host.name` are promoted to labels by Prometheus.

- Series are bounded by host × local service × peer service × port × role;
  replicas and changing IPs of peers do not add series. Per host, local
  service and role, at most `max_peers` (50) peer names are used; the rest
  are folded into `~other`. `keep_peer_address` keeps
  `network.peer.address` when it is really needed.
- Inputs are cumulative per peer address; outputs merge several of them.
  The connector keeps the last value of every input series and adds the
  increase to the output, treating a decrease or a new start time as a
  reset, so an output never decreases when an input disappears. An input
  that started before the connector is taken as a baseline, so a restart of
  the connector does not add past totals at once. Open connections are the
  sum of the current inputs.
- An output series without input is sent until `idle_ttl` and then dropped.
- This state requires the data of a host to reach the same connector. With
  several connectors, route by resource with the loadbalancing exporter of a
  collector in front.
- The metrics of the agents are forwarded under `job="shawk-agent"`.

| Prometheus name | |
|---|---|
| `shawk_connection_opened_total`, `shawk_connection_failed_total` | connections |
| `shawk_connection_count` | open connections |
| `shawk_network_io_bytes_total`, `shawk_udp_datagrams_total` | traffic |
| `shawk_tcp_retransmits_total` | retransmitted segments |
| `shawk_tcp_rtt_seconds_sum`, `shawk_tcp_rtt_seconds_count` | RTT |
| `shawk_agent_*` | agents |

Prometheus needs `--web.enable-otlp-receiver`,
`otlp.promote_resource_attributes: [host.id, host.name]` and an
out-of-order window of 30 minutes; counters stay cumulative.

## 6. PostgreSQL

PostgreSQL 14 or later (multiranges and `CYCLE`). The schema is bundled
with the connector as migrations (`collector/shawkconnector/migrations`),
applied by `shawk-migrate` or by the connector with `postgres.migrate`.

### 6.1 Tables (internal, schema `shawk`)

```
hosts(id, machine_id, hostname, kernel, agent_version, first_seen, last_seen)
agent_sessions(host_id, started_at, last_heartbeat, udp_traced, netns_scope, dropped_flows)
host_addrs(host_id, addr, first_seen, last_seen)
processes(id, host_id, unit, comm, exe, service_name, first_seen, last_seen)
edges(id, host_id, process_id, role, proto, local_addr, remote_addr, port, netns, first_seen, last_seen)
listeners(host_id, process_id, proto, addr, port, netns, first_seen, last_seen)
```

`service_name` has the form of the `job` label (`namespace/name`), so that
names in PostgreSQL and Prometheus match.

### 6.2 Contract (schema `shawk_v1`)

| view or function | |
|---|---|
| `dependencies` | one row per logical dependency: the client edge and the server edge matched by their addresses and port (loopback within a host and netns). `observed_by` is `both`, `client` or `server`; a one-sided row means no agent on the other side, or a NAT or load balancer between. `client_observed_until` and `server_observed_until` are the latest heartbeats of the hosts: an old `last_seen` with a recent `observed_until` means *no longer used*; both old means *no longer observed*. |
| `graph_nodes`, `graph_edges` | the dependency map between services in the format of the Grafana Node Graph; peers without a service are named by address |
| `dependency_changes` | dependencies between services that appeared, or disappeared while a host that saw them kept observing for 15 minutes |
| `service_endpoints` | addresses and ports services accept connections on (listeners, with unspecified addresses expanded to the addresses of the host, and server edges); used by the connector |
| `client_endpoints` | the client sides of connections in the last hour (client address, server address, port, client service); used by the connector to name the peer of a server edge |
| `agent_addrs` | addresses of hosts whose agent reported in the last 5 minutes; used by the connector |
| `agents` | the latest segment of every host and whether its agent is alive |
| `unobserved(since, until, tolerance)` | the periods in which each host was not observed; Grafana overlays them as annotations |

The connector role writes `shawk` and reads `shawk_v1`; Grafana reads
`shawk_v1` only (`packaging/postgres`).

## 7. Counting each dependency once

When both ends run an agent, a dependency appears on the client side
(`shawk_role="client"`) and on the server side (`shawk_role="server"`). The
recording rules in `packaging/prometheus/shawk-rules.yml` count it once:

| metric | per dependency |
|---|---|
| connections, open connections, bytes, datagrams, RTT | the client side; the server side only when the client has no agent (`shawk_peer_agent="false"`) |
| connection failures | the client side only (the server never sees them) |
| retransmissions | both sides: each counts its own retransmitted segments; `shawk_role` is the sender |

The two sides differ in `shawk_role`, so their `or` is a union. The rules
label the client `src` and the server `dst` whichever side observed the
dependency, e.g. `shawk:dependency_connections:rate5m{src, dst,
server_port, network_transport}`.

## 8. Grafana

`packaging/grafana` holds data sources, dashboards (fleet, dependency map,
dependency details, changes, application layer of OBI) and alert rules.

The PostgreSQL data source is used for alerts in the **time series
format**: a `time` column, string columns as labels and one numeric
`value`. A query that finds nothing returns no rows, which is No Data, so
the rules treat No Data as Normal. A disappeared dependency is an explicit
row — its `last_seen` falls in a window while a host that saw it is still
observed — rather than a row that vanishes from the result, so a stopped
agent does not look like a removed dependency. Agents that stopped are
alerted by Prometheus (`ShawkAgentDown`) while their series are in the TSDB,
and by PostgreSQL (`shawk_v1.agents`) afterwards.

## 9. OBI

OBI (OpenTelemetry eBPF Instrumentation) cannot replace the tracer of
shawk: its network flows and TCP statistics do not tell which process
communicates, and its application layer covers only the protocols it
parses. shawk runs beside it instead:

- OBI instruments the application layer (`application` and
  `application_service_graph` features) of selected services and sends to
  the `otlp` receiver of the same collector; its network and statistics
  features stay disabled, since shawk observes the same per process.
- Both name services the same way and both set the resource `service.name`,
  so `job` matches; dashboards use one `$service` variable for both.
- `host.id` is the machine id in both. Cloned VMs should regenerate it
  (`systemd-machine-id-setup`) for OBI's sake; shawk tells them apart by
  host name anyway.
- Dependencies seen by shawk but absent from the service graph of OBI show
  where application-layer instrumentation is missing.

## 10. Limitations

- **Relays that rewrite addresses** (NAT, IPVS, kube-proxy, cloud load
  balancers) hide the real peer, as discussed in §5.2 of the paper.
  Dependencies end at the relay address and are seen on one side only.
- **Addresses shared by many hosts** (container bridges such as
  172.17.0.1) can be attributed to the wrong host when naming peers.
- **Same port shared by different services** with `SO_REUSEPORT` cannot be
  told apart (§5.3 of the paper); this is rare.
- **UDP peer-to-peer protocols** where both sides send first are recorded
  as clients of each other's port. A UDP client socket that existed before
  the agent started and receives before it sends again is recorded as a
  server.
- **MPTCP clients**: an outgoing MPTCP connection that existed before the
  agent started is not attributed to its process, and additional subflows
  opened by the kernel's path manager are attributed to a kernel worker.
- **Flow table capacity**: when more distinct flows than `-max-flows` occur
  in one interval, updates are dropped and `shawk.agent.flows.dropped`
  counts them.
- **Clocks**: times come from the clock of each agent; heartbeats are
  compared with the clock of PostgreSQL.
