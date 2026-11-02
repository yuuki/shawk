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
| SYN_RECV→* | **passive open**; counts an incoming connection. It usually goes to ESTABLISHED; a child created by a TCP Fast Open SYN, which carries data and is accepted at once, may also be closed or reset before the handshake completes. Other children that leave SYN_RECV for CLOSE failed to be created (e.g. without a route to the client) and are not counted. On a socket that went through SYN_SENT it ends a simultaneous open instead, e.g. of a socket connected to itself, which stays outgoing. |
| *→CLOSE | account the remaining bytes of the connection, if any |
| `iter/tcp` (every interval) | account byte deltas of long-lived connections, sample RTT, count open connections, list listening sockets, **adopt** connections established before the agent started |
| `iter/task_file` | find the owners of adopted connections, of MPTCP connections and of listening sockets |

A socket iterator walks only the network namespace of the thread that opens
it, so the agent opens the TCP and UDP iterators inside every network
namespace of the host (found through `/proc/*/ns/net` and `/run/netns`).

Bytes are not counted on the send/receive path. They are read from the
cumulative counters of `struct tcp_sock` (`bytes_acked`, `bytes_received`,
`total_retrans`) at close and at every scan, and the difference to the last
accounted value is added to the flow. These counters count sequence
numbers, so the SYN and the FIN of each side are subtracted: the local SYN
when an active open is established (data carried by a TCP Fast Open SYN is
counted), and a FIN once it is acknowledged (the local one) or received
(`SOCK_DONE`, the peer's). The iterator and the tracepoint do not
interleave on a socket where the TCP iterator locks each socket (Linux 5.19+
and RHEL 9 by backport); on older kernels, a connection closing during a scan
may rarely be counted twice. Atomic exchange is avoided because the arm64 JIT
supports it only since Linux 5.18. The direction of a
connection is decided once, when it is opened, and kept in the socket local
storage.

A connection that existed before the agent started is adopted by the first
walk. It is incoming when its local port is listening; it then belongs to
the owner of the listener. Otherwise `iter/task_file` finds the process
holding it. It may still have been accepted: by a listener that is gone (a
server draining its connections after a graceful restart, an FTP data
connection) or, with TPROXY, on another port than the listener's. Ports
cannot tell, since clients may bind any port and servers may listen
anywhere; but `listen(2)` sets `sk_max_ack_backlog`, the connections a
listener accepts are clones of it that keep it, and a socket that connects
never listened. Such connections are incoming, the others outgoing. The
traffic of an adopted connection before the adoption is not counted.

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
* **IPv6** and **MPTCP** are handled (see below).

The owner of an incoming connection is a holder of its listening socket.
The passive open records the cgroup of the accepted socket, which it
inherits from the listener and thus from the process that created the
listener. User space matches it against the holders that `iter/task_file`
found, so that programs sharing a port with `SO_REUSEPORT` are told apart; a
socket-activated service is preferred to systemd, which created its
listener, and the parent to forked workers. When no holder matches (the
listener was closed or replaced since the last scan), the cgroup still names
the service and another scan is requested. The walk also reports the inode
of every listening socket, and a listening socket that the last scan did not
see, or that it saw and is gone, requests one, so that a listener replaced
by another process of the same cgroup, e.g. a restarted service, is
attributed to it at once, also when both listen for a while with
`SO_REUSEPORT`.

**Sockets of the kernel.** The kernel opens and holds sockets of its own,
without a file: the clients of NFS, iSCSI, CIFS and Ceph, nfsd, DRBD.
They are what matters before a server is decommissioned (a mounted NFS
export), but they have no stable process. A connection is opened in a
kernel worker (NFS) or in whichever process triggers it (CIFS connects in
`mount`), in the root cgroup or that of the process, so the command name
(`kworker/u8:2`) changes from one reconnection to the next; and an adopted
connection has no process for `iter/task_file` to find, so it would never
be accounted. A socket that connects or sends a datagram is the kernel's
when `sk_kern_sock` is set (a 1-bit bitfield in 5.14, read with
`BPF_CORE_READ_BITFIELD_PROBED`) and it is not an orphan, closed by its
process. Whether it has a file does not tell: the NFS client gives its
sockets one, which no process holds. The kernel also creates sockets for
processes: MPTCP subflows, which are checked first (below), and the TCP
socket of an SMC socket, which sends an SMC option in its SYN (`syn_smc`,
read only on kernels with `CONFIG_SMC`) and connects in `connect(2)` of
the process; it keeps the current process. Such a socket gets the command name
`~kernel` and cgroup id 0, which no process has, at its active open (TCP)
or datagram (UDP), and an adopted outgoing one is ready at once. The
children of a listener inherit `sk_kern_sock`, so it does not tell who owns
an incoming connection: the plain TCP children of an MPTCP listener for
clients without MPTCP, which a process accepts, inherit it from the first
subflow of the listener. Incoming connections are attributed through their
listener (above) instead. A listener is the kernel's when no process held
it at the last owner scan and the walk found that the kernel may hold it:
it was created by the kernel (`sk_kern_sock`, other than the first subflow
of an MPTCP listener), it has no file, or the kernel uses it
(`sk_user_data`), as nfsd uses the sockets that `rpc.nfsd` creates and
passes to it (`/proc/fs/nfsd/portlist`), whose children are not kernel
sockets. Neither alone is enough: an agent in a PID namespace does not see
the processes outside it, and processes hold MPTCP listeners. Such
listeners no longer request an owner scan for every connection they
accept. How these flows are named is in
§4.1.

**MPTCP.** Go listens with MPTCP by default since 1.24, and dials with it
with `GODEBUG=multipathtcp=1`. An MPTCP socket, which the application
holds, carries its traffic over TCP subflows, which the kernel creates
without a file; the TCP hooks see the subflows. MPTCP listeners are
reported as TCP listeners. The first subflow of a connection is opened in
`connect(2)`, so its owner is known as for TCP; additional subflows
(MP_JOIN) are opened by the path manager in a kernel worker, and adopted
subflows have no file for `iter/task_file` to find. Both get the owner of
their MPTCP socket instead. On 5.14 a program cannot reach the MPTCP socket
of a subflow as a socket (`bpf_skc_to_mptcp_sock` is 5.19), only read its
address (`icsk_ulp_data` → `mptcp_subflow_context.conn`), so the owners are
kept in an LRU hash map by that address, as large as the tables of
listening ports: recorded when the first subflow connects and by
`iter/task_file` for the MPTCP sockets processes hold, which replaces at
every owner scan what an earlier one recorded (so that an entry left at a
reused address does not last), and removed when the MPTCP socket closes. A
subflow whose owner is not known yet waits for the next walk after an
owner scan, like an adopted connection, or takes it when it closes. A connection counts once, by its first subflow: additional
subflows (`request_join` or `mp_join` in the subflow context) count no
connection or failed attempt, on either side, but their traffic, RTT and
retransmissions are accounted to the flow of their own addresses. It is
open once, on the subflow at the head of its list of subflows
(`mptcp_sock.conn_list`): the initial one, or another once the initial one
closed. Kernels without MPTCP have no `tcp_sock.is_mptcp`, which guards
these reads. RHEL 9 turns MPTCP off by default (`net.mptcp.enabled=0`).
Go's dialer retries with TCP after any MPTCP error, so a failed dial makes
two attempts, and both are counted.

### 3.3 UDP

UDP has no connection, so datagrams are bundled per message as in the paper:
`fentry/ip_send_skb`, `fentry/ip6_send_skb` and `fentry/skb_consume_udp`,
which run in process context. A UDP GSO send (`UDP_SEGMENT`) and a GRO
receive by a socket with `UDP_GRO` count every datagram they carry; a
datagram peeked at (`MSG_PEEK`) is counted when it is read. Ports cannot tell clients from servers:
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
| fentry (UDP only) | 5.5 on x86_64, 6.0 on arm64 (not in RHEL 9 on arm64) |

What is tested in CI: the tests that load the programs run on the kernel of
the Ubuntu runners (6.8 to 7.0) on x86_64 and arm64, and in virtual
machines (`test/vm/run.sh`, `make vm-test`) on the kernel of Rocky Linux 9.6
(x86_64 and aarch64) and on upstream 5.14 (x86_64) and 5.15 (x86_64 and
aarch64). On aarch64 before 6.0, Rocky Linux 9 included, UDP is not traced:
the fentry programs load but cannot attach, and the tests check that the
tracer reports it and traces TCP.

All struct accesses use CO-RE. `TestKernelCompatibility` checks every
attach target, helper and CO-RE relocation against the BTF of the Rocky Linux
9.6 kernel (`scripts/fetch-kernel-btf.sh`); for example `sk_userlocks` is a
plain byte in recent kernels but a 4-bit bitfield at a different offset in
5.14. It also compares the parameters of the kernel functions and BTF
tracepoints the programs attach to with those `BPF_PROG` declares in the
source, which the verifier does not check for arguments read through
`BPF_CORE_READ`; `TestProgramPrototypes` does the same against the running
kernel and its modules.

The kernel types come from `internal/tracer/bpf/include/vmlinux.h`, dumped
by bpftool from the BTF of Linux 6.18.44 (x86_64, release `6.18.44-fc-v185`). `scripts/gen-vmlinux.sh`
(`make vmlinux`) regenerates it from the running kernel or a BTF file and
records the kernel in its first lines.

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
  read), then the base name of the executable, then comm, then the unit,
  then `~unknown` (a socket whose owner is not known).
  `-service-name-fallback=unit` uses the unit instead of the executable.
  `service.namespace` is read from `OTEL_RESOURCE_ATTRIBUTES`.
- Sockets of the kernel (§3.2) are named after their service port, the
  one thing that stays the same across reconnections: `~kernel:nfs` (2049),
  `~kernel:rpcbind` (111), `~kernel:smb` (139, 445), `~kernel:iscsi`
  (3260), `~kernel:ceph` (3300, 6789, 6800-7300), `~kernel:nvme-tcp` (4420,
  8009), `~kernel:drbd` (7788-7799), `~kernel:ocfs2` (7777), `~kernel:rds`
  (16385), `~kernel:dlm` (21064), and `~kernel` for other ports. The
  servers of the kernel are named apart from its clients, so that a
  dependency on them has two ends: `~kernel:nfsd` (2049), `~kernel:ksmbd`
  (445), `~kernel:iscsi-target` (3260, LIO) and `~kernel:nvmet-tcp` (4420,
  8009) on the server side; the other subsystems are clients only or peers
  of one another and have one name. Only sockets of the kernel are named
  by port; an application on these ports keeps its own name. The name
  starts with `~` like the other names shawk makes up, which `peer_cidrs`
  cannot take, and
  has no `/`, which would read as a namespace in the Prometheus `job`. The
  process has comm `~kernel`, no unit and no executable, so PostgreSQL has
  one row per host and name in `shawk.processes`, and each name is one
  `job` in Prometheus. The socket itself could tell more than the port
  (its `sk_data_ready` callback is `xs_data_ready` for the NFS client),
  but mapping it to a name needs `/proc/kallsyms`, which shows addresses
  only with `CAP_SYSLOG`, which the agent's unit does not grant.
- Services that share an executable on a host (`ruby`, `python`, `java`,
  `php-fpm`) share a name unless they set `OTEL_SERVICE_NAME`, e.g. with
  `Environment=` in a systemd drop-in. PostgreSQL also tells them apart by
  unit.
- The kernel bundles flows by cgroup and comm, not by process, and the
  agent names a flow after the last process seen on it. Processes that
  share a cgroup and a comm, e.g. two Python services under one supervisor
  unit, are therefore not told apart even with different
  `OTEL_SERVICE_NAME`; put them in different units (or containers) to tell
  them apart.
- `/proc` is read for the processes of an interval several at once, within
  one second per interval. A read of the environment takes the lock of the
  memory map of the process, which a stuck process may hold; it gives up
  after 200 ms, and a process whose read timed out is not read again for 5
  minutes after the read returns. The command name in `/proc` must match
  that of the flow, so that a PID reused by another process since is not
  trusted. When a process exits before `/proc` is read, or is not read in
  time, the latest identity seen for the same unit and comm is used.
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
carries `host.id`, `host.name`, `host.ip` (addresses of the interfaces of
the traced namespaces, and the local addresses of the series active in the
last two intervals, at least a minute, and of the open listeners, which
include containers), `os.version`, and `service.name=shawk-agent` with
`service.version`. Strings that are not valid UTF-8, such as a command name
cut in the middle of a character, are sent with the invalid bytes
replaced.

### 4.3 How it is sent

- **One interval at a time.** Every 15 seconds (`-interval`, at most a
  minute) the agent sends all live series of the host over OTLP (gRPC or
  HTTP/protobuf, gzip), in requests of at most `-max-series-per-request`
  (1000) edges and listeners and at most 3 MiB, below the 4 MiB default
  limit of a gRPC receiver. Listeners come first, then server edges, then
  client edges, so that the connector knows the services of the host
  before it names the peers of its clients. The last request carries the
  metrics of the agent and closes the interval; after a failed request the
  rest of the interval is not sent. Every request has its own timeout (two
  thirds of the interval), which starts once the interval is collected.
- **TLS.** An `https://` endpoint verifies the collector (`-otlp-ca-file`)
  and may present a client certificate (`-otlp-cert-file`,
  `-otlp-key-file`) to a receiver that requires one.
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
  edges active since then are still being sent. The start is expressed by
  the current wall clock, so that it stays right after the clock steps
  (e.g. when NTP corrects it after boot): the connector converts it with
  the current clock skew of the agent.

## 5. The shawk connector

### 5.1 Writes to PostgreSQL

For every request (one host), the connector accumulates the changes of
hosts, segments, addresses, processes, edges and listeners. Every
`write_interval` (1 minute, at most a minute) it writes the changes of each
host in one transaction. Edges and listeners are upserted with
`first_seen = least(...)` and `last_seen = greatest(...)`, so replays and
reordering give the same result and several connectors do not conflict. An
edge whose `last_seen` alone advances is written once per interval, and an
idle edge that agents keep sending until its TTL is not written again.

The segment of the request that closes an interval is upserted into
`agent_sessions` with `last_heartbeat` set to the time the connector
received the request: observations up to there are written. The addresses
of the host are written from that request too, one row per period the
host held an address in (a period ends when the address was not seen for
5 minutes), so that an address that moves away and comes back is not held
in between; an agent whose last requests never arrive emits nothing and
does not count as alive. Liveness is thus judged by the clock
of the connector; the difference to the clock of the agent is kept as
`clock_skew`, shown on the fleet dashboard and alerted on beyond a minute.
Edges, listeners and processes keep the times of the agent that observed
them. While the database is down, changes accumulate (in proportion
to the number of edges, not to time) and are written when it returns, and
the connector writes what is pending when it stops. Rows that PostgreSQL
rejects as invalid data are dropped rather than kept for the next write,
which would fail again (IPv6 zones are stripped from addresses before);
the edges and listeners agents still send are then written again.

Changes still pending are lost when the connector crashes, or stops while
the database is down; agents send again only the edges active within their
idle TTL. So a session written by a connector starts no earlier than 2
minutes (the shortest idle TTL of an agent) before the first request it
received from the host, and again after it dropped changes of the host:
the session written before ends at its last heartbeat, and the time in
between shows as not observed.

A connector that does not migrate checks at start that the schema is not
older than it (`shawk.schema_version()`), and waits until it is. Writes and
`shawk.prune()` hold a shared advisory lock that migrations hold
exclusively, so that a migration waits for them and they wait for it.

Rows last seen longer ago than `retention` (3 years by default) are deleted
every hour by `shawk.prune()`, in batches of short transactions; processes
and hosts go once nothing refers to them. Sessions are deleted with them,
so `unobserved()` reports the time before the retention as not observed.

### 5.2 Names of peers

The connector loads `shawk_v1.service_endpoints`,
`shawk_v1.client_endpoints` and `shawk_v1.agent_addrs` every write interval,
and adds what it learns from requests at once. The times of what it loaded
are judged as of the load: while the database cannot be read, agents of
hosts behind other connectors keep the age they had then rather than all
expiring. A socket without a known owner (`~unknown`) names no service;
sockets of the kernel (`~kernel:nfs`, §4.1) do.

| role | peer | `service.peer.name` |
|---|---|---|
| client | a service listens on the peer address and port | the service (`[namespace/]name`) |
| server | a client edge has the same addresses and port | the client service |
| either | unknown, in a range of `peer_cidrs` | the name of the narrowest range |
| either | unknown, private address | `~unresolved` |
| either | unknown, public address | `~external` |

`shawk.peer.agent` tells whether the peer address belongs to a host whose
agent is alive (closed an interval in the last 5 minutes, or the host
itself for loopback) and records the other side of the edge, which for UDP
requires that it traces UDP. An agent that traces one network namespace
reports the addresses of that namespace only, so its peers are traced
(see §10 for the initial namespace). The counting convention of §7 relies
on it. The connector writes `peer_cidrs` to PostgreSQL, so that the
contract names peers without a service the same way.

Loopback peers are looked up on the same host only, and so are addresses
that several live hosts hold at once, such as the gateway of a container
bridge (172.17.0.1 on every Docker host); such a peer is on the host itself
when the host holds the address too. An address counts as held by several
hosts when they reported it within 3 minutes of each other; one whose former
holder stopped reporting it earlier has moved. Among several services on an
endpoint, one on the same host wins, then one observed on a socket (a server
edge or a listener on that address) over one inferred from a listener on an
unspecified address, then the most recently seen, then the first by name.
Names are the best guess at the time of aggregation; PostgreSQL is the
truth of attribution. A new server may show as `~unresolved` until its
listener is written (up to one write interval), and a new client on the
server side until its client edge reaches the connector;
`shawk.peer.agent` is right meanwhile, so counting (§7) is not affected.

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
  seen for the first time counts in full only if it started after the
  latest interval of its host closed at this connector, or, for a host that
  has not closed one here yet, if it started after the connector and
  within the last two minutes; otherwise its first value is a baseline. A
  restart of the connector, or a host routed to another connector, thus
  does not add past totals at once. Open connections are the sum of the
  values the inputs had in the interval that closes.
- An agent may send an interval in several requests. The outputs of a
  host are emitted once per interval, when the last request (the one with
  the metrics of the agent) arrives; an interval whose last request is
  older than one already emitted emits nothing. Every input point keeps its
  timestamp, and a point not newer than the last one of its series (a late
  or retried request) changes nothing. A request more than 2 minutes older
  than the newest of its host means that the clock of the agent went back:
  every input of the host takes its next point as a baseline, and the next
  interval is emitted.
- Outputs, and the metrics of the agents forwarded with them, carry the
  time of the connector, so that one host with a wrong clock does not make
  Prometheus reject a batch with the points of other hosts.
- An error of the pipeline after the connector (Prometheus down) is logged
  and not returned to the agent: the request was taken for PostgreSQL.
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

PostgreSQL 14 or later (multiranges). The schema is bundled with the
connector as migrations (`collector/shawkconnector/migrations`), applied by
`shawk-migrate` or by the connector with `postgres.migrate`; run
`grants.sql` again after a migration that adds tables.

### 6.1 Tables (internal, schema `shawk`)

```
hosts(id, machine_id, hostname, kernel, agent_version, first_seen, last_seen)
agent_sessions(host_id, started_at, last_heartbeat, udp_traced, netns_scope, dropped_flows)
host_addrs(host_id, addr, first_seen, last_seen)  -- one row per period
processes(id, host_id, unit, comm, exe, service_name, first_seen, last_seen)  -- unique (host_id, unit, comm, service_name)
edges(id, host_id, process_id, role, proto, local_addr, remote_addr, port, netns, first_seen, last_seen)
listeners(host_id, process_id, proto, addr, port, netns, first_seen, last_seen)  -- the latest owner
listener_owners(host_id, process_id, proto, addr, port, netns, first_seen, last_seen)  -- every known owner
peer_cidrs(prefix, name)  -- written by the connector from its peer_cidrs
known_dependencies(client_service, server_service, port, proto, first_seen, last_seen)
```

`known_dependencies` keeps every dependency between services ever seen; the
connector brings it up to date every 5 minutes
(`shawk.refresh_known_dependencies()`).

`service_name` has the form of the `job` label (`namespace/name`), so that
names in PostgreSQL and Prometheus match.

### 6.2 Contract (schema `shawk_v1`)

| view or function | |
|---|---|
| `dependencies` | one row per logical dependency: the client edge and the server edge matched by their addresses and port (loopback within a host and netns, addresses held by several hosts at once within a host). `observed_by` is `both`, `client` or `server`; a one-sided row means no agent on the other side, or a NAT or load balancer between. Edges are matched by address over all time: when an address moves to another host, the edges of each host that held it are matched with those of the peer. `client_observed_until` and `server_observed_until` are the latest heartbeats of the hosts: an old `last_seen` with a recent `observed_until` means *no longer used*; both old means *no longer observed*. |
| `graph_nodes`, `graph_edges` | the dependency map between services in the format of the Grafana Node Graph; a peer without a service is named by `peer_class` |
| `peer_class(addr)` | the name of a peer without a known service, as in `service.peer.name`: the narrowest range of `peer_cidrs`, `~unresolved` for an address not routed on the Internet, `~external` otherwise |
| `dependency_changes` | dependencies between services that appeared, or disappeared while a host that saw them kept observing for 15 minutes |
| `service_endpoints` | addresses and ports services accept connections on: the last known listeners of each host (unspecified addresses expanded to the addresses of the host) and its server edges, for hosts that reported in the last 30 days, except addresses another host took over since; used by the connector |
| `client_endpoints` | the client sides of connections in the last hour (client address, server address, port, client service); used by the connector to name the peer of a server edge |
| `agent_addrs` | addresses of hosts whose agent closed an interval in the last 5 minutes; used by the connector |
| `agents` | the latest segment of every host and whether its agent is alive |
| `unobserved(since, until, tolerance)` | the periods in which each host was not observed; Grafana overlays them as annotations |
| `dependencies_between(since, until)`, `graph_edges_between`, `graph_nodes_between`, `dependency_changes_between` | the same for the dependencies active in a period. They take the edges active in the period with a margin of 15 minutes before matching them, so a recent window does not scan the history (about 0.3 s instead of 3 s with a million edges) and both sides of a connection are matched at the edges of the period; the dashboards and alerts use them. A dependency appeared in a period when it was first seen in it and is not in `known_dependencies` from before it: one that comes back on new edges (a new container, an hourly job) did not appear |

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
`value`. Grafana turns the rows into one series per label set and requires
them sorted by time; every row carries the same time, `now()`, so that each
series has a value at the last time. A query that finds nothing returns no
rows, which is No Data, so the rules treat No Data as Normal. New and
disappeared dependencies are judged per service and port
(`dependency_changes_between`), so a dependency seen before is not new, and
peers without a service are named like in Prometheus rather than by
address. The window of new dependencies ends 5 minutes ago, when both
sides of a new connection are written. A disappeared dependency is an explicit
row — its `last_seen` falls in a window while a host that saw it is still
observed — rather than a row that vanishes from the result, so a stopped
agent does not look like a removed dependency. Agents that stopped are
alerted by Prometheus (`ShawkAgentDown`) for 24 hours, and by PostgreSQL
(`shawk_v1.agents`) from then on for 30 days, labelled with the host id; a
host reinstalled under the same name and alive is not alerted.

The panels of OBI use a minimal interval of a minute: OBI exports every 60
seconds by default, and a rate over a shorter range would hold one sample.

## 9. OBI

OBI (OpenTelemetry eBPF Instrumentation) cannot replace the tracer of
shawk: its network flows and TCP statistics do not tell which process
communicates, and its application layer covers only the protocols it
parses. shawk runs beside it instead:

- OBI instruments the application layer (`application` and
  `application_service_graph` features) of selected services and sends to
  the `otlp` receiver of the same collector, with a client certificate
  (`OTEL_EXPORTER_OTLP_CERTIFICATE`, `OTEL_EXPORTER_OTLP_CLIENT_CERTIFICATE`,
  `OTEL_EXPORTER_OTLP_CLIENT_KEY`); its network and statistics features
  stay disabled, since shawk observes the same per process. Its metrics
  are not batched in the collector: they carry the clock of their host.
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
- **Addresses of container networks** are told apart only when several
  hosts with agents hold them at once. A container address held by one
  host with an agent may be attributed to that host for a peer on a host
  without an agent.
- **Same port shared by different services** with `SO_REUSEPORT` cannot be
  told apart (§5.3 of the paper); this is rare.
- **UDP peer-to-peer protocols** where both sides send first are recorded
  as clients of each other's port. A UDP client socket that existed before
  the agent started and receives before it sends again is recorded as a
  server.
- **MPTCP**: additional subflows opened by the server side (with a path
  manager that does so, which the default does not) are recorded as
  outgoing connections from the server. Data that MPTCP sends again on
  another subflow is counted on both. On a host with more open MPTCP
  connections than the owner map holds, the subflows that the path
  manager adds to evicted connections make the agent walk the processes
  at every interval.
- **Sockets of the kernel** are named after their port (§4.1), so a
  subsystem on a port of another is named after it, and one on a port of
  none is `~kernel`; NFSv3 also talks to `lockd` and `mountd` on
  ports that rpcbind assigns. A socket created by a process and then
  held by the kernel alone (an `nbd` or iSCSI connection whose process
  exited) is not the kernel's: an outgoing one adopted at startup is not
  attributed, and a new one belongs to the process that connected it. A
  listener that a process in another PID namespace than the agent's holds
  and that has `sk_user_data` (e.g. in a BPF sockmap) is taken for the
  kernel's; run the agent in the host PID namespace.
- **Flow table capacity**: when more distinct flows than `-max-flows` occur
  in one interval, updates are dropped and `shawk.agent.flows.dropped`
  counts them. The tables of listening TCP and UDP ports hold `-max-flows`
  ports, at least 8192 and at most 65536; the agent warns when they
  overflow, since connections that predate the agent and UDP sockets on the
  ports left out may then be given the wrong direction. It also warns when
  the kernel could not allocate socket storage for a TCP connection, which
  is then counted from the next walk on.
- **Connections that predate the agent** are counted from the adoption on.
  One accepted by a listener created with a backlog of 0 whose listener is
  gone is recorded as outgoing.
- **Clocks**: first and last seen times of dependencies come from the clock
  of each host, and the start of a segment too; heartbeats from the clock
  of the connector, compared with the clock of PostgreSQL. Keep clocks
  synchronized (chrony); `clock_skew` shows hosts that are not.
- **The initial network namespace only** (`-netns self` on a host): the
  connections of containers in other namespaces are not traced, and those
  that leave with the addresses of the host look traced to their peers,
  whose server side is then not counted. The agent warns; use `-netns all`
  on hosts with containers.
