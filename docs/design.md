# Design of shawk

shawk keeps the record of network dependencies of a fleet: which process
talks to which network service on every host, since when, until when, and
how much. It answers the questions asked before changing a system: who
still uses this database, what appeared after the deployment, did anything
use this host in the last 90 days, and were we watching? The answers are in
Grafana, from PostgreSQL and Prometheus.

It is built on the socket-based tracing method with in-kernel flow bundling
proposed in

> Yuuki Tsubouchi, Masahiro Furukawa, Ryosuke Matsumoto. *Low Overhead TCP/UDP
> Socket-based Tracing for Discovering Network Services Dependencies.* Journal of
> Information Processing, Vol. 30, pp. 260–268, 2022.

## 1. Why

The paper is motivated by changes whose impact administrators cannot
predict: platform migrations where old and new systems coexist, and clients
such as batch jobs that talk to a server once a day or a week, which
sampling-based tracing misses. Answering those needs:

- completeness: every process and every TCP/UDP service, including
  middleware and third-party software that cannot be instrumented;
- always-on tracing with low overhead, so that rare dependencies are
  observed;
- long retention with known coverage, so that "nobody used it in the last
  90 days" is backed by data, and "not observed" (or observed with dropped
  flows) is not mistaken for "not used".

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

- The agent traces flows with eBPF, resolves the process and service of
  each flow, and sends every 15 seconds all live series of its host as
  cumulative OTLP metrics (§4). It keeps no database and opens no port.
- The shawk connector is an OpenTelemetry Collector component (§5). It
  writes the relations of every host to PostgreSQL, names the peer of every
  edge, and forwards aggregated metrics without addresses to Prometheus.
  Only the connector holds database credentials.
- PostgreSQL is the truth of whether a dependency exists (§6), Prometheus
  of how much flows (§5.3, §7). They are joined by names (`service.name`,
  `service.peer.name`, `server.port`, `network.transport`, `host.id`),
  never by a cross-database join.
- Grafana is the user interface; dashboards and alerts are in `packaging/`
  (§8).

shawk promises two contracts: the views and functions of the PostgreSQL
schema `shawk_v1`, and the names and labels of its metrics in Prometheus.
The OTLP between agent and connector and the configuration of the connector
are internal; agent and connector are released together.

## 3. Tracing

### 3.1 What is recorded

A bundled flow is identified by

| field | meaning |
|---|---|
| direction | `out`: the local process opened the connection (client). `in`: it accepted it (server). |
| local / remote address | IPv4 is stored as IPv4-mapped IPv6 in the kernel |
| port | the service port: the remote port of an outgoing flow, the local port of an incoming flow |
| protocol | TCP or UDP |
| network namespace | inode number |
| cgroup id, comm | the identity of the local process |

The client's ephemeral port is dropped, so all connections between the same
pair of addresses to the same service collapse into one entry, and the
records transferred to user space grow with the number of dependencies, not
of connections or messages (the key idea of the paper). Unlike the original
implementation, the process identity is part of the key; the paper notes
that without it, different clients on one host cannot be distinguished
(§5.3 of the paper). A key can also bundle all the peers outside the
internal ranges of the host, with a zero remote address (§3.6).

Per flow and interval the kernel accumulates established connections,
failed connection attempts, connections open at the end of the interval,
bytes sent/received, UDP datagrams, retransmissions and smoothed RTT
samples. These cover the edge weights of §2.4 of the paper, except TCP
messages, which would need a hook on the data path (§3.2); failures and
retransmissions stand for errors, and open connections are added. For TCP
active opens it also accumulates the handshake duration from `connect(2)`
to the SYN-ACK in fixed buckets, the SYNs retransmitted, and the failures
by reason (§3.2): the measurement of Pingmesh, taken passively on the
connections hosts open anyway. Aggregating it by network location is
proposed in [proposals/path-quality-zones.md](proposals/path-quality-zones.md).

### 3.2 TCP: tracepoints and socket iterators only

| hook | role |
|---|---|
| `tp_btf/inet_sock_set_state` CLOSE→SYN_SENT | active open, inside `connect(2)`, so the current task is the client; key and owner go to socket local storage |
| SYN_SENT→ESTABLISHED / →CLOSE | an established or failed outgoing connection, with its handshake, retransmitted SYNs and failure reason |
| SYN_RECV→* | passive open: an incoming connection |
| *→CLOSE | the remaining bytes |
| `iter/tcp` (every interval) | byte deltas of long-lived connections, RTT, open connections, listening sockets, adoption of connections that predate the agent |
| `iter/task_file` | owners of adopted connections, MPTCP connections and listeners; stands in for `iter/tcp` where its walk skips connections (below) |

Compared with the original kprobes (`tcp_v4_connect`, `inet_csk_accept`,
`tcp_sendmsg`, `tcp_cleanup_rbuf`), this costs nothing per message: in the
paper the streaming method was cheapest for persistent connections and
bundling paid on every message, while shawk pays per state change, about
0.11 to 0.16 µs each and 1.1 to 1.6 µs per connection on Rocky Linux 9.8
and Linux 6.8 on arm64. Bundling every message costs 0.11 µs per message
there with fentry and 0.3 µs with kprobes, 11 % and 27 % of a saturated
loopback request-response, and would only add message counts
([research/kernel-hooks](research/kernel-hooks/kernel_hooks.md)). A
tracepoint assumes no kernel function signature (`inet_csk_accept` changed
in 6.10, and RHEL 9.8 has the change on 5.14), needs no BPF trampolines,
and has socket local storage, which kprobes have not. A hook on accept
would name the accepting task, but every rule of the owners below would
stay (for `Accept=yes`, connections never accepted or adopted, listeners of
the kernel). What the tracepoint does not see is left to the walks: the
traffic and RTT of a connection between its state changes, and the
connections that predate the agent (connection pools, gRPC channels).
IPv6 and MPTCP are handled.

Bytes are read from the cumulative counters of `struct tcp_sock`
(`bytes_acked`, `bytes_received`, `total_retrans`) at close and at every
walk, and the difference to the last accounted value is added to the flow
(SYN and FIN are subtracted; see shawk.bpf.c). A socket iterator walks only
the network namespace of the thread that opens it, so the agent opens the
iterators in every namespace of the host (`/proc/*/ns/net`, `/run/netns`).
Where the TCP iterator does not lock each socket (before 5.19; RHEL 9 has
the backport), a connection closing during a walk may rarely be counted
twice.

**Connections the TCP iterator skips.** Before Linux 6.17 (the fix reached
the 6.1, 6.6 and 6.12 stable releases, not 5.15, RHEL 9 or 10), the TCP
iterator can skip the established sockets of a hash bucket on every walk,
for as long as the listeners of the namespace stay (see
`tcp_seek_last_pos()` in shawk.bpf.c). A skipped connection that predates
the agent would never be adopted, and the others would not be counted as
open nor have their traffic and RTT accounted before they close. Every walk therefore has a generation that the
connections it accounts record; `iter/task_file` adopts held connections
without state and accounts ready ones the latest walk missed. Once an owner
scan finds such connections, the agent scans processes every interval until
a scan finds none, and warns.

**Handshakes and failures of active opens.** The duration runs from
CLOSE→SYN_SENT (before the local port is chosen) to SYN_SENT→ESTABLISHED,
in whole microseconds, into the first bucket whose inclusive upper bound it
reaches: 100 µs, 250 µs, 500 µs, 1 ms (within a rack or data center),
2.5 ms, 10 ms, 50 ms, 250 ms (between data centers and regions), 1 s, 3 s,
and one without bound. The upper buckets separate handshakes that waited
for a retransmission timeout. The number of retransmitted SYNs comes from
`total_retrans` at the end of SYN_SENT, not from the buckets, because SYN
schedules differ between kernels (5.14 and RHEL 9 send at 0, 1, 3, 7 s;
`net.ipv4.tcp_syn_linear_timeouts` starts with one a second). Sockets in
`TCP_REPAIR` or with `TCP_FASTOPEN_CONNECT` (which may defer the SYN to the
first write) have no duration; simultaneous opens, adopted connections,
additional MPTCP subflows and the agent's own connections have no
handshake. The failure reason, `error.type`, is decided at SYN_SENT→CLOSE
(`fail_reason()` in shawk.bpf.c). A task that reads the error (`SO_ERROR`)
while the kernel closes the socket takes it first, on every kernel, and the
failure then counts as `timeout` (§10):

| reason | meaning |
|---|---|
| `refused` | a reset (no listener), or ICMP port unreachable, which iptables and nft send to reject by default |
| `timeout` | no answer to any SYN |
| `unreachable` | ICMP host/network unreachable or administratively prohibited, or no answer to ARP/ND |
| `local` | no SYN was built, e.g. no free local port |
| `aborted` | the application closed the socket first, usually after its own connect timeout |
| `_OTHER` | any other error (`ECONNABORTED` from `ss -K`, a failed simultaneous open) |

The cost is two `bpf_ktime_get_ns()` calls and a few comparisons per
connection, on a flow looked up anyway. Limits of the measurement are in
§10.

**Adopted connections and owners.** A connection that predates the agent
is incoming when its local port is listening, or when it keeps the nonzero
`sk_max_ack_backlog` of the listener it was cloned from (the listener may
be gone, or TPROXY accepted it on another port); ports alone cannot tell.
Its traffic before the adoption is not counted. The owner of an incoming
connection is a holder of its listener, matched by the cgroup the passive
open records, so that `SO_REUSEPORT` programs are told apart; a
socket-activated service is preferred to systemd, and a parent to its
workers (`internal/tracer/owner.go`). A listener that appears or disappears
requests an owner scan, so a restarted service is attributed at once.

**Sockets of the kernel.** The clients of NFS, iSCSI, CIFS and Ceph,
nfsd and DRBD hold sockets without a process. They matter before a server
is decommissioned (a mounted NFS export), but connect from a kernel worker
or whichever process triggered them, so comm and cgroup change between
reconnections. A connecting socket is the kernel's when `sk_kern_sock` is
set and it is not an orphan (MPTCP subflows and SMC's TCP socket excepted);
it gets comm `~kernel` and cgroup id 0. A listener is the kernel's when no
process held it at the last scan and the kernel may hold it; incoming
connections are attributed through their listener, since children inherit
`sk_kern_sock`. The exact tests are in shawk.bpf.c and
`internal/tracer/owner.go`; naming is in §4.1.

**MPTCP.** Go listens with MPTCP by default since 1.24. The TCP hooks see
the subflows of the MPTCP socket the application holds. Subflows opened
outside `connect(2)` (MP_JOIN, by the path manager) and adopted ones get the
owner of their MPTCP socket from an LRU map. A connection counts once, by
its first subflow; the others add traffic, RTT and retransmissions to the
flow of their own addresses. Go's dialer retries with TCP after an
MPTCP error, so a failed dial counts two attempts. RHEL 9 disables MPTCP by
default (`net.mptcp.enabled=0`).

### 3.3 UDP

UDP has no connection, so datagrams are bundled per message as in the paper,
by fentry programs on `ip_send_skb`, `ip6_send_skb` and `skb_consume_udp`,
which run in process context; GSO and GRO count every datagram they carry.
Ports cannot tell clients from servers (resolvers bind random ports in
1024-65535, servers listen in the ephemeral range), so the direction is
decided per socket by its first datagram:

* a socket that receives first is a server, one that sends first a client;
* a socket that sends first on the port of a known server socket (e.g. the
  per-client connected sockets of a QUIC server) is a server;
* bound, unconnected sockets that exist when the agent starts are servers,
  since their first datagram afterwards may be a reply;
* a connected socket on a port the kernel chose is a client even if it
  receives first: no client could have known its port.

fentry rather than kprobes: on arm64 a kprobe doubles the cost per datagram
(0.29 rather than 0.15 µs), and only tracing programs have socket local
storage for the direction. cgroup_skb costs less (0.06 µs) but runs outside
the task, so the process of a flow would not be known, and it runs on every
TCP packet too
([research/kernel-hooks](research/kernel-hooks/kernel_hooks.md)). UDP thus
needs BPF trampolines, which arm64 has since Linux 6.0 and RHEL 9 since
kernel 5.14.0-621 (Rocky Linux 9.8, not 9.6); without them the agent
traces TCP and reports that UDP is not traced. Misattributions are listed
in §10.

### 3.4 Reading flows without losing updates

Bundled flows are written into one of two hash maps selected through an
`ARRAY_OF_MAPS`. At every interval user space walks the sockets (so that the
traffic of long-lived connections lands in the closing interval), flips the
active index, and drains the inactive map after an RCU grace period, so no
program writes to the map being read (`internal/tracer/collect.go`).

### 3.5 Kernel requirements and features used

The target is Rocky Linux 9 (5.14 with RHEL's backports) and upstream
Linux 5.14 or later with BTF (`CONFIG_DEBUG_INFO_BTF`):

| feature | since |
|---|---|
| BTF-enabled tracepoints (`tp_btf`) | 5.5 |
| ring buffer (cgroup events) | 5.8 |
| BPF iterators `tcp`, `udp`, `task_file` | 5.8 / 5.9 |
| socket local storage in tracing programs | 5.11 |
| LPM trie (internal ranges, §3.6) | 4.11 |
| `bpf_sock_from_file`, `bpf_get_current_task_btf` | 5.11 |
| cgroup pointer in `sock_cgroup_data` (else the owner of accepted connections is resolved in user space only) | 5.15, RHEL 9 |
| TCP iterator that locks each socket (else rare double counting) | 5.19, RHEL 9 |
| fentry (UDP only) | 5.5 on x86_64, 6.0 on arm64 (RHEL 9 on arm64: 5.14.0-621, in 9.8, not in 9.6) |
| kprobes on the module nf_conntrack (translations, §3.7; `CONFIG_KPROBES`, the system call `perf_event_open`) | `__nf_conntrack_confirm`, and `nf_ct_destroy` since 5.19 and in RHEL 9, `destroy_conntrack` before |

CI loads the programs on the Ubuntu runner kernels (6.8 to 7.0, x86_64 and
arm64) and in VMs (`make vm-test`) on Rocky Linux 9.6 (x86_64, aarch64),
upstream 5.14 (x86_64) and 5.15 (x86_64, aarch64); on aarch64 before 6.0
the tests check that UDP is reported as not traced. All struct accesses use CO-RE. `make compat`
checks every attach target, helper, CO-RE relocation and `BPF_PROG`
parameter list against the BTF of Rocky Linux 9.6 and its nf_conntrack
module (the verifier does not check arguments read through
`BPF_CORE_READ`); `TestProgramPrototypes` does the same on the running
kernel. Fields that moved are read through flavors. `vmlinux.h` is
regenerated with `make vmlinux`, which records the source kernel.

### 3.6 Folding external peers

The remote address is part of the key, so on an internet-facing host (a
load balancer, a web server, a public DNS or QUIC server) every client
address would be a flow of its own: in the flow table, which drops what
does not fit (§10), in the series of the agent, sent every interval for the
idle TTL (§4.3), and in the edges of PostgreSQL, kept for the retention
(§6). No name needs them: a peer without a service is named after its
address range (§5.2), so every client on the Internet is `~external`
anyway. The kernel therefore folds the peers outside the internal ranges of
the host into one flow per local endpoint:

- `-internal-peers` lists the ranges whose peers stay exact. The default,
  `private`, is the ranges not routed on the Internet (RFC 1918, CGNAT,
  loopback, link-local, IPv6 ULA), which `peer_class()` names
  `~unresolved`. The host's own interface addresses are always kept, so a
  host connecting to its own public address keeps both sides. A fleet that
  uses public addresses internally adds them, e.g.
  `-internal-peers=private,203.0.113.0/24`. An IPv6 range overlapping
  `::ffff:0:0/96` (such as `::/0`) is refused, since IPv4 peers are looked
  up as such addresses.
- `-fold-external` chooses which flows fold: `in` (default), the clients of
  local servers; `all` also outgoing flows, for hosts that contact many
  external servers (crawlers, mail relays, forward proxies, recursive
  resolvers); `none` keeps every address. Outgoing flows keep their server
  address by default because it tells which external service a host uses.
- A key is folded when it is built, at the cost of one LPM trie lookup per
  connection or UDP server datagram. Its remote address becomes 0.0.0.0
  (IPv4-mapped) or ::, and `KEY_FOLDED` keeps it from merging with an exact
  key. It is sent with `shawk.peer.folded=true` (§4.2), and PostgreSQL
  stores the peer as the network 0.0.0.0/0 or ::/0, which `peer_class()`
  names `~external`. Service names and dependencies are the same as without
  folding, provided the ranges of `peer_cidrs` are in `-internal-peers` too.
  `shawk flows` does not fold.

The flow table then holds about one flow per internal peer and local
service, plus one per local endpoint for all external peers. What folding
loses is in §10; the connector warns about agents that fold peers of the
fleet or of `peer_cidrs` (§5.2).

### 3.7 Translations of addresses learned from conntrack

A host that translates addresses (DNAT of Docker published ports and
kube-proxy, REDIRECT, IPVS with `net.ipv4.vs.conntrack=1`, SNAT,
masquerade) learns its translations from conntrack, so that the connector
can match the two sides of the connections (§5.4). Two kprobes on the
module nf_conntrack, in a collection of their own, are loaded once the
module is (checked every minute; a failed load is retried with backoff up
to an hour). Kprobes need no trampolines and run once per connection, not
per packet.

- `__nf_conntrack_confirm` runs once per new entry, after DNAT, SNAT and
  IPVS have rewritten it. An entry whose reply tuple does not mirror its
  original is a translation: client C connected to virtual V:Pv, and backend
  B:Pb saw it from source S (C unless the host replaced it). Tuples are
  compared rather than the NAT status bits, which IPVS does not set.
  Ephemeral ports are dropped as in flows, so a change of the source port
  alone translates nothing.
- `nf_ct_destroy` (`destroy_conntrack` before 5.19) runs when an entry
  goes, so `xlats` counts live entries and a translation is in use in every
  interval in which one of its connections is open, as edges are. An entry
  outlives its connection by its conntrack timeout (up to 2 minutes), within
  the margin of matching (§5.4); an established entry whose peer vanished
  stays 5 days, but the rows it matches are still bounded by the edges. A
  missed destroy (a kprobe is skipped while another BPF program runs on the
  CPU) keeps a translation live until conntrack reuses the entry's memory.
- With folding (§3.6), a translation whose source, client or backend is
  outside the internal ranges is not learned, nor, with `all`, one whose
  virtual address is: no edge would match it, and the Internet clients of a
  published port stay out of the table. `-netns` restricts translations to
  one namespace.
- Translations idle for an interval are deleted. `xlats` holds
  `-max-flows` translations and `xlat_conns` four times as many live entries
  (about 9 MiB at the default), allocated only once nf_conntrack is loaded
  (most RHEL 9 hosts, whose firewalld loads it, and hosts with Docker or
  kube-proxy). Overflow is counted in `shawk.agent.translations.dropped`; a
  host with more live translated entries (`nf_conntrack_count`) needs a
  larger `-max-flows`, or a translation used only by long-lived connections
  that did not fit may end early.
- The kprobes are not reattached when the module is reloaded; restart the
  agent then. A load failure is logged, e.g. a unit whose
  `SystemCallFilter` denies `perf_event_open`.

## 4. The agent

### 4.1 Identity of processes and services

- `shawk.unit` is derived from the cgroup path (`nginx.service`,
  `docker-0123456789ab`, `user-1000.slice/session.scope`), normalized so
  that names that change on every run (login sessions, transient units)
  accumulate under one name. The cgroup of a short job is often gone before
  the interval ends, so `tp_btf/cgroup_mkdir` reports every new cgroup
  through a ring buffer and the agent keeps paths for an hour. Events
  dropped when it is full are counted in `shawk.agent.cgroup_events.dropped`
  (alert `ShawkCgroupEventsDropped`), and such a cgroup is named by its id.
- A container is named after what survives its recreation:
  `k8s/<namespace>/<workload>/<container>` for Kubernetes,
  `docker/<project>/<service>` for Docker Compose, otherwise
  `docker/<name>`, `podman/<name>` or `containerd/<name>` (nerdctl); its id
  is `container.id`. The id comes from the cgroup path and the names from
  the state the runtime keeps on disk (`internal/procinfo`), because the
  runtime APIs are on Unix sockets the agent's unit does not allow. The
  state is read when the cgroup is created, so a container removed within
  an interval keeps its name; reads that do not fit the queue are counted in
  `shawk.agent.container_reads.dropped` (alert `ShawkContainerReadsDropped`)
  and retried at export.
- Container names are not trusted blindly. Docker merges image labels into
  container labels, so pod labels are believed only with the container name
  cri-dockerd gives, and Compose labels only with the name Compose gives.
  Only the outermost container of a cgroup, made by a runtime of the host,
  is named from its state: a user with delegated cgroups could otherwise
  create a cgroup named after any container. Host runtimes never create
  cgroups inside a unit, so a container in a unit is named by id after the
  unit (`user@1000.service/podman-0123456789ab`). Name parts are limited to
  `[A-Za-z0-9_.-]` and 253 characters, so they cannot add a level to the
  unit or the `job`.
- A container whose state cannot be read is named
  `<runtime>-<12 hex digits>`, which changes when it is recreated: rootless
  containers, runtimes with another state directory (`data-root` on the
  `dockerd` command line, k3s, rke2, microk8s), `ctr run`. A container in a
  container (Docker in Docker, kind) is named after the outer one.
- The workload of a pod is its name without the suffixes Kubernetes appends
  (`web-5d8f7c9b6-x7z2k` → `web`, `db-0` → `db`); a long workload name may
  lose its end where the API server cut the generated name.
- `service.name` follows the order of OBI: `OTEL_SERVICE_NAME`, then
  `service.name` in `OTEL_RESOURCE_ATTRIBUTES` (only `OTEL_` variables of
  `/proc/PID/environ` are kept), then the service of the pod, then the
  executable's base name, then comm, then the unit, then `~unknown` (owner
  not known). `-service-name-fallback=unit` uses the unit instead of the
  executable. `service.namespace` comes from `OTEL_RESOURCE_ATTRIBUTES`,
  else the namespace of the pod's service. Both are cut to 255 bytes, since
  any process sets them and they repeat in every data point.
- The service of a pod is named as OBI names it from API server metadata
  (annotations, `app.kubernetes.io/*` labels, then the top owner; see
  `internal/procinfo/container.go`). The agent does not ask the API server:
  it reads labels and annotations from the pod sandbox on disk, believed
  only if the sandbox names the same pod. CRI-O and cri-dockerd keep both;
  containerd keeps labels only in its bolt store, and on the bundle only the
  annotations that `pod_annotations` of the runtime handler lets through
  (set it to `["resource.opentelemetry.io/*", "kubernetes.io/config.source"]`).
  The `job` of a pod therefore differs from OBI's when the runtime does not
  keep what names it, when the owner guessed from the pod name is wrong, or
  when an annotation has characters replaced with `_`; a pod that sets
  `OTEL_SERVICE_NAME` has the same `job` in both.
- Services that share an executable (`ruby`, `python`, `java`, `php-fpm`)
  share a name unless they set `OTEL_SERVICE_NAME` (e.g. `Environment=` in a
  systemd drop-in), as with OBI; PostgreSQL still tells them apart by unit.
  Processes that share a cgroup and comm are not told apart even with
  different `OTEL_SERVICE_NAME`, since the kernel bundles by cgroup and comm
  and a flow is named after the last process seen on it; put them in
  different units.
- Sockets of the kernel (§3.2) are named after their service port, the one
  thing stable across reconnections: `~kernel:nfs` (2049),
  `~kernel:rpcbind` (111), `~kernel:smb` (139, 445), `~kernel:iscsi`
  (3260), `~kernel:ceph` (3300, 6789, 6800-7300), `~kernel:nvme-tcp` (4420,
  8009), `~kernel:drbd` (7788-7799), `~kernel:ocfs2` (7777), `~kernel:rds`
  (16385), `~kernel:dlm` (21064), and `~kernel` otherwise. Kernel servers
  are named apart so that a dependency has two ends: `~kernel:nfsd` (2049),
  `~kernel:ksmbd` (445), `~kernel:iscsi-target` (3260, LIO),
  `~kernel:nvmet-tcp` (4420, 8009). Names start with `~`, which
  `peer_cidrs` names cannot, and have no `/`, which would read as a
  namespace in the `job`. The socket's callbacks would tell more, but
  mapping them to names needs `/proc/kallsyms` with `CAP_SYSLOG`, which the
  agent's unit does not grant.
- Reading `/proc/PID/environ` takes the process's memory map lock, which a
  stuck process can hold forever (a stalled FUSE mapping), so reads time out
  and back off, and hung reads are bounded (`internal/procinfo/service.go`). A PID whose comm no longer
  matches the flow is not trusted; a process that exits before it is read
  takes the latest identity seen for the same unit and comm.
- The host is identified by `host.id` (`/etc/machine-id`, else
  `/var/lib/dbus/machine-id`) and `host.name`. PostgreSQL keys a host by
  the hash of both, so VMs cloned with the same machine id stay apart.

### 4.2 What is sent

Every edge (a bundled flow with its process identity) is a series with the
attributes `service.name`, `service.namespace`, `process.executable.name`,
`process.executable.path`, `process.command`, `shawk.unit`, `container.id`,
`shawk.role` (`client` or `server`), `network.transport`,
`network.local.address`, `network.peer.address`, `server.port` (the service
port, whatever the role), `shawk.netns`, and `shawk.peer.folded=true` for a
folded edge (§3.6). The PID is not an attribute, so a restarted process
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
| `shawk.tcp.handshake` | Histogram, `s` | handshakes of established active opens, with the bounds of §3.2 (TCP client side only) |
| `shawk.tcp.syn_retransmits` | Counter, `{segment}` | SYNs the active opens retransmitted, established or failed (TCP client side only) |
| `shawk.connection.failed.by_reason` | Counter, `{connection}` | failed attempts with `error.type` (`refused`, `timeout`, `unreachable`, `local`, `aborted`, `_OTHER`; TCP client side only) |
| `shawk.edge.first_seen`, `shawk.edge.last_seen` | Gauge, `s` | Unix time of the first and last activity |

A failure reason is sent from its first occurrence on an edge, starting at
that interval, so an edge does not carry six series of zeros and the
connector takes the first value as new rather than as a baseline.

Listeners are sent as `shawk.listener.first_seen`/`last_seen`, and
translations (§3.7) as `shawk.translation.first_seen`/`last_seen` with the
client, virtual, source and backend addresses and ports. The agent's own
metrics are `shawk.agent.up` (with `shawk.netns.scope`),
`shawk.agent.segment.start`, `shawk.agent.udp.traced`, the drop counters
`shawk.agent.flows.dropped`, `shawk.agent.cgroup_events.dropped`,
`shawk.agent.container_reads.dropped` and
`shawk.agent.translations.dropped`, `shawk.agent.translations.traced`,
`shawk.agent.export.failures`, and with `-bpf-stats` per-program run counts
and times. The resource carries `host.id`, `host.name`, `os.version`,
`service.name=shawk-agent` with `service.version`, `shawk.peer.fold`,
`shawk.peer.internal`, and `host.ip`: the interface addresses of the traced
namespaces plus the local addresses of recent series and open listeners,
which include containers.

### 4.3 How it is sent

- Every 15 seconds (`-interval`) the agent sends all live series of the
  host over OTLP in requests of at most 1000 series and 3 MiB, below the
  4 MiB default of a gRPC receiver; a series too large for a request alone
  is logged and left out, since a refused request would stop the interval. Listeners
  come first, then translations, server edges and client edges, so the
  connector knows the services and translations of the host before naming
  the peers of its clients; the example pipeline has no batch processor, to
  keep this order. The last request carries the agent's metrics and closes
  the interval; after a failed request the rest is not sent. Translations of
  other hosts may arrive later, so a client edge may lack its translation
  for an interval.
- Counters are cumulative, so a failed request is made up for by the next
  one, and requests are not retried.
- A series idle (no connections, bytes, datagrams or open connections) for
  `-idle-ttl` (15 minutes) is dropped and restarts from zero if it
  reappears. This bounds the series of a host by its recent dependencies.
- Observation segments. `shawk.agent.segment.start` is the time from which
  every dependency active on the host has reached the connector: the start
  of the agent, or, after requests failed for longer than the idle TTL minus
  a minute (edges that ended meanwhile may have been dropped unsent), now
  minus the idle TTL. It is expressed by the current wall clock and
  converted with the agent's current clock skew, so it stays right after the
  clock steps.
- TLS. An `https://` endpoint verifies the collector and may present a
  client certificate. Over `http://` the host's dependencies, executables,
  name and machine id travel in the clear, and the agent warns unless the
  endpoint is loopback. The agent does not follow HTTP redirects, so nothing
  in the path can divert the export elsewhere or to `http://`.
- Host identity. With `host_identity: certificate` the connector accepts a
  host's metrics only from an agent whose verified certificate names its
  `host.name` (a DNS name, else the common name; no wildcards), so one
  certificate cannot write as another host; the receiver passes
  certificates over gRPC only, so HTTP requests are then refused. With
  `none`, the default, the connector believes every request. OBI's receiver
  trusts another CA than the agents' (`packaging/collector/config.yaml`), so
  OBI's certificates cannot send as an agent.

## 5. The shawk connector

### 5.1 Writes to PostgreSQL

The connector accumulates changes from requests and every `write_interval`
(1 minute, at most a minute) writes the changes of each host in one
transaction. Edges and listeners are upserted with `first_seen = least(...)`
and `last_seen = greatest(...)`, so replays and reordering give the same
result and several connectors do not conflict. An edge whose `last_seen`
alone advances is written once per write interval, and an idle edge that
agents keep sending until its TTL is not written again.

The request that closes an interval upserts the segment into
`agent_sessions`, with `last_heartbeat` the time the connector received it,
and the host's addresses, one row per period held (a period ends after 5
minutes unseen). Liveness is thus judged by the connector's clock; the
difference to the agent's is kept as `clock_skew`, shown and alerted on
beyond a minute. Edges, listeners, translations and processes keep the
agent's times, capped at 2 minutes ahead of the connector, so a clock far
ahead or an agent making times up cannot pin `last_seen` (`greatest()`),
win the choice of most recently seen endpoint (§5.2) or escape the
retention.

While the database is down, changes accumulate in proportion to the number
of edges, not to time, up to `max_pending_rows` (§5.5). Rows PostgreSQL
rejects as invalid are dropped rather than retried forever; edges and
listeners agents still send are written again. Changes still pending are
lost when the connector crashes, or stops while the database is down, and
agents resend only edges within their idle TTL, so a session starts no
earlier than 2 minutes (the shortest idle TTL) before the first request the
connector received from the host, and again after it dropped changes of the
host; the gap since the previous heartbeat shows as not observed.

The session also keeps `peer_fold`, `peer_internal` and `counters_started`
(the start of the agent's drop counter, by its clock), which identifies one
run of the agent across the sessions that several connectors, a connector
restart or a clock step create. When the drops of a run exceed the most
PostgreSQL holds for it, the period since the run's latest heartbeat is
recorded in `partial_observations`: the host was observed, but dependencies
active then may be missing. The writes of a host serialize on its row, so
each compares with the one before.

A connector that does not migrate waits at start until the schema is at
least its version (`shawk.schema_version()`), warns if it is newer, checks
the migration history as `shawk-migrate` does, and refuses a schema from
before the migrations were consolidated (§6). Writes and `shawk.prune()`
take a shared advisory lock that migrations take exclusively.

Rows last seen longer ago than `retention` (3 years) are deleted hourly by
`shawk.prune()` in short batches, with sessions and partly observed
periods, so `unobserved()` reports the time before the retention as not
observed.

### 5.2 Names of peers

The connector loads `shawk_v1.service_endpoints`,
`shawk_v1.client_endpoints` and `shawk_v1.agent_addrs` every write interval
and adds what it learns from requests at once. Loaded times are judged as
of the load, so hosts behind other connectors do not all expire while the
database cannot be read. A socket without a known owner (`~unknown`) names
no service; kernel sockets (§4.1) do.

| role | peer | `service.peer.name` |
|---|---|---|
| client | a service listens on the peer address and port | the service (`[namespace/]name`) |
| server | a client edge has the same addresses and port | the client service |
| client | a virtual address of a translation, without a service of its own | the service at a backend, with its port (§5.4) |
| server | a backend of a translation without sources, and a client edge to its virtual address from the peer | the client service (§5.4) |
| either | unknown, in a range of `peer_cidrs` | the name of the narrowest range |
| either | unknown, private address | `~unresolved` |
| either | unknown, public address | `~external` |
| either | folded (`0.0.0.0/0`, `::/0`) | a range of `peer_cidrs` that holds the whole network, `~external` otherwise |

`shawk.peer.agent` tells whether the peer address belongs to a host whose
agent is alive (closed an interval in the last 5 minutes, or the host itself
for loopback) and so records the other side (for UDP, only if it traces
UDP); a folded peer has none. The counting of §7 relies on it. The
connector writes `peer_cidrs` to PostgreSQL, so that the contract names
peers without a service the same way.

Loopback peers are looked up on the same host only, and so are addresses
that several live hosts reported within 3 minutes of each other, such as
the gateway of a container bridge (172.17.0.1 on every Docker host). Among
several services on an endpoint, one on the same host wins, then one
observed on a socket, then the most recently seen (`peers.go`). An address
that one live host holds alone is that host's: what other hosts report at
it, also at the backends of translations (§5.4), is a socket they no longer
have or one made up (§10), and is ignored. Since `host.ip` includes the
addresses of an agent's listeners and recent edges, two hosts with sockets
at an address make it shared.

Names are the best guess at aggregation time; PostgreSQL is the truth of
attribution. A new server may show as `~unresolved` until its listener is
written (up to one write interval), and a new client on the server side
until its client edge arrives; `shawk.peer.agent` is right meanwhile, so
counting (§7) is not affected.

An agent that folds its clients also folds a client with an agent whose
address is outside its internal ranges, as between hosts that talk over
public addresses; the two sides then do not match in PostgreSQL and §7
counts both. The connector detects this from a client edge to an address
one live host holds alone and logs both hosts and addresses, so the address
can be added to that agent's `-internal-peers`; likewise for an agent with
`-fold-external=all` that folds a server with an agent, and for agents that
fold peers in a range of `peer_cidrs`. When both agents fold the other
side, nothing tells and nothing is logged. Each folding host is logged at
most once an hour; the connector has no metrics of its own.

### 5.3 Metrics to Prometheus

Edge metrics are reduced to `service.peer.name`, `shawk.peer.agent`,
`shawk.role`, `server.port`, `network.transport`, `network.io.direction`
(bytes, datagrams) and `error.type` (failures by reason), and summed into
one resource per host and local service whose `service.name` and
`service.namespace` are the local process's, so Prometheus gives the series
the same `job` as OBI's metrics for the service. `service.instance.id` is
the host name; `host.id` and `host.name` are promoted to labels.

- Series are bounded by host × local service × peer service × port × role,
  × 2 directions (`transmit`, `receive`) for bytes and datagrams, × 6
  values of `error.type` (others become `_OTHER`); replicas and changing
  peer IPs add none. Per host at most `max_services` (200) local services,
  room for the 110 pods Kubernetes runs per node by default, and per
  service and role at most `max_peers` (50) peer names are kept; the rest
  fold into `~other`, while PostgreSQL keeps them apart. Agent-chosen names
  are cut to 255 bytes (`service.peer.name` to 511). `keep_peer_address`
  keeps `network.peer.address` when really needed.
- Some servers listen on a port chosen anew at every run: srun and salloc
  without `SrunPortRange`, to which slurmctld and slurmstepd connect. Their
  dependencies have `server.port` 0, so that each run adds no series:
  those on a service of `port_agnostic_services` (e.g. `[srun, salloc]`),
  and those on a server address, port and transport in a range of
  `dynamic_ports` (e.g. the `SrunPortRange` of the cluster, for its
  hosts). The server is the peer of a client edge, at its backend through
  a translation (§5.4), and the local process of a server edge;
  PostgreSQL applies the same rules (§6.1, §6.2) and keeps the ports of
  the edges. Without them every
  port is kept. Ports chosen by the kernel are not detected: a listener
  is seen only while the iterator lists it, and a kernel-chosen port does
  not make the servers on it one service.
- Inputs are cumulative per peer address and outputs merge several, so the
  connector adds the increases of each input to its output, treating a
  decrease or new start time as a reset; an output never decreases when an
  input disappears. A new input counts in full only if it started after
  the latest interval its host closed at this connector (for a host new
  here, after the connector started and within 2 minutes); otherwise its
  first value is a baseline, so a connector restart or a host moving between
  connectors does not add past totals at once.
- Histograms are forwarded as sum and count only (mean RTT and connect
  time): buckets would add 10 series to every TCP client dependency. A
  handshake histogram with other bounds than §3.2 is dropped as invalid.
- The output of a failure reason is created at its first increase and
  emits 0 first, because `rate()` and `increase()` take the first sample as
  the start and failures are often few. Other outputs start with their whole
  value, so failures by reason may count failures in the first interval of
  a new dependency that `shawk_connection_failed_total` leaves out.
- A host's outputs are emitted once per interval, when its last request
  arrives; late or retried points change nothing, and a clock that went
  back makes every input take its next point as a baseline. Outputs carry
  the connector's time, so one host with a wrong clock does not make
  Prometheus reject a batch. Errors downstream are logged, not returned to
  the agent, since the request was taken for PostgreSQL.
- This state requires the data of a host to reach the same connector, so
  run one connector per fleet. Spreading hosts over connectors (the
  loadbalancing exporter routing by resource) is not reliable yet: the
  resource changes with `host.ip`, `service.version` and
  `shawk.peer.internal`, so a host may move and be counted twice (#128).
- The agents' metrics (§4.2) except `shawk.agent.segment.start` are
  forwarded under `job="shawk-agent"`, rebuilt with only the expected type,
  unit and attributes (`shawk.netns.scope`, `shawk.bpf.program`), so an
  agent cannot create series of its choosing. A connector older than its
  agents drops the metrics they added.

| Prometheus name | |
|---|---|
| `shawk_connection_opened_total`, `shawk_connection_failed_total` | connections |
| `shawk_connection_count` | open connections |
| `shawk_network_io_bytes_total`, `shawk_udp_datagrams_total` | traffic |
| `shawk_tcp_retransmits_total` | retransmitted segments |
| `shawk_tcp_rtt_seconds_sum`, `shawk_tcp_rtt_seconds_count`, `shawk_tcp_rtt_seconds_bucket{le="+Inf"}` | RTT |
| `shawk_tcp_handshake_seconds_sum`, `shawk_tcp_handshake_seconds_count`, `shawk_tcp_handshake_seconds_bucket{le="+Inf"}` | time to connect |
| `shawk_tcp_syn_retransmits_total` | retransmitted SYNs |
| `shawk_connection_failed_by_reason_total{error_type}` | failures by reason, one series per reason that occurred |
| `shawk_agent_*` | agents |

A TCP client dependency thus has 13 series, plus one per failure reason
that occurred. Prometheus needs `--web.enable-otlp-receiver`,
`otlp.promote_resource_attributes: [host.id, host.name]` and a 30-minute
out-of-order window.

The OTLP receiver of Prometheus writes whatever it is sent, so anyone who
could push could write `shawk_agent_up` and silence `ShawkAgentDown`. The
example pushes over TLS with a password (`packaging/collector/config.yaml`,
`packaging/prometheus/web.yml`). Prometheus's web configuration does not
tell readers from writers, so every user, Grafana included, can push;
restricting pushes to the collector takes a proxy in front of Prometheus.

### 5.4 Translations of addresses

A relay without an agent may rewrite the addresses of the connections it
forwards: a load balancer, a keepalived or LVS virtual address, a TCP proxy.
The client connects to a virtual address; the server sees as the client
either the client's address (DNAT) or an address of the relay (SNAT, a
proxy). The two sides then do not match by address. `translations` in the
connector configuration describes the relays, by name so that collector
configuration files merge as with `peer_cidrs`:

```yaml
translations:
  postgres-vip:
    virtual: [10.0.100.1:5432]         # addresses clients connect to, with a port or for every port
    backends: [10.0.1.10, 10.0.1.11]   # addresses or ranges of the servers, with their port or the client's
    transport: tcp                     # tcp, udp, or empty for both
  web-lb:
    virtual: ["10.0.100.2:80", "[2001:db8::2]:80"]
    backends: [10.0.1.0/24:8080]
    sources: [10.0.100.250]            # what the servers see the clients at, when the relay replaces them
```

Virtual addresses are single addresses, since the server side looks a
client edge up by its virtual address; backends and sources (no port) may
be ranges. A virtual address and port belongs to at most one translation,
and a backend with a port needs virtual addresses with ports. At start the
connector writes `peer_cidrs` and the translations to PostgreSQL in one
transaction under an advisory lock, so the views never see a mix of two
connectors' configurations; the last to write wins, so every connector
should have the same.

- In PostgreSQL, a client edge to a virtual address that matches no server
  edge by address is matched with the server edges at the backends: on the
  backend's port or the client edge's; from the client's address (in the
  same scope, §6.2) for a translation without sources, or from a source;
  and when their periods overlap, within 2 minutes. The row has the period
  both edges were active in, the server's address and port, and
  `virtual_addr`, `virtual_port` and `translation`. A server edge from a
  source bundles every client of the relay, so it also keeps a row of its
  own, for clients without an agent. Any other matched edge keeps a row of
  its own for the part of its period its matched rows leave uncovered (a
  client may also reach backends without an agent; a server may serve the
  client directly), starting at the edge's start so that a side that stops
  observing does not make the other look new. On these rows the
  `*_observed_until` of a side whose edge outlives the row is NULL: whether
  the dependency ended is for the other side to tell, so a stopped agent
  does not make it look removed (§8). Where a server edge at the virtual
  address matches by address (a relay that runs an agent), the translation
  is not used.
- In the names of peers, a client edge to a virtual address is named after
  the service at a backend, with the backend's `server.port` and
  `shawk.peer.agent`, unless a service was observed on a socket at the
  virtual address (a relay with an agent; a listener on an unspecified
  address does not count, since the translation may bypass it). The choice
  among backends is stable (`collector/shawkconnector/peers.go`). A
  server edge at a backend of a translation without sources is named after
  the client whose client edge has its peer's address, and is counted by
  that client (§7). Behind sources the server sees the relay, named after
  its address, with `shawk.peer.agent` false even if an agent holds the
  address, since the relay forwards in the kernel or for clients without an
  agent.
- Translations apply to the whole history: a former backend kept in its
  translation is matched over the period it served.
- Learned translations. The backends of Kubernetes services and Docker
  published ports change constantly and cannot be written down, so the
  agents of the translating hosts learn them (§3.7), and the connector
  writes them to `shawk.learned_translations`. A client edge to a virtual
  address with no static translation is matched through the learned rows of
  its client address, virtual address and port, and with the server edges
  at their backend from their source, in its scope (loopback in the host and
  namespace of the row, a shared address on the host of the row, any host
  otherwise). Overlapping rows within 2 minutes are combined (two directors
  in turn), and the matched row covers only their span, so a client that
  moved to another backend leaves the former. The rules above apply
  otherwise, and static translations come first; the `translation` is
  `~learned`, so configured names may not start with `~`. In names, a match
  by address still comes first: docker-proxy serves the containers of its
  own host that reach a published port at the host's address, while clients
  of other hosts are DNATed. A server edge behind a learned SNAT keeps its
  name and `shawk.peer.agent`, since the host of the source translated those
  clients and its agent sees them.
- An agent of a backend that folds its clients (§3.6) must keep the
  sources, or the clients of a translation without sources, in its
  `-internal-peers`, and an agent with `-fold-external=all` the virtual
  addresses it connects to: a folded edge has no address to match. The
  connector warns otherwise (§5.2).
- With LVS direct routing the backends hold the virtual address, so several
  hosts hold it at once and edges do not match by address (§5.2); list the
  virtual address as the backend of its translation.

### 5.5 Bounds of what is held

The connector's state is keyed by what agents send. The `memory_limiter`
processor refuses requests when memory runs short but cannot free what the
connector holds, so the connector bounds it:

- Hosts (`max_hosts`, 10000), each held until it has not sent for
  `idle_ttl`. At the bound, requests of new hosts are refused with a
  non-permanent error (the agent counts a failed export); held hosts are
  never evicted.
- Series per host (`max_series_per_host`, 100000): edges, listeners,
  translations and addresses, each held until `idle_ttl` after its latest
  request. New ones beyond the bound are dropped, and since a dropped
  series may never be written, the host is not observed in that interval:
  its session ends at the previous heartbeat and the next starts no earlier
  than the request that closed the interval. Input series of edges are
  bounded to 16 times the bound (an edge has at most 15), and endpoints
  inferred from listeners on unspecified addresses to the bound; those
  beyond are left out of Prometheus or named from PostgreSQL after the next
  load (§5.2).
- Pending rows (`max_pending_rows`, 10 million), kept while writes fail or
  the schema is not ready. Beyond the bound, the changes of the hosts
  pending longest are dropped whole, as with rejected rows (§5.1).

Agent strings are cut to 4096 bytes and `shawk.peer.internal` to 4096
ranges. The defaults are far above what one connector serves and what a
large host sends (16384 flows per interval by default; a much larger
`-max-flows` may need a larger `max_series_per_host`). To bound memory more
tightly, lower `max_hosts` to the fleet size with room: the connector holds
about 5 KB per edge with its metrics and about 300 bytes per pending row.

## 6. PostgreSQL

PostgreSQL 14 or later (multiranges). The schema ships with the connector
as SQL migrations (`collector/shawkconnector/migrations`), applied by
`shawk-migrate` or by the connector with `postgres.migrate`. A schema from
v0.8.0 or a development build before `0001_schema.sql` is refused, with an
error that says to drop the schemas `shawk` and `shawk_v1` (losing their
history) and migrate again. A database is set up with
`packaging/postgres/setup.sql`, then `shawk-migrate`, then `grants.sql`,
which must be run again after every `shawk-migrate` that applies migrations.

### 6.1 Tables (internal, schema `shawk`)

```
hosts(id, machine_id, hostname, kernel, agent_version, first_seen, last_seen)
agent_sessions(host_id, started_at, last_heartbeat, udp_traced, netns_scope, dropped_flows, clock_skew,
               peer_fold, peer_internal, counters_started)
partial_observations(host_id, started_at, period_start, period_end, dropped_flows)  -- periods with drops
host_addrs(host_id, addr, first_seen, last_seen)  -- one row per period
processes(id, host_id, unit, comm, exe, service_name, first_seen, last_seen)  -- unique (host_id, unit, comm, service_name)
edges(id, host_id, process_id, role, proto, local_addr, remote_addr, port, netns, first_seen, last_seen)
  -- remote_addr is the network 0.0.0.0/0 or ::/0 for folded peers
listeners(host_id, process_id, proto, addr, port, netns, first_seen, last_seen)  -- the latest owner
listener_owners(host_id, process_id, proto, addr, port, netns, first_seen, last_seen)  -- every known owner
peer_cidrs(prefix, name)  -- written by the connector from its peer_cidrs
translations(name, side, proto, addr, port)  -- side virtual, backend or source; written by the connector (§5.4)
learned_translations(host_id, proto, netns, client_addr, virtual_addr, virtual_port, source_addr,
                     backend_addr, backend_port, first_seen, last_seen)  -- learned by agents (§3.7, §5.4)
known_dependencies(client_service, server_service, port, proto, first_seen, last_seen)
port_agnostic_services(service)  -- written by the connector (§5.3)
dynamic_ports(name, proto, addr, port_from, port_to)  -- written by the connector (§5.3); 0.0.0.0/0 and ::/0 for every host
```

`known_dependencies` keeps every dependency between services ever seen,
refreshed every 5 minutes (`shawk.refresh_known_dependencies()`). When the
connector changes the rules of ports, the dependencies known on ports they
cover are added on port 0 (`shawk.aggregate_known_dependencies()`; it has
no addresses, so a range of `dynamic_ports` covers its ports on every host
there), and the next refresh rebuilds the table from every edge kept, so
that neither adding nor removing a rule makes a dependency seen before
new. The session columns are described in §5.1. `service_name` has the
form of the `job` label (`namespace/name`), so names in PostgreSQL and
Prometheus match.

### 6.2 Contract (schema `shawk_v1`)

| view or function | |
|---|---|
| `dependencies` | one row per logical dependency: the client edge and the server edge matched by addresses and port over all time (loopback within a host and netns, addresses held by several hosts at once within a host), or through a translation (§5.4), when `virtual_addr`, `virtual_port` and `translation` (`~learned` for a learned one) tell what the client connected to. `observed_by` is `both`, `client` or `server`; a one-sided row means no agent on the other side, an undescribed NAT or load balancer between, or one of the own rows of §5.4. `client_observed_until` and `server_observed_until` are the latest heartbeats of the hosts (or NULL, §5.4): an old `last_seen` with a recent `observed_until` means no longer used; both old means no longer observed. An address `0.0.0.0/0` or `::/0` stands for folded peers (§3.6), named `~external`. `port` is that of the edges, also under the rules of ports (§5.3): between two hosts it tells the connections of different processes apart. |
| `graph_nodes`, `graph_edges` | the dependency map between services in the format of the Grafana Node Graph; a peer without a service is named by `peer_class`, and a dependency on a port of `port_agnostic_services` or `dynamic_ports` (§5.3) has port 0 |
| `peer_class(addr)` | the name of a peer without a known service, as in `service.peer.name`: the narrowest range of `peer_cidrs`, `~unresolved` for an address not routed on the Internet, `~external` otherwise, including the networks of folded peers |
| `dependency_changes` | dependencies between services that appeared, or disappeared while a host that saw them kept observing for 15 minutes; port 0 for those of `port_agnostic_services` and `dynamic_ports` (§5.3), so that a run of srun on a new port is not new |
| `service_endpoints` | addresses and ports services accept connections on: the last known listeners of each host (unspecified addresses expanded to the host's addresses) and its server edges, for hosts that reported in the last 30 days, except addresses another host took over since; used by the connector (§5.2) |
| `client_endpoints` | the client sides of connections in the last hour (client address, server address, port, client service); used by the connector to name the peer of a server edge |
| `agent_addrs` | addresses of hosts whose agent closed an interval in the last 5 minutes, with what the agent traces and folds; used by the connector |
| `agents` | the latest segment of every host and whether its agent is alive; the last columns, `peer_fold` and `peer_internal`, tell what the agent folds and the ranges it keeps exact |
| `unobserved(since, until, tolerance)` | the periods in which each host was not observed; Grafana overlays them as annotations |
| `partly_observed(since, until)` | the periods in which each host was observed but its agent dropped flows, cut to `[since, until]`: `host`, `gap_start`, `gap_end`, `dropped_flows` (flow updates dropped). A dependency may be missing from them although it was used; Grafana overlays them as annotations |
| `dependencies_between(since, until)`, `graph_edges_between`, `graph_nodes_between`, `dependency_changes_between` | the same for the dependencies active in a period. They take the edges active in the period with a margin of 15 minutes before matching, so a recent window does not scan the history (about 0.3 s instead of 3 s with a million edges) and both sides of a connection are matched at the edges of the period; the dashboards and alerts use them. A dependency appeared in a period when it was first seen in it and is not in `known_dependencies` from before it, so one that comes back on new edges (a new container, an hourly job) did not appear |

The connector role writes `shawk` and reads `shawk_v1`; Grafana reads
`shawk_v1` only (`packaging/postgres`). Neither may create objects in the
database (tables or functions in `public`, temporary tables, large
objects). The read-only transactions and statement timeout that `setup.sql`
gives Grafana are session defaults it could change; the privileges are what
hold.

## 7. Counting each dependency once

When both ends run an agent, a dependency appears on the client side
(`shawk_role="client"`) and on the server side (`shawk_role="server"`). The
recording rules in `packaging/prometheus/shawk-rules.yml` count it once:

| metric | per dependency | recording rules (`shawk:dependency_…`) |
|---|---|---|
| connections, open connections, bytes, datagrams, RTT | the client side; the server side only when the client has no agent (`shawk_peer_agent="false"`) | `connections:rate5m`, `open_connections`, `request_bytes:rate5m`, `response_bytes:rate5m`, `request_datagrams:rate5m`, `response_datagrams:rate5m`, `rtt_seconds_sum:rate5m`, `rtt_seconds_count:rate5m` |
| connection failures, by reason, handshakes, SYN retransmissions | the client side only (the server never sees them, and its side of a handshake is not measured) | `connection_failures:rate5m`, `connection_failures_by_reason:rate5m`, `handshake_seconds_sum:rate5m`, `handshake_seconds_count:rate5m`, `syn_retransmits:rate5m` |
| retransmissions | both sides: each counts its own retransmitted segments; `shawk_role` is the sender | `retransmits:rate5m` |

The two sides differ in `shawk_role`, so their `or` is a union. The rules
label the client `src` and the server `dst` whichever side observed the
dependency, e.g. `shawk:dependency_connections:rate5m{src, dst,
server_port, network_transport}`.

Behind a translation with sources (§5.4), the server sees the relay
(`shawk_peer_agent="false"`) and counts the connections of every client of
the relay, while the clients that run an agent count theirs. Each
dependency is counted right, but the sum into the server counts those
clients twice, since the server cannot tell its clients apart.

## 8. Grafana

`packaging/grafana` holds data sources, dashboards (fleet, dependency map,
dependency details, changes, application layer of OBI) and alert rules.

PostgreSQL alerts use the time series format, with every row at `now()` so
each series has a value at the last time; a query that finds nothing
returns No Data, which the rules treat as Normal. New and disappeared
dependencies are judged per service and port (`dependency_changes_between`;
port 0 under the rules of §5.3), so a dependency seen before is not new,
and peers without a service are named as in Prometheus. The window of new
dependencies ends 5 minutes ago, when both sides of a new connection are
written. A disappeared dependency is an explicit row (its `last_seen`
falls in the window while a host that saw it is still observed) rather
than a row missing from the result, so a stopped agent does not look like
a removed dependency. Stopped agents are alerted by Prometheus
(`ShawkAgentDown`) for 24 hours, then from `shawk_v1.agents` for 30 days,
labelled with the host id; a host reinstalled under the same name and
alive is not alerted.

The fleet, dependency details and changes dashboards overlay the periods
from `unobserved()` and `partly_observed()` as annotations, so the absence
of a dependency is not read as disuse over them. SYN retransmissions
per connection attempt (handshakes plus failures) exceed 1 when connects
time out, and `TCP_FASTOPEN_CONNECT` connects, which have no handshake,
raise them. OBI panels use a minimum interval of a minute, since OBI
exports every 60 seconds by default.

## 9. OBI

OBI cannot replace the tracer of shawk: its network flows and TCP statistics
do not tell which process communicates, and its application layer covers
only the protocols it parses. shawk runs beside it:

- OBI instruments the application layer (`application` and
  `application_service_graph` features) of selected services and sends to
  the `otlp` receiver of the same collector, with a client certificate from
  another CA than the agents' (§4.3). Its network and statistics features
  stay disabled, since shawk observes the same per process. Its metrics are
  not batched in the collector: they carry the clock of their host.
- Both name services the same way (§4.1) and set the resource
  `service.name`, so `job` matches and dashboards use one `$service`
  variable.
- `host.id` is the machine id in both. Cloned VMs should regenerate it
  (`systemd-machine-id-setup`) for OBI's sake; shawk tells them apart by
  host name anyway.
- Dependencies seen by shawk but absent from OBI's service graph show where
  application-layer instrumentation is missing.

## 10. Limitations

- **Relays that rewrite addresses** (NAT, IPVS, kube-proxy, cloud load
  balancers) hide the real peer, as discussed in §5.2 of the paper:
  dependencies end at the relay address and are seen on one side only,
  unless `translations` describes the relay or the translating host learns
  it (§5.4, §3.7). Learned translations cover one hop, and miss IPVS
  without `conntrack=1` (#139), datapaths without netfilter conntrack
  (Cilium's kube-proxy replacement), and connections confirmed before the
  agent started, until the client opens another. A REDIRECTing sidecar
  (Istio, Linkerd) is a dependency of its client when the server is reached
  at another address (a ClusterIP). Connections to a published port on
  loopback go through `docker-proxy`, a service of its own. Learned SNAT of
  clients forwarded from other hosts (a NodePort) leaves those without an
  agent uncounted in Prometheus. See
  [proposals/translation-followups.md](proposals/translation-followups.md).
  Behind a relay that replaces client addresses, every client of the relay
  is matched with every server edge from it, so rows grow as clients times
  backends (a million for a thousand of each, seconds to read), and the
  server side is counted besides the clients (§7).
- **Container network addresses** are told apart only when several hosts
  with agents hold them at once. A container address held by one host with
  an agent may be attributed to that host for a peer on a host without one.
- **The same port shared by different services** with `SO_REUSEPORT` cannot
  be told apart (§5.3 of the paper); this is rare.
- **UDP direction** (§3.3): peer-to-peer protocols where both sides send
  first are recorded as clients of each other's port. A client socket that
  existed before the agent started and receives before it sends again is
  recorded as a server, unless it is connected on a port the kernel chose. A
  connected socket on a bound port cannot be told from a server connected to
  its client (socat, DTLS). A socket that is both client and server on its
  port, like ntpd, has the direction of its first datagram for all peers.
- **MPTCP**: subflows opened by the server side (not by the default path
  manager) are recorded as outgoing from the server, and data resent on
  another subflow is counted on both. With more open MPTCP connections than
  the owner map holds, the agent scans processes every interval.
- **Sockets of the kernel** are named after their port (§4.1), so a
  subsystem on another's port is named after that one, and one on an
  unlisted port is `~kernel`; NFSv3 also talks to `lockd` and `mountd` on
  ports rpcbind assigns. A socket created by a process and then held by the
  kernel alone (an `nbd` or iSCSI connection whose process exited) is not
  the kernel's: adopted at startup it is not attributed. A listener with
  `sk_user_data` (e.g. in a BPF sockmap) held by a process in another PID
  namespace is taken for the kernel's; run the agent in the host PID
  namespace.
- **Flow table capacity**: when more distinct flows than `-max-flows` occur
  in one interval, updates are dropped and counted in
  `shawk.agent.flows.dropped`, and the period is partly observed
  (`partly_observed()`, §6.2): a dependency not seen in it may still have
  been used. An insertion the kernel refuses with `-EBUSY` counts as a drop
  too (the agent warns that the table was not full). With folding (§3.6)
  flows grow with internal peers and local services, but a host with very
  many internal clients, or `-fold-external=none`, may need a larger
  `-max-flows`. The tables of listening ports hold `-max-flows` ports (8192
  to 65536); when they overflow, pre-existing connections and UDP sockets
  on the ports left out may get the wrong direction, and the agent warns.
- **Folded peers** (§3.6): the address of each external peer is not kept,
  only that the endpoint had external peers; set `-fold-external=none` where
  it is needed. A fleet that uses public addresses internally must list them
  in `-internal-peers`, or the two sides of connections between its hosts do
  not match (the connector warns, §5.2). A peer in a `peer_cidrs` range
  outside `-internal-peers` (a public office range) is named `~external`.
- **Connections the TCP iterator skips** (§3.2) are found only by an owner
  scan, every minute or sooner when connections are adopted or listeners
  change; until then they are not counted as open and their traffic waits
  until they close or are found. Connections without a file (the kernel's,
  MPTCP subflows, children not yet accepted) are not found.
- **Handshakes** are measured only on connections that are opened; a path
  used only by connection pools is not, which active probing would add.
  Retransmitted SYNs are attempts, not losses on the wire: SYNs dropped on
  the host count, and so do a lost SYN-ACK and a full SYN or accept queue on
  the server. The duration includes the search for a free local port. A
  REDIRECTing sidecar answers the handshake itself in microseconds, and a
  proxy that terminates TCP ends the measured path. Buckets above 1 s are
  not comparable across kernels with different SYN schedules. Failures
  before CLOSE→SYN_SENT (no route, a cgroup BPF connect program) are not
  seen. A firewall that rejects with a reset or port unreachable gives
  `refused`, which reads as a service that is down; an application connect
  timeout below a second turns losses into `aborted`, as does a SYN an LSM
  denies on output. An application that reads the error while the kernel
  closes the socket takes it first, on every kernel, and the failure is
  counted as `timeout`: 0.01 to 0.05 % of the connects that an ICMP error
  failed, for a client that waits in poll(2) or epoll, but up to 60 % of
  all failures, resets included, for one that busy-polls the socket
  ([research/kernel-hooks](research/kernel-hooks/kernel_hooks.md) §5,
  #166). UDP and QUIC have no kernel handshake.
- **Connections that predate the agent** are counted from the adoption on.
  One accepted by a listener with a backlog of 0 that is gone is recorded
  as outgoing.
- **Clocks**: first and last seen times come from each host's clock, capped
  at 2 minutes ahead of the connector (§5.1), as does the segment start;
  heartbeats come from the connector's clock, compared with PostgreSQL's.
  Keep clocks synchronized (chrony); `clock_skew` shows hosts that are not.
- **Agents report the addresses of their hosts**, unverified:
  `host_identity: certificate` ties requests to a host, not to addresses.
  What a host reports at an address another live host holds alone does not
  name peers (§5.2). An agent can still:
  - name the peers at an address no live agent holds (a host without an
    agent, or whose agent stopped more than 5 minutes ago);
  - declare another host's address in its `host.ip`, which makes it shared:
    on other hosts its peers are then named after their address range with
    `shawk.peer.agent` false, so the servers of a client at it count its
    connections too (§7), and in PostgreSQL, once both hosts held it for 10
    minutes, its edges match within each host only;
  - write edges at another host's address, which `shawk_v1.dependencies`
    matches with their peers' edges, beside those of the host that holds it;
  - send times up to 2 minutes ahead of the connector (§5.1).

  `shawk_v1.agent_addrs` and `shawk_v1.service_endpoints` show who reports
  an address and what.
- **The initial network namespace only** (`-netns self` on a host): the
  connections of containers in other namespaces are not traced, and those
  that leave with the host's addresses look traced to their peers, whose
  server side is then not counted. The agent warns; use `-netns all` on
  hosts with containers.
