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

- completeness: every process and every TCP/UDP service, and the local
  services reached on Unix sockets, including middleware and third-party
  software that cannot be instrumented;
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

What is observed is TCP and UDP sockets and the connections of Unix stream
sockets (§3.8), so "not used" means "no TCP, UDP or Unix stream
connection": datagram Unix sockets are not traced. RDMA verbs (InfiniBand,
RoCE) bypass the sockets: in HPC clusters,
where the main data paths use them (the RDMA transports of MPI and NCCL,
Lustre o2ib, GPFS verbs, NFS over RDMA), a host may be observed
throughout and still be used (§10).

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
| protocol | TCP, UDP, or Unix stream sockets, whose flows have the name of a socket instead of addresses and a port (§3.8) |
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

**Sockets of the kernel.** The clients of NFS, iSCSI, CIFS, Ceph and
BeeGFS, nfsd, DRBD and Lustre's LNet hold sockets without a process. They
matter before a server is decommissioned (a mounted NFS export), but
connect from a kernel worker or whichever process triggered them, so comm
and cgroup change between reconnections. A connecting socket is the
kernel's when `sk_kern_sock` is set and it is not an orphan (MPTCP
subflows and SMC's TCP socket excepted); it gets comm `~kernel` and cgroup
id 0. A listener is the kernel's when no process held it at the last scan
and the kernel may hold it; incoming connections are attributed through
their listener, since children inherit `sk_kern_sock`. The exact tests
are in shawk.bpf.c and `internal/tracer/owner.go`; naming is in §4.1.

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
  since their first datagram afterwards may be a reply; the walk at start
  marks them before the UDP programs attach, so that a reply sent in
  between does not make one a client;
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
| fentry, fexit (UDP and Unix sockets only) | 5.5 on x86_64, 6.0 on arm64 (RHEL 9 on arm64: 5.14.0-621, in 9.8, not in 9.6) |
| kprobes on the module nf_conntrack (translations, §3.7; `CONFIG_KPROBES`, the system call `perf_event_open`) | `__nf_conntrack_confirm`, and `nf_ct_destroy` since 5.19 and in RHEL 9, `destroy_conntrack` before |

CI loads the programs on the Ubuntu runner kernels (6.8 to 7.0, x86_64 and
arm64) and in VMs (`make vm-test`) on Rocky Linux 9.6 (x86_64, aarch64),
upstream 5.14 (x86_64) and 5.15 (x86_64, aarch64); on aarch64 before 6.0
the tests check that UDP and Unix sockets are reported as not traced. All struct accesses use CO-RE. `make compat`
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

### 3.8 Unix stream sockets

Local clients often reach a service on its Unix socket rather than over
TCP: PostgreSQL and MySQL (`/run/postgresql/.s.PGSQL.5432`,
`mysqld.sock`), php-fpm behind nginx, Docker and containerd, munge for
Slurm, sssd. "Who still uses this database" then has answers that TCP does
not show. The connections of stream and seqpacket Unix sockets to a named
socket, a path or an abstract name, are traced at the connect and the close
of the client; no tracepoint reports their state, so the programs hook two
functions that the socket operations point to, and so are never inlined:

| hook | role |
|---|---|
| `fexit/unix_stream_connect` | in `connect(2)` of the client: an established connection, counted open in the socket storage of the client, or a failed connect with its reason |
| `fentry/unix_release` | the client closes its socket (its last file): the connection is no longer open |
| `iter/task_file` | the listening sockets with their names and owners, and the adoption of the client sides of connections that predate the agent |

- **Flows.** A flow bundles the connections of a client process (cgroup and
  comm) to one name, in the network namespace of the client socket, with
  `network.transport` `unix` and the name as `server.address` instead of
  addresses and a port. The client's own name, which it rarely has or which
  the kernel gives it (autobind, e.g. with `SO_PASSCRED`), is dropped like an
  ephemeral port. The name is the one the server bound, which the socket the
  kernel creates for the server shares with the listener: a client that
  connects through a symbolic link (`/var/run` to `/run`) or through a mount
  in a container has the name as the server bound it. Names are shown
  as ss(8) shows them, an abstract name with `@` for its leading NUL; bytes
  that are not printable UTF-8 are escaped as `\xHH`, a backslash as `\\`
  and the `@` a path starts with as `\x40`.
- **No server side.** A client is traced in its own process, the only side
  that has a name to connect to: the server's end is created by the kernel
  in the connect of the client and accepted later, by whichever process.
  The server is the owner of the listener of the name on the same host
  (§5.2): in the namespace of the client, else, for a path, the only
  listener of the name on the host, since a socket file is reached from
  other namespaces through mounts; an abstract name is reached in the
  namespace of its client only. Listeners are found by the owner scans of §3.2 (every
  minute), since `iter/unix` exists only since Linux 5.17; a client of a
  name that no scan found requests one at the next interval, so a new
  server is named an interval later. The owner is chosen as for TCP: the
  service rather than systemd for socket activation, the parent among its
  workers.
- **Open connections** are entries of a table that is not flipped, one per
  client socket, by its address: added at the connect, or when the walk
  of the processes adopts it, and deleted at the close; user space counts
  them per flow, so an edge with an open connection stays alive without
  new ones. Entries rather than counts leave nothing that a race could
  make drift: the programs that add the same socket at once insert it
  once, user space deletes nothing, and connect(2) and the walk hold a
  reference to the file of the socket, so it cannot close while they add
  it. A Unix
  socket keeps no counters of the bytes it carries, so its traffic is not
  measured: it would take a hook on every message, the cost that §3.2
  avoids for TCP.
- **Failures** have the name the client asked for and a reason, as
  `error.type` of TCP: `refused` (no such path, or nothing listens on it,
  e.g. a socket file left by a server that exited), `timeout` (the backlog
  of the listener is full), `unreachable` (permission denied on the path or
  by an LSM), `local` (no memory for the connection), `aborted` (a signal
  interrupted a connect that waited for the backlog), and `_OTHER`. A connect
  the kernel restarts after a signal is counted when it ends.
- **Adoption.** The owner scan at start adopts the connections that predate
  the agent, which are counted open from then on, not as connections. The
  client side of a connected socket is the one whose peer has a name while
  it has none, or only one the kernel gave it; when both bound names, the
  server's is the listener's, held more than once while the listener is
  open. Unnamed pairs (`socketpair(2)`) connect no service and are not
  traced, nor are the connections the scans cannot tell apart.
- **Not traced:** datagram Unix sockets (syslog and journald, `sd_notify`),
  whose messages only a hook on every message would see, and unnamed pairs.
- The programs need BPF trampolines, as UDP does (§3.3): without them the
  agent reports that Unix sockets are not traced
  (`shawk.agent.unix.traced`). `-max-flows` sizes the tables of Unix flows to
  a quarter of it and that of their open connections to a half, at least
  1024 each (about 3.6 MiB at the default); a connection that does not fit
  is a dropped update (§10).

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
- The processes of Slurm jobs (cgroup v2) are named by the structure of
  `system.slice/slurmstepd.scope/<job>/<step>/...`, whatever names the job
  directory (`job_<id>` before Slurm 26.05 or with `CgroupJobIdPaths=yes`,
  the SLUID otherwise): `user/task_*` (`task_special` too, where
  `pam_slurm_adopt` puts the processes it adopts) is named after the kind
  of its step, `slurm/batch`, `slurm/step` (`step_<n>`,
  `step_<n>+<component>`), `slurm/extern` or `slurm/interactive`, and the
  directory of slurmstepd in a step (`slurm`; `slurm_processes` in the
  documentation) and `<scope>/system` are `slurmstepd`, as Slurm's
  `cgroup/v2` plugin makes them. The scope is `slurmstepd.scope`, or
  `<node>_slurmstepd.scope` with `--enable-multiple-slurmd`, recognized
  only under slices from the root (`system.slice`, or the slice of
  `CgroupSlice`), where users cannot make cgroups; other hierarchies, and
  cgroup v1, keep the rules above (`internal/procinfo/cgroup.go`).
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
  any process sets them and they repeat in every data point. The `OTEL_`
  variables of the processes of Slurm jobs are not read: any user could
  name a job `slurmctld`, so they are named after their executable onwards.
  Nor is their environment read, so that reads that hang on a parallel
  file system do not hold the slots of the other processes.
  PostgreSQL keeps these names; Prometheus has them under one `job` (§5.3).
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
  (16385), `~kernel:dlm` (21064), `~kernel:lnet` (988, Lustre over TCP),
  `~kernel:beegfs` (8003, 8005 and 8008 of the daemons, 8004, the client's
  UDP port), and `~kernel` otherwise. The BeeGFS daemons are processes and
  keep their names; the nodes of LNet connect to each other in both
  directions, so it has one name for both sides, as DRBD and OCFS2. Kernel
  servers are named apart so that a dependency has two ends:
  `~kernel:nfsd` (2049), `~kernel:ksmbd` (445), `~kernel:iscsi-target`
  (3260, LIO), `~kernel:nvmet-tcp` (4420, 8009). Names start with `~`, which
  `peer_cidrs` names cannot, and have no `/`, which would read as a
  namespace in the `job`. The socket's callbacks would tell more, but
  mapping them to names needs `/proc/kallsyms` with `CAP_SYSLOG`, which the
  agent's unit does not grant.
- Reading `/proc/PID/environ` takes the process's memory map lock, which a
  stuck process can hold forever (a stalled FUSE mapping), so reads time out
  and back off, and hung reads are bounded (`internal/procinfo/service.go`). A PID whose comm no longer
  matches the flow is not trusted, except the child that systemd forks for
  a service, named `(cron)` until it executes `cron`, which connects the
  standard output of the service to journald over a Unix socket (§3.8):
  its flow takes the identity and the comm of the service. A process that exits before it is read
  takes the latest identity seen for the same unit and comm, and for the
  processes of Slurm jobs, whose units every job of every user shares, the
  same cgroup (step) too. The agent reads `/proc/PID/cgroup` with the
  executable. What `/proc` tells of a PID now in another cgroup than the
  flow, one of them a job's, is not used: the PID was reused by another
  job, or `pam_slurm_adopt` moved the process; nor is a read during which
  the cgroup changed. A flow whose cgroup path is not known (its event was
  dropped) learns it from its process if the process is still in that
  cgroup (same inode); otherwise a process now in a job is not taken for
  it.
- Users, opt-in. With `-job-users`, a process of a Slurm job (a unit
  `slurm/...`) carries its user as `process.user.id`: the effective uid of
  `/proc/PID/status`, read with the executable in the interval. It is read
  together with `/proc/PID/cgroup` through one open `/proc/PID`, which
  fails once that process exits, and sent only if the process is in the
  cgroup of the flow: a process of another job with the same comm may have
  taken the PID since the flow was seen. A uid that could not be read (the
  process exited, its PID was taken, the reads ran out of time) is unknown
  and not sent: unlike the executable and the service, it is never taken
  from the latest identity. Processes outside jobs (slurmstepd included)
  have no user, nor do the sockets of kernel clients (NFS, Lustre), which
  belong to no job. The series of a job grow with its users, not with
  jobs; the connector keeps the users only with `job_users` (§6), for
  administrators.
- The host is identified by `host.id` (`/etc/machine-id`, else
  `/var/lib/dbus/machine-id`) and `host.name`. PostgreSQL keys a host by
  the hash of both, so VMs cloned with the same machine id stay apart.
  A node whose machine id changes at every boot (a stateless node with an
  empty `/etc/machine-id`) becomes a new host each time; provisioning gives
  each node a stable one (`packaging/README.md`), and
  `unobserved_by_name()` (§6.2) computes gaps over all the hosts of a name.

### 4.2 What is sent

Every edge (a bundled flow with its process identity) is a series with the
attributes `service.name`, `service.namespace`, `process.executable.name`,
`process.executable.path`, `process.command`, `shawk.unit`, `container.id`,
`shawk.role` (`client` or `server`), `network.transport`,
`network.local.address`, `network.peer.address`, `server.port` (the service
port, whatever the role), `shawk.netns`, `shawk.peer.folded=true` for a
folded edge (§3.6), and `process.user.id` for a process of a Slurm job
with `-job-users` (§4.1). The PID is not an attribute, so a restarted
process continues the same series. An edge of Unix sockets (§3.8), always
a client's, has `network.transport=unix` and `server.address`, the name of
the socket, instead of the addresses and the port, and its connections,
failures and open connections only.

| metric | type, unit | |
|---|---|---|
| `shawk.connection.opened` | Counter, `{connection}` | established connections (TCP, Unix) |
| `shawk.connection.failed` | Counter, `{connection}` | failed attempts (client side only: TCP, Unix) |
| `shawk.connection.count` | UpDownCounter, `{connection}` | connections open at the end of the interval (TCP, Unix) |
| `shawk.network.io` | Counter, `By` | bytes, with `network.io.direction` (TCP, UDP) |
| `shawk.udp.datagrams` | Counter, `{datagram}` | UDP datagrams, with `network.io.direction` |
| `shawk.tcp.retransmits` | Counter, `{segment}` | segments the local socket retransmitted |
| `shawk.tcp.rtt` | Histogram without buckets, `s` | smoothed RTT samples (sum and count) |
| `shawk.tcp.handshake` | Histogram, `s` | handshakes of established active opens, with the bounds of §3.2 (TCP client side only) |
| `shawk.tcp.syn_retransmits` | Counter, `{segment}` | SYNs the active opens retransmitted, established or failed (TCP client side only) |
| `shawk.connection.failed.by_reason` | Counter, `{connection}` | failed attempts with `error.type` (`refused`, `timeout`, `unreachable`, `local`, `aborted`, `_OTHER`; client side only: TCP, Unix, §3.8) |
| `shawk.edge.first_seen`, `shawk.edge.last_seen` | Gauge, `s` | Unix time of the first and last activity |

A failure reason is sent from its first occurrence on an edge, starting at
that interval, so an edge does not carry six series of zeros and the
connector takes the first value as new rather than as a baseline.

Listeners are sent as `shawk.listener.first_seen`/`last_seen`, with
`shawk.port.kernel_chosen=true` when the kernel chose the port: the socket
lacks `SOCK_BINDPORT_LOCK`, since it was bound to port 0 or listened
without bind (§5.3). Those of Unix sockets have `server.address`, and
`shawk.netns` the namespace of the listening socket. Translations (§3.7)
are sent as `shawk.translation.first_seen`/`last_seen` with the client,
virtual, source and backend addresses and ports. The agent's own
metrics are `shawk.agent.up` (with `shawk.netns.scope`),
`shawk.agent.segment.start`, `shawk.agent.udp.traced`,
`shawk.agent.unix.traced`, the drop counters
`shawk.agent.flows.dropped`, `shawk.agent.cgroup_events.dropped`,
`shawk.agent.container_reads.dropped` and
`shawk.agent.translations.dropped`, `shawk.agent.translations.traced`,
`shawk.agent.export.failures`, and with `-bpf-stats` per-program run counts
and times. A host whose RDMA ports (InfiniBand, RoCE) have readable port
counters also sends `shawk.agent.rdma.io`, the bytes its ports sent and
received since the agent started, from
`/sys/class/infiniband/*/ports/*/counters` (`port_xmit_data` and
`port_rcv_data`, which count octets divided by 4). A read may query the
device, so the counters are read every interval apart from the
collection, and a device that does not answer delays only them. It goes
to Prometheus only, as a hint that the host used what shawk does not
observe (§10); its absence does not mean that the host has no RDMA
(software devices such as rxe and siw have no port counters). The resource
carries `host.id`, `host.name`, `os.version`,
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
- Readiness. Under systemd (`Type=notify`) the agent reports ready
  (`READY=1` on `NOTIFY_SOCKET`) once its programs are attached and the
  sockets that existed before were adopted; a failure to attach fails the
  start. Units ordered after the agent, such as slurmd on a node that
  power saving resumes, then start traced. What happens before the
  programs are attached is not observed: connections that ended before are
  lost, and those still open are adopted without their earlier traffic.
  The start of the agent, and of its first segment, is taken after the
  first walk and the resolution of owners, a little after the programs
  are attached.
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
  certificates over gRPC only, so HTTP requests are then refused. The
  certificate names neither the `host.id` nor the case of `host.name` or a
  final dot, which make other hosts (§4.1), so the connector holds at most
  4 hosts of a certificate (§5.5). With
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

Edges and listeners of Unix sockets (§3.8) are written the same way to
tables of their own, `unix_edges` and `unix_listeners`, since they have a
name rather than addresses and a port; a listener of a Unix socket
whose owner is not known is not written, and a server edge of a Unix
socket is invalid.

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

The session also keeps `peer_fold`, `peer_internal`, `unix_traced` (NULL
for an agent that does not send it) and `counters_started`
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
observed; node states and maintenance windows (§5.7) by
`shawk.prune_node_states()`.

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
| client of a Unix socket | a service listens on the name on the same host, in the namespace of the edge, else, for a path, in the only namespace where any does | the service |
| client of a Unix socket | no listener of the name, listeners in several other namespaces, or an abstract name served in other namespaces only | `~unresolved` |

The listeners of Unix sockets come from requests and from
`shawk_v1.unix_endpoints`; among them only those seen within 5 minutes of
the latest one of the name count, so that a socket that moved to another
namespace leaves the former, and the most recently seen service wins. A
Unix socket is on the host of its client, so its peer has
`shawk.peer.agent` true and, with `peer_hosts`, `shawk.peer.host` the host
itself.

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

With `peer_hosts` (§5.3) a peer also gets a host, `shawk.peer.host`. A host
takes stronger evidence than a service, so a peer whose host is not certain
gets none:

| peer | `shawk.peer.host` |
|---|---|
| loopback, or an address several live hosts hold, this one included | the host itself |
| an address the inventory maps to one host (§5.6) | that host |
| an address one live host holds alone | that host |
| an address no live host holds, whose latest holder held it alone within 30 days and whose agent has stopped since | that host, so that failures towards a host that is down are named |
| otherwise, private address | `~unknown` |
| otherwise, public address; or folded | `~external` |
| a virtual address of a translation that no service of its own names | the host of its backend if the translation has one backend, a single address, or learned translations sent the client to one address; `~unknown` otherwise |

The latest holders are read from `shawk.host_addrs` with the other names,
with `peer_hosts` only: the host whose latest period at the address ended
last, unless another host held the address after that period began (beyond
3 minutes), and that last held it within 30 days, by the time it last
held it, not as of the load. Until what the connector saw is written and
read back, the holders it saw itself count too, so that an address that
moved while PostgreSQL could not be written does not name its former
holder again once the new one stops. An address that left a host whose
agent is still alive names no host. The names of `peer_cidrs` are ranges,
not hosts. Through a translation, `pickBackend()` chooses a
representative to name the service, not the backend a connection reached,
so a virtual address with several backends has host `~unknown`; the names
of services do not change.
`shawk.peer.agent` keeps its meaning: knowing the host of a peer does not
mean that its agent records the other side.

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
- The processes of Slurm jobs (units `slurm/*`, §4.1) are forwarded under
  `job="slurm-job"`, which takes one place of `max_services`, so that
  every executable of every job does not become a `job`. As peers they are
  `service.peer.name="slurm-job"` too, so both sides of a dependency
  between jobs match: the endpoints the connector learns from agents are
  named so, and those read from PostgreSQL by the column `slurm_job` of
  `shawk_v1.service_endpoints` and `client_endpoints`. PostgreSQL keeps
  their names; the series from the agent are still keyed by executable,
  bounded by its idle TTL.
- Some servers listen on a port chosen anew at every run: srun and salloc
  without `SrunPortRange`, to which slurmctld and slurmstepd connect. Their
  dependencies have `server.port` 0, so that each run adds no series:
  those on a service of `port_agnostic_services` (e.g. `[srun, salloc,
  slurm-job]`, where `slurm-job` names the processes of Slurm jobs, which
  PostgreSQL keeps under their own names), and those on a server address,
  port and transport in a range of
  `dynamic_ports` (e.g. the `SrunPortRange` of the cluster, for its
  hosts). The server is the peer of a client edge, at its backend through
  a translation (§5.4), and the local process of a server edge;
  PostgreSQL applies the same rules (§6.1, §6.2) and keeps the ports of
  the edges. Without them every port is kept. PostgreSQL holds the rules
  of the connector that wrote them last, so connectors that share it need
  the same ones; one that finds others there, e.g. during a rolling update
  of the configuration, logs an error hourly. Ports chosen by the kernel
  are a hint for the rules, not a rule: `shawk_v1.kernel_chosen_ports`
  (§6.2), shown on the changes dashboard, lists the services that listened
  on such ports in the last 30 days and that no rule covers, with how many
  hosts and ports, so that operators can add them. Nothing is aggregated
  by it, since a listener is seen only while the iterator lists it (an
  srun of a few seconds may be missed) and a kernel-chosen port does not
  make the servers on it one service.
- Inputs are cumulative per peer address and outputs merge several, so the
  connector adds the increases of each input to its output, treating a
  decrease or new start time as a reset; an output never decreases when an
  input disappears. A new input counts in full only if it started after
  the latest interval its host closed at this connector (for a host new
  here, after the connector started and within 2 minutes); otherwise its
  first value is a baseline, so a connector restart or a host moving between
  connectors does not add past totals at once.
- The dependencies over Unix sockets (§3.8) are client edges with
  `network.transport` `unix` and `server.port` 0: their names are not
  forwarded, as addresses are not (`keep_peer_address` keeps none), so
  the series grow with the services their clients reach, not with names.
  They have connections, failures by reason and open connections, no
  bytes, and in the family of peer hosts connections and failures by
  reason. A service that listens on Unix sockets only has no series of
  its own: it is the `service.peer.name` of its clients.
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
that occurred, and one over a Unix socket 3.

The outputs above reduce a peer to its service, which treats the hosts of
one service as interchangeable; in an HPC cluster they are not (nfs01
exports /home and nfs02 /scratch, and the `slurmd` of every compute node are
one `slurmd`). `peer_hosts: true` adds a separate family whose series carry
`shawk.peer.host` (§5.2) besides the attributes above; the outputs above,
their labels and the rules over them do not change:

| Prometheus name | sides |
|---|---|
| `shawk_host_connection_opened_total` | client, server |
| `shawk_host_connection_failed_by_reason_total{error_type}` | client, reasons that occurred |
| `shawk_host_tcp_handshake_seconds_sum`, `_count`, `_bucket{le="+Inf"}` | client |
| `shawk_host_tcp_syn_retransmits_total` | client |
| `shawk_host_network_io_bytes_total` | client, server |
| `shawk_host_tcp_retransmits_total` | client, server |

A TCP client edge has 8 series of the family, a TCP server edge 4, and
each side of a UDP edge 2, per peer host, plus the failure reasons that
occurred. `max_peer_hosts` (500) bounds the hosts per host, local service,
role and peer service, folding the others into `~other`, and
`peer_host_services` restricts the family to the dependencies with one of
its services at either end, named as peers name them (`[namespace/]name`,
`slurm-job` for the processes of Slurm jobs). Either end, so that both
sides of a dependency have the family or neither: the rules of §7 leave out
the server side of a client with an agent, whose client side counts the
dependency, so a family on the server side only would count nothing.
Connectors with other settings would break this the same way. Neither
bound limits the total: traffic between all the
compute nodes of a cluster costs about 12 series per pair, service and
port, so measure the label combinations before enabling the family widely.
A series lives until both idle TTLs pass after its last activity.

A node of an HPC cluster has addresses on several networks (management,
IPoIB or fast Ethernet, storage, BMC), and the peer host does not tell
which one a connection used. `networks` names their ranges (e.g. `mgmt:
10.0.0.0/16`, `ib: 10.10.0.0/16, fd00:10::/32`) and needs `peer_hosts`:
the family then carries `shawk.local.network` and `shawk.peer.network`,
the networks of the local and the peer address of each edge, so that NFS
traffic over the management network rather than the storage network
shows. The narrowest range wins. An address in none is `~unknown` if it is
not routed on the Internet, loopback included, and `~external` otherwise,
as is a folded peer unless a range holds its whole network. A Unix socket
has no address and uses no network: its outputs carry none. The ranges are
parsed as those of `peer_cidrs` (`ranges.go`): names neither empty nor
starting with `~`, one name per prefix, IPv4-mapped prefixes unmapped. A
host and service reach a peer host over one pair of networks as a rule, so
the networks add series only for the dependencies that use several; the
outputs outside the family, and the family without `networks`, do not
change.

Prometheus needs `--web.enable-otlp-receiver`,
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
- Hosts of a certificate, with `host_identity: certificate`: at most 4
  per client certificate (by its SHA-256), whatever their `host.id`, the
  name of the certificate they send or how `host.name` is spelt in case or
  with a final dot, refused beyond like hosts beyond `max_hosts`.
  Otherwise one certificate could take every host of `max_hosts` with
  made-up `host.id` values. Four leave room for a host whose machine id
  changes, as at a reinstall or the boots of a stateless node (§4.1): the
  former host is held until `idle_ttl` after it stopped, so a longer
  `idle_ttl` leaves room for fewer boots. Machines that share a name and
  each have a certificate of their own, as in two clusters, do not share
  the bound; machines that share one certificate do. The bound is of what
  one connector holds: a certificate can still make 4 new hosts every
  `idle_ttl`, which PostgreSQL keeps for `retention`.
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
With `host_identity: none` an agent may send any `host.name`, and only
`max_hosts` bounds its hosts.

### 5.6 Static inventory

In a cluster whose hosts are known in advance, `inventory_file` lists the
hosts expected, with all their addresses, including hosts that cannot run
an agent (storage appliances, switches, BMCs). It is YAML or JSON:

```yaml
hosts:
  - name: cn001.hpc.example        # host.name, as the agent of the host sends it
    slurm_node: cn001              # the NodeName in Slurm, if the host is a node
    roles: [compute, gpu]          # free text, e.g. for dashboards
    addrs: [10.0.1.1, 10.10.1.1, 10.20.1.1]  # management, IPoIB, storage
  - name: sfa01
    roles: [storage]
    agent: false                   # no agent is expected (default true)
    addrs: [10.20.0.5]
```

- **Addresses come from provisioning** (Warewulf, xCAT, …), not from Slurm:
  `NodeAddr` may be a name and is one address. Each is a single address,
  not loopback, unspecified or multicast, and belongs to one host at most,
  so that an address maps to a host without ambiguity. Floating addresses
  (a keepalived VIP) belong to no host and are left out; `translations`
  (§5.4) describe them.
- **The mapping to Slurm is written**, since `NodeName` may be any alias.
  Host and node names are unique and must not start with `~`. Roles are
  free text, without control characters.
- **Loading.** The connector reads the file at start and every write
  interval, and, when its contents changed (whatever their order and
  layout), replaces the inventory in PostgreSQL in one transaction under an
  advisory lock; it records the time it read them either way. A file that
  cannot be read, is invalid (unknown fields included), larger than 16 MiB
  or has no hosts (as a failed generator may leave) keeps the inventory
  read before, from PostgreSQL if the connector has read none since it
  started, and written again if writing it failed. The failure is logged
  and recorded with its time (`inventory_status`); the record is shared, so
  a connector that reads the file clears the failure of another. A file of
  several YAML documents is invalid. Every connector should read the same
  file, as with `peer_cidrs`: the last to write wins. A connector without
  `inventory_file` leaves the inventory as it is; to drop it, delete the
  rows of `shawk.inventory_hosts` and `shawk.inventory_state`.
- **Generating it.** The connector does not talk to Slurm. A cron job may
  write the file from the provisioning database and `scontrol show nodes
  --json`, to a temporary file renamed over the old one, so that the
  connector never reads half a file.
- **Conflicts.** The inventory wins over what agents send: an agent that
  sends an address the inventory gives to another host is logged at most
  once an hour, with the addresses and their hosts in the inventory.
- **Uses.** `never_observed()` reports the hosts expected to run an agent
  whose agent never reported (§6.2). The host of an address is the row of
  `shawk_v1.inventory_addrs` with that address, at most one, e.g. `LEFT
  JOIN shawk_v1.inventory_addrs i ON i.addr = d.server_addr` for the
  servers of `dependencies`; the connector holds the same mapping
  (`inventory.hostOf()` in `inventory.go`) for the peers it names. Node
  states of Slurm join `shawk_v1.inventory` on `slurm_node` to get the
  host, and are kept apart from it, as time-stamped transitions: the
  inventory holds the current contents only.

### 5.7 Node states and maintenance windows

Slurm powers nodes down to save energy, reboots them and takes them out
for maintenance, so on its clusters stopped agents and observation gaps
are often planned. The connector does not talk to Slurm: every write
interval it reads two files in YAML or JSON, `node_states_file`, which a
cron job generates every minute, and `maintenance_file`, which lists the
maintenance windows registered by hand:

```yaml
# node_states_file
generated_at: 2026-11-04T10:00:00Z     # when the states were read from Slurm
nodes:
  - node: cn001                        # NodeName, mapped by the inventory (§5.6)
    state: [IDLE, POWERED_DOWN]        # or "IDLE+POWERED_DOWN"
    reason: ""
  - host: login01.cluster.example      # or host.name of the agent
    state: [IDLE]
# maintenance_file, for hosts with or without Slurm
maintenance:
  - hosts: [nfs01.cluster.example]
    start: 2026-11-05T09:00:00+09:00
    end: 2026-11-05T18:00:00+09:00     # required; at most 30 days after the start
    reason: firmware update
```

The node states are generated, e.g. `scontrol show nodes --json | jq
'{generated_at: (now | todate), nodes: [.nodes[] | {node: .name, state,
reason}]}'`. `NodeName` may be any alias, so the connector maps it to a host
by `slurm_node` of the inventory (§5.6), when it reads the file, and writes
the host: the state of a past gap stays with the host it had then. Nodes
the inventory does not map are left out, with a warning when they change,
and the reading is written again until they are mapped; without an
inventory, the file names hosts (`host`).

- **Gaps.** `unobserved_reasons()` cuts the gaps of host names
  (`unobserved_by_name()`), whose states and windows these are: a node
  that power saving boots often may get a new host id at every boot (§4.1).
- **Times.** States are written as periods (`node_states`): a state read
  again within 5 minutes (`shawk.node_state_max_age()`) continues its
  period, anything else starts one at `generated_at`. Older or repeated
  readings, from the same file or another connector, change nothing. The
  reason of a past gap is thus the state at that time, never today's.
- **Staleness.** A state not read again for 5 minutes explains nothing
  after that. A file whose `generated_at` is older is not written, with a
  warning; one more than 10 seconds ahead is invalid (the file is
  generated on the host of the connector). When a file cannot be read, is
  invalid (an empty file is) or is larger than 16 MiB, as the inventory,
  what was written from it stays, and the states become stale. Flags are
  names (`DOWN`, `POWERED_DOWN`), as `scontrol` gives them; the `*` of a
  node that does not respond becomes `NOT_RESPONDING`, and the symbols of
  `sinfo` (`idle~`) are invalid.
- **Maintenance windows** are written by the clock of the database
  (`maintenance_windows`) when the file changes, and count from when they
  were written, so a window registered afterwards does not make a past
  failure planned. A window removed from the file is deleted before it
  starts and ends then while in progress, as one whose end is moved to the
  past. A row that ended stays as it was: a window registered again after
  its row ended, e.g. after a file read while it lacked the window or by a
  connector with an older file, gets a new row from then, so the time in
  between is not planned and nothing is lost for good. The file is still
  the whole registry: it is replaced at once (renamed) and is the same for
  every connector. It is written when it changes and again every 5
  minutes, so what a connector wrote from an older file is put right.
- **What is planned.** Power saving (`POWERED_DOWN`, `POWERING_DOWN`,
  `POWERING_UP`) with no other flag than `IDLE`, `ALLOCATED`, `MIXED` (a
  job waits for a node that powers up), `CLOUD` and `POWER_DOWN`, so never
  with `DOWN`, which also follows failed boots and a `ResumeTimeout`,
  `DRAIN`, on which jobs keep running, `FAIL`, `NOT_RESPONDING` or a flag
  unknown here (`shawk.planned_state()`). Powering up ends as the node is
  up, when its agent is expected back, or at the `ResumeTimeout` of Slurm,
  when the node is `DOWN`; without it, a node that resumes would be alerted
  while it boots. Maintenance: a window of the file, or the flag `MAINT` of
  a reservation of Slurm, which is registered with an end; alerts are
  stopped for 30 days at most from the first of the states with `MAINT`
  that follow each other, whatever their other flags and reasons.
  `unobserved_reasons()` reports the state as Slurm had it, `MAINT`
  included, without this bound.

Slurm partitions and states are not labels of the metrics of shawk.

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
               peer_fold, peer_internal, counters_started, unix_traced)
partial_observations(host_id, started_at, period_start, period_end, dropped_flows)  -- periods with drops
host_addrs(host_id, addr, first_seen, last_seen)  -- one row per period
processes(id, host_id, unit, comm, exe, service_name, user_id, first_seen, last_seen)
  -- unique (host_id, unit, comm, service_name, user_id); user_id only for processes of jobs (job_users)
edges(id, host_id, process_id, role, proto, local_addr, remote_addr, port, netns, first_seen, last_seen)
  -- remote_addr is the network 0.0.0.0/0 or ::/0 for folded peers
unix_edges(id, host_id, process_id, path, netns, first_seen, last_seen)  -- clients of Unix sockets (§3.8)
unix_listeners(host_id, process_id, path, netns, first_seen, last_seen)  -- every known owner of a listening Unix socket
listeners(host_id, process_id, proto, addr, port, netns, first_seen, last_seen)  -- the latest owner
listener_owners(host_id, process_id, proto, addr, port, netns, first_seen, last_seen, kernel_chosen_seen)
  -- every known owner; kernel_chosen_seen when the kernel last chose the port (§5.3)
peer_cidrs(prefix, name)  -- written by the connector from its peer_cidrs
translations(name, side, proto, addr, port)  -- side virtual, backend or source; written by the connector (§5.4)
inventory_hosts(host, slurm_node, roles, agent)  -- written by the connector from its inventory_file (§5.6)
inventory_addrs(addr, host)  -- every address of the inventory, one host each
inventory_state(digest, read_at, failed_at, error)  -- when the inventory was read, and the latest failure since
learned_translations(host_id, proto, netns, client_addr, virtual_addr, virtual_port, source_addr,
                     backend_addr, backend_port, first_seen, last_seen)  -- learned by agents (§3.7, §5.4)
known_dependencies(client_service, server_service, port, proto, first_seen, last_seen)
port_agnostic_services(service)  -- written by the connector (§5.3)
dynamic_ports(name, proto, addr, port_from, port_to)  -- written by the connector (§5.3); 0.0.0.0/0 and ::/0 for every host
node_states(hostname, first_seen, last_seen, state, reason)  -- periods of states of Slurm (§5.7)
maintenance_windows(hostname, starts_at, ends_at, reason, registered_at)  -- registered windows (§5.7)
```

With `job_users`, the user (`process.user.id`) of a process of a Slurm job
(a unit `slurm/...`) is part of its identity, so that the jobs of
different users with the same unit, comm and service have rows of their
own: rows grow with users, not with jobs. `user_id` is NULL for other
processes, and for processes of jobs whose user is unknown: the agent
could not read it or does not send it (`-job-users`), the connector does
not keep it, or the row was written before. PostgreSQL 14 has no `NULLS
NOT DISTINCT`, so the identity is a unique index on `coalesce(user_id,
-1)`. Job ids are not kept: edges have only their first and last times, so
joining them with slurmdbd cannot split them by job.

`known_dependencies` keeps every dependency between services ever seen,
refreshed every 5 minutes (`shawk.refresh_known_dependencies()`). When the
connector changes the rules of ports, the next refresh rebuilds the table
from every edge kept under the new rules, so that neither adding nor
removing a rule makes a dependency seen before new, and the dependencies
known on a service of `port_agnostic_services` are also added on port 0
(`shawk.aggregate_known_dependencies()`), for those whose edges are gone.
Ranges of `dynamic_ports` hold for addresses, which `known_dependencies`
lacks, so they are left to the rebuild: a dependency known only outside a
range would hide one new in it. The session columns are described in
§5.1. `service_name` has the form of the `job` label (`namespace/name`), so
names in PostgreSQL and Prometheus match.

### 6.2 Contract (schema `shawk_v1`)

| view or function | |
|---|---|
| `dependencies` | one row per logical dependency: the client edge and the server edge matched by addresses and port over all time (loopback within a host and netns, addresses held by several hosts at once within a host), or through a translation (§5.4), when `virtual_addr`, `virtual_port` and `translation` (`~learned` for a learned one) tell what the client connected to. `observed_by` is `both`, `client` or `server`; a one-sided row means no agent on the other side, an undescribed NAT or load balancer between, or one of the own rows of §5.4. `client_observed_until` and `server_observed_until` are the latest heartbeats of the hosts (or NULL, §5.4): an old `last_seen` with a recent `observed_until` means no longer used; both old means no longer observed. An address `0.0.0.0/0` or `::/0` stands for folded peers (§3.6), named `~external`. `port` is that of the edges, also under the rules of ports (§5.3): between two hosts it tells the connections of different processes apart. A dependency over a Unix socket (§3.8) has `proto` `unix`, port 0, no addresses, and `path`, the last column (NULL otherwise), the name of the socket: its client edge is matched with the owners of the listeners of the name on its host (in the namespace of the client, else, for a path, in the only namespace that has one) whose periods overlap it, within 2 minutes; a matched row lasts the part of the client edge the owner held the listener, except that the row of the first owner starts with the client edge and that of the last ends with it, as a row of TCP spans both its edges (a client keeps the connections it opened after the listener closed, or keeps trying), never longer than the client edge; it has `server_host` the client's and `observed_by` `both`, and an unmatched edge is a row of its own observed by the client. |
| `graph_nodes`, `graph_edges` | the dependency map between services in the format of the Grafana Node Graph; a peer without a service is named by `peer_class`, and a dependency on a port of `port_agnostic_services` or `dynamic_ports` (§5.3) has port 0 |
| `peer_class(addr)` | the name of a peer without a known service, as in `service.peer.name`: the narrowest range of `peer_cidrs`, `~unresolved` for an address not routed on the Internet or no address (the server of a Unix socket without a listener), `~external` otherwise, including the networks of folded peers |
| `dependency_changes` | dependencies between services that appeared, or disappeared while a host that saw them kept observing for 15 minutes; port 0 for those of `port_agnostic_services` and `dynamic_ports` (§5.3), so that a run of srun on a new port is not new |
| `kernel_chosen_ports` | a hint for the rules of ports (§5.3): the services whose port the kernel chose in the last 30 days that no rule covers (`service`, `slurm_job` for processes of Slurm jobs, `proto`, `hosts`, `ports` distinct, `port_min`, `port_max`, `first_seen`, and `last_seen`, when the kernel last chose one). Rules apply to the address clients reach, so a listener on an unspecified address is covered only when they cover every address its host held meanwhile, but loopback and link-local; a process that binds the port it was given leaves after 30 days. A UDP client socket taken for a server (§10) appears too |
| `service_endpoints` | addresses and ports services accept connections on: the last known listeners of each host (unspecified addresses expanded to the host's addresses) and its server edges, for hosts that reported in the last 30 days, except addresses another host took over since; `slurm_job` if a process of a Slurm job serves it; used by the connector (§5.2) |
| `unix_endpoints` | the names of the Unix sockets services listen on (`path`, `netns`, host, service, `slurm_job`), seen within an hour of the latest listener of Unix sockets of the host, for hosts that reported in the last 30 days; used by the connector (§5.2) |
| `client_endpoints` | the client sides of connections in the last hour (client address, server address, port, client service, `slurm_job` if the client is a process of a Slurm job); used by the connector to name the peer of a server edge |
| `agent_addrs` | addresses of hosts whose agent closed an interval in the last 5 minutes, with what the agent traces and folds; used by the connector |
| `agents` | the latest segment of every host and whether its agent is alive; the last columns, `peer_fold` and `peer_internal`, tell what the agent folds and the ranges it keeps exact, and `unix_traced` whether it traces Unix sockets (NULL if it does not tell) |
| `unobserved(since, until, tolerance)` | the periods in which each host was not observed; Grafana overlays them as annotations |
| `unobserved_by_name(since, until, tolerance)` | the same over the sessions of all the host ids of each host name, for nodes whose machine id changed (§4.1), where `unobserved()` reports the time after the last heartbeat of each old id; two machines that share a name hide each other's gaps |
| `unobserved_reasons(since, until, tolerance)` | the periods of `unobserved_by_name()` cut by what explains them (§5.7): `cause` is `maintenance` or `power_saving` for a planned stop and NULL otherwise, `node_state` the state of Slurm then (flags joined by `+`, NULL if none was read or it was stale) and `reason` that of Slurm or of the maintenance window, which takes precedence. The gaps are per host name, as the states and windows are, since a node that power saving boots often may get a new host id at every boot. `unobserved()` and `unobserved_by_name()` do not change |
| `partly_observed(since, until)` | the periods in which each host was observed but its agent dropped flows, cut to `[since, until]`: `host`, `gap_start`, `gap_end`, `dropped_flows` (flow updates dropped). A dependency may be missing from them although it was used; Grafana overlays them as annotations |
| `planned_stops` | hosts in a planned stop now and until when at the latest (`host`, `cause`, `since`, `until`, `reason`): in a maintenance window, or in a planned state of their latest reading from Slurm while it is fresh |
| `never_observed()` | the hosts of the inventory (§5.6) expected to run an agent whose agent never reported within the retention (no host has their name): `host`, `slurm_node`, `roles`, and `seen_as`, the hosts whose agents reported an address of the host, as an agent whose `host.name` differs from the inventory would |
| `inventory`, `inventory_addrs` | the hosts of the inventory with their addresses (`host`, `slurm_node`, `roles`, `agent`, `addrs`), and one row per address with its host: join an address on `addr` to name its host |
| `inventory_status` | when the inventory was last read from a valid file (`read_at`, NULL if never), the latest failure since (`failed_at`, `error`), and how many hosts it has; no row before a connector with `inventory_file` read it |
| `job_edges` | the edges of the processes of Slurm jobs, those to Unix sockets included (with `path`), with the user of the process (`user_id`, NULL if unknown), host, unit, service and executable: which users connected to what, and when. For administrators: only its owner reads it (below) |
| `dependencies_between(since, until)`, `graph_edges_between`, `graph_nodes_between`, `dependency_changes_between` | the same for the dependencies active in a period. They take the edges active in the period with a margin of 15 minutes before matching, so a recent window does not scan the history (about 0.3 s instead of 3 s with a million edges) and both sides of a connection are matched at the edges of the period; the dashboards and alerts use them. A dependency appeared in a period when it was first seen in it and is not in `known_dependencies` from before it, so one that comes back on new edges (a new container, an hourly job) did not appear |

The connector role writes `shawk` and reads `shawk_v1`; Grafana reads
`shawk_v1` only (`packaging/postgres`). Neither may create objects in the
database (tables or functions in `public`, temporary tables, large
objects). The read-only transactions and statement timeout that `setup.sql`
gives Grafana are session defaults it could change; the privileges are what
hold.

Neither reads `job_edges`: user ids with executables, peers and times tell
the activity of the jobs of other users, and every viewer of Grafana can
send SQL through the data source, so the users are for administrators in
this version. `grants.sql` takes the view back from the connector and
Grafana in the transaction that grants them the rest of `shawk_v1`, so
that no session sees them on it in between, and the schema revokes what
default privileges grant as it creates the view. Only the owner reads
it, or a role of administrators the owner grants it to. The rest of the
contract shows no user, but with `job_users` the processes of a job of
different users are rows of their own, and so are their edges:
`dependencies` and `dependencies_between()` have a row per user where
they would have one, so their readers, Grafana included, can count the
users of the executable of a job and tell when each was active. Views of
their own jobs for users would be designed separately.

## 7. Counting each dependency once

When both ends run an agent, a dependency appears on the client side
(`shawk_role="client"`) and on the server side (`shawk_role="server"`). The
recording rules in `packaging/prometheus/shawk-rules.yml` count it once:

| metric | per dependency | recording rules (`shawk:dependency_…`) |
|---|---|---|
| connections, open connections, bytes, datagrams, RTT | the client side; the server side only when the client has no agent (`shawk_peer_agent="false"`) | `connections:rate5m`, `open_connections`, `request_bytes:rate5m`, `response_bytes:rate5m`, `request_datagrams:rate5m`, `response_datagrams:rate5m`, `rtt_seconds_sum:rate5m`, `rtt_seconds_count:rate5m` |
| connection failures, by reason, handshakes, SYN retransmissions | the client side only (the server never sees them, and its side of a handshake is not measured) | `connection_failures:rate5m`, `connection_failures_by_reason:rate5m`, `handshake_seconds_sum:rate5m`, `handshake_seconds_count:rate5m`, `syn_retransmits:rate5m` |
| retransmissions | both sides: each counts its own retransmitted segments; `shawk_role` is the sender | `retransmits:rate5m` |

A dependency over a Unix socket is seen on its client side only (§3.8),
which the rules count, with `network_transport="unix"` and `server_port`
0; it has no bytes, datagrams, RTT, handshakes or retransmissions.

The two sides differ in `shawk_role`, so their `or` is a union. The rules
label the client `src` and the server `dst` whichever side observed the
dependency, e.g. `shawk:dependency_connections:rate5m{src, dst,
server_port, network_transport}`.

Behind a translation with sources (§5.4), the server sees the relay
(`shawk_peer_agent="false"`) and counts the connections of every client of
the relay, while the clients that run an agent count theirs. Each
dependency is counted right, but the sum into the server counts those
clients twice, since the server cannot tell its clients apart.

The family per peer host (§5.3) is counted once the same way, per metric,
by `shawk:host_dependency_…{src_host, src, src_network, dst_host, dst,
dst_network, server_port, network_transport}`: `src_host` is the host of
the client and `dst_host` that of the server, on the client side its
`instance` (the host name) and its `shawk_peer_host`, on the server side
the other way round. `src_network` and `dst_network` are the networks of
their addresses likewise, from `shawk_local_network` and
`shawk_peer_network`, and are not set without `networks`, nor for Unix
sockets, which have no address.

| metric | per dependency | recording rules (`shawk:host_dependency_…`) |
|---|---|---|
| connections, bytes | the client side; the server side only when the client has no agent | `connections:rate5m`, `request_bytes:rate5m`, `response_bytes:rate5m` |
| failures by reason, handshakes, SYN retransmissions | the client side only | `connection_failures_by_reason:rate5m`, `handshake_seconds_sum:rate5m`, `handshake_seconds_count:rate5m`, `syn_retransmits:rate5m` |
| retransmissions | both sides; `shawk_role` is the sender | `retransmits:rate5m` |

The exception above remains: behind a translation with sources, the server
side also counts the clients that run an agent.

## 8. Grafana

`packaging/grafana` holds data sources, dashboards (fleet, dependency map,
dependency details, peer hosts, changes, application layer of OBI) and
alert rules. The peer hosts dashboard needs `peer_hosts` (§5.3): the hosts
towards the selected services, and failures, connect times and traffic by
peer host; a host that accepts no connection, such as one that is down,
shows a failure ratio of 100%. With `networks`, a table gives the
connections and bytes of the selected services by the networks of the
client and the server.

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
alive is not alerted. Neither alerts hosts in a planned stop (§5.7): the
Grafana alert excludes `shawk_v1.planned_stops`, and `ShawkAgentDown` the
nodes a Slurm exporter reports in power saving (powered down, powering down
or up, with no flag but `IDLE`, `ALLOCATED`, `MIXED`, `CLOUD` and
`POWER_DOWN`) or in a `MAINT` reservation, joined on the host name. The
example in `packaging/prometheus/shawk-rules.yml` assumes
`slurm_node_state{node, state}`; the metric, its labels and the mapping of
`NodeName` to `host_name` are replaced with those of the exporter in use. A
state is current only while the exporter is scraped, so a stale state stops
nothing. Prometheus does not know the windows of `maintenance_file`: in the
first 24 hours of one, `ShawkAgentDown` fires unless it is silenced in
Alertmanager or is a `MAINT` reservation. A node that resumed is alerted if
its agent does not send within the minute of `for` after it is up.

The fleet, dependency details, peer hosts and changes dashboards overlay
the periods from `unobserved()` and `partly_observed()` as annotations, so
the absence of a dependency is not read as disuse over them. The table of
gaps of the fleet dashboard gives their reasons (`unobserved_reasons()`),
per host name as `unobserved_by_name()`: the old ids of a node whose
machine id changed have gaps in the annotations, not in the table. SYN
retransmissions per connection attempt (handshakes plus failures) exceed 1
when connects time out, and `TCP_FASTOPEN_CONNECT` connects, which have no
handshake, raise them. OBI panels use a minimum interval of a minute, since
OBI exports every 60 seconds by default.

Where the absence of a dependency is read (the changes dashboard, and the
observation periods of the fleet dashboard), the panels say that only TCP,
UDP and Unix stream sockets are observed; the fleet dashboard shows which
agents trace Unix sockets (`unix_traced`), and `ShawkUnixNotTraced` alerts,
as `ShawkUDPNotTraced`, on agents that do not. `ShawkConnectionFailureRate`
leaves out the failed connects to Unix sockets that no listener serves
(`~unresolved`): glibc tries the socket of nscd from every process that
looks up a user or a host, and most hosts do not run nscd; the dashboards
still show them. Below the changes, the changes dashboard lists the
services on ports the kernel chose that no rule of ports covers
(`kernel_chosen_ports`, §5.3), over the last 30 days whatever the time
range. The fleet dashboard shows the traffic of the RDMA
ports of each host (`shawk.agent.rdma.io`) below the observation periods,
as a hint only (§10).

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

- **TCP, UDP and Unix stream sockets only.** "Observed and not used" holds
  for TCP and UDP sockets and the connections of Unix stream and seqpacket
  sockets (§3.8), not for datagram Unix sockets (syslog, journald,
  `sd_notify`), unnamed pairs, pipes or shared memory. RDMA verbs
  (InfiniBand, RoCE) bypass the sockets, so the RDMA
  transports of MPI (UCX) and NCCL, Lustre o2ib, GPFS verbs and NFS over
  RDMA are not seen, even when their control connections over TCP are; TCP
  over IPoIB is. In HPC clusters the main data paths use RDMA, so a storage
  server used over o2ib looks observed and unused. The counters of RDMA
  ports (§4.2) are a hint, not a coverage guarantee like `udp_traced`: they
  cover a whole port, all its virtual lanes and IPoIB included, so an
  increase tells neither which hosts nor which jobs used RDMA, and no
  increase does not prove that no RDMA dependency was missed (a counter of
  32 bits stops at its maximum). The sockets of kernel clients (NFS, Lustre
  over TCP) belong to cgroup 0 and are named `~kernel` or after their port
  (`~kernel:nfs`, §4.1): shawk tells which hosts use a file system, not
  which users or jobs; usage by job is left to the file systems (Lustre
  jobstats with `jobid_var=SLURM_JOB_ID`). Tracing RDMA connections is not
  done; [rpingmesh](https://github.com/yuuki/rpingmesh) traces those of user
  space from the commands of the uverbs device, and those of the kernel
  from `ib_modify_qp`, which needs the BTF of `ib_core`. See
  [proposals/slurm-hpc-clusters.md](proposals/slurm-hpc-clusters.md) §7.
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
  recorded as a server, unless it is connected on a port the kernel chose;
  unconnected on such a port, it is also listed in `kernel_chosen_ports`
  (§5.3). A
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
  ports rpcbind assigns. Ports set in configuration are not read: LNet with
  another `accept_port`, or BeeGFS with other `conn*Port`s, is named after
  the port it moved to like any other. A socket created by a process and
  then held by the kernel alone (an `nbd` or iSCSI connection whose process
  exited) is not the kernel's: adopted at startup it is not attributed. A
  listener with `sk_user_data` (e.g. in a BPF sockmap) held by a process in
  another PID namespace is taken for the kernel's; run the agent in the
  host PID namespace.
- **Machine ids that change at every boot** (§4.1) make a new host per
  boot: `unobserved()` reports false gaps for the old ids, which
  `unobserved_by_name()` does not, and `host_id` changes in Prometheus. The
  host key stays the hash of the machine id and the name: keying by the
  name would need a migration of the hosts, sessions and processes, and
  would affect `host_id`, OBI's `host.id` and `host_identity: certificate`.
  Host names are not rewritten either (a domain dropped to match a Slurm
  `NodeName`): names could collide and certificates stop matching.
- **Slurm clusters.** The processes of jobs are recognized on cgroup v2
  only, under the scope of slurmstepd in a slice from the root (§4.1): with
  cgroup v1 or another hierarchy they are named as other processes, after
  their `OTEL_` variables too, so a job can take the name of a service. Job
  ids are not kept (§6.1). A server whose port changes at every run makes a
  new dependency each time unless the rules of ports cover it (§5.3): ports
  chosen by the kernel are a hint for the rules
  (`kernel_chosen_ports`), which misses listeners shorter than an
  interval. Connections that end before the
  agent attached its programs are not observed, whatever the start order
  (§4.3). Node states map to hosts through the inventory, and alerts in
  Prometheus stop only for the states of a Slurm exporter, not for the
  windows of `maintenance_file` (§5.7, §8).
- **Networks** (§5.3) classify the addresses at the two ends of an edge,
  not the path or the interface: they do not tell apart the NICs of one
  subnet or of a bond, and a connection routed between two networks has
  the network of each end. A container behind NAT has the network of its
  own address, not of its host's.
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
- **Unix sockets** (§3.8): their traffic is not measured, only their
  connections. A failed connect has the name the client asked for, which
  differs from the server's when the client reaches it through a link or a
  mount, so its failures are on an edge of their own. The server is the
  owner of the listener of the name in the namespace of the client, else,
  for a path, the only one on the host: servers that bind the same path in file systems
  of their own (systemd's `PrivateTmp=`) in one network namespace are not
  told apart, and a client from another namespace of a name that several
  namespaces listen on is not named. A listener appears up to a minute
  after it opened (an interval after a client connected) and stays until
  the scan after it closed. A connection that the client passed to another
  process stays with the process that connected. Connections that predate
  the agent are not adopted when both sides bound names and the listener is
  gone. More open connections than the table holds (half of `-max-flows`)
  are dropped updates, and the period is partly observed.
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
