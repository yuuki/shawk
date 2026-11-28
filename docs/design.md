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
  (§8). `shawk-impact` reads PostgreSQL to tell what removing a host would
  break (§6.3), and `shawk-policy` to write, for review, the rules that
  allow what a host was seen to do and a baseline of the dependencies of
  services, against which the connector reports a drift (§6.4).

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
With `-classify-protocols`, a TCP flow also records the wire protocols
that the first payloads of its connections showed, such as the version of
TLS (§3.9).

### 3.2 TCP: tracepoints and socket iterators

| hook | role |
|---|---|
| `tp_btf/inet_sock_set_state` CLOSE→SYN_SENT | active open, inside `connect(2)`, so the current task is the client; key and owner go to socket local storage |
| SYN_SENT→ESTABLISHED / →CLOSE | an established or failed outgoing connection, with its handshake, retransmitted SYNs and failure reason |
| SYN_RECV→* | passive open: an incoming connection |
| *→CLOSE | the remaining bytes |
| `iter/tcp` (every interval) | byte deltas of long-lived connections, RTT, open connections, listening sockets, adoption of connections that predate the agent |
| `iter/task_file` | owners of adopted connections, MPTCP connections and listeners; stands in for `iter/tcp` where its walk skips connections (below) |

Compared with the original kprobes (`tcp_v4_connect`, `inet_csk_accept`,
`tcp_sendmsg`, `tcp_cleanup_rbuf`), this costs nothing per message (the
classification of wire protocols, which is opt-in, is the one exception,
§3.9): in the
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
iterators in every namespace of the host, and reads them, one namespace at a
time: the files it holds do not grow with the number of namespaces. The
namespaces are found through the bind mounts of `ip netns`, CNI and Docker
(`/run/netns`, `/var/run/netns`, `/run/docker/netns`), which keep their
namespace, and through `/proc/*/ns/net`, whose process may exit, and its PID
be reused in another namespace, before the walk. Each namespace keeps up to
four paths, bind mounts first, then the lowest PIDs; the agent checks that
the file it opened is the namespace it listed (device and inode), else it
tries the next path, and skips the namespace for the walk when none is left.
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
while the kernel closes the socket takes it first, on every kernel, so the
error that ends a connect is recorded before the kernel stores it (#166):
a reset by `tp_btf/tcp_receive_reset`, first in `tcp_reset()`, and an ICMP
error by kprobes on `ip_icmp_error()` and `ipv6_icmp_error()`, which
`tcp_v4_err()` and `tcp_v6_err()` call in SYN_SENT with the error. Kprobes
have no socket local storage, so the error is kept in an LRU hash keyed by
the socket, which the state change takes when the socket leaves SYN_SENT.
An ICMP error that arrives while a task holds the socket is soft
(`sk_err_soft`, read at the close) and the connect goes on, so it is not
recorded. The hooks run only on failed connects; the state change of every
connect looks the hash up once. Without them (no kprobes, §10) the reason
is read from `sk_err` as before:

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
([research/kernel-hooks](research/kernel-hooks/kernel_hooks.md)). fentry
needs BPF trampolines, which arm64 has since Linux 6.0 and RHEL 9 since
kernel 5.14.0-621 (Rocky Linux 9.8, not 9.6). Where the fentry programs do
not attach, kprobes on the same functions stand in for them (#118), with
the same work: the direction of a socket is then kept in an LRU hash keyed
by the socket, with its inode, which tells it from a former socket at the
same address (`udp_kstates`, sized as the listening ports); a socket whose
entry the LRU evicted is decided again by its next datagram. The inode is
that of its `struct socket`, not of its file, which the sockets of the
kernel (nfsd, lockd, VXLAN) lack: with the inode 0 of their missing file,
one would take the direction of a former one at its address (#256). The
agent logs that UDP is traced with kprobes. Without either it traces TCP
and reports that UDP is not traced. Misattributions are listed in §10.

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
| fentry, fexit (UDP, Unix sockets and wire protocols only) | 5.5 on x86_64, 6.0 on arm64 (RHEL 9 on arm64: 5.14.0-621, in 9.8, not in 9.6); UDP and Unix sockets fall back to kprobes (`CONFIG_KPROBES`, `perf_event_open`), wire protocols (§3.9) are not classified |
| kprobes on the module nf_conntrack (translations, §3.7; `CONFIG_KPROBES`, the system call `perf_event_open`) | `__nf_conntrack_confirm`, and `nf_ct_destroy` since 5.19 and in RHEL 9, `destroy_conntrack` before |
| kprobes on `ip_icmp_error` and `ipv6_icmp_error` (the ICMP errors of failed connects, §3.2; `CONFIG_KPROBES`, `perf_event_open`) | any; without them, the reasons of such failures race with `SO_ERROR` |

CI loads the programs on the Ubuntu runner kernels (6.8 to 7.0, x86_64 and
arm64) and in VMs (`make vm-test`) on Rocky Linux 9.6 (x86_64, aarch64),
upstream 5.14 (x86_64) and 5.15 (x86_64, aarch64); on aarch64 before 6.0
the UDP and Unix socket tests require the kprobe fallback.
`TestUDPKprobes` and `TestUnixKprobes` force it on the other kernels.
A VM run fails when the kernel was tainted while the tests ran, e.g. by a
warning; the one exception is a false positive of RCU Tasks Trace that
upstream 5.14 reports at random (`test/harness/README.md`).
All struct accesses use CO-RE. `make compat` checks every attach target,
helper, CO-RE relocation and `BPF_PROG`
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
  goes, so `xlat_conns` holds the live entries and a translation is in use
  in every interval in which one of its connections is open, as edges are.
  An entry outlives its connection by its conntrack timeout (up to 2
  minutes), within the margin of matching (§5.4); an established entry whose
  peer vanished stays 5 days, but the rows it matches are still bounded by
  the edges. A missed destroy (a kprobe is skipped while another BPF program
  runs on the CPU) keeps a translation live until conntrack reuses the
  entry's memory.
- With folding (§3.6), a translation whose source, client or backend is
  outside the internal ranges is not learned, nor, with `all`, one whose
  virtual address is: no edge would match it, and the Internet clients of a
  published port stay out of the table. `-netns` restricts translations to
  one namespace.
- The translations confirmed in an interval are recorded in `xlats` with the
  index of the flow maps, which user space reads and deletes after the flip
  (§3.4); the programs alone add and delete the entries of `xlat_conns`.
  User space thus writes nothing that a program may update at the same
  time, and a confirm or a destroy during a read is not lost (#237).
  `xlats` holds `-max-flows` translations confirmed in an interval and
  `xlat_conns` four times as many live entries (about 9 MiB at the
  default), allocated only once nf_conntrack is loaded (most RHEL 9 hosts,
  whose firewalld loads it, and hosts with Docker or kube-proxy). Overflow is counted in `shawk.agent.translations.dropped`; a
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
| `fexit/unix_stream_connect` | in `connect(2)` of the client: an established connection, recorded in `unix_conns`, or a failed connect with its reason |
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
  name that no scan found in its namespace requests one at the next
  interval, so a new server is named an interval later, also when another
  namespace listens on the name. A client that reaches the listener of a
  path in another namespace through a mount requests such a scan again
  after each periodic one. The owner is chosen as for TCP: the
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
- If the trampolines do not attach, the agent tries kprobes on the same
  functions. The entry probe of `unix_stream_connect` saves the socket,
  address and length by task in a 1024-entry LRU hash. The return probe
  removes them and accounts for the result. A return whose arguments were
  evicted counts as a dropped update. If the kernel misses a return probe
  while too many connects are in flight, that result is lost. Both paths
  share `unix_conns` with the owner scan. If neither set attaches, the agent reports
  `shawk.agent.unix.traced` as 0. `-max-flows` sizes the tables of Unix flows to
  a quarter of it and that of their open connections to a half, at least
  1024 each (about 3.6 MiB at the default); a connection that does not fit
  is a dropped update (§10).

### 3.9 Wire protocols of TCP connections

A port does not tell which protocol a dependency speaks when the service
is not on the port of its protocol, nor whether it uses TLS, and which
version: the questions before TLS 1.0 and 1.1 are turned off on a server,
or before a database is made to refuse clients in clear text. With
`-classify-protocols` (off by default) the agent reads the first payload
that the local socket of each new TCP connection sends, once, and records
the wire protocol it shows in the flow: the request of a client, the answer
or the greeting of a server. PostgreSQL keeps when each edge first and last
saw each protocol (`shawk_v1.edge_protocols`, §6.2); Prometheus does not
have them, so they add no series.

| hook | role |
|---|---|
| `tp_btf/inet_sock_set_state` | marks, in the socket storage, the connections that a process opens in `connect(2)` and the incoming ones, once the program below is attached |
| `fentry/tcp_sendmsg` | the first send of a marked connection, once established: up to 512 bytes of its data, from the memory of the process (one buffer, or the first 4 iovecs), are classified (`wire_classify()` in `internal/tracer/bpf/wire.h`) and wiped, and the mark is cleared; a first send of 4 bytes is held for the next one |

- **Why a hook on every send.** No hook that runs once per connection sees
  its first payload: the tracepoint of §3.2 runs before any data, and the
  data is gone or not yet sent at the walks. Of the hooks that could stop
  per socket, sockops programs see the headers of segments, not their
  payload, and sk_msg programs run only for the sockets of a sockmap,
  which replaces their protocol operations. So `fentry/tcp_sendmsg` runs on
  every send and returns at once for the connections that sent.
- **Cost.** An empty fentry program costs 0.03 to 0.04 µs per run on arm64
  ([research/kernel-hooks](research/kernel-hooks/kernel_hooks.md) §2). A
  saturated loopback request-response (`tcp_rr`) sends twice per round
  trip, so the hook adds about 0.06 to 0.08 µs to its 3.2 to 3.9 µs, about
  2 %, and the lookup of the socket storage adds to that. `-bpf-stats`
  measures the program (`shawk_tcp_sendmsg`), not the trampoline around
  it. The copy, the classification and the wipe run once per connection.
  A kprobe has no socket storage and costs more per run, so where
  trampolines are missing (§3.5) wire protocols are not classified. The
  agent logs it and tells it (`shawk.agent.protocols.classified`,
  `protocols_classified` of `shawk_v1.agents`, alert
  `ShawkProtocolsNotClassified`), so that an edge without protocols is not
  taken for one in clear text.
- **What is read.** 512 bytes rather than the 64 the issue proposed. The
  version field of a ClientHello of TLS 1.2 and 1.3 is 1.2 in both, and
  the version offered is in the extension `supported_versions`. With a
  server name of 22 bytes, that extension starts at byte 213 for Go 1.27,
  252 for Python with OpenSSL 3.5, 267 for OpenSSL 3.0 and 279 for Java
  21. It moves with the server name: a ClientHello of Java whose server
  name is longer than about 245 bytes is `tls`. A first send of exactly 4
  bytes that matches nothing is held and classified with the next send,
  because Slurm before 24.05 sends the length of a message apart. The data
  of the kernel (`ITER_KVEC`), pages (`ITER_BVEC`) and user memory that is
  paged out are not read. The bytes read may hold credentials (an
  `Authorization` header, the user of PostgreSQL, the `AUTH` of Redis):
  they are wiped from the per-CPU buffer once classified, and only the
  protocol leaves the kernel.
- **Not classified**, rather than by the middle of their stream:
  - connections that predate the agent;
  - connections whose first payload `sendfile(2)` or `splice(2)` sends:
    before Linux 6.5 through `tcp_sendpage()`, which the program does not
    see, and since then as pages, which it does not read;
  - the sockets of a sockmap with sk_msg programs, which send in
    `tcp_bpf_sendmsg()`;
  - connections that `sendmsg(2)` opens with `MSG_FASTOPEN`, with a
    cookie or not, and those of `TCP_FASTOPEN_CONNECT` with a cookie,
    whose SYN carries their first data;
  - a client whose first send blocks before its handshake ends (a
    blocking send in another thread than `connect(2)`, or after a
    non-blocking `connect(2)`): the program runs before the send waits,
    and the next send finds data sent;
  - a send that preempts another run of the program on its CPU: the
    recursion guard of trampolines (since Linux 5.12) skips it, and the
    next send finds data sent;
  - MPTCP connections, which send through their MPTCP socket;
  - sockets restored in `TCP_REPAIR` (CRIU), whose queues are sent again;
  - the sockets of the kernel (NFS, iSCSI), whose data is not read.
- **Signatures.** The values are a fixed enum (`enum shawk_wire_proto`).
  An answer is a first payload sent after the socket received data: a
  server of PostgreSQL or Redis answers, while one of MySQL, SSH, SMTP or
  POP3 greets first.

  | value | first payload of a client | of a server |
  |---|---|---|
  | `tls_1_0`, `tls_1_1`, `tls_1_2`, `tls_1_3` | a ClientHello, by the highest version it offers: its version field below TLS 1.2, then `supported_versions` (GREASE skipped); also one in the format of SSL 2.0 (Java 6, OpenSSL 0.9.8), by its version | a ServerHello, by the version it chose: its version field below TLS 1.2, then `supported_versions`, which only TLS 1.3 sends, or, when the bytes read do not hold its extensions, a cipher suite that only TLS 1.3 has (`0x13xx`, and SM4 of RFC 8998) |
  | `tls` | a ClientHello whose version the bytes read do not tell: `supported_versions` beyond 512 bytes, or a ClientHello split across records | the alert that refuses a client; a ServerHello split across records |
  | `http1` | a request line in clear text: a method (`GET`, `POST`, ...) and a target of HTTP, a path, an absolute URI of `http` or `https`, `*` of `OPTIONS`, or the host and port of `CONNECT` | a status line (`HTTP/1.`) |
  | `http2_grpc` | the preface of HTTP/2 in clear text (h2c, gRPC without TLS) | a SETTINGS frame |
  | `ssh` | `SSH-` | `SSH-` |
  | `postgres` | a StartupMessage of protocol 3.x, in clear text | as an answer: `N` alone, which refuses TLS or GSSAPI, an authentication request or an error |
  | `postgres_tls` | an SSLRequest, which asks for TLS | as an answer: `S` alone, which accepts it |
  | `mysql` | as an answer: a HandshakeResponse41 without `CLIENT_SSL` (MySQL, MariaDB) | the greeting of protocol 10, before it knows what the client asks |
  | `mysql_tls` | as an answer: an SSLRequest, or a response with `CLIENT_SSL` | — |
  | `redis` | an array of bulk strings (RESP of Redis, Valkey) | as an answer: a simple string in capitals ended by CR LF (`+OK`, `+PONG`; not the `+OK` text of a greeting of POP3), an error in capitals, a number, a bulk string, an array, a map or a set |
  | `slurm_rpc` | a message of Slurm 2.3 or later, also to slurmdbd, whose length is that of the send (24.05 and later) or of the sends that follow the length (before; 22.05 to 23.11 send the length, the header, the credential and the body apart) | the same; the answers of slurmdbd, whose header has no version, are `unknown` |
  | `unknown` | none of these | none of these |

  `tls_1_0` includes SSL 3.0 and 2.0. A first record of TLS other than a
  hello, or an alert sent by a client, is `unknown`: it is more likely the
  length of another protocol (a message of 788 to 791 bytes of MongoDB
  starts like one). The header of Slurm before 22.05 has an index of 2
  bytes before the type. A StartupMessage starts its parameters with a
  name, which tells it from a request of Kafka of the same length and
  type. A GSSENCRequest and a CancelRequest of a client, and `G` of a
  server, which accepts GSSAPI, add no protocol: libpq sends a
  CancelRequest on a new connection in clear text whatever `sslmode` says,
  and GSSAPI encrypts what follows without TLS. A greeting of MySQL is
  taken also after data, the header of the PROXY protocol that a load
  balancer sends first.
- **Read as another protocol.** A client that sends the header of the
  PROXY protocol first, as a load balancer does, is `unknown`. A tunnel of
  HTTP `CONNECT` is `http1`, whatever it carries. A server of POP3 that
  greets with `+OK` alone after the header of the PROXY protocol is
  `redis`.
- **Both sides.** A client tells what it offers or asks for, its server
  what it chose. A client that offers TLS 1.3 to a server of TLS 1.2 is
  `tls_1_3` on its side and `tls_1_2` on the server's; a client below TLS
  1.2 cannot reach 1.2, so its side alone finds the clients to upgrade,
  also those of servers without an agent. A client of PostgreSQL that asks
  for TLS (`sslmode=prefer`) of a server that refuses it is `postgres_tls`
  on its side and `postgres` on the server's. The server of MySQL greets
  before it knows, so its side is `mysql` whatever its clients ask.
- **TLS started later.** PostgreSQL and MySQL tell whether TLS is asked for
  and, for PostgreSQL, accepted, but not its version; STARTTLS of SMTP or
  LDAP is not seen. PostgreSQL 17 with `sslnegotiation=direct` starts with
  TLS, of a known version. A client of PostgreSQL that asks for GSSAPI
  first (`gssencmode=prefer` with Kerberos credentials) adds no protocol,
  whatever follows. Kernel TLS (kTLS) is turned on after the handshake,
  which the program reads as any other.
- **Against the issue (#233).** The agent reads what the local socket
  sends, not what it receives: a server is classified by its answer or its
  greeting, and the hook runs on every send rather than costing nothing
  after the first (see the cost above). The enum adds `tls`, of an unknown
  version, and `postgres_tls` and `mysql_tls`, the clients that ask for
  TLS. The protocols are in a view of their own, `edge_protocols`, rather
  than a column of `dependencies`, since an edge may show several.
- **Flows and series.** The program sets a byte per protocol in the flow of
  the connection (`protos` of `struct shawk_flow_stats`), so that
  connections of one flow classified at once on several CPUs set their
  protocols without atomic operations and none is lost. The agent keeps
  when each edge first and last saw each protocol, at the end of the
  intervals that saw it, and sends both with the edge (§4.2), so a TCP edge
  has at most two gauges per value of the enum.

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
  `docker/<project>/<service>` for Docker Compose,
  `docker/swarm/<service>` for Docker Swarm, otherwise
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
  the SLUID otherwise): `user/task_*` and the cgroups under it, containers
  included (`task_special` too, where `pam_slurm_adopt` puts the processes
  it adopts), are named after the kind of their step, `slurm/batch`,
  `slurm/step` (`step_<n>`, `step_<n>+<component>`), `slurm/extern` or
  `slurm/interactive`, and the directory of slurmstepd in a step (`slurm`;
  `slurm_processes` in the documentation) and `<scope>/system` are
  `slurmstepd`, as Slurm's `cgroup/v2` plugin makes them. The scope is
  `slurmstepd.scope`, or `<node>_slurmstepd.scope` with
  `--enable-multiple-slurmd`, recognized only under slices from the root
  (`system.slice`, or the slice of `CgroupSlice`), where users cannot make
  cgroups; other hierarchies, and cgroup v1, keep the rules above
  (`internal/procinfo/cgroup.go`).
- Container names are not trusted blindly. Docker merges image labels into
  container labels, so pod labels are believed only with the container name
  cri-dockerd gives, and Compose labels only with the name Compose gives.
  Only the outermost container of a cgroup, made by a runtime of the host,
  is named from its state: a user with delegated cgroups could otherwise
  create a cgroup named after any container. Host runtimes never create
  cgroups inside a unit, so a container in a unit (a service or a scope,
  which systemd delegates with `Delegate=yes`) is named by id after the
  unit (`user@1000.service/podman-0123456789ab`). Name parts are limited to
  `[A-Za-z0-9_.-]` and 253 characters, so they cannot add a level to the
  unit or the `job`.
- The state is read where the runtimes of the host keep it: the bundles of
  containerd under `/run/containerd`, and under `/run/k3s/containerd` (k3s,
  rke2) and `/var/snap/microk8s/common/run/containerd` (microk8s), which
  run their own; containers/storage of Podman and CRI-O; and the data root
  of every `dockerd` of root in the mount namespace of PID 1, from
  `--data-root` on its command line or `data-root` in its configuration
  file (`--config-file`, `/etc/docker/daemon.json`), found again every
  minute. The agent reads no other command line, and keeps nothing else of
  it; a process of a user, or the `dockerd` of a container, does not tell
  where to read.
- The tasks of a service of Docker Swarm are named `docker/swarm/<service>`
  when their container has the name Swarm gives it,
  `<service>.<slot>.<task id>`, and the labels `com.docker.swarm.*` that
  match it, which Swarm sets over those of the image.
- A container whose state cannot be read is named
  `<runtime>-<12 hex digits>`, which changes when it is recreated: rootless
  containers, runtimes with another state directory (containerd with
  `--state`), `ctr run`. A container in a container (Docker in Docker,
  kind) is named after the outer one.
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
  same cgroup (step) too. The agent reads the executable, the comm and
  `/proc/PID/cgroup` through one open `/proc/PID`, which fails once that
  process exits, so that they are of one process: the executable is used
  only with the comm read with it, and a process that exits while it is
  read is taken as one that exited before. What `/proc` tells of a PID now
  in another cgroup than the flow, one of them a job's, is not used: the
  PID was reused by another job, or `pam_slurm_adopt` moved the process;
  nor is an environment during whose read the process exited, executed
  another executable or changed cgroup. A flow whose cgroup path is not
  known (its event was dropped) learns it from its process if the process
  is still in that cgroup (same inode); otherwise a process now in a job is
  not taken for it.
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
| `shawk.edge.wire_protocol.first_seen`, `.last_seen` | Gauge, `s` | with `shawk.wire_protocol`, the Unix time a connection first and last showed the wire protocol (TCP, `-classify-protocols`, §3.9), for the protocols seen |

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
`shawk.agent.unix.traced`, `shawk.agent.protocols.classified` (§3.9), the drop counters
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
- Each request has a deadline of 2/3 of the interval (at least a second)
  from when it is sent, so that a host with many requests sends them all
  when they take longer together; the requests of an interval together
  take at most 4 intervals. A collection waits for the requests of the
  previous interval, so the intervals of a host whose requests take longer
  than an interval are as long as its requests take, which the agent logs
  (at most every 10 minutes). In a VM of 8 vCPUs, 96 768 edges took 149
  requests and 4.7 s to a local sink, and 9 s on a busy host.
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
  client certificate. `-otlp-server-name` verifies the certificate by
  another name than the host of the endpoint, and asks for it in SNI, for
  an endpoint given by its address, such as a virtual address of a network
  without DNS; over gRPC it is also the authority of the requests. Over
  `http://` the host's dependencies, executables, name and machine id
  travel in the clear, and the agent warns unless the endpoint is
  loopback. The agent does not follow HTTP redirects, so nothing in the
  path can divert the export elsewhere or to `http://`.
- Bearer token. Instead of a client certificate, the agent can send a token
  to a front collector that authenticates agents by tokens (the
  bearertokenauth extension of otelcol-contrib) and forwards to the
  connectors (§5.3): `Authorization: Bearer` with every request, in the
  metadata of gRPC and the headers of HTTP. The token is read at start from
  `-otlp-bearer-token-file` (e.g. a credential of systemd), without the
  white space around it, so a new token takes a restart. The agent refuses
  to start with an empty file, a token that is not one word of visible
  ASCII, or an endpoint other than `https://`, loopback included: in the
  clear the token could be read on the way and replayed, and while the
  collector is down any user of the host could listen on its port and take
  it, whereas TLS verifies the collector. The token is never logged; errors
  hold the path of its file, not its content. A token names no host, so
  any holder can write as any host, as behind a front with certificates
  (`host_identity: none`, §5.5).
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

The wire protocols of TCP edges (§3.9) are upserted the same way into
`edge_protocols`, after their edges in the same transaction: an edge whose
protocol changed is written with it, so that the row of the protocol finds
the row of its edge. `shawk.prune()` deletes them after the edges, in
the same order, so that a write and a prune cannot deadlock. The rows of
an edge it deletes go with the edge: up to 15 rows, which its batch size
does not count.

Edges and listeners of Unix sockets (§3.8) are written the same way to
tables of their own, `unix_edges` and `unix_listeners`, since they have a
name rather than addresses and a port; a listener of a Unix socket
whose owner is not known is not written, and a server edge of a Unix
socket is invalid.

An edge keeps when it was first and last seen, not what happened in
between: a job of every month and a connection that never closes are the
same row. The hours in which an edge was active are therefore kept beside
it, in `edge_activity` (`unix_edge_activity` for Unix sockets): a row per
edge and month with a bit per hour of the month, in UTC. An agent sends
the time it last saw an edge active, the end of an interval, in every
request; the connector sets the hour of that time when the edge is new to
it and whenever the time moves into another hour, so an edge that stays
active is written with its hour once an hour rather than at every write.
The upsert sets bits and clears none: replays, reordering and several
connectors give the same result, as for the times of the edges, and the
hour of an edge whose changes were dropped is set again from what the
agent still sends. The cadence of a dependency is read from these hours
(§6.3).

The agent also sends the time it first saw the edge. Its hour is set only
when it is the hour of the time the edge was last seen, or the one before:
the start of the stretch the edge is active in. An older one would be an
hour alone, weeks before the others, for the edge of a connection that has
been open for weeks when a connector meets it, as one that just started
or that records hours since an upgrade: the hours in between were not
recorded, not idle, and the cadence would read two runs and stay `unknown`
for as long as the period. An hour that is not set tells nothing; one that
is set alone would tell that the dependency stopped after it.

A client edge of a Unix socket also keeps whether one of its connections
was ever established (`unix_edges.established`): an agent reports failed
attempts as an edge too (§3.8), and those of every process at a socket
that nothing serves are no dependency on the services of the host (§6.3).
It is true once the agent reported an opened or an open connection, false
for an edge of failed attempts only, and NULL for an edge that a connector
wrote before it told.

`shawk.prune()` records the latest cutoff it was called with
(`shawk.retention`): the time before it is not observed for the impact
(§6.3), since the edges last seen then are deleted while the session of
an agent that goes on is kept whole. The migration that adds the record
starts it from the oldest time an edge still kept was last seen, for the
prunes before it (§6.3).

- **Why a bit per hour and a row per month.** A row per run of activity
  would have no bound (26000 rows a year for a job of every 20 minutes),
  and a row per edge and day costs 30 times the rows for an edge that is
  always active. A month of hours is at most one row per edge and month,
  about 190 bytes with its index: 12 rows a year for an edge active all
  along, and one for an edge seen once. That is as much as the edge
  itself for each month it is active in: for 1.1 million edges active in
  two months on average, the hours take 401 MB where the edges take 364.
  `shawk.prune()` deletes the months that ended before the retention, and
  the months of an edge go with it.
- **What a bit tells.** A bit that is not set tells that no agent
  reported the edge active in that hour. That is not idle where the host
  was not observed (§6.3), nor before the first bit of an edge written
  before migration 0004, or met by a connector after it was first seen:
  the hours of the past cannot be derived. An hour
  is the resolution: a job of every hour sets every bit, like a connection
  that stays open, whose edge is active in every interval, also without
  traffic.
- **What is not set.** The hours between two requests more than an hour
  apart that the agent sent in one session, as when its requests fail
  for longer while its idle TTL is above an hour: the agent then tells
  only when the edge was last active. With the default idle TTL of 15
  minutes the session ends first, and the time shows as not observed.

The request that closes an interval upserts the segment into
`agent_sessions`, with `last_heartbeat` the time the connector received it,
and the host's addresses, one row per period held (a period ends after 5
minutes unseen). Liveness is thus judged by the connector's clock; the
difference to the agent's is kept as `clock_skew`, shown and alerted on
beyond a minute. The segment starts no later than the request by the
agent's clock, so that, converted with `clock_skew`, it never starts after
its heartbeat. Edges, listeners, translations and processes keep the
agent's times, capped at 2 minutes ahead of the connector, so a clock far
ahead or an agent making times up cannot pin `last_seen` (`greatest()`),
win the choice of most recently seen endpoint (§5.2) or escape the
retention; a first time after the last is taken as the last.

While the database is down, changes accumulate in proportion to the number
of edges, not to time, up to `max_pending_rows` (§5.5). Rows PostgreSQL
rejects as invalid are dropped rather than retried forever; edges and
listeners agents still send are written again. Changes still pending are
lost when the connector crashes, or stops while the database is down, and
agents resend only edges within their idle TTL, so a session starts no
earlier than 2 minutes (the shortest idle TTL) before the first request the
connector received from the host, and again after it dropped changes of the
host; the gap since the previous heartbeat shows as not observed. So does a
session already pending from requests received while the dropped changes
were being written, which skipped the edges those changes held; one that
ended before that start is not written.

The session also keeps `peer_fold`, `peer_internal`, `unix_traced`,
`protocols_classified` and `translations_traced` (NULL for an agent that
does not send them, or a connector that did not keep them) and
`counters_started`
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
before the migrations were consolidated (§6). Writes, those of the
configuration and of the inventory included, the refresh of
`known_dependencies` and `shawk.prune()` take a shared advisory lock that
migrations take exclusively, before any other lock, so that they wait for
a migration rather than deadlock with it. A migration that cannot release
its lock within 5 seconds closes its connection, which releases it.

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
holder again once the new one stops; those of changes it drops (§5.1) no
longer count, so that they are bounded with the pending rows (§5.5). An
address that left a host whose agent is still alive names no host. The
names of `peer_cidrs` are ranges, not hosts. Through a translation,
`pickBackend()` chooses a
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
- The wire protocols of edges (§3.9) are not forwarded, as series or as
  labels: they would multiply the series of every TCP dependency by its
  protocols. PostgreSQL has them.
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
- This state requires the data of a host to reach the same connector: a
  host that moves to another connector and back within `idle_ttl` is
  counted twice, since the first still holds the values it saw before.
  Run one connector per fleet, or spread the hosts over connectors by the
  configuration of the agents, each with the endpoint of one connector
  (e.g. per group of hosts), so that a host moves only when its
  configuration changes. A front collector with the `load_balancing`
  exporter (`packaging/collector/front.yaml`) must route by `host.id` and
  `host.name` (`routing_key: attributes`), not by resource, which changes
  with `host.ip`, `service.version` and `shawk.peer.internal` (#128); over
  a static list of connectors, since a change of the list moves hosts;
  and without the queues of the exporter and of its OTLP exporters, which
  would reorder the requests of a host (§4.3). The connectors behind it
  see its certificate, not the agent's, so they run with
  `host_identity: none` (§5.5).
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

The exporter to Prometheus queues what it sends (`sending_queue`), so that
the connector, which hands its outputs to the batch processor within the
request of an agent, does not wait for Prometheus: without the queue, or
with one that blocks when full, the retries of a batch (for 5 minutes by
default) would block the batch processor, then the connector, and with it
the requests of agents. The queue counts points (`sizer: items`), the
batches being retried included, about 600 bytes of memory each (measured
on outputs of the connector; encoded, a third of it). Its default counts
1000 batches, which bounds no number of points: the batch processor sends
what arrived within 200 ms, a few hundred points for a fleet whose agents
send at different times, up to `send_batch_max_size`. While Prometheus is
down the queue fills; by default, a large fleet or large hosts make batches
that would fill the memory of the collector (1000 batches of 8192 points
take about 4.5 GiB) until `memory_limiter` refuses the requests of agents,
so that PostgreSQL gets nothing either until Prometheus is back. The
example holds 409 600 points, under 250 MiB, which last 4 minutes for a
fleet whose outputs are 100 000 points a minute, where 50 batches would
last 10 seconds: size it to the fleet (the rate of
`otelcol_exporter_sent_metric_points`) and to the memory of the collector.
`send_batch_max_size` bounds batches to 8192 points: the outputs of a host
arrive whole, and a batch larger than the queue would be refused. Points
beyond are dropped (`otelcol_exporter_enqueue_failed_metric_points`) and
leave gaps, possibly in part of the outputs of a host; the next points of a
series carry its totals, but a new series whose first points are dropped
counts from its next ones. OBI's metrics, which are not batched, take an
exporter of their own (`otlp_http/obi`), so that they do not fill the queue
of the connector; its queue counts the encoded bytes of their requests
(`sizer: bytes`, 64 MiB, up to about 3.5 times as much in memory), since a
request is as large as an export of OBI and their points range from
counters to histograms with buckets.

A store that takes Prometheus remote write, such as VictoriaMetrics, whose
OTLP receiver does not translate names as Prometheus's does by default,
gets the same series from the `prometheus_remote_write` exporter of the
collector (`packaging/collector/config.yaml`). Its translation
`UnderscoreEscapingWithSuffixes`, the default of the exporter and of
Prometheus, gives the names above and the same `job` and `instance`;
`resource_constant_labels` with `included: [host.id, host.name]` gives the
labels of `promote_resource_attributes`; and `disable_scope_info: true`
leaves out `otel_scope_name`, which the exporter would put on every series
and Prometheus does not. Its queue (`remote_write_queue`) counts batches,
whatever their size, since the exporter counts nothing else: the example
holds 50, at most about 225 MiB of batches of 8192 points but 10 seconds
for the fleet above, so size it to the outage to cover and to the memory
of the collector; the default of 10000 would fill that memory as above. It
must stay enabled for the same reason, and batches beyond it are dropped
and leave gaps. OBI's metrics take an instance of their own, as they take
`otlp_http/obi`; its queue counts their requests, each as large as an
export of OBI. The store must take points as late as Prometheus does with
its window.

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
  is not used. A matched edge that also matches an edge by address over
  another period (such a relay served the client before, or the client
  also connects to the backend directly) has that row over the period of
  the other edge, with the rules above for `*_observed_until`, and its row
  of its own covers what neither leaves.
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
  at their backend from their source, in its scope (a loopback client or
  virtual address in the host and namespace of the row, a shared address on
  the host of the row, any host otherwise). Overlapping rows within 2
  minutes are combined (two directors in turn), and the matched row covers
  only their span, so a client that moved to another backend leaves the
  former. The rules above apply
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
  load (§5.2). The wire protocols of an edge (§3.9) are held with it, one
  per value of their enum: a point of another value, as of a newer agent,
  is dropped and logged at most once a minute, and one without a value or
  of an edge that is not of TCP is invalid.
- Pending rows (`max_pending_rows`, 10 million), kept while writes fail or
  the schema is not ready. Beyond the bound, the changes of the hosts
  pending longest are dropped whole, as with rejected rows (§5.1). Of
  these, at most 16 sessions per host, each with the ranges its agent keeps
  exact: an agent starts a segment when it starts or after it could not
  send for its idle TTL, so more are pending only when it restarts faster
  than they are written. A new one beyond is not written, and logged at
  most once a minute; the host is not observed over it if it ends before
  the pending sessions are written. The hours of activity of an edge (§5.1) are a pending
  row of 93 bytes of bits per month, however long the writes fail within
  the month.

- Of the baseline (`baseline_file`, §5.9) the connector keeps the file
  as it last parsed it, or the error of reading it (one baseline, of at
  most 10000 services and 100000 dependencies, from a file of at most
  16 MiB), and the result of its last evaluation: at most 1000 drifting
  dependencies, 20 per service, and three counts per service of the file.

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
inventory, the file names hosts (`host`). Host and node names, in both
files, follow the rules of the inventory (§5.6). Reasons are free text,
cut to 4096 bytes, with NUL and bytes that are not UTF-8 replaced as in
the strings of agents: PostgreSQL refuses them, and one of them would
fail the write of every host.

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
  invalid (an empty file is, as is one of several YAML documents or one
  that is only `null`; `{}` or `maintenance: []` says that there is no
  window) or is larger than 16 MiB, as the inventory, what was written
  from it stays, and the states become stale. Flags are names (`DOWN`,
  `POWERED_DOWN`), as `scontrol` gives them; the `*` of a node that does
  not respond becomes `NOT_RESPONDING`, and the symbols of `sinfo`
  (`idle~`) are invalid.
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
  that follow each other, whatever their other flags and reasons. A state
  follows the one before if it was read while that one was fresh, so a
  reservation read after the states became stale (a node left out of the
  file for a while) counts from its own start.
  `unobserved_reasons()` reports the state as Slurm had it, `MAINT`
  included, without this bound.

Slurm partitions and states are not labels of the metrics of shawk.

### 5.8 SQLite lightweight mode

For small to medium single-connector deployments that want shawk's
Prometheus metrics and live 1-hop service map without running PostgreSQL,
the connector can use an embedded SQLite store (`sqlite.path`) instead of
`postgres` (`collector/shawkconnector/sqlite.go`). It uses pure-Go SQLite
(`modernc.org/sqlite`), keeping the collector static (`CGO_ENABLED=0`) and
compatible with `MemoryDenyWriteExecute=yes` of its systemd unit.

- **Scope.** SQLite is an internal persistence store of one collector
  process, not a public SQL contract like `shawk_v1`. It persists only the
  state `store.peers()` and `inventory_file` fallback need: hosts with their
  latest heartbeat and folding settings, `host_addrs` (30 days), TCP/UDP and
  Unix `listeners` (latest 1-hour window per host, kept 30 days for stopped
  hosts), server-side `server_endpoints` aggregated without client addresses
  (7 days relative to each host's latest report, kept 30 days for stopped
  hosts), `client_endpoints` (1 hour) and `learned_translations` (`idle_ttl`).
  Across collector restarts and dead hosts, `service.peer.name`,
  `shawk.peer.host` and `shawk.peer.agent` keep the same semantics as with
  PostgreSQL, and all Prometheus metrics and recording rules remain unchanged.
- **Bounds and locking.** A file-backed database acquires an exclusive
  non-blocking `flock` on `<path>.lock` so two collectors cannot open the
  same file. It runs in WAL mode (`synchronous=NORMAL`, single serialized
  connection with per-connection PRAGMAs re-applied via driver connection hook,
  `cache_size=-16384`, `mmap_size=0`, `auto_vacuum=INCREMENTAL`), migrates
  its internal schema on start via `PRAGMA user_version` (failing start and
  releasing the lock on a newer or unreadable schema), and prunes each table
  hourly in bounded batches on its fixed window with incremental vacuuming
  regardless of `retention`.
- **What stays PostgreSQL-only.** `job_users`, `node_states_file`,
  `maintenance_file`, `baseline_file` (§5.9) and `postgres.migrate` are
  refused by configuration validation when `sqlite.path` is set. Multi-connector scaling, multi-year
  `first_seen`/`last_seen` dependency history, `dependency_changes` alerts,
  `unobserved()`/`partly_observed()` coverage proofs, `edge_protocols`,
  recursive N-hop maps, the hours of activity (§5.1) and the impact of
  removing a host (§6.3: `impact()`, `impact_verdict()`, `coverage()`, the
  impact dashboard and `shawk-impact`) require PostgreSQL. `shawk-impact`
  fails with that message when its connection string names a file of
  SQLite: the store keeps the state that names peers, 7 days of server
  endpoints without their clients and no observation periods, so nothing
  in it tells that a host was not used, and a verdict from it would be
  from part of the data. Nor do rules or a baseline come from it (§6.4):
  `shawk-policy` refuses it the same way.
- **Packaging.** `packaging/collector/config-sqlite.yaml`, the drop-in
  `packaging/systemd/shawk-collector-sqlite.conf` (`StateDirectory=shawk-collector`),
  and Prometheus-only dashboards `packaging/grafana/dashboards-lite/`
  (`shawk-map-live.json`, `shawk-fleet-live.json`, `shawk-hosts-live.json`).

### 5.9 Baseline of dependencies

`baseline_file` lists, per service, the dependencies that an operator
approved, and the connector tells Prometheus the dependencies of those
services that are not among them: the drift (§6.4). It is YAML or JSON, as
`shawk-policy baseline` writes it for review (§8):

```yaml
services:
  - service: shop/app                 # as in PostgreSQL and the job label
    dependencies:
      - {peer: shop/postgres, port: 5432, proto: tcp}
      - {peer: ~external, port: 443, proto: tcp}
      - {peer: resolvers, port: 53, proto: udp}   # a range of peer_cidrs
  - service: batch/report
    dependencies: []                  # approved to have none
end: {services: 2, dependencies: 3}   # the last line: the file is whole
```

- **Loading**, as the inventory (§5.6): the connector reads the file at
  start and every write interval and, when its contents changed (whatever
  their order and layout), replaces the baseline in PostgreSQL in one
  transaction under an advisory lock (`shawk.baseline_services`,
  `shawk.baseline_dependencies`); it records the time it read them either
  way (`shawk.baseline_state`). Every connector should read the same file:
  the last to write wins. A connector without `baseline_file` leaves the
  baseline as it is, and evaluates nothing. The file is parsed only when
  its size or its time of change differ from those of the last read, and
  every 5 minutes all the same (a change within the granularity of the
  times of a file system is then read late rather than never; a file that
  changed in the 2 seconds before it was read is read again next time):
  parsing a file of the largest size takes most of a second. Between two
  reads the connector holds the baseline of the file, or the error of
  reading it, one of them, which the 16 MiB of the file bound (§5.5).
- **A file that would approve something else than was written is
  refused**, and the baseline read before stays. What a baseline approves
  is what stays silent, so the file is read strictly:
  - It **ends with `end:`**, the last key of the file, with the numbers of
    its services and dependencies. A file that was cut short, by a disk
    that filled or a copy that stopped, is still YAML up to many of its
    bytes: without the last line it would drop the services that follow
    the cut, or approve a service to have no dependency, without a word.
    Every proper prefix of a file that `shawk-policy baseline` writes is
    refused, but the file without its last line break. The counts are
    those of the file as written; they are checked when they are there,
    and a file written by hand may leave them out (`end: {}`).
  - A service must list its dependencies: `dependencies: []` approves
    none, and a service without the key is an error rather than a service
    approved to have none. A baseline of no service is written
    `services: []`. An item that is empty (`-` alone) is refused.
  - A name is a string: one that YAML reads as a number, a boolean or
    nothing (`123`, `true`, `~`) is quoted. It is any name that
    PostgreSQL may hold (valid UTF-8 without NUL, of 4096 bytes at most,
    §5.5), so that whatever an agent names a service, a baseline can
    approve a dependency on it.
  - A port is a decimal number from 0 to 65535, where 0 stands for every
    port: `0443`, which YAML 1.1 reads as 291, `0x1bb`, `+443`, `4_43` and
    `"443"` are refused. The transport is `tcp` or `udp`.
  - Unknown fields, a field given twice, several documents, anchors and
    aliases, a file larger than 16 MiB and an empty file, as a generator
    that failed leaves it, are refused. A service listed twice is refused;
    a dependency listed twice is one.

  The failure is logged and recorded with its time, for every connector
  (`shawk_v1.baseline_status`) and for Prometheus
  (`shawk.baseline.file.failed`): a baseline that no longer follows its
  file must not go unnoticed.
- **A file under review shows what it holds.** `shawk-policy baseline`
  writes a name between double quotes unless it is made of letters,
  digits and the marks of the names of services (`shop/app`, `~external`,
  `nginx.service`), and writes as an escape every character that does not
  print: a line break, a control character, and those that turn the
  direction of a text around or have no width (U+202E, U+200B, U+2028),
  which would show a reviewer another name than the one that is approved.
  Each dependency is on one line.
- **Evaluation.** Every 5 minutes the connector reads
  `shawk_v1.baseline_drift()` and `shawk_v1.baseline_verdict()` over the
  last hour, up to 5 minutes ago, when both sides of a new connection are
  written (§8), and `shawk_v1.baseline_new_services()` over the same
  period, in one read-only transaction of a minute at most. The period
  starts an hour before the previous one ended, so that what was written
  late, by an agent whose clock is behind or after PostgreSQL was down, is
  still judged; after evaluations failed for long it reaches back 24 hours
  at most. An evaluation that failed is tried again a minute later. A
  connector that restarts starts from the last hour: what drifted before
  is in PostgreSQL, and `shawk-policy drift -lookback` reads it.
- **Why the connector evaluates, in SQL.** The drift is a question about
  the fleet, and PostgreSQL is the truth of attribution (§5.2): the names
  that the connector gives peers as it aggregates are the best guess of
  that moment, and a server shows as `~unresolved` until its listener is
  written. A drift judged there would alert on names that settle a minute
  later. The connector therefore reads the contract, like Grafana and
  `shawk-policy drift`, and only sends what it reads; of the baseline it
  holds the file as it last parsed it, and the result of the last
  evaluation.

What the connector knows is sent with every write interval, so that its
series have no gaps, from its first attempt to evaluate. The series of a
service are on a resource whose `service.name` is the service, so that
Prometheus gives them the `job` of the series of its dependencies (§5.3):

| Prometheus name | |
|---|---|
| `shawk_baseline_drift_hosts{job, service_peer_name, server_port, network_transport}` | a dependency that the baseline of the service does not hold; the value is the number of hosts of the service that have it |
| `shawk_baseline_dependencies{job}` | the dependencies of the baseline of a service: the services that are judged |
| `shawk_baseline_hosts{job}` | the hosts that run the service: those on which a process of it was seen within `baseline_host_memory`. 0 for a service that no host is known to run, which nothing judges |
| `shawk_baseline_hosts_unobserved{job}` | of those, the hosts that were not observed for the whole period that was evaluated: what the service did there is not known |
| `shawk_baseline_drift_truncated{shawk_baseline_peer}` | the dependencies that drift beyond those sent, on peers that shawk names (`named`: a service, a range of `peer_cidrs`, `~external`) and on `~unresolved` (`unresolved`) |
| `shawk_baseline_new_services` | the services without a baseline first seen in the period (§6.4) |
| `shawk_baseline_evaluation_timestamp_seconds` | when the last evaluation succeeded; 0 before any did |
| `shawk_baseline_evaluation_attempt_timestamp_seconds` | when the last evaluation was tried |
| `shawk_baseline_evaluation_failed` | 1 while the last evaluation failed |
| `shawk_baseline_file_failed` | 1 while the latest read of a `baseline_file` failed |

The last six are of the connector, under `job="shawk-connector"`.

- **No address and no host.** A series is a service, a peer by its name, a
  port and a transport: the labels of the series of the dependency itself.
  The hosts are a count, so a release that opens a new connection on 500
  hosts is one series, and one alert. `shawk-policy drift` lists the hosts
  and the addresses from PostgreSQL.
- **Unknown is not zero.** No drift is an answer only where the drift is
  known, and each way it is not has a series of its own:
  - *The evaluation.* The connector sends, from its first attempt, whether
    its last evaluation failed, when it was tried and when the last one
    succeeded, 0 before any did: a connector whose evaluations fail from
    the start is told as one, where sending nothing would look like a
    fleet without a drift. `ShawkBaselineNotEvaluated` alerts on the time
    of the last success (§8).
  - *A drift that can no longer be evaluated.* The result of the last
    evaluation that succeeded is sent for as long as none replaces it: a
    drift does not go away because PostgreSQL cannot be read. The time
    of the last success tells how old it is. (A connector that stops
    sends nothing; the alerts hold a drift for 30 minutes after its last
    series, longer than `ShawkBaselineNotEvaluated` takes to fire.)
  - *The hosts.* The drift of a service is known only when every host
    that runs it was observed for the whole period
    (`shawk_v1.baseline_verdict`, §6.4). A host runs a service for
    `baseline_host_memory` (a week by default, from 1 hour to 90 days)
    after a process of the service was last seen on it. Until then a
    host whose agent went silent, with every process it reported, or
    whose clock is so far behind that what it does now is dated before
    the period, counts in `shawk_baseline_hosts_unobserved` rather than
    as a host without the service. The cost is that a host that was
    removed counts for as long: a fleet whose hosts come and go shortens
    the memory. A service of the baseline that no host runs has
    `shawk_baseline_hosts` 0: nothing was there to see what it did.
  - Before a baseline was read from a valid file nothing is judged, and
    the series of the connector alone are sent.
- **Bounds** (§5.5). The `job` of a series is a service of the file: at
  most 10000 services, with 100000 dependencies in all, which the
  connector writes to PostgreSQL. Each service has three series of its
  own (`dependencies`, `hosts`, `hosts_unobserved`). The names of peers
  are what agents send, so the series of the drift are bounded twice: at
  most 20 per service, and 1000 in all. Within a service the dependencies
  on named peers come before those on `~unresolved`, then by the bytes of
  peer, port and transport, so that the same ones are sent every time;
  among the services, the first of each comes before the second of any,
  those on named peers first. A service cannot use up the share of
  another: a process that tries a thousand ports of a private address
  under the name of one service of the baseline cuts 980 series of that
  service, and none of a drift of another. What is cut is counted by the
  kind of its peer in `shawk_baseline_drift_truncated`: a count above 0
  for `named` is a critical alert, since each such dependency would be.
  The names of services and peers are cut to 511 bytes, as
  `service.peer.name` is, and two that are the same once cut are one
  series (with the fewer hosts, and the more of them not observed).
- **Several connectors** with `baseline_file` evaluate the same
  PostgreSQL and send series with the same labels, which Prometheus
  keeps as one: the points of each follow those of the others within
  the out-of-order window (§5.3). The evaluation is part of the work of
  a write interval, like the refresh of `known_dependencies`: while it
  runs, at most a minute, the connector writes nothing.
- **Cost.** On a synthetic fleet of 2000 hosts and 1.13 million edges, of
  which 254000 were active in the hour, the drift of 5 services with a
  baseline is read in 3.1 s when every agent reports, 2.7 s after the
  agents of the 20 busiest servers stopped two hours before, and 2.9 s
  after those of 400 hosts did (35600 dependencies whose server is then
  named by its last known listener); the verdicts of the same services
  take 0.1 s (PostgreSQL 16, one core, the tables in memory). The first
  evaluation after PostgreSQL restarted, which reads the edges from disk,
  took 38 s there: within the minute, and one that is not is tried again
  a minute later, with `shawk_baseline_evaluation_failed` at 1 until it
  succeeds. The dependencies of the period
  are joined with the servers that a listener names by hash
  (`shawk.named_dependencies`, nested loops off): with nested loops the
  second case took 234 s, far beyond the minute of an evaluation, which
  would then have failed for as long as an agent was stopped.
- **Not with SQLite** (§5.8), which keeps no dependencies of a period:
  `baseline_file` is refused by configuration validation.

## 6. PostgreSQL

PostgreSQL 14 or later (multiranges). The schema ships with the connector
as SQL migrations (`collector/shawkconnector/migrations`), applied by
`shawk-migrate` or by the connector with `postgres.migrate`. A schema from
v0.8.0 or a development build before `0001_schema.sql` is refused, with an
error that says to drop the schemas `shawk` and `shawk_v1` (losing their
history) and migrate again. A database is set up with
`packaging/postgres/setup.sql`, then `shawk-migrate`, then `grants.sql`,
which must be run again after every `shawk-migrate` that applies migrations.
A connection string may hold a password, so `shawk-migrate` prints no value
of its command line or environment: the usage of `-dsn` names
`$SHAWK_POSTGRES_DSN` without its value, and its errors are made of
constants and the names of its flags, since escaping or quoting a value does
not hide it. A connection string that pgx cannot parse gives `invalid
PostgreSQL connection string`, as in the connector, and a failed connection
gives its cause and the SQLSTATE of the server, not the error of pgconn,
which quotes the user, the database and the hosts. Errors of the migrations
themselves come from the server after it accepted the connection and are
printed as they are.

### 6.1 Tables (internal, schema `shawk`)

```
hosts(id, machine_id, hostname, kernel, agent_version, first_seen, last_seen)
agent_sessions(host_id, started_at, last_heartbeat, udp_traced, netns_scope, dropped_flows, clock_skew,
               peer_fold, peer_internal, counters_started, unix_traced, protocols_classified, translations_traced)
partial_observations(host_id, started_at, period_start, period_end, dropped_flows)  -- periods with drops
host_addrs(host_id, addr, first_seen, last_seen)  -- one row per period
processes(id, host_id, unit, comm, exe, service_name, user_id, first_seen, last_seen)
  -- unique (host_id, unit, comm, service_name, user_id); user_id only for processes of jobs (job_users)
edges(id, host_id, process_id, role, proto, local_addr, remote_addr, port, netns, first_seen, last_seen)
  -- remote_addr is the network 0.0.0.0/0 or ::/0 for folded peers
edge_protocols(edge_id, protocol, first_seen, last_seen)  -- wire protocols of TCP edges (§3.9), pruned alone or with their edge
edge_activity(edge_id, month, hours)  -- the hours of a month in which an edge was active, a bit each (§5.1)
unix_edges(id, host_id, process_id, path, netns, first_seen, last_seen, established)
  -- clients of Unix sockets (§3.8); established: a connection was, false for failed attempts only, NULL if not told (§5.1)
unix_edge_activity(edge_id, month, hours)  -- the same for the edges of Unix sockets
retention(pruned_before)  -- the latest cutoff of shawk.prune(): the history before it is not whole (§5.1, §6.3)
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
baseline_services(service)  -- the services with a baseline, written by the connector from its baseline_file (§5.9)
baseline_dependencies(service, peer, port, proto)  -- the dependencies approved for them; port 0: every port
baseline_state(digest, read_at, failed_at, error)  -- when the baseline was read, and the latest failure since
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
| `dependencies` | one row per logical dependency: the client edge and the server edge matched by addresses and port over all time (edges with a loopback address on either side within a host and netns, addresses held by several hosts at once within a host), or through a translation (§5.4), when `virtual_addr`, `virtual_port` and `translation` (`~learned` for a learned one) tell what the client connected to. `observed_by` is `both`, `client` or `server`; a one-sided row means no agent on the other side, an undescribed NAT or load balancer between, or one of the own rows of §5.4. `client_observed_until` and `server_observed_until` are the latest heartbeats of the hosts (or NULL, §5.4): an old `last_seen` with a recent `observed_until` means no longer used; both old means no longer observed. An address `0.0.0.0/0` or `::/0` stands for folded peers (§3.6), named `~external`. `port` is that of the edges, also under the rules of ports (§5.3): between two hosts it tells the connections of different processes apart. A dependency over a Unix socket (§3.8) has `proto` `unix`, port 0, no addresses, and `path`, the last column (NULL otherwise), the name of the socket: its client edge is matched with the owners of the listeners of the name on its host (in the namespace of the client, else, for a path, in the only namespace that has one) whose periods overlap it, within 2 minutes; a matched row lasts the part of the client edge the owner held the listener, except that the row of the first owner starts with the client edge and that of the last ends with it, as a row of TCP spans both its edges (a client keeps the connections it opened after the listener closed, or keeps trying), never longer than the client edge; it has `server_host` the client's and `observed_by` `both`, and an unmatched edge is a row of its own observed by the client. |
| `graph_nodes`, `graph_edges` | the dependency map between services in the format of the Grafana Node Graph; a peer without a service is named by `peer_class`, and a dependency on a port of `port_agnostic_services` or `dynamic_ports` (§5.3) has port 0 |
| `peer_class(addr)` | the name of a peer without a known service, as in `service.peer.name`: the narrowest range of `peer_cidrs`, `~unresolved` for an address not routed on the Internet or no address (the server of a Unix socket without a listener), `~external` otherwise, including the networks of folded peers |
| `dependency_changes` | dependencies between services that appeared, or disappeared while a host that saw them kept observing for 15 minutes; port 0 for those of `port_agnostic_services` and `dynamic_ports` (§5.3), so that a run of srun on a new port is not new |
| `kernel_chosen_ports` | a hint for the rules of ports (§5.3): the services whose port the kernel chose in the last 30 days that no rule covers (`service`, `slurm_job` for processes of Slurm jobs, `proto`, `hosts`, `ports` distinct, `port_min`, `port_max`, `first_seen`, and `last_seen`, when the kernel last chose one). Rules apply to the address clients reach, so a listener on an unspecified address is covered only when they cover every address its host held meanwhile, but loopback and link-local; a process that binds the port it was given leaves after 30 days. A UDP client socket taken for a server (§10) appears too |
| `service_endpoints` | addresses and ports services accept connections on: the last known listeners of each host (unspecified addresses expanded to the host's addresses) and its server edges of the 7 days before its latest report, also of a host without listeners such as a UDP server, for hosts that reported in the last 30 days, except addresses another host took over since; `slurm_job` if a process of a Slurm job serves it; used by the connector (§5.2) |
| `unix_endpoints` | the names of the Unix sockets services listen on (`path`, `netns`, host, service, `slurm_job`), seen within an hour of the latest listener of Unix sockets of the host, for hosts that reported in the last 30 days; used by the connector (§5.2) |
| `client_endpoints` | the client sides of connections in the last hour (client address, server address, port, client service, `slurm_job` if the client is a process of a Slurm job); used by the connector to name the peer of a server edge |
| `agent_addrs` | addresses of hosts whose agent closed an interval in the last 5 minutes, with what the agent traces and folds; used by the connector |
| `agents` | the latest segment of every host and whether its agent is alive. `unix_traced` tells whether the agent traces Unix sockets, and `protocols_classified` whether it classifies wire protocols (§3.9); both are NULL if the agent does not tell. `peer_fold` and `peer_internal` tell what the agent folds and the ranges it keeps exact. `protocols_classified` is the last column (migration 0002) |
| `unobserved(since, until, tolerance)` | the periods in which each host was not observed; Grafana overlays them as annotations |
| `unobserved_by_name(since, until, tolerance)` | the same over the sessions of all the host ids of each host name, for nodes whose machine id changed (§4.1), where `unobserved()` reports the time after the last heartbeat of each old id; two machines that share a name hide each other's gaps |
| `unobserved_reasons(since, until, tolerance)` | the periods of `unobserved_by_name()` cut by what explains them (§5.7): `cause` is `maintenance` or `power_saving` for a planned stop and NULL otherwise, `node_state` the state of Slurm then (flags joined by `+`, NULL if none was read or it was stale) and `reason` that of Slurm or of the maintenance window, which takes precedence. The gaps are per host name, as the states and windows are, since a node that power saving boots often may get a new host id at every boot. `unobserved()` and `unobserved_by_name()` do not change |
| `partly_observed(since, until)` | the periods in which each host was observed but its agent dropped flows, cut to `[since, until]`: `host`, `gap_start`, `gap_end`, `dropped_flows` (flow updates dropped). A dependency may be missing from them although it was used; Grafana overlays them as annotations |
| `planned_stops` | hosts in a planned stop now and until when at the latest (`host`, `cause`, `since`, `until`, `reason`): in a maintenance window, or in a planned state of their latest reading from Slurm while it is fresh |
| `never_observed()` | the hosts of the inventory (§5.6) expected to run an agent whose agent never reported within the retention (no host has their name): `host`, `slurm_node`, `roles`, and `seen_as`, the hosts whose agents reported an address of the host, as an agent whose `host.name` differs from the inventory would |
| `inventory`, `inventory_addrs` | the hosts of the inventory with their addresses (`host`, `slurm_node`, `roles`, `agent`, `addrs`), and one row per address with its host: join an address on `addr` to name its host |
| `inventory_status` | when the inventory was last read from a valid file (`read_at`, NULL if never), the latest failure since (`failed_at`, `error`), and how many hosts it has; no row before a connector with `inventory_file` read it |
| `edge_protocols` | the wire protocols of TCP edges (§3.9), one row per edge and protocol: `host`, `host_id`, `service`, `unit`, `role` and `proto` of the side that saw it, `client_addr` and `server_addr` whichever side that was (a network for folded peers), `port`, `netns`, `protocol`, `first_seen`, `last_seen`. A client tells what it offers or asks for, a server what it chose. `last_seen` is the end of the last interval in which a new connection showed the protocol, not the last use of the edge. An edge without rows had no connection classified; `protocols_classified` of `agents` tells whether its agent classifies. The clients of PostgreSQL at 10.0.0.5 that do not ask for TLS: `WHERE role = 'client' AND server_addr = '10.0.0.5' AND port = 5432 AND protocol = 'postgres'`. Rows of `role` `server` tell what the server chose (`postgres` also for a client that asked for TLS and was refused), and give the address of the client, also of one without an agent, which `dependencies` names on `client_addr`, `server_addr` and `port` |
| `job_edges` | the edges of the processes of Slurm jobs, those to Unix sockets included (with `path`), with the user of the process (`user_id`, NULL if unknown), host, unit, service and executable: which users connected to what, and when. For administrators: only its owner reads it (below) |
| `dependencies_between(since, until)`, `graph_edges_between`, `graph_nodes_between`, `dependency_changes_between` | the same for the dependencies active in a period. They take the edges active in the period with a margin of 15 minutes before matching, so a recent window does not scan the history (about 0.3 s instead of 3 s with a million edges) and both sides of a connection are matched at the edges of the period; the dashboards and alerts use them. A dependency appeared in a period when it was first seen in it and is not in `known_dependencies` from before it, so one that comes back on new edges (a new container, an hourly job) did not appear |
| `impact(target_host, since, until, target_service, target_port, target_proto, max_depth, cadence_depth)` | what removing a host would break (§6.3): its dependents in the period, one row per dependent, server and port. `depth` is 1 for the clients of the target and n for the clients of a dependent of depth n-1, up to `max_depth` (3; 1 to 10); `client_host`, `client_service` and, for a client without an agent, `client_addr`, with the name of its address as its service and the host the inventory gives the address; `server_host`, `server_service` (NULL if unknown; `~unknown` for a socket without a known owner; `~relay` for a client whose connections the host relays in its kernel, with the virtual port as `port`), `port` (0 under the rules of ports, §5.3) and `proto`; `first_seen`, `last_seen`, `observed_by`; `cadence` (`continuous`, `daily`, `weekly`, `monthly`, `periodic`, `irregular`, `one-off`, `dormant` or `unknown`), `period` and `next_expected` of a dependent with a period, and `runs`, for the dependents up to `cadence_depth` (1; 0 to 10) and NULL beyond. `target_service`, `target_port` and `target_proto` (NULL by default) narrow the target to a service, a port and a transport |
| `impact_verdict(target_host, since, until, target_service, target_port, target_proto, min_coverage, tolerance)` | whether the target can be removed (§6.3), one row: `verdict` is `UNSAFE` (it has dependents), `INCONCLUSIVE` (none was seen, but the history does not tell so for `min_coverage` of the period, a part from 0 to 1, 1 by default) or `SAFE`; `reasons` tell why (`active_dependents`; `unknown_host`, `no_agent`, `not_observed`, `before_retention`, `dropped_flows`, `netns_limited`, `udp_not_traced`, `unix_not_traced`, `masquerade_not_traced`, `unknown_service`, `unknown_port`) and `caveats` the same shortfalls where they did not decide the verdict; `direct` counts the dependents, those of depth 1 of `impact()`; `coverage` is the part of the period, from 0 to 1 and cut rather than rounded, for which the history tells all that the target covers; `unobserved`, `gaps` and `partly_observed` as in `coverage()`. It fails for a period that is empty, a `min_coverage` that is not above 0 and up to 1, a `tolerance` that is not from 0 to 1 hour, a `target_proto` other than `tcp`, `udp` and `unix`, `unix` without a service or with a port, and a `target_port` that is no port |
| `coverage(since, until, hosts, tolerance)` | how much of a period the history tells what each host of `hosts` (every host that reported since `since` if NULL) was used for, by name: `host`, `agent` (false for a name no agent reported under), `observed` (from 0 to 1, cut), `unobserved` and its `gaps`, of which `before_retention` precedes the retention of the connector, `partly_observed` and `dropped_flows` (`partly_observed()`), and the time observed without UDP (`udp_untraced`), without Unix sockets or by an agent that does not tell (`unix_untraced`), or in one network namespace only (`netns_limited`). Unlike `unobserved_by_name()`, a session ends earlier by the time the clock of its host is behind, and nothing is observed before the retention (§6.3) |
| `coverage_gaps(since, until, hosts, tolerance)` | the gaps of `coverage()`, which the verdict counts: `host`, `gap_start`, `gap_end` and `cause`, `retention` for the time before the retention of the connector and `agent` for the time in which no agent of the name observed. A name that no agent reported in the period has one gap, the whole period |
| `policy_flows(target_host, since, until, target_unit)` | what a host connected to and accepted connections from over TCP and UDP, which least-privilege rules allow (§6.4): one row per `direction` (`egress`, `ingress`), local `service` and `unit`, `proto`, `peer_addr` (as the sockets of the host saw it; a network for folded peers) and `port`, with the ports to allow (`port_from`, `port_to`: the port, the range of `dynamic_ports` that holds it, or 1 to 65535 for a server of `port_agnostic_services`), the name of the peer (`peer`, as in `baseline_observed()`) and its host if its agent saw the connection (`peer_host`), `translated` for a backend that the host itself translates a connection of its own to, `kernel_chosen` for a server on a port the kernel chose, and `first_seen`, `last_seen`. `in_period` is false for a flow last seen before the period, which is listed and not allowed. `target_unit` (NULL by default) narrows the flows to the processes of a unit and of the units under it (`<unit>/...`), with those of the sockets without a known owner of the host (the service `~unknown` without a unit). The rows are in the order of the bytes of their names |
| `policy_verdict(target_host, since, until, target_unit, min_coverage, tolerance)` | whether the history tells every flow of `policy_flows()` (§6.4), one row: `status` is `COMPLETE` or `INCOMPLETE`; `reasons` tell why it is incomplete (`unknown_host`, `no_agent`, `unknown_unit`, `several_machines`, `translations_not_learned`, `not_observed`, `before_retention`, `dropped_flows`, `netns_limited`, `udp_not_traced`) and `caveats` the shortfalls that `min_coverage` (1 by default) accepted, which are those of time alone; `coverage` is that of the least observed machine that reported under the name, and `unobserved`, `gaps`, `partly_observed`, `udp_untraced`, `netns_limited` and `before_retention` how long each shortfall lasted, the longest among those machines; `machines` counts them; `tolerated` and `tolerated_gaps` tell the time that counts as observed although no agent reported in it, within `tolerance` (3 minutes) of a report; `network_namespaces` counts those of the sockets of the flows, `unix_sockets` tells whether the target used Unix sockets, and `translations_traced` is false with `translations_not_learned`. It fails for a period that is empty, a `min_coverage` that is not above 0 and up to 1, a `tolerance` that is not from 0 to 1 hour, and an empty host or unit |
| `policy_gaps(target_host, since, until, tolerance)` | the gaps of `policy_verdict()`: one row per stretch for which the history does not tell the flows of a machine of the host name, with the id of the `machine` (`agents.host_id`; NULL for a name without a machine in the period), `gap_start`, `gap_end` and the `cause` (`agent` or `retention`) |
| `baseline_observed(since, until, services, judged)` | the dependencies of services in a period as a baseline lists them (§6.4), of the services of `services` (every service if NULL): `service` (the service that a baseline judges the client as: its own, or a service of `judged`, by default `services`, that runs in the unit of a client whose own service is not in `judged`), `peer` (the server: its service, as an agent saw it or as its listener names it, else the name of its address as `peer_class`), `port` (0 under the rules of ports, §5.3, and for a server on a port that the kernel chose), `proto` (`tcp` or `udp`: no Unix sockets), `first_seen`, `last_seen`, `hosts` (those of the clients), `addrs` (up to 50 of the addresses they connected to), `named_by` (`edge`, `endpoint` or `address`), `kernel_chosen`, `ports` (up to 20 of the ports that the sockets saw) and `processes` (up to 20 of the other services of the clients) |
| `baseline_verdict(services, since, until, min_coverage, tolerance, hosts_since)` | whether the history tells every dependency of each service of `services`, one row per service: `status` (`COMPLETE`, or `INCOMPLETE` when a machine that runs the service was observed for less than `min_coverage` of the period, or no machine runs it: `unknown_service`), `reasons` and `caveats` as in `policy_verdict()`, `hosts` (how many run it, by name), `coverage` (that of the least observed machine), `short_hosts` (up to 20 of the hosts below `min_coverage`, the least observed first) and `unobserved_hosts` (how many there are). A machine runs the service when a process of it was last seen there since `hosts_since` (NULL: from 15 minutes before the period) |
| `baseline`, `baseline_status` | the baseline that the connector read from its `baseline_file` (§5.9): one row per `service` and approved dependency (`peer`, `port`, where 0 stands for every port, and `proto`; NULL for a service approved to have none); and when it was last read from a valid file (`read_at`), the latest failure since (`failed_at`, `error`) and how many `services` and `dependencies` it holds, no row before a connector read one |
| `baseline_drift(since, until, services, members_since)` | the dependencies of `baseline_observed()` of the services that have a baseline (those of `services` if not NULL) that it does not hold (§6.4), with the same columns. A service without a baseline has no row, unless its process is in a unit that runs a service that has one (a process of it was seen there since `members_since`; NULL: from 15 minutes before the period): it is then judged as that service, and `processes` names it |
| `baseline_new_services(since, until)` | the services without a baseline that were first seen in the period and opened connections (`service`, `first_seen`, `hosts`); not the processes of Slurm jobs, nor the sockets without a known owner. One in a unit that runs a service of the baseline is judged as that service (`baseline_drift()`); another is judged by no baseline |

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

### 6.3 Impact of removing a host or a service

Before a host or a service is removed, three questions are asked together:
what used it, how often, and was anyone watching? `impact()`,
`impact_verdict()`, `coverage()` and `coverage_gaps()` answer them over a
period, and `shawk-impact` prints the answers (§8).

They are in the contract, in SQL, so that Grafana, psql and the command
give the same answer and nothing holds a second copy of the rules: the
command only formats. It is a command of the collector module, shipped
with the collector like `shawk-migrate`, not a subcommand of `shawk`: the
agent has no database driver and holds no database credentials (§2), and a
subcommand would add both to the binary that runs as root on every host.
They need PostgreSQL: the SQLite lightweight mode (§5.8) keeps neither the
dependencies of a period nor when hosts were observed, so nothing in it
tells that a host is unused, and `shawk-impact` refuses a file of SQLite
rather than give a verdict from part of the data.

One rule decides every case below: **`SAFE` is the answer only when the
history can tell that nothing used the target.** A dependent that the
history holds makes the target `UNSAFE`; where the history cannot tell,
the answer is `INCONCLUSIVE`, with the reason.

**The target** is a host by name, the `host.name` of its agent or its name
in the inventory, narrowed or not to a service (`[namespace/]name`), a port
and a transport. A name stands for all the host ids that had it, as in
`unobserved_by_name()`.

**Dependents.** The dependencies of the period are those of
`dependencies_between()`, read once: the matching of the two sides, the
translations and the Unix sockets are those of the dashboards, with their
limits (§10). From them:

- **The server of a dependency that its client alone saw**, as when the
  server has no agent or its agent did not observe then, is found by its
  address: the host that held the address while the dependency was active
  in the period, the host of the client for loopback and for an address
  the client holds too (the gateway of a container bridge), or the host
  the inventory gives the address. The connector ends the periods of the
  addresses of a host when its agent stops (§5.1), so a host that is used
  while its agent is down would hold no address then, and look unused when
  it is least observed. A host therefore keeps the addresses of the last
  report of its agents before they stopped, and already holds those of
  their first report after, until a host of another name reports the
  address; an address that its agents dropped while they went on reporting
  is no longer its own. The service is the latest owner of a listener on
  the port seen since the start of the period, none if no listener is
  known.
- **A host that relays connections in its kernel**, a load balancer, a NAT
  gateway or a node that forwards to the pods of other nodes, accepts
  nothing: the dependency is that of the client on the backend, and the
  relay shows nowhere. Its clients are its dependents all the same, with
  the server service `~relay` and the virtual address and port they
  connected to: the clients of the translations its agents learned from
  conntrack (§5.4), unless the client is on the host itself; the clients
  that reached a backend through a virtual address the host held, by a
  translation of the configuration or one another host learned; and what
  the backends of a translation of the configuration saw while the host
  held its virtual address, since it may have come through it: the
  clients that a backend saw alone, and, through a translation with
  sources, whatever a backend saw from a source, also when a client with
  an agent explains the edge, as the health checks of the director do,
  since a backend cannot tell the clients behind a source apart.
- **A backend on the host itself** changes one thing. When the host
  keeps the address of the client (a published port), the server edge has
  that address: the client is the dependent of the service, once, and the
  translation adds nothing. When the host replaces the address of the
  client by its own (masquerade, as kube-proxy does for a NodePort), the
  server edge has an address of the host, and the translation alone tells
  the client: it stays a `~relay` dependent. Such a client counts for the
  port of the backend as for the virtual port it connected to: the edge
  of the backend may be explained by a process of its own unit, which is
  part of a target that is that port.
- **What counts for a service of a host**: the clients of the service;
  those of a socket of the host without a known owner (`~unknown`, §4.1)
  and those the host relays (`~relay`), since either may be the service's
  and shawk does not know which service keeps the translations of the
  kernel; and those of a port whose owner is not known, seen by clients
  alone, when the host was not observed while they were active, or has no
  agent. A port narrows all of them, and a service given with a port must
  own it. A probe of a port nothing listens on, seen while the host was
  observed, is a dependent of the host and of the port, not of every
  service.
- **Over Unix sockets**, a client whose socket has no server in its
  namespace counts for the services that listened on the name on the host
  in the period, in whatever namespace and at whatever time: a name served
  in several namespaces, or a client that keeps trying after its server
  stopped. If no listener of the name is known, it counts for every
  service of the host (`~unknown`) when one of its connections was
  established, or when the connector that wrote the edge did not tell
  (`unix_edges.established`): the listener may be the service's. Attempts
  that all failed at a name nothing is known to serve reach no service:
  every process of a host without nscd tries its socket.
- **A client is a dependent unless it is part of the target**, and only an
  agent on the target tells that it is. With the whole host as the target,
  a process that the agent saw on the host is part of it, and so is a peer
  on loopback: otherwise every host would depend on itself (a resolver,
  sshd). With a service as the target, the processes of the service are;
  with a port alone, the process that serves the port, by its unit, since
  two instances of the same program have the same service name. The other
  clients on the host, a backup over loopback or an application on the
  Unix socket, break when the service goes and the host stays.
- **An address of the target tells nothing.** A connection from an address
  the target holds, whose client its agent did not see on it, is that of a
  dependent: a host that translates addresses (a published port, a
  NodePort with masquerade) is the source of the clients outside it, and a
  process on the host has a client edge that the agent matches with its
  server (§6.2).
- **Nor does a client on the target, for an edge that others share.** A
  pod sees the kubelet that probes it and every client that its node
  masqueraded as one peer, the bridge of the node: one server edge, which
  matches the client edge of the kubelet and so looks like the node's
  own. The evidence of a client outside wins over that explanation: the
  translation that the agent learned names it (above). Where the agent
  learned none because it could not, nothing tells: an agent that does
  not trace translations, or that folds the peers outside its internal
  ranges (§3.6, the default), whose translations it does not learn
  (§3.7), leaves the clients from outside that the host masqueraded
  nowhere in the history. The verdict on such a host is then not `SAFE`
  for the time a socket of it accepted connections from an address of
  the host in a network namespace in which no client of the host has
  that address (`masquerade_not_traced`). A server in the namespace of
  its client is reached by nothing that the host masqueraded, since what
  is delivered locally is not translated on its way out: a host that
  talks to itself over its own address stays its own. This is the case
  of a Kubernetes node whose kubelet probes its pods, and of a Docker
  host at its defaults, whose `docker-proxy` connects to the containers
  over the bridge: with an agent that folds, such a host has a coverage
  of 0 for as long as those edges last, which no `min_coverage` accepts.
  Once its agent runs with `-fold-external none`, the time before still
  counts: the host is `INCONCLUSIVE` until the period asked for starts
  after the change (10 days after it, a period of 90 days has a coverage
  of 0.11, and one of 9 days is `SAFE`).
- **A dependent with an agent is followed**: the clients of its service on
  its host are the dependents of the next depth, up to `max_depth`. Each
  dependent is reported once, at the depth it is first reached, with the
  dependencies that reach it there; a cycle ends at a dependent already
  reached. The walk reads the dependencies of the period once per depth,
  10 at most, so they bound its size. A client without an agent, an
  address or the folded clients `~external`, is a dependent of each server
  it uses and is not followed: what depends on it is not known. Nor are
  the sockets without a known owner of a host (`~unknown`), which are no
  one service.

**Cadence.** How often a dependent uses its server is read from the hours
of activity of its edges (§5.1), the client's and the server's together,
in the period:

- *blind* time is the time in which no agent that sees the dependency
  observed its host, widened to whole hours: an hour that was not observed
  in full is neither active nor idle;
- a *run* is a stretch of active hours that follow each other; blind time
  between two active hours does not end it, since the dependency may have
  been active then;
- the *gap* of two runs is the time between the end of one and the start
  of the next, their *interval* the time between their starts;
- *idle* is the time observed since the end of the last run, and *duty*
  the part of the time observed since the start of the first run in which
  the dependency was active;
- a dependency has *ended* when it is idle for longer than a day and than
  twice its longest gap: before that, its next run may still come.

The first rule that holds gives the cadence (`shawk.cadence()`):

| cadence | rule |
|---|---|
| `unknown` | no run: no hour was recorded |
| `continuous` | not ended, observed for a day at least since the first run, and a duty of 0.9 at least |
| `one-off` | ended, after one run shorter than a day |
| `dormant` | ended, after a longer run or several |
| `unknown` | one run or two: too recent to tell, or one interval, which tells no period |
| `daily`, `weekly`, `monthly`, `periodic` | two thirds of the intervals at least are within 25% of their median, and the median run lasts half of it at most: `daily` for a median of 20 to 28 hours, `weekly` for 6 to 8 days, `monthly` for 27 to 32 days, `periodic` otherwise |
| `irregular` | anything else |

A dependent of the last four has a `period`, the median interval, and
`next_expected`, the start of its last run plus the period.

- **An hour is the resolution**, so a job of every hour or more often is
  `continuous`: for a removal both break within the hour. A job of every
  two hours is `periodic`.
- **One threshold tells that a dependency ended**, with one run as with
  several: a connection used for 90 days and idle for 2 hours is
  `continuous`, and `dormant` a day later; 20 hours of use idle for 2
  hours are `unknown`, and a `one-off` a day later.
- **`unknown` rather than a guess** when there is too little to tell: no
  hour recorded, as for edges written before the hours were; fewer than
  three runs; less than a day observed. It is also the cadence of a
  dependency whose hours end before it was last seen: a connector that
  does not record them wrote the edge since, and the hours would read as
  idle.
- **The period is the evidence.** A job of every month is `monthly` over
  three months, `unknown` over two, and absent over a week in which it did
  not run; one of every quarter has one run in 90 days, a `one-off`. The
  period must be longer than the cadences that matter.
- **`next_expected` is an estimate**, for telling what breaks first, not a
  schedule: a job of the weekdays is expected on Saturday, and the first
  of the month is 28 to 31 days away. One that is past is overdue, or was
  not observed.
- **`dormant` and `one-off` are still dependents**: they used the target
  in the period. Their cadence tells that they stopped, which is for the
  reader to weigh.
- **The cadence is that of the dependents of depth 1** unless more is
  asked for (`cadence_depth`): it reads the hours of every edge of a
  dependent, a fraction of a millisecond each (below), and the dependents
  of depth 1 are those that decide. The others have none (NULL), not
  `unknown`.

**Verdict.** `impact_verdict()` gives, in this order:

| verdict | when |
|---|---|
| `UNSAFE` | the target has a dependent |
| `INCONCLUSIVE` | no dependent was seen, and the history does not tell for `min_coverage` of the period that there was none, or the target is not known: no agent ever reported under its name, no process of the host had the service, or no socket of it listened on the port |
| `SAFE` | no dependent was seen, and the history tells so |

- **A dependent is evidence whatever the coverage**, so `UNSAFE` comes
  first; with gaps the dependents listed may not be all, which `caveats`
  tells. The verdict counts the dependents (depth 1) and does not follow
  them: `impact()` does.
- **No dependent is evidence only where someone watched**: what nobody
  observed may have been used. Who must have watched is the agent of the
  target. It sees every connection the target accepts, from clients with
  and without an agent, so its observation can show that nothing used the
  target. The agents of the clients cannot, however many they are: a
  client without an agent, or one never seen before, would be missed. So a
  target no agent ever reported under is never `SAFE`: the reason is
  `unknown_host`, which a misspelt name gives too, or `no_agent` for a
  host of the inventory, whose clients with an agent still make it
  `UNSAFE`.
- **What is not known was not seen to be used**, which tells nothing: a
  service that no process of the host had in the period
  (`unknown_service`), or a port that no socket listened on nor served
  there, or none of the service when both are given (`unknown_port`), is
  `INCONCLUSIVE` whatever the coverage. Otherwise a service or a port
  mistyped would be `SAFE` on any host that is watched. The clients of a
  Unix socket are on its host, so `target_proto` `unix` is for a service,
  and refused for a host or a port.
- **The coverage** is the part of the period for which the history tells
  all that the target covers:
  - *an agent of the target observed* (`not_observed` otherwise). A
    session counts from its start to its last heartbeat, with the
    tolerance of the delay of writes. The edges keep the times of the
    agent (§5.1): with a clock behind, what the agent saw up to the
    heartbeat is dated up to `clock_skew` earlier, so the session ends
    that much earlier, and the latest hours of a host whose clock is 2
    hours behind are not observed yet. A clock ahead shortens nothing,
    since the connector writes no time after its own;
  - *within the retention* (`before_retention`). The connector deletes
    the edges last seen before its retention and keeps the session of an
    agent that goes on whole, so the sessions alone would tell that a host
    was observed, and unused, in a time whose dependencies are gone.
    `shawk.prune()` records its cutoff (`shawk.retention`), and the time
    before it is not observed, whatever the sessions say. What was pruned
    before that record existed is not known, so the migration starts it
    from what the history itself tells: the oldest time an edge still
    kept was last seen. A prune deletes every edge last seen before its
    cutoff, so that time is no earlier than the latest cutoff, and before
    it the history holds no dependency that ended, whether none did or
    all were deleted. Without a start, a period longer than the retention
    would look whole from the upgrade to the next prune, and for good
    where none follows (a retention of 0, connectors stopped). The time
    of the migration would be safe too, and would make every period that
    starts before the upgrade `INCONCLUSIVE` for as long as the period,
    with the history at hand. A prune that its bound of rows cut short
    leaves older edges, so the start may be earlier than that cutoff
    until the next prune records its own. Where every edge left is
    recent, as in a small database whose dependencies are all in use, the
    start is recent too, and it never moves back, whatever the retention
    of later prunes: every host is then `INCONCLUSIVE` for periods that
    reach before it, until they no longer do;
  - without dropped flows (`dropped_flows`, `partly_observed()`), in every
    network namespace (`netns_limited`), with UDP unless the target is of
    another transport (`udp_not_traced`), and with Unix sockets when the
    target is a service without a port, whose clients on the host may use
    one (`unix_not_traced`);
  - *with the translations that tell masqueraded clients*, for a target
    of which a pod or a container accepted connections from an address
    of the host itself (`masquerade_not_traced`, above):
    `agent_sessions` keeps whether the agent traces translations
    (`translations_traced`) and what it folds (`peer_fold`).

  `coverage()` reports it per host and `coverage_gaps()` lists its gaps
  with their cause, `agent` or `retention`, also for a name that no agent
  reported in the period, whose gap is the whole period. They are not the
  gaps of `unobserved_by_name()`, which knows neither the retention nor
  the clocks.
- **`min_coverage` is 1 by default**: any gap beyond the tolerance of the
  delay of writes (3 minutes, as in `unobserved()`; 1 hour at most) makes
  the verdict `INCONCLUSIVE`, and the gaps are listed. An agent that
  restarts within the tolerance leaves no gap. A gap of minutes in 90 days
  may hold the only run of a job of every month, and nothing tells that it
  does not. A caller who accepts the gaps says so (`min_coverage => 0.999`)
  and gets `SAFE` with the shortfalls as `caveats`. The coverage is
  compared as it is and reported cut, not rounded: 1 is all of the period.
  It is a part of the period, from 0 to 1, in SQL, in the dashboard and in
  `shawk-impact` alike, which refuses a percentage: with two units, 1
  would be all of the period for one and a hundredth of it for the other.
- **Planned stops (§5.7) are gaps like the others.** An agent stopped on
  purpose did not observe either, and only a host that was off could not
  be used, which a maintenance window does not tell. The reasons of the
  gaps are in `unobserved_reasons()`.
- **The observation of the hosts of the dependents** does not decide the
  verdict. `coverage()` reports it: where the agent of a dependent did not
  observe, its cadence and what depends on it may be wrong.

**Cost.** The functions read the dependencies of the period once, like the
dashboards, then the edges, the hours, the sessions and the addresses of
the hosts they find through their indexes. Of the addresses that hosts
held, they read the periods that meet the period asked for and, of each
host, those of its last report before it, found from its last heartbeat:
not the history of the retention, which is millions of periods where
pods or nodes come and go (`dependencies_between()` still reads it, for
the shared addresses). On a synthetic fleet of 2000 hosts with 1.1
million edges, of which 500000 dependencies are in a period of 90 days,
`dependencies_between()` takes 4.1 to 4.8 seconds, the verdict 5.4 to
7.4, and `impact()` 4.8 to 7.0 at depth 1 (179 dependents with their
cadences), 5.7 to 8.9 at depth 2 (7263 rows) and 7.9 to 10.8 at depth 3
(126260 rows): once to twice the dependencies of the period, at any
depth. The cadence costs 0.3 to 0.9 milliseconds per dependent, for 1 to
150 runs: 4 more seconds for a hub with 3559 dependents, and 100 for the
rows of depth 3 above, which is why it is read for depth 1 unless asked.
`shawk-impact` at its defaults takes 13 to 14 seconds there, and 17 to
19 for the hub. These are the best and the worst of five runs on a
machine shared with other work, at load averages of 9 to 17; at 25 to
35 the command took 83 and 109 seconds, which is why its time limit is
5 minutes.

- **The joins hash.** `shawk.dependents()` joins the dependencies of the
  period with each other, and they are the rows of a function, of which
  the planner knows nothing: it joined the few rows it expected in nested
  loops, 2 billion comparisons for the walk of the fleet above. Nested
  loops are off in that function, and so is the JIT compiler, which the
  costs of such a plan start for seconds of no use; a test reads the plans
  (`TestPGImpactPlans`).
- **The runs of a cadence are read in one pass** over the stretches of
  active and blind time in the order they start, so the cost grows with
  the hours recorded, not their square. So are the stretches in which a
  host reported addresses, over its periods in the order they start: a
  join of every period with every stretch of its host took minutes for
  3 million periods, where the verdict over 7 days now takes 3 seconds,
  as without them.
- **The verdict does not walk**, and the cadence is read for the depth
  asked for: what decides is computed first, and `shawk-impact` prints the
  verdict even when the list of the dependents then fails or runs out of
  time, with an exit status of failure.

The verdict is of what shawk observes (§10): a host used over RDMA, one
that only forwards packets, or one used less often than the period, is not
seen to be used.

### 6.4 Least-privilege rules and the baseline of dependencies

The history tells what every process connected to, so it can spell the
rules that allow just that, and tell when a service does something else.
Two things are made from it, both for a person to review: the rules of a
host or of a systemd unit (`shawk-policy rules`), and a baseline of the
dependencies of services, against which the connector reports a drift
(`shawk-policy baseline`, `baseline_file`, §5.9). `policy_flows()`,
`policy_verdict()`, `policy_gaps()`, `baseline_observed()`,
`baseline_verdict()`, `baseline_drift()` and `baseline_new_services()` are
in the contract, in SQL, as the impact is (§6.3): Grafana, psql, the
connector and the command give the same answer, and the command only
writes it as rules.

One rule decides the cases below: **a rule denies what was not seen, so
what was not watched must be told before a rule is written.** The impact
answers `SAFE` only when the history can tell that nothing used a target;
a rule that denies is the same claim, enforced by a firewall. The two
worst failures of this feature are a file that says `COMPLETE` and blocks
what its host needs, and an answer of no drift, or an alert that stays
silent, where nothing looked. So where shawk cannot know, it says so:
`INCOMPLETE` or `INCONCLUSIVE`, an exit status that is not 0, a line in
the file, a series of its own. It prints no claim that it cannot keep.

**The same contents give the same output.** Where the contract returns
rows or the items of an array in an order, or keeps the first of them, the
order is that of the bytes of the names (`COLLATE "C"`), and the command
sorts what it lists the same way: a database of `en_US.UTF-8`, the default
of the PostgreSQL image, sorts capitals after small letters and skips
marks such as `~` and `-`, and a file of rules or a baseline that differed
between two databases with the same contents could not be compared.

**shawk writes, a person applies.** `shawk-policy` reads the contract as a
role that reads `shawk_v1` only and writes to its standard output. It has
no option to load a ruleset, to install a drop-in or to write the
database, and the baseline reaches the connector as a file that an
operator deploys. A deny rule made from an incomplete history is an
outage, and the review is what stands between the two; a file also
carries what its reviewer must know as comments, wherever it goes.

**The flows.** `policy_flows()` gives what a host connected to (egress)
and accepted connections from (ingress) over TCP and UDP, for the whole
host or for the processes of a unit:

- **They are the edges of the host, not the dependencies matched from
  them.** A firewall of the host sees what its sockets see: the virtual
  address of a load balancer, not its backends; the address of a relay
  that replaced that of the client, not the client. `dependencies` names
  the real client of such a connection (§5.4), which the server never
  sees: rules made from it would deny the relay. The dependencies only
  name the peer of each flow, for the reviewer.
- **A connection that the host itself translates allows its backend
  too.** When the kernel of the host rewrites the destination of a
  connection of one of its own processes (kube-proxy for a Service, a
  published port reached from the host), the packets leave for the
  backend: what filters after the translation, the hook `output` of
  nftables at the priority of filters and the cgroup programs of systemd,
  sees the backend, and the answers come back from the virtual address.
  The flows have both, the backend marked `translated`, from the
  translations that the agent learned in the network namespace of the
  socket (§3.7). A connection of a pod is translated in another namespace,
  after what filters the pod: it has the virtual address alone.
- **Where an agent did not learn every translation, the flows are not
  complete** (`translations_not_learned`). An agent that traces no
  translation learns none; one that folds the peers outside its internal
  ranges, which is the default (§3.6), does not learn a translation to a
  backend outside them (§3.7): a Service whose backend has a public
  address, a NAT rule to an external server. The packets of such a
  connection leave for an address that the flows lack, the rule of the
  virtual address does not match them, and nothing in the history tells
  whether the host rewrites any connection that way. The verdict is
  `INCOMPLETE`, whatever `min_coverage` accepts, which is time; an agent
  with `-fold-external none` learns them all. This makes the rules of a
  host whose agent runs with its defaults `INCOMPLETE`: the audit form
  (below) is what tells whether such a host needs more.
- **Folded peers are a whole network.** The agent keeps no address of the
  peers it folds (§3.6): their flow has the network `0.0.0.0/0` or `::/0`,
  and its rule allows every address of the family on the port. Leaving
  them out would deny them; the rule says that it is wide, and that
  `-fold-external none` or `-internal-peers` keeps the addresses.
- **A unit holds the units under it.** A container that a service runs
  in a control group of its own is the unit `app.service/podman-<id>`
  (§4.1), and a limit of systemd on `app.service` holds for it: the flows
  of a unit are those of its processes and of the units `<unit>/...`.
- **A socket without a known owner counts for every unit** of its host
  (`~unknown`, §4.1), as it counts for every service in the impact: it may
  be the unit's, and a rule that leaves it out would deny it. Such a
  socket has no unit. A process of another unit that gives itself the
  name `~unknown` is a process of that unit, and counts for no other: a
  name is what a process declares.
- **A flow of UDP allows its peer both ways.** A socket of UDP may send
  and receive first on one port (gossip between members, NTP between
  peers, IKE, a DHCP relay), and the agent decides one direction per
  socket (§3.3): the flows have the peer and the port once, as accepted
  or as opened. The connection tracking of the kernel knows the other
  direction as a reply only for a while after the last datagram, so a
  datagram that the other side starts would be refused. The rules of a
  host therefore allow, beside the datagrams to the port, those that the
  same peer exchanges the other way **between that port on both sides**
  (`udp sport P udp dport P`), with the addresses that were seen, and say
  so. The rule names both ports because the history holds one: the source
  port alone would open every port of the host to whoever sends from that
  port (a rule `ip saddr <resolver> udp sport 53 accept` lets the
  resolver, or a datagram that forges its address, reach every UDP server
  of the host; with a folded peer, every address), and every port of the
  peer to the socket of the host. What it leaves out is a peer that
  starts from another port later than the tracking remembers the exchange
  (30 seconds, or 120 once both sides sent, by default): the audit form
  counts it. There is no such rule for a range of ports or for a port
  that the kernel chose, which no exchange keeps on both sides, and the
  rule stays pinned to the addresses with `-ingress ports` too. The
  drop-in of systemd lists addresses for both directions and needs
  nothing more.
- **Ports follow the rules of ports** (§5.3): a flow in a range of
  `dynamic_ports` allows the range, and one to a server of
  `port_agnostic_services` every port of its address, since the server
  listens on another one at every run. A server that listened on a port
  the kernel chose, which no rule of ports covers, is marked: a rule
  pinned to that port breaks at the next run.
- **What was last seen before the period is listed, not allowed.** A
  period cannot tell what it does not hold, a job of every quarter or a
  server used only when another fails; but the flows that the history
  holds from before it are evidence at hand of exactly that, and the
  report lists them so that a reviewer extends the period or accepts the
  loss.
- **Connections within the host** (loopback) are in no rule: both formats
  leave loopback open.

**What a rule pins, and what that costs.** Neither nftables nor
`IPAddressAllow=` matches the name of a service, and shawk keeps no DNS
name, so a rule pins the addresses that the sockets saw. A peer that gets
another address is then denied until the rules are written again: a lease
of DHCP that changes, a group that scales out, a replica that this client
never used, a failover. The command does not hide it: every report counts
the addresses pinned, the sources pinned, the peers it could not name and
the ports that will change, and names the peer above each rule so that a
reviewer can widen a rule to the range he knows.

- **Not widened automatically.** A rule could allow every endpoint of the
  service it names, or the whole range of `peer_cidrs` an address is in.
  Both allow what was never observed, and how wide is right depends on
  what the reviewer knows of the network (a range of pods and a `/8` are
  both ranges of `peer_cidrs`): the choice stays his, with the names to
  make it.
- **Sources are pinned by default, and can be opened.** The rules of the
  connections a host accepts are where addresses change most: clients, and
  administrators. `-ingress sources` (the default) is the least privilege
  the history supports, `-ingress ports` opens the ports that were seen to
  every source, and `-ingress none` writes no rule for what the host
  accepts.

**The formats.**

- **nftables** (`-format nftables`), for a whole host: a table of its
  own, `inet shawk_policy`, with the chains `output` and, unless
  `-ingress none`, `input`. Each accepts what belongs to an established
  connection, loopback and **every protocol but TCP and UDP**; then the
  flows; what is left is counted, in a counter with a name
  (`egress_unlisted`, `ingress_unlisted`), and logged, at most 10 lines a
  second. shawk does not observe ICMP, neighbour discovery, VRRP or
  IPsec: a ruleset that dropped them would deny what nothing looked at. A
  table of its own replaces no other rule, and a packet passes only if
  every table accepts it. There is no chain `forward`: the connections of
  containers that a host forwards do not pass `input` and `output`, and
  the report tells when the sockets of the flows are in several network
  namespaces. Rules of a host cannot tell its units apart, so the format
  takes no unit. The table matches the state of connections, so loading
  it starts the connection tracking of the kernel on a host where nothing
  used it: every file says, among the checks before loading, that the
  tracking keeps at most `nf_conntrack_max` connections and that the
  kernel drops the packets of new ones when its table is full. This is
  read from the documentation of the kernel, not run.
- **The audit form is the default; a file that blocks is asked for.**
  Without `-enforce` the table ends there: what no rule lists passes, and
  the counters and the log show it. With `-enforce` it is then refused
  (`reject` for what the host opens, so that a client fails at once
  rather than at its time limit; `drop` for what it accepts). Some of
  what a host needs is not in any history of shawk, and a file that says
  `COMPLETE` and rejects it is the worst failure of this feature; the
  audit form shows exactly that, on the host itself, before anything
  breaks. Every file lists what shawk cannot observe as checks for its
  reviewer:
  - *tunnels that the kernel makes* (VXLAN, Geneve, WireGuard,
    IP-in-IP). The connections over an overlay are observed and in the
    rules, by the addresses inside it; the outer datagrams (UDP 4789,
    8472, 6081, 51820) are sent by the kernel, by no socket of a process,
    so no flow has them and the form that rejects stops the tunnel;
  - *a host that balances for others in its kernel* (IPVS: an LVS
    director, kube-proxy in IPVS mode). A virtual service has no socket,
    so no ingress flow has it, and the chain `input` (priority 0) runs
    before IPVS takes its packets (priority 99). This is read from the
    source of the kernel, not run: the file says that `shawk-policy` was
    not run on such a host, and to use `-ingress none` there;
  - *protocols other than TCP and UDP*, which the table accepts;
  - *destinations that the host rewrites*, where an agent did not learn
    them (above);
  - *what the host forwards*.
- **The audit form shows a connection for as long as it lives.** A
  counter that counted the first packet of what no rule lists would give
  a false answer for exactly the traffic that matters: a connection that
  began before the counters were cleared (a tunnel of the kernel, a
  session that stays open) never shows again, the form that rejects lets
  it go on as established, and it is refused when it is opened again,
  after a restart. So the audit form gives a **connection label** to the
  connection that no rule lists (126 in `output`, 127 in `input`) and
  counts every packet that its opening side sends, where the form that
  rejects has one rule for what is established:
  - a connection that begins under the table gets the label 125 with its
    first packet, and its later packets pass at the first rule of the
    chain unless it has the label of what no rule lists;
  - what is left of the established connections are those with that
    label, and those that were open before the table (no label: the
    tracking of a host that tracked connections already knows which side
    opened them). The packets of their answering side pass
    (`ct direction reply`), and those of their opening side are compared
    with the rules, each one: a connection that a rule lists now passes
    uncounted, the others are counted. The log has the first packet of a
    labelled connection only, and every packet of one that cannot have a
    label, within the same limit;
  - the lines of the flows are the same in both forms, in the same order,
    and every rule of the frame of the audit form accepts or goes on: it
    rejects nothing. It counts what the form that rejects would refuse
    if every connection were opened again, which is more than that form
    refuses at the moment it is loaded.

  *Labels, not the mark.* The mark of a connection is one value that
  other tools write and read as a whole: `wg-quick` sets it for the
  datagrams of its own tunnel, which is the first thing the audit form
  must show, and rules of routing read it. A label is a bit apart from
  the others, and setting one changes no other. The labels are the three
  highest; the file names them, says that `nft` refuses it as a whole on
  a kernel without connection labels, and that it must not be loaded
  where another tool uses the same ones. The kernel gives the storage of
  labels to the connections that begin while a rule uses labels, which
  is why one that was open before cannot have one. *What it costs*: such
  a connection is compared with the rules at every packet of its opening
  side until it ends; one that begins under the table, once.

  *What it cannot show*, which the file says: a connection whose opening
  side sends nothing during the watch; and, on a host where the table
  itself started the tracking, a TCP connection that was open at that
  moment. The tracking takes such a connection up from its next packet,
  whichever side sends it (`nf_conntrack_tcp_loose`), so it cannot tell
  which side opened it: following it would count a listed connection for
  as long as it lives whenever its server spoke first. It is counted
  once, with that packet (a rule for TCP packets that begin a tracked
  connection without being a SYN), and compared for good when it is
  opened again. An exchange of UDP that was going on at that moment
  cannot be told from a new one: it is followed from the side that sent
  next, and one that a rule lists the other way keeps counting until it
  pauses. Both limits are of hosts that tracked no connection before;
  where the host did, every connection that sends is compared.
- **From the audit form to rules that reject.** The files tell the
  procedure, which also keeps open connections alive. On a host where
  nothing used the connection tracking, the tracking does not know the
  connections that are open: it takes the next packet of each for a new
  connection, which no rule lists when the peer sends it (the answer of a
  server to a client of the host comes from the port of the server, and
  what a server of the host sends goes to the port of its client). Loaded
  directly, the form that rejects stops those connections. Loaded first,
  the audit form lets those packets pass, and the tracking takes the
  connections up: so (1) load the audit form; (2) read its counters and
  the log; (3) only where the table started the tracking, clear the
  counters a few minutes later, since until then they hold listed
  connections that were taken up from their answering side; (4) leave it
  for as long as the slowest job of the host takes to come round, and
  longer than the longest silence of its open connections; (5)
  only while the counters stay at 0, write the form that rejects and
  load it, which replaces the table in one transaction. The connections
  that are established by then stay, listed or not, until they end, which
  the form that rejects says of itself.
- **systemd** (`-format systemd -enforce`), for a service unit: a drop-in
  with `IPAddressDeny=any`, `IPAddressAllow=localhost` and an
  `IPAddressAllow=` per address. The setting has one list for both
  directions and no ports, so an address of a client and that of a server
  are allowed alike, for every port. **It filters every IP protocol** of
  the sockets of the unit, not TCP and UDP alone: a unit that sends ICMP
  echo, VRRP or SCTP is denied every address that is not listed, and the
  file says so rather than that it filters TCP and UDP only. It is not
  applied to the sockets that systemd passes to the unit (socket
  activation), and it holds for the control groups under the unit. A rule
  that allows a whole family (folded peers) leaves the drop-in limiting
  nothing for that family, which the file says at the line. A drop-in has
  no audit form and blocks as soon as the unit restarts with it, so the
  command writes it only with `-enforce`, and the file points to the
  audit form of the host. Only a unit named `*.service` has a unit file
  to drop it in: the unit of a container, a session or a job is refused.
- **`RestrictAddressFamilies=` is written as a comment**, not as a
  setting. shawk records the addresses of connections, not the families
  of sockets: an `AF_INET6` socket carries IPv4 peers, as the listeners
  of most servers do, and `AF_NETLINK`, `AF_PACKET` and datagram
  `AF_UNIX` sockets are not observed at all. A list made from what was
  seen (IPv4 peers only, so `AF_INET`) could keep a unit from starting.
  The comment tells what was seen and gives a list to start from.
- **iptables is not written.** On the primary target (RHEL 9) it is a
  front end of nftables and deprecated; it needs a file per family and is
  loaded over the tables of the host unless told otherwise. One format
  that the kernel is seen to load as meant (below) is worth more than
  two.
- **Kubernetes `NetworkPolicy` and Cilium policies are not written.**
  They select pods by labels, which shawk does not keep (the unit of a
  pod is its namespace, workload and container, §4.1), and their peers
  must be labels too: the addresses of pods, which is all the history
  has, are what such a policy must not pin. No validator of either is at
  hand to check a manifest against either. They would need the labels of
  pods in the history first.
- **The files are checked against what reads them.** The tests load the
  tables, in both forms, into the kernel of a network namespace of their
  own with `nft` and compare what the kernel then lists with the flows,
  address by address, and give the drop-ins to `systemd-analyze verify`;
  both over flows whose names are what agents may send (a name with a
  line break and a rule after it, one that ends with a backslash). Names
  are written in comments only, quoted unless plain; every other
  character of a file is an address, a number or a word of the command.
  The cases above were run with packets between two network namespaces:
  over a VXLAN the audit form lets the connection pass and counts the
  datagrams of the tunnel, and the form that rejects stops it; a
  connection that the host rewrites to a public backend passes the audit
  form and is counted; a socket of UDP that sends from the port it
  receives on reaches its peer through the form that rejects; and two
  open connections whose peer sends next stop when the form that rejects
  is loaded directly, and go on when the audit form was loaded first.

**Completeness.** `policy_verdict()` tells whether the history holds
every flow of the target over the period:

| status | when |
|---|---|
| `INCOMPLETE` | the target is not known (no agent ever reported under the name of the host: `unknown_host`, or `no_agent` for a host of the inventory; no process of the host had the unit: `unknown_unit`), several machines reported under the name of the host in the period (`several_machines`), an agent did not learn every translation (`translations_not_learned`), or the history covers less than `min_coverage` of the period |
| `COMPLETE` | one machine reported under the name, its agents learned its translations, and the history tells every connection of the target over TCP and UDP for `min_coverage` of the period |

- **The coverage is that of the impact** (§6.3) for what rules cover: an
  agent of the host observed (`not_observed`), within the retention
  (`before_retention`), without dropped flows (`dropped_flows`), in every
  network namespace (`netns_limited`) and with UDP (`udp_not_traced`: a
  resolver is a dependency over UDP). `min_coverage` is 1 by default, and
  a caller who accepts a gap says so and gets `COMPLETE` with the gap as a
  caveat, as for `SAFE`. The file then says "`COMPLETE` by -min-coverage
  only" and the part of the period that the history tells, not that it
  tells every connection.
- **It is that of a machine, not of a host name.** `coverage()` of the
  impact takes the time that any machine of a name was observed, which
  fits a host that was installed again. For rules it would hide a machine
  that was not observed behind another that was: two machines that report
  under one name (clones, or nodes that are all `localhost`). The
  observation is therefore by machine (`shawk.hosts.id`,
  `shawk.machine_shortfalls`): the coverage is that of the least observed
  machine that reported under the name in the period, `policy_gaps()`
  lists the gaps of each, and more than one machine is `INCOMPLETE`
  whatever is accepted, since the flows are then of them all. A host that
  was installed again is two machines until the period starts after the
  last report of the first.
- **What the tolerance counts as observed is told.** A session counts as
  observed for 3 minutes after its last report, so that the restart of an
  agent, or its latest report that is not written yet, is no gap. No agent
  reported in that time all the same: the verdict tells how many such
  stretches there were and how long they were (`tolerated`,
  `tolerated_gaps`), and the files say it under a status of `COMPLETE`.
- **No file that blocks from an incomplete history, unless asked.**
  `shawk-policy rules -enforce` then writes the report, with what was not
  seen, and no rule; `-allow-incomplete` writes them, with `INCOMPLETE` as
  their first line and the shortfalls below it. The audit form blocks
  nothing and is written as it is, marked `INCOMPLETE`: it is how an
  operator finds what the history lacks. The exit status is 4 either way,
  and 0 for `COMPLETE` alone, so that no script takes rules of a partial
  history for rules of a whole one. Writing a file that blocks with a
  warning by default would leave the decision to whoever reads the
  warning last; refusing it always would leave an operator who knows why
  his agent restarted without rules at all. `-min-coverage` accepts a
  known amount of gaps and changes the status; `-allow-incomplete`
  accepts whatever is missing and does not.
- **A name that nothing knows is never complete**, whatever is accepted:
  a host or a unit mistyped has no flow, and its rules would deny
  everything. No file is written for it, in either form.
- **What completeness cannot tell** is said in every report and file:
  what shawk cannot observe (above), and that a connection that was not
  made in the period is denied.

**The baseline** is per service, by its name in PostgreSQL and in the
`job` label, not per host: the hosts of a service share it, so a host
that joins a service is judged by what the service may do, and adding
replicas alerts nothing. An entry is a server by its name, a port and a
transport.

- **A file is the source of truth.** A baseline is approved where an
  operator approves everything else, in a file under review and version
  control, and the connector reads it like the inventory (§5.9);
  PostgreSQL holds a copy to evaluate. `shawk-policy baseline` writes the
  file from a period, with the evidence of every entry as comments (how
  many hosts, when it was last seen, where its name comes from), and
  `-merge FILE` writes a file again with some services replaced, so that a
  change is a difference to review. A table that the command writes would
  give a tool that reads a credential to write, and leave no trail of who
  approved what. Learning the baseline as time goes, as
  `dependency_changes` tells what is new, would make a compromise that
  lasts part of the baseline: a lock is explicit.
- **Names are those of the dependencies between services, with one
  addition.** A server that no agent saw the side of is named after the
  service that listens at its address (`service_endpoints`, the last
  known endpoints, as the connector names peers, §5.2), or at a backend
  of the translation of the configuration whose virtual address it is,
  before it is named after its address (`peer_class`). Otherwise a server
  whose agent stops would turn every dependency on it into one on
  `~unresolved`, on every client at once, and the baseline would hold
  both names or alert on each stop. `named_by` tells which evidence named
  a server: `edge`, `endpoint` or `address`.
- **A port of 0 stands for every port**, and a dependency is in the
  baseline by the port of the dependency between services or by the port
  of the server itself (§5.3). A rule of ports added or removed after a
  baseline was approved thus makes no drift of what it holds.
- **A port that the kernel chose is not pinned.** A server that listened
  on a port the kernel chose (§5.3) has another one at its next run. The
  rules of a host pin the port and mark it; a baseline that pinned it
  would tell a critical drift at every restart of the server. The
  dependency is on every port of the server (port 0), marked
  `kernel_chosen` with the ports that were seen, in the file and in the
  drift alike, so that one dependency is one line whatever its port is
  today. A rule of ports for the server (`port_agnostic_services`,
  `dynamic_ports`) says the same on purpose.
- **A baseline judges the unit that runs its service.** The name of a
  service is what a process declares (`OTEL_SERVICE_NAME`, else its
  executable, §4.1); the unit is what it cannot leave. A process that an
  approved service starts (`curl`, a shell), or one that takes another
  name, would otherwise be a service of its own that no baseline judges,
  and a connection out of the unit would be told nowhere. So a process
  whose own name has no baseline is judged as each service of the
  baseline that runs in its unit on its host, where a process of that
  service was seen recently (as for the hosts, below); `processes` names
  it, and the reports say "by curl in its unit". The baseline of a
  service lists what its drift is judged on: `shawk-policy baseline
  -service` includes what such processes connected to, where their names
  are neither asked for nor in the file to merge with. With `-all` every
  name that was seen has a baseline of its own.
- **What this does not detect**, said under every drift: a process that
  takes the name of *another* service of the baseline is judged by that
  baseline, and may use what it approves; a process in a unit that runs
  no service of the baseline, under a name without a baseline, is judged
  by none (it is counted once as a new service, below); and a socket
  without a known owner (`~unknown` without a unit) belongs to no unit
  that could judge it. A process without a service name at all, whose
  telemetry has no `service.name`, cannot be named in a file: `-all`
  leaves it out and says so.
- **Unix sockets are not part of a baseline**: they have neither a port
  nor a network, every process tries the socket of nscd (§8), and agents
  that start to trace them would make every such dependency a drift at
  once.
- **A service must have run to be written.** `baseline_verdict()` is the
  observation of every machine that ran the service, by machine as for
  the rules, and a service that no process had (`unknown_service`) is
  never written, even when asked: a name mistyped would approve nothing,
  and deny everything. A machine that ran the service for a part of the
  period counts over the whole period: what it did before its agent first
  reported is not known.

**The drift** is what the services of the baseline did that it does not
hold (`baseline_drift()`).

- **New means not in the baseline**, not "not seen for some time": the
  answer does not depend on how long a dependency was idle, and the same
  period gives the same drift. A dependency is told while it was active
  in the period, an hour for the connector (§5.9).
- **The ports of clients are not recorded** (§3.1), and a server that
  takes another port at every run is one dependency under the rules of
  ports.
- **A service that is itself new is not judged**, unless it runs in a
  unit of a service that has a baseline (above), and neither is any other
  service without a baseline: there is nothing to compare it with. It is
  not silent either: `shawk_baseline_dependencies{job}` tells the
  services that are judged, and `baseline_new_services()` the services
  without a baseline that were first seen in the period and opened
  connections, which the connector counts
  (`shawk_baseline_new_services`). It is an `info` alert, not a drift:
  administrators run new tools every day.
- **A peer that shawk cannot name is a drift of its own kind.**
  `~unresolved` is a private address without a known service: a host
  without an agent, or a server of the baseline at an address that shawk
  does not know of. It is told with its name, and the alert on it is a
  warning that waits (§8), apart from the alert on servers that shawk
  names.
- **No drift is an answer only where someone looked**: `shawk-policy
  drift` is `INCONCLUSIVE` when no connector read a baseline or the
  baseline holds no service, when a service asked for has none, when a
  host that runs a service was not observed for the whole period, or
  when no host is known to run a service of the baseline; the connector
  tells the same per service, and when it last evaluated (§5.9).
- **The hosts of a drift are those that run the service, not those that
  were seen in the period.** The question is what a service did, on the
  hosts that have it. Counting only the hosts whose processes were seen
  in the period would leave out exactly the hosts that matter: one whose
  agent stopped three hours ago, by a fault or by whoever took the host,
  has no process in the last hour, and the drift would be "none" for a
  service of which nothing was watched. The same holds for a host whose
  clock is two hours behind: its agent reports now, and what it does now
  is dated before the period. A host therefore runs a service for some
  time after a process of the service was last seen on it:
  `-hosts-lookback` (7 days) for the command, `baseline_host_memory` (a
  week) for the connector. Within it a host that is not observed makes
  the answer `INCONCLUSIVE`; a service that no host runs is
  `INCONCLUSIVE` too (`no_host`), since nothing was there to see it.
  The memory is a choice between two failures: too short, and a silent
  host is forgotten with its silence; too long, and a host that was
  removed keeps the answer `INCONCLUSIVE`, and the alert of its service
  firing, until it runs out. A week keeps a host that is off over a
  weekend. The baseline of a period, which lists what was seen in it,
  counts the hosts that ran the service in the period.

**Cost.** Each function reads the dependencies of the period once
(`dependencies_between()`), like the impact, and the last known endpoints
once. On the synthetic fleet of §6.3 (2000 hosts, 1.1 million edges,
500000 dependencies in 90 days), on a machine at a load average of 3:
`policy_flows()` takes 5 seconds for any host, also one with 4449 clients;
`baseline_observed()` 5 seconds for a service of every host and 8 for
every service; `baseline_drift()` 1.2 seconds over an hour in which few
edges are active, and 3 seconds over an hour in which a quarter of the
edges are, whether or not agents are stopped (§5.9); `shawk-policy rules`
and `baseline` 5 to 8 seconds and `drift` 1.4.

- **Names are made for the rows that are read**: those of the host, or
  of the services asked for. A name costs calls of `peer_class()`, a few
  seconds over the dependencies of months.
- **The joins of the flows and of the names hash**, as those of
  `shawk.dependents()`: the edges of a host, and the dependencies of a
  period, are joined with rows of functions, of which the planner knows
  nothing, and with nested loops the flows of the host with 4449 clients
  took 22 seconds, and the drift of a fleet with 20 stopped agents 234
  (§5.9). The edges and the translations of the
  host are read through their indexes all the same, by its host ids as
  values. The JIT compiler is off in these functions: it took 2 seconds
  to compile what then ran for one.

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
dependency details, peer hosts, changes, impact, application layer of OBI)
and alert rules. The peer hosts dashboard needs `peer_hosts` (§5.3): the
hosts towards the selected services, and failures, connect times and
traffic by peer host; a host that accepts no connection, such as one that
is down, shows a failure ratio of 100%. With `networks`, a table gives the
connections and bytes of the selected services by the networks of the
client and the server.

The dependency details dashboard selects services from Prometheus, and its
table of `dependencies_between()` names each side as Prometheus does
(§5.3): `slurm-job` for a process of a Slurm job (unit `slurm/*`), which
the table shows under its own name and unit, and `peer_class()` for a side
without a service. `~other` can fold any service, with an agent or not, and
matches every side. A selection without values, as over a time range that
Prometheus no longer holds while PostgreSQL does (`retention`), matches
every side too.

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
alive is not alerted. A clock off by more than a minute is alerted per host
name, with the largest skew of its live host ids, so that a node that
booted with a new machine id within the alive window is one series.
Neither alerts hosts in a planned stop (§5.7): the
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
machine id changed have gaps in the annotations, not in the table. The
panels keep `network_transport` beside `server_port`, as the recording
rules do: port 0 is that of Unix sockets and of the servers of
`port_agnostic_services` and `dynamic_ports` (§5.3), and TCP and UDP share
the numbers of ports. SYN retransmissions per connection attempt
(handshakes plus failures over TCP) exceed 1 when connects time out, and
`TCP_FASTOPEN_CONNECT` connects, which have no handshake, raise them. OBI
panels use a minimum interval of a minute, since
OBI exports every 60 seconds by default.

Where the absence of a dependency is read (the changes dashboard, and the
observation periods of the fleet dashboard), the panels say that only TCP,
UDP and Unix stream sockets are observed; the fleet dashboard shows which
agents trace Unix sockets (`unix_traced`), and `ShawkUnixNotTraced` alerts,
as `ShawkUDPNotTraced`, on agents that do not. It also shows which agents
classify wire protocols (`protocols_classified`, §3.9), and
`ShawkProtocolsNotClassified` alerts on the agents asked to that cannot.
`ShawkConnectionFailureRate`
leaves out the failed connects to Unix sockets that no listener serves
(`~unresolved`): glibc tries the socket of nscd from every process that
looks up a user or a host, and most hosts do not run nscd; the dashboards
still show them. Below the changes, the changes dashboard lists the
services on ports the kernel chose that no rule of ports covers
(`kernel_chosen_ports`, §5.3), over the last 30 days whatever the time
range. The fleet dashboard shows the traffic of the RDMA
ports of each host (`shawk.agent.rdma.io`) below the observation periods,
as a hint only (§10).

The impact dashboard answers, for a host and the time range (90 days by
default), what `shawk_v1.impact_verdict()`, `impact()`, `coverage()` and
`coverage_gaps()` tell (§6.3): the verdict with its reasons, the
dependents with the cadence of those of depth 1, how the host was
observed, and the gaps the verdict counts. The coverage that `SAFE` takes
is a variable, a part of the time range from 0 to 1 as in the functions.
It does not refresh by itself: the verdict and the dependents each read
the dependencies of the whole time range (§6.3).

`shawk-impact` prints the same for a host, or for a service or a port of
it, as text or JSON, and exits with the verdict: 0 for `SAFE` and for
nothing else, 3 for `UNSAFE` and 4 for `INCONCLUSIVE`, so that a script
can make a removal wait for it; its help exits 2 like an invalid command
line, and a failure 1.

- **It reads the verdict first**, then how the target was observed and
  the dependents, in one read-only transaction, as any role that reads
  `shawk_v1` (`shawk_grafana`). When what follows the verdict fails, as
  the list of the dependents of a hub may run out of time, it prints the
  verdict, tells that the rest is missing, and fails: a verdict that was
  reached is not lost, and no script takes a report cut short for a whole
  one.
- **It refuses what widens the question without a word**: an empty
  `-service`, `-port 0` (a variable of a script that is empty would make
  the target the whole host), a `-min-coverage` that is no part of the
  period from 0 to 1 (99.9 is refused rather than taken for more than
  all), and a `-lookback` under an hour, the resolution of the hours of
  activity: `3m` is 3 minutes, not 3 months, and would be `SAFE` for a
  host used the hour before.
- **It names what is no service** where it lists it: `~relay`, a client
  whose connections the host relays in its kernel, and `~unknown`, a
  socket without a known owner, count for each service of the host
  (§6.3), and an operator must be able to tell them from the clients of
  the service asked for. A cadence that was not read prints as `-`, with
  the depth it is read to (`-cadence-depth`).
- **The period ends at the clock of the database**, with which the
  heartbeats are compared, and its `statement_timeout` (`-timeout`, 5
  minutes) is set in the transaction, which a connection pooler accepts
  where it refuses the setting at the connection: the 30 seconds of
  Grafana are short for months of a large fleet, and a database under
  load took close to 2 minutes for the fleet of §6.3.
- **It tells what it cannot see** at the end of every report: a host
  that only forwards packets looks unused (§10), which is what an
  operator who asks about a director or a gateway must know.
- **It needs PostgreSQL** (§5.8): a connection string that names a file
  of SQLite, or a database without `shawk_v1.impact_verdict()`, is an
  error that says so.

`shawk-policy` writes what §6.4 describes, as text or JSON, with three
commands. It shares the flags of `shawk-impact` for the database and the
period (`-dsn`, `-dsn-file`, `-timeout`, `-lookback`, `-until`,
`-min-coverage`), reads in one read-only transaction as any role that
reads `shawk_v1`, and needs PostgreSQL the same way. Its exit status is 0
for `COMPLETE`, or for no drift, and for nothing else; 3 for a drift; 4
for `INCOMPLETE`, or for a drift that cannot be told; 2 for its help and
an invalid command line; 1 for a failure.

- **`shawk-policy rules -host NAME [-unit NAME]`** writes the report of
  the flows of a host over a period (90 days by default), and with
  `-format nftables` or `-format systemd` the rules, under the status,
  the findings and what shawk cannot observe as comments. `-format
  nftables` writes the audit form, which rejects nothing; `-enforce`
  writes the form that rejects, and is needed for the drop-in of systemd,
  which has no other. From an incomplete history a file that blocks is
  not written, and the report is, unless `-allow-incomplete`; the audit
  form is written as it is, marked. Nothing is written for a target that
  is not known. It refuses an empty `-unit`, which would widen the target
  to the host; `-format systemd` without a service unit or without
  `-enforce`; `-format nftables` with a unit; `-enforce` and
  `-allow-incomplete` where they mean nothing; and `-ingress` with
  systemd, whose setting has one list for both directions.
- **`shawk-policy baseline -service NAME ... | -all`** writes a baseline
  file of the services over a period, with their status and the evidence
  of each dependency as comments, and `-merge FILE` writes a file again
  with those services replaced. A service that is incomplete keeps the
  whole file from being written unless `-allow-incomplete`; one that no
  process had is never written, nor taken out of the file it is merged
  with. The file ends with the line that tells it is whole (§5.9), and
  notes at the end of a line what is particular to a dependency: a port
  that the kernel chose, a process of another name in the unit.
- **`shawk-policy drift [-service NAME ...]`** tells the drift over a
  period that ends 5 minutes ago (an hour by default), with the hosts and
  the addresses, which Prometheus does not have, the process when it is
  one of another name in a unit of the service, the line to add to the
  baseline to approve a dependency, and the new services without a
  baseline. Its verdict is `CLEAN`, `DRIFT` or `INCONCLUSIVE`; it is
  `CLEAN` only when every host that runs the services was observed for
  the whole period, where a host runs a service for `-hosts-lookback` (7
  days) after a process of it was last seen there.
- **Names are quoted wherever they are not plain.** A name of a host, a
  unit, a service or a peer is what an agent sent: in a report it could
  redraw the terminal, and in a file of rules start a line of its own.
  Outside the characters that such names usually have, a name is written
  quoted, on one line. In the JSON reports every character that does not
  print is an escape, also those that `encoding/json` writes as they are
  (the controls above U+007F, U+202E).

The alerts of the baseline are rules of Prometheus
(`packaging/prometheus/shawk-rules.yml`), over what the connector sends
(§5.9):

| alert | severity | when |
|---|---|---|
| `ShawkBaselineDrift` | critical | a service of the baseline connects to a server that shawk names (a service, a range of `peer_cidrs`, `~external`) on a port that the baseline does not hold; it holds for 30 minutes after the last series of the drift |
| `ShawkBaselineDriftUnresolved` | warning, after 15 minutes | the same on `~unresolved`: a private address that shawk cannot name |
| `ShawkBaselineNotEvaluated` | critical, after 5 minutes | no connector evaluated the drift in the last 15 minutes, or none ever did; for 30 days after the last one stopped |
| `ShawkBaselineHostsNotObserved` | warning, after 10 minutes | a host that runs a service of the baseline was not observed for the whole period that was evaluated |
| `ShawkBaselineServiceWithoutHosts` | warning, after 10 minutes | no host is known to run a service of the baseline |
| `ShawkBaselineFileInvalid` | warning, after 10 minutes | the latest read of a `baseline_file` failed: the baseline is the one read before |
| `ShawkBaselineDriftTruncated` | critical | more dependencies on named peers drift than the connector sends series for |
| `ShawkBaselineDriftUnresolvedTruncated` | warning, after 15 minutes | the same on `~unresolved` |
| `ShawkNewServiceWithoutBaseline` | info | services without a baseline appeared and opened connections |

- **No alert may stay silent where the drift is not known.** A drift
  that is firing does not resolve because nothing evaluates it any more:
  the connector goes on sending the drift it last knew while its
  evaluations fail, the alerts hold a drift for 30 minutes after its last
  series, and `ShawkBaselineNotEvaluated` fires within 20 minutes of the
  last evaluation, with the severity of the drift it stands for. The
  price is that a drift that was approved, or that ended, resolves 30
  minutes later. `ShawkBaselineNotEvaluated` also fires for 30 days after
  `baseline_file` is taken out of every connector on purpose: silence it
  then. Where no connector with `baseline_file` ever sent to a
  Prometheus, nothing in its rules knows that a baseline is meant to be
  evaluated: add an alert on
  `absent(shawk_baseline_evaluation_timestamp_seconds)` there.
- **The rules are tested as Prometheus evaluates them**:
  `packaging/prometheus/tests` holds unit tests for `promtool test rules`
  with the "for" and the annotations of the alerts, for the cases above.

One series, and so one alert, is a service, a peer, a port and a
transport, whatever the number of hosts: a release that opens a new
connection on every host of a service alerts once, and a release that
opens three alerts three times. A peer that is renamed alerts once per
service that uses it; group the alerts by `service_peer_name` in
Alertmanager where that matters. An alert resolves when the dependency
was not used for an hour, or when the baseline holds it.

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

OBI's traces go through the batch processor (`traces/obi`, at most 8192
spans a batch) to a trace store such as Tempo (`otlp_grpc/traces`), whose
queue is bounded as those to Prometheus are (§5.3). It stays enabled and
does not block, so that the retries of a batch (for 5 minutes by default)
do not block the batch processor, and with it the requests of OBI. It
counts the encoded bytes of the batches (`sizer: bytes`), not spans: a span
is as large as the attributes OBI reads from the applications (paths,
URLs, SQL queries). Measured as pdata, as the receiver makes them, a mix
of the spans of HTTP, gRPC, SQL and Redis requests takes about 750 bytes of
memory a span (250 encoded), an internal span without attributes 235 bytes
and one with a query of 2 KiB 3 KB, while memory stays within 1.3 to 3.5
times the encoded bytes. The default counts 1000 batches, which hold 200
seconds of spans whatever their rate, since the batch processor sends what
arrived within 200 ms: about 250 MB at 100 000 spans a minute, but about
5.7 GiB once batches are full (41 000 spans a second). While the store is
down that memory grows with the rate of spans, until `memory_limiter`,
which measures the whole collector, refuses the requests of agents, so that
PostgreSQL gets nothing either until the store is back. The example holds
64 MiB, about 200 MiB in memory whatever the rate, or 270 000 spans of 250
encoded bytes, which last 2.7 minutes at 100 000 spans a minute: size it
to the fleet and to the memory of the collector. With this sizer,
`otelcol_exporter_queue_size` and `otelcol_exporter_queue_capacity` are in
bytes, and the queue fills while the store is down at the rate of
`otelcol_exporter_enqueue_size_bytes_sum`, which the collector reports at
the `detailed` level of its telemetry. Spans beyond are dropped
(`otelcol_exporter_enqueue_failed_spans`), as are those still not sent when
their retries end (`otelcol_exporter_send_failed_spans`), and their traces
miss them. With the queues to Prometheus, those of the example hold up to
about 700 MiB, which must fit, beside what the connector holds (§5.5),
under the soft limit of `memory_limiter`: 60% of the memory of the
collector in the example.

A batch of 8192 spans is larger than the 4 MiB a gRPC receiver takes by
default (the OTLP receiver of a collector without `max_recv_msg_size_mib`)
once its spans average 512 encoded bytes, as with long SQL queries. The
receiver checks the size after decompression, so compression does not
help, and refuses the whole batch with `ResourceExhausted`, which the
exporter does not retry: every span of it would be lost
(`otelcol_exporter_send_failed_spans`). The batcher of the queue therefore
splits batches into requests of at most 3 MiB of encoded spans
(`batch` with `sizer: bytes` and `max_size`), below the 4 MiB as the
requests of agents are (§4.3); with `min_size: 0` it merges nothing, which
the batch processor does. A span larger than `max_size` alone is dropped
and logged (`Failed to split request`), the rest of its batch is sent. A
batch takes its room in the queue until all its requests are sent, so the
bound above holds. A store whose receiver takes less needs a smaller
`max_size`.

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
  manager) are recorded as outgoing from the server, and data that the
  MPTCP level resends is counted again, on another subflow or on the same
  one, which carries it as new data. A receiver can acknowledge data on its
  subflow before its MPTCP socket takes it; when the connection then goes
  idle, the sender resends that data after its retransmission timeout
  (`MPTCPRetrans`, and `DuplicateData` at the receiver, in
  `/proc/net/netstat`). With more open MPTCP connections than the owner
  map holds, the agent scans processes every interval.
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
  denies on output. The errors of resets and ICMP errors are recorded
  where the kernel produces them (§3.2): without the kprobes on
  `ip_icmp_error()` (no `CONFIG_KPROBES`, or `perf_event_open` denied), an
  application that reads the error while the kernel closes the socket
  takes it first, and a failure an ICMP error caused is counted as
  `timeout`: 0.01 to 0.05 % of them for a client that waits in poll(2) or
  epoll, up to 60 % for one that busy-polls the socket
  ([research/kernel-hooks](research/kernel-hooks/kernel_hooks.md) §5,
  #166). A recorded error that the LRU hash evicted, among more than 8192
  sockets in SYN_SENT with one at once, falls back the same way. UDP and
  QUIC have no kernel handshake.
- **Connections that predate the agent** are counted from the adoption on.
  One accepted by a listener with a backlog of 0 that is gone is recorded
  as outgoing.
- **Wire protocols** (§3.9) come from the first payload that a socket
  sends, once per connection. Some connections are not classified (those
  that predate the agent, `sendfile(2)` first, TCP Fast Open, MPTCP), so an
  edge without rows in `edge_protocols` is not proof of clear text.
  STARTTLS and a later switch to another protocol are not seen, and a
  signature can match another protocol that starts the same way (§3.9).
  `last_seen` tells the last new connection that showed a protocol, not
  the last use of the edge.
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
- **Wire protocols** (§3.9) are those of the first payload of each
  connection, with `-classify-protocols` only, whose program runs on every
  TCP send. The version of TLS that PostgreSQL and MySQL start later, and
  STARTTLS, are not seen, and a client and its server tell different
  versions of TLS. Some connections are not classified (§3.9): an edge
  without a protocol is no evidence of clear text, even from an agent that
  classifies. The signatures are matched on the first bytes, so a protocol
  that starts like another one is taken for it, and others are `unknown`.
- **The impact of removing a host** (§6.3) is told from what was observed
  in the period asked for, in PostgreSQL only (§5.8).
  - *The period.* A client that used the target before it, or that uses
    it less often than the period, is not a dependent, and the verdict is
    `SAFE` if the target was watched; the period must be longer than the
    rarest job that matters. A target is never `SAFE` without an agent of
    its own, however well its clients were observed.
  - *What no socket shows.* A host that only forwards packets is not seen
    to be used: a router, a hypervisor whose guests have the addresses, a
    bridge, and a load balancer whose kernel keeps no conntrack entry of
    what it forwards (IPVS at its defaults, without
    `net.ipv4.vs.conntrack=1`, #139) and for which no translation is
    configured. The clients of a relay are its dependents only through
    the translations its agent learned or the configuration gives (§5.4):
    an active director with neither, whose clients have no agent, is
    `SAFE` while it forwards their traffic. `shawk-impact` says so under
    every report.
  - *Masquerade.* The clients from outside that a host masqueraded to a
    pod or a container of its own are told by the translations its agent
    learned, and the verdict is not `SAFE` where the agent traces none or
    folds external peers (§6.3). With an agent that traces translations
    and folds nothing, a history without a translation still reads as
    no masqueraded client, and the verdict may be `SAFE`, where the
    translation is missing for another reason: a connection confirmed
    before the agent started, a table of translations of the agent that
    overflowed, or a datapath without netfilter conntrack (§3.7). Such a
    client shows only as the address of the host, which a client on the
    host may explain. The overflow is counted in Prometheus
    (`shawk.agent.translations.dropped`, to be watched) and not kept in
    PostgreSQL, so the verdict cannot know of it. Nor are protocols other than TCP, UDP and
    Unix stream sockets seen (RDMA, SCTP, ICMP, VRRP), nor what a service
    needs to run at all without a connection: a container runtime, a
    supervisor.
  - *Relays.* A client behind a relay that no translation describes is a
    dependent of the relay, not of the servers behind it, and the relay
    shows as a client of the server by its address. The clients that a
    host relays count for each of its services (`~relay`), since nothing
    tells which service keeps the translations of the kernel: a question
    about one service of a relay is `UNSAFE` while the host relays. A
    port narrows it.
  - *UDP.* The direction of a UDP exchange is that of its first datagram
    (§3.3), and the cases in which the agent takes a server for a client
    (issue #99: a socket that predates the agent, one used both ways, a
    QUIC server between scans) record the target as the client of its
    client: no dependent.
  - *Addresses and names.* The servers of a dependency that only its
    client saw are found by the addresses hosts held, which agents report
    unverified (below); while the agents of a host do not report, it
    keeps the addresses of their last report, so a client of an address
    that moved to a machine without an agent in the meantime counts for
    the host that had it. Names stand for hosts: two machines that share
    a name are one target, and hide each other's gaps.
  - *Clocks.* The coverage allows for a clock of the target that is
    behind, by the skew of its latest heartbeat; a clock that jumped
    within a session is not followed.
  - *Folded peers.* An agent that folds its peers (§3.6) does not tell
    which servers its processes used: while the target is not observed,
    its clients on such hosts are not tied to it, and a caller who
    accepts gaps (`min_coverage`) accepts that.
  - *Cadences* have the resolution of an hour and start when the
    connectors were upgraded to record the hours (migration 0004): a
    dependency is `unknown` until it has three runs, or a day, of hours;
    a connector of an earlier version that still writes makes the
    cadences of its hosts `unknown`. A job of a cycle longer than the
    period is a `one-off`.
  - Planned stops count as gaps. The walk follows the dependents of
    dependents by service and host, not by request: a dependent of depth
    2 uses a service that uses the target, which need not be on its path.
- **Rules and baselines** (§6.4) are made from what was observed in the
  period asked for, in PostgreSQL only (§5.8).
  - *What a rule denies.* Everything over TCP and UDP that was not seen
    in the period: a job that runs less often, a server that is used only
    when another fails, a client that was not there yet. The flows that
    the history holds from before the period are listed; what happened
    before the retention, or never yet, is not. Review the rules, and
    load the audit form, which counts what they would refuse, before the
    form that rejects.
  - *What no history of shawk holds* and a file that rejects would break:
    tunnels of the kernel (VXLAN, Geneve, WireGuard), whose outer packets
    no socket sends; virtual services of IPVS, which have no socket;
    protocols other than TCP and UDP for a drop-in of systemd, which
    blocks them all; and a connection that the host rewrites to an
    address its agent did not learn. The verdict cannot tell the first
    three, and is `COMPLETE` on such a host: the files list them, and the
    audit form shows them. The IPVS case was read from the kernel source
    and not run.
  - *Open connections.* The form that rejects, loaded on a host that did
    not track connections, stops the open connections whose peer sends
    next. The audit form, loaded first, lets the tracking take them up; a
    connection that stays silent for the whole audit is not taken up.
  - *Addresses.* A rule pins the addresses that the sockets saw. A peer
    that changes its address is denied until the rules are written again,
    and an address that passes to another machine is allowed as the one
    that had it. Public addresses that an agent folds (the default) are
    not kept: their rule allows every address on the port, and a drop-in
    of systemd with such a peer restricts nothing of that family.
  - *What rules cover.* TCP and UDP of the host itself. The rules of
    nftables accept every other protocol and do not filter what a host
    forwards for its containers; a drop-in of systemd has no ports, and
    allows an address in both directions. `RestrictAddressFamilies=`,
    policies of Kubernetes and of Cilium, and iptables are not written.
  - *Translations.* The backends of the connections that a host
    translates itself are allowed from the translations its agent learned
    (§3.7), with their limits. Where an agent traces no translation, or
    folds peers, which is its default, the rules are `INCOMPLETE`
    (`translations_not_learned`): the rules of a host are `COMPLETE`
    only with `-fold-external none`. A datapath without netfilter
    conntrack has no translation to learn, and nothing tells: such a host
    needs the audit form.
  - *Several machines under one name* are `INCOMPLETE` for rules, and so
    is a host that was installed again until the period starts after the
    last report of its first machine.
  - *Names.* A baseline is per service name, and a name is what a
    process declares. A process of another name in a unit that runs a
    service of the baseline is judged as that service. A process that
    takes the name of another service of the baseline is judged by that
    baseline; one in a unit that runs no service of the baseline, under a
    name without a baseline, is judged by none
    (`shawk_baseline_new_services` counts it once, when it appears); a
    socket without a known owner is judged by none. A service that is
    renamed, by a release or by
    an agent that names services otherwise (`-service-name-fallback`), is
    such a new service: it is counted once, when it appears, and nothing
    judges it until a baseline is written under its new name, while the
    baseline of the old name judges nothing. A peer that is renamed is a
    drift for each service that uses it.
  - *What a baseline tells apart.* The name of a server, its port and the
    transport: a server of the same name at another address is no drift,
    `~external` does not tell one public address from another, and
    `~unresolved` one private address without a known service from
    another. Name the ranges that matter in `peer_cidrs`, and keep their
    addresses with `-internal-peers`. Dependencies over Unix sockets are
    not judged.
  - *Names of servers whose agent is stopped* are those of their last
    known listeners, which hold for hosts that reported in the last 30
    days and not for a virtual address of a translation that an agent
    learned: a dependency on such a server may then be told as a drift on
    `~unresolved`, a warning.
  - *Hosts that come and go.* The history of a service is complete only
    when every host that ran it was observed for the whole period: a host
    that joined the service within it makes it `INCOMPLETE`, since what it
    did before its agent reported is not known. A fleet whose hosts live
    for days has no complete period longer than they do; `-min-coverage`
    or `-allow-incomplete` is then a standing choice. For the drift, a
    host that was removed runs its services for `baseline_host_memory` (a
    week) after its last report: until then the drift of those services
    is `INCONCLUSIVE` and `ShawkBaselineHostsNotObserved` fires. Nothing
    in the history tells a host that was removed from one whose agent was
    stopped, so the choice is how long to say "not known": shorten the
    memory where hosts come and go by design. A restart of an agent that
    takes more than 3 minutes makes the drift of its services
    `INCONCLUSIVE` for the hour that holds it.
  - *The alert of a drift* resolves 30 minutes after the drift ends, and
    `ShawkBaselineNotEvaluated` goes on for 30 days after the last
    connector with a `baseline_file` stopped (§8).
  - *Timing.* The drift is evaluated every 5 minutes, up to 5 minutes
    ago: a dependency is alerted 5 to 10 minutes after it was first used.
    Edges written more than an hour late, by an agent whose clock is
    behind, are judged only by `shawk-policy drift` over a longer period.
- **Clocks**: first and last seen times come from each host's clock, capped
  at 2 minutes ahead of the connector (§5.1); so does the segment start,
  capped at the request that carries it, which `clock_skew` converts;
  heartbeats come from the connector's clock, compared with PostgreSQL's.
  A series seen again after its host's clock stepped back to before its
  first time takes the new time as its first time too, so that it is never
  first seen after it was last seen. Keep clocks synchronized (chrony);
  `clock_skew` shows hosts that are not.
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
