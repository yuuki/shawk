# Design of shawk

shawk is a **dependency ledger**: it records which process talks to which
network service on every host, keeps that record for years, and answers
operational questions such as *"who still uses this database?"* or *"can I
remove this host?"* with evidence.

It is built on the socket-based tracing method with in-kernel flow bundling
proposed in

> Yuuki Tsubouchi, Masahiro Furukawa, Ryosuke Matsumoto. *Low Overhead TCP/UDP
> Socket-based Tracing for Discovering Network Services Dependencies.* Journal of
> Information Processing, Vol. 30, pp. 260–268, 2022.

and follows the future work of the paper: a tool for containerized and
classic hosts that works **without a central database**.

## 1. Why a ledger

The paper is motivated by changes whose impact administrators cannot
predict: platform migrations where old and new systems coexist, and clients
such as batch jobs that talk to a server only once a day or a week, which
sampling-based tracing misses. Answering those needs

- **completeness**: every process, every TCP/UDP service, including
  middleware and third-party software that cannot be instrumented;
- **always-on tracing** with low overhead, so that rare dependencies are
  observed;
- **long retention**, so that "nobody used it in the last 90 days" is a
  statement backed by data.

Existing eBPF service maps (Coroot, Pixie, Hubble, Beyla, ...) focus on the
present state and on Kubernetes. shawk focuses on history and questions, and
on VMs and on-premises hosts (the primary target is Rocky Linux 9, kernel
5.14).

## 2. Architecture

```
          host A                          host B
 ┌──────────────────────────┐   ┌──────────────────────────┐
 │ processes                │   │ processes                │
 │   │ TCP/UDP sockets       │   │                          │
 │ ──┼────────────── kernel │   │                          │
 │ eBPF: bundle flows       │   │ eBPF                     │
 │   │ every interval       │   │                          │
 │ shawk agent ─ ledger.db  │   │ shawk agent ─ ledger.db  │
 │   └ HTTP API :7464       │   │   └ HTTP API :7464       │
 └───────────▲──────────────┘   └───────────▲──────────────┘
             │      shawk who-uses / deps / graph ...      │
             └──────────────── CLI (anywhere) ─────────────┘
```

* The **agent** on each host traces flows, resolves process identities and
  records the dependencies of *its own host* in a local SQLite ledger.
* There is **no central database**. A query walks edges across agents: an
  incoming edge on the server tells the client address; the agent on that
  address tells which process the client is (and its own clients, and so on).
  When both ends run an agent, an edge is recorded on both hosts, so the
  history of a decommissioned host survives on its peers.
* Peers without an agent (external clients, managed services) appear as
  addresses.

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
These are the edge weights listed in §2.4 of the paper.

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
* **Stable ABI.** `inet_sock_set_state` is a tracepoint; no kernel function
  signature is assumed (e.g. `inet_csk_accept` changed in Linux 6.10).
* **Works without BPF trampolines** (fentry/fexit), e.g. on kernels that
  restrict ftrace, or on arm64 before Linux 6.0.
* **Connections that predate the agent are found** (DB connection pools,
  gRPC channels). The original streaming mode never saw them.
* **IPv6** and **MPTCP** are handled. Go listens with MPTCP by default since
  1.24; its listening socket is an MPTCP socket whose TCP subflows carry the
  traffic, so MPTCP listeners are reported as TCP listeners.

The owner of an incoming connection is the owner of the listening socket.
User space resolves it from `iter/task_file`, preferring a service process to
systemd (which shares listeners of socket-activated services) and the parent
to forked workers. This makes the identity of the server side independent of
which worker thread accepted the connection.

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
active index, waits a grace period, and drains the inactive map. Programs
never write to the map being read.

### 3.5 Kernel requirements and features used

Linux ≥ 5.14 with BTF (`CONFIG_DEBUG_INFO_BTF`), e.g. Rocky Linux 9.

| feature | since |
|---|---|
| BTF-enabled tracepoints (`tp_btf`) | 5.5 |
| BPF iterators `tcp`, `udp`, `task_file` | 5.8 / 5.9 |
| socket local storage in tracing programs | 5.11 |
| `bpf_sock_from_file`, `bpf_get_current_task_btf` | 5.11 |
| fentry (UDP only) | 5.5 on x86_64, 6.0 on arm64 |

All struct accesses use CO-RE. `TestKernelCompatibility` checks every
attach target, helper and CO-RE relocation against the BTF of the Rocky Linux
9.6 kernel (`scripts/fetch-kernel-btf.sh`); for example `sk_userlocks` is a
plain byte in recent kernels but a 4-bit bitfield at a different offset in
5.14.

## 4. The ledger

### 4.1 Data model

```
edges(direction, proto, local_addr, remote_addr, port, netns, unit, comm,
      cgroup, exe, last_pid, first_seen, last_seen)
activity(edge_id, res, ts, conns, conn_fails, max_open_conns, bytes_sent,
         bytes_recv, msgs_sent, msgs_recv, retrans, rtt_sum_us, rtt_count)
listeners(proto, addr, port, netns, unit, comm, cgroup, exe, pid,
          first_seen, last_seen)
```

* An **edge** is a bundled flow with a resolved, *stable* process identity:
  `unit` is derived from the cgroup path (`nginx.service`,
  `docker-0123456789ab`, `user-1000.slice/session.scope`, ...). Names that
  change on every run (login sessions, transient units) are normalized so that
  a cron job accumulates under one edge.
* **activity** keeps counters in buckets of one minute, one hour and one day.
  All three are updated at every interval, so no roll-up job is needed;
  retention is per resolution (2 days, 90 days and 3 years by default).
* `first_seen` / `last_seen` make the core questions cheap: *what appeared
  since the deployment*, *who used this in the last 90 days*.

### 4.2 Choice of the storage engine

Requirements: embedded in the agent (no server to operate), crash-safe,
small footprint, a single static binary for easy deployment on RHEL-family
hosts, flexible queries (by port, by peer, by time window, joins of edges and
activity), and inspectable by operators. The write load is small *because of
the in-kernel bundling*: one upsert per dependency and resolution per
interval (a host with 500 dependencies and a 15 s interval does ~100 upserts
per second in one transaction).

| candidate | assessment |
|---|---|
| **SQLite** (modernc.org/sqlite, pure Go) | Relational queries, upserts, indexes, WAL for concurrent readers, a single file that operators can open with `sqlite3` for audits. No cgo. Throughput is far beyond the load. **Chosen.** |
| bbolt | Pure Go, ACID, but key-value only: every query and index would be hand-written. |
| Pebble / BadgerDB | LSM trees optimized for high write throughput, which bundling makes unnecessary; compaction and tuning add operational weight; no query language. |
| DuckDB | Excellent for analytics, but requires cgo, adds tens of MB, and is single-writer per process; analytical scans are not the workload. |
| Embedded Prometheus TSDB / VictoriaMetrics | Good for numeric series, but a dependency is a relational entity with first/last seen and identity attributes; "edges by port" or "first seen" queries are awkward and label cardinality grows with peers. Exporting metrics to such systems is a better fit than storing the ledger in them. |
| Plain files (JSON lines / Parquet) | Simple to write but every query becomes a scan; no transactional upserts. |

## 5. Queries

| command | question |
|---|---|
| `who-uses HOST[:PORT]` | Who uses this service? With `-depth N`, who is affected transitively (blast radius). |
| `deps HOST[/UNIT]` | What does this process depend on, transitively? |
| `can-i-remove HOST[:PORT]` | Did any remote process use it in the window? Exit status 1 if so. Warns when the ledger is younger than the window. |
| `unused HOST` | Which listening services had no client in the window? |
| `diff HOST -since 24h` | Which dependencies appeared or disappeared (e.g. after a deployment)? |
| `graph HOST... -depth N` | Export the graph around hosts as Mermaid, Graphviz or JSON. |

Traversal resolves the process at the other end of an edge by querying the
peer's agent with the reverse edge (`direction=out, remote=<server address>,
port=<port>` for clients; `direction=in, remote=<client address>` for
servers). Loopback and the host's own addresses refer to the same agent.

## 6. Limitations

* **Relays that rewrite addresses** (NAT, IPVS, kube-proxy, cloud load
  balancers) hide the real peer, as discussed in §5.2 of the paper. Edges end
  at the relay address. Resolving them through the conntrack table is future
  work.
* **Same port shared by different services** with `SO_REUSEPORT` cannot be
  told apart (§5.3 of the paper); this is rare.
* **UDP peer-to-peer protocols** where neither side binds a port are recorded
  with the peer's ephemeral port as the service port.
* **Clocks**: `first_seen`/`last_seen` use the clock of each agent.
* The agent API is plain HTTP with an optional bearer token; put it on a
  management network or behind TLS termination.
