# Passive path quality: design proposal

Status: proposal (2026-11-02), not implemented; no issue yet. It answers
whether shawk should do what Pingmesh [1] does: not its active probing,
but its measurements, taken on the connections that hosts open anyway. The
sections of `docs/design.md` that would change are listed in §6.

## 1. Problem

Pingmesh runs an agent on every server of a data center. The agent opens
TCP and HTTP connections to the servers on a list that a controller
generates: every server under the same top-of-rack switch, some servers of
every other rack, and some servers of the other data centers. From the time
these connections take to set up, it derives latency percentiles for each
pair of racks and of data centers. From the connections whose setup took 3
or 9 seconds (the retransmission timeouts of a lost SYN on Windows), it
estimates the packet drop rate. It answers *is it the network?*, and it
helps to localize black holes and silent drops to switches.

shawk already records, per dependency, connections established and failed,
retransmitted segments, and the smoothed RTT of open connections, sampled
at every walk (§3.1 of the design). It does not tell:

- **how long applications wait for a connection**, nor the distribution of
  that wait;
- **whether SYNs were lost.** SYN retransmissions are kept out of
  `shawk.tcp.retransmits`: `established_base()` takes `total_retrans` at
  the establishment as the base;
- **why a connection failed.** `conn_fails` lumps together several causes:
  - a refused connection (no listener: the service is down);
  - a timeout (no answer: the network, or a host that is gone);
  - an ICMP unreachable (routing, a firewall);
  - no free local port;
  - an application that gave up;
- **any of this per network location** rather than per service, which is
  how a network team reads it.

Active probing does not fit shawk (§5). The agent:

- opens no port (`packaging/systemd/shawk-agent.service`) and has no
  `CAP_NET_RAW`;
- receives no instructions, and knows no topology.

Beyond the agent, a full mesh of probes gives N² series, which the
Prometheus contract avoids (review P0-1). And the probes of a separate
prober would make every host look used, which spoils the very question
shawk answers. The measurement that Pingmesh makes, though (the time and
the losses of the TCP handshake), is available on every connection that
hosts open, at the state changes that shawk already traces.

## 2. Approach

- **Measure in the kernel**, for every active open:
  - how long the handshake took;
  - how many SYNs it retransmitted;
  - when it failed, why.

  These are additions to the existing `inet_sock_set_state` program. There
  is no new hook, no cost per packet and no traffic of its own.
- **Report them per dependency** like the other metrics: the mean connect
  time, SYN retransmissions, and failures by reason (`error.type`).
- **Optionally (phase 2), aggregate them per zone.** Zones are address
  ranges that the operator names after the network: racks, subnets, data
  centers. The result is a matrix of zones in Prometheus and a Grafana
  dashboard that reads like Pingmesh: connect time percentiles and the SYN
  loss ratio between zones, with drill-down to the source hosts.

What this gives up compared with Pingmesh: paths that carry no new
connections are not measured (§4).

## 3. Design

### 3.1 Kernel

**Handshake duration.**
- **Start.** At CLOSE→SYN_SENT (`on_active_open()`), the time is stored in
  the socket storage: `_pad` of `struct shawk_sock_state` becomes
  `__u32 syn_us` (`bpf_ktime_get_ns() / 1000`), so the storage does not
  grow.
- **Duration.** At SYN_SENT→ESTABLISHED, the duration is
  `(__u32)(now_us - syn_us)`. It is computed modulo 2³², which is valid for
  71 minutes, while `connect(2)` gives up after about 2 minutes by default.
- **Pending until counted.** The duration replaces the start in the same
  field, and a new flag `SS_HANDSHAKE` marks it pending. `count_conn()`
  adds it to the flow together with the connection. A handshake whose flow
  update was dropped is therefore added by the recount, like its connection
  (`SS_RECOUNT`).

Durations are counted in fixed buckets, so that percentiles can be read.
The bucket is found with a chain of at most 10 comparisons with constants.
The bounds are:

| bounds | for |
|---|---|
| 100 µs, 250 µs, 500 µs, 1 ms | within a rack and within a data center |
| 2.5 ms, 10 ms, 50 ms, 250 ms | between data centers and regions, WAN |
| 1 s, 3 s | Linux retransmits a SYN after the initial RTO of 1 s, then 2 s later (1, 3, 7, ... s after the first). One lost SYN or SYN-ACK puts a handshake in (1 s, 3 s]; two or more put it above 3 s. |

**SYN retransmissions.**
- At SYN_SENT→ESTABLISHED and at SYN_SENT→CLOSE, `tcp_sock.total_retrans`
  counts only the SYNs retransmitted. No data has been sent yet; data
  carried by a Fast Open SYN is retransmitted after the establishment.
- The count is added to the flow.
- A lost SYN-ACK shows up as a retransmitted SYN too, since the client
  hears nothing.

**Failure reasons.** At SYN_SENT→CLOSE, the kernel has already set `sk_err`
(in `tcp_reset()`, `tcp_write_err()`, and `tcp_v4_err()` or `tcp_v6_err()`).
`tcp_sock.segs_out` tells whether a SYN left at all.

| `sk_err` | `segs_out` | `error.type` | meaning |
|---|---|---|---|
| `ECONNREFUSED` | | `refused` | reset by the peer: no listener, or a firewall that rejects with a reset |
| `ETIMEDOUT` | | `timeout` | no answer to any SYN (`tcp_syn_retries`, `TCP_USER_TIMEOUT`) |
| `EHOSTUNREACH`, `ENETUNREACH` | | `unreachable` | ICMP from a router or a firewall, or no answer to ARP/ND |
| 0 | 0 | `local` | no SYN left the host: no free local port (`EADDRNOTAVAIL` from `inet_hash_connect()`) |
| 0 | > 0 | `aborted` | the application closed the socket first, usually after its own connect timeout |
| any other | | `other` | |

**Which connections.**
- Included: the active opens that shawk counts as connections, including
  the sockets of the kernel (an NFS client that keeps reconnecting is worth
  seeing).
- Excluded: the additional subflows of MPTCP (`SS_JOIN`) and the agent's
  own connections (`SS_IGNORE`).
- Not measured: connections adopted at startup, which have no handshake.
- Later: passive opens (phase 3, §8).

**Flow statistics.** `struct shawk_flow_stats` grows by 80 bytes:

```c
__u64 hs_sum_us;              /* sum of the handshake durations */
__u32 hs_buckets[HS_BUCKETS]; /* established active opens by duration (11) */
__u32 syn_retrans;            /* SYNs retransmitted by active opens */
__u32 fails[FAIL_REASONS];    /* failed active opens by reason (5);
                                 conn_fails minus their sum is other */
```

The number of handshakes is the sum of the buckets. With the default
`-max-flows` of 16384, the two flow maps take 2.6 MB more.

**Cost.**
- On every connection: one `bpf_ktime_get_ns()` per active open and one per
  establishment, the comparisons, and two or three atomic adds on a flow
  that is looked up anyway.
- On failure only: reads of `sk_err`, `segs_out` and `total_retrans`.
- It is measured with `-bpf-stats` (§7).

**Kernel versions.** `sk_err`, `segs_out` (Linux 4.6) and `total_retrans`
exist on 5.14. `make compat` checks the relocations against Rocky Linux 9.

### 3.2 Agent

New internal OTLP metrics on the client edges of TCP
(`internal/otlp/names.go`):

| metric | type |
|---|---|
| `shawk.tcp.handshake` | cumulative histogram with the bounds of §3.1, unit `s` |
| `shawk.tcp.syn_retransmits` | sum, `{segment}` |
| `shawk.connection.failed` | sum as now, with one data point per reason in `error.type` (the reasons of §3.1, `other` for the rest) |

Like the other metrics, they are sent for every live series. `shawk flows`
shows the mean handshake, the SYN retransmissions and the failures by
reason.

### 3.3 Connector: per dependency

**Input.** `input.go` reads:
- the histogram with its buckets;
- the new sum;
- `error.type`, as part of `valueKey`, like `network.io.direction`.

**Output.** New series alongside the others (`outMetrics`):

| Prometheus | |
|---|---|
| `shawk_tcp_handshake_seconds_sum`, `_count` | a histogram without buckets, like the RTT: the mean connect time of a dependency |
| `shawk_tcp_syn_retransmits_total` | |
| `shawk_connection_failed_total{error_type}` | the existing metric, by reason |

**No buckets per dependency.** They would add 12 series to every client
dependency of TCP, and percentiles are read per zone instead (§3.4). A
dependency with a bad tail still shows up in its mean, in its SYN
retransmissions and in the matrix of its zones.

**Counting** (§7 of the design). All three come from the client side only,
like failures today, so each dependency is counted once. New recording
rules:
- `shawk:dependency_handshake_seconds_sum:rate5m` and `_count:rate5m`;
- `shawk:dependency_syn_retransmits:rate5m`;
- `shawk:dependency_connection_failures_by_reason:rate5m`.

`shawk:dependency_connection_failures:rate5m` keeps its labels.

### 3.4 Connector: zones and path metrics (phase 2)

**Configuration.** Zones have the same form as `peer_cidrs`:

```yaml
connectors:
  shawk:
    zones:
      dc1/rack01: 10.1.1.0/24
      dc1/rack02: 10.1.2.0/24
      dc2: 10.2.0.0/16, fd00:2::/48
```

- The narrowest range wins.
- Names do not start with `~`. By convention, `/` separates levels, and the
  recording rules roll the first level up into `shawk_site`.
- Without `zones` (the default), no path metric is emitted.

**Zones of the two ends of a client edge of TCP.**
- **Local zone.** The zone of the local address. When no zone holds it (a
  container address behind NAT), it is the zone of the host's addresses
  (`host.ip`) if one zone holds them all; otherwise it is `~unzoned`.
- **Peer zone.**
  - The zone of the peer address.
  - `~unzoned` for an address not routed on the Internet that no zone
    holds.
  - `~external` for any other address and for folded peers.
- **Left out:** loopback, connections to the host's own addresses, and UDP.

**Output.** The inputs of a host are summed per local zone and peer zone.
The sums are emitted once per interval, with the metrics of the agent and
under its resource: `job="shawk-agent"`, `instance` the host name,
`host_id`, `host_name`.

| Prometheus | labels |
|---|---|
| `shawk_path_tcp_handshake_seconds_bucket`, `_sum`, `_count` | `shawk_zone`, `shawk_peer_zone`, `le` |
| `shawk_path_tcp_syn_retransmits_total` | `shawk_zone`, `shawk_peer_zone` |
| `shawk_path_connection_failed_total` | `shawk_zone`, `shawk_peer_zone`, `error_type` |

Inputs become outputs as in §5.3 of the design (cumulative, baselines on
first sight, resets detected), bucket by bucket.

**Series.**
- **Cap.** Per host and local zone, at most `max_peers` peer zones; the
  rest are folded into `~other`.
- **Per pair of zones.** About 20 series: 13 for the histogram, 1 for the
  SYN retransmissions, up to 6 for the failures.
- **Example.** 500 hosts that each talk to 20 zones give 200 000 series.
- **Knobs.** How fine the zones are is the main one. Native histograms
  with custom buckets would make each histogram one series (decision 6).

**Why per host.** Pingmesh localizes a problem by comparing the sources.
The matrix gives the pairs of zones; the hosts behind a cell tell where to
look:

| what the matrix shows | where to look |
|---|---|
| one source host is bad towards every zone | that host: its NIC, its link, its CPU (softirq) |
| every source of zone A is bad towards every zone | the uplinks of A, e.g. its top-of-rack switch |
| every source is bad towards zone B | B: its switch, or its servers dropping SYNs on full listen queues (§4) |
| one pair of zones is bad | the path between them |
| a steady fraction of the connections between two zones fails, not all | a link or an ECMP member that drops some flows (the black holes of Pingmesh); locating it takes traceroute (§5) |

**Recording rules.**
- `shawk:path_handshake_seconds_bucket:rate5m` and `_count:rate5m`, summed
  by `shawk_zone`, `shawk_peer_zone` (and `le`);
- `shawk:path_syn_retransmits:rate5m`;
- `shawk:path_connection_failures:rate5m` (with `error_type`);
- the same rolled up by `shawk_site`.

The SYN loss ratio of a pair is its SYN retransmissions divided by its
attempts (handshakes plus failures). Percentiles come from
`histogram_quantile()`.

**Alerts** (examples; the thresholds are to be tuned):
- `ShawkPathSynLoss`: the SYN loss ratio between two zones is above 1 %
  for 15 minutes, with at least one attempt per second;
- `ShawkPathConnectTimeouts`: `timeout` and `unreachable` failures between
  two zones for 10 minutes.

### 3.5 Grafana

- **shawk / Dependency details**: the mean connect time, SYN
  retransmissions per attempt, and failures by reason (stacked).
- **shawk / Network paths** (new, phase 2):
  - **Matrices** (Grafana's grouping-to-matrix transformation, colored
    cells): p99 connect time, SYN loss ratio, timeouts.
    - Each cell shows its number of attempts.
    - Cells with fewer than `$min_attempts` are left blank, so that a few
      samples are not read as a trend.
  - **Hosts of a pair of zones**: a table of the source hosts behind the
    selected cell, worst first.
  - **Over time**: p50 and p99 of the selected pair.

## 4. Limitations

- **Coverage.** Only connections that are opened are measured: paths
  without new connections are not, which is what active probing would add.
  - Connection pools open few connections. Their established connections
    are still covered by the sampled RTT (`shawk.tcp.rtt`) and their
    retransmissions.
- **What the duration holds.**
  - It starts in `connect(2)` before the local port is chosen, so it
    includes `inet_hash_connect()`, which slows down when the ephemeral
    ports to a destination run out.
  - It ends when the SYN-ACK is processed, which happens in the kernel of
    both hosts, not in the server application.
  - A server whose softirqs are saturated inflates it.
- **SYNs dropped by servers.**
  - A listener whose accept queue is full drops SYNs. A SYN queue that is
    full without SYN cookies does the same.
  - The client sees this as a lost SYN, like a network loss. In the matrix,
    it shows as "every source is bad towards zone B".
  - Phase 3 adds the listen drops of the server to tell the two apart.
- **Retransmission timing.** The buckets assume the initial RTO of 1 s,
  which a BPF `sock_ops` program can change.
- **Relays.** A proxy or a load balancer that terminates TCP is the end of
  the measured path. A connection to a virtual IP takes the zone of the
  VIP, as in §10 of the design.
- **`aborted` depends on the applications:** a short connect timeout in an
  application turns network losses into `aborted`. Their SYN
  retransmissions are still counted.
- **No location below a zone.** shawk tells which hosts and zones, not
  which link or switch; that takes traceroute (§5).
- **TCP only.** UDP has no handshake. QUIC sets up its connections in user
  space.

## 5. Alternatives not taken

| alternative | why not |
|---|---|
| Active probing in the agent, as Pingmesh does | It needs a port open on every host for the probes, or `CAP_NET_RAW` for ICMP. It needs a controller to distribute the lists, and knowledge of the topology. Its traffic grows with the square of the hosts, and so do its series. It measures what probes see, not what applications see. A separate prober (Cloudprober, blackbox_exporter) does it better, beside shawk, like OBI (§9 of the design). |
| Connection setup time from a separate prober | Its connections are recorded as dependencies of every host, so "who still uses this host?" always answers the prober, unless every query filters it out. |
| The first RTT sample after the handshake (`srtt_us >> 3` at ESTABLISHED) instead of the time from `connect(2)` | It leaves out the retransmission waits that applications see. Without TCP timestamps, Karn's algorithm skips the sample when the SYN was retransmitted, so it is biased towards the good cases. It could be added later as the RTT of the path. |
| Counting SYN retransmissions with a hook on `tcp_retransmit_skb` | A new hook on a kernel function (fentry: its signature can change, and fentry is not available on Rocky Linux 9 on arm64), while `total_retrans` already holds the count. |
| The kernel's counters (`TcpExtTCPSynRetrans` in `/proc/net/netstat`) | They count per host, without a peer, so they cannot localize anything. Listen drops from the same file are useful as an explanation (phase 3). |
| Buckets per dependency in Prometheus | 12 more series for every client dependency of TCP. The mean per dependency and the percentiles per zone answer the questions. |
| Series per pair of hosts | N² series, against review P0-1. Hosts appear only as sources of a pair of zones. |
| Zones in `peer_cidrs` | `peer_cidrs` names peers without a service. Rack ranges added there would rename those peers on the dependency map and in `service.peer.name`. Topology and naming are kept apart. |
| Percentiles or sketches in the kernel | Complex under the verifier. Fixed buckets are enough for the questions of §1. |
| Path quality in PostgreSQL | PostgreSQL holds relations and their periods, not time series. |
| Localizing links with traceroute, as 007 does [2] | It sends probes, and it needs routers that answer them. It is out of scope; the matrix tells where to start. |

## 6. Compatibility, migration and documents

- **BPF object.** `shawk.h` changes; regenerate the object and the types of
  bpf2go.
- **Order of upgrade: connectors first.**
  - An old connector ignores the new metric names: `addMetric()` returns
    for a name it does not know. But it keeps only one data point of
    `shawk.connection.failed` per edge, so it would undercount the failures
    of a new agent.
  - A new connector reads agents of the previous version: they produce no
    handshake series, and their failures have no `error.type`, so their
    outputs have no `error_type` label.
- **Prometheus contract.**
  - New metrics are added.
  - `shawk_connection_failed_total` gains `error_type`, so its series are
    replaced when the connector is upgraded. Rates and sums over labels
    are not affected beyond the first 5 minutes.
  - The existing recording rules keep their labels.
- **PostgreSQL:** no change.
- **Configuration:** `zones` in the connector. The agent gets no flag: the
  cost is negligible and there is nothing to choose.
- **Documents to change:**
  - `docs/design.md`: §3.1 (what is recorded), §3.2 (the table of hooks),
    §5.3 (the table of metrics), §7 (the counting table), §8 (dashboards),
    §10 (the limitations of §4);
  - README: Prometheus row, dashboards, a PromQL example;
  - `packaging/README.md`;
  - CHANGELOG.

## 7. Tests

**BPF** (`make test-root`, VM tests), in a network namespace:
- **Loopback.** One handshake per connection, in the lowest buckets. None
  for MPTCP join subflows, the agent's own connections, or connections
  adopted at startup.
- **One lost SYN.**
  - Set up a listener with a backlog of 1 whose queue is full (it does not
    accept), so that it drops SYNs.
  - Accept after 1.5 s, which lets the retransmitted SYN through.
  - Expect a handshake in (1 s, 3 s] and `syn_retrans` of at least 1.
- **Each reason:**
  - `refused`: a closed port;
  - `timeout`: a dummy interface, which drops every packet, with
    `net.ipv4.tcp_syn_retries=1` in the namespace (about 3 s);
  - `unreachable`: a veth to a namespace without the address (ARP fails);
  - `local`: `ip_local_port_range` of one port, held by a connection to the
    same server;
  - `aborted`: a non-blocking connect through the dummy interface, closed
    after 100 ms.
- **Delay**, where `tc` is in the VM image: netem with 5 ms of delay puts
  handshakes in (2.5 ms, 10 ms].
- **Dropped update.** A flow update dropped at the establishment (a tiny
  `-max-flows`) is recounted with its handshake.

**Kernel compatibility.** `TestKernelCompatibility` and `make compat`.

**Agent.** Golden tests of the OTLP: the bounds, and the data points of
`error.type`.

**Connector:**
- deltas bucket by bucket, resets and baselines;
- `error.type` in the keys;
- input from agents of the previous version;
- zones:
  - parsing, the narrowest range;
  - the fallback to the zone of the host;
  - loopback and the host's own addresses left out;
  - folded peers as `~external`;
  - the `~other` cap;
  - no path output without `zones`;
  - path outputs emitted once per interval with the agent's resource.

**Packaging.** Extend the tests in `test/packaging` (names, rules,
dashboards).

**e2e.** Hosts in two zones of namespaces; check the dependency outputs and
the path outputs of the collector.

**Performance.** A storm of connections on loopback; compare the run time
of `shawk_inet_sock_set_state` with `-bpf-stats` before and after.

## 8. Phases

1. **Phase 1:** §3.1–§3.3, the panels of the dependency details dashboard,
   the rules, the documents.
2. **Phase 2:** §3.4–§3.5: zones, path metrics, the network paths dashboard
   and alerts.
3. **Phase 3** (separate issues, measured first):
   - **The server side of passive opens,** for clients without an agent:
     - SYN-ACK retransmissions. `tcp_create_openreq_child()` is expected
       to copy the retransmissions of the request into `total_retrans`; to
       be verified;
     - the RTT sample of the SYN-ACK.

     It is counted only when the client has no agent, as in §7 of the
     design.
   - **The loss ratio of data:** deltas of `segs_out`, accounted like the
     bytes, against `shawk.tcp.retransmits`.
   - **Listen overflows and drops** per network namespace, as metrics of
     the agent, to tell overloaded servers from network losses.

## 9. Decisions to make

1. Measure the handshake from `connect(2)` (recommended) or take the first
   RTT sample (§5).
2. The bucket bounds of §3.1.
3. Where the reason of a failure goes.
   - In Prometheus: `error_type` on `shawk_connection_failed_total`
     (recommended), or a new metric.
   - In OTLP: on the existing metric, with connectors upgraded first
     (recommended), or as a separate internal metric that keeps either
     order of upgrade right.
4. Zones apart from `peer_cidrs` (recommended).
5. Path metrics under the resource of the agent (`job="shawk-agent"`,
   recommended) or under a job of their own.
6. Whether to rely on native histograms with custom buckets.
   - To be verified: whether the Prometheus in use stores the
     explicit-bucket histograms it receives over OTLP that way, and with
     which setting.
   - The proposal does not depend on it: classic buckets work, at the cost
     of §3.4.

## References

1. Chuanxiong Guo et al. *Pingmesh: A Large-Scale System for Data Center
   Network Latency Measurement and Analysis.* SIGCOMM 2015.
2. Behnaz Arzani et al. *007: Democratically Finding the Cause of Packet
   Drops.* NSDI 2018.
