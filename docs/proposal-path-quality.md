# Passive path quality: design proposal

Status: phase 1 (§3.1–§3.3) implemented (2026-11-03); phases 2 and 3
proposed; no issue yet. The decisions of §9 are made. It answers
whether shawk should do what Pingmesh [1] does: not its active probing,
but its measurements, taken on the connections that hosts open anyway.
It was revised after an adversarial review (§10); what the implementation
of phase 1 changed or left out is in §11. The sections of
`docs/design.md` that change are listed in §6.

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

Active probing does not fit shawk (§5). It needs:

- a controller that hands out the lists, and knowledge of the topology;
- a way to probe: a responder on every host, ICMP, or the ports of the
  services. The agent opens no port and has no `CAP_NET_RAW`.

It also adds traffic and series for every pair it probes, and it measures
what probes see, not what applications see. The measurement that Pingmesh
makes, though (the time and the losses of the TCP handshake), is available
on every connection that hosts open, at the state changes that shawk
already traces.

## 2. Approach

- **Measure in the kernel**, for every active open:
  - how long the handshake took;
  - how many SYNs it retransmitted;
  - when it failed, why.

  These are additions to the existing `inet_sock_set_state` program. There
  is no new hook, no cost per packet and no traffic of its own.
- **Report them per dependency** like the other metrics: the mean connect
  time, SYN retransmissions, and failures by reason (`error.type`) in a new
  metric. The existing metrics do not change.
- **Optionally (phase 2), aggregate them over the network.** Zones are
  address ranges that the operator names after the network (racks,
  subnets), grouped into sites (data centers). There are three levels, as in
  Pingmesh:
  - percentiles between sites;
  - means and loss between the zones of a site;
  - per source host, to localize.

  A Grafana dashboard shows them as matrices.

What this gives up compared with Pingmesh: paths that carry no new
connections are not measured (§4).

## 3. Design

### 3.1 Kernel

**Handshake duration.**
- **Start.** At CLOSE→SYN_SENT (`on_active_open()`), `bpf_ktime_get_ns()`
  is stored in a new `__u64 syn_ns` of `struct shawk_sock_state`. The
  storage of a TCP socket grows from 104 to 112 bytes.
- **Duration.** At SYN_SENT→ESTABLISHED, the duration is
  `(now - syn_ns) / 1000`. It is saturated to 32 bits (71 minutes) and
  stored in the former `_pad` as `__u32 hs_us`.
- **Pending until counted.** A new flag `SS_HANDSHAKE` marks the duration
  pending. `count_conn()` adds it to the flow together with the connection,
  and so do the SYN retransmissions (below). A handshake whose flow update
  was dropped is therefore added by the recount, like its connection
  (`SS_RECOUNT`).

Durations are counted in fixed buckets, so that percentiles can be read.
The bucket is found with a chain of at most 10 comparisons with constants.
The bounds are:

| bounds | for |
|---|---|
| 100 µs, 250 µs, 500 µs, 1 ms | within a rack and within a data center |
| 2.5 ms, 10 ms, 50 ms, 250 ms | between data centers and regions, WAN |
| 1 s, 3 s | they separate the handshakes that waited for a retransmission timeout from those that did not |

The buckets measure latency only. How many SYNs were lost comes from the
SYN retransmissions, not from the bucket, because the schedule depends on
the kernel:

| kernel | SYNs sent at | gives up at |
|---|---|---|
| Rocky Linux / RHEL 9, upstream without `tcp_syn_linear_timeouts` (5.14, 5.15, 6.4) | 0, 1, 3, 7, 15, 31, 63 s | 127 s |
| upstream with `net.ipv4.tcp_syn_linear_timeouts` (6.12, 6.18; default 4) | 0, 1, 2, 3, 4, 5, 7, 11, 19, 35, 67 s | 131 s |

These defaults change with `tcp_syn_retries` and `TCP_SYNCNT`, with
`tcp_rto_max_ms` and `TCP_RTO_MAX_MS` on newer kernels, and with BPF
`sock_ops` programs.

**SYN retransmissions.**
- At SYN_SENT→ESTABLISHED, `tcp_sock.total_retrans` counts only the SYNs
  retransmitted: data carried by a Fast Open SYN is retransmitted after
  `tcp_finish_connect()`. `established_base()` already stores it in
  `retrans_base`, which keeps it until `take_tcp_delta()` first runs, after
  the recount. `count_conn()` adds it from there.
- At SYN_SENT→CLOSE, it is added with the failure.
- What it counts are retransmission *attempts*, not losses on the wire:
  - It includes SYNs dropped on the local host (netfilter, egress BPF,
    qdisc).
  - It includes the SYN that is sent again after an unacceptable ACK.
  - It leaves out retransmissions skipped while the previous copy is still
    queued, e.g. during neighbor resolution.
  - A lost SYN-ACK shows up as a retransmitted SYN too, since the client
    hears nothing.

**Failure reasons.** At SYN_SENT→CLOSE, the rules below are applied in
order:

| condition | `error.type` | meaning |
|---|---|---|
| `segs_out == 0`, with `tcp_sock.fastopen_connect` | `aborted` | a Fast Open connect deferred to the first write (`TCP_FASTOPEN_CONNECT`) was closed before writing |
| `segs_out == 0` | `local` | `tcp_connect()` did not get as far as building a SYN: no free local port (`EADDRNOTAVAIL` from `inet_hash_connect()`), no buffer, no route at that point. A stale `ECONNRESET` left by `connect(AF_UNSPEC)` is ignored here. |
| `sk_err` `ECONNREFUSED` | `refused` | a reset from the peer (no listener), or ICMP port unreachable, which is the default of iptables `REJECT` and nft `reject` |
| `sk_err` `ETIMEDOUT` | `timeout` | no answer to any SYN (`tcp_syn_retries`, `TCP_USER_TIMEOUT`) |
| `sk_err` `EHOSTUNREACH`, `ENETUNREACH`, `EHOSTDOWN`, `ENONET`, `EACCES` | `unreachable` | ICMP from a router or a firewall (firewalld rejects with administratively prohibited: `EHOSTUNREACH` over IPv4, `EACCES` over IPv6), or no answer to ARP/ND |
| `sk_err == 0`, socket not owned by a process (`sk_lock.owned == 0`) | from `sk_err_soft`, else `timeout` | a timer or an ICMP error closed it, but user space already read the error. On 5.14 and RHEL 9, `tcp_write_err()` and `tcp_v4_err()`/`tcp_v6_err()` report the error before `tcp_done()`, and `SO_ERROR` takes it without the socket lock. |
| `sk_err == 0` | `aborted` | the application closed the socket first (under the socket lock), usually after its own connect timeout |
| any other `sk_err` (`ECONNABORTED` from `ss -K`, `EPROTO`, ...) | `_OTHER` | the fallback value of OpenTelemetry for `error.type` |

**Which connections.**
- **Included:** the active opens that shawk counts as connections,
  including the sockets of the kernel (an NFS client that keeps
  reconnecting is worth seeing).
- **Excluded:** the additional subflows of MPTCP (`SS_JOIN`: `count_conn()`
  returns early for them) and the agent's own connections (`SS_IGNORE`).
- **No duration:**
  - sockets in `TCP_REPAIR` (CRIU), which become ESTABLISHED without a SYN;
  - deferred Fast Open connects, whose wait includes the application's own
    time until its first write. Their SYN retransmissions are still
    counted.
- **No handshake at all:** connections adopted at startup, and a
  simultaneous open, which counts as a connection.
- **Later:** passive opens (phase 3, §8).

**Flow statistics.** `struct shawk_flow_stats` grows from 56 to 136 bytes:

```c
__u64 hs_sum_us;              /* sum of the handshake durations */
__u32 hs_buckets[HS_BUCKETS]; /* established active opens by duration (11) */
__u32 syn_retrans;            /* SYNs retransmitted by active opens */
__u32 fails[FAIL_REASONS];    /* failed active opens by reason (5);
                                 conn_fails minus their sum is _OTHER */
```

- The number of handshakes is the sum of the buckets.
- The flow maps are preallocated, so the two of them take 2.6 MB more with
  the default `-max-flows` of 16384.
- The zero value that `flow_get()` inserts moves from the stack to a
  `static const` in `.rodata`. Otherwise every program that calls it grows
  by 80 bytes of stack; the UDP fentry programs would reach 392 of 512.

**Cost.**
- On every connection: two `bpf_ktime_get_ns()` calls, the comparisons,
  and up to three atomic adds on a flow that is looked up anyway.
- On failure only: reads of `sk_err`, `sk_err_soft`, `sk_lock.owned`,
  `segs_out` and `total_retrans`.
- Verifier: in a trial build in the review, the tracepoint program grew
  from 2160 to 3010 instructions and iter/tcp from 3044 to 3450 (Linux
  6.18).
- It is measured with `-bpf-stats` (§7).

**Kernel versions.**
- `sk_err`, `sk_err_soft`, `sk_lock.owned` and `total_retrans` exist on
  5.14; `segs_out` since 4.2.
- `fastopen_connect` and `repair` are bitfields of `tcp_sock`, read with
  `BPF_CORE_READ_BITFIELD_PROBED`.
- `make compat` checks the relocations against Rocky Linux 9.

### 3.2 Agent

New internal OTLP metrics on the client edges of TCP
(`internal/otlp/names.go`); `shawk.connection.failed` does not change:

| metric | type |
|---|---|
| `shawk.tcp.handshake` | cumulative histogram with the bounds of §3.1, unit `s` |
| `shawk.tcp.syn_retransmits` | sum, `{segment}` |
| `shawk.connection.failed.by_reason` | sum, `{connection}`, with `error.type` |

**Reasons.**
- A reason is sent from its first occurrence on the edge, with the start
  time of the interval in which it first occurred. The connector then takes
  its first value as new, not as a baseline (`isNew()`).
- Sending every reason with zeros would cost 6 data points per edge.
  Sending a new reason with the start of its edge would make its first
  value a baseline, and the first failures would be lost.

**Request sizes.**
- `edgeSize()` and `pointOverhead` must count the new points. The review
  measured a TCP client edge of the first draft at 6 561 bytes instead of
  3 633, while the estimate stayed at 3 654.
- Without the fix, requests filled to 3 MiB by estimate would exceed the
  4 MiB gRPC limit. `TestRequestsByteLimit` covers it.

**`shawk flows`** shows the mean handshake, the SYN retransmissions and the
failures by reason. Its JSON output (`-json`) gains the new fields of
`tracer.Flow`.

### 3.3 Connector: per dependency

**Outputs.** New series alongside the others (`outMetrics`):

| Prometheus | |
|---|---|
| `shawk_tcp_handshake_seconds_bucket{le="+Inf"}`, `_sum`, `_count` | a histogram without buckets, like the RTT: the mean connect time of a dependency |
| `shawk_tcp_syn_retransmits_total` | |
| `shawk_connection_failed_by_reason_total{error_type}` | one series per reason that occurred on the dependency |

- **Series.** A client dependency of TCP has 9 series today: opened,
  failed, count, two of bytes, retransmits, and three of RTT. With this
  proposal it has 13, plus one per reason that occurred. Buckets per
  dependency would add 10 more, so they are not kept (percentiles are read
  between sites, §3.4).
- **New reasons.** A reason's output series is created at its first
  increase. In that interval it emits 0, and the increase one interval
  later, because `rate()` does not count the first sample of a series.
- **Counting** (§7 of the design). All three metrics come from the client
  side only, like failures, so each dependency is counted once.
- **New recording rules:**
  - `shawk:dependency_handshake_seconds_sum:rate5m` and `_count:rate5m`;
  - `shawk:dependency_syn_retransmits:rate5m`;
  - `shawk:dependency_connection_failures_by_reason:rate5m`.

  The existing rules do not change.

**Implementation.**
- **`error.type`** needs its own field in `valueKey` and `outKey`.
  `outKey.dir` is emitted as `network.io.direction`.
- **Histogram inputs and outputs carry bucket counts.** That means
  `point`, `inputState` and `outSeries`.
- **Resets.** A point resets as a whole when its start changes or any of
  its count, sum or buckets decreases, so that output buckets stay
  monotonic.
- **Bounds.** The bounds of an input must equal the expected ones;
  otherwise the input is dropped and counted as invalid.
- **One delta per input.** `delta()` advances the state, so it runs once
  per input and its increase feeds every output: the dependency, and the
  host, zone and site of §3.4.

### 3.4 Connector: zones and paths (phase 2)

**Configuration:**

```yaml
connectors:
  shawk:
    zones:
      dc1/rack01: 10.1.1.0/24
      dc1/rack02: 10.1.2.0/24
      dc2: 10.2.0.0/16, fd00:2::/48
    path_hosts: site            # site (default), zone or none
    path_exclude_services: []   # local services left out, e.g. behind a sidecar
```

- **Site.** The site of a zone is its name up to the first `/`, or the
  whole name.
- **Parsing.**
  - Prefixes are parsed like peer addresses: IPv4-mapped prefixes are
    unmapped.
  - The narrowest range wins.
  - Empty names, names starting with `~`, duplicate prefixes, and more than
    1000 zones are rejected.
- **No zones.** Without `zones` (the default), no path metric is emitted.
- **`peer_cidrs`.** Zones may overlap with `peer_cidrs`, which only names
  peers without a service.

**Zones of the two ends of a client edge of TCP.**
- **Local zone.**
  - The zone of the local address.
  - When no zone holds it (a container address behind NAT), the zone of
    the host. That is the one zone that holds the addresses of `host.ip`
    that some zone holds, ignoring loopback and link-local addresses.
  - Otherwise `~unzoned`.
- **Peer zone.**
  - The zone of the peer address.
  - `~unzoned` for an address not routed on the Internet that no zone
    holds.
  - `~external` for other addresses and for folded peers, unless a zone
    holds the whole network (as for `peer_cidrs`).
- **Left out:**
  - loopback, connections to the host's own addresses, and UDP;
  - the local services in `path_exclude_services`;
  - edges without the inputs of §3.2 (agents of the previous version).

**Outputs.** Three families, as in Pingmesh:

| family | resource | Prometheus | labels |
|---|---|---|---|
| between sites | the connector: `job="shawk-connector"`, `instance` the host name of the collector | `shawk_path_site_tcp_handshake_seconds_bucket`, `_sum`, `_count`; `shawk_path_site_tcp_syn_retransmits_total`; `shawk_path_site_connection_failed_by_reason_total` | `shawk_site`, `shawk_peer_site` (`le`, `error_type`) |
| between the zones of a site | the connector | `shawk_path_zone_tcp_handshake_seconds_bucket{le="+Inf"}`, `_sum`, `_count`; `shawk_path_zone_tcp_syn_retransmits_total`; `shawk_path_zone_connection_failed_by_reason_total` | `shawk_site`, `shawk_zone`, `shawk_peer_zone` (`error_type`) |
| per source host | the agent: `job="shawk-agent"`, `instance` the host name | `shawk_path_host_tcp_handshake_seconds_bucket{le="+Inf"}`, `_sum`, `_count`; `shawk_path_host_tcp_syn_retransmits_total`; `shawk_path_host_connection_failed_by_reason_total` | `shawk_site`, `shawk_zone`, `shawk_peer_site` (`shawk_peer_zone` with `path_hosts: zone`) (`error_type`) |

- **Buckets** are kept between sites only. With flat zone names, every zone
  is its own site, so every pair of zones has percentiles; the zone family
  is then empty.
- **Emission.**
  - The site and zone families sum the increases of all the hosts of a
    connector. A timer of the connector emits them every 15 s.
  - With several connectors, each emits its own `instance`, and the rules
    sum over `instance`.
  - The host family is emitted once per interval of its host, with the
    metrics of the agent: the final request of an interval always carries
    them.
- **No `~other`.** Zones are a closed set from the configuration, so no
  peer is folded into `~other`. Folding by first come, as `max_peers`
  does, would differ from host to host and corrupt the matrices.

**Series.**
- **Sites:** connectors × communicating pairs of sites × (13 + 1 + reasons
  that occurred).
- **Zones:** connectors × communicating pairs of zones within a site × (3 +
  1 + reasons).
- **Hosts:** hosts × peer sites (or zones) × (3 + 1 + reasons).
- **Example:** 10 000 hosts in 5 sites of 50 racks each, 2 connectors,
  everything talking to everything:
  - sites: 2 × 25 × 14 ≈ 700;
  - zones: 2 × 5 × 2 500 × 4 = 100 000;
  - hosts: 10 000 × 5 × 4 = 200 000.
- **Per pair of hosts.** That would be 10⁸ pairs, which is why there are no
  such series.

**Localization.** Pingmesh localizes a problem by comparing the sources:

| what the matrices show | where to look |
|---|---|
| one source host is bad towards every site (hosts table) | that host: its NIC, its link, its CPU (softirq), or a local firewall or network policy that drops (§4) |
| every host of zone A is bad (a row of the zone matrix) | the uplinks of A, e.g. its top-of-rack switch |
| every zone is bad towards zone B (a column) | B: its switch, or its servers dropping SYNs on full listen queues (§4) |
| one pair of zones or sites is bad | the path between them |
| a steady fraction of the connections of a pair fails, not all | a link or an ECMP member that drops some flows (the black holes of Pingmesh); locating it takes traceroute (§5) |

**SYN loss estimate.**
- The probability that a SYN (or its SYN-ACK) is lost is estimated, per
  pair and family, as

  lost / sent = (SYN retransmissions + `timeout` failures) / (handshakes +
  failures − `local` failures + SYN retransmissions).
- An established attempt with k retransmissions lost k of its k + 1 SYNs;
  an attempt that timed out lost all of them.
- The estimate stays within [0, 1], and an unreachable pair reads 1 on
  every kernel, whatever its schedule.
- `local` failures sent no SYN and are left out.
- `aborted` failures are shown as their own ratio of attempts, because an
  application whose connect timeout is below 1 s gives up before any SYN
  is retransmitted.

**Recording rules** (missing series are taken as 0 with `or ... * 0`):
- `shawk:path_site_handshake_seconds_bucket:rate5m`, summed by
  `shawk_site`, `shawk_peer_site`, `le` (and over `instance`);
- `shawk:path_{site,zone,host}_syn_sent:rate5m` and `_syn_lost:rate5m`;
- `shawk:path_{site,zone,host}_attempts:rate5m` and `_aborted:rate5m`.

**Alerts** (in `packaging/prometheus/shawk-rules.yml`, group
`shawk-alerts`; the thresholds are to be tuned):
- `ShawkPathSynLoss`: the loss estimate of a pair of sites or of zones is
  above 1 % for 15 minutes, with at least one SYN per second, seen by at
  least 2 source hosts (from the host family);
- `ShawkPathConnectTimeouts`: `timeout` and `unreachable` failures are
  above 1 % of the attempts of a pair for 10 minutes, seen by at least 2
  source hosts.
- A single dependency that fails (e.g. clients of a decommissioned server)
  is the case of the per-dependency rule, not of these alerts.

### 3.5 Grafana

- **shawk / Dependency details**: the mean connect time, SYN
  retransmissions per attempt, and failures by reason (stacked).
- **shawk / Network paths** (new, phase 2). The grouping-to-matrix
  transformation of Grafana takes one value per cell, so each quantity has
  its own matrix:
  - **Between sites:** p99 connect time (from handshakes), the SYN loss
    estimate, the aborted ratio, and the attempts.
    - Cells with fewer than `$min_attempts` are blanked with
      `and on (shawk_site, shawk_peer_site) (attempts >= $min_attempts)`.
    - Data links on the cells set `$site` and `$peer_site`.
  - **Between the zones of `$site`:** mean connect time, the loss estimate,
    the attempts.
  - **Hosts:** a table of the hosts of `$site` towards `$peer_site`: their
    attempts, loss estimate, mean connect time and failures by reason, worst
    first.
  - **Over time:** p50 and p99 and the loss estimate of the selected pair.

## 4. Limitations

- **Coverage.** Only connections that are opened are measured: paths
  without new connections are not, which is what active probing would add.
  - Connection pools open few connections. Their established connections
    are still covered by the sampled RTT (`shawk.tcp.rtt`) and their
    retransmissions.
- **"Lost" is not only lost on the wire.** These cannot be told apart from
  losses in the network:
  - SYNs dropped by a local firewall, by egress BPF or by a network policy
    (Calico and Cilium drop by default);
  - SYNs dropped by a remote firewall that drops rather than rejects;
  - SYNs dropped by a server whose accept queue is full, or whose SYN queue
    is full without SYN cookies.

  Phase 3 adds the listen drops of servers to tell the last case apart.
- **Listen overflows at the final ACK.** When the accept queue fills between
  the SYN and the final ACK, the client is already ESTABLISHED and sees no
  loss, while the server drops the ACK and retransmits its SYN-ACK. With
  `tcp_abort_on_overflow=1`, the client gets a reset after the
  establishment.
- **What the duration holds.**
  - It starts in `connect(2)` before the local port is chosen, so it
    includes `inet_hash_connect()`, which slows down when the ephemeral
    ports to a destination run out.
  - It ends when the SYN-ACK is processed, in the kernel, not in the server
    application.
  - A server whose softirqs are saturated inflates it.
- **Retransmission schedules** differ between kernels (§3.1). The buckets of
  a mixed fleet are not comparable above 1 s. The loss estimate is.
- **ICMP processed while `connect(2)` holds the socket.** An ICMP reject
  from the same host is processed in that window. It then only sets
  `sk_err_soft`, and the socket closes at the next retransmission: 1 s
  later, with one SYN retransmission counted.
- **Not seen at all:** failures before CLOSE→SYN_SENT, such as no local
  route (`ip_route_connect()`, `ip6_dst_lookup_flow()`), prohibit routes,
  and cgroup BPF `connect4`/`connect6` programs (e.g. the socket load
  balancer of Cilium for a service without backends).
- **Reasons.**
  - Firewalls that reject with ICMP port unreachable or a reset give
    `refused`, which reads as "service down".
  - An application connect timeout below 1 s turns network losses into
    `aborted` with no retransmission.
  - The race of `SO_ERROR` on 5.14 and RHEL 9 is covered only in part by
    the fallback of §3.1.
- **Relays.**
  - A proxy or a load balancer that terminates TCP is the end of the
    measured path.
  - A connection to a virtual IP takes the zone of the VIP, as in §10 of
    the design.
  - A sidecar that intercepts connections locally (iptables REDIRECT, e.g.
    Istio) answers the handshake in microseconds, while the edge keeps the
    remote peer. Its samples would pull the matrices down, so those
    services belong in `path_exclude_services`. The per-dependency mean is
    affected the same way, as the RTT already is.
- **No location below a zone.** shawk tells which hosts and zones, not
  which link or switch; that takes traceroute (§5).
- **TCP only.** UDP has no handshake. QUIC sets up its connections in user
  space.

## 5. Alternatives not taken

| alternative | why not |
|---|---|
| Active probing in the agent, as Pingmesh does | **Needs:** a controller to hand out the lists, and knowledge of the topology. **Probes need:** a responder on every host, ICMP (`CAP_NET_RAW`, or ping sockets allowed by `ping_group_range`), or the ports of the services. **Costs:** it adds traffic and series for every probed pair. **Measures** what probes see, not what applications see. |
| A separate prober (Cloudprober, blackbox_exporter) beside shawk | **Possible, and complementary.** shawk would measure the prober's handshakes passively too, which covers idle paths. **Catch:** its connections are recorded as dependencies of every host it probes. They carry its `service.name`, but the views of `shawk_v1` and the rules cannot leave a service out, so "who still uses this host?" would answer the prober. **Would need** a way to exclude named services from the views and rules, which is a separate change. |
| The first RTT sample after the handshake (`srtt_us >> 3` at ESTABLISHED) instead of the time from `connect(2)` | **Misses** the retransmission waits that applications see. **Biased:** without TCP timestamps, Karn's algorithm skips the sample when the SYN was retransmitted, so it is biased towards the good cases. **Later:** it could be added as the RTT of the path. |
| Counting SYN retransmissions with the tracepoints `tcp_retransmit_skb` and `tcp_retransmit_synack` (stable, as `tp_btf`, since 4.15) | **Cost:** a program run on every retransmission, while `total_retrans` at the state change already holds the count. **Would gain:** counting only retransmissions handed to IP, leaving out local drops. **Revisit** if local drops turn out to dominate. |
| The kernel's counters (`TcpExtTCPSynRetrans` in `/proc/net/netstat`) | **Too coarse:** they count per network namespace, without a peer, and include SYN-ACKs, so they cannot localize anything. **Still useful:** listen drops from the same file explain losses (phase 3). |
| Native histograms with custom buckets (`otlp.convert_histograms_to_nhcb`, Prometheus 3.4 and later) | **Breaks today's series:** the setting applies to the whole OTLP receiver and replaces classic histograms instead of adding to them. It would remove `shawk_tcp_rtt_seconds_sum` and `_count`, which the recording rules use, and the request-duration buckets of OBI, which the application dashboard uses. **Alternative:** OTLP exponential histograms are stored as native histograms without that setting (decision 5). |
| Buckets per dependency in Prometheus | **Too many series:** 10 more for every client dependency of TCP. **Not needed:** the mean per dependency and the percentiles between sites answer the questions. |
| Series per pair of hosts | **Quadratic:** N² series, against review P0-1. Hosts appear only as sources towards a site or a zone. |
| Zones in `peer_cidrs` | **Mixes concerns:** `peer_cidrs` names peers without a service, so rack ranges added there would rename those peers on the dependency map and in `service.peer.name`. Topology and naming are kept apart. |
| Percentiles or sketches in the kernel | **Complex** under the verifier. Fixed buckets are enough for the questions of §1. |
| Path quality in PostgreSQL | **Wrong store:** PostgreSQL holds relations and their periods, not time series. |
| Localizing links with traceroute, as 007 does [2] | **Out of scope:** it sends probes, and it needs routers that answer them. The matrices tell where to start. |

## 6. Compatibility, migration and documents

- **BPF object.**
  - `shawk.h` and the socket storage change; regenerate the object and the
    types of bpf2go.
  - The storage of a TCP socket grows from 104 to 112 bytes, and the flow
    maps by 2.6 MB.
- **Order of upgrade.** Either order works.
  - An old connector ignores the three new metric names: `addMetric()`
    returns for a name it does not know. `shawk.connection.failed` is
    unchanged.
  - A new connector reading agents of the previous version produces none of
    the new series, and those edges are left out of the paths.
- **Prometheus contract.** Only additions. No existing metric or label
  changes.
- **PostgreSQL:** no change.
- **Configuration:** `zones`, `path_hosts` and `path_exclude_services` in
  the connector, with an example in `packaging/collector/config.yaml`. The
  agent gets no flag.
- **Several connectors.** The paths sum per-host state, like every output
  of the connector, so they need a host to stay on one connector. Routing by
  resource does not guarantee that today (#128).
- **Documents to change:**
  - `docs/design.md`:
    - §3.1 (what is recorded) and §3.2 (the table of hooks);
    - §4.2 (what is sent) and §4.3 (request sizes);
    - §5.3 (the table of metrics, and the reduction and the bound of
      series). Its table of metrics should also list the `+Inf` bucket of
      the RTT.
    - §7 (the counting table), §8 (dashboards), §10 (the limitations of
      §4);
  - README: Prometheus row, dashboards, a PromQL example;
  - `packaging/README.md`;
  - CHANGELOG.

## 7. Tests

**BPF** (`make test-root`, VM tests), in network namespaces:
- **Loopback.**
  - One handshake per connection, below 10 ms. Loopback handshakes take
    0.1 to 0.3 ms, more in emulated VMs, so the assertion is loose.
  - None for MPTCP join subflows, the agent's own connections, connections
    adopted at startup, or `TCP_REPAIR`.
- **One lost SYN.**
  - Set up a listener with a backlog of 1 and fill its accept queue with
    two connections that are not accepted. `sk_acceptq_is_full()` compares
    with `>`.
  - Connect, then accept after 0.5 s. The SYN retransmitted at 1 s gets
    through on both schedules of §3.1.
  - Expect `syn_retrans == 1`, a handshake in (1 s, 3 s], and a delta of 1
    in `TcpExtListenOverflows`.
- **Each reason:**
  - `refused`: a closed port; where nft exists, `reject` (ICMP port
    unreachable) in a separate namespace acting as the router;
  - `unreachable`: a veth to a namespace without the address (three ARP
    probes, about 3 s); where nft exists, an administratively prohibited
    reject in a router namespace (`EHOSTUNREACH`, and `EACCES` over IPv6);
  - `timeout`: a dummy interface, which drops every packet, with
    `net.ipv4.tcp_syn_retries=1` in the namespace (about 3 s). Run it
    under both schedules where `tcp_syn_linear_timeouts` exists;
  - `local`: `ip_local_port_range` of one port, held by a connection to the
    same server. Also after `connect(AF_UNSPEC)`, which leaves
    `ECONNRESET`;
  - `aborted`: a non-blocking connect through the dummy interface, closed
    after 100 ms; and a `TCP_FASTOPEN_CONNECT` socket closed before
    writing.
- **Delay**, where `tc` is in the VM image: netem with 5 ms of delay on one
  end of a veth only puts handshakes in (2.5 ms, 10 ms]. On loopback it
  would delay both the SYN and the SYN-ACK.
- **Dropped update.** A flow update dropped at the establishment (a tiny
  `-max-flows`) is recounted with its handshake and its SYN
  retransmissions.
- **Loading.** Every program loads on 5.14, 5.15 and Rocky Linux 9.6.

**Kernel compatibility.** `TestKernelCompatibility` and `make compat`.

**Agent.**
- Golden tests of the OTLP: the bounds, and a reason whose start is the
  interval of its first occurrence.
- `TestRequestsByteLimit` with the new points.

**Connector:**
- deltas of histograms: resets as a whole, baselines, bounds that differ;
- one delta per input feeding the dependency, host, zone and site outputs;
- a new reason emitting 0 first;
- input from agents of the previous version;
- zones:
  - parsing (IPv4-mapped prefixes, duplicates, the limit), the narrowest
    range;
  - the zone of the host with a `host.ip` that holds loopback and container
    addresses;
  - loopback and the host's own addresses left out;
  - folded peers;
  - `path_exclude_services`;
  - no path output without `zones`;
- emission: the timer of the site and zone families, the host family with
  the agent's resource once per interval, and two connectors with their own
  `instance`.

**Packaging.** Extend the tests in `test/packaging` (names, rules,
dashboards) to the new names.

**e2e.** Hosts in two sites of namespaces; check the dependency outputs and
the three families of path outputs of the collector.

**Performance.** A storm of connections on loopback; compare the run time
of `shawk_inet_sock_set_state` with `-bpf-stats` before and after.

## 8. Phases

1. **Phase 1:** §3.1–§3.3, the panels of the dependency details dashboard,
   the rules, the documents.
2. **Phase 2:** §3.4–§3.5: zones, the three path families, the network
   paths dashboard and alerts. It should follow #128 for fleets with
   several connectors.
3. **Phase 3** (separate issues, measured first):
   - **The server side of passive opens,** for clients without an agent:
     - SYN-ACK retransmissions. `tcp_create_openreq_child()` copies the
       retransmissions of the request into `total_retrans`. But they count
       the SYN-ACKs sent by the request timer and in answer to duplicate
       SYNs: one lost SYN-ACK counts 2. Behind SYN cookies there is no
       request at all.
     - The RTT sample of the SYN-ACK (`tcp_synack_rtt_meas()`).

     It is counted only when the client has no agent, as in §7 of the
     design, and kept apart from the client view in the path families.
   - **The loss ratio of data:** deltas of `data_segs_out` (4.6; `segs_out`
     also counts pure ACKs), accounted like the bytes, against
     `shawk.tcp.retransmits`.
   - **Listen overflows and drops** per network namespace, as metrics of
     the agent, to tell overloaded servers from network losses.
   - **Excluding named services** (e.g. a prober) from the views of
     `shawk_v1` and the rules.

## 9. Decisions (decided)

All six were decided as recommended (2026-11-02):

1. **What to measure.** The handshake from `connect(2)`. The first RTT
   sample is left for later (§5).
2. **The bucket bounds** are those of §3.1.
3. **Granularity of the host family.** Per host towards sites:
   `path_hosts: site` is the default, and `zone` and `none` are available.
4. **Zones are kept apart from `peer_cidrs`.**
5. **The histogram between sites** uses classic buckets with the bounds of
   §3.1.
   - An OTLP exponential histogram, which Prometheus would store as a
     native histogram with power-of-two bounds, is reconsidered once the
     TSDB settings it needs are verified. That includes out-of-order native
     histograms within the window of 30 minutes.
6. **`path_exclude_services`** is a list of services, named as the `job`
   label names them (`namespace/name`), as everywhere else in shawk.
   Matching by unit or executable is not added.

## 10. Adversarial review and responses (2026-11-02)

Two independent subagents reviewed the first draft (commit cb0589e):
- **kernel:** the claims about Linux and the BPF program, checked against
  the sources of v5.14, v6.12, mainline and CentOS Stream 9, with
  experiments on Linux 6.18 in throwaway namespaces;
- **pipeline:** the agent, connector, Prometheus, Grafana and
  compatibility, checked against the code, the OTLP translator of
  Prometheus and measured request sizes.

Neither found a blocker. "Confirmed" marks findings that were checked again
apart from the reviewer; the others are accepted on the reviewer's
evidence.

| finding | validity | response |
|---|---|---|
| The SYN schedule differs on upstream kernels with `tcp_syn_linear_timeouts` (default 4: 1, 2, 3, 4, 5 s, ...), so the number of losses cannot be read from the buckets | confirmed (the sysctl is 4 on 6.18) | The buckets measure latency only; losses come from SYN retransmissions. §3.1 gives the schedule per kernel. The loss estimate is comparable across kernels. |
| The test of one lost SYN fails on 5.14 and RHEL 9: the SYN at 1 s is dropped too, while the queue is still full, and a backlog of 1 needs two queued connections | valid (measured by the reviewer: 3.035 s with 2 retransmissions) | Accept at 0.5 s; assert `syn_retrans == 1` and the delta of ListenOverflows. |
| Firewall rejects are mislabelled: ICMP port unreachable gives `ECONNREFUSED`, and firewalld's administratively prohibited gives `EHOSTUNREACH` (IPv4) or `EACCES` (IPv6, then `other`) | valid | `EACCES`, `EHOSTDOWN` and `ENONET` go to `unreachable`. §3.1 and §4 say what `refused` also covers. |
| `segs_out` and `total_retrans` are counted before netfilter, egress BPF and the qdisc, so local drops look like losses; retransmissions skipped while a copy is queued are not counted | valid | `segs_out` is reworded as "got as far as building a SYN", and SYN retransmissions as attempts. Local and remote drop policies are added to §4 and to the localization table. |
| On 5.14 and RHEL 9 user space can take `sk_err` (`SO_ERROR`) before the tracepoint, turning a timeout into `aborted` | valid (from the source; not reproduced) | Fallback on `sk_lock.owned` and `sk_err_soft` (§3.1); the remaining race is in §4. |
| An ICMP reject processed while `connect(2)` holds the socket adds 1 s and one retransmission | valid (measured by the reviewer) | §4; the tests reject from a separate namespace. |
| `TCP_FASTOPEN_CONNECT`, `TCP_REPAIR`, `connect(AF_UNSPEC)` and `ss -K` are misattributed | valid | Deferred Fast Open: no duration, and `aborted` when closed before writing. Repair: no duration. `segs_out == 0` is decided before `sk_err`. `ECONNABORTED` is `_OTHER`. |
| Failures before SYN_SENT (no route, cgroup connect programs) are invisible; overflows at the final ACK are not SYN losses | valid | §4. |
| `syn_retrans` must take the pending path of `count_conn()`, or it is lost with a dropped update; a join subflow without an owner would create a flow without owner | valid | It is added in `count_conn()` from `retrans_base`. |
| The stack of every program that calls `flow_get()` grows by 80 bytes (UDP fentry programs 392 of 512) | valid (measured by the reviewer) | The zero value moves to `.rodata`. |
| A 32-bit µs start wraps when handshakes are not bounded (`TCP_SYNCNT` up to 127, deferred Fast Open) | valid | The start is a 64-bit `syn_ns`, and the duration is saturated. The storage grows by 8 bytes. |
| netem on loopback delays both directions | valid | Delay on one end of a veth. |
| Phase 3: `num_retrans` counts SYN-ACKs of both the timer and duplicate SYNs; SYN cookies have no request; `segs_out` counts pure ACKs | valid | §8 phase 3. |
| `segs_out` exists since 4.2; the stable retransmission tracepoints were overlooked; `TcpExtTCPSynRetrans` is per network namespace and counts SYN-ACKs | valid | §3.1 and §5 corrected. |
| The zone of the host from `host.ip` can never be found: `host.ip` holds loopback and the container addresses themselves | confirmed (`internal/agent/agent.go:322-331`, `hostAddrs()`) | Only the addresses that a zone holds are considered, ignoring loopback and link-local. |
| One `error.type` data point per reason either multiplies the failure series by 6 or loses the first occurrences (a new point with the start of its edge is a baseline) | confirmed (`request.go:181-183` sends failures with zeros; `isNew()`) | A separate metric `shawk.connection.failed.by_reason`. A reason is sent from its first occurrence, with the start of that interval. Its output is created at the first increase and emits 0 first. |
| An old connector keeps the last data point per edge, so it would report only `other` and silence `ShawkConnectionFailureRate`; `error_type` on the existing metric changes the contract | valid | `shawk.connection.failed` and `shawk_connection_failed_total` are unchanged. Either order of upgrade works. |
| Path series grow with hosts × zones (10 M with racks as zones), against review P0-1 | valid | Three families as in Pingmesh. Buckets only between sites; means between the zones of a site; hosts only towards sites by default. §3.4 gives the formulas. |
| Folding peer zones into `~other` first come, first served differs between hosts and corrupts the matrices | valid | No `~other`; zones are a closed set, limited to 1000. |
| The SYN loss ratio is unbounded (600 % for a black hole), is an odds, is diluted by `local` failures, and is blind to connect timeouts below 1 s | valid | The estimate of §3.4, within [0, 1]. `aborted` is shown as its own ratio; §4 corrected. |
| `otlp.convert_histograms_to_nhcb` exists (Prometheus 3.4), but applies to the whole OTLP receiver and replaces classic series, breaking the RTT rules and the dashboard of OBI | confirmed (Prometheus v3.15.1 `config/config.go:1777`) | Not used (§5). Exponential histograms are an option (decision 5). |
| Routing by resource moves a host between connectors when `host.ip` changes, counting outputs twice | confirmed (`internal/agent/agent.go:322-331`, the README of the loadbalancing exporter) | It affects every output today: #128. §6 and §8 depend on it. |
| A TCP client edge grows from 3 633 to 6 561 bytes while `edgeSize()` still estimates 3 654, so requests would exceed 4 MiB | valid (measured by the reviewer on the first draft) | §3.2: the estimate counts the new points; tested by `TestRequestsByteLimit`. |
| Sidecars that intercept connections locally answer the handshake in microseconds and pollute the matrices | valid (reasoned; not reproduced) | §4; `path_exclude_services`. |
| `ShawkPathConnectTimeouts` would fire forever for clients of a decommissioned server | valid | The alerts need at least 2 source hosts and a ratio of attempts. Single dependencies are left to the per-dependency rule. |
| The matrix cannot show attempts in the same cell, and tables have no cell selection | valid | One matrix per quantity, data links that set `$site` and `$peer_site`; the p99 matrix counts handshakes. |
| The alternatives table contradicts itself on a separate prober, and is unfair to active probing (ping sockets, probing service ports, Pingmesh is not a full mesh) | valid | §1 and §5 rewritten. A prober is complementary, and needs a way to exclude services (phase 3). |
| The connector is under-specified: `error.type` cannot reuse `dir`, `delta()` must run once per input, histograms need buckets in the state, resets as a whole, bounds checked, old agents skipped in the paths | valid | §3.3 (implementation) and §3.4. |
| Series arithmetic: a histogram without buckets still has `_bucket{le="+Inf"}`, so buckets add 10 series, not 12 | valid | Corrected; §6 notes the same omission in §5.3 of the design. |
| Zones: IPv4-mapped prefixes would never match; duplicates and empty names; a zone holding the whole network | valid | §3.4 (parsing, folded peers). |
| Missing pieces: §4.2, §4.3 and §5.3 of the design, OTLP names, where the alerts live, `_OTHER`, `shawk flows -json`, the collector example | valid | Added to §3, §6 and §7. |

## 11. Implementation of phase 1 (2026-11-03)

Phase 1 follows §3.1–§3.3, with the differences below. They come from a
review of this proposal against the code before the implementation, and
from the implementation itself.

| finding | response |
|---|---|
| `count_conn()` also counts passive opens (`on_passive_open()`, and their recount), whose `retrans_base` holds the SYN-ACKs they retransmitted (phase 3) | `SS_HANDSHAKE` is set at SYN_SENT→ESTABLISHED only; `count_conn()` adds the SYN retransmissions and the duration only with it. |
| The active opens without a duration (`TCP_REPAIR`, `TCP_FASTOPEN_CONNECT`) still count their SYN retransmissions, so one flag cannot tell both | A second flag, `SS_HS_TIME`, marks the duration pending. They count in `conns`, not in the buckets, so the number of handshakes is that of the durations. |
| At SYN_SENT→ESTABLISHED, a connect with `TCP_FASTOPEN_CONNECT` that was deferred to its first write cannot be told from one that sent its SYN at once, without a cookie (`inet->defer_connect` is a bitfield before 6.6 and a flag after) | Every connect with the option has no duration, as §3.1 says of the deferred ones. |
| A simultaneous open (SYN_SENT→SYN_RECV→ESTABLISHED) has no handshake (§3.1), but the proposal does not say what its failure is | Reasons are decided at SYN_SENT→CLOSE only; a failed simultaneous open is `_OTHER`. |
| The stale `ECONNRESET` of `connect(AF_UNSPEC)` survives only until `tcp_connect_init()` clears `sk_err` when it builds a SYN | Nothing beyond the order of §3.1 (no segment sent first) is needed; a test closes a socket after `connect(AF_UNSPEC)` and a new connect, which is `aborted`. |
| A duration truncated to microseconds would put 100.4 µs in the bucket of 100 µs | It is rounded up, so that the bounds hold as inclusive upper bounds. |
| The tests of §7 need `ip`, `tc` and `nft`, which the virtual machines of `test/vm` do not have (their initramfs holds the test binary alone) | The tests run on loopback in network namespaces: a listener with a full accept queue drops SYNs, and raw sockets read a SYN and answer it with an ICMP error (port unreachable, host and network unreachable, host unknown, administratively prohibited), as a router or a firewall would. Not tested: ARP without an answer, netem, ICMPv6 (`EACCES`) and `ss -K`. |
| The timer of a retransmission may expire up to a tick before 1 s, and a failed blocking connect clears `total_retrans` (`tcp_disconnect()` in `inet_stream_connect()`) | The test of a lost SYN accepts 0.9 s; the tests read `TCP_INFO` after non-blocking connects. |
| The connector needs the buckets of its inputs for phase 2 only | Phase 1 keeps them in the input state, checks the bounds and resets histograms as a whole; outputs have no buckets until the family of sites. |
| The new series of a reason emits 0 first (§3.3), but the proposal does not say when a reason whose first value is a baseline (after a restart of the connector) creates its series | At its first increase, like a new reason: a baseline creates none. |
| "SYN retransmissions per attempt" (§3.5) has no denominator | The handshakes with a duration plus the failures, both of the client side; `shawk:dependency_connections:rate5m` also counts the server side of clients without an agent, which has no SYN retransmissions. |
| The claims of sizes (storage 104→112 bytes, flow statistics 56→136 bytes, 2.6 MB for the two maps), of the `.rodata` zero value and of the fields on 5.14 | Confirmed: `make compat` passes against Rocky Linux 9, and every program loads on Linux 6.18. |

## References

1. Chuanxiong Guo et al. *Pingmesh: A Large-Scale System for Data Center
   Network Latency Measurement and Analysis.* SIGCOMM 2015.
2. Behnaz Arzani et al. *007: Democratically Finding the Cause of Packet
   Drops.* NSDI 2018.
