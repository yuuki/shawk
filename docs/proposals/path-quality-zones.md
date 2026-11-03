# Path quality by network location: design proposal

Status: proposed, not implemented; no issue yet. The measurement this
builds on is implemented: the agent measures the handshake of every active
open of TCP, from `connect(2)` to the SYN-ACK, the SYNs it retransmitted and
the reason of a failure, and the connector forwards them per dependency.
`docs/design.md` describes it: the kernel in §3.1 and §3.2, the OTLP in
§4.2 and §4.3, the outputs in §5.3, the counting in §7, the dashboard in §8
and the limitations in §10. This proposal covers what remains: aggregating
those measurements by network location (zones and sites) into path metrics,
with their rules, alerts and a Grafana dashboard (phase 2), and further
measurements (phase 3, §9).

## 1. Problem

Pingmesh [1] runs an agent on every server of a data center. The agent
opens TCP and HTTP connections to the servers on a list that a controller
generates: every server under the same top-of-rack switch, some servers of
every other rack, and some servers of the other data centers. From the time
these connections take to set up, it derives latency percentiles for each
pair of racks and of data centers; from the connections whose setup took 3
or 9 seconds (the retransmission timeouts of a lost SYN on Windows), it
estimates the packet drop rate. It answers *is it the network?*, and it
helps to localize black holes and silent drops to switches.

shawk takes the same measurement passively, on the connections that hosts
open anyway, but reports it per dependency between services. A network team
reads it per network location: between racks, subnets and data centers,
whatever the services.

Active probing does not fit shawk (§5): it needs a controller that hands
out the lists and knows the topology, and a way to probe (a responder on
every host, ICMP, or the ports of the services), while the agent opens no
port and has no `CAP_NET_RAW`. It also adds traffic and series for every
pair it probes, and it measures what probes see, not what applications see.

## 2. Approach

- **Zones** are address ranges that the operator names after the network
  (racks, subnets), grouped into **sites** (data centers).
- The connector sums the handshakes, SYN retransmissions and failures of
  the client edges of TCP by the zones of their two ends, in three
  families, as in Pingmesh:
  - percentiles between sites;
  - means and loss between the zones of a site;
  - per source host, to localize.
- A Grafana dashboard shows them as matrices, and alerts fire on the loss
  and the timeouts of a pair seen by several source hosts.

What this gives up compared with Pingmesh: paths that carry no new
connections are not measured (§4).

## 3. Design

### 3.1 Configuration

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
  peers without a service (decision 2).
- **`path_exclude_services`** lists local services, named as the `job`
  label names them (`namespace/name`), as everywhere else in shawk
  (decision 4).

### 3.2 Zones of the two ends of a client edge of TCP

- **Local zone.**
  - The zone of the local address.
  - When no zone holds it (a container address behind NAT), the zone of
    the host: the one zone that holds the addresses of `host.ip` that some
    zone holds, ignoring loopback and link-local addresses. `host.ip` also
    holds loopback and the addresses of containers (§4.2 of the design), so
    only the addresses in zones are considered.
  - Otherwise `~unzoned`.
- **Peer zone.**
  - The zone of the peer address.
  - `~unzoned` for an address not routed on the Internet that no zone
    holds.
  - `~external` for other addresses and for folded peers, unless a zone
    holds the whole network (as for `peer_cidrs`).
- **Left out:**
  - loopback, connections to the host's own addresses, and UDP;
  - the local services in `path_exclude_services`.

### 3.3 Outputs

| family | resource | Prometheus | labels |
|---|---|---|---|
| between sites | the connector: `job="shawk-connector"`, `instance` the host name of the collector | `shawk_path_site_tcp_handshake_seconds_bucket`, `_sum`, `_count`; `shawk_path_site_tcp_syn_retransmits_total`; `shawk_path_site_connection_failed_by_reason_total` | `shawk_site`, `shawk_peer_site` (`le`, `error_type`) |
| between the zones of a site | the connector | `shawk_path_zone_tcp_handshake_seconds_bucket{le="+Inf"}`, `_sum`, `_count`; `shawk_path_zone_tcp_syn_retransmits_total`; `shawk_path_zone_connection_failed_by_reason_total` | `shawk_site`, `shawk_zone`, `shawk_peer_zone` (`error_type`) |
| per source host | the agent: `job="shawk-agent"`, `instance` the host name | `shawk_path_host_tcp_handshake_seconds_bucket{le="+Inf"}`, `_sum`, `_count`; `shawk_path_host_tcp_syn_retransmits_total`; `shawk_path_host_connection_failed_by_reason_total` | `shawk_site`, `shawk_zone`, `shawk_peer_site` (`shawk_peer_zone` with `path_hosts: zone`) (`error_type`) |

- **Buckets** are kept between sites only, with the bounds of §3.2 of the
  design (decision 3). With flat zone names, every zone is its own site, so
  every pair of zones has percentiles; the zone family is then empty.
- **Emission.**
  - The site and zone families sum the increases of all the hosts of a
    connector. A timer of the connector emits them every 15 s.
  - With several connectors, each emits its own `instance`, and the rules
    sum over `instance`.
  - The host family is emitted once per interval of its host, with the
    metrics of the agent: the last request of an interval always carries
    them.
- **No `~other`.** Zones are a closed set from the configuration, so no
  peer is folded into `~other`. Folding by first come, as `max_peers`
  does, would differ from host to host and corrupt the matrices.
- **Reasons** follow the outputs per dependency: a series is created at
  its first increase and emits 0 first (§5.3 of the design).

### 3.4 Connector

The inputs are those of the outputs per dependency. The connector already
keeps the buckets of the histograms of handshakes in the state of each
input, checks their bounds and resets a histogram as a whole when any of
its buckets decreases (§5.3 of the design); the outputs per dependency have
no buckets. For the paths:

- **One delta per input.** The delta of an input advances its state, so it
  is computed once and its increase feeds every output: the dependency, and
  the host, zone and site families.
- **Outputs with buckets** for the family of sites.

### 3.5 Series

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
- **Per pair of hosts** there would be 10⁸ pairs, which is why there are
  no such series.

### 3.6 Localization

Pingmesh localizes a problem by comparing the sources:

| what the matrices show | where to look |
|---|---|
| one source host is bad towards every site (hosts table) | that host: its NIC, its link, its CPU (softirq), or a local firewall or network policy that drops (§4) |
| every host of zone A is bad (a row of the zone matrix) | the uplinks of A, e.g. its top-of-rack switch |
| every zone is bad towards zone B (a column) | B: its switch, or its servers dropping SYNs on full listen queues (§4) |
| one pair of zones or sites is bad | the path between them |
| a steady fraction of the connections of a pair fails, not all | a link or an ECMP member that drops some flows (the black holes of Pingmesh); locating it takes traceroute (§5) |

### 3.7 SYN loss estimate

- The probability that a SYN (or its SYN-ACK) is lost is estimated, per
  pair and family, as

  lost / sent = (SYN retransmissions + `timeout` failures) / (handshakes +
  failures − `local` failures + SYN retransmissions).
- An established attempt with k retransmissions lost k of its k + 1 SYNs;
  an attempt that timed out lost all of them.
- The estimate stays within [0, 1], and an unreachable pair reads 1 on
  every kernel, whatever its schedule of SYNs.
- `local` failures sent no SYN and are left out.
- `aborted` failures are shown as their own ratio of attempts, because an
  application whose connect timeout is below 1 s gives up before any SYN
  is retransmitted.

### 3.8 Recording rules and alerts

Recording rules (missing series are taken as 0 with `or ... * 0`):

- `shawk:path_site_handshake_seconds_bucket:rate5m`, summed by
  `shawk_site`, `shawk_peer_site`, `le` (and over `instance`);
- `shawk:path_{site,zone,host}_syn_sent:rate5m` and `_syn_lost:rate5m`;
- `shawk:path_{site,zone,host}_attempts:rate5m` and `_aborted:rate5m`.

Alerts, in `packaging/prometheus/shawk-rules.yml`, group `shawk-alerts`;
the thresholds are to be tuned:

- `ShawkPathSynLoss`: the loss estimate of a pair of sites or of zones is
  above 1 % for 15 minutes, with at least one SYN per second, seen by at
  least 2 source hosts (from the host family);
- `ShawkPathConnectTimeouts`: `timeout` and `unreachable` failures are
  above 1 % of the attempts of a pair for 10 minutes, seen by at least 2
  source hosts.

A single dependency that fails (e.g. the clients of a decommissioned
server) is the case of `ShawkConnectionFailureRate`, not of these alerts.

### 3.9 Grafana: shawk / Network paths

The grouping-to-matrix transformation of Grafana takes one value per cell,
so each quantity has its own matrix:

- **Between sites:** p99 connect time (from the handshakes), the SYN loss
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

The limitations of the measurement itself are in §10 of the design
(Handshakes). Those that matter for the paths:

- **Coverage.** Paths without new connections are not measured, which is
  what active probing would add. Connection pools open few connections;
  their established connections are covered by the sampled RTT and the
  retransmissions per dependency only.
- **"Lost" is not only lost on the wire.** SYNs dropped by a local
  firewall, egress BPF or a network policy (Calico and Cilium drop by
  default), by a remote firewall that drops rather than rejects, or by a
  server whose accept queue is full (or whose SYN queue is full without SYN
  cookies) cannot be told from losses in the network. The listen drops of
  phase 3 would tell the last case apart.
- **Retransmission schedules** differ between kernels, so the buckets of a
  mixed fleet are not comparable above 1 s. The loss estimate is.
- **Relays.**
  - A proxy or a load balancer that terminates TCP is the end of the
    measured path.
  - A connection to a virtual address takes the zone of the virtual
    address, which its client edge records, also when a translation names
    the service at a backend (§5.4 of the design).
  - A sidecar that intercepts connections locally (iptables REDIRECT, e.g.
    Istio) answers the handshake in microseconds, while the edge keeps the
    remote peer. Its samples would pull the matrices down, so those
    services belong in `path_exclude_services`.
- **No location below a zone.** shawk tells which hosts and zones, not
  which link or switch; that takes traceroute (§5).
- **Several connectors.** The paths sum per-host state, like every output
  of the connector, so they need each host to stay on one connector, which
  routing by resource does not guarantee (#128). Phase 2 should follow it
  for fleets with several connectors.

## 5. Alternatives not taken

| alternative | why not |
|---|---|
| Active probing in the agent, as Pingmesh does | **Needs:** a controller to hand out the lists, and knowledge of the topology. **Probes need:** a responder on every host, ICMP (`CAP_NET_RAW`, or ping sockets allowed by `ping_group_range`), or the ports of the services. **Costs:** it adds traffic and series for every probed pair. **Measures** what probes see, not what applications see. |
| A separate prober (Cloudprober, blackbox_exporter) beside shawk | **Possible, and complementary.** shawk would measure the prober's handshakes passively too, which covers idle paths. **Catch:** its connections are recorded as dependencies of every host it probes. They carry its `service.name`, but the views of `shawk_v1` and the rules cannot leave a service out, so "who still uses this host?" would answer the prober. **Would need** a way to exclude named services from the views and rules (phase 3). |
| Native histograms with custom buckets (`otlp.convert_histograms_to_nhcb`, Prometheus 3.4 and later) | **Breaks the existing series:** the setting applies to the whole OTLP receiver and replaces classic histograms instead of adding to them. It would remove `shawk_tcp_rtt_seconds_sum` and `_count`, which the recording rules use, and the request-duration buckets of OBI, which the application dashboard uses. **Alternative:** OTLP exponential histograms are stored as native histograms without that setting (decision 3). |
| Series per pair of hosts | **Quadratic:** N² series. Hosts appear only as sources towards a site or a zone. |
| Zones in `peer_cidrs` | **Mixes concerns:** `peer_cidrs` names peers without a service, so rack ranges added there would rename those peers on the dependency map and in `service.peer.name`. Topology and naming are kept apart. |
| Path quality in PostgreSQL | **Wrong store:** PostgreSQL holds relations and their periods, not time series. |
| Localizing links with traceroute, as 007 does [2] | **Out of scope:** it sends probes, and it needs routers that answer them. The matrices tell where to start. |

## 6. Decisions

Decided as recommended (2026-11-02):

1. **Granularity of the host family.** Per host towards sites:
   `path_hosts: site` is the default, and `zone` and `none` are available.
2. **Zones are kept apart from `peer_cidrs`.**
3. **The histogram between sites** uses classic buckets with the bounds of
   the handshakes. An OTLP exponential histogram, which Prometheus would
   store as a native histogram with power-of-two bounds, is reconsidered
   once the TSDB settings it needs are verified, including out-of-order
   native histograms within the window of 30 minutes.
4. **`path_exclude_services`** is a list of services named as the `job`
   label names them. Matching by unit or executable is not added.

## 7. Changes elsewhere

- **Prometheus contract:** additions only.
- **PostgreSQL:** no change.
- **Agent:** no change and no flag.
- **Configuration:** `zones`, `path_hosts` and `path_exclude_services` in
  the connector, with an example in `packaging/collector/config.yaml`.
- **Documents:** `docs/design.md` §5.3 (the path outputs), §7 (counting:
  the paths come from the client side only), §8 (the dashboard) and §10;
  README (dashboards); `packaging/README.md`.

## 8. Tests

**Connector:**
- one delta per input feeding the dependency, host, zone and site outputs;
- outputs with buckets for the site family;
- zones: parsing (IPv4-mapped prefixes, duplicates, the limit), the
  narrowest range; the zone of the host with a `host.ip` that holds
  loopback and container addresses; loopback and the host's own addresses
  left out; folded peers; `path_exclude_services`; no path output without
  `zones`;
- emission: the timer of the site and zone families, the host family with
  the agent's resource once per interval, and two connectors with their own
  `instance`.

**Packaging.** Extend the tests in `test/packaging` (names, rules,
dashboards) to the new names.

**e2e.** Hosts in two sites of network namespaces; check the three families
of path outputs of the collector.

## 9. Phase 3

Separate issues, each measured first:

- **The server side of passive opens,** for clients without an agent:
  - SYN-ACK retransmissions. `tcp_create_openreq_child()` copies the
    retransmissions of the request into `total_retrans`, but they count
    the SYN-ACKs sent by the request timer and in answer to duplicate
    SYNs: one lost SYN-ACK counts 2. Behind SYN cookies there is no
    request at all.
  - The RTT sample of the SYN-ACK (`tcp_synack_rtt_meas()`).

  It is counted only when the client has no agent, as in §7 of the
  design, and kept apart from the client view in the path families.
- **The loss ratio of data:** deltas of `data_segs_out` (4.6; `segs_out`
  also counts pure ACKs), accounted like the bytes, against
  `shawk.tcp.retransmits`.
- **Listen overflows and drops** per network namespace
  (`TcpExtListenOverflows`, `TcpExtListenDrops` of `/proc/net/netstat`), as
  metrics of the agent, to tell overloaded servers from network losses.
- **Excluding named services** (e.g. a prober) from the views of
  `shawk_v1` and the rules.
- **The RTT of the path:** the first RTT sample after the handshake
  (`srtt_us >> 3` at ESTABLISHED), besides the time from `connect(2)`.
  Without TCP timestamps, Karn's algorithm skips the sample when the SYN
  was retransmitted, so it is biased towards the good cases.
- **SYN retransmissions handed to IP:** the tracepoints
  `tcp_retransmit_skb` and `tcp_retransmit_synack` would leave out local
  drops, at the cost of a program run on every retransmission; worth it if
  local drops turn out to dominate.

## References

1. Chuanxiong Guo et al. *Pingmesh: A Large-Scale System for Data Center
   Network Latency Measurement and Analysis.* SIGCOMM 2015.
2. Behnaz Arzani et al. *007: Democratically Finding the Cause of Packet
   Drops.* NSDI 2018.
