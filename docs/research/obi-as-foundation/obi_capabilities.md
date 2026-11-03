# OpenTelemetry eBPF Instrumentation (OBI): what it offers for a process-level network dependency map on plain Linux hosts (state as of 2026-10-31)

## Scope, versions and method

- **Core release:** OBI **v1.0.0**, tagged 2026-10-30 (commit `d23be0d`). The release notes call it "the project's first stable core release". It "promotes the instrumentation validated in v1.0.0-rc.2, which includes the v0.15.2 functionality and fixes". Under the stability contract, Config v2, documented CLI flags, environment variables, release binaries and image behavior, and telemetry classified `stable` receive compatibility guarantees. — [v1.0.0 release](https://github.com/open-telemetry/opentelemetry-ebpf-instrumentation/releases/tag/v1.0.0); [OBI v1.0.0 blog (2026-10-30)](https://opentelemetry.io/blog/2026/obi-v1-release/)
- **Where v1.0.0 comes from:** a release branch cut at v1.0.0-rc.2 (2026-10-16). It is not an ancestor of `main`. Several relevant features merged to `main` after the branch point are **not in any release** as of 2026-10-31 (checked with `git merge-base --is-ancestor`):
  - peer-metadata exchange for non-Kubernetes hosts, #3806 (2026-10-30)
  - the `traces_service_graph_connection_info` gauge, #3796 (2026-10-26)
  - a GRO/TSO wire-size fix for NetO11y, #3964
  - "real local port of closed sockets" in StatsO11y, #3992

  This document labels these **main-only**.
- **Collector receiver:** a separate Go module, `go.opentelemetry.io/obi/collector`, on its own v0 line. Latest is `collector/v0.15.2`, which pairs with core v1.0.0. — [v1.0.0 release](https://github.com/open-telemetry/opentelemetry-ebpf-instrumentation/releases/tag/v1.0.0); [VERSIONING.md "Release scope"](https://github.com/open-telemetry/opentelemetry-ebpf-instrumentation/blob/v1.0.0/VERSIONING.md)
- **Stability of the telemetry shawk would use:** in the v1.0.0 schema registry, every NetO11y metric, every StatsO11y metric and every service-graph metric is classified `development`. TELEMETRY.md says development telemetry "may change or be removed in a v1 minor release". It is therefore **outside the v1 compatibility contract**. — [schemas/obi/groups/network/metrics.yaml](https://github.com/open-telemetry/opentelemetry-ebpf-instrumentation/blob/v1.0.0/schemas/obi/groups/network/metrics.yaml); [schemas/obi/groups/stats/metrics.yaml](https://github.com/open-telemetry/opentelemetry-ebpf-instrumentation/blob/v1.0.0/schemas/obi/groups/stats/metrics.yaml); [site/docs/metrics.md](https://github.com/open-telemetry/opentelemetry-ebpf-instrumentation/blob/v1.0.0/site/docs/metrics.md); [TELEMETRY.md](https://github.com/open-telemetry/opentelemetry-ebpf-instrumentation/blob/v1.0.0/TELEMETRY.md)
  - Inconsistency: VERSIONING.md and SUPPORT_MATRIX.md at the v1.0.0 tag still say "OBI is currently in Development".
- **Method:**
  - Read the opentelemetry.io OBI docs from the `open-telemetry/opentelemetry.io` repo (`content/en/docs/zero-code/obi`, commit `e731dee`, 2026-10-31). Those pages still describe **v0.15.2**.
  - Read the OBI source at tag `v1.0.0` and at `main` (`4e33aec`, 2026-10-30).
  - The GitHub REST/GraphQL API was blocked for this repository, so release notes were read from github.com HTML pages (v1.0.0 and v0.14.0).
- **Evidence labels:** statements marked "(source)" were verified in code but are not stated in the user docs. Statements marked "(inference)" are my own reasoning.

## Summary for shawk

| # | Question | Short answer |
|---|---|---|
| 1 | NetO11y (`network`) | Packet-level flows from a socket filter (default) or TC. The flow key is the 5-tuple plus ifindex, with **no PID, cgroup or comm**. On plain hosts, flows are host and interface level only. `src.name`/`dst.name` hold the IP unless reverse DNS is enabled. Sampling is off by default. `cache_max_flows` is 5000 and `cache_active_timeout` is 5s. UDP is included. |
| 2 | StatsO11y (`stats*`) | Tracepoint, raw-tracepoint and kprobe hooks (`inet_sock_set_state`, `tcp_retransmit_skb`, `tcp_close`, `tcp_sendmsg`, `tcp_cleanup_rbuf`). Attributes are src/dst address (port opt-in). They are node-wide by design ("unreliable PID calculations … false positives"). RTT arrived in v0.7.0, failed connections in v0.9.0, retransmits and io in v0.10.0, successful connections in v0.14.0. |
| 3 | AppO11y | About 20 L7 protocols. **No generic or unknown-TCP spans** (only `obi.failed_connect`). The service graph is built in-process from spans. Uninstrumented peers become `virtual_node` edges named by DNS, or by IP, or are collapsed to `outgoing`/`incoming`. Pre-existing connections are traced from the next request onward. |
| 4 | Discovery and identity | Selectors are open port, exe path, cmd args, language, PID and container. There is **no systemd unit or cgroup selector**. OBI **does** read `OTEL_SERVICE_NAME`/`OTEL_RESOURCE_ATTRIBUTES` from `/proc/PID/environ` of instrumented processes, then falls back to the executable name. `host.id` comes from `/etc/machine-id`; `host.name` is the FQDN. |
| 5 | Listeners / first-seen | Not exported in v1.0.0; listening ports are only internal BPF state. Main-only: a peer-metadata HTTP API lists the TCP listeners of instrumented services, and a `connection_info` gauge marks recently seen edges. There is no first-seen anywhere. |
| 6 | Hooks and overhead | AppO11y loads many kprobes (`tcp_sendmsg`, `tcp_recvmsg`, `sock_recvmsg`, accept, connect, …) plus uprobes, but only when selectors are set. With Config v1 you can run network and stats only. With Config v2 you must set `default_action: exclude`. No quantitative overhead numbers are published. |
| 7 | RHEL deployment | Kernel 5.8+ (RHEL 4.18+ exception), BTF required, so Rocky 9 (5.14) qualifies. RHEL 9.6 is in CI verifier coverage. Distribution is a tarball, a container image, and a contrib `obi@.service` template; **no RPM**. SELinux is undocumented. Per-feature capabilities are documented. |
| 8 | Output | OTLP metrics and traces, a Prometheus endpoint, and `attributes.select` include/exclude with globs. The Collector receiver is **alpha** (traces, metrics, logs), must be built with OCB from a local checkout, and is single-node. |

---

## 1. Network metrics (NetO11y, `network` feature)

### Answer
- **Enabling:** add `network` to `OTEL_EBPF_METRICS_FEATURES` (Config v1 `metrics.features`; Config v2 `capture.metrics.features` or `capture.network.capture.enabled`). An OTLP or Prometheus metrics exporter, or `print_flows`, must also be configured.
- **Metrics:**

  | OTLP name | Prometheus name | Feature |
  |---|---|---|
  | `obi.network.flow.bytes` | `obi_network_flow_bytes_total` | `network` |
  | `obi.network.flow.packets` | `obi_network_flow_packets_total` | `network_flow_packets` |
  | `obi.network.inter.zone.bytes` | `obi_network_inter_zone_bytes_total` | `network_inter_zone` (experimental, Kubernetes only) |

  All three are `development` stability.
- **Capture mechanism:** `network.source` / `OTEL_EBPF_NETWORK_SOURCE`, default **`socket_filter`**, alternative **`tc`**.
  - Socket-filter mode: OBI opens **one** `AF_PACKET`/`SOCK_RAW`/`ETH_P_ALL` socket and attaches the `obi_socket__filter` program with `SO_ATTACH_BPF`.
  - TC mode: `tc_ingress`/`tc_egress` programs in direct-action mode. The backend is `ebpf.traffic_control_backend` = `tc`, `tcx` or `auto` (TCX on kernel ≥ 6.6).
  - TC conflicts with other TC users such as Cilium; socket_filter does not.
  - The code is derived from netobserv-ebpf-agent release-1.4.
- **Flow key (`flow_id`):**
  - `src_ip`, `dst_ip` (IPv4 stored as IPv4-mapped IPv6), `if_index`, `eth_protocol`, `src_port`, `dst_port`, `transport_protocol`.
  - Per-flow values: bytes, packets, start/end monotonic timestamps, OR-ed TCP flags, interface direction, initiator (src/dst/unknown), and errno.
  - Kernel aggregation is in an `LRU_PERCPU_HASH` (`aggregated_flows`, sized by `cache_max_flows`). When an insert fails, records fall back to a 16 MiB ring buffer (`direct_flows`).
- **Process attribution: none.** The key and the record carry no PID, TGID, cgroup, comm or netns.
  - The user-space pipeline adds K8s metadata, reverse DNS, GeoIP, CIDR names, `obi.ip`, and interface names.
  - On a plain VM or bare-metal host the result is **host/interface-level 5-tuple traffic only**.
  - The attributes `service.name`, `service.namespace`, `service.peer.name` and `service.peer.namespace` exist in the metric definition, but:
    - they belong to the *Kubernetes* attribute group, which is disabled when K8s metadata is off (source);
    - they are filled only by the K8s decorator, or by the Go-embedding `DynamicSelector`.
  - The `DynamicSelector` maps **IPs** to services. Without a K8s store it uses only the addresses of an *isolated container netns*. The code says it "yields nothing for a process sharing the host or agent namespace" (source).
- **Directionality:**
  - `direction` = `request`/`response`/`unknown`. It is derived from a `conn_initiators` LRU map filled when a SYN or SYN-ACK is seen. Entries are deleted on FIN/RST.
  - `client.port`/`server.port` are opt-in attributes derived from the same initiator.
  - If no SYN was seen (pre-existing connections, UDP, map eviction), the initiator is unknown. In that case `direction=unknown` and client/server ports are empty, unless `network.guess_ports: ordinal`, which treats the lower port as the server. Ordinal guessing is off by default since v0.7.0.
  - **Implication (inference):** you *can* aggregate flows by `src.address, dst.address, server.port, transport` and drop the ephemeral port, similar to shawk's key, but only for TCP connections whose handshake OBI observed.
- **Attribute list:**
  - **Default, non-K8s:** `direction` only. `src.cidr`/`dst.cidr` are added when `network.cidrs` is set. `iface`/`iface.direction` are added only when the deduper is `none`.
  - **Opt-in:** `obi.ip`, `transport`, `src.address`, `dst.address`, `src.port`, `dst.port`, `src.name`, `dst.name`, `client.port`, `server.port`, `src.zone`, `dst.zone`, `network.type`, `network.protocol.name`, `iface`, `iface.direction`.
  - **GeoIP** (shown when configured): `src.country`, `dst.country`, `src.asn`, `dst.asn`.
  - **K8s (shown with K8s):** `k8s.src/dst.owner.name`, `owner.type`, `namespace`, `k8s.cluster.name`.
  - **K8s (opt-in):** `k8s.src/dst.name`, `type`, `node.ip`, `node.name`.
  - **Service (opt-in):** `service.name`, `service.namespace`, `service.peer.name`, `service.peer.namespace`.
  - Address/port semantics: `src.*` is local for egress and remote for ingress; `dst.*` is the opposite.
- **`src.name`/`dst.name` on non-K8s hosts:** the pipeline order is K8s decorator (off) → `ReverseDNS` → … → `Decorate`, which fills the name with the **IP string** when it is still empty.
  - `network.reverse_dns.type` (env `OTEL_EBPF_REVERSE_DNS_TYPE`, legacy `OTEL_EBPF_NETWORK_REVERSE_DNS_TYPE`) accepts:
    - `none` (default);
    - `local` (Go `net.LookupAddr`);
    - `ebpf` (XDP program snooping DNS responses).
  - Cache: `cache_len` 256, `cache_expiry` 1h.
  - The code calls ReverseDNS "currently experimental … hidden from the documentation". The docs' description of `dst.name` as "resolved from service discovery" does not apply to plain hosts.
- **Sampling:** `network.sampling` / `OTEL_EBPF_NETWORK_SAMPLING`, default **0 (disabled)**. When set to N, the kernel program keeps a random 1-in-N packets (`bpf_get_prandom_u32() % sampling`).
- **Cache and flush defaults:**

  | Setting (env `OTEL_EBPF_NETWORK_*`) | Default | Meaning |
  |---|---|---|
  | `cache_max_flows` | **5000** | Also sizes the `flow_directions` and `conn_initiators` maps |
  | `cache_active_timeout` | **5s** | Maximum time a flow stays in the accounting cache before export |
  | `deduper` | `first_come` | `deduper_fc_ttl` defaults to 2 × `cache_active_timeout` |
  | `direction` | `both` | |
  | `exclude_interfaces` | `lo` | |
  | `listen_interfaces` | `watch` | `listen_poll_period` 10s |
  | `agent_ip_iface` | `external` | |
  | `agent_ip_type` | `any` | |

  Export interval: OTLP metrics `interval` 60s; Prometheus `ttl` 5m.
- **UDP coverage:** TCP and UDP ports are parsed. Other IP protocols are counted without ports. `protocols`/`exclude_protocols` filter by IP protocol name. UDP has no initiator detection, so direction is `unknown` unless ordinal guessing is enabled.
- **Things that are *not* seen (source/inference):**
  - Packets whose source IP equals the destination IP are dropped in the BPF program, and `lo` is excluded. So **same-host process-to-process traffic is invisible** to NetO11y.
  - The AF_PACKET socket only sees OBI's own network namespace (inference from the socket-based design).
- **Overhead notes:**
  - The docs give no quantitative numbers. They only note that bytes "are captured from the host perspective, so they include the overhead of the network stack (protocol headers)".
  - Cardinality is controlled by `attributes.select`.
  - There is an internal metric `obi_bpf_network_ignored_packets_total`.
  - `ebpf.force_bpf_map_reader` chooses `batch` or `legacy` map reads; RHEL 8-based systems fall back to the slower `legacy` reader.
  - The BPF program runs on **every packet** of the observed netns when sampling is 0 (inference).
  - In v1.0.0 each skb is counted as one packet, so GRO/TSO packet counts and header bytes are undercounted. This is fixed main-only by #3964.

### Cited findings
- Metrics, feature names, attribute table, the "host perspective" note, the CIDR example, and the statement "pre-aggregated at the process level" (meaning inside the OBI process). — [OBI docs: Network metrics](https://opentelemetry.io/docs/zero-code/obi/network/)
- `source` (default `socket_filter`, alternative `tc`; Cilium caveat), `cidrs`, `agent_ip*`, `interfaces`, `exclude_interfaces` (default `lo`), `protocols`, `cache_max_flows` (5000), `cache_active_timeout` (5s), `direction` (`both`), `sampling` (0 = disabled), `print_flows`, `guess_ports` (`disable`, breaking change in v0.7.0). — [OBI docs: Network configuration](https://opentelemetry.io/docs/zero-code/obi/network/config/)
- Defaults and the `deduper`, `listen_interfaces` and `reverse_dns` fields. — [pkg/obi/network_cfg.go (`DefaultNetworkConfig`, L163+)](https://github.com/open-telemetry/opentelemetry-ebpf-instrumentation/blob/v1.0.0/pkg/obi/network_cfg.go)
- Flow key and metrics structs. — [bpf/netolly/flow.h (L66–82)](https://github.com/open-telemetry/opentelemetry-ebpf-instrumentation/blob/v1.0.0/bpf/netolly/flow.h)
- Maps (`direct_flows` 1<<24, `aggregated_flows`, `conn_initiators`) and initiator logic. — [bpf/netolly/flows_common.h](https://github.com/open-telemetry/opentelemetry-ebpf-instrumentation/blob/v1.0.0/bpf/netolly/flows_common.h)
- Socket-filter program: sampling at L191 and the `same_ip` drop at L203. — [bpf/netolly/flows_sock.c (L188+)](https://github.com/open-telemetry/opentelemetry-ebpf-instrumentation/blob/v1.0.0/bpf/netolly/flows_sock.c)
- TC programs. — [bpf/netolly/flows.c (L291, L296)](https://github.com/open-telemetry/opentelemetry-ebpf-instrumentation/blob/v1.0.0/bpf/netolly/flows.c)
- AF_PACKET socket and `SO_ATTACH_BPF`. — [pkg/internal/netolly/ebpf/sock_tracer.go (L106–108)](https://github.com/open-telemetry/opentelemetry-ebpf-instrumentation/blob/v1.0.0/pkg/internal/netolly/ebpf/sock_tracer.go)
- Pipeline order (ProtocolFilter → Deduper → K8s → ReverseDNS → GeoIP → CIDR → Decorate → DynamicPID → AttributeFilter → exporters). — [pkg/netolly/agent/pipeline.go](https://github.com/open-telemetry/opentelemetry-ebpf-instrumentation/blob/v1.0.0/pkg/netolly/agent/pipeline.go)
- Name fallback to the IP. — [pkg/internal/pipe/decorate/decorator.go (L50)](https://github.com/open-telemetry/opentelemetry-ebpf-instrumentation/blob/v1.0.0/pkg/internal/pipe/decorate/decorator.go)
- ReverseDNS modes and the "experimental" comment. — [pkg/internal/pipe/rdns/reverse_dns.go (L36+)](https://github.com/open-telemetry/opentelemetry-ebpf-instrumentation/blob/v1.0.0/pkg/internal/pipe/rdns/reverse_dns.go)
- Attribute groups and defaults (`networkAttributes` L87, `networkKubeAttributes` L132 with `service.*`). — [pkg/export/attributes/attr_defs.go](https://github.com/open-telemetry/opentelemetry-ebpf-instrumentation/blob/v1.0.0/pkg/export/attributes/attr_defs.go)
- Direction and client/server port getters. — [pkg/internal/netolly/ebpf/record_getters.go](https://github.com/open-telemetry/opentelemetry-ebpf-instrumentation/blob/v1.0.0/pkg/internal/netolly/ebpf/record_getters.go); [record_port_guess.go](https://github.com/open-telemetry/opentelemetry-ebpf-instrumentation/blob/v1.0.0/pkg/internal/netolly/ebpf/record_port_guess.go)
- IP-based DynamicSelector decoration; not applicable to host-netns processes. — [pkg/selection/dynamic_app_ips.go (L270–291)](https://github.com/open-telemetry/opentelemetry-ebpf-instrumentation/blob/v1.0.0/pkg/selection/dynamic_app_ips.go); [pkg/selection/dynamic_flow_attrs.go](https://github.com/open-telemetry/opentelemetry-ebpf-instrumentation/blob/v1.0.0/pkg/selection/dynamic_flow_attrs.go); PR #2861 "Support isolated netns non-k8s processes for network+stats metrics" (v0.13.0)
- Generated reference with requirement levels and the `development` stability of every flow metric. — [site/docs/metrics.md](https://github.com/open-telemetry/opentelemetry-ebpf-instrumentation/blob/v1.0.0/site/docs/metrics.md)
- `ebpf.force_bpf_map_reader` (RHEL 8 falls back to `legacy`). — [devdocs/config/CONFIG.md](https://github.com/open-telemetry/opentelemetry-ebpf-instrumentation/blob/v1.0.0/devdocs/config/CONFIG.md)
- The Grafana Beyla network page mirrors OBI: same attributes and no process attribution. `src.name` is described as "Kubernetes name, host name, or IP address". — [Grafana Beyla docs: network](https://grafana.com/docs/beyla/latest/network/)

### Gaps / not documented
- No published CPU or memory overhead figures for socket_filter versus TC.
- The docs do not say that loopback or same-IP traffic is dropped; I found it in source.
- The docs do not say that `interfaces`/`exclude_interfaces` effectively apply to TC attachment, while socket_filter uses one unbound AF_PACKET socket (source/inference).
- No flow export with timestamps: flows become counters only. `print_flows` prints attributes but no times.

## 2. StatsO11y (`stats` features)

### Answer
- **Metrics:**

  | OTLP name | Prometheus name | Type, unit | Feature |
  |---|---|---|---|
  | `obi.stat.tcp.rtt` | `obi_stat_tcp_rtt_seconds` | histogram, s | `stats_tcp_rtt` |
  | `obi.stat.tcp.failed.connections` | `obi_stat_tcp_failed_connections_total` | counter | `stats_tcp_failed_connections` |
  | `obi.stat.tcp.successful.connections` | `..._total` (derived) | counter | `stats_tcp_successful_connections` |
  | `obi.stat.tcp.retransmits` | `obi_stat_tcp_retransmits_total` | counter | `stats_tcp_retransmits` |
  | `obi.stat.tcp.io` | `obi_stat_tcp_io_bytes_total` | counter, By | `stats_tcp_io` |

  - RTT default buckets (seconds): 0.0005, 0.001, 0.002, 0.005, 0.010, 0.025, 0.050, 0.100, 0.250, 0.500, 1.0. Override with `buckets.stat_tcp_rtt_histogram`.
  - **Enabling:** `stats` enables everything, **including** `stats_tcp_io`; or list individual features.
  - Config v2: `capture.network.stats.enabled` plus `features` from [`tcp_rtt`, `tcp_failed_connections`, `tcp_successful_connections`, `tcp_retransmits`, `tcp_io`].
  - All five metrics are `development` stability.
- **Hook points and when events fire** (bpf/statsolly):
  - **RTT:** `kprobe/tcp_close` reads `tcp_sock.srtt_us >> 3`.
    - It skips sockets that never connected, and values of 0 or above 60 s.
    - It fires **once per connection, at close**, so long-lived connections report nothing until they close.
    - It is not reported if the kernel closed the socket (for example on a reset) before the application did and the local endpoint never sent data. This limitation is worded in main's SUPPORT_MATRIX. The v1.0.0 SUPPORT_MATRIX instead notes that `src.port` may be 0 on the RST-receiver side. The RTT probe logic is otherwise unchanged between the two.
  - **Failed connections:** `tracepoint/sock/inet_sock_set_state` on any transition to `TCP_CLOSE`. Excluded transitions are `LAST_ACK→CLOSE`, `TIME_WAIT→CLOSE` and `LISTEN→CLOSE`.
    - It counts when `sk_err ≠ 0`, or on an aborted `SYN_SENT`.
    - So it counts failed connect attempts **and** established connections aborted by RST or timeout (source). The docs describe only "failed connection attempts".
    - `reason` comes from `sk_err`: `refused`, `reset`, `timed_out`, `host_unreachable`, `net_unreachable`, `other`, `unknown`.
  - **Successful connections:** the same tracepoint, on `SYN_SENT→ESTABLISHED` (role client) or `SYN_RECV→ESTABLISHED` (role server).
  - **Retransmits:** `raw_tracepoint/tcp_retransmit_skb`. It counts data-segment and client-SYN retransmits; server SYN-ACK retransmits are not counted.
  - **IO:** `kprobe`+`kretprobe/tcp_sendmsg` (bytes returned) and `kprobe/tcp_cleanup_rbuf` (bytes copied).
    - Calls are batched 10 per socket and direction in an LRU map (`tcp_io_accum`, 16384 entries) and flushed on `tcp_close`.
    - On kernels older than about 6.5, `sendfile()` traffic is missed.
  - A helper tracepoint program keeps a `sock_role` map (client/server). It is written on `ESTABLISHED` and deleted on `CLOSE`.
- **Delivery:** every event is pushed to a 1 MiB ring buffer (`stats_events`). The wake-up threshold is `ebpf.stats_wakeup_data_bytes`, default 4096. Events are turned into metric observations in user space, so there is **no in-kernel aggregation** apart from the IO batches.
- **Attributes:**
  - `src.address` and `dst.address`, **shown by default** per the v1.0.0 code and the registry (`recommended`).
  - Opt-in: `src.port`, `dst.port`, `src.name`, `dst.name`, `src.zone`, `dst.zone`, `obi.ip`.
  - Per metric: `reason` (failed, opt-in), `network.tcp.handshake.role` = client/server/unknown (rtt, failed, successful; opt-in), `network.io.direction` (io; shown).
  - With K8s metadata: the K8s src/dst owner and namespace attributes, plus opt-in `service.name`/`service.peer.name`.
  - `src` is the **local** socket side and `dst` the remote side (`skc_rcv_saddr`/`skc_num` versus `skc_daddr`/`skc_dport`).
  - **There is no `server.port`/`client.port` attribute.** Getting the service port means selecting `src.port`/`dst.port`, which brings in the peer's ephemeral port and a cardinality blow-up. `handshake.role` tells you which side is which.
  - At v1.0.0, `src.port` can be 0 on the RST-receiver side. This is fixed main-only by #3992, which uses `inet_sport`.
  - Conflict: the opentelemetry.io metrics page lists `src.address`/`dst.address` as "hidden" for the stats metrics, but code and registry say they are default.
- **Per process / peer / service:**
  - **Not per process.** No PID, cgroup or comm is captured.
  - **Per peer:** yes, by address (port opt-in).
  - **Per service:** only through K8s metadata or the DynamicSelector, which is IP-based and needs a container netns.
- **Documented reason for no per-PID attribution:**
  - devdocs/metrics.md: "StatsO11y is the component responsible for calculating statistical metrics … across all applications running on a node, **regardless of which PID triggered the event**."
  - Also: "We decided to create a component separate from AppO11y and NetO11y … because statistical metrics are important if correlated to all applications, and also because **some hook points can cause unreliable PID calculations and lead to false positives**. The user can then filter the metrics in userspace…"
  - SUPPORT_MATRIX labels every stats metric "Node-wide statistical metric collection".
  - (Inference) The hooks run in softirq or timer context, where `current` is unrelated to the socket owner: passive-open `SYN_RECV→ESTABLISHED`, RST-triggered close, and the retransmit timer. shawk solved the same problem by matching the accepted socket's cgroup against listener holders.
- **Version introduced:**

  | Item | PR | First release |
  |---|---|---|
  | StatsO11y framework + `obi.stat.tcp.rtt` | #1572 (merged 2026-03-21) | **v0.7.0** (2026-04-03) |
  | `failed.connections` | #1825 | v0.9.0 (2026-05-11) |
  | `handshake.role` on failed connections | #2009 | v0.9.0 |
  | `handshake.role` on RTT | #2090 | v0.10.0 |
  | `retransmits` | #2124 | **v0.10.0** (2026-06-30) |
  | `io` | #2157 | **v0.10.0** |
  | `successful.connections` | #3464 | **v0.14.0** (2026-10-02) |
  | kprobes with lesser permissions | #3606 | v0.14.0 |

- **Capabilities (code check):** `CAP_BPF` plus `CAP_SYS_PTRACE`, `CAP_PERFMON` and `CAP_NET_RAW`.

### Cited findings
- Metric table, `stats_tcp_io` overhead warning, RTT buckets. — [OBI docs: exported metrics](https://opentelemetry.io/docs/zero-code/obi/metrics/); [Export data → metrics export features](https://opentelemetry.io/docs/zero-code/obi/configure/export-data/); [Histograms → TCP RTT](https://opentelemetry.io/docs/zero-code/obi/configure/metrics-histograms/)
- Config v2 keys. — [OBI docs: Config v2 → Network observability](https://opentelemetry.io/docs/zero-code/obi/configure/config-v2/); [devdocs config-v2.md](https://github.com/open-telemetry/opentelemetry-ebpf-instrumentation/blob/v1.0.0/devdocs/config/version-2.0/config-v2.md)
- Hooks: [bpf/statsolly/tp_tcp.c (tracepoints L90/L113/L174, raw_tracepoint L211)](https://github.com/open-telemetry/opentelemetry-ebpf-instrumentation/blob/v1.0.0/bpf/statsolly/tp_tcp.c); [bpf/statsolly/k_tcp.c (tcp_close L106/L114, tcp_sendmsg L157/L167, tcp_cleanup_rbuf L187)](https://github.com/open-telemetry/opentelemetry-ebpf-instrumentation/blob/v1.0.0/bpf/statsolly/k_tcp.c); [bpf/statsolly/maps/stats_events.h (1<<20)](https://github.com/open-telemetry/opentelemetry-ebpf-instrumentation/blob/v1.0.0/bpf/statsolly/maps/stats_events.h)
- Local/remote orientation. — [bpf/common/sockaddr.h `parse_sock_info`](https://github.com/open-telemetry/opentelemetry-ebpf-instrumentation/blob/v1.0.0/bpf/common/sockaddr.h)
- Rationale quotes (L100, L161); performance considerations. — [devdocs/metrics.md](https://github.com/open-telemetry/opentelemetry-ebpf-instrumentation/blob/v1.0.0/devdocs/metrics.md)
- "Node-wide" scope and limitations (SYN-ACK retransmits not counted; `sendfile` before about 6.5). — [SUPPORT_MATRIX.md → Statistical Metrics](https://github.com/open-telemetry/opentelemetry-ebpf-instrumentation/blob/v1.0.0/SUPPORT_MATRIX.md)
- Attribute defaults (`statsAttributes` L113: `src.address`/`dst.address` true); per-metric sections from L904. — [pkg/export/attributes/attr_defs.go](https://github.com/open-telemetry/opentelemetry-ebpf-instrumentation/blob/v1.0.0/pkg/export/attributes/attr_defs.go)
- Registry requirement levels. — [schemas/obi/groups/stats/metrics.yaml](https://github.com/open-telemetry/opentelemetry-ebpf-instrumentation/blob/v1.0.0/schemas/obi/groups/stats/metrics.yaml)
- Feature map (`stats` includes io). — [pkg/export/feature.go (L66–71)](https://github.com/open-telemetry/opentelemetry-ebpf-instrumentation/blob/v1.0.0/pkg/export/feature.go)
- Capability check. — [pkg/obi/os.go (L201)](https://github.com/open-telemetry/opentelemetry-ebpf-instrumentation/blob/v1.0.0/pkg/obi/os.go)
- PR #1572 introduced StatsO11y as "node-wide statistical metrics"; the PR discussion has no stated rationale for skipping PID attribution. — [PR #1572](https://github.com/open-telemetry/opentelemetry-ebpf-instrumentation/pull/1572)
- v0.14.0 release notes list "Add TCP successful connections stat metric (#3464)" and "Allow kprobes to run with lesser permissions (#3606)". — [v0.14.0 release](https://github.com/open-telemetry/opentelemetry-ebpf-instrumentation/releases/tag/v0.14.0)
- Release mapping verified with `git tag --contains` (#1572→v0.7.0, #1825→v0.9.0, #2124/#2157→v0.10.0, #3464→v0.14.0).

### Gaps / not documented
- The docs don't say that failed connections include resets and timeouts on established connections.
- The docs don't say that RTT is emitted only at close.
- No "open connections" gauge, and no periodic sampling of live sockets (no socket iterators in StatsO11y).
- The opentelemetry.io page lists no `successful.connections` row, although the feature is documented.

## 3. Application observability (AppO11y)

### Answer
- **L7 protocols traced** (SUPPORT_MATRIX):
  - HTTP/1.0–1.1 and HTTP/2 (plaintext and TLS) and gRPC;
  - MySQL, PostgreSQL, MSSQL, Redis, MongoDB 5.0+, Couchbase, Memcached (ASCII), Aerospike;
  - Kafka (produce/fetch), MQTT 3.1.1/5.0, NATS, AMQP 1.0;
  - SunRPC/ONC RPC over TCP (including NFS);
  - DNS (lookups; not enabled by default for traces);
  - with HTTP payload extraction enabled: GraphQL, JSON-RPC 2.0/MCP, Elasticsearch/OpenSearch, AWS S3/SQS/SNS, SQL++, and GenAI providers.

  TLS is covered through libssl uprobes, Go library probes, a Java agent, and Node.js and Python helpers. Client/server direction per protocol is in the docs' feature list.
- **Generic or unknown-protocol TCP tracing: none.**
  - `ReadTCPRequestIntoSpan` tries the kernel-classified protocols, then generic detection (SQL, FastCGI, Mongo, Couchbase, Memcached), then heuristics. Otherwise it returns `ignore` with the comment "ignore if we couldn't parse it".
  - The only protocol-agnostic span is **`obi.failed_connect`** (name `CONNECT`, client kind, `development`). It carries `server.address`, `server.port`, `client.address` and `error.type`, and is emitted for failed outbound connects of *instrumented* processes.
- **Peer identification in spans:**
  - Client spans (for example `obi.http.client`): `server.address` is the domain from the Host header or URL when available, otherwise the resolved name or the IP. They also carry `server.port`, `network.peer.address`, `network.peer.port`, and `service.peer.name`.
    - `service.peer.name` is opt-in since v0.14.0; select it with `attributes.select.traces.include`.
    - Since v0.15.2, HTTP client `server.address` omits the Host header port.
  - Server spans: `client.address`, `network.peer.address`/`port`, and the local `server.address`/`server.port`.
  - In metrics, client `server.address`/`server.port` and server `client.address` are listed as "hidden" on opentelemetry.io. The v1.0.0 code (`httpClientInfo`, `grpcClientInfo`, `serverInfo`) defaults `server.address`/`server.port` to shown and `client.address` to hidden.
- **Peer name resolution:**
  - `name_resolver.sources` defaults to `[k8s, ecs]`. Options are `dns` (reverse lookup), `rdns` (eBPF-captured DNS answers), `route53` (v0.15.2+), plus GCE and Azure via Config v2. Cache is 1024 entries with a 5 min TTL.
  - On a plain host without `dns`/`rdns`, the peer stays an IP.
  - Main-only addition: peer-metadata exchange between OBI agents (section 5) resolves remote services by destination IP and listening port.
- **Service graph metrics** (`application_service_graph`):
  - **Metric names:**
    - `traces_service_graph_request_client` (histogram)
    - `traces_service_graph_request_server` (histogram)
    - `traces_service_graph_request_total`
    - `traces_service_graph_request_failed_total`

    The names match the collector-contrib `servicegraphconnector`.
  - **Labels:** `client`, `server`, `client_service_namespace`, `server_service_namespace`, `connection_type` (`messaging_system` | `database` | `virtual_node`), `source="obi"`, plus K8s namespace/cluster labels when K8s is enabled. User attribute selection is disabled for these metrics.
  - They are **computed inside OBI from its own spans**, not by a Collector connector.
  - **Who counts the request total:** server spans always increment `request_total`. Client spans increment it only if the resolved server name is *not* a service this OBI instance tracks; then `connection_type=virtual_node`. This is how **uninstrumented peers** appear.
  - **Unresolved peer names:** IP-only names are replaced in graph labels by `attributes.rename_unresolved_hosts_outgoing` (default **`outgoing`**) for the server of client spans, and by `rename_unresolved_hosts_incoming` (default **`incoming`**) for the client of server spans. `rename_unresolved_hosts` (default `unresolved`) is the generic fallback. Set them to `""` to keep IPs.
  - As a result, on plain hosts without DNS, all uninstrumented destinations collapse into one `outgoing` node unless the rename is disabled.
  - TELEMETRY.md lists this as a known limitation, and also says the Prometheus service-graph series have no unique OBI-instance label.
  - (Inference) In v1.0.0, a cross-host edge where both ends are instrumented by different OBI instances can be counted by both, because client-side suppression only checks the local tracker. The main-only peer-metadata design explicitly adds a "leave the request-total increment to the server agent" handshake.
  - Self-references are excluded by default (`allow_service_graph_self_references: false`).
- **Main-only:** `traces_service_graph_connection_info`, a gauge with value 1 while an edge is "observed recently". The Config v2-only feature is `application_service_graph_connection_info`; `connection_info_ttl` defaults to 15 min (PR #3796).
- **Connections that existed before OBI started:** traffic is captured per send/recv call, so later requests on old keep-alive connections are traced.
  - Server-versus-client classification uses a `listening_ports` BPF map that is seeded at startup by an `iter/tcp` program (`obi_iter_tcp`) and maintained by kprobes (source).
  - Documented caveats:
    - gRPC on connections opened before OBI "may use `*` for method names";
    - PostgreSQL "connections opened before OBI started miss `db.namespace`";
    - prepared statements created earlier may miss query text;
    - Redis may miss the database number;
    - Couchbase may miss the bucket.
  - Context propagation (disabled by default) handles already-open TCP sockets differently by version. At v1.0.0, tpinjector's own `iter/tcp` iterator adds all existing TCP sockets to `sock_dir` at startup. On main only (#3689, 2026-10-22), enrollment is scoped to instrumented processes, whose open sockets are copied with `pidfd_getfd`.
  - No user doc states the general rule.
- **Scope limits relevant to a complete map:**
  - Only processes selected by discovery are instrumented.
  - `exclude_otel_instrumented_services` defaults to **true**, so OBI turns off instrumentation of processes it sees exporting OTLP themselves.

### Cited findings
- Protocol list and caveats. — [OBI docs index](https://opentelemetry.io/docs/zero-code/obi/); [SUPPORT_MATRIX.md → Protocol Instrumentation](https://github.com/open-telemetry/opentelemetry-ebpf-instrumentation/blob/v1.0.0/SUPPORT_MATRIX.md); [Export data → compatibility](https://opentelemetry.io/docs/zero-code/obi/configure/export-data/)
- Unknown protocol ignored. — [pkg/ebpf/common/tcp_detect_transform.go (L82)](https://github.com/open-telemetry/opentelemetry-ebpf-instrumentation/blob/v1.0.0/pkg/ebpf/common/tcp_detect_transform.go)
- `obi.failed_connect`, `obi.http.client`, `obi.http.server` attributes; service-graph metric definitions. — [site/docs/spans.md](https://github.com/open-telemetry/opentelemetry-ebpf-instrumentation/blob/v1.0.0/site/docs/spans.md); [site/docs/metrics.md](https://github.com/open-telemetry/opentelemetry-ebpf-instrumentation/blob/v1.0.0/site/docs/metrics.md)
- Opt-in `service.peer.name`; `attributes.select.traces`. — [Metrics and traces attributes](https://opentelemetry.io/docs/zero-code/obi/configure/metrics-traces-attributes/)
- v0.14.0 and v0.15.2 upgrade notes. — [OBI docs index](https://opentelemetry.io/docs/zero-code/obi/)
- Service-graph record logic and `virtual_node`. — [pkg/export/otel/metrics_svc_graph.go (L343, L401–409)](https://github.com/open-telemetry/opentelemetry-ebpf-instrumentation/blob/v1.0.0/pkg/export/otel/metrics_svc_graph.go)
- Unresolved renames. — [pkg/appolly/app/request/span_getters_unresolved.go](https://github.com/open-telemetry/opentelemetry-ebpf-instrumentation/blob/v1.0.0/pkg/appolly/app/request/span_getters_unresolved.go); [pkg/obi/config.go (L320)](https://github.com/open-telemetry/opentelemetry-ebpf-instrumentation/blob/v1.0.0/pkg/obi/config.go); [devdocs/config/CONFIG.md](https://github.com/open-telemetry/opentelemetry-ebpf-instrumentation/blob/v1.0.0/devdocs/config/CONFIG.md)
- Known limitations (`outgoing` fallback for non-HTTP destinations without K8s; no instance label). — [TELEMETRY.md (L75–90)](https://github.com/open-telemetry/opentelemetry-ebpf-instrumentation/blob/v1.0.0/TELEMETRY.md)
- Name-resolver defaults and logic. — [pkg/obi/config.go (L232)](https://github.com/open-telemetry/opentelemetry-ebpf-instrumentation/blob/v1.0.0/pkg/obi/config.go); [pkg/transform/name_resolver.go](https://github.com/open-telemetry/opentelemetry-ebpf-instrumentation/blob/v1.0.0/pkg/transform/name_resolver.go); [Service discovery → enhanced service name lookup](https://opentelemetry.io/docs/zero-code/obi/configure/service-discovery/)
- Listening-port seeding. — [bpf/generictracer/iter_tcp.c](https://github.com/open-telemetry/opentelemetry-ebpf-instrumentation/blob/v1.0.0/bpf/generictracer/iter_tcp.c)
- Context propagation for existing sockets (v1.0.0: `iter/tcp` pre-population, L113/L313). — [devdocs/context-propagation.md](https://github.com/open-telemetry/opentelemetry-ebpf-instrumentation/blob/v1.0.0/devdocs/context-propagation.md). Main-only `pidfd_getfd` backfill: [main devdocs/context-propagation.md](https://github.com/open-telemetry/opentelemetry-ebpf-instrumentation/blob/main/devdocs/context-propagation.md)
- Main-only connection-info gauge. — [PR #3796](https://github.com/open-telemetry/opentelemetry-ebpf-instrumentation/pull/3796); [main site/docs/metrics.md](https://github.com/open-telemetry/opentelemetry-ebpf-instrumentation/blob/main/site/docs/metrics.md)

### Gaps / not documented
- No user doc describes how OBI decides that a peer is uninstrumented, or that unresolved names become `outgoing`/`incoming`. The rename keys appear only in the generated CONFIG.md.
- The metric-attribute defaults conflict between docs and code.
- No doc statement on pre-existing connections in general.

## 4. Process discovery and identity on plain hosts

### Answer
- **Selectors:**
  - Config v1 `discovery.instrument[]`: `open_ports`, `exe_path` (glob), `languages`, `cmd_args`, `target_pids`, `containers_only`, `container_name`, and `k8s_*`.
  - Config v2 `capture.rules[].match.process`: `open_ports`, `target_pids`, `language_glob`/`regex`, `cmd_args_glob`/`regex`, `exe_path_glob`/`regex`, `containers_only`, `exports_otlp`.
  - **There is no systemd unit or cgroup-path selector or attribute.** The cgroup file is parsed only to extract a container ID (source).
  - Mechanism: a `/proc` poller (`discovery.poll_interval`, effective default 5s) plus a `kprobe/sys_bind` watcher. Open ports come from gopsutil `ConnectionsPid`.
  - `min_process_age` is 5s.
  - Default exclusions: OBI/otelcol binaries and K8s system namespaces. `excluded_linux_system_paths` (`/lib/systemd/`, `/usr/lib/systemd/`, `/usr/libexec/`, `/sbin/`, `/usr/sbin/`) only skips *language detection*; those processes can still be selected.
  - Known limitation: port-based discovery can pick a helper or port-forwarder that binds the same port.
- **`OTEL_SERVICE_NAME` / `OTEL_RESOURCE_ATTRIBUTES` from the target: yes.**
  - On discovery, OBI reads `/proc/<pid>/environ` (`procs.EnvVars`, through procfs `Environ()`).
  - `OTEL_SERVICE_NAME` sets `service.name`; otherwise `service.name` from `OTEL_RESOURCE_ATTRIBUTES` is used.
  - `service.namespace` and every other key in `OTEL_RESOURCE_ATTRIBUTES` are added as resource metadata. Values starting with `$` are ignored.
  - This applies only to processes that AppO11y instruments; NetO11y and StatsO11y never use it.
  - Since v0.12.1 OBI also reads the experimental `OTEL_CTX` process-context mapping, polled every 1s (`process_context_poll_interval`).
- **`service.name` derivation order (docs):**
  1. env vars;
  2. (K8s) annotations, labels, owner;
  3. Java: Spring Boot name, JAR manifest title, or JAR name;
  4. **the executable name**.

  Explicit names in the discovery config: the v0.14.0 notes say "Target declarations still take precedence over resource metadata". In code, `ApplyEnvVariables` overwrites the selector-supplied name when `OTEL_SERVICE_NAME` is set, so the precedence should be tested.
  - Cloud inventories (ECS, Route53, GCE, Azure) can rename auto-named services.
  - `service.instance.id` / `target.instance` = `<hostname>:<pid>`.
- **Host resource attributes:**
  - `host.id`: `/etc/machine-id`, falling back to `/var/lib/dbus/machine-id`, then overridden by cloud/K8s metadata. Explicit override: `OTEL_EBPF_HOST_ID`.
  - `host.name`: the DNS FQDN of `os.Hostname()`, falling back to `hostname -f`, then `hostname`. Controls: `OTEL_EBPF_HOSTNAME_DNS_RESOLUTION` (default true) and the override `OTEL_EBPF_HOSTNAME`.
  - OTLP resources for **network and stats** metrics carry only `obi.version`, `obi.revision`, `telemetry.distro.*` and `host.id`, **not `host.name`** (source). Per-flow host identity otherwise needs the opt-in `obi.ip`.

### Cited findings
- Selector tables, default exclusions, `exclude_otel_instrumented_services` (default true), `OTEL_CTX`, the name-derivation order, the name-resolver sources. — [Service discovery](https://opentelemetry.io/docs/zero-code/obi/configure/service-discovery/)
- Config v2 match fields and policy. — [Config v2](https://opentelemetry.io/docs/zero-code/obi/configure/config-v2/)
- Environment reading. — [pkg/appolly/discover/elf_linux.go (L61)](https://github.com/open-telemetry/opentelemetry-ebpf-instrumentation/blob/v1.0.0/pkg/appolly/discover/elf_linux.go); [pkg/appolly/discover/exec/file.go (L284)](https://github.com/open-telemetry/opentelemetry-ebpf-instrumentation/blob/v1.0.0/pkg/appolly/discover/exec/file.go); [pkg/internal/procs/procenv.go](https://github.com/open-telemetry/opentelemetry-ebpf-instrumentation/blob/v1.0.0/pkg/internal/procs/procenv.go)
- Poller. — [pkg/appolly/discover/watcher_proc.go (L37, gopsutil)](https://github.com/open-telemetry/opentelemetry-ebpf-instrumentation/blob/v1.0.0/pkg/appolly/discover/watcher_proc.go); [bpf/watcher/watcher.c (`kprobe/sys_bind`)](https://github.com/open-telemetry/opentelemetry-ebpf-instrumentation/blob/v1.0.0/bpf/watcher/watcher.c)
- System paths and poll defaults. — [devdocs/config/CONFIG.md](https://github.com/open-telemetry/opentelemetry-ebpf-instrumentation/blob/v1.0.0/devdocs/config/CONFIG.md)
- Cgroup used only for the container ID. — [pkg/internal/helpers/container/container.go](https://github.com/open-telemetry/opentelemetry-ebpf-instrumentation/blob/v1.0.0/pkg/internal/helpers/container/container.go)
- Port-discovery limitation. — [TELEMETRY.md](https://github.com/open-telemetry/opentelemetry-ebpf-instrumentation/blob/v1.0.0/TELEMETRY.md); [v1.0.0 release notes](https://github.com/open-telemetry/opentelemetry-ebpf-instrumentation/releases/tag/v1.0.0)
- Host ID and name. — [pkg/metadata/meta_node_linux.go (L32–36)](https://github.com/open-telemetry/opentelemetry-ebpf-instrumentation/blob/v1.0.0/pkg/metadata/meta_node_linux.go); [pkg/metadata/meta_node.go](https://github.com/open-telemetry/opentelemetry-ebpf-instrumentation/blob/v1.0.0/pkg/metadata/meta_node.go); [pkg/internal/traces/hostname/hostname_linux.go](https://github.com/open-telemetry/opentelemetry-ebpf-instrumentation/blob/v1.0.0/pkg/internal/traces/hostname/hostname_linux.go); [pkg/config/tracescfg.go](https://github.com/open-telemetry/opentelemetry-ebpf-instrumentation/blob/v1.0.0/pkg/config/tracescfg.go)
- Network resource attributes. — [pkg/export/otel/metrics_net.go (L50)](https://github.com/open-telemetry/opentelemetry-ebpf-instrumentation/blob/v1.0.0/pkg/export/otel/metrics_net.go)

### Gaps / not documented
- No systemd or cgroup identity at all.
- The precedence between configured names and process env is ambiguous.
- `host.name` is missing from network and stats OTLP resources (only seen in source).

## 5. Listening sockets inventory and "first seen"

### Answer
- **v1.0.0: no.**
  - Listening ports exist only as internal state: the BPF `listening_ports` map (port + netns), seeded by `iter/tcp` and maintained by kprobes, and the discovery poller's port list used for `open_ports` matching.
  - Neither is exported as telemetry.
  - The internal metric `obi_instrumented_processes` (gauge by process name) is the closest inventory signal.
- **Main-only (unreleased):** peer-metadata exchange (PR #3806, 2026-10-30), disabled by default.
  - Each agent exposes `GET /v1/metadata` on port 8998, with optional bearer token and TLS.
  - The response contains `hostname`, `services`, **TCP `listeners`** (`endpoint{ip,port}` → `service`) of *selected, instrumented* services, and recent `callers`.
  - The inventory refreshes every 10s by polling live processes for listening sockets.
  - "UDP listener attribution is not supported."
  - It is bypassed when Kubernetes enrichment is on, and it is intended for agent-to-agent use, not as an export.
  - #3997 (same day) abstracts this behind an interface "for other modes of data submission/retrieval".
- **First seen:** none.
  - Flow records carry start/end monotonic timestamps internally, but only counters are exported.
  - The main-only `traces_service_graph_connection_info` gauge signals "observed recently" (TTL 15 min), which approximates *last seen*, not first seen.

### Cited findings
- [bpf/generictracer/iter_tcp.c](https://github.com/open-telemetry/opentelemetry-ebpf-instrumentation/blob/v1.0.0/bpf/generictracer/iter_tcp.c)
- [OBI docs: internal metrics table](https://opentelemetry.io/docs/zero-code/obi/metrics/)
- [main devdocs/peer-metadata.md](https://github.com/open-telemetry/opentelemetry-ebpf-instrumentation/blob/main/devdocs/peer-metadata.md) (not in v1.0.0)
- [PR #3806](https://github.com/open-telemetry/opentelemetry-ebpf-instrumentation/pull/3806); [PR #3997](https://github.com/open-telemetry/opentelemetry-ebpf-instrumentation/pull/3997)
- [main site/docs/metrics.md `traces_service_graph_connection_info`](https://github.com/open-telemetry/opentelemetry-ebpf-instrumentation/blob/main/site/docs/metrics.md)

### Gaps / not documented
- No timeline for releasing peer metadata; presumably the next minor release, but this is unconfirmed.
- No listener export for uninstrumented processes.

## 6. Hooks and overhead of the default configuration; running network and stats only

### Answer
- **Default config:** `metrics.features: ["application"]` (RED metrics plus HTTP body-size histograms). Context propagation is `disabled` by default.
  - **AppO11y is enabled only when a selector is configured**: `OTEL_EBPF_OPEN_PORT`, `OTEL_EBPF_AUTO_TARGET_EXE`, `OTEL_EBPF_AUTO_TARGET_LANGUAGE`, `discovery.instrument`, or target PIDs (`Config.Enabled(FeatureAppO11y)`).
  - With no selector, OBI only starts if network or stats features are enabled with an exporter. Otherwise validation fails with "at least one of 'network', 'application' or 'stats' features must be enabled".
- **Running only network + stats without L7:**
  - **Config v1:** `OTEL_EBPF_METRICS_FEATURES=network,stats_tcp_rtt,stats_tcp_failed_connections,stats_tcp_successful_connections,stats_tcp_retransmits` plus an exporter, and no discovery selector. AppO11y does not start.
  - **Config v2 pitfall (source):** when `capture.policy.default_action` is omitted and there are no include rules, OBI treats the policy as `include` and maps it to `exe_path: "*"`. That means AppO11y instruments every process. Set `capture.policy.default_action: exclude` with no include rules.
- **AppO11y hooks** (generic tracer; loaded only for instrumented PIDs, with in-kernel PID filtering):
  - Required kprobes: `sys_accept`/`sys_accept4`, `security_socket_accept`, `sys_connect`, `tcp_connect`, `sock_recvmsg`, `tcp_sendmsg`, `tcp_recvmsg`, `tcp_cleanup_rbuf`, `tcp_close`, `sock_def_error_report`, `udp_sendmsg`, `sys_clone`/`sys_clone3`, `sys_exit`, `unix_stream_sendmsg`/`recvmsg`, `inet_csk_listen_stop`, `sys_ioctl`, plus kretprobes.
  - Also an `iter/tcp` program and the `sched_process_exit` tracepoint.
  - Uprobes on libssl `SSL_*`, Go library symbols, nginx, Node.js, Python/asyncio and Ruby; JVM USDT.
  - `sk_msg`/`sockops` only with context propagation.
  - The discovery watcher adds `kprobe/sys_bind`.
- **NetO11y:** one socket filter (or TC programs) running on every packet.
- **StatsO11y:**
  - Low-frequency hooks: `inet_sock_set_state` tracepoint, `tcp_retransmit_skb` raw tracepoint, `tcp_close` kprobe.
  - **High-frequency:** `tcp_sendmsg` kprobe+kretprobe and `tcp_cleanup_rbuf` kprobe for `stats_tcp_io`.
  - Docs: `stats_tcp_io` "observes every TCP send and receive call and can have higher overhead". devdocs recommends enabling the stats features individually instead of `stats`. Disabled stats probes are replaced by no-op stubs before loading.
- **Overhead tuning:** `ebpf.wakeup_len` 500, `ebpf.stats_wakeup_data_bytes` 4096, `ebpf.maps_config.global_scale_factor` (−3 to 3), `high_request_volume`, `traffic_control_backend`.
  - The **docs publish no quantitative overhead numbers**; they only say "minimal overhead".
  - SUPPORT_MATRIX warns that Redis tracing "can materially increase Redis CPU usage at high request rates".

### Cited findings
- [Export data → metrics export features](https://opentelemetry.io/docs/zero-code/obi/configure/export-data/)
- [Tune performance](https://opentelemetry.io/docs/zero-code/obi/configure/tune-performance/)
- [pkg/obi/config.go (`Enabled` L1058; `ContextPropagation` default L136)](https://github.com/open-telemetry/opentelemetry-ebpf-instrumentation/blob/v1.0.0/pkg/obi/config.go)
- [internal/config/convert/import.go (`applyV2Rules` L346, `effectiveV2CapturePolicy` L460)](https://github.com/open-telemetry/opentelemetry-ebpf-instrumentation/blob/v1.0.0/internal/config/convert/import.go)
- [pkg/internal/ebpf/generictracer/generictracer.go (`KProbes`)](https://github.com/open-telemetry/opentelemetry-ebpf-instrumentation/blob/v1.0.0/pkg/internal/ebpf/generictracer/generictracer.go)
- [devdocs/metrics.md → performance considerations](https://github.com/open-telemetry/opentelemetry-ebpf-instrumentation/blob/v1.0.0/devdocs/metrics.md)
- [SUPPORT_MATRIX.md](https://github.com/open-telemetry/opentelemetry-ebpf-instrumentation/blob/v1.0.0/SUPPORT_MATRIX.md)

### Gaps / not documented
- No benchmark figures.
- The Config v2 default-include behavior when no rules are given is documented only as "If you omit `default_action`, OBI includes workloads by default". Its consequence for network-only deployments is not spelled out.

## 7. Deployment on RHEL-family hosts (Rocky Linux 9, kernel 5.14)

### Answer
- **Kernel:**
  - **Linux 5.8+**, or RHEL-family **4.18+** "with the required eBPF backports". The code recognizes `rhel`, `centos`, `rocky` and `alma` via `/etc/os-release` or `.elN` in `/proc/version`.
  - Rocky 9 (5.14) passes the general check.
  - CI verifier coverage includes **RHEL 8.9, 8.10 and 9.6**; VM integration tests run on 5.15, 6.18 and 7.2.
  - Network-level context-propagation header parsing needs 5.17 (BPF loops), "Some patched kernels, such as RHEL 9.2, may have this functionality ported back" (`OTEL_EBPF_OVERRIDE_BPF_LOOP_ENABLED`). This is irrelevant to network and stats.
  - Kernel lockdown `integrity` (Secure Boot) blocks `bpf_probe_write_user`, which only affects Go library-level propagation and the Go Auto SDK.
- **BTF:** required. OBI checks `/sys/kernel/btf/vmlinux` and the libbpf fallback paths, and refuses to start without BTF. RHEL 9 kernels ship BTF (general knowledge, not from OBI docs).
- **Capabilities:**
  - Root or `CAP_SYS_ADMIN` covers everything. `OTEL_EBPF_ENFORCE_SYS_CAPS=true` fails fast when capabilities are missing.
  - Socket-filter network: `CAP_BPF`, `CAP_NET_RAW` (the code also checks `CAP_PERFMON`).
  - TC network: `CAP_BPF`, `CAP_NET_ADMIN`, `CAP_PERFMON`.
  - Stats (code): `CAP_BPF`, `CAP_SYS_PTRACE`, `CAP_PERFMON`, `CAP_NET_RAW`.
  - AppO11y: `CAP_BPF`, `CAP_DAC_READ_SEARCH`, `CAP_CHECKPOINT_RESTORE`, `CAP_PERFMON`, `CAP_NET_RAW`, `CAP_SYS_PTRACE` (+ `CAP_NET_ADMIN` for propagation).
  - `CAP_SYS_RESOURCE` is needed only below kernel 5.11.
  - Since v0.14.0, OBI falls back to tracefs for kprobes and uprobes when `perf_event_paranoid` blocks PMU access.
- **SELinux:** **not mentioned anywhere** in OBI docs or devdocs.
- **Packaging:**
  - Release tarballs `obi-v<ver>-linux-{amd64,arm64}.tar.gz` with `SHA256SUMS`, CycloneDX SBOMs and Cosign signatures.
  - Container image `otel/ebpf-instrument:v<ver>`, run with `--privileged --pid=host` or the listed capabilities. Host networking is needed for host-level NetO11y (inference; the K8s quickstart uses `hostNetwork: true`).
  - **No RPM or deb packages** are documented or published.
  - The repo contains a template unit **`contrib/obi@.service`**: `ExecStart=/usr/local/bin/obi --config=/etc/obi/%i.yaml`, `EnvironmentFile=/etc/obi/%i.env`, `User=root`. It is not referenced by the user docs.
  - The Java agent is embedded and extracted to `$XDG_CACHE_HOME/obi/java`; set `XDG_CACHE_HOME` for service deployments.
- **Configuration:**
  - YAML via `--config` or `OTEL_EBPF_CONFIG_PATH`, plus env vars (`OTEL_EBPF_*`, standard `OTEL_EXPORTER_OTLP_*`).
  - **Config v2** (`file_format: "1.0"` + `extensions.obi` with `version: "2.0"`, using OTel declarative `meter_provider`/`tracer_provider`) is the v1.0 compatibility contract.
  - Config v1 is "frozen" and gets no fixes. Use `obi config validate` and `obi config migrate`.

### Cited findings
- [OBI docs index → compatibility](https://opentelemetry.io/docs/zero-code/obi/)
- [SUPPORT_MATRIX.md (runtime requirements, L37, verifier coverage L65)](https://github.com/open-telemetry/opentelemetry-ebpf-instrumentation/blob/v1.0.0/SUPPORT_MATRIX.md)
- [pkg/obi/os.go (`rhelIDs` L30, `checkOSSupport` L105, capability sets L174–206)](https://github.com/open-telemetry/opentelemetry-ebpf-instrumentation/blob/v1.0.0/pkg/obi/os.go)
- [Security, permissions and capabilities](https://opentelemetry.io/docs/zero-code/obi/security/)
- [Distributed traces → kernel and lockdown limitations](https://opentelemetry.io/docs/zero-code/obi/distributed-traces/)
- [Standalone setup](https://opentelemetry.io/docs/zero-code/obi/setup/standalone/)
- [Docker setup](https://opentelemetry.io/docs/zero-code/obi/setup/docker/)
- [contrib/obi@.service](https://github.com/open-telemetry/opentelemetry-ebpf-instrumentation/blob/v1.0.0/contrib/obi@.service)
- [v1.0.0 release notes](https://github.com/open-telemetry/opentelemetry-ebpf-instrumentation/releases/tag/v1.0.0)
- [OBI v1.0.0 blog](https://opentelemetry.io/blog/2026/obi-v1-release/)

### Gaps / not documented
- No SELinux guidance.
- No RPM.
- No hardened systemd unit (it runs as root, with no `AmbientCapabilities`).
- No RHEL 9-specific notes beyond verifier coverage.

## 8. Output options

### Answer
- **OTLP metrics:**
  - Endpoint: `otel_metrics_export.endpoint` / `OTEL_EXPORTER_OTLP_METRICS_ENDPOINT` (or `OTEL_EXPORTER_OTLP_ENDPOINT`). HTTP(S), gRPC and Unix sockets are supported.
  - Protocol: inferred from the port, or set with `*_PROTOCOL`.
  - `interval` 60s; histogram aggregation `explicit_bucket_histogram` or base2 exponential.
  - Since v0.11.0, OTLP names use dot notation.
- **OTLP traces:** `otel_traces_export` / `OTEL_EXPORTER_OTLP_TRACES_ENDPOINT`.
- **Prometheus:** `prometheus_export.port` / `OTEL_EBPF_PROMETHEUS_PORT` (no endpoint when unset), `path` `/metrics`, `ttl` 5m.
  - Prometheus names are derived from the OTLP names with the upstream translator: `obi_network_flow_bytes_total`, `obi_stat_tcp_rtt_seconds`, `obi_stat_tcp_failed_connections_total`, `obi_stat_tcp_retransmits_total`, `obi_stat_tcp_io_bytes_total`, `traces_service_graph_*`.
  - Internal metrics come from a separate reporter.
- **Attribute selection:** `attributes.select.<metric>.include/exclude`.
  - Metric names may use OTel or Prometheus form and support wildcards (`http_*`); globs are allowed in attribute names; an exact metric match wins over a wildcard.
  - Special keys: `resource` (filters OTLP resources and `target_info`) and `traces` (opt-in span attributes such as `service.peer.name`).
  - An `include` list **replaces** the defaults.
  - Service-graph and span metrics do **not** support attribute selection.
- **Collector receiver** (`go.opentelemetry.io/obi/collector`, component type `obi`):
  - Runs OBI inside a custom Collector built with **OCB** (Go 1.26+). The build needs a **local OBI checkout** and `make docker-generate` for the BPF bindings, plus `replaces:` for both modules.
  - Version `collector/v0.15.2` pairs with core v1.0.0 and stays on a separate v0 line.
  - Stability **alpha** for traces, metrics and logs (`component.StabilityLevelAlpha`).
  - Accepts Config v1 or v2 bodies, including `metrics.features: [network, …]`.
  - Documented limitations: single node only (local processes), privileged access, Linux only, Collector restart on config change.
  - No prebuilt distribution is documented.
- **Embedding as a Go library (relevant if shawk vendored OBI):**
  - `instrumenter.Run(ctx, cfg, opts...)` with `OverrideAppExportQueue(*msg.Queue[[]request.Span])` (public types) and `WithDynamicSelector`. See `examples/vendoring` and `examples/dynamicselector-host`.
  - The network and stats override queues (`OverrideNetExportQueue`, `OverrideStatsExportQueue`) use types from `pkg/internal/...`, so **external modules cannot consume raw flow or stat records**; only spans are reachable (source/inference).

### Cited findings
- [Export data](https://opentelemetry.io/docs/zero-code/obi/configure/export-data/)
- [Metrics and traces attributes](https://opentelemetry.io/docs/zero-code/obi/configure/metrics-traces-attributes/)
- [TELEMETRY.md → Exporters](https://github.com/open-telemetry/opentelemetry-ebpf-instrumentation/blob/v1.0.0/TELEMETRY.md)
- [Collector receiver](https://opentelemetry.io/docs/zero-code/obi/configure/collector-receiver/)
- [collector/factory.go (L30–32)](https://github.com/open-telemetry/opentelemetry-ebpf-instrumentation/blob/v1.0.0/collector/factory.go)
- [VERSIONING.md → Release scope](https://github.com/open-telemetry/opentelemetry-ebpf-instrumentation/blob/v1.0.0/VERSIONING.md)
- [pkg/instrumenter/opts.go (L26, L38)](https://github.com/open-telemetry/opentelemetry-ebpf-instrumentation/blob/v1.0.0/pkg/instrumenter/opts.go)
- [pkg/pipe/global/context.go (L61, L67)](https://github.com/open-telemetry/opentelemetry-ebpf-instrumentation/blob/v1.0.0/pkg/pipe/global/context.go)
- [examples/dynamicselector-host/main.go](https://github.com/open-telemetry/opentelemetry-ebpf-instrumentation/blob/v1.0.0/examples/dynamicselector-host/main.go)

### Gaps / not documented
- No guidance on mapping OBI metrics into a relational edge store.
- No prebuilt `otelcol` distribution with the OBI receiver.

---

## Fit for shawk

| shawk need | OBI v1.0.0 | Notes |
|---|---|---|
| TCP edges attributed to **client and server processes** (connect-context client, accepted-socket cgroup → listener holder) | **Not covered** at L4 | NetO11y and StatsO11y are host-level by design. AppO11y attributes edges only for *recognized L7 protocols*, only for *selected* processes, and by service name, not cgroup or unit. |
| UDP per-socket client/server direction per process | **Not covered** | NetO11y UDP is host-level with direction `unknown`; AppO11y covers DNS client only. |
| Aggregation key dropping the ephemeral port (`direction, proto, local, remote, service port, netns, cgroup, comm`) | **Partial** | NetO11y can aggregate by `src/dst.address` + `server.port` + `transport` when the SYN was seen. There is no netns, cgroup or comm. Stats has no `server.port`. |
| Counts: connections / failed connects | **Partial** | `successful.connections` (v0.14.0+) and `failed.connections` with `reason`. Both are host-level, and failed also includes aborted established connections. |
| Open connections, periodic (15 s) accounting of long-lived connections, adopting pre-existing connections | **Not covered** | No socket-iterator accounting. RTT arrives only at close; IO is per send/recv. |
| Bytes, retransmits, SRTT | **Partial** | Wire bytes from NetO11y, socket bytes from `stats_tcp_io` (costly), retransmits, and an SRTT histogram at close. All by address, not process. |
| Listening-socket inventory | **Not covered** (main-only peer-metadata API: TCP listeners of instrumented services only, unreleased) | |
| `first_seen` / `last_seen` relations to PostgreSQL | **Not covered** | Metrics only. The main-only `connection_info` gauge approximates "recently seen". |
| Identity from `OTEL_SERVICE_NAME` / `OTEL_RESOURCE_ATTRIBUTES` in `/proc/PID/environ` | **Covered** for AppO11y-instrumented processes | Matches shawk's planned design; falls back to the executable name. |
| systemd unit / cgroup path identity | **Not covered** | |
| host.id / host.name | **Covered** | machine-id and FQDN; `host.name` is absent from network/stats OTLP resources. |
| Service-level metrics via OTLP → Prometheus → Grafana | **Covered** | Service graph metrics are servicegraphconnector-compatible and development-stability. Uninstrumented peers become `virtual_node` nodes named `outgoing`/`incoming` unless renaming is disabled or DNS resolves them. |
| L7 RED and traces (HTTP, gRPC, SQL, Redis, Kafka…) | **Covered** (shawk has none today) | |
| RHEL 9 deployment | **Partial** | Kernel and BTF are OK, RHEL 9.6 is CI-verified. Distribution is a tarball plus a contrib systemd template; no RPM and no SELinux notes. |
| Use as a library / stable surface | **Partial** | Go embedding works for spans only; net/stats records are internal types. Network, stats and service-graph telemetry is `development`, outside the v1 contract. The receiver is alpha. |

**Bottom line:** OBI v1.0.0 cannot replace shawk's process-attributed L4 tracer. StatsO11y deliberately avoids PID attribution, and NetO11y has no process context. The realistic options are:

- run OBI **alongside** shawk for L7 RED, traces and service-graph edges, reusing the same `OTEL_SERVICE_NAME` identity convention; or
- propose upstream changes. Per-cgroup attribution in StatsO11y would run against its documented design stance. The main-only peer-metadata work, an inventory of instrumented-service TCP listeners exchanged between agents, is the closest upstream direction to shawk's listener-based server attribution.
