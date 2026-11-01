# Flow-oriented eBPF network observability pipelines (Hubble/Timescape, Retina, NetObserv, opentelemetry-network, Datadog CNM): architecture and design decisions, compared with shawk

Research date: 2026-10-31. Versions seen: Cilium docs "stable" = **Cilium 1.20.4**; Isovalent Networking for Kubernetes / Timescape **1.18** (blog dated 2025-12-03); NetObserv operator `main` docs (health rules, FlowCollector v1beta2); Retina docs (copyright 2026); Datadog docs as of fetch date. The GitHub API was not reachable from this environment, so release numbers and dates for Retina, NetObserv and Datadog Agent are not confirmed.

---

## Q0. End-to-end pipeline for each tool (kernel → agent → central → storage → UI)

### Takeaway
All five tools follow the same pattern: an eBPF node agent, an optional central stage, Prometheus-style metrics for aggregates, and a separate (often optional) store for per-flow records. They differ in where they hook (TC packet path for Hubble, Retina and NetObserv; socket and connection kprobes for opentelemetry-network and Datadog) and in where the central stage sits (Hubble Relay only fans in queries, the opentelemetry-network reducer does stateful matching, flowlogs-pipeline enriches, aggregates and tracks conversations).

### Cited Findings
**Cilium Hubble (OSS) + Isovalent Timescape (enterprise)**
- The Hubble server is embedded in cilium-agent "in order to achieve high performance with low-overhead". It registers a listener on Cilium's event monitor and stores events in a user-space, lock-free ring buffer of configurable size. When the buffer is full, the oldest events are overwritten. The docs mention no persistence. — [Cilium docs: Hubble internals](https://docs.cilium.io/en/stable/internals/hubble/)
- The Hubble API runs per node and by default only sees traffic the local agent observes. The `hubble` CLI queries it over a Unix socket. Hubble Relay extends visibility to the cluster or ClusterMesh. — [Cilium docs: Hubble overview](https://docs.cilium.io/en/stable/observability/hubble/index.html)
- Relay uses the Peer service to discover Hubble instances, keeps a persistent connection to each (port 4244, mTLS when exposed over TCP), and implements the same Observer API (`GetFlows`, `GetNodes`, …) cluster-wide for UI and CLI. Relay was a tech preview in v1.8 and stable in v1.9. — [Cilium docs: Hubble internals](https://docs.cilium.io/en/stable/internals/hubble/)
- Hubble metrics are produced by the Hubble instance inside cilium-agent and scraped on port 9965. All metric families are disabled by default. — [Cilium 1.20.4 docs: Monitoring & Metrics](https://docs.cilium.io/en/stable/observability/metrics/)
- Hubble Exporter (inside cilium-agent) writes flows to a file (default `/var/run/cilium/hubble/events.log`) or stdout, for an external log shipper. It has a static mode (restart to change) and a dynamic mode (several named flow logs, each with its own filters and an optional `end` time; changes apply in about 60 s). — [Cilium docs: Hubble exporter](https://docs.cilium.io/en/stable/observability/hubble/configuration/export/)
- Timescape (enterprise) ingestion paths: (1) exported files written to object storage and pulled by the Timescape Ingester; (2) a Push API over HTTP; (3) from Timescape 1.18, a gRPC **Stream API**: "the Cilium agent talks directly to Timescape over gRPC… no need for object storage or an intermediate REST server". It is the default for "Integrated Timescape" and available in "Timescape Lite". Isovalent says the older paths need "a component to export the log files and some delay", and that JSON conversion is "a resource costly exercise". — [Isovalent blog, INK 1.18 (2025-12-03)](https://isovalent.com/blog/post/isovalent-networking-for-kubernetes-118-new-routing-policy-and-observability-enhancements/)
- Timescape deployment models: "Integrated Timescape" is enabled through the Cilium Helm chart and stays "compatible with the Hubble API and CLI"; a standalone Helm chart offers full customization. Isovalent describes the options as covering "different scale and retention configurations". — [Isovalent blog, INK 1.18](https://isovalent.com/blog/post/isovalent-networking-for-kubernetes-118-new-routing-policy-and-observability-enhancements/)

**Microsoft Retina**
- eBPF plugins hook kernel events, convert data into Cilium-defined `flow` objects, enrich them with Kubernetes context, and convert them to metrics. There are two control planes. (a) The **Hubble control plane** (Linux only): plugins feed the Cilium monitor agent and Hubble observer, which enriches flows with Cilium libraries and serves `hubble_*` metrics on 9965, a Relay endpoint on 4244 and a local socket. (b) The **standard control plane** (Windows and Linux): Retina's own Enricher uses a Kubernetes object cache, writes to an output ring, and a Metrics Module exports. — [Retina docs: Architecture](https://retina.sh/docs/Introduction/architecture)
- Plugins: Linux has ciliumEventObserver, dns, dropreason, infiniband, linuxutil, packetforward, packetparser and tcpretrans. Windows has hnsstats. — [Retina docs: packetparser](https://retina.sh/docs/Metrics/plugins/Linux/packetparser)
- Packet captures can be requested through the `kubectl retina` CLI or a Capture CRD (with the operator). — [GitHub microsoft/retina](https://github.com/microsoft/retina)

**Red Hat NetObserv (Network Observability Operator)**
- eBPF agent (DaemonSet): attaches to host interfaces, captures ingress and egress packets, aggregates them into flows and exports them periodically. **flowlogs-pipeline (FLP)**: enriches flows with Kubernetes informers (pod, namespace, zone), turns flows into Prometheus counters, and optionally writes raw flows to Loki or exports them to Kafka, IPFIX or OpenTelemetry. **Console plugin**: metrics overview, topology and a flow table. **Operator**: CRDs FlowCollector, FlowCollectorSlice (per-tenant) and FlowMetrics. — [NetObserv Architecture.md](https://github.com/netobserv/network-observability-operator/blob/main/docs/Architecture.md)
- Deployment models: **Service** (default; FLP Deployment behind a Service), **Direct** (FLP as a per-node DaemonSet; "only recommended on small clusters, below 15 nodes", "less memory efficient" because each FLP caches the same cluster info), **Kafka** (agents → Kafka → FLP consumers; "better scalability, resiliency, and high availability"). — [FlowCollector API reference](https://github.com/netobserv/network-observability-operator/blob/main/docs/FlowCollector.md); [Architecture.md](https://github.com/netobserv/network-observability-operator/blob/main/docs/Architecture.md)
- The agent's export protocol can be `grpc` (default), `kafka`, `ipfix+udp`, `ipfix+tcp` or `direct-flp`, which embeds flowlogs-pipeline in the agent. — [netobserv-ebpf-agent config.md](https://github.com/netobserv/netobserv-ebpf-agent/blob/main/docs/config.md)
- Loki, Prometheus and Kafka are not managed by the operator and must be installed separately. — [Architecture.md](https://github.com/netobserv/network-observability-operator/blob/main/docs/Architecture.md)

**opentelemetry-network (formerly Flowmill)**
- The kernel collector (eBPF, one per node) gathers low-level telemetry "with negligible compute and network overheads". The k8s collector and cloud collector gather workload metadata. The **reducer** receives telemetry, enriches and aggregates it, and outputs metrics. — [opentelemetry-network README](https://github.com/open-telemetry/opentelemetry-network); [kernel-collector.md](https://github.com/open-telemetry/opentelemetry-network/blob/main/docs/kernel-collector.md)
- The reducer has three sharded stages: **ingest → matching → aggregation** (`--num-ingest-shards`, `--num-matching-shards`, `--num-aggregation-shards`). Collectors connect on TCP port 8000. Output is Prometheus by default (127.0.0.1:7010) or OTLP gRPC (`--enable-otlp-grpc-metrics`, port 4317, `--disable-prometheus-metrics`). Scaling is "a manual trial-and-error process". — [reducer.md](https://github.com/open-telemetry/opentelemetry-network/blob/main/docs/reducer.md)

**Datadog Cloud Network Monitoring (CNM, formerly NPM)**
- "Connection data at the IP, port, and PID levels is aggregated into application-layer dependencies between client and server endpoints", which are shown on a network page and a network map. — [Datadog CNM overview](https://docs.datadoghq.com/network_monitoring/cloud_network_monitoring/)
- Linux uses eBPF in system-probe (enabled with `network_config.enabled: true` in `system-probe.yaml`). Windows uses a network kernel driver. — [Datadog CNM setup](https://docs.datadoghq.com/network_monitoring/cloud_network_monitoring/setup/)
- "Data is collected every 30 seconds, aggregated into five-minute buckets, and retained for 14 days." — [Datadog Network Analytics](https://docs.datadoghq.com/network_monitoring/cloud_network_monitoring/network_analytics/)

### Inferences
- shawk's split (relations in PostgreSQL every 1–5 min, metrics via OTLP every 15 s) matches the industry pattern of "aggregates in a TSDB, entity and flow detail elsewhere". shawk's relation store is an aggregated, deduplicated edge table rather than a raw-flow log, which puts it closer to Timescape's 1.18 "connection logs" (see Q4) than to Loki-style flow logs.
- shawk has no central stateful stage: agents write straight to PostgreSQL and the OTel Collector. Among the five tools, only opentelemetry-network has a central stage that matches the two ends of a connection (Q1).

### Gaps
- Timescape's storage backend (widely assumed to be ClickHouse) could not be confirmed from a primary source. The Isovalent feature page and "Hubble for the Enterprise" post are JS-rendered and returned no body text.
- Release numbers and dates for Retina and NetObserv could not be retrieved (GitHub API blocked).

---

## Q1. Collection: hooks, per-packet vs per-connection cost, sampling, in-kernel aggregation, export interval

### Takeaway
Hubble, Retina and NetObserv observe **packets** on the TC path. To control cost they each use a different in-kernel reduction: Cilium monitor aggregation, Retina's conntrack-style periodic reports plus sampling, and NetObserv's per-CPU hash-map flow aggregation with 1:50 sampling by default. opentelemetry-network and Datadog observe **sockets and connections** with kprobes or fentry, which is the model closest to shawk. shawk's design (state-change tracepoint plus socket iterators, no send/recv hooks) is lighter than all of them. The cost is that byte counts must be sampled from socket state rather than counted per packet.

### Cited Findings
**Hubble / Cilium**
- Flows come from Cilium datapath monitor notifications. `bpf.monitorAggregation` (none/low/**medium** default/maximum) sets the "level of aggregation for monitor notifications". `bpf.monitorFlags` ("all") sets which TCP flags trigger a notification "when seen for the first time in a connection". `bpf.monitorInterval` ("5s") is "the typical time between monitor notifications for active connections". — [Cilium 1.20.4 Helm reference](https://docs.cilium.io/en/stable/helm-reference/)
- `lost_events_total` reports loss at three points: `perf_event_ring_buffer`, `observer_events_queue` and `hubble_ring_buffer`. This shows the kernel → perf ring → observer queue → in-memory ring path. — [Cilium docs: Metrics](https://docs.cilium.io/en/stable/observability/metrics/)

**Retina packetparser**
- packetparser attaches a `clsact` qdisc to every pod veth and the host's default interface, with eBPF filters on ingress and egress. Each event becomes an enriched `Flow`. — [Retina docs: packetparser](https://retina.sh/docs/Metrics/plugins/Linux/packetparser)
- At the `high` data-aggregation level, `dataSamplingRate` reports 1 in N routine packets. TCP control packets (SYN/FIN/RST), connection eviction, and the first packet after `conntrackReportInterval` (default **30 s**, per direction) are always reported. Byte and packet totals are aggregated in the kernel and carried on the next reported event. — [Retina docs: packetparser](https://retina.sh/docs/Metrics/plugins/Linux/packetparser)
- The default kernel→user transport is `BPF_MAP_TYPE_PERF_EVENT_ARRAY` (per-CPU buffers read by one thread), which "may scale poorly on high-core-count" systems. `BPF_MAP_TYPE_RINGBUF` is an option on kernel 5.8+. Users have reported degradation on nodes with 32+ cores. — [Retina docs: packetparser](https://retina.sh/docs/Metrics/plugins/Linux/packetparser); [GitHub microsoft/retina](https://github.com/microsoft/retina)

**NetObserv eBPF agent**
- In flow mode, TC/TCX (and netkit) hooks feed `bpf/flows/flows.c`, which writes into the `aggregated_flows` map. A separate packet-capture mode writes every packet to a ring buffer. — [agent architecture.md](https://github.com/netobserv/netobserv-ebpf-agent/blob/main/docs/architecture.md)
- v2 design: a **per-CPU hash map**. Each packet looks up the flow and updates packet count, byte count and timestamps, or creates the entry. If the map is full, the record goes to user space through a ring buffer, which triggers an immediate eviction. Every `CACHE_ACTIVE_TIMEOUT` user space reads and clears the whole map. Stated rationale: the v1 ring-buffer-per-packet design "creates a bottleneck and record loss" and keeps user space busy with per-packet callbacks. — [ebpf_implementation.md](https://github.com/netobserv/netobserv-ebpf-agent/blob/main/docs/ebpf_implementation.md)
- Operator defaults: `sampling: 50` (1 packet in 50; 0 or 1 = all), `cacheActiveTimeout: 15s`, `cacheMaxFlows: 120000`. The docs note that raising these "can decrease the network traffic overhead and the CPU load" at the cost of memory and latency. Per-rule sampling can override the global value in `flowFilter`. — [FlowCollector API reference](https://github.com/netobserv/network-observability-operator/blob/main/docs/FlowCollector.md). Standalone agent defaults differ: `CACHE_ACTIVE_TIMEOUT=5s`, `CACHE_MAX_FLOWS=5000`, sampling disabled. — [agent config.md](https://github.com/netobserv/netobserv-ebpf-agent/blob/main/docs/config.md)
- Optional features: `PacketDrop`, `DNSTracking`, `FlowRTT` ("flow latency (sRTT) extraction… from TCP traffic"), `NetworkEvents` (policy correlation; requires OVN-Kubernetes), `PacketTranslation` (Service NAT), `UDNMapping`, `IPSec`, `TLSTracking`, `EbpfManager`. Several require a privileged agent. — [FlowCollector API reference](https://github.com/netobserv/network-observability-operator/blob/main/docs/FlowCollector.md)

**opentelemetry-network kernel collector** (socket and connection level)
- The BPF source attaches kprobes and kretprobes including: `tcp_init_sock`, `tcp_connect`, `inet_csk_accept`, `inet_csk_listen_start`, `inet_release`, `security_sk_free`, `tcp_rcv_established`, `tcp_event_data_recv`, `tcp_rtt_estimator`, `tcp_retransmit_timer`, `tcp_reset`, `tcp_send_active_reset`, `tcp_syn_ack_timeout`; UDP `udp_send_skb`, `udp_v6_send_skb`, `ip_send_skb`, `ip6_send_skb`, `skb_consume_udp`, `udp_v4/v6_get_port`; **existing-socket enumeration via `tcp4_seq_show`, `tcp6_seq_show`, `udp4_seq_show`, `udp6_seq_show`**; process and cgroup tracking (`wake_up_new_task`, `__set_task_comm`, `taskstats_exit`, `cgroup_*`); and conntrack (`__nf_conntrack_confirm`, `nf_ct_delete`, `ctnetlink_dump_tuples`). — [render_bpf.c](https://github.com/open-telemetry/opentelemetry-network/blob/main/collector/kernel/bpf_src/render_bpf.c)
- Historically the collector compiled eBPF on the node, using kernel headers fetched through the host package manager. The roadmap lists CO-RE support so that deployments have "fewer failure modes and cost: there is no header fetching and on-node compilation". Current code uses `BPF_CORE_READ`. — [kernel-collector.md](https://github.com/open-telemetry/opentelemetry-network/blob/main/docs/kernel-collector.md); [roadmap.md](https://github.com/open-telemetry/opentelemetry-network/blob/main/docs/roadmap.md); [render_bpf.c](https://github.com/open-telemetry/opentelemetry-network/blob/main/collector/kernel/bpf_src/render_bpf.c)
- SELinux: running in a container under the `spc_t` domain needs a custom policy module that allows `bpf {map_create map_read map_write prog_load prog_run}`. This applies to Rocky/RHEL. — [kernel-collector.md](https://github.com/open-telemetry/opentelemetry-network/blob/main/docs/kernel-collector.md)

**Datadog system-probe**
- system-probe has an fentry-based tracer and a kprobe-based tracer. PR #59165 adds an automatic fallback from fentry to kprobe when fentry fails to load. — [datadog-agent PR #59165](https://github.com/DataDog/datadog-agent/pull/59165)
- Agent 7.60.0 deprecated the prebuilt eBPF network tracer on newer kernels in favour of CO-RE and runtime compilation (`allow_prebuilt_fallback` keeps it). — [datadog-agent 7.60.0 release](https://github.com/DataDog/datadog-agent/releases/tag/7.60.0)
- On SELinux systems a policy module may be needed. The CentOS RPM bundles one. — [Datadog CNM setup](https://docs.datadoghq.com/network_monitoring/cloud_network_monitoring/setup/)
- "Failed Connections" (TCP resets, refusals, timeouts) is on by default from Agent 7.59. Mixed Agent versions lead to under-reporting. — [Datadog CNM setup](https://docs.datadoghq.com/network_monitoring/cloud_network_monitoring/setup/)
- Metrics per connection: volume and throughput, established and closed connections, TCP latency (smoothed RTT), jitter (RTT variance), retransmits, resets, timeouts, refusals, connection cancels (7.70+), host and network unreachable (7.68+). — [Datadog Network Analytics](https://docs.datadoghq.com/network_monitoring/cloud_network_monitoring/network_analytics/)

### Inferences
- opentelemetry-network's use of `tcp*_seq_show` and `udp*_seq_show` to enumerate sockets that already exist at startup is the predecessor of shawk's socket-iterator approach. Its use of `tcp_rcv_established`, `tcp_event_data_recv` and `tcp_rtt_estimator` puts work on the per-segment receive path, which shawk deliberately avoids.
- Datadog's metric set (established/closed, resets, timeouts, refusals, RTT, jitter, retransmits) is almost a superset of shawk's (connections, failed connects, open, bytes, retransmits, RTT). shawk could split "failed connects" into reset, refused and timeout, as Datadog does.
- Export cadence across the field: NetObserv 15 s (operator default), Cilium monitor 5 s for active connections, Retina 30 s report interval, Datadog 30 s collection with 5-min buckets. shawk's 15 s is in line.
- The packet-level tools need sampling (NetObserv 1:50 by default), which makes byte and packet counters estimates. shawk's socket-state counters are exact, but shawk sees nothing below the socket layer (drops, interface-level traffic).

### Gaps
- Exact Datadog kprobe and fentry attach points and the in-agent connection map structure were not confirmed from a primary source (the `pkg/network` README returned 404).
- Exact NetObserv hooks for FlowRTT, PacketDrop, DNS and PacketTranslation (for example fentry `tcp_rcv_established` or tracepoint `skb/kfree_skb`) were not confirmed. The implementation doc does not cover them.
- Default Hubble ring-buffer capacity is not stated on the pages fetched. A default of 4095 events is recalled but not verified.

---

## Q2. Aggregation stages and central matching / deduplication of two-sided observations

### Takeaway
Only opentelemetry-network's reducer explicitly **matches both ends of a connection** into one flow span and lets **only one side update metrics "to avoid double counting"**. NetObserv deduplicates at the agent (same packet seen on several interfaces) and can build bidirectional "conversations" in flowlogs-pipeline's conntrack stage. Datadog defines client = connection initiator and measures from the client side when available, falling back to the server side. Hubble Relay only merges streams for queries and does no deduplication.

### Cited Findings
- **opentelemetry-network reducer matching:** `FlowSpan` holds two-element arrays (side A/B) of `agent_info`, `task_info` (comm, cgroup), `socket_info` (local and remote addr/port, `is_connector`, `remote_dns_name`), `k8s_info`, `container_info` and `service_info`. A comment on `metrics_update_side_` reads: "Side of the flow that will update metrics. Only one side will do that, to avoid double counting." The resolved per-side `NodeData` (id, az, role, version, env, ns, address, comm, container, pod) is sent to aggregation roots. — [reducer/matching/flow_span.h](https://github.com/open-telemetry/opentelemetry-network/blob/main/reducer/matching/flow_span.h)
- Reducer stages are ingest → matching → aggregation, each sharded. The docs say "each shard uses memory even when lightly loaded". — [reducer.md](https://github.com/open-telemetry/opentelemetry-network/blob/main/docs/reducer.md)
- **NetObserv agent dedup:** `DEDUPER=firstCome` "forwards only flows from the first interface they arrive on", which handles duplicates across physical and virtual interfaces. `DEDUPER_JUST_MARK` marks duplicates instead of dropping them. — [agent config.md](https://github.com/netobserv/netobserv-ebpf-agent/blob/main/docs/config.md). In the operator, `processor.deduper` can "sample or drop flows identified as duplicates". — [FlowCollector API](https://github.com/netobserv/network-observability-operator/blob/main/docs/FlowCollector.md)
- **flowlogs-pipeline conntrack stage:** the connection hash can use `fieldGroupARef` and `fieldGroupBRef` "for bidirectional matching, so flows in both directions map to one connection". Outputs are `newConnection`, `heartbeat`, `endConnection` and `flowLog` records, with per-field `sum`/`count`/`min`/`max`/`first`/`last` and optional `splitAB` A→B and B→A fields. TCP FIN detection ends a connection. `swapAB` handles a first flow that carries SYN_ACK. `maxConnectionsTracked` sets a cap. — [FLP api.md](https://github.com/netobserv/flowlogs-pipeline/blob/main/docs/api.md)
- Operator exposure: `processor.logTypes` = `Flows` (default), `Conversations`, `EndedConversations` or `All`. In the conversation modes "Prometheus metrics are not accurate on long-standing conversations", and `All` is "not recommended due to the impact on resources footprint". Defaults: `conversationEndTimeout` 10 s, `conversationHeartbeatInterval` 30 s, `conversationTerminatingTimeout` 5 s. — [FlowCollector API](https://github.com/netobserv/network-observability-operator/blob/main/docs/FlowCollector.md)
- FLP also has `reinterpret_direction`, which reinterprets flow direction at the node level using reporter IP and source/destination host fields. — [FLP api.md](https://github.com/netobserv/flowlogs-pipeline/blob/main/docs/api.md)
- **Datadog:** "The client is the side that initiates a connection, and the server is the side that responds… Datadog monitors traffic based on who opened the connection". Reverse-direction traffic is a separate flow. "Metrics are measured from the client side when available, otherwise from the server side." The default UI aggregation is service-to-service, with rows aggregated over one hour. — [Datadog Network Analytics](https://docs.datadoghq.com/network_monitoring/cloud_network_monitoring/network_analytics/)
- **Hubble Relay** keeps persistent connections to every node's Hubble server and implements the Observer service cluster-wide. Its docs do not describe merge, sort or dedup semantics. — [Cilium docs: Hubble internals](https://docs.cilium.io/en/stable/internals/hubble/)

### Inferences
- shawk stores outbound records on the client host and inbound records on the server host for the same service edge. Without a matching stage, `sum by (service, peer_service)` across hosts double-counts bytes and connections whenever both ends run shawk. Two options in the prior art:
  - Datadog's rule (count from the client side; use server-side data only when the client is not instrumented) can be done in PromQL or SQL views using the `direction` label plus "is the peer instrumented?" knowledge from the PostgreSQL host↔address table.
  - opentelemetry-network's rule (designate one side per span) needs a central stateful matcher, which shawk does not have.
- Because shawk drops the client ephemeral port, it cannot do 5-tuple matching like the opentelemetry-network reducer or FLP conntrack. It can match only at the edge level (client host addr → server addr:port), which suits a service-dependency view.

### Gaps
- How the opentelemetry-network reducer chooses `metrics_update_side_` (for example, preferring the connector side) is not documented beyond the comment.
- Whether Datadog's backend joins client-side and server-side agent reports into one connection record, or only picks one, is not documented on the pages fetched.

---

## Q3. Enrichment: Kubernetes, process/container identity, DNS names, cloud metadata (where it happens)

### Takeaway
Enrichment happens in user space on the node (Hubble/Cilium, Retina, Datadog), centrally (NetObserv FLP, opentelemetry-network reducer), or in the backend (Datadog's tag joins). DNS-name attribution uses DNS snooping in the agent (Datadog, opentelemetry-network `remote_dns_name`, Hubble `dns` context). Cloud metadata comes from a cloud collector or integration.

### Cited Findings
- Retina: on the Hubble control plane, the Hubble Observer enriches with Cilium libraries (IP → pod, node, namespace, labels). On the standard control plane, Retina's Enricher uses its own Kubernetes cache. An API Server Watcher keeps an IP cache of API-server addresses for enrichment. — [Retina architecture](https://retina.sh/docs/Introduction/architecture)
- NetObserv FLP enrichment: `add_kubernetes` (pod, owner and node, with optional labels and annotations by prefix, plus zone via `add_zone`), `add_subnet`, `add_location` (ip2location DB), and `subnetLabels`, which label CIDRs so "cluster external traffic" can be identified (`SrcSubnetLabel` / `DstSubnetLabel`). — [FLP api.md](https://github.com/netobserv/flowlogs-pipeline/blob/main/docs/api.md); [FlowCollector API](https://github.com/netobserv/network-observability-operator/blob/main/docs/FlowCollector.md). Direct mode is memory-inefficient because "each FLP instance caches the same cluster information". — [Architecture.md](https://github.com/netobserv/network-observability-operator/blob/main/docs/Architecture.md)
- opentelemetry-network: the kernel collector supplies process (comm), cgroup and socket data. The k8s collector and cloud collector supply workload and cloud metadata. The reducer resolves per-side node data (id, az, role, env, namespace, container, pod). Optional AS enrichment (`--enable-autonomous-system-ip`, GeoIP DB) and AWS enrichment (`--enable-aws-enrichment`, needs the cloud collector) are available. — [flow_span.h](https://github.com/open-telemetry/opentelemetry-network/blob/main/reducer/matching/flow_span.h); [reducer.md](https://github.com/open-telemetry/opentelemetry-network/blob/main/docs/reducer.md)
- Datadog: IP → domain resolution ("domain" tag) since Agent 7.17 for internal and external traffic, so endpoints without an agent (S3, load balancers, APIs) can be monitored. It "requires the system probe to run in the root network namespace". Cloud service autodetection maps traffic to AWS services (S3, RDS, Kinesis, ELB, ElastiCache) and Google Cloud APIs. "Enhanced resolution" for AWS/Azure adds tags for load balancers, NAT gateways and VPC endpoints. Unresolved endpoints appear as `N/A`. — [Datadog Network Analytics](https://docs.datadoghq.com/network_monitoring/cloud_network_monitoring/network_analytics/). DNS resolution is not supported on CentOS/RHEL 7.6 kernels. `dns_monitoring_ports` is configurable (7.76+). — [Datadog CNM setup](https://docs.datadoghq.com/network_monitoring/cloud_network_monitoring/setup/)
- Hubble metric labels can use `dns` as a context (for example `destinationContext=dns|ip`, where the first non-empty value is used). — [Cilium docs: Metrics](https://docs.cilium.io/en/stable/observability/metrics/)

### Inferences
- shawk enriches in the agent (comm, cgroup, netns) and maps `peer_service` centrally via PostgreSQL's host↔address history. Datadog's `domain` tag and NetObserv's `subnetLabels` are cheap ways to make "external" more useful than one bucket: label known CIDRs (on-prem ranges, partner networks, cloud provider ranges) and DNS names before collapsing everything else to "external".
- Datadog's root-netns requirement for DNS snooping is relevant if shawk adds DNS attribution in containers.

### Gaps
- Hubble's own DNS-to-IP mapping mechanism (FQDN cache from the DNS proxy) was not verified on a fetched page in this session.

---

## Q4. NAT / conntrack / load-balancer resolution

### Takeaway
The two connection-level tools resolve NAT by **hooking conntrack in eBPF**. Datadog hooks the conntrack hash insert (plus a netlink dump at startup and netlink as a fallback) and keeps an LRU map. opentelemetry-network hooks `__nf_conntrack_confirm` and `nf_ct_delete`, records only NAT-ed entries and ships them to the reducer. NetObserv has an opt-in `PacketTranslation` feature for Service NAT. Datadog shows post-NAT IPs by default with pre-NAT IPs on request, and does not resolve NAT gateways.

### Cited Findings
- **Datadog:** PR #7500 added eBPF NAT tracking that hooks only the conntrack hash-insert path. Removals are left to user space so mappings persist until process-agent reads them. Netlink still dumps the existing table at startup. At the time this needed runtime compilation because `nf_conn` was "too complicated to offset guess". Netlink-only operation had "unacceptable" performance. Reviewers chose an LRU hash map (evicts instead of failing when full). — [datadog-agent PR #7500](https://github.com/DataDog/datadog-agent/pull/7500)
- PR #16010 made the eBPF conntracker the default for the prebuilt tracer, with fallback to the netlink conntracker if loading fails. — [datadog-agent PR #16010](https://github.com/DataDog/datadog-agent/pull/16010)
- A hard-coded 10 s netlink conntrack-initialization timeout made system-probe fail on large clusters. Issue #7781 asked for it to be configurable. — [datadog-agent issue #7781](https://github.com/DataDog/datadog-agent/issues/7781)
- The Datadog Operator still documents a netlink/conntrack option that "add[s] NAT information to connection data". — [Datadog Operator configuration](https://docs.datadoghq.com/containers/datadog_operator/configuration/)
- Secondary sources: Datadog's eBPF conntracker cut CPU by about 35% compared with Netlink-based updates and removed the need to throttle updates. — [TFiR write-up](https://tfir.io/datadog-boosts-network-observability-with-ebpf-cuts-cpu-usage-by-35/); [Linux Foundation case study PDF (July 2025; text not machine-readable)](https://www.linuxfoundation.org/hubfs/eBPF/eBPF%20Datadog%20Case%20Study.pdf)
- UI semantics: Client and Server IP columns show **post-NAT** IPs by default. "Show pre-NAT IPs" shows the top 5 pre-NAT IPs when several map to one post-NAT IP. `pre_nat.ip` is searchable. "NAT gateways are not resolved." — [Datadog Network Analytics](https://docs.datadoghq.com/network_monitoring/cloud_network_monitoring/network_analytics/)
- **opentelemetry-network:** a kprobe and kretprobe on `__nf_conntrack_confirm` builds the ORIGINAL (pre-NAT) tuple and a post-NAT tuple (REPLY flipped), "Filter[s] out non-NAT flows by comparing tuples", and records the entry in a `seen_conntracks` map. A kprobe on `nf_ct_delete` ("invoked for all teardown paths") reports cleanup only for conntracks seen on the confirm path. `ctnetlink_dump_tuples` is also hooked. The code filters to IPv4 TCP/UDP. — [render_bpf.c](https://github.com/open-telemetry/opentelemetry-network/blob/main/collector/kernel/bpf_src/render_bpf.c)
- **NetObserv:** the `PacketTranslation` feature enables "enriching flows with packet translation information, such as Service NAT". It is opt-in. — [FlowCollector API](https://github.com/netobserv/network-observability-operator/blob/main/docs/FlowCollector.md)

### Inferences
- For shawk on Rocky Linux 9 (kernel 5.14 with BTF), the prior art suggests this design:
  - Use a CO-RE kprobe or fentry on `__nf_conntrack_confirm` (or the hash-insert path) that stores only NAT-ed entries in an LRU hash.
  - Dump existing entries over netlink at startup, with a configurable timeout.
  - Clean up on `nf_ct_delete`.
  - Correlate on connect: the socket's 4-tuple equals the conntrack ORIGINAL tuple on the client host. Rewrite `remote addr:port` to the post-DNAT backend, or keep both, as Datadog's pre-NAT/post-NAT pair does.
- This resolves kube-proxy (iptables/IPVS) DNAT and local DNAT on the same host. It cannot see NAT done by an external load balancer or NAT gateway; Datadog explicitly does not resolve NAT gateways. shawk's server-side observation (with the client IP as seen by the server) remains the only way to recover those relations.
- Cilium's kube-proxy replacement does socket-level load balancing in its own maps, so a conntrack hook would not see Cilium-LB translations. This is not covered by the sources above.

### Gaps
- NetObserv's `PacketTranslation` implementation (which hook, and whether it reads conntrack or OVN data) was not confirmed.
- No primary source was found on how Hubble represents service translation (pre/post-LB addresses) in flows.

---

## Q5. Storage split: metrics TSDB vs flow-log store (what goes where and why)

### Takeaway
Every tool puts low-cardinality aggregates in Prometheus. Per-flow detail is either ephemeral (the Hubble in-memory ring), shipped to logs (Hubble exporter files, NetObserv → Loki/Kafka/IPFIX/OTel), or kept in a dedicated history store (Timescape; Datadog's backend, 14 days). NetObserv made Loki optional in 1.6 and measured large savings. Isovalent introduced aggregated **connection logs** because per-flow events are hard to store at scale. Both moves support shawk's choice to store aggregated relations rather than raw flows.

### Cited Findings
- **NetObserv Loki-less** (operator 1.6, `loki.enable: false`):
  - Measured savings: memory down 45–65%, CPU down 10–20%, storage down about 90% (15-day estimate). P90 query latency for Prometheus vs Loki: 99 ms vs 984 ms (5 min window), 236 ms vs 2410 ms (1 h), 474 ms vs over 10 s (6 h).
  - Losses: the Traffic flows table; per-pod granularity ("creates high-cardinality Prometheus metrics"); Loki-style multitenancy.
  - Raw flows can still go out through `spec.exporters` (Kafka, IPFIX).
  - [Red Hat Developer, 2024-09-19](https://developers.redhat.com/articles/2024/09/19/lightweight-network-observability-operator-without-loki)
- The upstream README says: "Loki is not mandatory but improves the overall experience with NetObserv." Without Loki some console features are disabled. — [NetObserv operator README](https://github.com/netobserv/network-observability-operator/blob/main/README.md)
- When Loki is disabled, default metrics switch from namespace-level to workload-level (`workload_flows_total` replaces `namespace_flows_total`, and so on), so the console can still render workload topology from Prometheus. — [NetObserv Metrics.md](https://github.com/netobserv/network-observability-operator/blob/main/docs/Metrics.md)
- **Hubble:** flows live only in the agent's in-memory ring buffer, with no persistence ([internals](https://docs.cilium.io/en/stable/internals/hubble/)). Metrics go to Prometheus ([metrics](https://docs.cilium.io/en/stable/observability/metrics/)). Flow logs go to files for an external log pipeline ([exporter](https://docs.cilium.io/en/stable/observability/hubble/configuration/export/)). History needs enterprise Timescape.
- **Timescape 1.18 connection logs:** "complement Hubble flow events with a more scalable representation of network activity… aggregated, database friendly, and designed for large clusters where high volumes of flow events are difficult to store or process". They give teams "a way to control storage use" while keeping flows for troubleshooting, and they underpin the graph view. — [Isovalent INK 1.18 blog](https://isovalent.com/blog/post/isovalent-networking-for-kubernetes-118-new-routing-policy-and-observability-enhancements/)
- **opentelemetry-network:** metrics only, to Prometheus or OTLP ([reducer.md](https://github.com/open-telemetry/opentelemetry-network/blob/main/docs/reducer.md)). The roadmap's "High cardinality storage" item says the cost of encoding, sending and ingesting fine-grained data into "traditional time-series databases is overwhelming". The plan was for the reducer to write state blocks to object storage (S3/GCS) and convert them to Parquet on demand, which never shipped before archival. — [roadmap.md](https://github.com/open-telemetry/opentelemetry-network/blob/main/docs/roadmap.md)
- **Datadog:** proprietary backend; 30 s collection, 5-min buckets, 14-day retention. — [Datadog Network Analytics](https://docs.datadoghq.com/network_monitoring/cloud_network_monitoring/network_analytics/)

### Inferences
- shawk's PostgreSQL relation store plays the role of NetObserv's Loki or Isovalent's connection logs, at a coarser grain (upserted edges with first_seen/last_seen, not time-series flow records). NetObserv's numbers suggest that skipping a log store is worth a lot when the main use is topology and dashboards.
- NetObserv's own Loki-less trade-off (no per-pod detail in Prometheus) maps to shawk's choice to keep `peer_addr` as a metric label. Keeping per-address detail in PostgreSQL and leaving only service-level labels in Prometheus would follow NetObserv's approach.

### Gaps
- Timescape's default and maximum retention, and its backend database, were not confirmed from primary sources.

---

## Q6. Cardinality controls and retention

### Takeaway
Every tool offers opt-in label dimensions. Pairwise (source × destination) series are flagged as the main cardinality risk: Retina calls "remote context" unbounded, opentelemetry-network disables `id-id` by default, and NetObserv warns about mixing Src and Dst fields. Mitigations are per-side ("local") context, workload or namespace rather than pod or IP, include/exclude filters, and removal of stale series.

### Cited Findings
- **Hubble metrics:**
  - `sourceContext` / `destinationContext` choose one label value from `identity|namespace|pod|pod-name|dns|ip|reserved-identity|workload|workload-name|app` (first non-empty value wins). `labelsContext` adds separate labels (`source_ip`, `source_workload`, `traffic_direction`, …).
  - Series bound to a deleted pod are removed one minute after deletion.
  - Dynamic metrics (`hubble.metrics.dynamic.enabled`) apply ConfigMap changes without restart and support `excludeFilters`.
  - [Cilium 1.20.4 Metrics](https://docs.cilium.io/en/stable/observability/metrics/)
- **Hubble exporter:** `allowList`/`denyList` (or `includeFilters`/`excludeFilters`) and `fieldMask` are the listed performance levers. Rotation is `fileMaxSizeMb` 10 and `fileMaxBackups` 5 by default. — [Cilium exporter docs](https://docs.cilium.io/en/stable/observability/hubble/configuration/export/)
- **Retina modes:**
  - **Basic**: per node; cardinality grows with node count; "scales well".
  - **Advanced / remote context**: by source and destination pod, including external IPs. Cardinality is "unbounded", so it has scale limits.
  - **Advanced / local context**: by the local pod only (source for egress, destination for ingress). It grows with the number of pods and is "designed for scale".
  - Pods to observe are selected with annotations or the MetricsConfiguration CRD.
  - [Retina docs: Metric modes](https://retina.sh/docs/Metrics/modes/)
- **NetObserv:**
  - `processor.metrics.includeList` selects predefined metrics. `workload_*` metrics "have a bigger cardinality".
  - FlowMetrics CRD fields are flagged `fine` or `careful`. Using both `SrcK8S_Name` and `DstK8S_Name` "potentially generates the square of the cardinality".
  - Agent-side `flowFilter` rules filter in the kernel. Processor `filters` are more flexible (for example by namespace) but give "a lesser improvement in performance".
  - [NetObserv Metrics.md](https://github.com/netobserv/network-observability-operator/blob/main/docs/Metrics.md); [FlowCollector API](https://github.com/netobserv/network-observability-operator/blob/main/docs/FlowCollector.md)
- FLP `encode prom` has `expiryTime` (default 2 min) for stale series and `maxMetrics`. — [FLP api.md](https://github.com/netobserv/flowlogs-pipeline/blob/main/docs/api.md)
- **opentelemetry-network:** `id-id` series (lowest level, "highest volume and cardinality") are off by default. `az-id` is optional. `--disable-node-ip-field` "can greatly reduce cardinality". `--enable-metrics` and `--disable-metrics` select metric groups (tcp, udp, dns, http). — [reducer.md](https://github.com/open-telemetry/opentelemetry-network/blob/main/docs/reducer.md)
- **Datadog:** auto-grouping by `service`, `kube_service`, `short_image` and `container_name`. The network map adds a second grouping tag automatically when there are too many nodes. — [Network Analytics](https://docs.datadoghq.com/network_monitoring/cloud_network_monitoring/network_analytics/); [Network Map](https://docs.datadoghq.com/network_monitoring/cloud_network_monitoring/network_map/)
- Retention: Datadog CNM keeps data 14 days ([Network Analytics](https://docs.datadoghq.com/network_monitoring/cloud_network_monitoring/network_analytics/)). The others defer retention to the user's Prometheus, Loki or Timescape.

### Inferences
- shawk's metric label set (host, service, direction, peer_addr, port, proto, peer_service) is a pairwise, "remote context" design. Collapsing external addresses to "external" bounds it the way Retina's local context does for the external side, but internal `peer_addr` × `host` still grows with the number of communicating pairs.
- The prior art suggests: (a) make `peer_addr` opt-in or drop it from default metrics, as opentelemetry-network does with `id-id` and `node-ip`, keeping it only in PostgreSQL; (b) provide a per-host, per-service "local context" metric family that is always on; (c) add a stale-series expiry so departed peers stop being exported, as FLP `expiryTime` and Hubble's one-minute pod cleanup do.

### Gaps
- No quantitative series-count benchmarks were found for any of the tools.

---

## Q7. Topology / service map: how it is built and rendered; Grafana support

### Takeaway
Hubble UI builds the service map from **live flows via Relay** (no history without Timescape). The NetObserv console builds topology from Loki flows or, without Loki, from Prometheus workload metrics. Datadog's network map groups by any tag, with automatic clustering. In Grafana, the Isovalent Hubble data source renders a service map as a **Node Graph from Prometheus Hubble HTTP metrics**. Retina publishes Grafana dashboards but no graph view.

### Cited Findings
- Hubble UI "automatically discovers the service dependency graph at L3/L4 and L7", presented as a filterable service map. — [Cilium docs: Hubble overview](https://docs.cilium.io/en/stable/observability/hubble/index.html). The UI and CLI use Relay's Observer API. — [Hubble internals](https://docs.cilium.io/en/stable/internals/hubble/)
- The Timescape UI (1.18) adds a **Connections** tab: "a live, aggregated map of how entities communicate across the cluster". It is built from connection logs and filterable with CEL. Boxes are workloads or services, lines are active paths, hovering shows volume and drops, and a table lists the same relationships. — [Isovalent INK 1.18 blog](https://isovalent.com/blog/post/isovalent-networking-for-kubernetes-118-new-routing-policy-and-observability-enhancements/)
- Grafana "Hubble" data source (isovalent-hubble-datasource): its Prometheus connection "must store Hubble metrics, used in Service Map query", rendered "as a node graph" from Hubble HTTP metrics that carry at least source and destination labels. A Tempo link connects flows to traces. — [Grafana plugin: Hubble datasource](https://grafana.com/grafana/plugins/isovalent-hubble-datasource/)
- NetObserv: the console offers a topology view plus a flow table ([Architecture.md](https://github.com/netobserv/network-observability-operator/blob/main/docs/Architecture.md)). Without Loki, topology views come from Prometheus queries, with less detail (no pods or IPs). — [Red Hat Developer article](https://developers.redhat.com/articles/2024/09/19/lightweight-network-observability-operator-without-loki)
- Datadog network map: nodes are the values of one chosen tag (service, host, team…). Edges carry one chosen metric (throughput, retransmits, latency, jitter, established or closed connections). Filters include tags, unresolved traffic and a percentile range. Large maps are clustered automatically, and a cluster gets a red border if an alerting monitor matches its tag. — [Datadog Network Map](https://docs.datadoghq.com/network_monitoring/cloud_network_monitoring/network_map/)
- Retina Grafana dashboards on grafana.com: "Kubernetes / Networking / Retina (Standard) / Pod Traffic" (22837), "(Standard) / DNS" (22836), "(Hubble) / DNS" (22898), "(Hubble) / Pod Flows (Namespace)" (22899), plus Pod Flows (Workload) and Clusters. — [Retina dashboards on grafana.com](https://grafana.com/orgs/retina1/dashboards); [22837](https://grafana.com/grafana/dashboards/22837); [22899](https://grafana.com/grafana/dashboards/22899)

### Inferences
- Since Grafana is shawk's only UI, the Hubble data source pattern applies directly: a Node Graph panel fed by a PromQL edge query (source and destination labels) for "live" topology. A second Node Graph fed by a PostgreSQL edges/nodes view (first_seen/last_seen) would cover "historical/all-time" topology, similar to the Hubble UI vs Timescape split.
- Datadog's automatic clustering and "second grouping tag" is a useful pattern for large graphs. In Grafana this means template variables that switch node granularity (host → service → team).

### Gaps
- Hubble UI internals (whether graph building happens in the UI backend or the browser) were not documented on the pages fetched.
- The NetObserv console topology implementation was not examined beyond the documentation summary.

---

## Q8. Alerting: built-in alerts / health rules

### Takeaway
NetObserv is the only one of the open-source tools here that ships built-in alert and health rules: PrometheusRule templates with thresholds and per-variant grouping, plus self-health alerts. Datadog has CNM monitor recipes. No built-in alert rule sets were found for Hubble or Retina, only metrics and dashboards (and Hubble's alpha drop-event emitter).

### Cited Findings
- **NetObserv health rules:**
  - Converted into `PrometheusRule` resources as Alerts or Recording rules and shown on a Network Health page.
  - Defaults: `PacketDropsByDevice`, `PacketDropsByKernel`, `IPsecErrors`, `NetpolDenied`, `LatencyHighTrend`, `DNSErrors`, `DNSNxDomain`, `ExternalEgressHighTrend`, `ExternalIngressHighTrend`, `Ingress5xxErrors`, `IngressHTTPLatencyTrend`, `TLSInsecureVersion`.
  - Self-health: `NetObservNoFlows` ("no flows are being observed for a certain period") and `NetObservLokiError`.
  - Rules are created only for enabled features. Each is configured as a template with variants (`thresholds: critical/warning/info`, `groupBy: Node`, …). `disableAlerts` turns them off. Custom rules join the dashboard via the `netobserv: "true"` label and a `netobserv_io_network_health` annotation. Runbooks live in openshift/runbooks.
  - [NetObserv HealthRules.md](https://github.com/netobserv/network-observability-operator/blob/main/docs/HealthRules.md)
- The sample custom alert "incoming-traffic-surge" compares a 30 m byte rate with `offset 1d` and fires above +100%. — [NetObserv HealthRules.md](https://github.com/netobserv/network-observability-operator/blob/main/docs/HealthRules.md)
- In operator 1.10, alerts and the Network Health dashboard were introduced as Technology Preview. — [OpenShift NetObserv release notes (localized copy)](https://docs.redhat.com/ko/documentation/openshift_container_platform/4.18/html/network_observability/network-observability-operator-release-notes). (Note: search-snippet based. The current upstream doc above shows these as default rules, so their status may have changed since 1.10.)
- **Datadog:** CNM has a "Common Monitors" page. Network map clusters get red borders when an alerting monitor matches. — [Datadog CNM overview](https://docs.datadoghq.com/network_monitoring/cloud_network_monitoring/); [Network Map](https://docs.datadoghq.com/network_monitoring/cloud_network_monitoring/network_map/)
- **Hubble:** the metrics page contains no recommended alert rules or dashboards beyond an example Prometheus/Grafana stack ([Cilium Metrics](https://docs.cilium.io/en/stable/observability/metrics/)). The alpha `hubble.dropEventEmitter` emits Kubernetes Events for pod drops (default reasons `auth_required` and `policy_denied`, interval 2 m). — [Cilium Helm reference](https://docs.cilium.io/en/stable/helm-reference/)
- **Retina:** the GitHub page does not mention alerting. — [GitHub microsoft/retina](https://github.com/microsoft/retina)

### Inferences
- NetObserv's design is directly reusable for shawk as Grafana-managed or Prometheus alert rules: templated rules, severities, a "no data from agent" self-alert, and trend alerts against `offset 1d`. Candidates: failed-connect ratio per service, retransmit ratio, RTT trend vs yesterday, new external peer (from PostgreSQL first_seen), and agent silence (NetObservNoFlows analog).

### Gaps
- No primary source was found for official Hubble or Retina PrometheusRule bundles.

---

## Q9. Support for non-Kubernetes hosts / VMs

### Takeaway
Datadog is the only tool here with first-class bare-metal and VM host support (Linux and Windows). opentelemetry-network ran on plain hosts but is now archived. NetObserv's agent and FLP can technically run standalone, but the product is Kubernetes-centric. Retina is Kubernetes-only. Cilium's VM feature ("external workloads") was deprecated or removed around 1.18.

### Cited Findings
- **Datadog:**
  - Linux kernel 4.4.0+ (or backports). Listed distributions: Ubuntu 16.04+, Debian 9+, Fedora 26+, SUSE 15+, Amazon Linux, CentOS/RHEL 7.6+. Rocky Linux is not explicitly listed.
  - Windows via a kernel driver (Server 2012 R2+). No macOS.
  - Non-container hosts are set up through `system-probe.yaml`. Datadog recommends at least 2 hosts.
  - [Datadog CNM setup](https://docs.datadoghq.com/network_monitoring/cloud_network_monitoring/setup/)
- **opentelemetry-network:** the kernel collector runs as a root binary or a privileged Docker container pointed at a reducer via `EBPF_NET_INTAKE_HOST`/`PORT`. The reducer is configured by CLI flags with no Kubernetes dependency in its docs. The k8s collector is a separate optional component. — [kernel-collector.md](https://github.com/open-telemetry/opentelemetry-network/blob/main/docs/kernel-collector.md); [reducer.md](https://github.com/open-telemetry/opentelemetry-network/blob/main/docs/reducer.md)
- **NetObserv agent:** export targets (`grpc`, `kafka`, `ipfix+udp/tcp`, `direct-flp`) and interface selection (`INTERFACES`, `INTERFACE_IPS`) are generic. The docs do not document a non-Kubernetes mode. — [agent config.md](https://github.com/netobserv/netobserv-ebpf-agent/blob/main/docs/config.md). The operator README describes NetObserv as a Kubernetes operator. — [NetObserv README](https://github.com/netobserv/network-observability-operator/blob/main/README.md)
- **Retina:** described as Kubernetes network observability, installed with Helm. No standalone mode was found. — [GitHub microsoft/retina](https://github.com/microsoft/retina)
- **Cilium external workloads (VMs):** added as beta in 1.9 ([v1.9.0 release](https://github.com/cilium/cilium/releases/tag/v1.9.0)). cilium-cli v0.17.0 dropped `external-workload` commands and said the feature "will be removed in v1.18" ([cilium-cli v0.17.0 notes](https://newreleases.io/project/github/cilium/cilium-cli/release/v0.17.0)). A 1.18.0 changelog summary lists External Workloads as deprecated ([third-party changelog copy](https://git.tdude.co/tristan/infrastructure/-/merge_requests/1520)). The sources conflict on removal vs deprecation, and this is not verified in the official 1.18 upgrade notes.

### Inferences
- shawk's focus on Rocky 9 VMs and on-prem servers fills a gap in the open-source landscape. The closest open-source predecessor (opentelemetry-network) supported plain hosts but is archived. Datadog is the commercial reference for host-centric NPM and is worth benchmarking for metric semantics and UX.
- Rocky 9 / RHEL 9 operational lessons from prior art: SELinux policy for bpf in containers (opentelemetry-network, Datadog); CO-RE rather than header fetching or runtime compilation (opentelemetry-network roadmap, Datadog 7.60 deprecation of prebuilt); fentry→kprobe fallback (Datadog PR #59165).

### Gaps
- Official confirmation of Cilium external-workload removal and its version was not obtained.

---

## Q10. Project status as of late 2026

### Takeaway
opentelemetry-network was **archived in October 2026**, and OBI (OpenTelemetry eBPF Instrumentation) is named as the natural home for its functionality. Cilium/Hubble (1.20.x), Isovalent Timescape (1.18, enterprise), Retina, NetObserv and Datadog CNM are active. Datadog renamed NPM to Cloud Network Monitoring.

### Cited Findings
- **opentelemetry-network:**
  - The GitHub banner says "archived by the owner on Oct 7, 2026. It is now read-only." Releases list is empty. — [GitHub open-telemetry/opentelemetry-network](https://github.com/open-telemetry/opentelemetry-network)
  - Community issue #3693 (opened 2026-09-16 by trask): no active SIG owns the repo, and the newer Network SIG does not own it. Maintainer yonch said no full-time team works on it ("volunteer-level effort"). svencowart suggested OBI as the natural home. grcevski noted the OBI donation commitment to reuse OBI for event generation in the eBPF network project. trask archived it on 2026-10-06 because it "was not being maintained and had not received security updates for some time", and it can be unarchived if things change. — [open-telemetry/community #3693](https://github.com/open-telemetry/community/issues/3693)
  - The banner (Oct 7) and the issue comment (Oct 6) differ by a day, probably a time-zone difference.
- **Cilium:** stable docs are Cilium **1.20.4**. — [Cilium Helm reference](https://docs.cilium.io/en/stable/helm-reference/)
- **Isovalent:** Isovalent Networking for Kubernetes / Timescape 1.18 announced 2025-12-03 (Stream API, connection logs, Integrated Timescape, mTLS ingestion). — [Isovalent blog](https://isovalent.com/blog/post/isovalent-networking-for-kubernetes-118-new-routing-policy-and-observability-enhancements/)
- **Retina:** public, MIT, about 3.2k stars, 1,694 commits, active CI. Windows Server 2019 is no longer supported. — [GitHub microsoft/retina](https://github.com/microsoft/retina)
- **NetObserv:** FlowCollector v1beta1 removed in 1.10. In 1.10.1 the operator warns when Direct mode is used on clusters over 15 nodes. — [OpenShift NetObserv release notes (localized)](https://docs.redhat.com/ko/documentation/openshift_container_platform/4.18/html/network_observability/network-observability-operator-release-notes). Upstream docs show health rules and FlowCollectorSlice multi-tenancy. — [HealthRules.md](https://github.com/netobserv/network-observability-operator/blob/main/docs/HealthRules.md); [Architecture.md](https://github.com/netobserv/network-observability-operator/blob/main/docs/Architecture.md)
- **Datadog:** product name is now "Cloud Network Monitoring". Recent agent features (7.68–7.76) add failure categories and DNS port configuration. — [Datadog CNM](https://docs.datadoghq.com/network_monitoring/cloud_network_monitoring/); [Network Analytics](https://docs.datadoghq.com/network_monitoring/cloud_network_monitoring/network_analytics/); [Setup](https://docs.datadoghq.com/network_monitoring/cloud_network_monitoring/setup/)

### Inferences
- Design ideas from opentelemetry-network (the matching reducer, conntrack hooks, `seq_show` enumeration) remain useful references, but shawk should not depend on its code or protocol. Its archival also suggests that a heavy central C++ reducer was hard to sustain with volunteer maintenance. shawk's choice of PostgreSQL plus a standard OTel Collector avoids a bespoke central service.

### Gaps
- Latest release versions and dates for Retina, NetObserv (1.11? 1.12?) and datadog-agent could not be retrieved (GitHub API blocked from this environment).
- OBI's network-metrics capabilities, as the proposed successor, were not examined here; they may be covered by another research thread.
