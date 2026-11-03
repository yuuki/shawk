# eBPF/metrics-based service-map tools: Coroot, Caretta, Beyla/OBI network metrics, Kiali, Tempo/OTel service graphs

Research date: 2026-10-31. Primary sources: GitHub source files fetched from `main`/`master` in October 2026, plus the official doc sites. Where a source is older (for example a 2022 or 2023 blog post), that is stated. The scope is limited to the five tool families named in the assignment. Each section ends with inferences for shawk's design: a Go eBPF agent; flows keyed in the kernel by (direction, proto, local addr, remote addr, service port, netns, cgroup, comm); relations stored in PostgreSQL; 15 s metrics sent over OTLP to a Prometheus-compatible store; Grafana as the only UI.

---

## Q1. What connection/flow metrics does each tool emit (names, labels, types, units)?

### Takeaway
- Coroot and Caretta use connection-oriented metrics. Coroot emits per-container counters and gauges keyed by `destination` and `actual_destination` (ip:port). Caretta emits one cumulative-bytes gauge per client→server:port link.
- OBI/Beyla emits per-packet-derived byte and packet counters whose labels you choose. It also has newer "StatsO11y" TCP RTT, failed-connect, retransmit and I/O metrics.
- Kiali emits nothing itself. It reads Istio/Envoy's `istio_requests_total` and `istio_tcp_*`.
- Tempo and the OTel servicegraph connector derive `traces_service_graph_*` from paired spans, not from sockets.

### Cited Findings

**Coroot node-agent** (all container metrics carry `container_id`, for example `/k8s/ns/pod/container` or `/system.slice/nginx.service`). Source: [docs.coroot.com/metrics/node-agent](https://docs.coroot.com/metrics/node-agent) ([doc source](https://github.com/coroot/coroot/blob/main/docs/docs/metrics/node-agent.md)).
- `container_net_tcp_successful_connects_total`: Counter. Labels `destination`, `actual_destination`. Source is the `tracepoint/sock/inet_sock_set_state` tracepoint. `actual_destination` is the post-iptables/IPVS address, for example Service IP 10.96.1.1:80 → Pod 10.40.1.5:80 — [Coroot docs](https://docs.coroot.com/metrics/node-agent)
- `container_net_tcp_failed_connects_total`: Counter. Label `destination` only. Covers TCP failures only, not DNS errors — [Coroot docs](https://docs.coroot.com/metrics/node-agent)
- `container_net_tcp_active_connections`: Gauge, "number of active outbound connections". Labels `destination`, `actual_destination` — [Coroot docs](https://docs.coroot.com/metrics/node-agent)
- `container_net_tcp_retransmits_total`: Counter. Source is `tracepoint/tcp/tcp_retransmit_skb`. Collected only for outbound connections. Labels `destination`, `actual_destination` — [Coroot docs](https://docs.coroot.com/metrics/node-agent)
- `container_net_tcp_bytes_sent_total` / `container_net_tcp_bytes_received_total`: Counters. Labels `destination`, `actual_destination` — [Coroot docs](https://docs.coroot.com/metrics/node-agent)
- `container_net_tcp_connection_time_seconds_total`: Counter, "time spent on TCP connections". Labels `destination`, `actual_destination` — [Coroot docs](https://docs.coroot.com/metrics/node-agent)
- `container_net_tcp_listen_info`: Gauge. Labels `listen_addr` (ip:port) and `proxy`. Sources are inet_sock_set_state and `/proc/<pid>/net/tcp{,6}` — [Coroot docs](https://docs.coroot.com/metrics/node-agent)
- `container_net_latency_seconds`: Gauge, label `destination_ip`. The agent measures it by sending ICMP echo to IPs the container is currently talking to, so it is not TCP RTT — [Coroot docs](https://docs.coroot.com/metrics/node-agent)
- `ip_to_fqdn`: Gauge, labels `ip` and `fqdn`. Built from eBPF tracking of the DNS requests containers make — [Coroot docs](https://docs.coroot.com/metrics/node-agent)
- L7 metrics:
  - `container_http_requests_total` has labels `destination`, `actual_destination`, `status`, `type`. There are equivalents for Postgres, Redis, Memcached, MySQL, Mongo, Kafka, Cassandra, RabbitMQ, NATS, Dubbo, DNS, ClickHouse, Zookeeper and FoundationDB, plus `*_duration_seconds_total` histograms.
  - Inbound variants (`container_http_inbound_requests_total` etc.) also exist, including a `container_llm_inbound_requests_*` family.
  - Sources: [containers/metrics.go](https://github.com/coroot/coroot-node-agent/blob/main/containers/metrics.go), [Coroot docs](https://docs.coroot.com/metrics/node-agent)
- Emission code: successful connects, connection time, retransmits and bytes are emitted per `DestinationKey` with `(DestinationLabelValue, ActualDestinationLabelValue)`. Failed connects are emitted per `dst.String()` only. Active connections are a gauge per DestinationKey — [containers/container.go](https://github.com/coroot/coroot-node-agent/blob/main/containers/container.go)
- Example exposition, from a 2022 blog post: `container_net_tcp_successful_connects_total{actual_destination="10.128.0.43:443",container_id="/k8s/default/prometheus-0/prometheus-server",destination="10.52.0.1:443"} 2` — [Coroot blog, Feb 15 2022](https://coroot.com/blog/building-a-service-map-using-ebpf)

**Caretta (groundcover)**
- `caretta_links_observed`: Gauge. Help text: "total bytes_sent value of links observed by caretta since its launch". Labels: `link_id, client_id, client_name, client_namespace, client_kind, client_owner, server_id, server_name, server_namespace, server_kind, server_port, role` — [pkg/caretta/caretta.go](https://github.com/groundcover-com/caretta/blob/main/pkg/caretta/caretta.go)
- `caretta_tcp_states`: Gauge, "state of TCP connections observed by caretta since its launch". Same label set — [caretta.go](https://github.com/groundcover-com/caretta/blob/main/pkg/caretta/caretta.go)
- Label semantics:
  - `*_name` is a K8s entity name, a resolved external domain, or a raw IP.
  - `*_namespace` and `*_kind` are the K8s namespace/kind, `"node"`, or `"external"`.
  - `role` is 1 = client or 2 = server.
  - Other labels such as `link_id`, `client_id` and `server_id` exist "for Grafana's Node Graph panel".
  - Source: [Caretta README](https://github.com/groundcover-com/caretta)
- Self-metrics: `caretta_polls_made` (Counter) plus map-size, map-deletion and filtered-loopback gauges/counters — [links_tracer.go](https://github.com/groundcover-com/caretta/blob/main/pkg/caretta/links_tracer.go)

**OBI (OpenTelemetry eBPF Instrumentation), formerly Grafana Beyla**
- Flow bytes: `obi.network.flow.bytes` (OTLP) / `obi_network_flow_bytes_total` (Prometheus), Counter in bytes. Enabled with the `network` feature in `OTEL_EBPF_METRICS_FEATURES` — [OBI network docs](https://opentelemetry.io/docs/zero-code/obi/network/), [OBI metrics](https://opentelemetry.io/docs/zero-code/obi/metrics/)
- Flow packets: `obi.network.flow.packets` / `obi_network_flow_packets_total`, Counter. Enabled with the `network_flow_packets` feature — [OBI network docs](https://opentelemetry.io/docs/zero-code/obi/network/)
- Inter-zone bytes: `obi.network.inter.zone.bytes` / `obi_network_inter_zone_bytes_total`. Experimental and K8s-only — [OBI network config](https://opentelemetry.io/docs/zero-code/obi/network/config/)
- StatsO11y metrics (node-level statistics pipeline):
  - `obi.stat.tcp.rtt` → `obi_stat_tcp_rtt_seconds` (Histogram)
  - `obi.stat.tcp.failed.connections` → `obi_stat_tcp_failed_connections_total` (Counter, with a `reason` label)
  - `obi.stat.tcp.retransmits` → `obi_stat_tcp_retransmits_total` (Counter)
  - `obi.stat.tcp.io` → `obi_stat_tcp_io_bytes_total` (Counter, label `network.io.direction`)
  - All src/dst address, port, name and zone attributes are hidden by default; `network.tcp.handshake.role` is available.
  - Source: [OBI metrics](https://opentelemetry.io/docs/zero-code/obi/metrics/)
- StatsO11y is described as a separate pipeline from AppO11y and NetO11y because "some hook points used for stats make reliable per-PID attribution difficult". It was introduced around v0.7.0 — [OBI docs index (via search)](https://opentelemetry.io/docs/zero-code/obi/). The exact version of the retransmit and failed-connection metrics was not confirmed; see Gaps.
- Full flow attribute set:
  - Direction: `direction` (request/response/unknown), `iface.direction` (ingress/egress), `iface`
  - Addressing: `src.address`, `dst.address`, `src.port`, `dst.port`, `src.cidr`, `dst.cidr`, `client.port`, `server.port`, `transport` (tcp/udp), `network.type`, `network.protocol.name`
  - Names: `src.name`, `dst.name` ("resolved from service discovery"), `service.name`, `service.namespace`, `service.peer.name`, `service.peer.namespace`
  - Location: `src.zone`, `dst.zone`, `obi.ip` (the agent's own IP)
  - Kubernetes: `k8s.{src,dst}.{name,namespace,owner.name,owner.type,type,node.ip,node.name}`, `k8s.cluster.name`
  - GeoIP: `src.country`, `src.asn`, `dst.country`, `dst.asn` when the `geoip` section is configured
  - Sources: [OBI network docs](https://opentelemetry.io/docs/zero-code/obi/network/), [OBI metrics](https://opentelemetry.io/docs/zero-code/obi/metrics/)
- Default visible labels on `obi.network.flow.bytes`: `direction`, plus `k8s.src/dst.owner.name`, `k8s.src/dst.owner.type`, `k8s.src/dst.namespace` and `k8s.cluster.name` when K8s metadata is enabled. `src/dst.cidr` appear if `cidrs` is configured. Addresses, ports and names are **hidden by default** — [OBI metrics](https://opentelemetry.io/docs/zero-code/obi/metrics/)
- "The metrics are captured from the host perspective, so they include the overhead of the network stack (protocol headers, etc.)" — [OBI network docs](https://opentelemetry.io/docs/zero-code/obi/network/)
- Beyla naming is `beyla.network.flow.bytes` / `beyla_network_flow_bytes_total` and `beyla_network_inter_zone_bytes_total`. Beyla's documented default attributes are `k8s.src.owner.name`, `k8s.src.namespace`, `k8s.dst.owner.name`, `k8s.dst.namespace`, `k8s.cluster.name` — [Beyla network docs](https://grafana.com/docs/beyla/latest/network/) ([source](https://github.com/grafana/beyla/blob/main/docs/sources/network/_index.md))
- OBI can also emit span metrics and **service-graph metrics** (`traces_service_graph_*`, the same format as the Collector connector) from its own L7 spans, via the `features` option — [OBI metrics](https://opentelemetry.io/docs/zero-code/obi/metrics/)

**Kiali (Istio)**: Kiali consumes these metrics and produces none of its own.
- Istio metrics:
  - `istio_requests_total` (COUNTER per request handled by a proxy)
  - `istio_tcp_sent_bytes_total`, `istio_tcp_received_bytes_total`
  - `istio_tcp_connections_opened_total`, `istio_tcp_connections_closed_total`
  - Source: [Istio standard metrics](https://istio.io/latest/docs/reference/config/metrics/)
- Istio labels: `reporter` (source|destination), `source_workload`, `source_workload_namespace`, `source_app`, `destination_workload`, `destination_workload_namespace`, `destination_app`, `destination_version`, `destination_service`, `destination_service_name`, `destination_service_namespace`, `destination_canonical_service`/`_revision`, `destination_cluster`, `destination_principal`, `connection_security_policy`, and on HTTP `response_code`/`request_protocol`. Dimensions can be suppressed with the Telemetry API `metricsOverrides.tagOverride` — [Istio metrics](https://istio.io/latest/docs/reference/config/metrics/)
- "The primary request traffic metrics for graph generation are `istio_requests_total` and `istio_tcp_sent_bytes_total`" — [Kiali FAQ: Graph](https://kiali.io/docs/faq/graph/)

**Tempo metrics-generator and the OTel Collector `service_graph` connector**
- Metrics:
  - `traces_service_graph_request_total` (Counter)
  - `traces_service_graph_request_failed_total` (Counter)
  - `traces_service_graph_request_server_seconds` and `traces_service_graph_request_client_seconds` (Histograms)
  - `traces_service_graph_unpaired_spans_total`, `traces_service_graph_dropped_spans_total` (Counters)
  - Tempo also has `traces_service_graph_request_messaging_system_seconds` (off by default) and **`traces_service_graph_connection_info`**, a Gauge "presence signal" that is off by default.
  - All of them carry the labels `client, server, connection_type`. `connection_type` is unset, `virtual_node`, `messaging_system` or `database`.
  - Source: [Tempo service graphs](https://grafana.com/docs/tempo/latest/metrics-from-traces/service_graphs/) ([source](https://github.com/grafana/tempo/blob/main/docs/sources/tempo/metrics-from-traces/service_graphs/_index.md))
- In the Collector connector README the histograms are named `traces_service_graph_request_server` / `_client` (seconds). Extra `dimensions` get a `client_` or `server_` prefix — [servicegraphconnector README](https://github.com/open-telemetry/opentelemetry-collector-contrib/tree/main/connector/servicegraphconnector)

### Inferences
- shawk's metric set covers almost the same ground as Coroot's TCP family and OBI's StatsO11y set: connections, failed connects, open connections, bytes, retransmits, RTT. Coroot is the closest prior art.
- Coroot labels failed connects with `destination` only, because there is no established flow to translate. shawk has to decide which label set failed connects get. A failed connect has no "peer_service" until it is resolved by address.
- Caretta, Coroot and shawk all key edges on the server port and drop the client's ephemeral port. OBI hides ports entirely by default.
- Coroot measures latency with active ICMP pings to peers. shawk's RTT probably comes from `tcp_sock` srtt, which is passive. The reviewer should know these are different signals.

### Gaps
- The exact OBI release that added `obi.stat.tcp.failed.connections`, `.retransmits` and `.io`, and the hook points StatsO11y uses, were not confirmed. The OBI GitHub release notes were not reachable from this environment.
- Coroot's docs list `container_net_tcp_connection_time_seconds_total` under the "Disk" heading, which looks like a doc placement error. Its exact semantics, for example whether it is cumulative connect duration, were not verified beyond the one-line description and `stats.TotalTime += duration` in the code.

---

## Q2. How is the topology (nodes/edges) assembled, stored, and resolved to identities? Are both ends matched?

### Takeaway
None of these tools has a separate topology store. All of them compute the graph from time series at query time. Identity resolution happens in one of three places:
- In the agent (Caretta, OBI, Istio/Envoy at emission time).
- In a central server that joins metrics (Coroot joins outbound `destination` with `listen_info` by IP:PORT).
- In a stateful span-pairing component (Tempo, Collector connector).

Kiali's backend is explicitly storage-less.

### Cited Findings
- **Coroot:** "The `container_net_tcp_successful_connects_total` and `container_net_tcp_active_connections` metrics show which IP:PORT each container is communicating with. The `container_net_tcp_listen_info` metric shows on which IP:PORT each container is accepting inbound TCP connections. So, joining these metrics by IP:PORT allows us to build a map of container-to-container communications." Containers are then aggregated into applications (Deployments, StatefulSets…) using kube-state-metrics — [Coroot blog, 2022](https://coroot.com/blog/building-a-service-map-using-ebpf)
- Coroot replaces a `0.0.0.0` listen address with the IP addresses assigned to that network namespace, so that the join works — [Coroot blog](https://coroot.com/blog/building-a-service-map-using-ebpf)
- Coroot treats any systemd service as a "container" (cgroup = container), so the same model covers VMs and bare metal. Supported targets are K8s pods, standalone Docker/containerd/CRI-O, Docker Swarm, ECS on EC2 and systemd units — [Coroot requirements](https://docs.coroot.com/installation/requirements)
- **Caretta:**
  - The eBPF map holds per-socket entries.
  - A userland poller generalizes each connection into a `NetworkLink{Client, Server, ServerPort, Role}` and sums `BytesSent` per link. Throughput of closed sockets is kept in an in-memory `pastLinks` map, so the gauge is "total since launch".
  - Each node publishes its links as Prometheus metrics, scraped by one central VictoriaMetrics.
  - Sources: [links_tracer.go](https://github.com/groundcover-com/caretta/blob/main/pkg/caretta/links_tracer.go), [types.go](https://github.com/groundcover-com/caretta/blob/main/pkg/caretta/types.go), [Caretta blog, Jan 9 2023](https://www.groundcover.com/blog/caretta)
- Caretta resolves identity in the agent:
  - It watches Pods, Nodes, ReplicaSets, DaemonSets, StatefulSets, Jobs, Services, Deployments and CronJobs through the K8s API, and with `traverseUpHierarchy` it resolves pods to their owning controller.
  - IPs it cannot resolve go through reverse DNS (`net.LookupAddr`, LRU cache of 10,000 entries). Anything still unknown gets namespace/kind `"external"`.
  - Sources: [pkg/k8s/ipresolver.go](https://github.com/groundcover-com/caretta/blob/main/pkg/k8s/ipresolver.go), [README](https://github.com/groundcover-com/caretta)
- Caretta handles client/server role as follows:
  - For new sockets it watches `tcp_set_state` for SYN_SENT versus SYN_RECV.
  - For already-established sockets it reads `sk_max_ack_backlog`: a positive value means the socket went through `listen()` and is the server side.
  - The same link is reported by both nodes, with `role="1"` from the client node and `role="2"` from the server node.
  - Sources: [Caretta blog](https://www.groundcover.com/blog/caretta), [README](https://github.com/groundcover-com/caretta)
- **OBI/Beyla:**
  - Each flow is decorated in the agent: K8s metadata (src/dst pod, owner, namespace), `src.name`/`dst.name` "resolved from service discovery", optional CIDR names and GeoIP.
  - Edges are just series with src/dst attribute pairs, and the backend aggregates them at query time.
  - Network metrics "are pre-aggregated at the process level" according to the selected attributes.
  - Source: [OBI network docs](https://opentelemetry.io/docs/zero-code/obi/network/)
- **Kiali:**
  - At request time the backend builds a per-namespace "traffic map" with PromQL such as `sum(rate(istio_requests_total{reporter="source",source_workload_namespace!="ns",destination_workload_namespace="ns"}[Ns])) by (source_cluster,source_workload_namespace,source_workload,source_canonical_service,…,destination_service,destination_workload,…,request_protocol,response_code,grpc_response_status,response_flags)`.
  - TCP edges use `istio_tcp_sent_bytes_total` and/or `istio_tcp_received_bytes_total`; gRPC message edges use `istio_.*_messages`.
  - A chain of "appenders" then decorates the graph.
  - Source: [graph/telemetry/istio/istio.go](https://github.com/kiali/kiali/blob/master/graph/telemetry/istio/istio.go)
- "The back-end doesn't need storage." Kiali takes its data from Prometheus, the Kubernetes API and istiod — [Kiali architecture](https://kiali.io/docs/architecture/architecture/)
- Kiali's two identity models: both ends are known at emission time because Istio's proxies exchange workload metadata, through headers for HTTP and through mTLS for TCP. Without mTLS, TCP edges are "disconnected": an edge from the workload to a terminal service node, plus a second edge from "Unknown" to the destination — [Kiali FAQ: Graph](https://kiali.io/docs/faq/graph/)
- Kiali appenders that touch graph completeness:
  - `idleNode` "looks for services that have never seen request traffic" and adds nodes for them from K8s definitions.
  - `deadNode` removes nodes that have no traffic and no backing workload (for example deleted from K8s), including "unknown", and removes service nodes with no traffic in or out.
  - Sources: [idle_node.go](https://github.com/kiali/kiali/blob/master/graph/telemetry/istio/appender/idle_node.go), [dead_node.go](https://github.com/kiali/kiali/blob/master/graph/telemetry/istio/appender/dead_node.go)
- **Tempo / Collector connector:**
  - The component looks for client/server or producer/consumer span pairs, plus database client spans.
  - It holds unpaired spans in an in-memory store until the pair arrives or a TTL expires, then emits one series per edge.
  - Because it must see both sides, all spans of a trace must reach the same instance. The connector's documented fix is a load-balancing exporter in front.
  - Uninstrumented peers become **virtual nodes** named from `peer.service`, `db.name`, `db.system` and similar attributes. A missing client becomes `user`.
  - Sources: [servicegraphconnector README](https://github.com/open-telemetry/opentelemetry-collector-contrib/tree/main/connector/servicegraphconnector), [Tempo service graphs](https://grafana.com/docs/tempo/latest/metrics-from-traces/service_graphs/)
- Store parameters:
  - Connector: `store.ttl` default 2 s, `max_items` 1000, `metrics_flush_interval` 60 s.
  - Tempo: `wait` 10 s, `max_items` 10000, `workers` 10.
  - Sources: [connector README](https://github.com/open-telemetry/opentelemetry-collector-contrib/tree/main/connector/servicegraphconnector), [Tempo configuration](https://grafana.com/docs/tempo/latest/configuration/)

### Inferences
- shawk's split puts relations in Postgres (`first_seen`/`last_seen`) and numbers in a TSDB. **None** of the five tools does this; they all derive topology from TSDB series.
- That is a real differentiator, but it creates a consistency problem the others avoid: two stores, two cadences (1–5 min versus 15 s), and an edge can exist in one store and not the other. The reviewer should check how shawk reconciles them, for example by using Postgres as the authoritative edge list and the TSDB only for numbers.
- Coroot's "join outbound destination with listen_info at query time" is the closest analogue to shawk's listener table plus host↔address history. Coroot does the join in its server at query time. shawk proposes that the **agent** look up `peer_service` from Postgres and stamp it on the metric labels.
- That agent-side stamping is closer to Caretta, OBI and Istio, which resolve at emission time. The cost: if the mapping changes, for example an IP reassigned to another host or a service renamed, old series keep the stale `peer_service`, and the label value churns, creating new series.
- Caretta and shawk both record both directions, so the same edge appears twice, once from each host. Caretta exposes this as `role`. shawk's `direction` label plays the same role. Dashboards must filter on one direction, or de-duplicate, to avoid double-counting bytes.

### Gaps
- I did not fetch Coroot's server-side Go code (the `coroot/coroot` model and auditor packages). The join logic is documented only by the 2022 blog. How Coroot handles a non-K8s host listening on 0.0.0.0 across multiple NICs, or VIPs, was not verified.
- How OBI's `src.name`/`dst.name` "service discovery" resolves names on non-K8s hosts (process name? reverse DNS? configured names?) was not documented on the pages fetched.

---

## Q3. How do they handle NAT / kube-proxy / load balancers?

### Takeaway
Only Coroot resolves NAT explicitly. It queries conntrack over Netlink, with a Cilium CT-map fallback, and keeps both the pre-NAT `destination` and the post-NAT `actual_destination`. Caretta documents NAT as an unsolved limitation. OBI sees post-NAT packets on the interface. Istio/Kiali sidesteps NAT by having proxies report logical identities.

### Cited Findings
- Coroot: "the destination address can be virtual, as in the case of Kubernetes services… ClusterIP… will be replaced by the IP of a particular Pod by iptables or IPVS… the agent resolves the actual destination of each connection by querying the conntrack table using the Netlink protocol. As a result, each metric contains both destination and actual_destination labels" — [Coroot blog](https://coroot.com/blog/building-a-service-map-using-ebpf)
- Coroot code: if the eBPF event carries no actual destination, it calls `lookupCiliumConntrackTable(src, dst)` and otherwise falls back to `actualDst = dst`. Loopback destinations are dropped for processes outside the host netns — [container.go](https://github.com/coroot/coroot-node-agent/blob/main/containers/container.go)
- Caretta: traffic "originated in NAT'd services arriving in other pods in the cluster… makes it impossible to associate it with a workload given the source IP alone". The authors mention that reverse-DNS lookups of external IPs could be added — [Caretta blog, 2023](https://www.groundcover.com/blog/caretta)
- OBI captures with a socket filter (default) or TC ingress/egress (direct action). `iface.direction` is relative to the interface, so "the same network packet could be seen as 'ingress' in a virtual network device and as 'egress' in the backing physical network interface". TC mode conflicts with Cilium; use `socket_filter` there — [OBI network config](https://opentelemetry.io/docs/zero-code/obi/network/config/)
- Kiali: traffic to unregistered external destinations appears as `PassthroughCluster` or `BlackHoleCluster`. A ServiceEntry maps it to a named node — [Kiali FAQ: Graph](https://kiali.io/docs/faq/graph/)

### Inferences
- On Rocky Linux 9 VMs, NAT cases that matter for shawk include:
  - Local DNAT (podman/docker port publishing, firewalld masquerade, keepalived/LVS VIPs on the same host). For these a conntrack lookup at connect time, as Coroot does, recovers the real backend.
  - Remote load balancers (F5, HAProxy on another host). Here the client only ever sees the VIP; it can only be resolved by matching the LB host's own inbound and outbound flows, or by an admin-maintained VIP→service mapping in Postgres.
- shawk's key stores only one remote address. The reviewer may want a second `actual_remote_addr` field in the key (Coroot's pattern), at least for TCP connect events where conntrack has a DNAT entry.
- For server-side (inbound) flows behind SNAT/masquerade, the observed peer address is the NAT box, not the real client. No tool solves this; Caretta documents it as a limitation. shawk should label such peers honestly, for example as "via NAT", rather than attributing them to a host.

### Gaps
- Coroot's netlink conntrack code path was not fetched; `containers/conntrack.go` returned 404, so the code has moved. Whether Coroot also does conntrack for UDP or inbound connections is unverified.
- No source found on how any of these tools treats IPVS/LVS direct-routing or DSR load balancers.

---

## Q4. Cardinality controls (allow/deny lists, CIDR grouping, external IP collapse, series TTL, aggregation intervals)

### Takeaway
Each tool uses a different approach:
- **OBI** offers the most configurable controls: per-metric attribute include/exclude, named CIDR buckets with a `0.0.0.0/0` catch-all, interface/protocol filters, sampling, and addresses/ports hidden by default.
- **Coroot** works through fixed agent-side filters (ephemeral-port skip, public-network allowlist, FQDN cap) and 10-minute garbage collection of idle destinations.
- **Tempo and the connector** expire idle series after 15 minutes and cap active series.
- **Caretta** has almost no controls, and its series never expire while the agent runs.

### Cited Findings
- **Coroot node-agent flags:**
  - `--ephemeral-port-range` (default `32768-60999`): "Destination and Listen TCP ports from these ranges will be skipped"
  - `--track-public-network` (default `0.0.0.0/0`): "all private networks are allowed by default"
  - `--max-fqdns-per-container` (default 50): extras are bucketed under `~other`
  - `--min-container-age` (default 30s): suppresses short-lived job pods "that produce high-cardinality series"
  - `--container-allowlist` / `--container-denylist` (regex), `--max-label-length` (4096), `--scrape-interval` (15s)
  - Source: [flags/flags.go](https://github.com/coroot/coroot-node-agent/blob/main/flags/flags.go)
- Coroot garbage collection: `gcInterval = 10 * time.Minute`. Connection stats, failed-attempt counters and L7 stats for a destination are deleted once the destination has no established connection and no connection attempt for more than 10 minutes, so its series disappear — [container.go](https://github.com/coroot/coroot-node-agent/blob/main/containers/container.go)
- **OBI:**
  - `attributes.select.<metric>.include/exclude` chooses the aggregation keys. The documented example aggregates only by `k8s.src/dst.owner.name/type`, which also drops `direction` — [OBI network docs](https://opentelemetry.io/docs/zero-code/obi/network/)
  - `network.cidrs` takes a list of CIDRs, optionally named. The narrowest match wins, and "you can safely add a `0.0.0.0/0` entry to group all the traffic that does not match any of the other CIDRs" — [OBI network config](https://opentelemetry.io/docs/zero-code/obi/network/config/)
  - Other knobs: `interfaces` / `exclude_interfaces` (default excludes `lo`; regex allowed), `protocols` / `exclude_protocols`, `direction` (ingress/egress/both), `sampling` (1 of N packets), `cache_max_flows` (default 5000), `cache_active_timeout` (default 5s), `guess_ports` (disabled by default since v0.7.0, a breaking change) — [OBI network config](https://opentelemetry.io/docs/zero-code/obi/network/config/)
  - Beyla warns that reporting all attributes "might lead to a cardinality explosion, especially when including external traffic in the `src.address`/`dst.address` attributes" — [Beyla network docs](https://grafana.com/docs/beyla/latest/network/)
- **Caretta:**
  - Only the polling interval (`pollIntervalSeconds`, default 5) and `traverseUpHierarchy` are configurable — [README](https://github.com/groundcover-com/caretta)
  - From reading `caretta.go`, the code calls only `.With(...).Set(...)` on its GaugeVecs and never deletes a label set. Links are retained in `pastLinks` forever, so series live until the agent restarts — [caretta.go](https://github.com/groundcover-com/caretta/blob/main/pkg/caretta/caretta.go), [links_tracer.go](https://github.com/groundcover-com/caretta/blob/main/pkg/caretta/links_tracer.go)
- **Collector connector:**
  - `cleanCache()` "removes series that have not been updated in 15 minutes". This is hard-coded and runs every `cache_loop` (default 1m) — [connector.go](https://github.com/open-telemetry/opentelemetry-collector-contrib/blob/main/connector/servicegraphconnector/connector.go)
  - `virtual_node_peer_attributes` and `dimensions` control which labels are added — [README](https://github.com/open-telemetry/opentelemetry-collector-contrib/tree/main/connector/servicegraphconnector)
- **Tempo metrics-generator:**
  - Registry `stale_duration` default 15m ("Interval after which a series is considered stale and will be deleted from the registry")
  - `collection_interval` default 15s
  - Per-tenant `max_active_series` override
  - `filter_policies`, and `enable_client_server_prefix`, which "doubles the label count for each configured dimension"
  - Sources: [Tempo configuration](https://grafana.com/docs/tempo/latest/configuration/), [Tempo service graphs](https://grafana.com/docs/tempo/latest/metrics-from-traces/service_graphs/)
- **Istio/Kiali:** dimensions can be removed with the Telemetry API `tagOverride` — [Istio metrics](https://istio.io/latest/docs/reference/config/metrics/). Kiali ignores request rates below 0.01 requests per minute — [Kiali FAQ: Graph](https://kiali.io/docs/faq/graph/)

### Inferences
- shawk's TSDB label set is {host, service, direction, peer_addr, port, proto, peer_service}. It is moderately high-cardinality because of `peer_addr`.
- Coroot carries `destination`/`actual_destination` ip:port per container. That is comparable to shawk's set and is evidently workable at Coroot's scale, with 10-minute idle GC and the ephemeral-port skip.
- OBI and Beyla, by contrast, deliberately **hide addresses by default** and push users toward workload- or CIDR-level aggregation. shawk could follow that by making `peer_addr` optional or droppable in the Collector, because Postgres already keeps exact addresses.
- shawk's "collapse external to `external`" rule maps directly onto OBI's named-CIDR plus `0.0.0.0/0` catch-all. Making the private/known ranges configurable as named CIDRs, rather than one hard-coded rule, would match prior art.
- Coroot caps FQDNs per container (50, then `~other`). An equivalent hard cap on distinct `peer_addr` values per (host, service) would bound worst-case cardinality, for example on scanners or NTP pools.
- **Series TTL is the one rule all of them share.**
  - Coroot uses 10 minutes; Tempo and the connector use 15 minutes; Caretta never expires and is the anti-pattern.
  - With OTLP cumulative counters, shawk must stop exporting idle flows after a TTL. Otherwise Prometheus keeps them active forever, or the agent's memory grows.
  - It also matters whether shawk exports delta or cumulative temporality. If the agent restarts and resets cumulative series, `rate()` tolerates the reset; delta-to-cumulative conversion in the Collector is stateful.

### Gaps
- No tool documents a hard cap on distinct remote addresses per process other than Coroot's FQDN cap. OBI's `cache_max_flows` bounds the flush cache, not series.
- Default Prometheus or VictoriaMetrics retention recommendations for these metrics were not found for any tool.

---

## Q5. Long-lived connections, rare/infrequent dependencies, "first seen"/new-dependency detection, topology history

### Takeaway
- None of the five tools has an explicit "first seen" timestamp, new-dependency detection or topology-change log. Topology history is "whatever the TSDB retains".
- Each tool keeps rare edges visible in its own way:
  - Tempo added a presence gauge (`traces_service_graph_connection_info`) for low-traffic edges.
  - Kiali has an "Idle Edges" option.
  - Caretta's cumulative never-expiring gauge keeps links visible as a side effect.
  - Coroot's active-connections gauge keeps long-lived connections visible.

### Cited Findings
- Tempo: "`traces_service_graph_connection_info` metric is a presence-only gauge held at `1` while an edge between two services is being observed… intended for topology discovery rather than rate calculations… so service-to-service relationships stay visible on low-traffic endpoints even when `rate(traces_service_graph_request_total[...])` is noisy or zero under aggressive head sampling". Suggested query: `last_over_time(traces_service_graph_connection_info[1h]) > 0`. It is off by default and enabled with the `service-graphs-connection-info` subprocessor — [Tempo service graphs](https://grafana.com/docs/tempo/latest/metrics-from-traces/service_graphs/)
- Tempo and the connector describe service graphs as providing "an historic view of a system's topology… offer a way of seeing how these systems have evolved over time". This history is derived from the metric history — [servicegraphconnector README](https://github.com/open-telemetry/opentelemetry-collector-contrib/tree/main/connector/servicegraphconnector), [Tempo service graphs](https://grafana.com/docs/tempo/latest/metrics-from-traces/service_graphs/)
- Kiali: "You can enable the 'Idle Edges' Display option to include request edges that previously had traffic, but not during the requested time period." It is disabled by default. Graph Duration options are capped at Prometheus `tsdbRetentionTime` and must be ≥ 2× `globalScrapeInterval` — [Kiali FAQ: Graph](https://kiali.io/docs/faq/graph/). The graph can be "paused… or replayed to re-examine a particular time period" — [Kiali topology](https://kiali.io/docs/features/topology/)
- Coroot `container_net_tcp_active_connections` is a gauge, so a long-lived idle connection still shows up as a dependency.
  - At startup the agent reads `/proc/net/tcp{,6}` in each netns and maps inodes through `/proc/<pid>/fd`, so connections established before the agent started are attributed — [Coroot blog](https://coroot.com/blog/building-a-service-map-using-ebpf)
  - The 10-minute GC keeps a destination while any established connection to it exists — [container.go](https://github.com/coroot/coroot-node-agent/blob/main/containers/container.go)
- Caretta handles pre-existing sockets through the `sk_max_ack_backlog` role heuristic. Its gauge is a "total since launch", so a link observed once stays as a series until restart — [Caretta blog](https://www.groundcover.com/blog/caretta), [caretta.go](https://github.com/groundcover-com/caretta/blob/main/pkg/caretta/caretta.go)
- Kiali's `idleNode` appender adds nodes for services that "have never seen request traffic", using K8s definitions. This is the inverse problem: known-but-unused services — [idle_node.go](https://github.com/kiali/kiali/blob/master/graph/telemetry/istio/appender/idle_node.go)

### Inferences
- shawk's Postgres relation table with `first_seen`/`last_seen` and host↔address history goes **beyond all five tools**.
- None offers "show me dependencies that appeared this week" or "edges not seen for 30 days". In Prometheus-only designs that query is expensive (`count_over_time` over long ranges) and bounded by retention.
- This is the strongest justification for shawk's two-store architecture. The design review should keep it.
- Tempo's `connection_info` presence gauge is a cheap pattern shawk could copy on the TSDB side. Prometheus alerts could then use `last_over_time(...)` without hitting Postgres, while Postgres stays the system of record.
- Coroot's /proc scan at startup and shawk's socket-iterator approach solve the same "connections pre-dating the agent" problem. Coroot's experience suggests attributing them via inode→pid. shawk's iterator gives the cgroup directly, which is more robust.
- Rarely used dependencies such as nightly batch jobs or monthly reports fall out of Coroot's and the connector's 10–15 minute series GC. In those tools they are only visible in history if the TSDB retention covers them. shawk's Postgres `last_seen` solves this independently of TSDB retention.

### Gaps
- No source found for any of the five tools emitting an event or alert on a *new* edge. Coroot's "Risks" and other inspections were not reviewed for this.

---

## Q6. Storage backends and retention, and why

### Takeaway
All five use Prometheus-compatible TSDBs for the graph. Coroot additionally offers ClickHouse as a metrics backend and keeps its own on-disk cache so Prometheus retention can be short. Caretta bundles a VictoriaMetrics single node. Kiali stores nothing. Tempo and the connector write to any Prometheus remote-write target.

### Cited Findings
- **Coroot:**
  - Metrics live in Prometheus, or VictoriaMetrics as "a drop-in replacement". In clustered VM, vminsert is used for ingestion and vmselect for queries.
  - Alternatively, ClickHouse can be the metrics backend (`--global-prometheus-use-clickhouse`) while "PromQL remains available".
  - Coroot keeps "its own on-disk metric cache, continuously retrieving metrics from Prometheus… This allows you to configure Prometheus with a shorter retention period, such as a few hours". The cache retention is set with `--cache-ttl`.
  - In multi-tenant mode, agents push via Prometheus remote write and Coroot adds a `coroot_project_id` label.
  - Source: [Coroot Prometheus config](https://docs.coroot.com/configuration/prometheus)
- Coroot stores logs, traces and profiles in ClickHouse, with metrics optional there. The claimed benefits are unified storage, columnar compression, scalability and cost. Coroot manages its own ClickHouse schema with TTLs, and can tier cold data to S3 — [Coroot ClickHouse config](https://docs.coroot.com/configuration/clickhouse)
- The Coroot node-agent can push metrics (`--metrics-endpoint`/`--collector-endpoint`) with an on-disk WAL (`--wal-dir`) and a spool (`--max-spool-size`, default 500MB) for when the collector is unreachable — [flags.go](https://github.com/coroot/coroot-node-agent/blob/main/flags/flags.go)
- **Caretta** "uses Victoria Metrics to collect and publish its metrics". The Helm chart bundles `victoria-metrics-single`, with no persistent volume by default, and Grafana. Both can be disabled and replaced by "any Prometheus-compatible" stack — [README](https://github.com/groundcover-com/caretta)
- **Kiali** needs Prometheus, the Kubernetes API and istiod; the backend "doesn't need storage" — [Kiali architecture](https://kiali.io/docs/architecture/architecture/)
- **Tempo** metrics-generator remote-writes to a Prometheus-compatible backend (`remote_write` config) — [Tempo configuration](https://grafana.com/docs/tempo/latest/configuration/). The Collector connector emits to any metrics pipeline exporter — [connector README](https://github.com/open-telemetry/opentelemetry-collector-contrib/tree/main/connector/servicegraphconnector)
- **OBI** exports via OTLP (`otel_metrics_export`) or a Prometheus endpoint — [OBI network config](https://opentelemetry.io/docs/zero-code/obi/network/config/). OBI can also be built into a Collector distribution as a receiver (`go.opentelemetry.io/obi/collector`) — [OBI docs](https://opentelemetry.io/docs/zero-code/obi/)

### Inferences
- shawk's choice of OTLP → Collector → Prometheus-compatible store matches OBI's export model.
- Coroot's WAL/spool for push mode is worth copying: VMs on-prem may lose connectivity to the central collector.
- Using PostgreSQL for relations is unusual among these tools. The nearest analogue is Coroot moving to ClickHouse for scale.
- At shawk's expected scale (VM fleet, relations upserted every 1–5 min), PostgreSQL is reasonable. The reviewer should check upsert write amplification: one row update per edge per interval just to bump `last_seen`. Batching or coarsening `last_seen`, for example only updating when older than N minutes, is a known mitigation.

### Gaps
- No tool publishes recommended retention periods or sizing for the topology metrics specifically.

---

## Q7. Grafana integration: dashboards, Node Graph feeding, alerting

### Takeaway
- Caretta is the only one of these that feeds Grafana's Node Graph panel straight from Prometheus. It does so with heavy `label_replace` PromQL in "table" format, which its authors call "PromQL witchcraft".
- Tempo and Grafana have a built-in Service Graph query type in the Tempo datasource that reads `traces_service_graph_*` from a linked Prometheus datasource.
- Coroot and Kiali have their own UIs with built-in health logic. Coroot has SLO and inspection checks with per-app thresholds; Kiali has health thresholds. Neither relies on Grafana alert rules.

### Cited Findings
- Caretta's chart ships Grafana with a predefined dashboard (anonymous access on; admin `admin`/`caretta`) — [README](https://github.com/groundcover-com/caretta)
- Caretta dashboard JSON, panel type `nodeGraph` "Service Map":
  - It has two table-format queries.
  - `nodes` = `increase((sum by (id, title, subTitle, detail__kind, arc__color) (label_replace(... caretta_links_observed{...} ...))))`
  - `edges` = `increase((sum by (id, source, target, mainStat) (label_replace(... "id", "$1", "link_id", "(.*)") ...))))`
  - Other panels: Active Ports (pie), Top Throughput Workloads (`topk(8, sum by (client_name)(rate(...)))`), Top Throughput Connections.
  - Source: [chart/dashboard.json](https://github.com/groundcover-com/caretta/blob/main/chart/dashboard.json)
- Caretta blog: "Caretta is equipped with a Grafana dashboard consisting of a Node Graph panel and some PromQL witchcraft queries to adjust the data to Node Graph's specifications". Some labels "are generated solely to comply with the format Grafana expects for displaying a Node Graph" — [Caretta blog](https://www.groundcover.com/blog/caretta)
- Tempo/Grafana: in Explore you select the Tempo datasource and the **Service Graph** query type. Grafana reads `traces_service_graph_request_total`, `_failed_total`, `_server_seconds` and `_client_seconds` from the linked Prometheus datasource, which is configured in the Tempo datasource's `serviceMap.datasourceUid`. It renders nodes coloured by success/fault — [Grafana Tempo service graph](https://grafana.com/docs/grafana/latest/datasources/tempo/service-graph/), [connector README](https://github.com/open-telemetry/opentelemetry-collector-contrib/tree/main/connector/servicegraphconnector)
- Service-graph metrics have been "natively supported by Grafana since v9.0.4" — [connector README](https://github.com/open-telemetry/opentelemetry-collector-contrib/tree/main/connector/servicegraphconnector)
- **Coroot alerting model:**
  - "Coroot turns the conventional metric analysis inside out… evaluate every inspection within an application's context". For example, the "Network round-trip time" inspection checks latency between an app and its dependencies.
  - Thresholds can be overridden per application or per project. Application status is taken from the SLO inspection.
  - Sources: [Coroot inspections overview](https://docs.coroot.com/inspections/overview), [Network inspection](https://docs.coroot.com/inspections/network)
- Coroot's default SLOs:
  - Availability: 99% of requests served without errors.
  - Latency: 99% of requests under 500ms (5s for the control-plane and monitoring categories). Fixed buckets run from 5ms to 10s.
  - SLOs can be set via K8s annotations such as `coroot.com/slo-availability-objective`, or by replacing the SLI with custom Prometheus metrics.
  - Source: [Coroot SLO inspection](https://docs.coroot.com/inspections/slo)
- Kiali health:
  - By default, a 5xx error rate ≥ 0.1% shows `Degraded` and > 10% shows `Failure`. 4xx errors have a higher tolerance.
  - Fine-grained overrides go in `health_config.rate` by namespace, kind and name regex.
  - Source: [Kiali traffic health](https://kiali.io/docs/configuration/health/)
- Kiali's graph UI is PatternFly-based. The old Cytoscape graph was deprecated in v2.0 and removed in v2.8 — [Kiali FAQ: Graph](https://kiali.io/docs/faq/graph/)

### Inferences
- Caretta's experience is direct evidence that feeding Node Graph from Prometheus is awkward. Synthetic id/source/target labels have to be emitted or `label_replace`d into existence, and the metric schema gets bent to fit the panel. In Caretta's case that meant hash-based `link_id`, `client_id` and `server_id` labels.
- shawk's plan to feed Node Graph from **Postgres via SQL** is cleaner: SQL can directly return node frames (`id`, `title`, `subtitle`, `mainstat`, `arc__*`, `detail__*`) and edge frames (`id`, `source`, `target`, `mainstat`).
  - It keeps synthetic IDs out of the TSDB labels.
  - The trade-off is that edge thickness and colour from live rates must be joined across datasources, Postgres and Prometheus. Grafana handles this with transformations, or by pre-computing rates into Postgres.
- Alerting: Coroot and Kiali encode domain knowledge in health and SLO checks rather than raw alert rules.
  - shawk relies on Grafana alerting over both stores. The reviewer may want a small set of opinionated, shipped rules in Coroot's style, for example:
    - failed-connect ratio per edge
    - retransmit ratio per edge
    - RTT regression per edge
    - "new edge" or "edge disappeared" from Postgres
  - Users then would not need to write PromQL from scratch.

### Gaps
- I did not fetch Grafana's official Node Graph panel data-format documentation; the GitHub raw path 404'd. Field names above are taken from Caretta's working dashboard.
- Whether Coroot ships Grafana dashboards for node-agent metrics was not verified; Coroot's primary UI is its own.
- Kiali has no documented built-in alert delivery in the pages fetched. Its health is display-only, and Istio/Prometheus alerting would be separate. This is unconfirmed.

---

## Q8. Hook points and overhead (per-packet vs per-connection)

### Takeaway
- Coroot, and Caretta for state, hook TCP state changes (`inet_sock_set_state`) and `tcp_retransmit_skb`: per connection or per event.
- Caretta also kprobes `tcp_data_queue`, which fires per received data segment, to read cumulative byte counters from `tcp_sock`.
- OBI/Beyla network flows are per-packet via socket filter or TC, aggregated in an eBPF flow map and flushed every 5 s.
- Istio/Kiali costs are those of Envoy proxies (a sidecar or ztunnel per pod or node).
- No tool's docs fetched here give quantitative overhead numbers for the network-map feature.

### Cited Findings
- Coroot uses `tracepoint/sock/inet_sock_set_state`. It stores the PID at CLOSE→SYN_SENT in a map keyed by `skaddr`, because the PID is only available at that transition.
  - SYN_SENT→ESTABLISHED counts as success and SYN_SENT→CLOSE as failure.
  - ESTABLISHED→FIN_WAIT1 or CLOSE_WAIT counts as close; there is no PID on a passive close, so it is resolved in userspace.
  - CLOSE↔LISTEN transitions track listen sockets.
  - Source: [Coroot blog](https://coroot.com/blog/building-a-service-map-using-ebpf)
- Coroot retransmits come from `tracepoint/tcp/tcp_retransmit_skb` — [Coroot docs](https://docs.coroot.com/metrics/node-agent). Minimum kernel is 4.16, needing `CONFIG_BPF_EVENTS=y`. RHEL 7.6+ (3.10 with backport) is supported with reduced features: no L7, no `container_net_latency_seconds` — [node-agent README](https://github.com/coroot/coroot-node-agent)
- Caretta BPF programs are `SEC("kprobe/tcp_data_queue")` and `SEC("tracepoint/sock/inet_sock_set_state")`. They read `bytes_received`/`bytes_sent` from `tcp_sock` via CO-RE — [caretta.bpf.c](https://github.com/groundcover-com/caretta/blob/main/pkg/tracing/ebpf/caretta.bpf.c)
  - The blog explains that `tcp_data_queue` was chosen as the "sweet spot" between "being too nosy and being blind". It is called from `tcp_rcv_established` — [Caretta blog](https://www.groundcover.com/blog/caretta)
  - Caretta also notes that `sock` structs are reused by the kernel, which "can lead to collisions and disinformation" if lifecycle is not tracked — [Caretta blog](https://www.groundcover.com/blog/caretta)
  - Caretta requires kernel ≥ 4.16 and CO-RE — [README](https://github.com/groundcover-com/caretta)
- OBI `network.source`: `socket_filter` (default) or `tc` (direct-action ingress/egress filters, which conflict with Cilium).
  - Flows accumulate in a cache: `cache_max_flows` 5000, `cache_active_timeout` 5s.
  - Optional 1-in-N packet `sampling`.
  - Source: [OBI network config](https://opentelemetry.io/docs/zero-code/obi/network/config/)
  - OBI requires kernel 5.8+, or RHEL-family 4.18+ with eBPF backports, and BTF — [OBI docs](https://opentelemetry.io/docs/zero-code/obi/). Beyla's README says RHEL 4.18 build 348+ kernels (CentOS, AlmaLinux, Oracle Linux) have the needed backports — [Beyla README](https://github.com/grafana/beyla)

### Inferences
- shawk's design (state-change tracepoint plus socket iterators, bundling in the kernel, 15 s reads) sits on the cheap end, like Coroot: cost scales with connection churn, not packet rate.
  - The open question is how shawk counts bytes and retransmits without per-packet hooks: reading `tcp_sock` counters via iterator at interval, or at close?
  - Caretta's per-segment `tcp_data_queue` kprobe and OBI's per-packet filters are the costlier alternatives.
- Caretta's warning about `sock` pointer reuse applies to any design keyed by `skaddr`, as Coroot's PID map is. shawk should clear map entries on TCP_CLOSE to avoid this.
- Rocky Linux 9 ships kernel 5.14 with BTF, so it satisfies every tool's minimum, including OBI's 5.8+/BTF requirement.

### Gaps
- No quantitative overhead claims (CPU % or memory per node) for the network-map features of Coroot, Caretta or OBI were found in the fetched primary sources.
- OBI StatsO11y hook points (presumably tracepoints and kprobes, given the per-PID attribution caveat) were not confirmed.

---

## Q9. Project status as of late 2026

### Takeaway
- **Coroot**: active.
- **Caretta**: dormant. Last push March 2025, no releases, chart still 0.0.1, but not archived.
- **Beyla**: donated to OpenTelemetry as **OBI**. Beyla now vendors OBI and is effectively Grafana's distribution. OBI is pre-1.0 (v0.15.x in docs) with a stable 1.0 as its 2026 goal.
- **Kiali**: active (v2.x; docs mention features in ≥ 2.23).
- **Collector `servicegraph` connector**: still **alpha**, renamed `service_graph`.
- **Tempo metrics-generator service graphs**: active, gaining features such as `connection_info`.

### Cited Findings
- Repository push dates and archive status, from ecosyste.ms snapshots synced October 2026:
  - groundcover-com/caretta: last pushed 2025-03-17, not archived, no tags — [ecosyste.ms caretta](https://repos.ecosyste.ms/api/v1/hosts/GitHub/repositories/groundcover-com%2Fcaretta)
  - coroot/coroot-node-agent: last pushed 2026-09-16 — [ecosyste.ms coroot-node-agent](https://repos.ecosyste.ms/api/v1/hosts/GitHub/repositories/coroot%2Fcoroot-node-agent)
  - grafana/beyla: last pushed 2026-10-29 — [ecosyste.ms beyla](https://repos.ecosyste.ms/api/v1/hosts/GitHub/repositories/grafana%2Fbeyla)
  - open-telemetry/opentelemetry-ebpf-instrumentation: last pushed 2026-10-16 — [ecosyste.ms OBI](https://repos.ecosyste.ms/api/v1/hosts/GitHub/repositories/open-telemetry%2Fopentelemetry-ebpf-instrumentation)
  - kiali/kiali: last pushed 2026-10-16 — [ecosyste.ms kiali](https://repos.ecosyste.ms/api/v1/hosts/GitHub/repositories/kiali%2Fkiali)
- Caretta's GitHub page shows no archive banner or maintenance notice, 151 commits and no releases — [GitHub caretta](https://github.com/groundcover-com/caretta). The chart is `version: 0.0.1`, `appVersion: v0.0.1` — [chart/Chart.yaml](https://github.com/groundcover-com/caretta/blob/main/chart/Chart.yaml)
- Beyla README: "Beyla has been donated to the CNCF OpenTelemetry Project, under the project name OpenTelemetry eBPF Instrumentation or OBI… All Beyla current maintainers work full time on the upstream repository". Beyla vendors OBI as a Git submodule (`.obi-src`) — [Beyla README](https://github.com/grafana/beyla) (donation tracked in [open-telemetry/community#2406](https://github.com/open-telemetry/community/issues/2406))
- OBI README: "OBI is currently in Development. Users should expect breaking changes between minor releases while the project remains in `v0`" — [OBI README](https://github.com/open-telemetry/opentelemetry-ebpf-instrumentation). The docs reference v0.15.2 upgrade notes — [OBI docs](https://opentelemetry.io/docs/zero-code/obi/)
- OBI 2026 goals: "Achieving a stable 1.0 release is our flagship goal for 2026", along with protocol expansion, .NET and hybrid instrumentation — [OTel blog: OBI 2026 Goals](https://opentelemetry.io/blog/2026/obi-goals/)
- A secondary source claims OBI v0.8.0 shipped on 2026-04-16 with a KubeCon EU 2026 "beta" announcement. This is a third-party post, so treat it with caution — [DEV Community post](https://dev.to/x4nent/opentelemetry-ebpf-instrumentation-obi-the-complete-guide-kubecon-eu-2026-beta-launch-5e2o)
- Collector connector: stability "alpha" for traces→metrics. "The component type has been renamed from `servicegraph` to `service_graph`. The old name still works but is deprecated" — [connector README](https://github.com/open-telemetry/opentelemetry-collector-contrib/tree/main/connector/servicegraphconnector)
- The Tempo docs page carries 2026-era features (`connection_info` subprocessor, tracestate span multiplier). Grafana's Tempo service-graph page shows `review_date: 2026-09-10` — [Grafana Tempo service graph doc source](https://github.com/grafana/grafana/blob/main/docs/sources/datasources/tempo/service-graph.md)

### Inferences
- For the review: Caretta is useful as a design reference, especially for Node Graph via PromQL and the role heuristic, but should not be presented as a live alternative.
- OBI is the vendor-neutral option to watch. Its `obi_stat_tcp_*` metrics overlap shawk's numeric set. If OBI reaches 1.0 with StatsO11y on non-K8s hosts, a reviewer could ask whether shawk's TSDB path should align with OBI's metric and attribute names, for example `src.address`/`dst.address`/`transport`, for interoperability.

### Gaps
- The exact latest release tags and dates for Coroot, OBI, Beyla and Kiali could not be retrieved. GitHub release feeds and the API were blocked in this environment, and ecosyste.ms returned no tags.

---

## Q10. Comparison against shawk's proposed design (synthesis for the reviewer)

### Takeaway
- shawk's in-kernel bundling key (server-port-based, ephemeral port dropped) and its TCP-state-change hooks match the Coroot and Caretta approach.
- Its OTLP/Prometheus metric path matches OBI's export model.
- Its PostgreSQL relation store with `first_seen`/`last_seen` and address history has **no counterpart** in the five tools. All of them derive topology from TSDB series at query time.
- The main gaps relative to prior art:
  - NAT "actual destination" resolution (Coroot)
  - explicit idle-series TTL (Coroot 10 min; Tempo and the connector 15 min)
  - configurable named-CIDR collapse and attribute selection (OBI)
  - a cap on per-service peer cardinality (Coroot's FQDN cap)

### Cited Findings
- Coroot keys on `destination` and `actual_destination`, skips ephemeral ports (32768–60999), and garbage-collects idle destinations after 10 min — [container.go](https://github.com/coroot/coroot-node-agent/blob/main/containers/container.go), [flags.go](https://github.com/coroot/coroot-node-agent/blob/main/flags/flags.go)
- Caretta's link key is (client, server, server_port, role); its cumulative gauge never expires — [types.go](https://github.com/groundcover-com/caretta/blob/main/pkg/caretta/types.go), [caretta.go](https://github.com/groundcover-com/caretta/blob/main/pkg/caretta/caretta.go)
- OBI hides addresses and ports by default, uses named CIDRs with a `0.0.0.0/0` catch-all, and offers per-metric include/exclude — [OBI metrics](https://opentelemetry.io/docs/zero-code/obi/metrics/), [OBI network config](https://opentelemetry.io/docs/zero-code/obi/network/config/)
- Tempo's presence gauge exists for rare edges — [Tempo service graphs](https://grafana.com/docs/tempo/latest/metrics-from-traces/service_graphs/)
- Kiali builds its graph at query time with a storage-less backend — [Kiali architecture](https://kiali.io/docs/architecture/architecture/), [istio.go](https://github.com/kiali/kiali/blob/master/graph/telemetry/istio/istio.go)

### Inferences
Questions the reviewer could raise against shawk, each grounded in prior art above:
1. **Identity resolution location.** shawk resolves `peer_service` in the agent from Postgres. Coroot resolves centrally at query time by joining with listen_info.
   - Agent-side stamping, as in Caretta, OBI and Istio, makes series immutable snapshots of a mapping that may later change.
   - Option: keep `peer_addr` plus port in the TSDB and resolve `peer_service` at query time in Grafana via a Postgres lookup. Or accept label churn and document it.
2. **Double counting.** Both endpoints report the same edge, as Caretta's `role` does. Dashboards need a convention, for example count bytes only from `direction="outbound"` and fall back to inbound when the client host has no agent.
3. **NAT.** Add an optional conntrack lookup (Netlink) at connect time to populate an `actual_remote_addr`, as Coroot does. VIPs and remote load balancers need a Postgres-maintained mapping table.
4. **Series lifecycle.** Define a TTL (10–15 min is the norm) after which idle flows stop being exported. Separately, Postgres `last_seen` keeps rare dependencies visible indefinitely. This combination is better than any single tool.
5. **External collapse.** Generalize "external" into named CIDR groups with a catch-all, as OBI does. Optionally keep DNS-derived names (Coroot's `ip_to_fqdn` with a per-container cap and `~other`) in Postgres rather than in TSDB labels.
6. **Node Graph.** Postgres-fed Node Graph avoids Caretta's "PromQL witchcraft". Rates on edges require either cross-datasource joins in Grafana or periodic rate snapshots written into Postgres.
7. **Alerting content.** Ship opinionated rule templates, as Coroot's inspections and Kiali's health thresholds do, instead of leaving all alerting to users. Postgres enables a "new dependency" alert that none of the five tools offers.
8. **Pre-existing connections and long-lived connections.** Coroot scans `/proc/net/tcp` plus fds at startup and uses an active-connections gauge. shawk's socket iterators plus "open connections" gauge are equivalent. Clear map entries on close because of `sock` pointer reuse, which Caretta warns about.

### Gaps
- No head-to-head overhead benchmarks exist among these tools in the primary sources reviewed. Any overhead comparison in the review would need shawk's own measurements.
