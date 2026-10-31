# Topology/relationship storage and history in observability and dependency-mapping tools

Scope: where DeepFlow, Pixie, Apache SkyWalking, Weave Scope, Dynatrace Smartscape, Datadog, New Relic, the OpenTelemetry Entities spec and VM/on-prem ADM tools (ServiceNow, Azure Migrate, Device42, Faddom) store relationships, how they keep history, and how relationships are joined with metrics. Context: shawk plans relations in PostgreSQL (upserts with least/greatest first_seen/last_seen) and numeric series via OTLP to a Prometheus-compatible TSDB, with Grafana as the only UI. Research date 2026-10-31. Where a fact comes from source code or a mirror rather than official docs, that is stated.

## 1. Where is topology stored, and with what data model?

### Takeaway
None of the open-source eBPF tools keeps a separate "relationship table" with first/last seen. DeepFlow, SkyWalking and Pixie store edges as time-bucketed metric or flow rows in the same store as their metrics and rebuild the graph for each query time range. DeepFlow also keeps entity metadata (VMs, K8s resources) in MySQL, separate from ClickHouse. Dynatrace and New Relic keep a dedicated entity/relationship model with lifetime or TTL semantics, and ServiceNow keeps one in CMDB tables. In all three, telemetry points to entities by ID. shawk's design (relational entity/edge store plus a separate TSDB) is closest to these commercial and CMDB designs, and to DeepFlow's split between MySQL metadata and ClickHouse data.

### Cited Findings
**DeepFlow (active; ClickHouse plus MySQL)**
- DeepFlow uses two storage components: "`mysql` stores metadata obtained from the deployed cluster, such as virtual machines, K8S resources, and synchronized collector information. `clickhouse` stores real-time collected data, such as network flow logs ... and performs aggregation and analysis." — [DeepFlow FAQ](https://deepflow.io/docs/diagnose/FAQ) (source: [deepflowio/docs 09-diagnose/01-FAQ.md](https://github.com/deepflowio/docs/blob/main/docs/translate/translated/09-diagnose/01-FAQ.md))
- ClickHouse data categories:
  - `flow_log.l4_flow_log`: TCP/UDP five-tuple flow logs, about 150 bytes per row.
  - `flow_log.l7_flow_log`: call logs, about 70 bytes per row.
  - `flow_metrics`: metrics aggregated from flow and call logs at 1m and 1s resolution, about 1/10 of the log storage.
  - Tables observed in a sample system: `flow_metrics.network_map.1s/1m`, `application_map.1s/1m`, `network.1s/1m` and `application.1s/1m`. The `*_map` tables hold the edges (client→server).
  — [DeepFlow: Reducing Storage Overhead](https://deepflow.io/docs/best-practice/reduce-storage-overhead/)
- Edge rows carry tags for both sides. Client-side tags use the suffix `_0`, for example "client IP address (`ip_0`)", and server-side tags use `_1`. — [DeepFlow: Metrics and Operators](https://deepflow.io/docs/features/universal-map/metrics-and-operators)
- Every metric is aggregated from per-Flow state (one per TCP connection or L7 request) into 1s and 1min data, which "draw a universal map of interactions between any services". eBPF observation points are labeled `observation_point` = `c-p` (client process) or `s-p` (server process). — [DeepFlow AutoMetrics](https://deepflow.io/docs/features/universal-map/auto-metrics)
- Tag dictionaries live in a ClickHouse `flow_tag` database and are resolved with `dictGet`, for example `dictGet(flow_tag.int_enum_map, 'name_zh', ('l7_protocol', toUInt64(l7_protocol)))` and `flow_tag.string_enum_map`. — [DeepFlow: Reducing Storage Overhead](https://deepflow.io/docs/best-practice/reduce-storage-overhead/)
- The server's flow_tag ingester writes to database `flow_tag`, or `<OrgId>_flow_tag` for other orgs, and keeps an LRU cache that maps tag info to `uint32` IDs. This is a secondary source (Go docs of a fork). — [pkg.go.dev flow_tag](https://beta.pkg.go.dev/github.com/khulnasoft/deepflow/server/ingester/flow_tag)
- Server modules: Controller (agent management, tag sync), Labeler ("Calculates unified attribute tags for all observability signals"), Ingester (writes ClickHouse, exports to otel-collector) and Querier (unified SQL/PromQL). — [DeepFlow Architecture](https://deepflow.io/docs/about/architecture)
- The SQL interface "can be used as a Grafana DataSource". DeepFlow "Provides Grafana Datasource and Panel". — [DeepFlow Architecture / features docs](https://github.com/deepflowio/docs/tree/main/docs/translate/translated)
- Process-level tagging on VMs and bare metal is optional:
  - `os-proc-sync-enabled` defaults to false and applies only to agent types CHOST_VM, CHOST_BM, K8S_VM and K8S_BM.
  - `os-proc-socket-sync-interval` defaults to 10 s and `os-proc-socket-min-lifetime` to 3 s.
  - `os-app-tag-exec` can attach per-PID tags from a command's YAML output.
  - By default the finest granularity of `auto_instance` is "the container Pod or cloud server to which the IP address belongs".
  — [DeepFlow: Process tags](https://deepflow.io/docs/features/auto-tagging/process-tags)
- Since 2025-04-28 DeepFlow "Aggregate[s] processes with the same `cmdline` within the same cloud host or the same K8s workload into a unique gprocess". — [DeepFlow 7.0 CE release notes](https://deepflow.io/docs/release-notes/release-7.0-ce)

**Pixie (in-memory, in-cluster)**
- Each `vizier-pem` pod reserves 60% of its memory for short-term data storage by default. With the default 2Gi limit that is 1.2Gi. Each table (for example `http_events`) has its own maximum size and "begin[s] dropping the oldest data" when full. Data leaves the cluster only through a plugin or the Pixie API. — [Pixie: Tuning memory usage](https://docs.px.dev/reference/admin/tuning-mem-usage)
- `conn_stats` "contains statistics on the communications made between client-server pairs". Network-level data is in `network_stats`. — [Pixie conn_stats](https://docs.px.dev/reference/datatables/conn_stats/)
- The service graph is computed at query time by PxL. `px/net_flow_graph` reads `conn_stats`, resolves the remote address with `px.nslookup`, and sums bytes. Rows carry a `upid` from which namespace, service, pod, container and command are inferred. Graph widgets need a `fromColumn` and a `toColumn`. — [Pixie Script of the Week 1](https://docs.px.dev/tutorials/pxl-scripts/script-of-the-week/script-of-the-week-1); [Custom PxL scripts](https://docs.px.dev/tutorials/pxl-scripts/write-pxl-scripts/custom-pxl-scripts-2)

**Apache SkyWalking (OAP; BanyanDB default)**
- Topology edges are stored as relation metrics. `service_relation_server_side` (class `ServiceRelationServerSideMetrics`) has the columns `source_service_id`, `dest_service_id`, `component_ids` and `entity_id`. `entity_id` is the BanyanDB `SeriesID`. The class is annotated `@MetricsExtension(supportDownSampling = true, supportUpdate = true, timeRelativeID = true)`. A matching `service_relation_client_side` exists. — [SkyWalking source: ServiceRelationServerSideMetrics.java](https://github.com/apache/skywalking/blob/master/oap-server/server-core/src/main/java/org/apache/skywalking/oap/server/core/analysis/manual/relation/service/ServiceRelationServerSideMetrics.java)
- Process-level edges for Rover use `ProcessRelationServerSideMetrics` (scope `PROCESS_RELATION`), with columns `service_instance_id`, `source_process_id`, `dest_process_id`, `entity_id` and `component_id`. — [SkyWalking source: ProcessRelationServerSideMetrics.java](https://github.com/apache/skywalking/blob/master/oap-server/server-core/src/main/java/org/apache/skywalking/oap/server/core/analysis/manual/relation/process/ProcessRelationServerSideMetrics.java)
- The topology is assembled at query time. `TopologyQueryService.getGlobalTopology(Duration, layer)` calls `loadServiceRelationsDetectedAtServerSide…` and `loadServiceRelationDetectedAtClientSide…` for the requested duration. Matching methods exist for instance, endpoint and process topology (`getProcessTopology(instanceId, duration)`). — [SkyWalking source: TopologyQueryService.java](https://github.com/apache/skywalking/blob/master/oap-server/server-core/src/main/java/org/apache/skywalking/oap/server/core/query/TopologyQueryService.java)
- Scope definitions:
  - `ServiceRelation` groups by `sourceServiceName`, `destServiceName`, instance, layer, `componentId` and `detectPoint` (client/server/proxy).
  - `TCPServiceRelation` adds `receivedBytes` and `sentBytes`.
  - `K8SServiceRelation` and `K8SServiceInstanceRelation` are "derived from Kubernetes monitoring by Rover (eBPF)".
  — [SkyWalking Scope Definitions](https://skywalking.apache.org/docs/main/latest/en/concepts-and-designs/scope-definitions/)
- Rover's network profiling builds topology "Based on the process and peer address": relations between local processes, or between a local process and external pods or services. OAP chooses the pods to monitor and fetches K8s metadata, and MAL aggregates the results. The feature is pod- and on-demand-oriented. — [SkyWalking K8s Network monitoring](https://skywalking.apache.org/docs/main/next/en/setup/backend/backend-k8s-network-monitoring); [Rover overview](https://skywalking.apache.org/docs/skywalking-rover/latest/en/concepts-and-designs/overview)
- Storage options:
  - BanyanDB is the default (`${SW_STORAGE:banyandb}`).
  - MySQL and PostgreSQL are "recommended for production environments for medium-scale deployments".
  - Elasticsearch and OpenSearch are for "large-scale deployments", at high resource cost.
  — [SkyWalking Backend Storage](https://skywalking.apache.org/docs/main/latest/en/setup/backend/backend-storage/)
- BanyanDB data model: groups whose catalog is MEASURE, STREAM, TRACE or PROPERTY. Measure has tags and fields, and its "index mode" (tags only, inverted index) suits non-time-series data but needs a TTL. Property is a schema-less document keyed by group/name/id. — [BanyanDB Data Model](https://skywalking.apache.org/docs/skywalking-banyandb/latest/concept/data-model)

**Weave Scope (deprecated, no longer maintained)**
- The README is titled "DEPRECATED" and says "PLEASE NOTE, THIS PROJECT IS NO LONGER MAINTAINED". The last commit on `master` is "Add deprecation notice (#3917)", dated 2023-06-13. — [weaveworks/scope](https://github.com/weaveworks/scope) (commit date from a local clone)
- Model: the probe sends a `Report` to the app.
  - The `Endpoint` topology holds "(address, port) tuples on each host ... Edges are present".
  - Process, Container, Pod, Service and other topologies have nodes with "Edges are not present".
  - Each `Node` has `Adjacency IDList` and a `Latest` map.
  - Endpoint node IDs are `MakeEndpointNodeID(hostID, namespaceID, address, port)`.
  — [scope/report/report.go](https://github.com/weaveworks/scope/blob/master/report/report.go); [report/node.go](https://github.com/weaveworks/scope/blob/master/report/node.go); [report/id.go](https://github.com/weaveworks/scope/blob/master/report/id.go)
- The app "processes reports from the probe into usable topologies" and merges reports from all probes. — [scope/site/how-it-works.md](https://github.com/weaveworks/scope/blob/master/site/how-it-works.md)
- The multitenant (Weave Cloud) backend had S3, memcache and Consul clients. — [scope/app/multitenant](https://github.com/weaveworks/scope/tree/master/app/multitenant)

**Dynatrace Smartscape on Grail**
- Nodes and edges are stored in Grail.
  - Node `id` is the type plus a 16-symbol number (`ENTITY_TYPE-000000000000007B`). Nodes also have `type`, `lifetime.start` ("the first time when the node was discovered"), `lifetime.end` ("the time when the node was last observed"), `tags`, `references` (static edges) and `id_classic`.
  - Edges store an edge type (`runs_on`, `calls`, `relates_to`) and two node IDs.
  - Static edges inherit the node's lifetime. Dynamic edges are "recorded for a specific point in time", for example a trace-based service call.
  — [Dynatrace: Smartscape on Grail](https://docs.dynatrace.com/docs/discover-dynatrace/platform/grail/smartscape-on-grail)
- DQL has `smartscapeNodes`, `smartscapeEdges` and `traverse`, for example `smartscapeNodes PROCESS | traverse runs_on, HOST, direction: forward`. Each hop is recorded in `dt.traverse.history`. — [Dynatrace Smartscape commands](https://docs.dynatrace.com/docs/platform/grail/dynatrace-query-language/commands/smartscape-commands)

**Datadog Cloud Network Monitoring**
- "Connection data at the IP, port, and PID levels is aggregated into application-layer dependencies between meaningful client and server endpoints". The Network Map shows traffic between tags such as `service`, `kube_service`, `short_image` and `container_name`. Flows that cannot be tied to tags appear as "N/A" or unresolved. — [Datadog CNM](https://docs.datadoghq.com/network_monitoring/cloud_network_monitoring); [CNM Glossary](https://docs.datadoghq.com/es/network_monitoring/cloud_network_monitoring/glossary)

**New Relic**
- Entities are synthesized from telemetry by per-type definition files. For example, "when two services that communicate using HTTP are instrumented ... we infer a 'calls/called-by' relationship". Relationships are read through NerdGraph `relatedEntities`. — [New Relic: What is an entity](https://docs.newrelic.com/docs/new-relic-solutions/new-relic-one/core-concepts/what-entity-new-relic/); [NerdGraph relationships tutorial](https://docs.newrelic.com/jp/docs/apis/nerdgraph/examples/nerdgraph-relationships-api-tutorial)

### Inferences
- Two patterns emerge:
  - (a) Edges as time-bucketed metric rows in the same store as the metrics, with topology reduced at query time: DeepFlow `*_map` tables, SkyWalking `*_relation_*`, Pixie `conn_stats`, Datadog CNM.
  - (b) A dedicated entity/relationship graph with lifetimes or TTLs, which telemetry references by ID: Dynatrace Smartscape, New Relic, ServiceNow CMDB, OTel Entities.
  - shawk's PostgreSQL relations store is pattern (b). Its PG `edges` table keeps first/last seen, not per-bucket rows. That makes it cheap but loses "was the edge active in bucket X" unless the TSDB series answers that.
- DeepFlow is the closest open-source analogue, and it already splits relational (MySQL: VMs, K8s resources, agents) from columnar (ClickHouse: flows and edge metrics). shawk's split is therefore not unusual. The difference is that DeepFlow keeps edges with the metrics, while shawk keeps them in the relational side.
- SkyWalking can run entirely on MySQL or PostgreSQL. There, relation rows are per-time-bucket metric rows with TTL, not first/last-seen rows.

### Gaps
- No primary documentation found on DeepFlow's exact `network_map` column list or the MySQL schema for resources. The docs repo has no schema reference; the deepflow server source would be needed.
- Datadog's storage backend for the service map and CNM dependencies is not publicly documented. The Universal Service Monitoring service-map internals were not found.
- Faddom's and Device42's storage internals are not publicly documented (see Q6).

## 2. How is relationship history kept (first/last seen, time travel, retention, change detection)?

### Takeaway
Only Dynatrace documents explicit first/last-seen semantics: node `lifetime.start`/`lifetime.end`, plus dynamic edges stamped per time, with fixed 35-day retention. Tools that store edges as metric rows get time travel implicitly by re-aggregating any window, but only within short retention (DeepFlow 1 day at 1s and 7 days at 1m; SkyWalking 7 days of metrics; Pixie hours; Scope 15 s). New Relic and the OTel entity events spec use TTL or heartbeat expiry rather than history. Explicit "new dependency" alerting is rarely documented.

### Cited Findings
- **Dynatrace**:
  - `lifetime.end` updates with each upsert while a node is observed.
  - Nodes appear in a query if their lifetime overlaps the query timeframe.
  - "dynamic edges are included in query results based on a timeframe when the edge was recorded".
  - "Query timeframes that start less than 15 minutes in the past are automatically extended to 15 minutes".
  - "Data retention is fixed at 35 days". Nodes whose `lifetime.end` is older than that are deleted with their static edges, and dynamic edges are also cleaned up after 35 days.
  — [Dynatrace Smartscape on Grail](https://docs.dynatrace.com/docs/discover-dynatrace/platform/grail/smartscape-on-grail)
- **DeepFlow**: for `flow_metrics` and `flow_log` tables, "minute-granularity data is retained for 1 week by default, and second-granularity data is retained for 1 day by default". System monitoring data and PCAP are kept 1 week. — [DeepFlow data-node guide](https://deepflow.io/docs/guide/ee-tenant/system/data-node/)
- DeepFlow's TTLs are set in `server.yaml` and should be adjusted "before the first deployment". `ext-metrics-ttl`, `flow-metrics-ttl` and `flow-log-ttl` were added in 6.1. — [DeepFlow FAQ](https://deepflow.io/docs/diagnose/FAQ); [DeepFlow 6.1 CE release notes](https://deepflow.io/docs/release-notes/release-6.1-ce)
- **SkyWalking**: `metricsDataTTL` defaults to 7 days and "applies to all metrics for service, instance, endpoint, and topology map" (metadata included). `recordDataTTL` defaults to 3 days. With BanyanDB, TTL is configured per group in `storage.banyandb` (progressive TTL) instead. — [SkyWalking TTL doc](https://github.com/apache/skywalking/blob/master/docs/en/setup/backend/ttl.md)
- SkyWalking 10.3.0 adopted BanyanDB 0.9.0's trace model and hot/warm/cold stages. — [SkyWalking 2025 in Review](https://skywalking.apache.org/blog/2026-01-01-skywalking-2025-year-in-review/)
- **Pixie**: "Retention time depends on the level of traffic in your cluster, but will generally be on the order of hours". — [Pixie: Tuning memory usage](https://docs.px.dev/reference/admin/tuning-mem-usage); [Pixie FAQ](https://docs.px.dev/about-pixie/faq)
- **Weave Scope**: probe spy interval 1 s, publish interval 3 s, a full report every 3 publishes (deltas in between), app `window` 15 s. There is no historical store in single-node mode. — [scope/prog/main.go](https://github.com/weaveworks/scope/blob/master/prog/main.go)
- **New Relic**: relationship synthesis rules have an `expires` field (ISO-8601, e.g. `P75M`). The default is 75 minutes and the allowed range is 10 minutes to 72 hours. This comes from a community mirror of the entity-definitions repo, so treat it as unverified against the official repo. — [entity-definitions relationship_synthesis.md (mirror)](https://github.com/thezackm/entity-definitions/blob/main/docs/relationships/relationship_synthesis.md)
- New Relic entity records expire per type via `entityExpirationTime`. This "solely impacts the record of the entity itself and not the associated telemetry data". — [New Relic: What is an entity](https://docs.newrelic.com/docs/what-entity-new-relic); [entity lifecycle (mirror)](https://github.com/thezackm/entity-definitions/blob/main/docs/entities/lifecycle.md)
- **OTel entity events**: `entity.report.interval` (int64 seconds) lets receivers "infer that an entity is gone if events stop arriving". Delete events are not guaranteed. — [OTel Entity Events spec](https://opentelemetry.io/docs/specs/otel/entities/entity-events/)
- The OTel blog recommends storing entity events "as an append-only, event-sourced log" replayed into a live graph. It also recommends collapsing consecutive unchanged observations while "keeping the first and last of each run", and keeping relationship appear/disappear changes. — [OTel blog: What can you do with OpenTelemetry entity events?](https://opentelemetry.io/blog/2026/consuming-opentelemetry-entity-events/)
- **ServiceNow** recommends using traffic-based discovery "at the initial stages" and turning it off after discovery and fine-tuning, which treats traffic-derived edges as bootstrap data rather than continuously maintained history. — [ServiceNow: Traffic-based discovery in Service Mapping](https://www.servicenow.com/docs/bundle/washingtondc-it-operations-management/page/product/service-mapping/concept/traffic-based-discovery.html)
- **Change detection as a use case**:
  - Datadog CNM lists "Pinpoint unexpected or latent service dependencies". — [Datadog CNM](https://docs.datadoghq.com/network_monitoring/cloud_network_monitoring)
  - A third-party comparison says Faddom has "tracked searches for monitoring topology changes over time". — [Virima on Faddom](https://virima.com/blog/faddom-solution-overview-top-alternatives)

### Inferences
- shawk's `first_seen`/`last_seen` with least/greatest upserts matches Dynatrace's `lifetime.start`/`lifetime.end` semantics and the OTel blog's "first and last of each run" coalescing. That is a recognized pattern, not an oddity.
- Dynatrace's distinction between static and dynamic edges is useful for shawk:
  - Listener and host↔address ownership resemble static or lifetime-scoped facts.
  - Process→service connections resemble dynamic edges.
  - A single first/last-seen range cannot represent gaps, such as an edge active in January, absent in February and back in March. Dynatrace's per-time dynamic edges and SkyWalking's per-bucket rows can.
- If shawk needs "was this dependency active during window W", a periodic presence table (for example a daily edge-activity row) or the TSDB series would be needed alongside first/last seen.
- Retention in the OSS tools is short (days). Long-lived relationship history (months, for migration or decommission questions) is something the CMDB/ADM tools and Dynatrace (35 days) cover better. A relational store with first/last seen retains this indefinitely at low cost, which is an argument in shawk's favor.
- None of the surveyed products documents a first-class "new dependency" event in detail. A `dependency_changes` view (edges whose `first_seen` falls in the window) is a differentiator rather than a standard feature.

### Gaps
- No documentation found on whether DeepFlow or SkyWalking emit "new edge" alerts. SkyWalking alarms operate on metrics; nothing on topology diffs was found.
- No documentation found on Dynatrace alerting on new Smartscape edges.
- Faddom's and Device42's history retention periods are undocumented publicly.

## 3. How are the relationship store and the metrics store joined at query time?

### Takeaway
Every surveyed system joins through shared IDs or tags carried on each telemetry row:
- DeepFlow: integer-encoded tags plus ClickHouse dictionaries, in one SQL/PromQL querier.
- SkyWalking: the relation `entity_id`, used as the series ID.
- Dynatrace: `dt.smartscape.<type>` node IDs on signals.
- Pixie: `upid` to metadata.
- Datadog: unified tags.
- New Relic: entity GUIDs.
- OTel: entity identifying attributes that reference Resource attributes.

None relies on a cross-database join between a relational DB and a TSDB. shawk's PostgreSQL↔Prometheus split would need a deliberate label convention, plus Grafana-side joins or transformations.

### Cited Findings
- **DeepFlow SmartEncoding** works in three stages:
  - The agent injects VPC (int), IP and PID.
  - At storage time, "the Server, based on the VPC, IP, and PID tags marked by the Agent, automatically injects a small number of Int-encoded meta tags", covering cloud, K8s and process attributes.
  - At query time, "the Server automatically calculates the associations between all custom tags and meta tags" so users query through SQL/PromQL as if on "a BigTable".
  - Custom tags (K8s labels, annotations, env, cloud tags, CMDB tags) are "not ... stored coupled with observability data" and are described as having "zero storage overhead".
  — [DeepFlow SmartEncoding](https://deepflow.io/docs/features/auto-tagging/smart-encoding) (source: [deepflowio/docs 02-smart-encoding.md](https://github.com/deepflowio/docs/blob/main/docs/translate/translated/05-features/05-auto-tagging/02-smart-encoding.md))
- DeepFlow's Querier provides "a unified SQL/PromQL interface to query all types of observability data". The SQL API can be used as a Grafana DataSource. — [DeepFlow Architecture](https://deepflow.io/docs/about/architecture)
- **SkyWalking**: relation metrics share the `entity_id` of the relation row. `entity_id` is annotated `@BanyanDB.SeriesID`. Topology and its metrics live in the same storage and module. — [ServiceRelationServerSideMetrics.java](https://github.com/apache/skywalking/blob/master/oap-server/server-core/src/main/java/org/apache/skywalking/oap/server/core/analysis/manual/relation/service/ServiceRelationServerSideMetrics.java)
- Relation metrics such as `service_relation_server_cpm` are defined in OAL by filtering on `detectPoint`. Secondary source: a SkyWalking PR mail archive. — [SkyWalking PR #3978 discussion](https://www.mail-archive.com/notifications@skywalking.apache.org/msg28056.html)
- **Dynatrace**: "Signal fields starting with `dt.smartscape.__type__` contain Smartscape IDs" and show which node a signal came from. Enrichment uses `getNodeName(...)` and `getNodeField(..., "tags")`. — [Dynatrace Smartscape on Grail](https://docs.dynatrace.com/docs/discover-dynatrace/platform/grail/smartscape-on-grail)
- **Pixie**: each `conn_stats` row has a `upid`, from which PxL infers namespace, service, pod, container and command. — [Pixie conn_stats](https://docs.px.dev/reference/datatables/conn_stats/)
- **Datadog CNM** groups connections by tags (`service`, `kube_service`, `short_image`, `container_name`). — [Datadog CNM Glossary](https://docs.datadoghq.com/es/network_monitoring/cloud_network_monitoring/glossary)
- **OTel**: entity "identifying and descriptive attributes reference shared attributes defined in the Resource", for OTLP 1.x compatibility. — [OTel Entity Data Model](https://opentelemetry.io/docs/specs/otel/entities/data-model/)

### Inferences
- shawk should make the edge identity in PostgreSQL derivable from Prometheus labels, for example `service.name`, `systemd unit`, `host.id`, peer address and port, and direction. That lets Grafana panels join the two. This is the equivalent of SkyWalking's `entity_id`, Dynatrace's `dt.smartscape.*` and DeepFlow's int tag IDs.
- DeepFlow's lesson is to carry only small stable IDs on high-volume series and resolve descriptive attributes (unit description, exe, version) from a dictionary at query time. For shawk, that argues against putting exe or version labels on every Prometheus series, and for keeping them in PostgreSQL.
- Grafana-only UI: DeepFlow ships its own Grafana datasource and panel to hide the join. With stock Grafana, shawk would rely on the PostgreSQL datasource for the graph (Node Graph panel) and Prometheus for metrics. The join is limited to Grafana transformations or dashboard variables.

### Gaps
- No public source quantifies Grafana Node Graph scale limits for this use. Not researched here.
- The exact DeepFlow Grafana plugin name and version status in 2026 was not verified.

## 4. How is identity handled (process, service, container, host; IP reuse; point-in-time resolution)?

### Takeaway
The OSS tools key identity on (network/VPC, IP, PID) or (host, netns, addr, port) and resolve to higher-level entities either at write time (DeepFlow injects int tags at ingest) or at query time (Pixie `upid` lookups, SkyWalking K8s metadata). The OTel spec formalizes immutable identifying attributes versus mutable descriptive attributes, and the OTel blog explicitly recommends `process.pid` plus `process.creation.time`. IP reuse over time is rarely documented explicitly.

### Cited Findings
- DeepFlow agent tags carry VPC (integer), IP and PID. The server maps these to cloud, K8s and process resources at storage time. — [DeepFlow SmartEncoding](https://deepflow.io/docs/features/auto-tagging/smart-encoding)
- By default DeepFlow's `auto_instance` resolves to the Pod or cloud server owning the IP. Process-level identity needs `os-proc-sync-enabled`. — [DeepFlow process tags](https://deepflow.io/docs/features/auto-tagging/process-tags)
- DeepFlow's "gprocess" collapses processes with the same cmdline within a host or workload into one identity. — [DeepFlow 7.0 CE release notes](https://deepflow.io/docs/release-notes/release-7.0-ce)
- Weave Scope endpoint identity is (hostID, network namespace ID, address, port). — [scope/report/id.go](https://github.com/weaveworks/scope/blob/master/report/id.go)
- OTel identity rules:
  - ID attributes "MUST not change during the lifetime of the entity".
  - Observers reporting the same entity must supply identical identifying values; if they can't, they must not emit that entity type.
  - Descriptive attributes "MAY change over the lifetime of the entity".
  — [OTel Entity Data Model](https://opentelemetry.io/docs/specs/otel/entities/data-model/)
- The OTel blog:
  - Put changing facts such as current IP in descriptive attributes.
  - Identify processes by `process.pid` plus `process.creation.time` "since a PID can be recycled".
  - "Prefer failing loudly over silently merging distinct entities".
  — [OTel blog 2026](https://opentelemetry.io/blog/2026/consuming-opentelemetry-entity-events/)
- Dynatrace node IDs are opaque type-prefixed 16-symbol IDs, with `id_classic` mapping to the older entity model. — [Dynatrace Smartscape on Grail](https://docs.dynatrace.com/docs/discover-dynatrace/platform/grail/smartscape-on-grail)
- Datadog flows that cannot be associated with client or server tags are shown as unresolved or "N/A". — [Datadog CNM Glossary](https://docs.datadoghq.com/es/network_monitoring/cloud_network_monitoring/glossary)
- Azure Migrate groups a dependency logically as source server plus process → destination server plus process plus port. — [Azure Migrate dependency analysis](https://learn.microsoft.com/en-us/azure/migrate/concepts-dependency-visualization)

### Inferences
- Because DeepFlow tags at ingest time, each historical row keeps the resource ID valid at write time. This sidesteps IP reuse for stored data, at the cost of not being able to re-tag history. This is inferred from the documented storage-stage injection; it is not explicitly documented.
- shawk's host↔address ownership history table (with validity intervals) is the query-time equivalent. It lets the remote IP of an edge be resolved "as of" the edge's last_seen. That is more explicit than any OSS tool documents.
- For shawk's process identity, the OTel guidance suggests:
  - Identity = (host.id, systemd unit or cgroup) for long-lived services.
  - (pid, start time) only where per-process granularity is required.
  - comm, exe and service.version stay descriptive, because they may change on upgrade.
- DeepFlow's gprocess and New Relic's entity synthesis both aggregate away PID churn. This argues that shawk's edge key should use the unit or service, not the PID.

### Gaps
- No primary source found describing how DeepFlow handles IP reuse in its MySQL resource history (for example retention of deleted resources).
- Dynatrace's handling of host IP changes is not documented on the pages fetched.

## 5. Scale numbers, known limitations, and the reasons for storage choices

### Takeaway
Published numbers are mostly vendor benchmarks. DeepFlow chose integer-encoded tags in ClickHouse to cut tag cost by about 10x. SkyWalking built BanyanDB because general databases fit APM data poorly, and made it the default in 2025. Pixie trades retention (hours) for zero external storage. Dynatrace caps topology history at 35 days.

### Cited Findings
- **DeepFlow**: a single record may need "100+" injected tags. In a benchmark with 16-character tags and cardinality 5000, relative costs (SmartEncoding Int = 1) were:
  - LowCard(string): CPU 10, memory 1, disk 1.5
  - plain string: CPU 5, memory 1.5, disk 7.5
  — [DeepFlow SmartEncoding](https://deepflow.io/docs/features/auto-tagging/smart-encoding)
- DeepFlow also claims "SmartEncoding can reduce tag storage overhead by an order of magnitude" in production. — [DeepFlow Architecture](https://deepflow.io/docs/about/architecture)
- DeepFlow sample table sizes (compressed per row): `l7_flow_log` about 72 B, `l4_flow_log` about 154 B, `network_map.1s` about 52 B, `network_map.1m` about 74 B, `application_map.1m` about 21 B. — [DeepFlow: Reducing Storage Overhead](https://deepflow.io/docs/best-practice/reduce-storage-overhead/)
- DeepFlow throttles L4/L7 flow-log processing at 50,000/s by default (per server replica). Excess is dropped. — [DeepFlow: profiling the server ingester](https://deepflow.io/docs/diagnose/how-to-profile-deepflow-server-ingester)
- **SkyWalking BanyanDB**:
  - Rationale: "the Databases that SkyWalking adopted are not ideal for the APM data model, especially for saving tracing and logging data". The design draws on the RUM conjecture.
  - Project-reported benchmark against Elasticsearch: 5x less memory, 1/5 disk IOPS, 1/4 disk throughput, 30% less disk, slightly higher CPU.
  — [BanyanDB Data Model](https://skywalking.apache.org/docs/skywalking-banyandb/latest/concept/data-model); [SkyWalking discussion #12286](https://github.com/apache/skywalking/discussions/12286). These came from one search summary, and I did not check which of the two pages holds which claim.
- The SkyWalking storage doc cites a BanyanDB test of about 200 services and 200+ calls/s on 2 liaison plus 2 data nodes (4 vCPU / 8 GB each). It says SQL databases' logs and traces performance "could be significantly lower than BanyanDB and Elasticsearch". — [SkyWalking Backend Storage](https://skywalking.apache.org/docs/main/latest/en/setup/backend/backend-storage/)
- 2025 storage changes in SkyWalking:
  - BanyanDB 0.8.0 became "the default path" in SkyWalking 10.2.0.
  - BanyanDB 0.9.0 added the Trace model, replicas, and backup to S3, GCS and Azure.
  - "the H2 storage option is permanently removed".
  — [SkyWalking 2025 in Review](https://skywalking.apache.org/blog/2026-01-01-skywalking-2025-year-in-review/); [H2 removal announcement](https://skywalking.apache.org/events/remove-jdbc-as-storage/)
- **Pixie**: default PEM memory 2Gi, with 60% (1.2Gi) for the table store. The lowest recommended value is 1Gi, and the limit should stay under about 25% of node memory. — [Pixie: Tuning memory usage](https://docs.px.dev/reference/admin/tuning-mem-usage)
- New Relic's example sets the table-store size with `PL_TABLE_STORE_DATA_LIMIT_MB=750`. — [New Relic: Manage Pixie memory](https://docs.newrelic.com/docs/kubernetes-pixie/auto-telemetry-pixie/advanced-configuration/manage-pixie-memory.md)
- **Dynatrace**: 35-day fixed retention and a minimum 15-minute query window. "Edges can't be filtered with segments", only nodes. Smartscape on Grail is "included in the DPS license". — [Dynatrace Smartscape on Grail](https://docs.dynatrace.com/docs/discover-dynatrace/platform/grail/smartscape-on-grail); [Smartscape commands](https://docs.dynatrace.com/docs/platform/grail/dynatrace-query-language/commands/smartscape-commands)
- **Weave Scope**: the probe's full-report cadence must satisfy "N < (app.window / probe.publish.interval)". The whole topology is held in memory for a 15 s window. — [scope/prog/main.go](https://github.com/weaveworks/scope/blob/master/prog/main.go)

### Inferences
- The OSS tools optimized for very high write rates (per-flow or per-second rows), which pushed them to columnar or custom stores. shawk aggregates edges in-kernel and upserts every 1–5 minutes, so its PostgreSQL write rate scales with distinct edges, not flows. That is a much smaller problem and fits the relational choice.
- SkyWalking's guidance ("MySQL/PostgreSQL ... medium-scale") supports the view that relational storage is acceptable for topology and metadata at moderate scale. Its caveat is about logs and traces, which shawk does not store.
- DeepFlow's 10x tag-cost finding is a warning for the Prometheus side. High-cardinality string labels (exe paths, remote IPs, versions) are expensive on series, so keep them in PostgreSQL and join by a small key.

### Gaps
- No independent (non-vendor) benchmarks found for DeepFlow SmartEncoding or BanyanDB.
- No published entity-count or edge-count limits found for Dynatrace Smartscape or New Relic relationships.
- Pixie's project health and governance in 2026 (CNCF sandbox status, maintenance level) was not verified. The GitHub API returned 403 from this environment.

## 6. VM/on-prem application dependency mapping products: collection, storage, presentation, use cases

### Takeaway
VM/on-prem ADM tools collect by periodic connection polling (netstat, ss, lsof) or flow export (NetFlow/sFlow/IPFIX, VPC flow logs). They store results as CMDB relationship tables or appliance-side aggregates, and they focus on grouping servers into applications for migration and impact analysis. Their sampling is coarse (minutes), and some vendors recommend using traffic discovery only during initial mapping. shawk's continuous eBPF capture with first/last seen addresses the known weakness of point-in-time polling.

### Cited Findings
- **ServiceNow Service Mapping, traffic-based discovery**:
  - Tables: `cmdb_tcp` (TCP Connection, filled by netstat and lsof), `sa_flow_connection` (Netflow and VPC logs), plus `sa_flow_service` and `sa_flow_server_comm`. "In a base system, Service Mapping does not use data from" the last two.
  - "In base systems, traffic-based discovery relies solely on TCP-related data collected using the netstat, ss, and lsof commands".
  - The feature is off by default.
  - When pattern-based discovery finds the same connection, the traffic-based duplicate is removed. "Connections created only through traffic-based discovery aren't removed".
  - Predictive Intelligence can suggest connections.
  - ServiceNow recommends turning traffic-based discovery off once maps are tuned.
  — [ServiceNow: Traffic-based discovery](https://www.servicenow.com/docs/bundle/washingtondc-it-operations-management/page/product/service-mapping/concept/traffic-based-discovery.html)
- **Azure Migrate (agentless dependency analysis)**:
  - The appliance "polls TCP connection data from servers every five minutes". It collects process names, application names and destination ports.
  - The data "is sent to Azure Migrate every six hours".
  - Dependencies group source server plus process → destination server plus process plus port. They can be shown in a map or exported as CSV.
  - The use case is grouping servers that must migrate together.
  - Agent-based analysis (Service Map / Log Analytics) is only in the classic view, which "is scheduled for deprecation by the end of 2026".
  — [Azure Migrate: Dependency analysis](https://learn.microsoft.com/en-us/azure/migrate/concepts-dependency-visualization) (updated 2026-09-24)
- The Azure Migrate FAQ says the agentless map can show a single server's dependencies over a period from one hour to 30 days, with group visualization up to 10 servers. — [Azure Migrate FAQ](https://learn.microsoft.com/vi-vn/azure/migrate/common-questions-discovery-dependency-analysis)
- **Device42 ADM**:
  - After autodiscovery, the module "picks up on communication patterns".
  - Optional Periodic Jobs sample port and database connections over time, beyond a point-in-time snapshot.
  - Application Groups are generated from Calculation Rules (starting points) and Logic Templates (how discovery traverses the network and when it stops).
  — [Device42 Enterprise ADM docs](https://docs.device42.com/apps/enterprise-application-dependency-mapping/)
- Application Groups replace Device42's Affinity Groups. Device42 markets ADM for cloud migration and claims customers migrate in "one-third of the originally planned time" (a vendor claim). — [Device42 blog 2025-02-27](https://www.device42.com/blog/2025/02/27/simplifying-dependency-mapping-unlocking-real-world-benefits/); [Device42 Application Mappings](https://www.device42.com/features/application-mappings/)
- **Faddom**:
  - Described as agentless and passive, using flow data (NetFlow/sFlow) and AWS/Azure flow logs.
  - One reviewer warns that NetFlow/sFlow configuration "may not be accepted by some companies". Another notes that flow-based mapping may miss granularity, especially with encrypted traffic.
  — [Faddom one-pager (PDF)](https://faddom.com/wp-content/uploads/2023/08/FDM-1Pager.pdf); [Capterra reviews](https://www.capterra.com/p/201265/VNT/reviews/); [AWS Marketplace review](https://aws.amazon.com/marketplace/reviews/reviews-list/prodview-aoli4cnn6qewg/review/91c37ab6-c5a8-3798-bff1-8cd29beb2df6)
- Faddom's listings include "Historical Behavior Data". A third-party comparison mentions tracking topology changes over time. — [SourceForge Faddom](https://www.sourceforge.net/software/product/Faddom); [Virima comparison](https://virima.com/blog/faddom-solution-overview-top-alternatives)

### Inferences
- Polling every 5 minutes (Azure Migrate) or during discovery runs (ServiceNow netstat, ss, lsof) misses short-lived connections. In-kernel bundling with first/last seen gives better coverage, a strong point for shawk relative to this category.
- Flow-based tools (Faddom, NetFlow paths in ServiceNow) see host:port pairs but not processes. Process and systemd-unit attribution is what the agent-based approach adds.
- These products' main outputs are application grouping, move-group or migration-wave planning, and impact analysis. shawk's `dependencies` and `dependency_changes` views, together with long first/last-seen history, map directly onto decommission questions ("has anything connected to X in the last N days?"). The OSS observability tools cannot answer these past their short TTLs.
- ServiceNow's advice to turn traffic discovery off after initial mapping implies traffic-derived edges are noisy (clients, ephemeral or irrelevant peers). shawk will likely need filtering or classification views (for example by service port or listener ownership) for similar reasons.

### Gaps
- Faddom's architecture, storage and retention are not documented in public sources found; the how-it-works URL returned 404.
- Device42's storage schema for service communications (whether it keeps first/last-detected fields) was not found in the fetched docs.
- No primary source found for ServiceNow `cmdb_tcp` retention or aging rules.

## 7. OpenTelemetry Entities: status as of late 2026, entity events and relationships, usability for topology export

### Takeaway
Entities remain at "Development" status. Entity events are encoded as OTLP log records: `entity.state` (create, change or heartbeat, with `entity.report.interval`) and `entity.delete`. Directional relationships are embedded in state events as `entity.relationships`. An OTel blog says this shipped in spec v1.58.0 (2026-06-22) but is not yet stable. Topology could be exported this way in principle, but it is not a stable contract, and attribute naming differs between the spec page and the blog.

### Cited Findings
- The Entity Data Model is "Status: Development". Its fields:
  - Type: required, immutable.
  - Schema URL.
  - ID: a map of identifying attributes, at least one, immutable.
  - Description: a map of descriptive attributes, mutable.
  - Entities merge only if identity attributes, type and schema URL match exactly.
  — [OTel Entity Data Model](https://opentelemetry.io/docs/specs/otel/entities/data-model/)
- The data-model page still says "Entity relationship modelling will be refined in future specification work". Its example is service→process→host. — [OTel Entity Data Model](https://opentelemetry.io/docs/specs/otel/entities/data-model/)
- Entity Events is "Status: Development".
  - `entity.state` is emitted on creation, on descriptive changes, or periodically. It requires `entity.type` and `entity.id`; optional attributes are `entity.description`, `entity.relationships` and `entity.report.interval`.
  - `entity.delete` takes an optional `entity.delete.reason`.
  - Relationships carry a type plus the target's `entity.type` and `entity.id`, and are "directional, from the emitting entity to the target".
  - The spec recommends placing relationships on the shorter-lived entity.
  - When an entity is deleted, "all relationships where that entity is involved are implicitly deleted".
  — [OTel Entity Events](https://opentelemetry.io/docs/specs/otel/entities/entity-events/)
- Entity instantiation can be pull-based (self-discovery) or push-based (env vars or config across process boundaries). — [OTel Entities overview](https://opentelemetry.io/docs/specs/otel/entities/)
- The OTel blog says:
  - "The entity-events specification shipped in the v1.58.0 spec release (2026-06-22)", with relationships in spec PR #4836.
  - The data model and conventions are "still in development (not yet stable)".
  - Relationship type values are an open enumeration (e.g. `depends_on`, `contains`).
  - Removing a relationship means re-emitting state without it.
  — [OTel blog: consuming entity events](https://opentelemetry.io/blog/2026/consuming-opentelemetry-entity-events/)
- Naming conflict: the blog uses `otel.entity.event.type` (`entity_state`/`entity_delete`), `otel.entity.type`, `otel.entity.id` and `otel.entity.attributes`, while the spec page uses event names `entity.state`/`entity.delete` with `entity.type`/`entity.id`. This could reflect version drift or illustrative naming; the blog says attribute names are illustrative. — [OTel blog](https://opentelemetry.io/blog/2026/consuming-opentelemetry-entity-events/) vs [OTel Entity Events spec](https://opentelemetry.io/docs/specs/otel/entities/entity-events/)
- OTLP proto support for EntityRefs on Resource, and an earlier proposal (PR #4665) for InstrumentationScope to carry entities, have unclear landed status. — [opentelemetry-specification PR #4665 (mirror)](https://scriptagc.wasmer.app/https_github_com/open-telemetry/opentelemetry-specification/pull/4665)

### Inferences
- The entity-events shape maps closely onto shawk's model:
  - Process, host and listener become entities.
  - "Process connects to service endpoint" becomes a relationship on the shorter-lived entity (the process or client).
  - The heartbeat interval maps to last_seen.
- shawk could optionally emit entity events via OTLP logs in addition to PostgreSQL. Relying on them as the primary topology store would be premature, because the status is Development and naming is unsettled.
- Event-sourced storage of entity events with first/last coalescing, as recommended by the OTel blog, is essentially what shawk's upsert pattern does. This gives forward-compatibility if shawk later adopts OTel entity semantics.
- `process.pid` plus `process.creation.time` as process identity, and host IP as a descriptive (mutable) attribute, align with shawk's planned host↔address ownership history.

### Gaps
- The v1.58.0 date and PR #4836 come from the OTel blog. They were not cross-checked against the spec CHANGELOG.
- No confirmation found of OpenTelemetry Collector components that emit or consume entity events in 2026, or of backends supporting them.
- Whether `opentelemetry-proto` has released Resource `entity_refs` as stable or development fields was not confirmed.
