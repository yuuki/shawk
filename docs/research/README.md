# Research notes

Background research written while designing shawk (late 2026, most of it
dated 2026-10-31). The notes record what other tools did and what their
documentation and code said at the time; they are not maintained as shawk
or those tools change. What shawk does is in [../design.md](../design.md).

OBI (OpenTelemetry eBPF Instrumentation) as a foundation for shawk:

- [obi-as-foundation/obi_capabilities.md](obi-as-foundation/obi_capabilities.md):
  what OBI offers for a process-level network dependency map on plain
  Linux hosts.
- [obi-as-foundation/obi_architecture_governance.md](obi-as-foundation/obi_architecture_governance.md):
  the architecture, extensibility, licensing and governance of OBI, for
  deciding whether to rebuild shawk on it.

The kernel hooks of shawk, measured on the targets (2026-11-04, #165):

- [kernel-hooks/kernel_hooks.md](kernel-hooks/kernel_hooks.md): the state
  change tracepoint and iterators of TCP against hooks on every message and
  on accept, fentry, kprobes and cgroup_skb for UDP, and where the errors
  of failed connects can be seen, on Rocky Linux 9.8 and Linux 6.8
  (aarch64), with the raw results and the harness in `test/hookcost`.

Similar tools, compared with the design of shawk:

- [similar-tools-comparison-and-design-review/flow_observability_pipelines.md](similar-tools-comparison-and-design-review/flow_observability_pipelines.md):
  flow-oriented eBPF pipelines (Hubble and Timescape, Retina, NetObserv,
  opentelemetry-network, Datadog CNM), from the kernel to storage and UI.
- [similar-tools-comparison-and-design-review/metrics_based_topology_tools.md](similar-tools-comparison-and-design-review/metrics_based_topology_tools.md):
  service maps built from metrics (Coroot, Caretta, the network metrics of
  Beyla and OBI, Kiali, the service graphs of Tempo and OpenTelemetry).
- [similar-tools-comparison-and-design-review/topology_storage_and_history.md](similar-tools-comparison-and-design-review/topology_storage_and_history.md):
  where dependency-mapping tools store relationships and their history
  (DeepFlow, Pixie, SkyWalking, Weave Scope, Dynatrace, Datadog, New Relic,
  OpenTelemetry Entities, CMDB and migration tools).
- [similar-tools-comparison-and-design-review/grafana_otel_integration.md](similar-tools-comparison-and-design-review/grafana_otel_integration.md):
  the mechanics of Grafana, Prometheus and OpenTelemetry for a PostgreSQL
  store of relations next to OTLP metrics (the Node Graph panel, the
  PostgreSQL data source, alerting, the OTLP ingestion of Prometheus,
  semantic conventions, cardinality).
