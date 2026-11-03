# OpenTelemetry eBPF Instrumentation (OBI): architecture, extensibility, licensing and governance, for deciding whether to rebuild shawk on OBI

Research date: **2026-10-31**.

Snapshot used:
- OBI `main` @ `4e33aec` (2026-10-30). Repo links below that use `blob/main/...` refer to this snapshot.
- Tag **`v1.0.0`**: commit `d23be0d6`, tagged 2026-10-30, GitHub release published 2026-10-30.
- Collector receiver module tag **`collector/v0.15.2`** (2026-10-16).
- Beyla `main` @ `98897a2` (2026-10-30) and **Beyla v3.40.0** (2026-10-26).
- Alloy `main` @ `872d1b4` (2026-10-30).
- `open-telemetry/community` `main` @ `78e583e` (2026-10-29).

Method:
- I cloned the OBI, Beyla, Alloy (tree only) and community repos and read the code and docs directly.
- I downloaded the `go.opentelemetry.io/obi@v1.0.0` module zip from proxy.golang.org.
- I read GitHub issue, PR and release HTML pages, and opentelemetry.io and grafana.com pages.
- The GitHub REST and MCP APIs for these repos were not enabled in this session. Issue and PR facts therefore come from the HTML pages, read through a fetch-and-summarise tool. Quotes from those pages are faithful to that summary but were not compared character by character.

---

## TL;DR

- **OBI reached v1.0.0 on 2026-10-30**, its "first stable core release" ([release](https://github.com/open-telemetry/opentelemetry-ebpf-instrumentation/releases/tag/v1.0.0), [blog 2026-10-30](https://opentelemetry.io/blog/2026/obi-v1-release/)). Things that matter for shawk but are **outside the v1 contract**:
  - the Go API of the root module (`go.opentelemetry.io/obi`);
  - the Collector receiver, which stays on its own **v0** line (`collector/v0.15.2`, alpha);
  - every network and stats metric, which is classified `development`;
  - network flow attribute names (`src.*`, `dst.*`, `transport`, `iface`, `direction`), which are explicitly excluded and expected to be renamed ([#1092](https://github.com/open-telemetry/opentelemetry-ebpf-instrumentation/issues/1092)).
- Architecture:
  - Go plus C eBPF. Loads with **cilium/ebpf v0.22.0**; bindings come from **bpf2go** via `go:generate`, with CO-RE against a vendored `vmlinux.h`.
  - Three independent components (AppO11y, NetO11y, StatsO11y), each with its own eBPF objects and its own `swarm`/`msg` pipeline. `instrumenter.Run` starts them in an errgroup.
  - Hooks are kprobes, tracepoints, uprobes, TC, socket filter, `sk_msg`, `sockops` and `iter/tcp`. OBI uses **no `fentry` or `tp_btf` programs**; a fentry fast path is only being evaluated ([#1099](https://github.com/open-telemetry/opentelemetry-ebpf-instrumentation/issues/1099)).
  - **NetO11y and StatsO11y records carry no PID or process attributes.** AppO11y spans carry process/service identity, but only for protocols OBI parses.
- Embedding as a library is possible, and Beyla and Odigos do it. It is costly:
  - the bpf2go outputs are **not in the Go module zip**, so consumers need `replace` plus a generated source tree;
  - the dependency tree is large: 101 direct and 125 indirect requires;
  - the eBPF loaders live under `pkg/internal`, so a new tracer cannot be plugged in from outside;
  - **Grafana Alloy stopped linking Beyla in-process in July 2026 and now runs it as a subprocess** ([alloy#6695](https://github.com/grafana/alloy/pull/6695)).
- The receiver is in **otelcol-contrib since v0.156.0** ([collector-releases#1386](https://github.com/open-telemetry/opentelemetry-collector-releases/pull/1386)). That distribution solves the generated-files problem by downloading `obi-<ver>-source-generated.tar.gz`.
- Licensing:
  - Go code is Apache-2.0.
  - OBI-authored eBPF C files carry `SPDX-License-Identifier: Apache-2.0`, but their ELF `license` section says `"Dual MIT/GPL"`. NetOlly flows say `"GPL"` and the rDNS XDP program says `"Dual BSD/GPL"`.
  - Vendored libbpf headers keep `LGPL-2.1 OR BSD-2-Clause` or `GPL-2.0-only OR BSD-2-Clause`.
  - Contributions need the **CNCF CLA via LF EasyCLA**; DCO is not required. A generative-AI policy applies.
- Governance:
  - SIG eBPF Instrumentation meets Wednesdays at 08:00 PT.
  - 7 maintainers: Grafana ×2, Coralogix ×2, Splunk, Odigos and Isovalent ×1 each. 4 approvers: Coralogix, Alibaba Cloud and Grafana ×2.
  - Commit activity since May 2026 is multi-vendor (Splunk, Coralogix and Grafana lead).
- opentelemetry-network was **archived 2026-10-07**. I found **no OBI issue or PR** about porting its reducer, conntrack/NAT resolution or both-ends connection matching. The closest work:
  - **peer metadata exchange for non-Kubernetes hosts** (#3806, merged 2026-10-30, experimental);
  - the opt-in `traces_service_graph_connection_info` topology metric (#3796, 2026-10-26);
  - the planned Mermin (ElastiFlow) flow-traces port.
- Grafana:
  - Beyla is "the Grafana Labs distribution of OBI". It tracks OBI `main` roughly weekly through a git submodule that points at Grafana's fork.
  - Alloy's `beyla.ebpf` (GA) now embeds a **Beyla binary** pinned at v3.40.0 and runs it as a child process. Alloy therefore depends on OBI only indirectly.

---

## 1. Code architecture

### Takeaway
OBI is a Go monorepo with C eBPF sources under `bpf/`, compiled to Go bindings with bpf2go and loaded with cilium/ebpf. Three top-level features ("components") are built and run independently:
- **AppO11y**: discovery, per-executable `ProcessTracer`, decoration, export.
- **NetO11y**: TC or socket-filter flow records, then a flow pipeline.
- **StatsO11y**: node-wide TCP statistics from kprobes and tracepoints.

Each owns its eBPF objects, its event types and a `swarm`-assembled graph of nodes connected by typed `msg.Queue`s. They share only export plumbing: one OTEL metrics exporter, the Prometheus manager and the attribute-selection framework.

There are two ways to add a feature:
- add a protocol parser or tracer inside AppO11y (documented checklist);
- add a new statistical or network metric (documented 7–12-step checklists).

A brand-new top-level component is not documented. It would mean adding a fourth `setupXxxO11y` the way StatsO11y was added in March 2026 (#1572).

### Cited findings

**Languages and size**
- Non-test source files, excluding integration tests and examples: about 783 Go files, 79 `.c`, 284 `.h`, 80 Java (the embedded Java agent under `pkg/internal/java/agent`) and 23 JS (the Node.js injector). Counted on the local clone.
- Module `go.opentelemetry.io/obi` declares `go 1.26.0` and `toolchain go1.27.3`. — [go.mod](https://github.com/open-telemetry/opentelemetry-ebpf-instrumentation/blob/main/go.mod)

**eBPF loader and generation**
- The loader is `github.com/cilium/ebpf v0.22.0`. — [go.mod](https://github.com/open-telemetry/opentelemetry-ebpf-instrumentation/blob/main/go.mod)
- Each loader package has a bpf2go directive, for example `//go:generate $BPF2GO -cc $BPF_CLANG -cflags $BPF_CFLAGS -target $BPF_TARGETS Bpf ../../../../bpf/generictracer/generictracer.c`. The same pattern appears in `pkg/internal/ebpf/{gotracer,tpinjector,logenricher,gpuevent,watcher,logger}`, `pkg/internal/netolly/ebpf/{tracer,sock_tracer}.go`, `pkg/internal/statsolly/ebpf/stats_tracer.go`, `pkg/internal/rdns/ebpf/xdp` and `pkg/ebpf/common/common.go`.
- Generated `*_bpfel.go` and `*_bpfel.o` files are git-ignored. You run `make generate` with local clang, or `make docker-generate` with the generator image that CI uses. Both targets build amd64 and arm64; `BPF_TARGETS` narrows that. — [CONTRIBUTING.md](https://github.com/open-telemetry/opentelemetry-ebpf-instrumentation/blob/main/CONTRIBUTING.md), [README.md](https://github.com/open-telemetry/opentelemetry-ebpf-instrumentation/blob/main/README.md)
- CO-RE: `bpf/bpfcore/` holds `vmlinux.h`, `vmlinux_amd64.h`, `vmlinux_arm64.h` and libbpf headers. AGENTS.md says not to edit them. — [AGENTS.md](https://github.com/open-telemetry/opentelemetry-ebpf-instrumentation/blob/main/AGENTS.md)
- `bpf/README` asks for naturally aligned, non-packed structs because Go reads ring buffers zero-copy, and enables `-Wpadded`.

**eBPF program organisation (`bpf/`)**
- One directory per subsystem: `generictracer`, `gotracer`, `tpinjector`, `logenricher`, `gpuevent`, `netolly`, `statsolly`, `rdns` (XDP DNS snooping), `watcher` (`kprobe/sys_bind` port watcher), `logger`, `pid`, `maps`, `common` and `shared`. There are also C unit tests (`bpf/tests`). — [AGENTS.md "Repository Layout"](https://github.com/open-telemetry/opentelemetry-ebpf-instrumentation/blob/main/AGENTS.md)
- Program section types, counted from `SEC(...)` on `main`: uprobe 180, kprobe 47, uretprobe 19, sk_msg 14, kretprobe 10, tracepoint 6, socket 4, iter 4 (`iter/tcp`), xdp 2, usdt 2, tc_ingress 1, tc_egress 1, sockops 1, raw_tracepoint 1. There are **no `fentry`, `fexit` or `tp_btf` programs**.
- StatsO11y hooks: `kprobe/tcp_close`, `kprobe/tcp_sendmsg`, `kprobe/tcp_cleanup_rbuf`, `tracepoint/sock/inet_sock_set_state` and `raw_tracepoint/tcp_retransmit_skb` (`bpf/statsolly/{k_tcp.c,tp_tcp.c}`).
- [#1099](https://github.com/open-telemetry/opentelemetry-ebpf-instrumentation/issues/1099) "Evaluate tracing programs as a kprobe fast path" is open (goal: 2026). A spike was proposed on 2026-07-02 with no decision. Its constraints are Linux 5.8+ with BTF, RHEL 4.18 backports and amd64/arm64, and selection "must rely on runtime capabilities".

**Internal pipeline: "swarm" and "msg"**
- `pkg/pipe/swarm`: an `Instancer` collects `InstanceFunc`s. `Instance()` builds all nodes, and if any constructor fails nothing starts. `Runner.Start` runs each `RunFunc` in a goroutine. `swarm.Bypass(in, out)` lets optional nodes short-circuit. — [pkg/pipe/swarm/runner.go](https://github.com/open-telemetry/opentelemetry-ebpf-instrumentation/blob/main/pkg/pipe/swarm/runner.go), [instancer.go](https://github.com/open-telemetry/opentelemetry-ebpf-instrumentation/blob/main/pkg/pipe/swarm/instancer.go)
- `pkg/pipe/msg.Queue[T]` is a typed fan-out queue with `Subscribe`, `Bypass` and `ClosingAttempts`, plus a send timeout and a deadlock panic option. — [pkg/pipe/msg/queue.go](https://github.com/open-telemetry/opentelemetry-ebpf-instrumentation/blob/main/pkg/pipe/msg/queue.go)
- `pkg/pipe/global.ContextInfo` holds shared state: the Kubernetes informer, Docker store, node metadata, Prometheus manager, the shared `OTELMetricsExporter`, rDNS, `DynamicSelector`, and the override queues described in §2. — [pkg/pipe/global/context.go](https://github.com/open-telemetry/opentelemetry-ebpf-instrumentation/blob/main/pkg/pipe/global/context.go)
- `instrumenter.Run`, through `runWithContextInfo`, starts `setupAppO11y`, `setupNetO11y` and `setupStatsO11y` in an `errgroup`. Each is enabled by `cfg.Enabled(obi.FeatureAppO11y|FeatureNetO11y|FeatureStatsO11y)` or by a dynamic selector. — [pkg/instrumenter/instrumenter.go](https://github.com/open-telemetry/opentelemetry-ebpf-instrumentation/blob/main/pkg/instrumenter/instrumenter.go), [pkg/obi/config.go](https://github.com/open-telemetry/opentelemetry-ebpf-instrumentation/blob/main/pkg/obi/config.go)
- The pipeline map explains why AppO11y has two connected pipelines: "there are plans to split OBI into two: a finder/instrumenter executable with high privileges and a reader/decorator executable with lesser privileges". — [devdocs/pipeline-map.md](https://github.com/open-telemetry/opentelemetry-ebpf-instrumentation/blob/main/devdocs/pipeline-map.md). This doc is partly stale: it still shows a `process.Collector` pipeline, but process metrics were removed in #965 (2025-12-05) and #20.

**AppO11y**
- The discovery pipeline runs `ProcessWatcher` → (Kubernetes and Docker enrichers) → `CriteriaMatcher` → `ExecTyper` → `TraceAttacher`, which creates one `ebpf.ProcessTracer` per executable. — [pipeline-map.md](https://github.com/open-telemetry/opentelemetry-ebpf-instrumentation/blob/main/devdocs/pipeline-map.md)
- Tracer groups: `gotracer` for Go executables (uprobes with offsets), `generictracer` for everything else, and a common group (`tpinjector` for context propagation over sk_msg/sockops, `logenricher`, `gpuevent`). — [pkg/appolly/discover/finder.go](https://github.com/open-telemetry/opentelemetry-ebpf-instrumentation/blob/main/pkg/appolly/discover/finder.go)
- The `ebpf.Tracer` interface exposes `KProbes`, `Tracepoints`, `GoProbes`, `UProbes`, `USDTProbes`, `SocketFilters`, `SockMsgs`, `SockOps`, `Iters`, `Tracing`, `AllowPID/BlockPID` and `Run(ctx, eventCtx, *msg.Queue[[]request.Span])`. There is also a smaller `UtilityTracer` for programs not tied to a service. — [pkg/ebpf/tracer.go](https://github.com/open-telemetry/opentelemetry-ebpf-instrumentation/blob/main/pkg/ebpf/tracer.go)
- Spans are protocol-typed. `EventType` values cover HTTP, gRPC, SQL, Redis, Kafka, MQTT, Mongo, NATS, AMQP, Couchbase, Memcached, SunRPC, Aerospike, DNS, `FailedConnect`, GPU and others. There is **no generic "unknown TCP/UDP connection" span**. — [pkg/appolly/app/request/span.go](https://github.com/open-telemetry/opentelemetry-ebpf-instrumentation/blob/main/pkg/appolly/app/request/span.go)
- Adding a TCP protocol means a new case in `ReadTCPRequestIntoSpan`, a new `EventType`, and edits "every single file where the data is flowing". — [devdocs/protocols/tcp/new-tcp-tracer.md](https://github.com/open-telemetry/opentelemetry-ebpf-instrumentation/blob/main/devdocs/protocols/tcp/new-tcp-tracer.md)

**NetO11y (network flow metrics)**
- Capture: eBPF at TC ingress/egress (`bpf/netolly/flows.c`) or a socket filter (`flows_sock.c`). The record is `flow_record_t`, mirrored by `ebpf.Record` in Go.
- Pipeline: MapTracer + RingBufTracer → ProtocolFilter → FlowDeduper → Kubernetes decorator → reverse DNS → GeoIP → CIDRs → attribute filter → OTEL, Prometheus or a printer. — [devdocs/metrics.md](https://github.com/open-telemetry/opentelemetry-ebpf-instrumentation/blob/main/devdocs/metrics.md), [pkg/netolly/agent/pipeline.go](https://github.com/open-telemetry/opentelemetry-ebpf-instrumentation/blob/main/pkg/netolly/agent/pipeline.go)
- `ebpf.Record` = `{id, Metrics, CommonAttrs{Src/Dst Port, Addr, Name, Zone, OBIIP, Metadata}, NetAttrs{Interface, IfIndex, TransportProtocol, EthProtocol}}`. It has **no PID or process field**. — [pkg/internal/netolly/ebpf/record.go](https://github.com/open-telemetry/opentelemetry-ebpf-instrumentation/blob/main/pkg/internal/netolly/ebpf/record.go), [pkg/internal/pipe/attrs.go](https://github.com/open-telemetry/opentelemetry-ebpf-instrumentation/blob/main/pkg/internal/pipe/attrs.go)
- A dynamic selector can decorate flows with service identity **by IP**: pod IP, or a container netns IP outside Kubernetes (#2861, 2026-09-04). — [pkg/internal/pipe/transform/dynamicpid/decorator.go](https://github.com/open-telemetry/opentelemetry-ebpf-instrumentation/blob/main/pkg/internal/pipe/transform/dynamicpid/decorator.go)
- The code derives from NetObserv's eBPF agent (Red Hat/IBM), per the [NOTICE](https://github.com/open-telemetry/opentelemetry-ebpf-instrumentation/blob/main/NOTICE) and the `flows.c` header.

**StatsO11y (statistical TCP metrics)**
- Introduced 2026-03-21 in #1572. Metrics:
  - `obi.stat.tcp.rtt`
  - `obi.stat.tcp.failed.connections` (2026-04-20)
  - `obi.stat.tcp.retransmits` (2026-05-15)
  - `obi.stat.tcp.io` (2026-05-29)
  - `obi.stat.tcp.successful.connections` (2026-09-18, with `network.tcp.handshake.role`)
  — git log; [schemas/obi/groups/stats/metrics.yaml](https://github.com/open-telemetry/opentelemetry-ebpf-instrumentation/blob/main/schemas/obi/groups/stats/metrics.yaml)
- It is node-wide by design: "statistical metrics … across all applications running on a node, regardless of which PID triggered the event … because … some hook points can cause unreliable PID calculations and lead to false positives". — [devdocs/metrics.md#statso11y](https://github.com/open-telemetry/opentelemetry-ebpf-instrumentation/blob/main/devdocs/metrics.md)
- Default attributes are `src.address` and `dst.address`. Optional: ports, names, zones, `obi.ip`, plus Kubernetes groups. There are no process attributes. — [pkg/export/attributes/attr_defs.go](https://github.com/open-telemetry/opentelemetry-ebpf-instrumentation/blob/main/pkg/export/attributes/attr_defs.go)
- It is TCP only; there are no UDP stats metrics. — [SUPPORT_MATRIX.md "Statistical Metrics"](https://github.com/open-telemetry/opentelemetry-ebpf-instrumentation/blob/main/SUPPORT_MATRIX.md)

**How a new feature or tracer is added (documented paths)**
- New network metric: extend `flow_record_t` and `ebpf.Record`, define `metric(...)` in `pkg/export/attributes/metric.go`, register it in `getDefinitions`, add record getters, add a feature bit in `pkg/export/feature.go` and `FeatureMapper`, run `make generate-config-schema`, wire the OTEL and Prometheus exporters, and add the metric to `schemas/obi/groups/network/metrics.yaml`. — [devdocs/metrics.md](https://github.com/open-telemetry/opentelemetry-ebpf-instrumentation/blob/main/devdocs/metrics.md)
- New stat metric: 12 steps. Pick a hook; add a `stat_type` in `bpf/statsolly/types.h` and the Go constant; name the program `obi_stats_{probe_type}_{kernel_func}[_{purpose}]`; add it to `NewStatsFetcher`, gated by a feature predicate (disabled probes are replaced by no-op stubs before load); handle it in `tracer_ringbuf.go`; then metric, attribute, getter, exporter and schema-registry steps. — same doc
- New application metric or attribute: the same pattern, plus Weaver live-check coverage in an integration suite. — same doc and [schemas/obi/README.md](https://github.com/open-telemetry/opentelemetry-ebpf-instrumentation/tree/main/schemas/obi)
- Cross-cutting requirements:
  - all configuration work targets **Config v2**, because Config v1 is frozen — [devdocs/README.md](https://github.com/open-telemetry/opentelemetry-ebpf-instrumentation/blob/main/devdocs/README.md);
  - telemetry must be declared in the Weaver schema registry; renames must be recorded as schema transformations — [AGENTS.md "Telemetry schema"](https://github.com/open-telemetry/opentelemetry-ebpf-instrumentation/blob/main/AGENTS.md);
  - the PR checklist asks for updates to `devdocs/features.md` and `SUPPORT_MATRIX.md` when core features change.
- CI covers the BPF verifier on kernels 5.10, 5.15, 6.1, 6.6, 6.12, 6.18, 7.2, bpf/bpf-next, RHEL 8.9, 8.10 and 9.6, and AL2023. VM integration tests run on 5.15, 6.18 and 7.2. — [SUPPORT_MATRIX.md](https://github.com/open-telemetry/opentelemetry-ebpf-instrumentation/blob/main/SUPPORT_MATRIX.md)
- Selective loading of eBPF parts by feature is still incomplete. [#2159](https://github.com/open-telemetry/opentelemetry-ebpf-instrumentation/issues/2159) is open; one user reported "an extra 30+% CPU" on 48-CPU nodes for a gRPC workload.

### Gaps
- There is no documentation for adding a **fourth top-level component** (an "XxxO11y" with its own agent). The StatsO11y PR (#1572) is the de facto template. That is my inference; I did not read the PR page.
- The pipeline-map doc is partly stale.

---

## 2. Embedding: Go library and Collector receiver

### Takeaway
OBI can be embedded as a Go library: `instrumenter.Run(ctx, *obi.Config, opts...)`. It has deliberate "vendored mode" hooks (`OverrideAppExportQueue`, `WithDynamicSelector`, `WithCriteriaUpdater`) and is embedded in practice by Beyla and Odigos.

The Go API is **not** part of the v1.0 stability contract, and embedding is operationally heavy:
- generated eBPF bindings are missing from the published module;
- the dependency closure is very large;
- eBPF loaders and the net/stats record types are `internal`.

The Collector receiver (`go.opentelemetry.io/obi/collector`, component type `obi`):
- produces traces, metrics and logs, all at **Alpha** stability;
- has been a separate **v0** module since 2026-10-15;
- works with `ocb` only if you `replace` both OBI modules with a source tree that contains generated files;
- ships inside `otelcol-contrib`.

### Cited findings

**Module paths and stability**
- `go.opentelemetry.io/obi`: proxy versions run v0.8.0 … v0.15.2, v1.0.0-rc.1, v1.0.0-rc.2 and v1.0.0. v1.0.0 has `Time: 2026-10-30T14:18:13Z` and `Origin.Hash d23be0d6…`. — `https://proxy.golang.org/go.opentelemetry.io/obi/@v/list`, `/@v/v1.0.0.info`
- `go.opentelemetry.io/obi/collector`: v0.15.0, v0.15.1 and v0.15.2 only. — `https://proxy.golang.org/go.opentelemetry.io/obi/collector/@v/list`
- v1.0.0 release notes (summary): the public Go API of the root module "is outside the stable surfaces declared for this milestone"; the receiver stays "on its independent v0 release line"; "receiver users should use `collector/v0.15.2`". — [release v1.0.0](https://github.com/open-telemetry/opentelemetry-ebpf-instrumentation/releases/tag/v1.0.0)
- VERSIONING.md: the receiver is a separate module "with its own `v0` version line and tags of the form `collector/vX.Y.Z`". After v1, Go guarantees would be "source-level API guarantees" with no ABI compatibility, but they apply "only after OBI declares a surface stable". — [VERSIONING.md](https://github.com/open-telemetry/opentelemetry-ebpf-instrumentation/blob/main/VERSIONING.md)
- `versions.yaml` module sets: `obi: v1.0.0` and `collector: v0.15.2`. — [versions.yaml](https://github.com/open-telemetry/opentelemetry-ebpf-instrumentation/blob/main/versions.yaml)

**Library usage**
- `examples/vendoring/vendoring.go` says OBI "is also designed to be vendored inside other components (for example, the OpenTelemetry Collector)". It calls `instrumenter.Run(ctx, &config, instrumenter.OverrideAppExportQueue(q))` and subscribes to `msg.Queue[[]request.Span]`. — [examples/vendoring/vendoring.go](https://github.com/open-telemetry/opentelemetry-ebpf-instrumentation/blob/main/examples/vendoring/vendoring.go)
- Options: `WithDynamicSelector` (add or remove PIDs or Kubernetes workloads per signal at runtime; contributed by the Odigos maintainer, Jun–Sep 2026), `OverrideAppExportQueue` and `WithCriteriaUpdater`. — [pkg/instrumenter/opts.go](https://github.com/open-telemetry/opentelemetry-ebpf-instrumentation/blob/main/pkg/instrumenter/opts.go), [examples/dynamicselector-host](https://github.com/open-telemetry/opentelemetry-ebpf-instrumentation/tree/main/examples/dynamicselector-host)
- `ContextInfo` also has `OverrideNetExportQueue *msg.Queue[[]*netebpf.Record]` and `OverrideStatsExportQueue`. Their element types live in `pkg/internal/netolly/ebpf` and `pkg/internal/statsolly/ebpf`. Go's `internal` rule means **external modules cannot name these types**, so these hooks are effectively unusable outside the OBI module tree. This is my inference from the code. — [pkg/pipe/global/context.go](https://github.com/open-telemetry/opentelemetry-ebpf-instrumentation/blob/main/pkg/pipe/global/context.go)
- Public vs internal: about 77 public directories under `pkg/` versus 242 under `pkg/internal`. All eBPF loaders are in `pkg/internal/ebpf/*`, `pkg/internal/netolly/ebpf` and `pkg/internal/statsolly/ebpf`. Tracer groups are hard-wired in `pkg/appolly/discover/finder.go`, with **no registration hook** for third-party tracers.
- `pkg/export.FeatureMapper` is public "so any extension package can add and remove feature definitions before loading them" (Beyla uses this). — [pkg/export/feature.go](https://github.com/open-telemetry/opentelemetry-ebpf-instrumentation/blob/main/pkg/export/feature.go)

**Generated code is not in the module**
- The v1.0.0 module zip from proxy.golang.org (3,800 files, about 21 MB) contains **0** `*_bpfel*` files.
- Linux-tagged loaders reference generated symbols, for example `BpfObjects` in `pkg/internal/ebpf/generictracer/generictracer.go`.
- So `go get go.opentelemetry.io/obi@v1.0.0` cannot be built on Linux without generating, or without the release's `obi-v<ver>-source-generated.tar.gz` and a `replace`. — local inspection; [RELEASING.md](https://github.com/open-telemetry/opentelemetry-ebpf-instrumentation/blob/main/RELEASING.md) describes the source-generated archive.
- How embedders cope:
  - **Beyla**: `replace go.opentelemetry.io/obi => ./.obi-src` (a git submodule). — [beyla go.mod](https://github.com/grafana/beyla/blob/main/go.mod)
  - **Odigos**: a wrapper module requires `go.opentelemetry.io/obi v0.10.1-0.20260706144415-c76a93c8775c`; its Dockerfile "materialize[s] OBI" and runs `make generate`. — [odigos odiglet/go.mod](https://github.com/odigos-io/odigos/blob/main/odiglet/go.mod), [odiglet/Dockerfile](https://github.com/odigos-io/odigos/blob/main/odiglet/Dockerfile)
  - **otelcol-contrib**: `scripts/prepare-obi.sh` downloads and verifies the source-generated tarball, extracts it to `internal/obi-src`, and adds `replaces: go.opentelemetry.io/obi => ../../../internal/obi-src`. "No BPF toolchain … is required." — [prepare-obi.sh](https://github.com/open-telemetry/opentelemetry-collector-releases/blob/main/scripts/prepare-obi.sh), [contrib manifest](https://github.com/open-telemetry/opentelemetry-collector-releases/blob/main/distributions/otelcol-contrib/manifest.yaml)
- Dependency weight: `go.mod` has 101 direct and 125 indirect requires. They include `k8s.io/client-go v0.37.1`, AWS, Azure and GCP SDKs, `go.opentelemetry.io/otel v1.47.0`, `collector/pdata v1.69.0` and `cilium/ebpf v0.22.0`. An embedder shares one MVS-resolved version of each, so for example shawk's cilium/ebpf would be forced to at least v0.22.0.

**Collector receiver**
- `collector/factory.go` registers `component.MustNewType("obi")` with `receiver.WithTraces(..., component.StabilityLevelAlpha)` and the same for Metrics and Logs. Receivers with the same component ID share one OBI instance; different IDs (`obi/a`, `obi/b`) run separate instances. It runs on Linux amd64/arm64 only and returns `errUnsupportedPlatform` elsewhere. — [collector/factory.go](https://github.com/open-telemetry/opentelemetry-ebpf-instrumentation/blob/main/collector/factory.go), [collector/internal/controller.go](https://github.com/open-telemetry/opentelemetry-ebpf-instrumentation/blob/main/collector/internal/controller.go)
- What each signal carries:
  - **traces**: AppO11y spans;
  - **metrics**: the OTEL metrics exporter, which is shared by app RED and span metrics, service graph, runtime, **network (NetO11y) and stats (StatsO11y)** exporters (`ctxInfo.OTELMetricsExporter.Instantiate` in `metrics.go`, `metrics_net.go`, `metrics_stats.go` and others);
  - **logs**: exception `LogRecord`s ([devdocs/exceptions](https://github.com/open-telemetry/opentelemetry-ebpf-instrumentation/blob/main/devdocs/exceptions/README.md)).
  The docs show `meter_provider.features: [network, application]`. Stats metrics through the receiver are not mentioned in the docs but follow from the code path (my inference).
- Side effect: `initLogger` calls `slog.SetDefault(...)` and installs a klog bridge for the whole process. — [collector/factory_linux.go](https://github.com/open-telemetry/opentelemetry-ebpf-instrumentation/blob/main/collector/factory_linux.go)
- Building with OCB, per the docs page:
  - check out OBI at v0.15.2 and run `make docker-generate` or `make generate` first ("This step must be completed before building with `ocb`");
  - the builder config needs `replaces` for **both** `go.opentelemetry.io/obi` and `go.opentelemetry.io/obi/collector` ("Replacing only the root module no longer replaces the receiver");
  - the example pins Collector components to v0.163.0 and providers to v1.69.0;
  - the receiver has existed since v0.5.0, and Config v2 is supported from v0.11.0;
  - "Configuration changes require a Collector restart". The page states no stability level.
  — [opentelemetry.io: OBI as Collector receiver](https://opentelemetry.io/docs/zero-code/obi/configure/collector-receiver/), [examples/otel-collector](https://github.com/open-telemetry/opentelemetry-ebpf-instrumentation/tree/main/examples/otel-collector)
- Distribution status:
  - The OBI receiver was added to **otelcol-contrib** in collector-releases **v0.156.0** (PR #1386 by MrAlias, merged 2026-07-02). It was upgraded to v0.12.2, then v0.13.0, then v0.15.2 (contrib v0.163.0). The current contrib manifest is dist v0.164.0 with `go.opentelemetry.io/obi/collector v0.15.2`. — [CHANGELOG](https://github.com/open-telemetry/opentelemetry-collector-releases/blob/main/CHANGELOG.md), [PR #1386](https://github.com/open-telemetry/opentelemetry-collector-releases/pull/1386)
  - OBI's 2026 goal "Build an otel collector distribution with obi as a receiver" ([#1157](https://github.com/open-telemetry/opentelemetry-ebpf-instrumentation/issues/1157)) was closed 2026-07-22 as resolved by that contrib integration. No dedicated `otelcol-ebpf` distribution exists.

### Gaps
- No document says how long `collector/v0.x` will stay v0, or what its path to stable is.
- No published guidance covers embedding OBI next to other eBPF code in the same process: shared cilium/ebpf version, bpffs pinning paths, rlimit/memlock handling. I did not find one.

---

## 3. Licensing and contribution terms

### Takeaway
- OBI's Go code is **Apache-2.0**.
- OBI-authored eBPF C sources are marked **SPDX Apache-2.0** in their headers but declare **"Dual MIT/GPL"** in the ELF `license` section. Exceptions: NetOlly flows declare **"GPL"** and rDNS XDP declares **"Dual BSD/GPL"**.
- Vendored libbpf headers keep their original `LGPL-2.1 OR BSD-2-Clause` or `GPL-2.0-only OR BSD-2-Clause` notices.
- Contributors must sign the **CNCF CLA through LF EasyCLA**. DCO sign-off is not required.
- OBI has its own Generative AI policy, derived from Cilium's.

For shawk, upstreaming eBPF code would in practice mean re-licensing it to OBI's convention: an Apache-2.0 SPDX header with a dual MIT/GPL kernel license string. That needs every shawk copyright holder to agree and to sign the CLA. Keeping `GPL-2.0-only OR BSD-2-Clause` headers would be a novel request; there is no written policy either way.

### Cited findings
- Repo license: Apache License 2.0. README: "licensed under the terms of the Apache Software License version 2.0". — [LICENSE](https://github.com/open-telemetry/opentelemetry-ebpf-instrumentation/blob/main/LICENSE), [README.md](https://github.com/open-telemetry/opentelemetry-ebpf-instrumentation/blob/main/README.md)
- `SPDX-License-Identifier` tally in `bpf/**/*.{c,h}`:
  - 343 × `Apache-2.0`;
  - 4 × `(LGPL-2.1 OR BSD-2-Clause)`: `bpfcore/bpf_tracing.h`, `bpf_helpers.h`, `bpf_endian.h`, `bpf_core_read.h`;
  - 2 × `(GPL-2.0-only OR BSD-2-Clause)`: `bpfcore/compiler.h`, `bpf_builtins.h`.
  `bpf/bpfcore/` ships `LICENSE`, `LICENSE.BSD-2-Clause`, `LICENSE.GPL-2.0-only` and `LICENSE.LGPL-2.1`. — local scan
- ELF license sections:
  - `"Dual MIT/GPL"`: generictracer, gotracer, tpinjector (3 objects), logenricher, gpuevent, statsolly, watcher;
  - `"GPL"`: `netolly/flows.c` and `flows_sock.c`;
  - `"Dual BSD/GPL"`: `rdns/rdns_xdp.c`.
  — local grep of `SEC("license")`
- Beyla donation proposal: "The eBPF probe source is dual-licensed GPL/MIT, which Grafana describes as required by the Linux kernel" (paraphrased from the issue page). — [community#2406](https://github.com/open-telemetry/community/issues/2406)
- NOTICE credits code "copied from, derived from, or inspired by" Grafana Beyla, Grafana jvmtools, OTel Go Auto-Instrumentation, libbpf, cilium/ebpf, cilium, NetObserv eBPF Agent and flowlogs-pipeline (Red Hat/IBM), the DataDog Agent, the New Relic Infrastructure Agent and Meta strobelight. — [NOTICE](https://github.com/open-telemetry/opentelemetry-ebpf-instrumentation/blob/main/NOTICE)
- CLA:
  - CONTRIBUTING: "Make sure CLA is signed and CI is clear." — [CONTRIBUTING.md](https://github.com/open-telemetry/opentelemetry-ebpf-instrumentation/blob/main/CONTRIBUTING.md)
  - OpenTelemetry "can only accept original source code from CLA signatories"; the linux-foundation-easycla bot checks on the first PR; there are individual and corporate CNCF CLAs. — [community guides/contributor/CLA.md](https://github.com/open-telemetry/community/blob/main/guides/contributor/CLA.md)
  - No DCO workflow exists in `.github/workflows`. Some contributors add `Signed-off-by` voluntarily, for example in #3796.
- AI policy: based on Cilium's. It requires human review and full accountability, disclosure of AI use "at level 2 or higher on the AI Influence Level", and forbids substantially AI-written community communication. — [AI-POLICY.md](https://github.com/open-telemetry/opentelemetry-ebpf-instrumentation/blob/main/AI-POLICY.md)

### Gaps
- There is **no written OBI policy on eBPF licensing**. I found no issue or discussion; the issue search for "license GPL" returned only PR #942.
- The mismatch between Apache-2.0 SPDX headers and "Dual MIT/GPL" kernel strings is not explained anywhere I found.
- Whether OBI would accept contributed eBPF files under `GPL-2.0-only OR BSD-2-Clause` is undocumented. Ask maintainers before planning (c).

---

## 4. Governance and contribution process

### Takeaway
- OBI is owned by the **OpenTelemetry SIG eBPF Instrumentation**, with multi-vendor maintainers. Grafana holds 2 of 7 maintainer seats and 2 of 4 approver seats.
- Feature proposals go through GitHub issues: a feature-request template, epics labelled `goal: 2026`, and the "OBI Roadmap" project board. Bigger designs are discussed in the weekly SIG meeting and sometimes written up as `devdocs/*.md` PRs. OTEPs are not used for OBI features.
- Scope:
  - "auto-instrumentation … using eBPF and other process-external technologies";
  - network metrics and flows are in scope, and the Network SIG plans to use OBI for flow traces and metrics;
  - VM/host deployments are in scope and actively being worked on (packaging, peer metadata);
  - maintainers push back on scope that duplicates other OpenTelemetry components.
- Releases were roughly monthly minors in v0. **v1.0.0 shipped 2026-10-30**; v1.1.0 is the next milestone, with no date.

### Cited findings

**SIG**
- SIG eBPF Instrumentation: Wednesday 08:00 PT; Slack `#otel-ebpf-instrumentation`; repo `open-telemetry/opentelemetry-ebpf-instrumentation`; TC sponsor David Ashpole (escalating); GC liaison Severin Neumann. — [community sigs.md](https://github.com/open-telemetry/community/blob/main/sigs.md#ebpf-instrumentation), [workstreams.yml](https://github.com/open-telemetry/community/blob/main/workstreams.yml)
- There is no GOVERNANCE.md in the OBI repo. General OpenTelemetry governance and the membership guide apply. Code owners: `* @open-telemetry/ebpf-instrumentation-approvers`. — [.github/CODEOWNERS](https://github.com/open-telemetry/opentelemetry-ebpf-instrumentation/blob/main/.github/CODEOWNERS)

**Maintainers** (CONTRIBUTING.md on `main`, 2026-10-30)

| Person | Company | Notes |
|---|---|---|
| Mario Macias | Grafana | |
| Mattia Meleleo | Coralogix | promoted to maintainer 2026-01-30 (#1212) |
| Mike Dame | Odigos | |
| Nikola Grcevski | Grafana | |
| Nimrod Avni | Coralogix | promoted 2026-01-30 (#1212) |
| Rafael Roquetto | Isovalent | maintainer since 2026-05-07 (#2063); org changed from Grafana on 2026-08-28 (#3242) |
| Tyler Yahn | Splunk | |

Approvers: Giuseppe Ognibene (Coralogix), Haibin Zhang (Alibaba Cloud, added 2026-09-21), Marc Tudurí (Grafana), Stephen Lang (Grafana). — [CONTRIBUTING.md](https://github.com/open-telemetry/opentelemetry-ebpf-instrumentation/blob/main/CONTRIBUTING.md) plus git history.

**Activity** (local `git log` since 2026-05-01)
- 896 non-bot commits from 60 distinct authors.
- Top authors: Tyler Yahn 236, Nimrod Avni 135, Giuseppe Ognibene 85, Nikola Grcevski 74, Mattia Meleleo 66, Mario Macias 48, Marc Tudurí 41, Stephen Lang 37, Haibin Zhang 31, Rafael Roquetto 21, Mike Dame 14.
- Rough share by employer: Coralogix ~32%, Splunk ~26%, Grafana ~22%.

**Process**
- Issues: the feature-request template asks for Component (OBI / k8s-cache / Other), Problem, Solution, Alternatives and Context. There is also a `new_instrumentation` template. Blank issues are disabled; questions go to GitHub Discussions or Slack. — [.github/ISSUE_TEMPLATE](https://github.com/open-telemetry/opentelemetry-ebpf-instrumentation/tree/main/.github/ISSUE_TEMPLATE)
- "For nontrivial changes, especially architectural or core instrumentation changes, we recommend discussing the approach with maintainers in an issue or on Slack before implementing it. This is a recommendation, not an approval process." — [CONTRIBUTING.md](https://github.com/open-telemetry/opentelemetry-ebpf-instrumentation/blob/main/CONTRIBUTING.md)
- Merge rules: at least one qualified approval (more for complex or sensitive PRs); atomic commits; "Changes must be small and focused". Unresolvable disagreements go to the weekly SIG meeting. — same
- Design docs are proposed as PRs that add `devdocs/*.md`. Example: [#3983](https://github.com/open-telemetry/opentelemetry-ebpf-instrumentation/pull/3983) "Design document: remote entity metadata service" (2026-10-29), which its author closed on 2026-10-30 to "rework the design manually".
- Large features may be developed on a separate branch until maintainers are ready. Example: [#3210](https://github.com/open-telemetry/opentelemetry-ebpf-instrumentation/issues/3210), process and I/O observability, deferred until after v1.0 and KubeCon NA 2026.
- Roadmap: [2026 goals blog (2026-01-23)](https://opentelemetry.io/blog/2026/obi-goals/), the "goal: 2026" label, and the OBI Roadmap board (org project 187). The v1.0 blog post invites proposals for **2027 planning**. — [blog 2026-10-30](https://opentelemetry.io/blog/2026/obi-v1-release/)

**Scope signals**
- "This project aims to provide auto-instrumentation functionality for applications using eBPF and other process-external technologies." It is not "a replacement for manual instrumentation". — [CONTRIBUTING.md "Scope"](https://github.com/open-telemetry/opentelemetry-ebpf-instrumentation/blob/main/CONTRIBUTING.md)
- Overlap with other OpenTelemetry projects is resisted:
  - mariomac on #3210 (2026-08-27): "we had to remove the Beyla Process monitoring capabilities to avoid duplicities with other OTEL projects";
  - mmat11 asked for "an explicit out-of-scope boundary";
  - grcevski nonetheless called it "very beneficial to add to the project".
  — [#3210](https://github.com/open-telemetry/opentelemetry-ebpf-instrumentation/issues/3210)
- The Beyla docs say OBI lacks process metrics, "With OBI, use the OpenTelemetry Collector Host Metrics Receiver". — [Beyla docs: Beyla and OBI](https://github.com/grafana/beyla/blob/main/docs/sources/introduction/obi.md)
- Network topology and dependency features in scope today:
  - service-graph metrics (`traces_service_graph_*`);
  - the opt-in `traces_service_graph_connection_info` gauge, "Indicates that a client-to-server connection was observed recently". It was added 2026-10-26 (#3796, by a Grafana engineer, "Align connection info feature naming with Tempo"), with stability `development`. — [schemas/obi/groups/service_graph/metrics.yaml](https://github.com/open-telemetry/opentelemetry-ebpf-instrumentation/blob/main/schemas/obi/groups/service_graph/metrics.yaml)
  - NetO11y flows and StatsO11y.
- I found no issue that explicitly accepts or rejects a process-level, all-protocol network dependency map. That is a **gap** and a question to ask the SIG.
- VM/host support is in scope:
  - standalone binary and Docker are supported;
  - Packaging SIG epic [#2828](https://github.com/open-telemetry/opentelemetry-ebpf-instrumentation/issues/2828) "Deliver OBI DEB/RPM packages" (open, 0/4 sub-issues; package `opentelemetry-obi` and virtual interface `opentelemetry-obi1`);
  - [#2837](https://github.com/open-telemetry/opentelemetry-ebpf-instrumentation/issues/2837) "Make standalone OBI suitable for managed Linux services" (systemd, open);
  - peer metadata for non-Kubernetes hosts (#3806).

**Release cadence** (tag dates)
- 2025: v0.1.0 (10-30), v0.2.0 (11-04), v0.3.0 (12-03).
- 2026 minors: v0.4.0 (01-08), v0.5.0 (02-11), v0.6.0 (03-06), v0.7.0 (04-03), v0.8.0 (04-16), v0.9.0 (05-11), v0.10.0 (06-30), v0.11.0 (08-17), v0.12.0 (08-19), v0.13.0 (09-04), v0.14.0 (10-02).
- 2026 pre-1.0 releases: v1.0.0-rc.1 (10-06), v0.15.2 (10-16; v0.15.0 and v0.15.1 were never published because of BPF verifier failures), v1.0.0-rc.2 (10-16), **v1.0.0 (10-30)**.
- Patch releases in between: v0.4.1, v0.7.1, v0.12.1 and v0.12.2.
- No cadence is documented. Nightly images are published (`nightly-release.yml`, cron 02:00). — local git tags, [releases page](https://github.com/open-telemetry/opentelemetry-ebpf-instrumentation/releases)
- Release mechanics: the tag triggers the full CI suite and then a **draft** release; at least 2 maintainers sign off on an RC; RCs stay available for at least 14 days; releases are immutable. Artifacts are Cosign-signed with SBOMs. — [RELEASING.md](https://github.com/open-telemetry/opentelemetry-ebpf-instrumentation/blob/main/RELEASING.md), [#1133](https://github.com/open-telemetry/opentelemetry-ebpf-instrumentation/issues/1133)

**v0 breaking-change policy**
- "breaking changes are allowed in minor releases"; patch releases are for backward-compatible fixes.
- Bump the minor for incompatible changes to "public packages, flags, config, defaults …, telemetry shape or naming, support expectations, or release artifact behavior".
- "dashboards, alerts, and downstream processors should not assume telemetry continuity across `v0` minor releases".
— [VERSIONING.md](https://github.com/open-telemetry/opentelemetry-ebpf-instrumentation/blob/main/VERSIONING.md)

**1.0 plan and what "stable" covers**
- Epic [#1133](https://github.com/open-telemetry/opentelemetry-ebpf-instrumentation/issues/1133) (opened 2026-01-20, sponsor MrAlias):
  - planned "v1.0.0: Oct 30, 2026 at the latest";
  - closed as completed 2026-10-30 (29/29 sub-issues);
  - sign-offs from MrAlias, mmat11, rafaelroquetto, grcevski, damemi and NimrodAvni78 (2026-10-28).
- Stable at v1.0:
  - the Config v2 model and generated schema;
  - the supported subset of OpenTelemetry declarative configuration;
  - documented CLI flags and environment variables;
  - documented binary and container behavior;
  - the documented emitted telemetry surface, meaning registry entries classified `stable`, in both OTLP **and** the built-in Prometheus exporter ([TELEMETRY.md](https://github.com/open-telemetry/opentelemetry-ebpf-instrumentation/blob/main/TELEMETRY.md));
  - the support matrix;
  - the upgrade and versioning policy.
  "Anything not explicitly included above remains outside the `v1` compatibility contract."
- Not covered:
  - **network flow attribute names** ("excluded from the stable v1 telemetry surface"; [#1092](https://github.com/open-telemetry/opentelemetry-ebpf-instrumentation/issues/1092));
  - full per-process declarative config parity (#923, #2251);
  - complete registry coverage (#2562, moved to v1.1.0);
  - the root Go API;
  - the Collector receiver.
- In the registry, `obi.network.flow.bytes`, `obi.network.flow.packets`, `obi.network.inter.zone.bytes` and all `obi.stat.tcp.*` metrics are `stability: development`. — [schemas/obi/groups/network/metrics.yaml](https://github.com/open-telemetry/opentelemetry-ebpf-instrumentation/blob/main/schemas/obi/groups/network/metrics.yaml), [stats/metrics.yaml](https://github.com/open-telemetry/opentelemetry-ebpf-instrumentation/blob/main/schemas/obi/groups/stats/metrics.yaml)
- Next milestone, v1.1.0: no due date ("will be set after the v1.0.0 release"), 142/150 issues closed; "Changes must keep v1 compatibility". — [milestones](https://github.com/open-telemetry/opentelemetry-ebpf-instrumentation/milestones)

### Gaps
- Several repo docs still describe OBI as being in "Development", including at the `v1.0.0` tag: README "Project Status", VERSIONING.md "Current status" and the SUPPORT_MATRIX.md preamble. The release notes, blog and TELEMETRY.md say v1 is stable. Treat the release notes as authoritative; this is documentation lag.
- No written release cadence.
- No written statement on whether a "network dependency map" or per-process connection inventory is in scope.

---

## 5. Relationship to the archived opentelemetry-network project

### Takeaway
- opentelemetry-network was archived on **2026-10-07**. It had no owning SIG, no active maintainers and no security updates.
- The community discussion named OBI as the natural home, but **no concrete migration plan exists in OBI**. I found no issue or PR to port the reducer, both-ends connection matching, or conntrack/NAT resolution; OBI's code has no conntrack handling at all.
- What does exist:
  - StatsO11y, whose origin was "Extend network metrics" (#1153, which asked for opentelemetry-network-like metrics);
  - **peer metadata exchange** (#3806), which partially covers "merging metadata from both sides of a socket" for directly routable hosts and explicitly does *not* handle NAT, proxies or load balancers;
  - the Mermin (ElastiFlow) port and flow semantic conventions, coordinated through the new **Network SIG**.

### Cited findings
- "This repository was archived by the owner on Oct 7, 2026." The README describes the kernel collector, k8s and cloud collectors, and the reducer, and does not point to a successor. — [opentelemetry-network](https://github.com/open-telemetry/opentelemetry-network)
- [community#3693](https://github.com/open-telemetry/community/issues/3693) "Is it ok to archive the opentelemetry-network repository?" (trask, 2026-09-16; still shown as open when fetched):
  - dashpole: "we do want to retire the repo, but … we wanted to work on a migration story";
  - svencowart: OBI is "the natural home" and gaps should be compared;
  - grcevski: "we'll try to re-use OBI as the event generation for the eBPF-network project", and mariomac is looking at service-name-to-IP mapping;
  - yonch: services-to-IP matching and "merging metadata from both sides of a socket" are easier to evolve from the existing repo, but "if we are moving in a different direction and want to archive … we can do that";
  - trask (2026-10-06): will archive because it is unmaintained and missing security updates.
  No reducer, conntrack or NAT porting is mentioned.
- OBI [#356](https://github.com/open-telemetry/opentelemetry-ebpf-instrumentation/issues/356) "Can it be used as a replacement for opentelemetry-network?" (2025-07-23). mariomac: "yes in many cases", but "the replacement is not automatic or effortless, since we provide a different set of network metrics".
- OBI [#1153](https://github.com/open-telemetry/opentelemetry-ebpf-instrumentation/issues/1153) "Extend network metrics" asked for metrics like opentelemetry-network's `metrics.yaml`. It was closed by #1572 (StatsO11y) on 2026-03-21. svencowart (2026-08-13): "If we have feature parity, I'd like to move towards deprecating the `opentelemetry-network` project". No reply is shown.
- Donation proposal [community#2406](https://github.com/open-telemetry/community/issues/2406): Beyla "would revive" opentelemetry-network because it covers much of that functionality (summary).
- Peer metadata ([devdocs/peer-metadata.md](https://github.com/open-telemetry/opentelemetry-ebpf-instrumentation/blob/main/devdocs/peer-metadata.md), [PR #3806](https://github.com/open-telemetry/opentelemetry-ebpf-instrumentation/pull/3806), merged 2026-10-30, milestone v1.1.0):
  - OBI agents on directly routable hosts exchange inventories of instrumented services and TCP listeners, plus recent callers, over HTTP(S) `GET /v1/metadata` (port 8998, optional token+TLS, `peer_cidrs`);
  - this lets client spans resolve the remote service by IP:port, and server spans learn caller services;
  - "UDP listener attribution is not supported"; "This protocol assumes trusted peers and does not account for NAT, proxies, or load balancers"; it is off when Kubernetes enrichment is on;
  - mariomac: "I see this feature as highly experimental".
  Follow-ups: [#3997](https://github.com/open-telemetry/opentelemetry-ebpf-instrumentation/pull/3997) "Abstract peer metadata interface for other modes of data submission/retrieval" (merged 2026-10-30) and the closed design [#3983](https://github.com/open-telemetry/opentelemetry-ebpf-instrumentation/pull/3983) for a central "remote entity metadata service" that would map IP to service identity outside Kubernetes, discussing Route53 and overlapping-CIDR conflicts.
- Flow traces: [#1659](https://github.com/open-telemetry/opentelemetry-ebpf-instrumentation/issues/1659) "Proposal: emit trace-correlated L3/L4 network flow spans" (open, **stale** since 2026-10-02). The SIG decided flow spans should be part of the application layer, opt-in, TCP first. svencowart (ElastiFlow) says Mermin is being ported into OBI, with flow semantic conventions in semantic-conventions PR #3656 and "No firm timeline".
- Network SIG project:
  - goals include "standardized metrics and flow trace instrumentation within … OBI";
  - long-term: "Collaborate with the OBI SIG to instrument the network, targeting the generation of flow traces and metrics via eBPF";
  - network entities with the Entities SIG;
  - staffing includes OBI people (pinoOgni, skl, mariomac).
  — [community projects/network.md](https://github.com/open-telemetry/community/blob/main/projects/network.md), [sigs.md#network](https://github.com/open-telemetry/community/blob/main/sigs.md#network) (Monday 07:00 PT, TC sponsor lmolkova, GC liaison tedsuo)
- No conntrack or NAT logic in OBI: `grep -i 'conntrack|nf_nat|SNAT|DNAT'` over `pkg/`, `bpf/` and `devdocs/` matches only `vmlinux.h` type definitions. I found no "reducer" concept.

### Gaps
- No issue or PR in OBI tracks parity with opentelemetry-network: both-ends socket merging, NAT/conntrack, reducer-style central aggregation, or the k8s/cloud collectors. Searches tried: `conntrack`, `NAT`, `"opentelemetry-network"`, `"both sides"`, `"feature parity"`, `"gap analysis"`, `topology`, `"dependency map"`, `"service map"`, `entities`.
- svencowart's promised gap analysis (community#3693, Sep 17) was not visible as of 2026-10-31.

---

## 6. Roadmap items relevant to shawk

| Topic | Current state (2026-10-31) | Open or roadmap items | Source |
|---|---|---|---|
| **Non-Kubernetes host/VM support** | Standalone binary and container are supported. Linux 5.8+ or RHEL 4.18+ with BTF; amd64/arm64; root or capabilities. Cloud name resolution for ECS, Route53 (with auto-detected hosted zones), GCE and Azure VMSS was added Oct 2026. | DEB/RPM packaging epic **#2828** (open, 0/4); **#2837** systemd-friendly runtime (open); Packaging SIG (`apt install opentelemetry` exists without OBI; "we will work with the OBI folks"); non-BTF fallback proposal **#3643** (open). | [SUPPORT_MATRIX.md](https://github.com/open-telemetry/opentelemetry-ebpf-instrumentation/blob/main/SUPPORT_MATRIX.md), [#2828](https://github.com/open-telemetry/opentelemetry-ebpf-instrumentation/issues/2828), [#2837](https://github.com/open-telemetry/opentelemetry-ebpf-instrumentation/issues/2837), [Packaging blog 2026-07-23](https://opentelemetry.io/blog/2026/packaging-first-repo/), [community projects/packaging.md](https://github.com/open-telemetry/community/blob/main/projects/packaging.md) |
| **Service identity across hosts** (both ends) | **Peer metadata exchange** (#3806, experimental, merged 2026-10-30; TCP only, no NAT/proxy). | Abstract peer-metadata interface (#3997, merged); central "remote entity metadata service" design being reworked (#3983, closed). | §5 |
| **Network flow features** | NetO11y bytes/packets/inter-zone metrics (development); TC or socket-filter source; GRO/TSO counting fix (#3964, 2026-10-29). | **#1092** rename to semantic conventions (open, "breaking change", post-v1; MrAlias: "A PR would be welcome"); #1091 flow-attribute proposal; #1659 flow spans (stale); Mermin port (no timeline). | [#1092](https://github.com/open-telemetry/opentelemetry-ebpf-instrumentation/issues/1092), [#1659](https://github.com/open-telemetry/opentelemetry-ebpf-instrumentation/issues/1659) |
| **StatsO11y expansion** | TCP RTT, failed, successful, retransmits and IO, all development. Real local port reported for closed sockets (#3992, 2026-10-30). | Discussion #1906 "OTel Semantic Conventions Proposal TCP/UDP stat metrics" (2026-04-23); semconv TCP/UDP proposal semantic-conventions#3682 under the Network SIG. **No UDP stats yet.** | [devdocs/metrics.md](https://github.com/open-telemetry/opentelemetry-ebpf-instrumentation/blob/main/devdocs/metrics.md), [discussions](https://github.com/open-telemetry/opentelemetry-ebpf-instrumentation/discussions/1906), [projects/network.md](https://github.com/open-telemetry/community/blob/main/projects/network.md) |
| **Conntrack/NAT** | None. | None found. | §5 |
| **Process-level network attribution** | NetO11y and StatsO11y have **no process attributes**; StatsO11y is node-wide by design. The dynamic selector maps flows to services by pod or container IP only. AppO11y spans and the connection-info metric carry process/service identity **for parsed protocols only**. Process metrics were removed (#965). | #3210 process lifecycle and I/O observability (proposal, separate branch, no per-process network attribution). Nothing found for per-process TCP/UDP connection inventory. | §1, [#3210](https://github.com/open-telemetry/opentelemetry-ebpf-instrumentation/issues/3210) |
| **OTel Entities** | No Entities code or emission in OBI. A grep for entity, EntityRef and similar found only unrelated hits. | Network SIG plans network entities with the Entities SIG. I found no OBI issue. | [projects/network.md](https://github.com/open-telemetry/community/blob/main/projects/network.md) |
| **Kernel hook style** | kprobe, tracepoint and uprobe based; no fentry or tp_btf. | **#1099** fentry/fexit fast path with kprobe fallback (evaluation spike, no decision). | [#1099](https://github.com/open-telemetry/opentelemetry-ebpf-instrumentation/issues/1099) |
| **Overhead control** | Per-feature stubbing in StatsO11y. | **#2159** selective loading of eBPF parts (open). | [#2159](https://github.com/open-telemetry/opentelemetry-ebpf-instrumentation/issues/2159) |
| **Collector integration** | Receiver alpha, v0 line; in otelcol-contrib. | No receiver path to stable is documented. | §2 |

---

## 7. Grafana's relationship: Beyla, Alloy and long-term maintenance

### Takeaway
- **Beyla is now "the Grafana Labs distribution of OBI"**. It imports OBI as a library through a git submodule and a `replace`. The submodule points at Grafana's fork, which carries Beyla release branches, and Beyla bumps it roughly weekly. Beyla adds Grafana-specific features on top: process metrics, survey mode, Alloy integration, AI Observability and Tempo service-graph wiring.
- **Alloy's `beyla.ebpf` component no longer links Beyla or OBI as Go code.** Since July 2026 it embeds a checksum-pinned **Beyla binary** (currently v3.40.0) and runs it as a subprocess, ingesting its OTLP over a Unix socket.
- So Grafana's commercial stack depends on OBI `main` (via Beyla) but has deliberately isolated Alloy from OBI's Go dependency graph. That is a useful precedent against in-process embedding.
- Long-term maintenance looks multi-vendor and well staffed. Grafana is one of three large contributors (with Coralogix and Splunk), and OBI does not depend on Grafana alone.

### Cited findings
- Beyla README: "Beyla has been donated … under the project name OpenTelemetry eBPF Instrumentation … We are in the process of vendoring most of the code … All Beyla current maintainers work full time on the upstream repository." — [grafana/beyla README](https://github.com/grafana/beyla/blob/main/README.md)
- Beyla docs:
  - "Grafana Beyla is the Grafana Labs distribution of OpenTelemetry eBPF Instrumentation";
  - "the Grafana Beyla code repository imports it as a library";
  - "Every feature that's available in OBI is also available in Beyla";
  - "Beyla usually releases more often than OBI";
  - Beyla-only features are process metrics, survey mode, "Integration inside Grafana Alloy", Grafana AI Observability, and "Connecting spans for Tempo service graph metrics";
  - metric prefixes differ (`beyla_` vs `obi_`), and environment variables use `BEYLA_` and `OTEL_EBPF_`.
  — [docs/sources/introduction/obi.md](https://github.com/grafana/beyla/blob/main/docs/sources/introduction/obi.md)
- Beyla `go.mod`: `replace go.opentelemetry.io/obi => ./.obi-src`, with `go.opentelemetry.io/obi v0.15.2` in `require`. `.gitmodules` points at `https://github.com/grafana/opentelemetry-ebpf-instrumentation.git`.
- On Beyla `main` the submodule is at upstream `8a51e026` (OBI #3796, 2026-10-26). On **Beyla v3.40.0** (2026-10-26) it is at `4838a24c`, which is `refs/heads/release-3.40` and `refs/tags/v3.40.0` in Grafana's fork.
- Submodule bumps on Beyla `main`: 09-22, 09-23, 09-28, 10-05, 10-15, 10-19, 10-26, 10-29. — local Beyla clone, `git ls-remote` of the fork
- Beyla MAINTAINERS lists Marc Tudurí, Mario Macias, Nikola Grcevski, Rafael Roquetto and Stephen Lang, all as Grafana. Rafael's entry is stale: OBI lists him at Isovalent since 2026-08-28. — [MAINTAINERS.md](https://github.com/grafana/beyla/blob/main/MAINTAINERS.md)
- Alloy `beyla.ebpf`:
  - docs front-matter `stage: general-availability`;
  - "{{PRODUCT_NAME}} spawns Beyla as a child process and transfers the required capabilities through the kernel's inheritable and ambient capability sets";
  - component README: "Runs Grafana Beyla … as a **child process** … spawns the embedded Beyla binary, then ingests Beyla's telemetry";
  - `beyla_version.yaml`: `version: v3.40.0` with sha256 checksums;
  - Alloy's `go.mod` has **no** Beyla or OBI module.
  — [Alloy docs beyla.ebpf.md](https://github.com/grafana/alloy/blob/main/docs/sources/reference/components/beyla/beyla.ebpf.md), [component README](https://github.com/grafana/alloy/blob/main/internal/component/beyla/ebpf/README.md), [updating-beyla.md](https://github.com/grafana/alloy/blob/main/docs/developer/updating-beyla.md)
- The switch happened in [alloy#6695](https://github.com/grafana/alloy/pull/6695) "Implement Beyla as a subprocess", by rafaelroquetto, merged **2026-07-21**:
  - "Go API removed in favor of embedding a verified Beyla binary and executing it as a subprocess";
  - the goal was "to avoid pulling Beyla as a dependency".
  The latest bump is Alloy #7531, Beyla v3.40, on 2026-10-28.
- Grafana blog (2026-01-14): "Grafana Labs is fully committed to the open source OpenTelemetry project", and Beyla was donated in 2025. — [Grafana blog](https://grafana.com/blog/opentelemetry-and-grafana-labs-whats-new-and-whats-next-in-2026)
- The first OBI alpha announcement credits "Grafana Labs, Splunk, Coralogix, Odigos and many other community members". — [blog 2025-11-03](https://opentelemetry.io/blog/2025/obi-announcing-first-release/)
- Other embedders: **Odigos** embeds OBI as a Go library (odiglet). **otelcol-contrib** ships the receiver. This broadens the set of stakeholders that maintain OBI's embedding surfaces.

### Gaps
- Grafana has made no explicit public statement about headcount committed to OBI after v1.0.
- Alloy#6695 does not spell out why Grafana chose the subprocess model. Only "avoid pulling Beyla as a dependency" is stated. Plausible reasons are dependency conflicts, binary size, the bpf2go toolchain and crash isolation, but these are my inference.

---

## Implications for options (a)–(d)

**(a) Run OBI unmodified next to shawk and align names.** *Lowest risk; recommended near-term baseline.*
- OBI v1.0.0 supports standalone Linux hosts and VMs. Its value is complementary to shawk's:
  - L7 spans and RED metrics, plus a service graph and `connection_info` edges, for parsed protocols;
  - IP-level flows (NetO11y) and node-wide TCP stats (StatsO11y).
- None of these give shawk's core output: **per-process, all-protocol TCP/UDP "who talks to whom"**.
- Name alignment:
  - Align with OpenTelemetry **semantic conventions** and with OBI's **stable resource/service identity** (`service.name`, `service.namespace`, `service.instance.id`, `host.id`/`host.name`).
  - Do **not** align with OBI's flow attributes (`src.*`, `dst.*`, `direction`, `iface`): they are excluded from v1 and scheduled for renaming (#1092 → `source.*`, `destination.*`, `network.transport`, `network.interface.name`, `flow.direction`).
  - If shawk emits a dependency edge metric, consider matching the shape of `traces_service_graph_connection_info` (client/server/namespace attributes), noting it is `development`.
- Operational notes:
  - Both agents need eBPF capabilities and may hook the same TCP functions, so overhead adds up.
  - OBI uses TC and cgroup-attached `sk_msg`/`sockops` for context propagation. Check coexistence on shawk's target hosts.
  - DEB/RPM packaging (#2828) is not shipped yet.

**(b) Custom Collector distribution: OBI receiver plus shawk receiver/connector/exporter.** *Technically feasible, but it ties shawk to OBI's v0/alpha receiver and its dependency graph.*
- It works the way otelcol-contrib does it: `ocb` with `go.opentelemetry.io/obi/collector v0.15.2`, and `replaces` for both OBI modules pointing at the verified `obi-v1.0.0-source-generated.tar.gz` (or a local `make generate`).
- Costs and risks:
  - The receiver is **Alpha** and on a separate **v0** line, so breaking changes are allowed.
  - The Collector core versions are pinned by OBI's `collector/go.mod` (v0.163/v1.69 on `main`), so shawk's distribution must move in lock-step.
  - shawk inherits about 226 modules (client-go, AWS/Azure/GCP SDKs) and is forced to OBI's `cilium/ebpf` version (≥ v0.22.0).
  - OBI sets the process-global `slog` default and a klog bridge.
  - One crash domain holds two privileged eBPF agents.
  - shawk cannot hook into OBI's net/stats record queues, because their types are internal. Integration would be at the OTLP/pdata level only.
- Grafana's own move away from in-process linking (Alloy#6695) argues for a looser variant: use **otelcol-contrib (which already contains the OBI receiver) or standalone OBI**, and have shawk export OTLP into the same Collector. This gives the same pipeline with no Go-level coupling.

**(c) Contribute shawk's dependency tracer upstream as an OBI feature.** *Strategically attractive, since it fills a real gap and the timing suits 2027 planning, but it is a large rewrite and needs governance and licensing groundwork first.*
- Fit:
  - OBI and the Network SIG want flow and topology telemetry.
  - Non-Kubernetes identity work (peer metadata) is active.
  - The `connection_info` metric shows appetite for lightweight topology edges.
  - No one is working on per-process, all-protocol connection inventory or conntrack/NAT.
  - opentelemetry-network's archival leaves that space open.
- Friction:
  - StatsO11y is deliberately PID-free ("unreliable PID calculations"), so a process-attributed design needs an explicit argument and SIG buy-in.
  - Maintainers guard scope against overlap, for example with hostmetrics.
  - The code must be rewritten to OBI conventions: C under `bpf/<subsystem>`; kprobe/tracepoint/iter hooks with no fentry or tp_btf until #1099 lands (RHEL8 4.18 and 5.8 floor); loaders in `pkg/internal`; a `swarm` pipeline; feature flags and Config v2 schema; Weaver registry entries (new telemetry starts as `development`); OTLP and Prometheus exporters; verifier and VM tests across 5.10–7.2 and RHEL.
- Licensing: shawk's eBPF code (`GPL-2.0-only OR BSD-2-Clause`) would likely need relicensing to OBI's Apache-2.0 SPDX convention with a dual-GPL kernel string. Every copyright holder would need to agree, and each must sign the CNCF CLA. Ask maintainers first, because there is no written policy.
- Process:
  1. Open a feature issue.
  2. Present at the Wednesday SIG.
  3. Submit a `devdocs/` design PR.
  4. Possibly develop on a branch.
  5. Submit small PRs, following the AI policy.
- Coordinate with the Network SIG on attribute names (`source.*`, `destination.*`) and on entities.

**(d) Replace shawk's tracer with OBI entirely.** *Not viable as of v1.0.0 without losing shawk's core capability.*
OBI v1.0.0 has:
- no per-process attribution in its flow or stats data;
- no edges for unparsed TCP or for UDP;
- no conntrack/NAT;
- no socket-iterator snapshot of pre-existing connections exposed as telemetry;
- process metrics removed;
- network and stats telemetry that is entirely `development`, with flow attribute names slated to change.

A dependency map rebuilt from OBI's L7 service graph, `connection_info` and IP flows would cover instrumented, protocol-parsed services only. Re-evaluate after (c) lands upstream, or if OBI gains per-process connection telemetry.

**Suggested sequencing (my inference):** (a) now, emitting OTLP into a Collector (possibly otelcol-contrib, which already bundles the OBI receiver) → open a scoping issue and SIG discussion for (c) during 2027 planning, including the licensing question → choose (b) only if a single binary is a hard requirement, and even then prefer the subprocess or side-by-side pattern over in-process linking.
