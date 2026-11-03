## Unreleased

* The time to connect and why connects fail, per dependency, measured
  passively on the connections that hosts open (phase 1 of
  `docs/proposal-path-quality.md`). The state change program of TCP now
  measures the handshake of every active open from `connect(2)` to the
  SYN-ACK, the SYNs it retransmitted, and the reason of a failure:
  `refused`, `timeout`, `unreachable`, `local` (no SYN sent, e.g. no free
  local port), `aborted` (the application gave up first) or `_OTHER`.
  The agent sends them on TCP client edges as the new metrics
  `shawk.tcp.handshake` (a histogram with buckets from 100 µs to 3 s),
  `shawk.tcp.syn_retransmits` and `shawk.connection.failed.by_reason`
  (with `error.type`), and `shawk flows` shows them. The connector
  forwards them per dependency as `shawk_tcp_handshake_seconds_sum` and
  `_count`, `shawk_tcp_syn_retransmits_total` and
  `shawk_connection_failed_by_reason_total{error_type}`, with the new
  recording rules `shawk:dependency_handshake_seconds_sum:rate5m`,
  `shawk:dependency_handshake_seconds_count:rate5m`,
  `shawk:dependency_syn_retransmits:rate5m` and
  `shawk:dependency_connection_failures_by_reason:rate5m`, and panels in
  the dependency details dashboard. No existing metric, label or table
  changes (`shawk flows` gains three columns), and the agents and
  connectors can be upgraded in either order: a connector of the
  previous version ignores the new metrics, and the edges of agents of the
  previous version have none of the new series. The flow tables of the
  agent take 2.6 MB more with the default `-max-flows`.
* The losses of new cgroups are visible (#126): the new counter
  `shawk.agent.container_reads.dropped`
  (`shawk_agent_container_reads_dropped_total`) tells how many containers
  of new cgroups were not queued to be read because the queue was full,
  and the new Prometheus alerts `ShawkCgroupEventsDropped` (warning) and
  `ShawkContainerReadsDropped` (info) fire when either counter increases.
  A test of the kernel creates a burst of 3000 cgroups: a reader that
  keeps up gets all of them, one that stalls gets the 496 that the ring
  buffer holds, and the drops of the others are counted.
* The state of a container is read on a worker instead of the goroutine
  that drains the events of new cgroups (#126), which the kernel dropped
  while it read the files of the runtimes, such as several MB of
  `containers.json` on a busy host of Podman or CRI-O: the cgroups of a
  burst of new containers lost their paths. The export no longer waits
  for these reads either. The new counter
  `shawk.agent.cgroup_events.dropped`
  (`shawk_agent_cgroup_events_dropped_total`) tells how many new cgroups
  the kernel did not report because the agent read too slowly.
* Dependencies through relays without an agent that rewrite addresses
  (#107): load balancers, keepalived or LVS virtual addresses, TCP
  proxies. `translations` in the configuration of the connector gives
  their virtual addresses, their backends and, for a relay that replaces
  the addresses of the clients, the addresses the backends see them at;
  the connector writes them to the new table `shawk.translations`
  (migration 12; run `grants.sql` again). `shawk_v1.dependencies` and
  `dependencies_between` match a client edge to a virtual address with
  the server edges at its backends, over the period both were active in,
  with the address and port of the server; the new last columns
  `virtual_addr`, `virtual_port` and `translation` tell what the client
  connected to. A server edge from the addresses of a relay keeps a row of
  its own too, since clients without an agent may be behind the relay, and
  so does another matched edge over a time its matched rows do not cover.
  On these rows, the observation of a side whose edge outlives the row is
  NULL, so that a stopped agent does not make a dependency disappear.
  `dependencies_between` is dropped and created again with the new
  columns: drop a view or a `BEGIN ATOMIC` function of yours that depends
  on it before the migration, and create it again after. In Prometheus, the peer of a client edge to a virtual address is
  the service at a backend, with the `server.port` of the backend, and the
  peer of a server edge behind a relay that keeps the addresses of the
  clients is the client service. The backends of Kubernetes services and
  Docker published ports change too often to be written down; learning
  the translations from conntrack on the hosts that make them is proposed
  in `docs/proposal-translation.md`.
* Fixed: connectors that started at the same time with different
  `peer_cidrs` could leave the ranges of both in PostgreSQL, and a
  database that defaults to REPEATABLE READ failed the write. The
  configuration of a connector (`peer_cidrs` and the translations) is
  written in one transaction in READ COMMITTED, one connector at a time.
* Fixed: the edges of the dependency map dashboard had no arrowheads in
  Grafana 12.2 and 13.3, so the direction of a dependency could not be
  seen. The Node Graph refers to the arrowhead of an edge by its id,
  unescaped, in `url(#...)`, which the spaces of the ids of
  `shawk_v1.graph_edges` (`client -> server`) made invalid. The dashboard
  shows the md5 of the id instead; `shawk_v1` is unchanged.
* A container keeps its name when it is recreated (#104). `shawk.unit` of a
  process in a container was `docker-<id>`, `podman-<id>`,
  `cri-containerd-<id>` or `crio-<id>`, so every redeploy added rows to
  `shawk.processes` and split the history of a container. It is now
  `k8s/<namespace>/<workload>/<container>` for a pod of Kubernetes,
  `docker/<project>/<service>` for Docker Compose, and `docker/<name>`,
  `podman/<name>` or `containerd/<name>` otherwise, read from the state
  the runtime keeps on disk when the cgroup is created; the id is the new
  attribute `container.id`, which the connector reads to keep the series
  of the replicas of a unit apart. Upgrade the connectors before the
  agents: a connector of the previous version takes the series of the
  containers of one unit for one series, and counts the connections of
  only one of them. The cgroupfs drivers of Docker and kubelet
  (`/docker/<id>`, `/kubepods/.../pod<uid>/<id>`) are recognized; their
  processes were named after the raw id. A container whose state cannot
  be read, such as a rootless one, is named `<runtime>-<12 hex digits>`
  (`containerd-` rather than `cri-containerd-`), or `container-<12 hex
  digits>` when the cgroup does not tell the runtime; a container in a
  container is named after the outer one. The labels of a pod or of
  Compose that Docker copies from the image name a container only with
  the name cri-dockerd or Compose gives it. The processes of a pod of
  Kubernetes are named after the workload of the pod (the name of the pod
  without the suffixes Kubernetes generates) unless they set
  `OTEL_SERVICE_NAME`, and get the namespace of the pod as
  `service.namespace` unless `OTEL_RESOURCE_ATTRIBUTES` sets one, also
  when they set `OTEL_SERVICE_NAME`: the Prometheus `job` of a pod changes
  from the executable (or `billing`) to `<namespace>/<workload>` (or
  `<namespace>/billing`), as OBI names them. OBI prefers the labels
  `app.kubernetes.io/instance` and `app.kubernetes.io/name` of the pod,
  which the agent cannot see, so the `job` of pods with these labels may
  differ from that of OBI. The existing rows of `shawk.processes` of
  containers keep their old units.
* The kernel folds the peers outside the internal ranges of the host into
  one dependency per local endpoint (#96). On an internet-facing host, the
  clients of a local server on the Internet no longer make one flow, one
  series and one edge in PostgreSQL per address, which filled the flow
  table (and dropped the flows of other dependencies), the requests of the
  agent and `shawk.edges`. `-internal-peers` lists the ranges whose peers
  are kept exact (default `private`: RFC 1918, CGNAT, loopback, link-local
  and IPv6 ULA; loopback and the addresses of the host are always kept);
  `-fold-external` folds the external peers of incoming flows (`in`, the
  default), of all flows (`all`) or of none (`none`). A folded edge carries
  `shawk.peer.folded=true` with `network.peer.address` 0.0.0.0 or ::, and
  the connector writes its peer to PostgreSQL as the network 0.0.0.0/0 or
  ::/0 and names it `~external` (or after a range of `peer_cidrs` holding
  the whole network); `keep_peer_address` outputs the network. The address
  of each external client is no longer recorded; set `-fold-external=none`
  where it is needed. A fleet that uses public addresses internally must
  add them to `-internal-peers`, and so must one whose `peer_cidrs` name
  public ranges, whose peers are otherwise named `~external`. The connector
  logs a warning, at most once an hour per host, when an agent folds a
  client (or, with `all`, a server) that runs an agent, whose connections
  then do not match (not when both agents fold the other side), and, at
  most once an hour per configuration, when agents fold the peers of a
  range of `peer_cidrs`. An IPv6 range of `-internal-peers` that overlaps
  `::ffff:0:0/96`, such as `::/0`, is refused. Upgrade the connectors
  before the agents: a connector of the previous version keeps a folded
  peer as the address 0.0.0.0 or ::, which it names `~unresolved`.
* The periods in which an agent dropped flows are recorded (migration 11):
  the new table `shawk.partial_observations` and the function
  `shawk_v1.partly_observed(since, until)`, so that the absence of a
  dependency over them is not taken for disuse. The fleet, dependency
  details and changes dashboards annotate them, and the fleet dashboard
  lists them. The drops of each run of an agent are compared with what
  PostgreSQL holds for the run, so several connectors and restarts record
  them once (`shawk.agent_sessions.counters_started`). `shawk_v1.agents`
  and `shawk_v1.agent_addrs` gain the columns `peer_fold` and
  `peer_internal` at their end. Connectors of the previous version keep
  writing during an upgrade, but do not record these periods.
  Run `grants.sql` again after the migration.
* The systemd units are sandboxed: the agent keeps only the capabilities it
  needs (`CAP_BPF`, `CAP_PERFMON`, `CAP_SYS_ADMIN`, `CAP_SYS_PTRACE`,
  `CAP_DAC_READ_SEARCH`) and both units filter system calls and address
  families. `ProtectHome=yes` replaces `read-only`: the binary and the TLS
  files of the agent must not be under `/home` or `/root`; override it with a
  drop-in otherwise.
* The release archive of the agent contains its systemd unit and
  `agent.env`; deb packages have their copyright in
  `/usr/share/doc/<package>/copyright`; archives, packages and the collector
  image ship the licenses of the Go modules linked into the binaries
  (`THIRD_PARTY_NOTICES`).
* `make build` and `make collector` set the version without the `v` of the
  tag (`0.8.0`), like the release.
* The BPF programs are tested on the kernels of Rocky Linux 9.6 (x86_64 and
  aarch64) and upstream 5.14 and 5.15 in virtual machines (`make vm-test`),
  and on an arm64 runner. On Rocky Linux 9 on aarch64, which has no BPF
  trampolines, UDP is not traced.
* Fixed: on kernels before 6.4, such as RHEL 9 and upstream 5.14, two
  CPUs that created the same flow at once could lose a connection or its
  bytes, counted in `shawk.agent.flows.dropped` as if the flow table were
  full (#119): the `-EEXIST` of the CPU that lost the race was not
  recognized, since the map operation returns it in 32 bits. A connection
  whose count fails is now counted by its next walk or its close. The agent
  warns when updates are dropped because another update of the same bucket
  was in progress on the same CPU (`-EBUSY`), not because the table was
  full.
* Fixed: UDP direction (#99). A connected client socket on a port the
  kernel chose that existed before the agent started and receives before
  it sends again is no longer recorded as a server of its own port, and
  the connected per-client sockets of a QUIC server started since the last
  walk are servers.
* Fixed: a UDP GSO send or GRO receive counted as one datagram, a peeked
  empty datagram counted twice, and IPv6 datagrams with extension headers
  were not counted.
* Fixed: a child of a TCP Fast Open listener reset or closed before its
  handshake completed was not counted, with the data of its SYN.
* Fixed: a listener replaced by another process of the same cgroup was
  attributed to the former process until the next periodic owner scan
  (up to a minute).
* The new table `shawk.listener_owners` keeps every known owner of a
  listener, so its history is kept when it changes hands (migration 10, from
  the migration on). `shawk.listeners` is unchanged, so connectors of the
  previous version keep writing during an upgrade. Run `grants.sql` again
  after the migration.
* Fixed: when the main thread of the agent was in another network namespace
  than the thread walking the sockets, one namespace was walked twice and
  another not at all.
* Sockets of the kernel (the clients of NFS, iSCSI, CIFS and Ceph, nfsd)
  belong to the kernel: their service is named after their port
  (`~kernel:nfs`, `~kernel:iscsi`, `~kernel:smb`, `~kernel:ceph`, ...,
  `~kernel` for other ports), and the servers of the kernel apart from its
  clients (`~kernel:nfsd`, `~kernel:ksmbd`, `~kernel:iscsi-target`,
  `~kernel:nvmet-tcp`).
  Previously a connection opened before the agent started was never
  accounted, and a new one was named after the kernel worker that opened it
  (`kworker/u8:2`), which changes at every reconnection: a new row in
  `shawk.processes`, another `service.name` and Prometheus `job`, and a
  dependency that seemed to disappear and reappear in `dependency_changes`.
  A listener that no process holds, such as that of nfsd, no longer makes
  the agent walk the processes for every connection it accepts.
* Fixed: MPTCP clients. An outgoing MPTCP connection opened before the
  agent started was never accounted; the subflows that the path manager
  adds (MP_JOIN) were attributed to a kernel worker and counted as further
  connections, on both sides. Subflows now belong to the process holding
  the MPTCP socket, and a connection counts once. A failed dial of Go with
  MPTCP still counts two attempts, since Go tries again with TCP.
* The virtual machine tests load the NFS client modules of Rocky Linux 9
  (`kernel-modules-core`), and `test/vm/run.sh` needs `xz`.

## [v0.8.0](https://github.com/yuuki/shawk/compare/v0.7.1...v0.8.0) (2026-11-01)

Rewritten from scratch.

* New eBPF tracer (CO-RE, Linux 5.14+): TCP is traced with the `inet_sock_set_state` tracepoint and socket iterators only, connections established before the agent started are adopted, IPv6 and MPTCP are supported, and UDP is bundled per message with fentry.
* The agent (`shawk agent`) sends the dependencies and listening ports of its host every 15 seconds as cumulative OTLP metrics (gRPC or HTTP, optionally with a client certificate), in requests of at most 1000 series and 3 MiB, drops dependencies idle for 15 minutes, and reports its observation segment. It keeps no database and opens no port.
* Services are named like OBI names them: `OTEL_SERVICE_NAME` or `service.name` in `OTEL_RESOURCE_ATTRIBUTES` of the process, then the executable name (`-service-name-fallback=unit` for the systemd unit). Hosts are identified by their machine id and name.
* New shawk connector for the OpenTelemetry Collector (`collector/`, with a manifest of the OpenTelemetry Collector Builder): writes hosts, observation segments, processes, dependencies and listeners to PostgreSQL 14+, names the peer of every dependency (`service.peer.name`), and forwards metrics aggregated without peer addresses to Prometheus, one `job` per local service.
* PostgreSQL contract in the schema `shawk_v1`: `dependencies` (both ends matched, with how long each side was observed), `graph_nodes`, `graph_edges`, `dependency_changes`, `service_endpoints`, `agent_addrs`, `agents`, `unobserved()`, `peer_class()` and functions over a period (`dependencies_between()` and others). The schema ships as migrations applied by `shawk-migrate`; a connector that does not migrate checks the version of the schema.
* Prometheus recording rules that count each dependency once and alerts, Grafana dashboards (fleet, dependency map, dependency details, changes, application layer of OBI) and alerts, and examples for the collector, PostgreSQL and systemd in `packaging/`.
* `shawk flows` shows the bundled flows of the local host live.
* Relicensed under the Apache License 2.0 (previously MIT). The eBPF programs are dual-licensed GPL-2.0-only OR BSD-2-Clause.
* Removed the polling/streaming probes, the PostgreSQL CMDB, `look` and `create-scheme`, and the dependency on go-conntracer-bpf. An interim design that kept a SQLite ledger on every host, with the commands `who-uses`, `deps`, `can-i-remove`, `unused`, `diff`, `graph` and `status` and an agent HTTP API on port 7464, was dropped before release in favor of PostgreSQL, Prometheus and Grafana.

## [v0.7.1](https://github.com/yuuki/shawk/compare/v0.7.0...v0.7.1) (2020-12-20)

* Bump version Go 1.15 [#56](https://github.com/yuuki/shawk/pull/56) ([yuuki](https://github.com/yuuki))
* Update golang Docker tag to v1.15.0 [#52](https://github.com/yuuki/shawk/pull/52) ([renovate[bot]](https://github.com/apps/renovate))
* [cmdb] Add missing rollback [#44](https://github.com/yuuki/shawk/pull/44) ([yuuki](https://github.com/yuuki))
* [doc] Quickstart guide [#47](https://github.com/yuuki/shawk/pull/47) ([yuuki](https://github.com/yuuki))
* To try with docker-compose [#45](https://github.com/yuuki/shawk/pull/45) ([pyama86](https://github.com/pyama86))
* Replacing lib/pq into pgx [#42](https://github.com/yuuki/shawk/pull/42) ([yuuki](https://github.com/yuuki))

## [v0.7.0](https://github.com/yuuki/shawk/compare/v0.6.0...v0.7.0) (2020-04-27)

* Support for configuration with environment variables [#38](https://github.com/yuuki/shawk/pull/38) ([yuuki](https://github.com/yuuki))
* Update postgres Docker tag to v11.7 [#34](https://github.com/yuuki/shawk/pull/34) ([renovate[bot]](https://github.com/apps/renovate))

## [v0.6.0](https://github.com/yuuki/shawk/compare/v0.5.1...v0.6.0) (2020-04-15)

* shawk look:  --since and --until option [#37](https://github.com/yuuki/shawk/pull/37) ([yuuki](https://github.com/yuuki))

## [v0.5.1](https://github.com/yuuki/shawk/compare/v0.5.0...v0.5.1) (2020-04-10)

* Bump Go version 1.14.2 [#35](https://github.com/yuuki/shawk/pull/35) ([yuuki](https://github.com/yuuki))
* Update golang Docker tag to v1.14.2 [#29](https://github.com/yuuki/shawk/pull/29) ([renovate[bot]](https://github.com/apps/renovate))
* Configure Renovate [#26](https://github.com/yuuki/shawk/pull/26) ([renovate[bot]](https://github.com/apps/renovate))

## [v0.5.0](https://github.com/yuuki/shawk/compare/v0.4.0...v0.5.0) (2020-04-07)

* Setup linux development environment on vagrant [#25](https://github.com/yuuki/shawk/pull/25) ([yuuki](https://github.com/yuuki))
* Rename 'transtracer' to 'shawk' [#24](https://github.com/yuuki/shawk/pull/24) ([yuuki](https://github.com/yuuki))

## [v0.4.0](https://github.com/yuuki/shawk/compare/v0.3.2...v0.4.0) (2020-04-04)

* Generate both rpm and deb packages by nfpm [#23](https://github.com/yuuki/shawk/pull/23) ([yuuki](https://github.com/yuuki))
* Implement streaming mode [#21](https://github.com/yuuki/shawk/pull/21) ([yuuki](https://github.com/yuuki))
* [readme] Add additional explanations of shawk's overview [#22](https://github.com/yuuki/shawk/pull/22) ([yuuki](https://github.com/yuuki))
* Prepare and apply golangci-lint [#20](https://github.com/yuuki/shawk/pull/20) ([yuuki](https://github.com/yuuki))

## [v0.3.2](https://github.com/yuuki/shawk/compare/v0.3.1...v0.3.2) (2020-03-10)

* Validate interval option [#15](https://github.com/yuuki/shawk/pull/15) ([yuuki](https://github.com/yuuki))
* Release v0.3.1 [#19](https://github.com/yuuki/shawk/pull/19) ([yuuki](https://github.com/yuuki))

## [v0.3.1](https://github.com/yuuki/shawk/compare/v0.3.0...v0.3.1) (2020-03-09)

* Make logging package set output [#18](https://github.com/yuuki/shawk/pull/18) ([yuuki](https://github.com/yuuki))
* Debug option [#17](https://github.com/yuuki/shawk/pull/17) ([yuuki](https://github.com/yuuki))

## [v0.3.0](https://github.com/yuuki/shawk/compare/v0.2.0...v0.3.0) (2020-03-07)

* Variable interval of flushing to the CMDB [#14](https://github.com/yuuki/shawk/pull/14) ([yuuki](https://github.com/yuuki))

## [v0.2.0](https://github.com/yuuki/shawk/compare/v0.1.2...v0.2.0) (2020-03-01)

* Release by GitHub actions [#13](https://github.com/yuuki/shawk/pull/13) ([yuuki](https://github.com/yuuki))
* Speed up scanning process [#12](https://github.com/yuuki/shawk/pull/12) ([yuuki](https://github.com/yuuki))

## [v0.1.2](https://github.com/yuuki/shawk/compare/v0.1.2...v0.1.2) (2020-02-27)


## [v0.1.1](https://github.com/yuuki/shawk/compare/v0.1.0...v0.1.1) (2019-11-24)

* Print both active and passive flows with --ipv4 option [#8](https://github.com/yuuki/shawk/pull/8) ([yuuki](https://github.com/yuuki))

## [v0.1.0](https://github.com/yuuki/shawk/compare/f3c6ecd52904...v0.1.0) (2019-11-10)

* Initial release
