## Unreleased

### Added

* Unix domain sockets. The agent traces the connections of Unix stream
  and seqpacket sockets to named sockets, a path or an abstract name
  (`/run/postgresql/.s.PGSQL.5432`, php-fpm, `/run/docker.sock`, munge),
  at the connect and the close of the client (`fexit/unix_stream_connect`,
  `fentry/unix_release`), which need BPF trampolines as UDP does:
  connections, failed connects by reason (`refused`, `timeout` for a full
  backlog, `unreachable` for a permission denied, `local`, `aborted`) and
  open connections. Their traffic is not measured: a Unix socket keeps no
  count of its bytes. The listening sockets are found by the walks of the
  processes, and connections that predate the agent are adopted. Datagram
  Unix sockets (syslog, journald, `sd_notify`) and unnamed pairs are not
  traced. Edges have `network.transport=unix` and the name of the socket
  as `server.address`, and the agent reports `shawk.agent.unix.traced`
  (`docs/design.md` §3.8).
* The connector names the server of a Unix socket after the owner of its
  listener on the host of the client, writes the edges and listeners to
  `shawk.unix_edges` and `shawk.unix_listeners`, and forwards their
  connections to Prometheus with `network_transport="unix"` and
  `server_port="0"`, counted by the recording rules like the others.
* PostgreSQL, in the one migration `0001_schema.sql`: `shawk_v1.dependencies`
  and `dependencies_between()` have a last column `path` and the
  dependencies over Unix sockets (`proto` `unix`, no addresses, port 0),
  matched with the owners of the listeners of their names; `agents` has
  `unix_traced` and `job_edges` `path`; the new view `unix_endpoints` is
  for the connector. `peer_class(NULL)` is `~unresolved`, the name of the
  server of a Unix socket without a listener, and `graph_edges` shows
  `unix` for those dependencies.
* The alert `ShawkUnixNotTraced`, and `unix_traced` in the fleet dashboard.
  `ShawkConnectionFailureRate` leaves out the failed connects to Unix
  sockets without a listener: glibc tries the socket of nscd from every
  process that looks up a user or a host, and most hosts do not run nscd.
* `shawk flows` shows the flows of Unix sockets.

### Changed

* A flow opened by the child that systemd forks for a service, named
  `(cron)` until it executes `cron`, takes the identity of the service:
  systemd connects the standard output of the service to journald in it.
* `-max-flows` also sizes the in-kernel tables of the flows of Unix
  sockets, to a quarter of it, and of their open connections, to a half,
  at least 1024 each (about 3.6 MiB at the default).

### Fixed

* A UDP server that existed before the agent started could be taken for a
  client of its own clients when it sent a reply between the attach of the
  UDP programs and the walk that marks the servers, as the end-to-end test
  did in a VM once the agent loaded more programs at start: the walk now
  runs before the UDP programs attach.

**Upgrading.** The tables and views of Unix sockets are in
`0001_schema.sql`, which `shawk-migrate` does not apply again to a database
that has it: create the database of v0.8.1 again as for the first build of
v0.8.0 below (back up, drop the schemas `shawk` and `shawk_v1`, then run
`shawk-migrate` and `grants.sql`). Upgrade the connectors with the agents:
a connector of the previous version ignores the series of Unix sockets as
invalid data points, and logs them.

## [v0.8.1](https://github.com/yuuki/shawk/compare/v0.8.0...v0.8.1) (2026-11-04)

No change in behavior: the BPF programs run the same instructions.

### Changed

* The BPF programs build with clang 21 (#168): `make generate` failed
  with `-Wdefault-const-init-var-unsafe`, which clang 21 enables by
  default, because `BPF_CORE_READ()` declares its result with the type of
  the field, which is const when the object is read through a pointer to
  const. The helpers take the sockets and conntrack entries they read as
  pointers to non-const. The committed object is still generated with
  clang 18.1.3, as in CI.

### Documentation

* Re-evaluation of the kernel hooks on Rocky Linux 9.8 and Ubuntu 24.04
  (aarch64) in `docs/research/kernel-hooks`, with the harness
  `test/hookcost` and the raw results (#165): hooks on every TCP message,
  on accept, and fentry, kprobes and cgroup_skb for UDP. `docs/design.md`
  §3 and §10 give the measured costs as the reasons for the hooks.
* The failure reason of a connect (`error.type`) races with user space on
  every kernel, not only on those without `tcp_done_with_error()`: an
  application that reads the error with `SO_ERROR` while the kernel
  closes the socket takes it first, and the failure counts as `timeout`
  (#166, `docs/design.md` §10).

## [v0.8.0](https://github.com/yuuki/shawk/compare/v0.7.1...v0.8.0) (2026-11-04)

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

**Upgrading from the first build of v0.8.0 (2026-11-01).** The PostgreSQL schema is now one migration,
`0001_schema.sql`. `shawk-migrate` and the connector, whether it migrates
or not, refuse a database created by the first build of v0.8.0 or an earlier development
version, which must be created again. Dropping its schemas deletes the
history they hold: back them up first if you need it (`pg_dump -n shawk -n
shawk_v1`), then `DROP SCHEMA shawk, shawk_v1 CASCADE` (which also drops
views of your own on them), and run `shawk-migrate` and `grants.sql`
again. Upgrade the agents and the connectors together. External peers are
now folded by default, and the Prometheus `job` of processes in pods
changes; see below.

For the security fixes below, bring `/etc/shawk/collector.yaml`, which
the packages keep once edited, in line with the new example, and:

* give each agent a client certificate that names its host as `hostname`
  prints it, without wildcards (`host_identity: certificate`), and send
  over gRPC to port 4327;
* issue the certificates of OBI from a CA of their own, installed as
  `/etc/shawk/tls/obi-ca.crt`: the collector does not start without it;
* run Prometheus with `--web.config.file` (`packaging/prometheus/web.yml`),
  set the header of the collector in `SHAWK_PROMETHEUS_AUTHORIZATION` in
  `/etc/shawk/collector.env`, and the password of Grafana in
  `SHAWK_GRAFANA_PROMETHEUS_PASSWORD`;
* run `setup.sql` in a terminal, since it asks for the passwords; roles
  that an earlier `setup.sql` created keep theirs, `change-me` unless it
  was edited: change them in psql with `\password ROLE`;
* as a superuser, run in the database `shawk` the two `REVOKE`s that
  `setup.sql` now runs there, then run `grants.sql` again.

### Added

* **Time to connect and why connects fail**, per dependency, measured
  passively on the connections that hosts open. The kernel measures every
  active open of TCP from `connect(2)` to the SYN-ACK, the SYNs it
  retransmitted, and the reason of a failure: `refused`, `timeout`,
  `unreachable`, `local` (no SYN sent, e.g. no free local port), `aborted`
  (the application gave up first) or `_OTHER`. The agent sends them on TCP
  client edges as `shawk.tcp.handshake` (a histogram from 100 µs to 3 s),
  `shawk.tcp.syn_retransmits` and `shawk.connection.failed.by_reason`
  (with `error.type`); the connector forwards them per dependency as
  `shawk_tcp_handshake_seconds_sum` and `_count`,
  `shawk_tcp_syn_retransmits_total` and
  `shawk_connection_failed_by_reason_total{error_type}`, with the
  recording rules `shawk:dependency_handshake_seconds_sum:rate5m`,
  `…_count:rate5m`, `shawk:dependency_syn_retransmits:rate5m` and
  `shawk:dependency_connection_failures_by_reason:rate5m`, and panels in
  the dependency details dashboard. `shawk flows` shows them. The flow
  tables of the agent take 2.6 MB more with the default `-max-flows`.
* **Dependencies through translations of addresses** (#107):
  * relays without an agent (load balancers, keepalived or LVS virtual
    addresses, TCP proxies) described by `translations` in the
    configuration of the connector: their virtual addresses, backends and,
    for a relay that replaces the addresses of the clients, the addresses
    the backends see them at (`shawk.translations`);
  * translations learned from conntrack by the agent of the host that makes
    them, with two kprobes on nf_conntrack once it is loaded: Docker
    published ports and masquerade, kube-proxy (iptables, nftables, IPVS
    with `net.ipv4.vs.conntrack=1`), REDIRECT and any DNAT or SNAT rule
    (`-learn-translations`, default `true`; `shawk.translation.first_seen`
    and `last_seen`, `shawk.agent.translations.traced` and `dropped`;
    `shawk.learned_translations`). Translations used by open connections
    stay in use while they are open. The systemd unit allows
    `perf_event_open`, which kprobes need.

  `shawk_v1.dependencies` and `dependencies_between()` match a client edge
  to a virtual address with the server edges at its backends, over the
  period both were active in; the last columns `virtual_addr`,
  `virtual_port` and `translation` (`~learned` for a learned one) tell
  what the client connected to; on these rows, the observation of a side
  whose edge outlives the row is NULL, so that a stopped agent does not
  make a dependency disappear. In Prometheus, the peer of a client edge to
  a virtual address is the service at a backend, with the `server.port` of
  the backend (on hosts with Docker or kube-proxy, where translations are
  learned by default, the `server_port` of such series changes), and the
  peer of a server edge behind a relay that keeps the addresses of the
  clients is the client service. A translation of the configuration may
  not have a name starting with `~`.
* **Folding of external peers** (#96): the kernel folds the peers outside
  the internal ranges of the host into one dependency per local endpoint,
  so that the clients of an internet-facing server do not fill the flow
  table, the requests and `shawk.edges`. `-internal-peers` lists the ranges
  kept exact (default `private`: RFC 1918, CGNAT, loopback, link-local and
  IPv6 ULA; the addresses of the host are always kept), and
  `-fold-external` which flows fold their external peers (`in`, the
  default, `all` or `none`). A folded edge carries
  `shawk.peer.folded=true`; the connector stores its peer as the network
  `0.0.0.0/0` or `::/0` and names it `~external`, and warns when an agent
  folds a host that runs an agent, or the peers of a range of
  `peer_cidrs`. Folding is on by default, so the address of each external
  client of a local server is no longer recorded: set `-fold-external=none`
  where it is needed. A fleet that uses public addresses internally must
  add them to `-internal-peers`, and so must one whose `peer_cidrs` name
  public ranges, whose peers are otherwise named `~external`.
* **Partly observed periods**: the periods in which an agent dropped flows
  (`shawk.partial_observations`, `shawk_v1.partly_observed()`), so that the
  absence of a dependency over them is not taken for disuse. The fleet,
  dependency details and changes dashboards annotate them.
  `shawk_v1.agents` and `agent_addrs` tell what each agent folds
  (`peer_fold`, `peer_internal`).
* **Every known owner of a listener** (`shawk.listener_owners`), so that the
  history of a listener is kept when it changes hands.
* **Containers keep their names when they are recreated** (#104):
  `shawk.unit` of a process in a container is
  `k8s/<namespace>/<workload>/<container>`, `docker/<project>/<service>`
  for Docker Compose, or `docker/<name>`, `podman/<name>` and
  `containerd/<name>`, read from the state the runtime keeps on disk; the
  id is `container.id`, which keeps the series of replicas apart. A
  container whose state cannot be read is named `<runtime>-<12 hex
  digits>`.
* **Pods are named as OBI names them** (#124): `service.name` is the
  annotation `resource.opentelemetry.io/service.name`, then the labels
  `app.kubernetes.io/instance` and `app.kubernetes.io/name`, then the
  owner of the pod (a Job cut at its last `-`, a static pod after its
  Node); `service.namespace` is the annotation
  `resource.opentelemetry.io/service.namespace`, then the label
  `app.kubernetes.io/part-of`, then the namespace of the pod. The agent
  reads them from the sandbox kept by CRI-O and cri-dockerd; containerd
  keeps only the annotations its `pod_annotations` lets through (add
  `resource.opentelemetry.io/*` and `kubernetes.io/config.source`).
* **Sockets of the kernel** (the clients of NFS, iSCSI, CIFS and Ceph,
  nfsd) belong to the kernel and are named after their port
  (`~kernel:nfs`, `~kernel:iscsi`, …, `~kernel:nfsd`), instead of the kernel
  worker that opened them.
* **Losses of new cgroups are visible** (#126):
  `shawk.agent.cgroup_events.dropped`
  (`shawk_agent_cgroup_events_dropped_total`) counts the new cgroups the
  kernel did not report because the agent read too slowly, and
  `shawk.agent.container_reads.dropped`
  (`shawk_agent_container_reads_dropped_total`) the containers not queued
  to be read; the Prometheus alerts `ShawkCgroupEventsDropped` (warning)
  and `ShawkContainerReadsDropped` (info) fire when they increase.
* The systemd units are sandboxed: the agent keeps only `CAP_BPF`,
  `CAP_PERFMON`, `CAP_SYS_ADMIN`, `CAP_SYS_PTRACE` and
  `CAP_DAC_READ_SEARCH`, and both units filter system calls and address
  families. With `ProtectHome=yes`, the binary and the TLS files of the
  agent must not be under `/home` or `/root`.
* The release archive of the agent contains its systemd unit and
  `agent.env`; archives, packages and the collector image ship the
  licenses of the Go modules linked into the binaries
  (`THIRD_PARTY_NOTICES`).
* The BPF programs are tested on the kernels of Rocky Linux 9.6 (x86_64,
  aarch64) and upstream 5.14 and 5.15 in virtual machines
  (`make vm-test`, which needs `xz` for Rocky Linux and `dpkg-deb` for the
  upstream kernels), and on an arm64 runner.

### Changed

* The PostgreSQL schema is one migration (see above). Its tables, views
  and functions are those of the migrations it replaces, with
  `shawk.schema_history()` for connectors that do not migrate;
  `shawk_v1.agents.peer_fold` is never NULL.
* **The Prometheus `job` of processes in pods** is `<namespace>/<name>`, as
  OBI names them (#104, #124): the name is the workload of the pod as
  above, or `OTEL_SERVICE_NAME` when the process sets it, and the namespace
  that of the pod unless `OTEL_RESOURCE_ATTRIBUTES` sets one. The `job` of
  a pod changes from the executable (or `billing`, with
  `OTEL_SERVICE_NAME=billing`) to `<namespace>/<workload>` (or
  `<namespace>/billing`); pods of Helm charts are named after their labels,
  e.g. `ingress-nginx/ingress-nginx` rather than
  `ingress-nginx/ingress-nginx-controller`. Dashboards and alerts that
  select pods by `job` need the new names.
* `shawk` exits with 2 on usage errors, including every invalid value of
  a flag, and with 1 when a command fails (2 for both before).
* The state of a container is read on a worker rather than on the
  goroutine that drains the events of new cgroups, so that a burst of new
  containers on a busy host of Podman or CRI-O does not make the kernel
  drop events (#126); the export no longer waits for these reads.
* `make build` and `make collector` set the version without the `v` of the
  tag (`0.8.0`), like the release.

### Security

* **An agent can no longer write as another host.** The connector believed
  the `host.name` and `host.id` that every request carries, so the holder
  of any client certificate could add dependencies to another host, or
  send its `shawk_agent_up`, or make PostgreSQL drop its changes with a
  string it refuses. With `host_identity: certificate`, which
  `packaging/collector/config.yaml` sets, the connector accepts the
  metrics of a host only from an agent whose verified client certificate
  names its `host.name` (a DNS name, or the common name of a certificate
  without DNS names); the certificates of the agents must name their
  hosts as `hostname` prints them. The receiver passes the certificate on
  over gRPC only, so the example configuration no longer receives agents
  over HTTP (port 4328). The connector replaces NUL and invalid UTF-8 in
  the strings of agents, which PostgreSQL refuses.
* **A user can no longer stop the export of a host.** `service.name` and
  `service.namespace`, from the environment of any process, were sent
  whole; with 128 KiB each, the series of one connection exceeded the
  size of a request, which the collector refused, and the rest of every
  interval was not sent. They are cut to 255 bytes, and a series too
  large for a request is left out and logged.
* **A user can no longer name their processes after another container.**
  A user to whom systemd delegates cgroups (`user@1000.service`) could
  make one named after a container of the host, and the agent named the
  user's flows after that container, its pod and its service. Only the
  outermost container of a cgroup, outside any unit, is named after the
  state of the runtimes of the host; a container in a unit is named by id
  after the unit (`user@1000.service/podman-0123456789ab` for a rootless
  container, `podman-0123456789ab` before).
* **An agent can no longer make series in Prometheus without limit.** The
  connector forwarded every metric whose name starts with `shawk.agent.`
  whole, with its unit, attributes and points, and the direction of
  bytes, the names of local services and host names as agents sent them,
  so one host could make series until Prometheus ran out of memory. The
  metrics of the agents are now made anew from what the agents send: the
  metrics, types and units they have, the values of `shawk.netns.scope`
  and `shawk.bpf.program` they send, and one point per metric or BPF
  program; other metrics, attributes and points are dropped and logged
  at most once a minute. A `network.io.direction` other than `transmit`
  and `receive` is output as `_OTHER`. The new option `max_services`
  (default 200) bounds the local services per host that have a `job` of
  their own; the others share the job `~other`, whose peers `max_peers`
  bounds as for one service. Service names and namespaces, host names,
  host ids and agent versions are cut to 255 bytes, and
  `service.peer.name` to 511. PostgreSQL keeps every service, whole.
* **An agent can no longer name the peers of another host after its own
  service.** A listener or a server edge that an agent reported at the
  address of another host was taken for the service at that address, and
  a time far in the future kept it the most recently seen for good: the
  client edges of other hosts to that address were named after the
  agent's service in Prometheus. The services and clients that a host
  reports at an address that another live host holds alone no longer
  name peers, nor count as the service at a backend of a translation.
  The times of edges, listeners, translations and processes are written
  no later than 2 minutes ahead of the clock of the connector. An agent
  can still claim the address of a host that runs no live agent, or make
  an address shared by declaring it in `host.ip` (`docs/design.md`,
  section 10).
* **The memory of the connector is bounded.** Its state is keyed by what
  agents send, and had no size limit: an agent could send thousands of
  host names with a thousand edges each, which were held for `idle_ttl`,
  or as long as PostgreSQL was down, until the collector ran out of
  memory. Three new options bound it. `max_hosts` (default 10000) refuses
  the requests of further hosts, which their agents count as failed
  exports, until a held host expires. `max_series_per_host` (100000)
  drops the new edges, listeners, translations and addresses of a host
  beyond it, and the host is not observed in the intervals with drops.
  `max_pending_rows` (10 million) drops the changes of the hosts pending
  the longest while PostgreSQL cannot be written, and these hosts are not
  observed over the changes lost. Strings from agents are cut to 4096
  bytes. The defaults leave room for a large fleet: lower `max_hosts` to
  the size of yours to bound the memory more tightly.
* **OBI can no longer send to the receiver of agents.** The two receivers
  of `packaging/collector/config.yaml` trusted the same client CA
  (`agents-ca.crt`), so a certificate issued to OBI, which often runs on
  hosts or in containers trusted less than the agents, was accepted by
  `otlp/shawk` and could send agent data there. The receiver `otlp`
  (ports 4317 and 4318) now trusts `/etc/shawk/tls/obi-ca.crt`: issue the
  certificates of OBI from another CA and install its certificate there,
  readable by `shawk-collector`, or leave out the receiver `otlp` and the
  pipelines `metrics/obi` and `traces/obi`. The collector does not start
  without that file.
* **The push to Prometheus is authenticated and encrypted.** The example
  collector pushed to the OTLP receiver of Prometheus, and to the trace
  store, in cleartext, and Prometheus accepted any push: anyone who could
  reach it could write `shawk_agent_up`, bypassing the client
  certificates the collector requires of agents, and silence the alerts
  on agents. `packaging/collector/config.yaml` now pushes over TLS,
  verifying Prometheus with `/etc/shawk/tls/prometheus-ca.crt`, with an
  `Authorization` header from `SHAWK_PROMETHEUS_AUTHORIZATION`, which the
  unit reads from the new `/etc/shawk/collector.env` (installed readable
  by root only; `docker run --env-file` for the image). The new
  `packaging/prometheus/web.yml`, for `--web.config.file`, serves
  Prometheus over TLS to the users of `basic_auth_users` only; Prometheus
  refuses to start until its placeholder hashes are replaced. The Grafana
  data source `shawk-prometheus` logs in as `grafana`, with the password
  in `$SHAWK_GRAFANA_PROMETHEUS_PASSWORD`, and verifies Prometheus with
  `/etc/grafana/tls/prometheus-ca.crt`. Prometheus does not tell readers
  from writers: every user can push. The trace exporter uses TLS
  (`/etc/shawk/tls/tempo-ca.crt`) with a client certificate
  (`/etc/shawk/tls/collector-client.crt`) that the store can require.
* **The roles of shawk can no longer create objects in its database.**
  The read-only transactions and the statement timeout of `shawk_grafana`
  are only defaults, which a session can lift (`SET statement_timeout =
  0`, `BEGIN READ WRITE`) with SQL that anyone who can view the
  dashboards can send through the data source. `shawk_grafana` and
  `shawk_connector` could then fill the disk with tables and functions in
  the schema `public` (on PostgreSQL 14), temporary tables and large
  objects. `setup.sql` now revokes from `PUBLIC`, in the database
  `shawk`, the creation in `public` and of large objects, and
  `grants.sql` that of temporary tables. On an existing database, run as
  a superuser in `shawk` `REVOKE CREATE ON SCHEMA public FROM PUBLIC` and
  `REVOKE EXECUTE ON FUNCTION lo_creat(integer), lo_create(oid),
  lo_from_bytea(oid, bytea) FROM PUBLIC`, then run `grants.sql` again. A
  session can still run a long query: `packaging/README.md` suggests
  limits that it cannot lift.
* **No default passwords for PostgreSQL.** `packaging/postgres/setup.sql`
  created the roles `shawk_owner`, `shawk_connector` and `shawk_grafana`
  with the password `change-me`, which stayed if the script was run
  without being edited. It now creates them without passwords, and psql
  asks for each (`\password`) and sends it hashed, so the passwords are in
  neither the script, the command line nor the server log: run it in a
  terminal. If you ran an earlier `setup.sql` unedited, set new passwords
  in psql with `\password shawk_owner` and the same for the other two.
  The examples connect to PostgreSQL with `sslmode=verify-full` instead
  of `require`, which accepts any certificate: the connection string of
  the connector names the CA with `sslrootcert`, and the Grafana data
  source with `sslRootCertFile` (`/etc/grafana/shawk-postgres-ca.crt`).
  Change `/etc/shawk/postgres-dsn` the same way; its host must be a name
  in the certificate of the server.
* **A link can no longer add SQL to the queries of a dashboard.** A link
  can set any value of a dashboard variable (`?var-depth=`), and the
  panels run their SQL as whoever opens it. The dependency map put
  `$depth` into its SQL unquoted, and `$service`, `$src` and `$dst` used
  the `singlequote` format, whose backslash PostgreSQL does not read as
  an escape, so that a quote in a value ended the string. Every variable
  in the SQL of the dashboards now uses the `sqlstring` format, and the
  depth is cast from it: a depth that is not a number fails the query.
* **Releases can be verified.** The archives, packages and the image
  `ghcr.io/yuuki/shawk-collector` carry an attestation of their build
  provenance, signed for the release workflow: check one with `gh
  attestation verify FILE --repo yuuki/shawk`, or the image with
  `oci://ghcr.io/yuuki/shawk-collector:VERSION` (the version without its
  `v`) in place of `FILE`. The release workflow pins its actions by
  commit and goreleaser by version, the image pins its base by digest,
  and the tests that run before a release can only read the repository.
* **A user can no longer grow the agent without bound with processes
  whose environment cannot be read.** A read of `/proc/PID/environ` that
  hangs, e.g. on memory mapped from a FUSE file system that its user
  stalls, kept a goroutine and a file descriptor of the agent for good,
  one per such process, and each new one took a reader for 200 ms of the
  second the agent spends reading `/proc` per interval. At most 32 reads
  are now outstanding at once; while 32 hang, no environment is read and
  processes keep their latest identity. At most 4096 processes back off,
  and the agent logs how many reads hang at most every 10 minutes.
* **The agent no longer follows redirects, and warns about cleartext
  export.** Over HTTP/protobuf, a 307 or 308 from the collector, or from
  anything in the path, sent the request again with its body to another
  address, possibly from `https://` to `http://`. Redirects are not
  followed: a 3xx response is a failed export
  (`shawk.agent.export.failures`) whose error names the status and the
  `Location`. The agent warns at start when `-otlp-endpoint` (or
  `OTEL_EXPORTER_OTLP_ENDPOINT`) uses `http://` and its host is neither
  `localhost` nor a loopback address, since the dependencies,
  executables, services, name and machine id of the host then cross the
  network unencrypted.

### Fixed

* On kernels whose TCP iterator skips sockets (Linux before 6.17 without
  its backport to 6.1, 6.6 and 6.12: 5.15, RHEL 9 and 10), the walks of the
  agent missed the established sockets of a bucket that follows the last
  listening bucket of a namespace: connections that predated the agent
  were never adopted, and others not counted as open. The walk of the
  processes now adopts and accounts the connections that the latest walk
  missed, and the agent warns about it.
* On kernels before 6.4 (RHEL 9, 5.14), two CPUs that created the same flow
  at once could lose a connection or its bytes, counted as dropped flows
  (#119). The agent warns when updates are dropped because another update
  of the same bucket was in progress on the same CPU, not because the table
  was full.
* UDP direction (#99): a connected client socket on a port the kernel
  chose, which existed before the agent and receives before it sends, is
  no longer a server of its own port; the per-client sockets of a QUIC
  server are servers. A GSO send or GRO receive counts its datagrams, a
  peeked empty datagram counts once, and IPv6 datagrams with extension
  headers are counted.
* MPTCP clients: a connection opened before the agent is accounted, and the
  subflows of the path manager belong to the process holding the MPTCP
  socket and count once.
* A child of a TCP Fast Open listener reset or closed before its handshake
  completed is counted, with the data of its SYN.
* A listener replaced by another process of the same cgroup was attributed
  to the former process until the next periodic owner scan (up to a
  minute).
* When the main thread of the agent was in another network namespace than
  the thread walking the sockets, one namespace was walked twice and
  another not at all.
* Connectors that started at the same time with different `peer_cidrs`
  could leave the ranges of both in PostgreSQL, and a database defaulting
  to REPEATABLE READ failed the write: the configuration is written in one
  transaction in READ COMMITTED, one connector at a time.
* The edges of the dependency map dashboard had no arrowheads in Grafana
  12.2 and 13.3: the dashboard shows the md5 of the edge ids, which hold
  spaces.

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
