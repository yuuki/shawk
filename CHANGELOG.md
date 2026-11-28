## Unreleased

### Added

* `shawk-impact`, in the `shawk-collector` packages and image: what
  removing a host, or a service or a port of it, would break (#231). From
  PostgreSQL, over a period (`-lookback`, 90 days), it lists the
  dependents of the target, its clients and the clients of its dependents
  up to `-depth`, with how often those of depth 1 use it and when they are
  next expected to (`-cadence-depth` for more), tells how much of the
  period the history covers for the target and the hosts that saw the
  dependents, and gives a verdict, which is also its exit status: `SAFE`
  (0, and 0 is nothing else) when nothing used the target and the history
  tells so for the whole period, `UNSAFE` (3) when it has dependents, and
  `INCONCLUSIVE` (4) when nothing was seen but the history cannot tell
  that nothing used it (a gap of the agent, a period that reaches before
  the retention, dropped flows, UDP not traced, no agent, a clock behind)
  or the target is not known (a host, a service or a port that shawk
  never saw, as one mistyped). `-min-coverage` accepts gaps, as a part of
  the period from 0 to 1 like in SQL, and `-json` writes the report for a
  script (`docs/design.md` §6.3). It needs PostgreSQL, and refuses the
  SQLite lightweight mode, which keeps no history to give a verdict from.
* The clients whose connections a host relays in its kernel (a load
  balancer, a NAT gateway, a node that forwards to pods of other nodes)
  are its dependents, with the server service `~relay`: those of the
  translations its agent learned, and of a virtual address it holds; also
  the clients from outside that a host masqueraded to a pod or a
  container of its own, which the pod sees as the address of the host. A
  host whose agent could not learn those (it folds external peers, the
  default, or traces no translation) while a pod of it accepted
  connections from an address of the host is `INCONCLUSIVE`
  (`masquerade_not_traced`). A host that only forwards packets, as a
  router, a hypervisor or an IPVS director at its defaults, is not seen
  to be used (`docs/design.md` §10).
* PostgreSQL, migration `0005_impact.sql`: the functions
  `shawk_v1.impact()`, `impact_verdict()`, `coverage()` and
  `coverage_gaps()`, which `shawk-impact` and the new dashboard
  **shawk / Impact** read. `impact()` gives the dependents of depth 1 (or
  up to `cadence_depth`) a `cadence`: `continuous`, `daily`, `weekly`,
  `monthly`, `periodic`, `irregular`, `one-off`, `dormant` or `unknown`,
  with the `period` and the `next_expected` run of a periodic one, an
  estimate. `coverage()` tells how much of a period the history covers
  for hosts, with what their agents did not trace, and `coverage_gaps()`
  lists the gaps, also before the retention.
* The connector records the hours in which each dependency was active
  (migration `0004_edge_activity.sql`: `shawk.edge_activity` and
  `shawk.unix_edge_activity`, a row per edge and month with a bit per
  hour), from which the cadences are read. An edge keeps only when it was
  first and last seen, so the hours start with this version: the cadence
  of what was last active before is `unknown`. The same migration records
  the cutoff of the retention (`shawk.retention`, written by
  `shawk.prune()` and started by the migration from the oldest edge the
  database holds), before which nothing counts as observed for the
  impact; whether a connection of a client edge of a Unix socket was ever
  established (`shawk.unix_edges.established`), so that failed attempts
  at a socket nothing serves are no dependency; and whether the agent of
  a session learns translations (`shawk.agent_sessions.translations_traced`).

* `shawk-policy`, in the `shawk-collector` packages and image: rules that
  allow what a host was seen to do, and a baseline of the dependencies of
  services, both written for review; it applies nothing (#232).
  `shawk-policy rules -host NAME` reports the connections of a host over a
  period (`-lookback`, 90 days) and writes them as a table of nftables
  (`-format nftables`; `-ingress sources`, `ports` or `none` for what the
  host accepts) or, for a service unit, as a drop-in of systemd with
  `IPAddressDeny=` and `IPAddressAllow=` (`-format systemd -unit NAME
  -enforce`), under comments that tell what the rules pin and leave out,
  and what shawk cannot observe. The table is an audit form unless
  `-enforce` asks for the one that rejects: it has the same rules, and
  counts and logs what they do not list instead of refusing it, so that
  what no history of shawk holds (the outer packets of tunnels that the
  kernel makes, the virtual services of IPVS, a destination that the host
  rewrites) shows before it breaks, and so that the connection tracking
  takes up the connections that are open. The audit form labels a
  connection that no rule lists (connection labels 125 to 127) and counts
  every packet of its opening side for as long as it lives, also of the
  connections that were open before the table on a host that tracked
  connections already; the file tells what the counters cannot show. A
  flow of UDP on one port allows its peer the other way too, between that
  port on both sides. A rule denies what was not seen: when the history does not
  tell every connection of the target (`INCOMPLETE`: a gap of the agent,
  a period before the retention, dropped flows, UDP not traced, no agent,
  a name that shawk does not know, two machines under one host name, an
  agent that did not learn the addresses that the host rewrites its
  connections to, as one that folds peers), the command writes no file
  that blocks unless `-allow-incomplete`, and exits 4; 0 is `COMPLETE`
  and nothing else. `RestrictAddressFamilies=` is written as a comment,
  and iptables and the policies of Kubernetes and Cilium are not written
  (`docs/design.md` §6.4).
* A baseline of dependencies, and alerts on what it does not hold (#232).
  `shawk-policy baseline -service NAME` writes the dependencies of
  services over a period as a file (`-merge FILE` replaces services in
  one), which ends with a line that tells it is whole (`end:`); the
  connector reads it with the new `baseline_file`, refuses one that was
  cut short, writes it to PostgreSQL and tells Prometheus, every write
  interval, the dependencies of those services that it does not hold:
  `shawk_baseline_drift_hosts{job, service_peer_name, server_port,
  network_transport}`, one series whatever the number of hosts, without
  addresses, at most 20 per service and 1000 in all, with
  `shawk_baseline_dependencies{job}`,
  `shawk_baseline_drift_truncated{shawk_baseline_peer}` and
  `shawk_baseline_new_services`. No drift is an answer only where the
  drift is known, and the connector tells where it is not:
  `shawk_baseline_hosts{job}` and `shawk_baseline_hosts_unobserved{job}`
  (a host runs a service for the new `baseline_host_memory`, a week,
  after a process of it was last seen there, so a host whose agent
  stopped is not observed rather than forgotten),
  `shawk_baseline_evaluation_timestamp_seconds` (0 before an evaluation
  succeeded), `shawk_baseline_evaluation_attempt_timestamp_seconds`,
  `shawk_baseline_evaluation_failed` and `shawk_baseline_file_failed`.
  A process of another name in a unit that runs a service of the baseline
  is judged as that service. `packaging/prometheus/shawk-rules.yml` has
  the alerts `ShawkBaselineDrift`, `ShawkBaselineDriftUnresolved`,
  `ShawkBaselineNotEvaluated`, `ShawkBaselineHostsNotObserved`,
  `ShawkBaselineServiceWithoutHosts`, `ShawkBaselineFileInvalid`,
  `ShawkBaselineDriftTruncated`, `ShawkBaselineDriftUnresolvedTruncated`
  and `ShawkNewServiceWithoutBaseline`, with unit tests for promtool in
  `packaging/prometheus/tests`. `shawk-policy drift` lists the drift with
  its hosts and addresses, and exits 0 for none, 3 for a drift and 4 when
  it cannot tell, as when a host that runs a service was not observed. A
  service without a baseline is not judged. `baseline_file` is refused
  with the SQLite lightweight mode.
* PostgreSQL, migration `0006_policy.sql`: the functions
  `shawk_v1.policy_flows()`, `policy_verdict()`, `policy_gaps()`,
  `baseline_observed()`, `baseline_verdict()`, `baseline_drift()` and
  `baseline_new_services()` and the views `shawk_v1.baseline` and
  `baseline_status`, which `shawk-policy` and the connector read, and the
  tables of the baseline. What they return is ordered by the bytes of
  names, whatever the collation of the database.

**Upgrading.** Run `shawk-migrate` and `grants.sql` again (migrations 0004
to 0006), and upgrade every connector: one of an earlier version records
no hours, and the cadences of its hosts read `unknown`. The hours cost
about 190 bytes per edge, a side of a dependency, and month in which it
was active, kept for the retention: the table `shawk.edge_activity` can be
larger than `shawk.edges` itself (401 MB against 364 MB for 1.1 million
edges active in two months on average), so plan for the database to about
double where the edges are most of it.

### Fixed

* `shawk-migrate -h` printed the value of `$SHAWK_POSTGRES_DSN` as the
  default of `-dsn`, with its password, as did the usage that follows an
  invalid flag. Its other errors could print the password too: usage
  errors quoted the arguments, `-print` and `-dsn-file` errors quoted
  their value, the parse error of pgx quoted the connection string
  without hiding every form of its password (`password = x`, a password
  with `@`), and a failed connection quoted the database, where a
  malformed URL can put the password. The usage now names the variable
  only, and these errors print no value of the command line or the
  environment: a usage error names the flag at most
  (`invalid value for flag -timeout (the value is not shown)`), and a
  failed connection gives its cause and the SQLSTATE of the server. The
  flags, the variable and the exit statuses are unchanged
  (`docs/design.md` §6).

## [v0.11.0](https://github.com/yuuki/shawk/compare/v0.10.1...v0.11.0) (2026-11-26)

### Added

* Unix stream and seqpacket socket tracing falls back to kprobes when BPF
  trampolines do not attach, including on Rocky Linux 9.6 arm64 (#220).
* `-otlp-bearer-token-file` of the agent sends a token read from a file
  at start with every request (`Authorization: Bearer`), for a front
  collector that authenticates agents by tokens (bearertokenauth) rather
  than client certificates. The agent refuses to start with an empty
  file or an endpoint other than `https://`, and never logs the token
  (`docs/design.md` §4.3).
* `-otlp-server-name` of the agent verifies the certificate of the
  collector by another name than the host of `-otlp-endpoint`, and asks
  for it in SNI, for nodes that reach the collector by an address
  (`docs/design.md` §4.3).
* The collector includes the `prometheus_remote_write` exporter of
  opentelemetry-collector-contrib, to send to VictoriaMetrics or another
  store that takes Prometheus remote write; `packaging/collector/config.yaml`
  has its settings, which give the names and labels of the OTLP receiver
  of Prometheus, with a small queue (`docs/design.md` §5.3).

### Fixed

* `packaging/collector/config.yaml` bounds the queues of the exporters to
  Prometheus: 409 600 points (`sizer: items`, under 250 MiB) for the
  outputs of the connector, in batches of at most 8192 points
  (`send_batch_max_size` of the batch processor), and 64 MiB for the
  metrics of OBI, which take an exporter of their own (`otlp_http/obi`).
  The default queue counted 1000 batches of any size, so that a Prometheus
  that was down could fill the memory of the collector until
  `memory_limiter` refused the requests of agents, and PostgreSQL got
  nothing either (`docs/design.md` §5.3). The packages keep
  `/etc/shawk/collector.yaml` once edited: bring yours in line with the
  example.
* `packaging/collector/config.yaml` bounds the queue of the exporter of
  OBI's traces (`otlp_grpc/traces`) to 64 MiB of encoded spans
  (`sizer: bytes`, about 200 MiB in memory). The default queue counted
  1000 batches of up to 8192 spans, 200 seconds of spans whatever their
  rate and about 5.7 GiB once batches are full, so that a trace store that
  was down could fill the memory of the collector until
  `memory_limiter` refused the requests of agents, and PostgreSQL got
  nothing either (`docs/design.md` §9). Bring an edited
  `/etc/shawk/collector.yaml` in line with the example.
* `packaging/collector/config.yaml` splits the requests of `otlp_grpc/traces`
  into at most 3 MiB of encoded spans (`sending_queue.batch`), below the
  4 MiB a gRPC receiver takes by default. A batch of 8192 spans of more
  than 512 bytes each, as with long SQL queries, was refused whole with
  `ResourceExhausted`, which the exporter does not retry, so that all its
  spans were lost (`docs/design.md` §9).

## [v0.10.1](https://github.com/yuuki/shawk/compare/v0.10.0...v0.10.1) (2026-11-21)

### Changed

* Host and node names in `node_states_file` and `maintenance_file` follow
  the rules of the inventory (`docs/design.md` §5.6), and a bad one makes
  the file invalid: what was written from it stays, and the states become
  stale. The collector refuses to start with a name of `peer_cidrs`,
  `translations`, `port_agnostic_services` or `dynamic_ports` that holds
  NUL or bytes that are not UTF-8, rather than fail every write (#254).
* The panels of the dependency details, peer hosts and application
  dashboards keep `network_transport` beside `server_port`, as the
  recording rules do, and show it in their legends and tables: `tcp/0` and
  `unix/0`, and TCP and UDP on one port, showed as one dependency (#262,
  `docs/design.md` §8).
* The table "Dependencies in PostgreSQL" of the dependency details
  dashboard names each side as Prometheus does (#243): `slurm-job` for the
  processes of Slurm jobs (units `slurm/*`), which PostgreSQL keeps under
  their own names (`a.out`, `mpirun`), and `peer_class()` for a side
  without a service; `~other` matches any side. Selecting `slurm-job`
  found none of their dependencies, and a name such as `python3` also
  found the jobs of that name. A variable without values, as over a time
  range that Prometheus no longer holds, now selects every side; it was a
  syntax error. The table also shows `server_unit` (`docs/design.md` §8).

### Fixed

* On kernels whose TCP iterator skips sockets (before Linux 6.17 without
  its backport: 5.15, RHEL 9 and 10), an incoming connection that predated
  the agent, adopted while its listener was open, was named after the
  first process the walk found holding it rather than after the owner of
  its listener, as other incoming connections are (#267).
* A UDP server whose per-client sockets send first, as those of a QUIC
  server do, could have such a socket taken for a client for good when it
  was made during the walk that marks the UDP servers: the walk emptied
  their ports before it listed them again, namespace by namespace. The
  ports now stay during the walk, and those of servers that are gone are
  deleted after it; the ports of a namespace that the walk could not open
  stay too (#270).
* On hosts that translate addresses (Kubernetes services, Docker published
  ports), a conntrack entry destroyed while the agent read the learned
  translations kept its translation live until the agent restarted, one
  confirmed meanwhile could lose its translation, and a failed update of
  the programs (on Linux 5.14) miscounted the live entries. The programs
  alone now add and delete the live entries, and user space writes nothing
  they update, so no confirm or destroy is lost or undone (#237,
  `docs/design.md` §3.7).
* A UDP socket of the kernel (nfsd, lockd, SunRPC, VXLAN, WireGuard) at
  the address of a former socket took its direction: with kprobes its
  first datagram had that direction, and with fentry too, the walk of the
  UDP sockets could list a socket that never received as a server and add
  its port to the listening ports. Sockets are now told apart by the inode
  of their `struct socket`, which the sockets of the kernel have too
  (#256, `docs/design.md` §3.3).
* The walk of the sockets skipped a network namespace for an interval,
  with its open connections, byte deltas, RTT and listeners, when the
  process through which the agent found it exited before the walk; a PID
  reused in another namespace made the walk read that one twice. The agent
  opened the iterators of every namespace before reading any, so a host
  with hundreds of namespaces could run it out of file descriptors. A
  namespace now keeps up to four paths, the bind mounts of `/run/netns`,
  `/var/run/netns` and `/run/docker/netns` first; the agent checks that it
  opened the namespace it listed, and walks one namespace at a time (#257,
  `docs/design.md` §3.2).
* The client of a Unix socket name did not request the owner scan that
  finds a new listener when another network namespace had a listener of
  that name: the new listener of an abstract name, or of a path that a
  container binds in a file system of its own, was found only by the
  periodic scan, up to a minute later, and its clients stayed unresolved
  or were named after the other listener meanwhile. The request is now per
  namespace and name (#258, `docs/design.md` §3.8).
* A process that exited while the agent read its identity could name a
  flow after the executable of another process that took its PID, and that
  name stayed the latest identity of its unit and command name for the
  idle TTL; a PID reused in the same cgroup could also give a flow the
  `OTEL_` variables of another process. The executable, the command name
  and the cgroup are now read through one open `/proc/PID`, and the
  environment is used only if the process is still there with the same
  executable and cgroup (#259).
* On hosts of thousands of cgroups, the walk of `/sys/fs/cgroup` for an
  unknown cgroup held the lock that the reader of the events of new
  cgroups needs, so the kernel dropped these events meanwhile, and their
  cgroups were unknown and walked again. The walk now runs without the
  lock, one at a time (#260).
* After the wall clock of a host stepped back, as when NTP corrects a
  clock that was ahead, the agent could send edges, wire protocols,
  listeners and translations first seen after they were last seen, and the
  connector wrote such rows. The agent now moves the first time back, and
  the connector takes a first time after the last as the last, as older
  agents send it (#261).
* A server that was not a backend of a translation, or a backend on
  another port, was taken for one when its port was that of the virtual
  address (any server on port 443 for `203.0.113.1:443`): the server side
  of its connections could have `shawk.peer.agent` false, which counts it
  too (`docs/design.md` §7), a client at a source of the translation was
  named after its address alone, and the connector warned that a client
  folds the virtual address. Only the backends of a translation, on their
  ports, are now reached through it (#266).
* A server edge whose client connected to the address of the server
  directly had `shawk.peer.agent` false, with a warning of the connector,
  when the agent of the client folds a virtual address of a translation
  that also reaches the server: it now names the client and keeps
  `shawk.peer.agent` true. A learned translation now marks a server edge
  as folded only in its scope and while it is current, as when it names
  the client (#269).
* With `peer_hosts`, a client edge to a virtual address whose learned
  translations came from several hosts, as from two directors in turn, had
  `shawk.peer.host` `~unknown` even when all of them sent the client to
  the same backend address: it is now the host that holds that address
  (#252).
* A `node_states_file` or `maintenance_file` of several YAML documents was
  read up to its first one, and a file of `null`, `~` or `---` alone
  removed every maintenance window. Both are now invalid, as an empty file
  is, and what was written from the file stays; `{}` or `maintenance: []`
  says that there is no window (#271, `docs/design.md` §5.7).
* Text that PostgreSQL refuses, NUL or bytes that are not UTF-8, failed
  whole writes when it did not come from agents: an escaped NUL in one
  reason of `node_states_file` or `maintenance_file` failed the write of
  the states, or of the windows, of every host, and an error of
  `inventory_file` with such bytes was never recorded in
  `inventory_status`. Reasons are now cut to 4096 bytes and cleaned as the
  strings of agents, and so is the error of the inventory (#254,
  `docs/design.md` §5.7).
* A migration released its lock without a deadline: on a connection that
  stopped answering, `shawk-migrate`, or a connector with
  `postgres.migrate`, waited many minutes, until the kernel gave the
  connection up. The release now gives up after 5 seconds and closes the
  connection, which releases the lock. The writes of the configuration and
  of the inventory, and the refresh of `known_dependencies`, could
  deadlock with a migration; they now wait for it, as the other writes do
  (#255).
* After `max_series_per_host` dropped series of a host, a drop of its
  changes (refused by PostgreSQL, or beyond `max_pending_rows`) moved the
  start of its next session back before the dropped series, so that
  `unobserved()` did not report the gap. The start no longer moves back
  (#253).
* A negative value of an edge, whose metrics are all counts or sums of
  durations, was taken for a reset and added, so that counters and the
  sums of histograms decreased and could turn negative: it is now an
  invalid data point. An output whose inputs added up beyond what it holds
  wrapped around; it now stays at its maximum, which Prometheus does not
  take for a reset (#245).
* The connector kept any start of an observation segment that an agent
  sent: a start after the request that carried it made `unobserved()`
  report the session as not observed, and one beyond what `timestamptz`
  holds made PostgreSQL refuse the writes of the host, which dropped all
  its pending changes. The start is now no later than the time of the
  request by the clock of the agent. A gauge of Unix seconds is valid only
  from 1970 to the end of 9999: one near 2^63 wrapped to a time before
  1970, which PostgreSQL refused too (#246, `docs/design.md` §5.1, §10).
* Three kinds of state per host outlived it in the connector. The fold
  warning of a host that stopped folding, or was decommissioned, stayed
  for good. A host that sent only the metrics of its agent, as an idle
  node does, was forgotten at every write interval while it kept sending,
  so that the first values of its next series could be taken for ones
  already counted. With `peer_hosts`, the holders of addresses piled up
  for up to 30 days while one host could not be written or PostgreSQL was
  down. A warning is now forgotten an hour after its last fold, a host is
  kept until `idle_ttl` after its latest request, and the holders of a
  host are forgotten as its changes are written or dropped (#251,
  `docs/design.md` §5.2).
* `shawk_v1.dependencies` and `dependencies_between()` matched an edge in
  the scope of its host and network namespace only when its remote address
  was loopback: a client that binds an address of its host and connects to
  `127.0.0.1` gave a client row and a server row instead of one row
  observed by both sides. An edge with a loopback address on either side
  is now matched in its host and namespace, and so are the learned
  translations of a client edge with a loopback client or virtual address,
  which those of any host matched before (#241, `docs/design.md` §6.2).
* An edge matched through a translation and also by address lost part of
  its period in `shawk_v1.dependencies` and `dependencies_between()`: a
  client edge to a virtual address that a relay with an agent served for a
  while had no row of its own for the time that no agent saw, and the row
  of a server edge at a backend that a client also reached directly took
  the whole period of the server edge. The row matched by address now has
  the period of the other edge on both sides, and the edge keeps a row of
  its own for what neither covers (#247, `docs/design.md` §5.4).
* `shawk_v1.planned_stops` counted the 30 days of a `MAINT` reservation
  from the start of an earlier one when the node was left out of
  `node_states_file` between them: a reservation after one that ended 30.5
  days before was left out at once, and the alert `shawk-agent-silent`
  fired during the planned maintenance. A state read after the one before
  became stale now starts a run (#248, `docs/design.md` §5.7).
* `shawk_v1.service_endpoints` had no server edges of a host without
  listeners, such as a UDP server or one whose listeners are too
  short-lived to be listed, so the connector could not name the peers of
  its clients after it. Its server edges now count too, and the view reads
  only the hosts that reported in the last 30 days, in about half the time
  (#249, `docs/design.md` §6.2).
* Queries that run at every write of the connector or for every dashboard
  read the whole retention of their tables: `shawk_v1.agents`,
  `unobserved()`, `unobserved_reasons()`, the latest node states, read
  under the lock of node states, and the sessions of an agent that dropped
  flows. They now read the rows of the hosts and the period asked for
  through indexes, two of them new, with the same results: on a test
  database of 2000 host ids and 400 000 sessions, `agents` took 13 ms
  instead of 405, and `unobserved_reasons()` over an hour 11 ms instead of
  540 (#250).
* The variables of the peer hosts dashboard listed only the services and
  hosts with connections or failed connects, so services that use UDP
  alone, and their peer hosts, could not be selected and were left out
  even with `All`. They now list those with bytes too (#272).
* The Grafana alert `shawk-agent-clock-skew` returned two rows with the
  same labels, which collide in Grafana, when two live host ids share a
  host name, as after a node boots with a new machine id: it now alerts
  the largest skew of each host name. The panel "SYN retransmissions per
  attempt" of the dependency details dashboard counted the failed connects
  of Unix sockets, which have port 0, as attempts of the TCP dependencies
  on port 0 of `port_agnostic_services` and `dynamic_ports`, which lowered
  the ratio: it now counts the failures over TCP (#262).

### Security

* **A user can no longer name their processes after a container of the
  host from a scope.** The walk of a cgroup stopped at a service, a
  session scope or a `run-*` unit above the containers, but not at the
  other scopes that systemd can delegate (`systemd-run --scope --unit=`,
  `machine-*.scope`, `slurmstepd.scope`): a user could make a cgroup in
  one named after a container of the host, and the agent named the user's
  flows after that container. Any scope or service above the containers
  now stops the walk, and the container is named by id after that unit,
  without reading the state of the runtimes of the host; scopes below the
  innermost container, such as `init.scope` of systemd in a container,
  keep the name of the container. The cgroups under a Slurm task,
  containers included, are now named after its step (`slurm/<kind>`), as
  the task is (#268, `docs/design.md` §4.1).
* **An agent can no longer make the connector hold a session per
  request.** Nothing bounded the sessions pending for a host: an agent
  that sent a new segment start with each request made the connector hold
  a session per request, each with up to 4096 ranges of
  `shawk.peer.internal`, and write as many rows. A session is now recorded
  only from a request that closes an interval, where agents send the
  segment start, and a host has at most 16 pending; a new one beyond is
  not written, and logged at most once a minute. The gauge of open
  connections also kept for good the expired inputs of a host whose
  requests never close an interval; they are now forgotten (#240,
  `docs/design.md` §5.5).

**Upgrading.** Apply the migration `0003_view_fixes.sql` with
`shawk-migrate`, or let the connector apply it with `postgres.migrate`: a
connector of this version waits at start until the schema has it. It
replaces views and functions of `shawk_v1` with the same columns, and adds
two indexes; the database of v0.10.0 is kept. Upgrade the connectors with
the agents.

## [v0.10.0](https://github.com/yuuki/shawk/compare/v0.9.0...v0.10.0) (2026-11-20)

### Added

* Wire protocols of TCP connections (#263), off by default. With
  `-classify-protocols`, the agent reads the first payload that each side
  of a new TCP connection sends and tells its protocol: the version of TLS
  (a client tells the highest version it offers, a server the version it
  chose), HTTP/1, HTTP/2 or gRPC in clear text, SSH, PostgreSQL and MySQL
  with or without a request of TLS, Redis and Slurm RPC. Clients still on
  TLS 1.0 or in clear text can so be found. The program runs on every TCP
  send and returns at once for connections that already sent, and it needs
  BPF trampolines (fentry), as Unix sockets do; without them the protocols
  are not classified. The agent reports `shawk.agent.protocols.classified`
  (`docs/design.md` §3.9).
* The connector writes the protocols to PostgreSQL, in the new migration
  `0002_edge_protocols.sql`: the table `shawk.edge_protocols`, pruned with
  its edges, and the view `shawk_v1.edge_protocols`, one row per edge and
  protocol with the addresses of the client and of the server; `agents`
  has the last column `protocols_classified`. Prometheus does not have the
  protocols, so that they add no series.
* The alert `ShawkProtocolsNotClassified`, for agents asked to classify
  protocols that cannot, and `protocols_classified` in the fleet dashboard.
* `shawk flows -classify-protocols` shows the protocols in the column `WIRE`.

### Documentation

* The README has status badges (#229), and an example query of
  `shawk_v1.edge_protocols`.

**Upgrading.** Apply the migration `0002_edge_protocols.sql` with
`shawk-migrate`, or let the connector apply it with `postgres.migrate`: a
connector of v0.10.0 waits at start until the schema has it. The database
of v0.9.0 is kept. Upgrade the connectors with the agents.

## [v0.9.0](https://github.com/yuuki/shawk/compare/v0.8.1...v0.9.0) (2026-11-11)

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
* Containers keep their names across recreation on more hosts (#125):
  - the pods of k3s and rke2, and of microk8s, whose containerd keeps its
    bundles under `/run/k3s/containerd` and
    `/var/snap/microk8s/common/run/containerd`;
  - the containers of a Docker whose data root is on the command line of
    `dockerd` (`--data-root`, or `data-root` in the file of
    `--config-file`): the agent reads the command line of every `dockerd`
    of root in the mount namespace of PID 1, every minute at most, and
    keeps only these two flags; with several daemons, each data root;
  - the tasks of Docker Swarm, named `docker/swarm/<service>` rather than
    after their container, `<service>.<slot>.<task id>`, when the labels
    `com.docker.swarm.*` match that name.
* UDP is traced on kernels without BPF trampolines, such as arm64 before
  Linux 6.0 and Rocky Linux 9.6 on arm64 (#118): where the fentry programs
  do not attach, kprobes on the same functions stand in for them, at about
  twice the cost per datagram on arm64, and keep the direction of each
  socket in an LRU hash instead of socket local storage, which kprobes
  have not. The agent logs that UDP is traced with kprobes, and reports
  `shawk.agent.udp.traced` 1. Unix sockets still need trampolines.

### Changed

* A flow opened by the child that systemd forks for a service, named
  `(cron)` until it executes `cron`, takes the identity of the service:
  systemd connects the standard output of the service to journald in it.
* `-max-flows` also sizes the in-kernel tables of the flows of Unix
  sockets, to a quarter of it, and of their open connections, to a half,
  at least 1024 each (about 3.6 MiB at the default).
* The collector is built with the components of the OpenTelemetry
  Collector v0.165.0 (v1.71.0 for the stable modules), and the Go
  modules are updated to their latest versions.

### Fixed

* The failure reason of a connect (`error.type`) was read from the error
  of the socket when it left SYN_SENT, and an application that read the
  error with `SO_ERROR` meanwhile took it first, on every kernel: the
  failure then counted as `timeout` (#166). On Linux 6.18 a client that
  busy-polls its socket had 35 of 40 refused connects counted so. The
  error is now recorded where the kernel produces it, before it stores
  it: a reset with the tracepoint `tcp_receive_reset`, an ICMP error with
  kprobes on `ip_icmp_error` and `ipv6_icmp_error` (`docs/design.md`
  §3.2). Each hook attaches on its own; without the kprobes (no
  `CONFIG_KPROBES`, or `perf_event_open` denied) the agent warns, and the
  failures of ICMP errors race as before. The connector forwards the run
  counts and times of the new programs with `-bpf-stats`
  (`shawk.bpf.program`); an older one leaves them out.
* A UDP server that existed before the agent started could be taken for a
  client of its own clients when it sent a reply between the attach of the
  UDP programs and the walk that marks the servers, as the end-to-end test
  did in a VM once the agent loaded more programs at start: the walk now
  runs before the UDP programs attach.
* A host whose requests of an interval took longer together than 2/3 of
  the interval (10 s) never sent the last ones, nor the last request, with
  the metrics of the agent, which closes the interval: the deadline of each
  request derived from one of the whole interval, collection included,
  although the agent meant to give every request its own (#194). It
  happened with 48 384 and 96 768 edges on a busy VM. Each request now has
  its own deadline of 2/3 of the interval from when it is sent, and the
  requests of an interval together at most 4 intervals; an interval that
  takes longer than the interval delays the next collection, which the
  agent logs at most every 10 minutes.
* The connector panicked on a request whose resource has no
  `service.name`, before it checked the identity of the host: such a
  resource is now ignored as one that does not come from an agent.
* A data point of an edge whose value is not a number, or beyond the int64
  counts of agents, stayed in the outputs it was added to (a NaN sum of RTTs
  in every later point of its dependency): the connector now counts it as
  an invalid data point.
* A service name longer than 255 bytes made of bytes that start no UTF-8
  character, e.g. in `OTEL_SERVICE_NAME`, was cut to an empty name; it is
  now cut to 252 to 255 bytes.
* A request of a host that arrived while the connector wrote its changes,
  which PostgreSQL then rejected, kept its session from before the drop:
  the session covered the time of the dropped edges that agents do not
  send again, and `unobserved()` left it out. Such a session now starts
  no earlier than the next one, like any after a drop, and is not written
  if it ended before (`docs/design.md` §5.1).

### Security

* **One certificate can no longer take every host of `max_hosts`.** With
  `host_identity: certificate` the certificate names the `host.name` of
  an agent, but not its `host.id`, nor the case of the name or a final
  dot, which all make another host: an agent could send made-up
  `host.id` values until the connector held `max_hosts` hosts and refused
  the others (#145, finding 6). The connector holds at most 4 hosts per
  client certificate, whatever names it has, which leaves room for hosts
  whose machine id changes at a reinstall or every boot, and refuses
  further ones like hosts beyond `max_hosts` until one has not sent for
  `idle_ttl` (`docs/design.md` §5.5). Machines that share one certificate
  share the 4.
* The agent, the collector and `shawk-migrate` build with Go 1.27.4, the
  security release of 2026-11-10: a race of `http.MaxBytesReader` with
  the handler in the HTTP/1 server of `net/http` (CVE-2026-97054), and
  code execution at build time through cgo flags and directives
  (CVE-2026-97033 to CVE-2026-97043). The VM of `test/harness/slurm.sh`
  installs the same release.

### Documentation

* With several connectors, a host must reach the same one all the time
  (#128). `docs/design.md` §5.3 said to route by resource with the
  `loadbalancing` exporter, which moves a host whenever its `host.ip`
  changes, and counts its outputs twice when it comes back within
  `idle_ttl`. It now says to give each agent one connector in its
  configuration, or to route by `host.id` and `host.name`, over a static
  list of connectors and without queues, which reorder the requests of a
  host; `packaging/collector/front.yaml` is an example of such a front
  collector. Behind it the connectors see its certificate, not the
  agent's, and run with `host_identity: none`.

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
