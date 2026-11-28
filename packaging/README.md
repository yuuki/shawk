# Packaging examples

Example deployment of shawk. The files are tested (`make test`) but meant
to be adapted. Their comments explain each setting; this page gives the
order of the steps and what the files leave out.

| path | what |
|---|---|
| `systemd/` | units of the agent and the collector, their environment files, and optional drop-ins (`shawk-agent-reserved-cpus.conf`, `shawk-collector-sqlite.conf`) |
| `collector/config.yaml` | the collector: `otlp/shawk` for agents, `otlp` for OBI, the shawk connector, exporters to Prometheus (OTLP, or remote write) and a trace store |
| `collector/config-sqlite.yaml` | single-collector configuration in SQLite lightweight mode (without PostgreSQL) |
| `collector/front.yaml` | a front collector that spreads agents over several connectors by `host.id` and `host.name`; read its caveats first |
| `postgres/` | roles (`shawk_owner`, `shawk_connector`, `shawk_grafana`), database and privileges |
| `prometheus/` | settings for the OTLP push, TLS and users (`web.yml`), recording rules and alerts (`shawk-rules.yml`) |
| `grafana/` | data sources (uids `shawk-postgres`, `shawk-prometheus`), dashboards (`dashboards/` for PostgreSQL + Prometheus, `dashboards-lite/` for Prometheus only) and alert rules |

## Agent

`shawk-agent.service` is `Type=notify`: `systemctl start` returns, and
units ordered after it start, once the agent has attached its BPF programs
and adopted the sockets that already existed. A failure to attach fails
the start. Connections that end before the programs are attached are not
traced.

On a Slurm node, where the first job may start seconds after a boot (e.g.
when power saving resumes the node), order slurmd after the agent with two
drop-ins:

```ini
# /etc/systemd/system/shawk-agent.service.d/slurmd.conf
[Unit]
Before=slurmd.service
```

```ini
# /etc/systemd/system/slurmd.service.d/shawk-agent.conf
[Unit]
Wants=shawk-agent.service
```

Then run `systemctl daemon-reload`. slurmd waits for the agent, at most its
`TimeoutStartSec` (90 seconds by default), and still starts if the agent
fails, since `Wants=` does not require it; with `Requires=` instead, a
node whose agent fails stays out of service. An agent older than the unit
does not report ready, so systemd stops it at the timeout: upgrade the
binary and the unit together, as the packages do.

Behind a front collector that authenticates agents by tokens rather than
client certificates (`collector/front.yaml`), give each agent its token
with `-otlp-bearer-token-file`, e.g. as an encrypted credential of
systemd (250 or later), which only the unit reads. Encrypt it on each
node, since the file is bound to the key of its host (and its TPM2, if
any), from the standard input rather than a file left on the disk:

```sh
systemd-creds encrypt --name=otlp-token - /etc/shawk/otlp-token.cred   # the token on the standard input
```

```ini
# /etc/systemd/system/shawk-agent.service.d/otlp-token.conf
[Service]
LoadCredentialEncrypted=otlp-token:/etc/shawk/otlp-token.cred
ExecStart=
ExecStart=/usr/bin/shawk agent $SHAWK_AGENT_OPTS -otlp-bearer-token-file ${CREDENTIALS_DIRECTORY}/otlp-token
```

The name embedded by `--name` must be the one of
`LoadCredentialEncrypted=`; without `--name` it is the name of the output
file, and the unit fails with `243/CREDENTIALS`. systemd expands
`${CREDENTIALS_DIRECTORY}` in `ExecStart=` but not in the value of
`SHAWK_AGENT_OPTS`, so the flag goes in the drop-in rather than in
`/etc/shawk/agent.env`. The drop-in replaces the command of the unit, so
keep it in step with the unit. The agent reads the token when it starts:
to change it, add the new token beside the old one in the file of the
front (bearertokenauth takes a token per line), restart the agents with
the new one, then remove the old one. The agent refuses to send a token
to an endpoint other than `https://`. Nodes that reach the collector by an address, e.g. a
virtual address of a network without DNS, verify its certificate by the
name it holds: `-otlp-endpoint https://10.0.0.10:4327 -otlp-server-name
collector.example`.

## PostgreSQL

```sh
psql -v ON_ERROR_STOP=1 -f packaging/postgres/setup.sql                        # as a superuser, in a terminal
shawk-migrate -dsn 'postgres://shawk_owner:...@db/shawk?sslmode=verify-full'
psql -v ON_ERROR_STOP=1 -d shawk -U shawk_owner -f packaging/postgres/grants.sql
```

`setup.sql` asks for the password of each role. Run `shawk-migrate` and
`grants.sql` again whenever an upgrade brings new migrations.

The users of the processes of Slurm jobs (`-job-users` of the agent,
`job_users` of the connector) are for administrators: `shawk_v1.job_edges`
is read by `shawk_owner` only, not by the connector or Grafana. To let
other administrators read it, grant it to a role of theirs as the owner
(`grants.sql` leaves such grants alone):

```sql
GRANT USAGE ON SCHEMA shawk_v1 TO hpc_admins;
GRANT SELECT ON shawk_v1.job_edges TO hpc_admins;
```

Use `sslmode=verify-full` in every connection string: with
`sslmode=require` any certificate is accepted, so whoever can intercept the
connection gets the password.

The read-only transactions and statement timeout that `setup.sql` sets for
`shawk_grafana` can be lifted by the session, and anyone who can view the
dashboards can send SQL through the data source. To bound what Grafana
uses, set limits as a superuser, and cancel long queries periodically as a
member of `pg_signal_backend`:

```sql
ALTER ROLE shawk_grafana CONNECTION LIMIT 10;   -- at least maxOpenConns × Grafana servers
ALTER ROLE shawk_grafana SET temp_file_limit = '1GB';

SELECT pg_cancel_backend(pid) FROM pg_stat_activity
WHERE usename = 'shawk_grafana' AND state = 'active' AND now() - query_start > interval '1 minute';
```

A database created by v0.8.0 or a development build before
`0001_schema.sql` is refused. Back it up if you need its history
(`pg_dump -n shawk -n shawk_v1`), drop it (`DROP SCHEMA shawk, shawk_v1
CASCADE`, which also drops your own views on them), then migrate and run
`grants.sql` again.

## Prometheus

Run Prometheus with `--web.enable-otlp-receiver` and
`--web.config.file=web.yml`. Without `web.yml`, anyone who can reach
Prometheus can push series, including `shawk_agent_up`, and silence the
agent alerts. Replace the placeholders in `web.yml` with bcrypt hashes and
give each client its own user.

To send to VictoriaMetrics or another store that takes Prometheus remote
write, use the exporter `prometheus_remote_write/victoriametrics` of
`collector/config.yaml` (commented out) in place of
`otlp_http/prometheus`, and another instance of it in place of
`otlp_http/obi`. Its names and
labels, `host_id` and `host_name` among them, are those of the OTLP
receiver of Prometheus with `prometheus.yml`, which the rules and
dashboards expect. The rules of `shawk-rules.yml` then need the ruler of
the store, such as vmalert for VictoriaMetrics; MetricsQL differs from
PromQL in details such as `rate()` and the lookback, so check when the
alerts fire there. Its queue counts batches, not points: while the store
is down it holds them in the memory of the collector, and 50 last seconds
for a large fleet, so size it to the outage to cover and to that memory
(`docs/design.md` §5.3).

## Collector

The `shawk-collector` packages install `/etc/shawk/collector.yaml` and run
the collector as the user `shawk-collector`. Write the connection string of
`shawk_connector` to a file only that user can read:

```sh
sudo install -m 0640 -g shawk-collector /dev/stdin /etc/shawk/postgres-dsn <<<'postgres://shawk_connector:...@db/shawk?sslmode=verify-full&sslrootcert=/etc/shawk/tls/postgres-ca.crt'
```

Set `SHAWK_PROMETHEUS_AUTHORIZATION` in `/etc/shawk/collector.env` (the
container image takes it with `docker run --env-file`).

TLS files in `/etc/shawk/tls/`, readable by `shawk-collector` (uid 65532 in
the image):

- `collector.crt` and `collector.key`, the server certificate of both
  receivers, and `collector-client.crt` and `collector-client.key`, which
  the trace store should require;
- `agents-ca.crt`, which issues the agents' client certificates. Each
  certificate must name its host as `hostname` prints it;
- `obi-ca.crt`, a different CA, for OBI. The collector does not start
  without it; if you do not use OBI, remove the receiver `otlp` and the
  pipelines `metrics/obi` and `traces/obi` instead;
- `prometheus-ca.crt`, `tempo-ca.crt` and `postgres-ca.crt`, which verify
  the servers the collector writes to.

OBI sends with the variables of the OpenTelemetry SDK:

```sh
OTEL_EXPORTER_OTLP_ENDPOINT=https://collector.example:4318
OTEL_EXPORTER_OTLP_CERTIFICATE=/etc/obi/tls/collector-ca.crt
OTEL_EXPORTER_OTLP_CLIENT_CERTIFICATE=/etc/obi/tls/obi.crt
OTEL_EXPORTER_OTLP_CLIENT_KEY=/etc/obi/tls/obi.key
```

## Grafana

Set `SHAWK_GRAFANA_PROMETHEUS_PASSWORD` and put the CA of Prometheus at
`/etc/grafana/tls/prometheus-ca.crt`, then adjust the URLs and credentials
in `grafana/provisioning/datasources/shawk.yaml`.

## Before removing a host

`shawk-impact`, in the `shawk-collector` packages and the image, tells
what removing a host, or a service or a port of it, would break, from
PostgreSQL ([design §6.3](../docs/design.md#63-impact-of-removing-a-host-or-a-service)):

```sh
shawk-impact -dsn-file /etc/shawk/impact-dsn -host db-01                       # the whole host, over 90 days
shawk-impact -dsn-file /etc/shawk/impact-dsn -host db-01 -service postgres -port 5432 -lookback 26w
shawk-impact -dsn-file /etc/shawk/impact-dsn -host db-01 -json | jq .verdict
```

- It reads `shawk_v1` and writes nothing: give it the connection string
  of a role with the privileges of `shawk_grafana`, in a file only its
  users read, not that of `shawk_connector`. It needs PostgreSQL: against
  the SQLite lightweight mode it fails, since that mode keeps no history
  to tell from.
- Its exit status is the verdict: 0 `SAFE` and nothing else, 3 `UNSAFE`,
  4 `INCONCLUSIVE`; 1 for a failure, also when the verdict was printed
  and the list of the dependents then failed, and 2 for an invalid
  command line or `-h`. A runbook or a pipeline can refuse to go on
  unless it is 0.
- `SAFE` takes a history that tells that nothing used the target over the
  whole period. It is `INCONCLUSIVE` at best for a host without an agent
  or a name that no agent reported under; for a service that the host
  does not run or a port that no socket of it listens on, as a name
  mistyped would be; for a period that reaches before the first agent, or
  before the `retention` of the connector, whose dependencies are
  deleted; and for a host whose clock is behind, for that long before
  now. `-min-coverage 0.999` accepts gaps, which the report then lists:
  a part of the period from 0 to 1, as in the functions and the
  dashboard; a percentage is refused.
- A host that relays connections in its kernel (a load balancer, a NAT
  gateway, a node that forwards to the pods of other nodes) has the
  clients of the translations its agent learned, and of the virtual
  addresses it holds, as dependents, with the server `~relay`. They count
  for each service of the host as well, since nothing tells which one
  keeps the translations; name a port to narrow the question. A host that
  only forwards packets is not seen to be used: a router, a hypervisor,
  and a director or a gateway whose translations its agent does not learn
  (IPVS at its defaults, without `net.ipv4.vs.conntrack=1`) and that
  `translations` of the connector does not describe. The report says so
  at its end.
- A host whose pods or containers are reached from outside through a
  port it publishes with masquerade (a NodePort) shows those clients as
  its own address, like its kubelet. The translations its agent learns
  tell them apart, and such clients are dependents; an agent that folds
  external peers (`-fold-external in`, the default) or traces no
  translation does not learn them, and the verdict on the host is then
  `INCONCLUSIVE` (`masquerade_not_traced`) rather than `SAFE`. The same
  holds for a Docker host at its defaults, whose `docker-proxy` connects
  to the containers over the bridge. The coverage of such a host is 0
  while those connections last, which no `-min-coverage` accepts. Run
  the agents of such hosts with `-fold-external none` to decide it, and
  allow for the time before the change: the verdict stays `INCONCLUSIVE`
  until the period asked for starts after it, so ask with a `-lookback`
  no longer than the time since (9 days, 10 days after the change), or
  wait for the lookback to pass. Translations are also missing for
  connections older than the agent and when its table of translations
  overflowed (`shawk_agent_translations_dropped_total` in Prometheus,
  which PostgreSQL does not hold): watch that counter on such hosts.
- The period (`-lookback`, 90 days, an hour at least) must be longer than
  the rarest job that matters: a job of every quarter is not a dependent
  over 90 days in which it did not run.
- The cadence of a dependent (`continuous`, `daily`, `weekly`, `monthly`,
  ...) is read from the hours in which it was active, which connectors
  record from this version on: it is `unknown` for what was last active
  before the connectors were upgraded, and until a dependency has a day,
  or three runs, of hours. It is read for the dependents of depth 1
  (`-cadence-depth`), and `-` for the others.

The dashboard **shawk / Impact** shows the same for a whole host over the
time range, and the functions take the place of both in SQL:

```sql
SELECT * FROM shawk_v1.impact_verdict('db-01', now() - interval '90 days', now(), target_service => 'postgres');
SELECT * FROM shawk_v1.impact('db-01', now() - interval '90 days', now(), target_service => 'postgres');
SELECT * FROM shawk_v1.coverage(now() - interval '90 days', now(), ARRAY['db-01', 'app-01']);
SELECT * FROM shawk_v1.coverage_gaps(now() - interval '90 days', now(), ARRAY['db-01']);
```

A period of months over a large fleet may take longer than the 30
seconds `setup.sql` gives the statements of `shawk_grafana`: the panels
then fail, and `shawk-impact` sets its own limit (`-timeout`, 5 minutes),
and prints the verdict even when the list of the dependents then runs
out of time. On a fleet
of 2000 hosts with 500000 dependencies in 90 days, the verdict takes 5
to 7 seconds and `shawk-impact` at its defaults 13 to 19, several times
that on a database under load (design §6.3).

## SQLite lightweight mode (without PostgreSQL)

For a single-collector deployment that needs live service dependency metrics
and maps without running PostgreSQL (`docs/design.md` §5.8):

1. Use `packaging/collector/config-sqlite.yaml` as `/etc/shawk/collector.yaml`.
2. Install the drop-in so `/var/lib/shawk-collector` is writable under
   `ProtectSystem=strict`:

```sh
sudo install -D -m 0644 packaging/systemd/shawk-collector-sqlite.conf \
  /etc/systemd/system/shawk-collector.service.d/sqlite.conf
sudo systemctl daemon-reload
sudo systemctl restart shawk-collector
```

3. In Grafana, provision only the `shawk-prometheus` data source and load
   `packaging/grafana/dashboards-lite/` (`shawk-map-live.json`,
   `shawk-fleet-live.json`, `shawk-hosts-live.json`) alongside
   `shawk-application.json`.

The embedded SQLite database is internal to one collector process (protected
by an exclusive lock file) and keeps peer-resolution state only (up to 30
days). Long-term history, change alerts, `unobserved()` coverage gaps,
multi-hop walks, the impact of removing a host (`shawk-impact`, which
refuses this mode, and the dashboard shawk / Impact), rules and the
baseline of dependencies (`shawk-policy`, `baseline_file`), `job_users`,
`node_states_file` and `maintenance_file` require PostgreSQL mode.

## Rules and a baseline of dependencies

`shawk-policy`, in the `shawk-collector` packages and the image, writes
least-privilege rules and a baseline of dependencies for review, from
PostgreSQL ([design §6.4](../docs/design.md#64-least-privilege-rules-and-the-baseline-of-dependencies)).
It applies nothing, and reads `shawk_v1` only: give it the connection
string of `shawk-impact`, a role with the privileges of `shawk_grafana`.

```sh
shawk-policy rules -dsn-file /etc/shawk/impact-dsn -host app-01                      # the report: what rules would hold
shawk-policy rules -dsn-file /etc/shawk/impact-dsn -host app-01 -format nftables > app-01.audit.nft
shawk-policy rules -dsn-file /etc/shawk/impact-dsn -host app-01 -format nftables -enforce > app-01.nft
shawk-policy rules -dsn-file /etc/shawk/impact-dsn -host app-01 -unit app.service -format systemd -enforce
```

- Read the top of the file first: the status, what the rules pin, what
  they leave out, and what shawk cannot observe. The exit status is 0 for
  `COMPLETE` and nothing else, and 4 for `INCOMPLETE`, when no file that
  blocks is written unless `-allow-incomplete`. The rules of a host whose
  agent folds peers (`-fold-external in`, the default) are `INCOMPLETE`:
  such an agent does not learn a destination that the host rewrites to an
  address outside its internal ranges.
- Load the audit form before the form that rejects. `-format nftables`
  writes the audit form, which rejects nothing:

  ```sh
  nft -c -f app-01.audit.nft && nft -f app-01.audit.nft
  nft list counters table inet shawk_policy    # egress_unlisted, ingress_unlisted: what no rule lists
  journalctl -k -g 'shawk-policy unlisted'     # the same, with addresses and ports (10 lines a second at most)
  nft reset counters table inet shawk_policy   # a few minutes later, only if the table started the connection tracking
  ```

  The counters count every packet that the opening side of a connection
  sends, where no rule lists the connection, for as long as it lives: a
  tunnel or a session that stays open keeps counting after the counters
  are cleared, and so does a connection that was open before the table
  on a host that tracked connections already. Leave the table for as
  long as the slowest job of the host takes to come round, and longer
  than the longest silence of its open connections. Only while
  the counters stay at 0, load the form that rejects (`nft -f app-01.nft`
  replaces the table in one transaction); it lets the connections that
  are established at that moment go on, listed or not, until they end.
  What the counters show and no history of shawk holds: the outer packets
  of tunnels that the kernel makes (VXLAN, Geneve, WireGuard), the
  virtual services of a host that balances with IPVS (use `-ingress none`
  there; `shawk-policy` was not run on such a host), and destinations
  that the host rewrites.
- Know what the audit form cannot show; the file lists it. A connection
  whose opening side sends nothing while you watch is not counted. On a
  host where the table itself started the connection tracking (nothing
  used it before), a TCP connection that was open at that moment is
  counted once, with its next packet, and not after the counters are
  cleared: the tracking cannot tell which side opened it. Restart its
  service under the audit form to have it compared with the rules. Until
  the counters are cleared they also hold listed connections that were
  taken up from their answering side.
- Check two things before loading a table on a host that tracks no
  connection yet (no firewall, no NAT, no container runtime). The table
  starts the connection tracking of the kernel, which keeps at most
  `net.netfilter.nf_conntrack_max` connections and drops the packets of
  new ones when its table is full (`nf_conntrack: table full, dropping
  packet` in the kernel log): on a host with very many connections,
  compare `ss -s` with the limit and raise it first. And the form that
  rejects, loaded without the audit form on such a host, stops the open
  connections whose peer sends next. The audit form uses the connection
  labels 125 to 127 and compares the connections that were open before
  it with the rules at every packet of their opening side: it costs
  processor time on a host with much traffic on old connections, for as
  long as it is loaded.
- A rule of UDP has a second rule for the other way, between the same
  port on both sides of the same peer (`udp sport P udp dport P`), for
  sockets that send and receive first on one port (gossip, NTP between
  peers, IKE). No other port is opened: a peer that starts from another
  port later than the tracking remembers the exchange is not listed, and
  the audit form counts it.
- A drop-in of systemd has no audit form: it blocks every address that it
  does not list, for every IP protocol, as soon as the unit restarts with
  it. Check it with `systemd-analyze verify app.service`, and the host
  with the audit form first. The table is one of its own
  (`nft delete table inet shawk_policy` removes it).
- Write the rules again when peers change: they pin addresses.

To alert on a service that does something its baseline does not hold:

1. Write a baseline from a period, and review it:

   ```sh
   shawk-policy baseline -dsn-file /etc/shawk/impact-dsn -service shop/app -service shop/worker > baseline.yaml
   ```

   The file ends with `end: {services: N, dependencies: N}`, which tells
   that it is whole: keep the line last, and its counts right when you
   edit the file by hand (or write `end: {}`). A dependency on a server
   that listens on a port the kernel chose is written
   `port: kernel-chosen`: it approves the ports that the kernel chooses
   for servers of that name, so a restart on another such port is no
   drift, and a server of the same name on a fixed port is one. Port 0
   approves every port. Whether the kernel chose a port is known by the
   host of the server and the number of the port: a process on that host
   that has the kernel choose the number of a fixed port of the server
   makes a connection to the fixed port pass. In Prometheus such a
   dependency has `server_port="0"`, and the alert says "a port that
   changes at every run". With `-all`, every name that was seen in the
   period has a baseline, also a tool that ran once: `drift` stays
   `CLEAN` for a service that runs nowhere while the hosts that ran it
   are observed.
2. Give it to every connector (`baseline_file: /etc/shawk/baseline.yaml`
   in `collector/config.yaml`), readable by `shawk-collector`. The
   connector reads it every write interval; a file that is invalid, or
   that was cut short, keeps the baseline read before, and
   `ShawkBaselineFileInvalid` alerts. It alerts too when the file is
   valid and PostgreSQL does not take it.
3. Load `prometheus/shawk-rules.yml`: `ShawkBaselineDrift` fires for a
   dependency that the baseline does not hold, once per service, server,
   port and transport. Three alerts tell where no drift is no answer:
   `ShawkBaselineNotEvaluated` (critical: no connector evaluates the
   drift), `ShawkBaselineHostsNotObserved` (a host that runs a service
   was not observed: its agent is stopped, or its clock is behind) and
   `ShawkBaselineServiceWithoutHosts` (no process of a service of the
   file was ever seen: check its name). A service that no host runs now
   is judged on the hosts that ran it last: where they are observed it
   did nothing and nothing fires, and where one of them is silent it may
   run there still, and `ShawkBaselineHostsNotObserved` fires until the
   host reports again, another host runs the service, or the service is
   taken out of the file. A host runs a service for
   `baseline_host_memory` (a week) after a process of it was last seen
   there, so a host that was removed alerts until then: shorten it where
   hosts come and go (1 hour at least; a memory shorter than the period
   that is evaluated counts as that period). A host that is installed
   again under its name replaces its first machine as soon as it
   reports.
   `prometheus/tests` holds unit tests of these alerts
   (`promtool test rules baseline.test.yml`).
4. When it fires, `shawk-policy drift -service NAME` lists the hosts and
   the addresses, and the process when it is one of another name in a
   unit of the service: the services of a unit judge such a process
   together, and what none of them approves is one finding. Units that
   unrelated processes share are the exception: the jobs of Slurm
   (`slurm/...`), login sessions (`session.scope`), `systemd-run` without
   a name and the units of a user (`user@N.service`) judge nothing, since
   a baseline of `python3` would otherwise judge every program of every
   user beside it. `drift` lists what such processes did next to a
   service of the baseline, under the drift, and no alert fires for it:
   give the tools that matter a baseline of their own name. To approve a
   dependency, add its line to the file, or write the service again and
   review the difference. Write it with `-merge` and the file of the
   connector: a file written for some services without it is a part of
   the baseline (it says `NOT A WHOLE BASELINE` at its top), and deployed
   alone it takes the baseline of the other services away:

   ```sh
   shawk-policy baseline -dsn-file /etc/shawk/impact-dsn -service shop/app -merge baseline.yaml > new.yaml
   ```

A service that is not in the file is not judged. The baseline needs
PostgreSQL: `baseline_file` is refused with the SQLite lightweight mode.

## Upgrading

The connector of the example does not migrate (`migrate: false`). It waits
until the schema is at least its own version, and warns when the schema is
newer. Run `shawk-migrate` and `grants.sql` before or while upgrading the
collectors, and upgrade all of them, along with the agents.

Migration 0004 adds the hours in which each dependency was active
(`shawk.edge_activity`), which the connectors record from then on, and
migration 0005 the functions of the impact. The hours take about 190
bytes per edge, a side of a dependency, and month in which it was active,
for the retention: with edges active in two months of three on average,
the table is larger than `shawk.edges` itself (401 MB against 364 MB for
1.1 million edges). A connector of an earlier version writes none, so
upgrade all the connectors before reading cadences (`shawk-impact`). The
connectors also record the cutoff of their retention from then on: a
period that reaches before it is `INCONCLUSIVE`. The migration starts
that record from the oldest edge the database still holds, so a period
that reaches before it is `INCONCLUSIVE` right after the upgrade too. In
a database whose edges are all recent, that start is recent as well and
does not move back: periods that reach before it stay `INCONCLUSIVE`
until they no longer do.

Migration 0006 adds the tables of the baseline and the functions that
`shawk-policy` and the connector read (`policy_flows()`,
`baseline_drift()` and the others). It changes no table that holds
history. A connector of an earlier version ignores them; one with
`baseline_file` needs the migration, and waits for it like any other.
A database that a build from before the release of 0005 and 0006
migrated (a build of a development branch) must be created again: their
texts changed until the release, and a migration is applied once, by its
number, so `shawk-migrate` calls such a database up to date while
`shawk-policy` and `shawk-impact` fail on it. Drop it, or its schemas
`shawk` and `shawk_v1`, and migrate again.

## HPC clusters

Notes for static clusters managed by Slurm. The design is in
[docs/proposals/slurm-hpc-clusters.md](../docs/proposals/slurm-hpc-clusters.md)
(#170) and `docs/design.md`; each subsection below is one topic. The
settings of the connector below are off unless set.

### What is observed

shawk observes TCP and UDP sockets, and the connections of Unix stream
sockets on each host (e.g. to the socket of munge or of a database), so
"not used" means "no TCP, UDP or Unix stream connection". RDMA verbs
(InfiniBand, RoCE) bypass the sockets: the RDMA transports of MPI (UCX)
and NCCL, Lustre o2ib, GPFS verbs and NFS over RDMA are not seen, even
when their control connections over TCP are, while TCP over IPoIB is. A
storage server used only over o2ib looks observed and unused.

The fleet dashboard shows, below the observation periods, the traffic of
the RDMA ports of each host (`shawk_agent_rdma_io_bytes_total`, from
`/sys/class/infiniband/*/ports/*/counters`). It is a hint that a host used
what shawk does not see, not a coverage guarantee: the counters cover the
whole port, IPoIB included, and tell neither which hosts or jobs used RDMA
nor, when flat, that nothing was missed. Hosts without readable port
counters (software devices such as rxe and siw) have no series.

The sockets of kernel clients (NFS, Lustre over TCP) belong to no process,
so shawk tells which hosts use a file system, not which users or jobs. For
usage by job, use the file systems, e.g. Lustre jobstats with
`jobid_var=SLURM_JOB_ID`.

### Start order

Order slurmd after the agent with the drop-ins of [Agent](#agent), so that
the first connections of a node that power saving resumes are traced.

### A stable machine id per node

PostgreSQL keys a host by its machine id and host name, and the connector
sends the machine id to Prometheus as `host_id`, as OBI does as `host.id`.
A node that gets a new machine id at every boot becomes a new host each
time, and `unobserved()` reports the time after the last heartbeat of each
old id as not observed although the node was observed throughout. Nodes
that boot a shared image without a disk (Warewulf, xCAT diskless or
statelite, a root on tmpfs) get a new id at every boot when the image holds
an empty or no `/etc/machine-id` and nothing below gives one; Slurm's power
saving boots them often.

At boot systemd takes the first of (machine-id(5)):

1. `systemd.machine_id=` on the kernel command line (or `--machine-id=` of
   systemd);
2. the id in `/etc/machine-id`;
3. if the file is empty or missing: `/var/lib/dbus/machine-id`,
   `container_uuid` on the kernel command line, the DMI `product_uuid` or
   the devicetree `vm,uuid` on KVM, the UUID of Xen, and finally a random
   one, which is what bare metal gets.

systemd then writes the id to `/etc/machine-id`, or mounts a temporary file
over it when the root is read-only; on a root that is not kept, the id is
lost at shutdown. A read-only root must hold the file, empty if the id
comes from elsewhere: systemd fails to boot when it is missing.

Give every node an id of its own: generate it once (`systemd-id128 new`),
keep it with the node in the provisioning database, and pass it before
systemd starts:

- on the kernel command line of the node, `systemd.machine_id=` and the 32
  hexadecimal digits: the kernel arguments of the node in Warewulf (`wwctl
  node set --kernelargs`; keep the arguments the profile sets) or the
  attribute `addkcmdline` of the node in xCAT. It takes precedence over the
  file of the image;
- or `/etc/machine-id` in the root the node boots, from a file per node: in
  Warewulf, a template of an overlay of the node; Warewulf provisions all
  of them with the image, and a system overlay is the one meant for files
  of the boot. A file that is changed only after boot (a postscript of
  xCAT, a runtime overlay that wwclient applies again) is too late for
  that boot: systemd has established the id and the agent has started with
  it.

Do not put a valid id in the shared image instead, in `/etc/machine-id` or
`/var/lib/dbus/machine-id`: every node would have the same one. shawk tells
them apart by host name, but `host_id` and OBI's `host.id` would not.
Newer versions of systemd also take `systemd.machine_id=firmware`, an id
from the firmware; check that machine-id(5) of the installed version lists
it.

Check that `cat /etc/machine-id` is the same after a reboot. In PostgreSQL,
names with many host ids are nodes whose id changed (or hosts reinstalled):

```sql
SELECT host, count(*) AS host_ids FROM shawk_v1.agents GROUP BY host HAVING count(*) > 1;
```

The host ids already recorded stay. `shawk_v1.unobserved_by_name()` takes
the same arguments as `unobserved()` and computes the periods over the
sessions of all the host ids of each name. The annotations of the
dashboards use `unobserved()`, and can call `unobserved_by_name()` instead
where machine ids changed; the table of gaps of the fleet dashboard is per
name already (`unobserved_reasons()`, below). Per name, the gaps of two
machines that share a name hide each other.

### Inventory

Set `inventory_file` in the connector to the hosts of the cluster, with all
their addresses (management, IPoIB, storage), their roles, and the
`NodeName` of each node in Slurm (`docs/design.md` §5.6). Generate it from
the provisioning database, which knows every address, rather than from
Slurm's `NodeAddr`, and replace it at once. The connector names the host
of an address from it before what agents report (`shawk_peer_host`
below), and maps the `NodeName`s of the node states to hosts with it;
`shawk_v1.never_observed()` lists the hosts expected to run an agent whose
agent never reported.

### Node states and maintenance windows

Nodes that Slurm powered down to save energy, or that are in maintenance,
are not alerted (`docs/design.md` §5.7). For PostgreSQL, set
`node_states_file` in the connector and generate the file every minute
on the host that runs it, with a cron job that replaces it at once:

```sh
scontrol show nodes --json \
  | jq '{generated_at: (now | todate), nodes: [.nodes[] | {node: .name, state, reason}]}' \
  > /etc/shawk/node-states.json.tmp && mv /etc/shawk/node-states.json.tmp /etc/shawk/node-states.json
```

The connector maps each `NodeName` to a host by `slurm_node` of the
`inventory_file` (above).

Register maintenance windows, of hosts with or without Slurm, in
`maintenance_file` before they start; replace it at once too, and give
every connector the same one.

For Prometheus, `ShawkAgentDown` joins the node states of a Slurm
exporter: replace `slurm_node_state` and its labels in
`prometheus/shawk-rules.yml` with those of the exporter in use. Silence
the maintenance windows that are not `MAINT` reservations in Alertmanager.

### Dynamic ports of srun and salloc

Without `SrunPortRange`, srun and salloc listen on a random port at every
run, and slurmctld and slurmstepd connect to it, so each run tends to show
as a new dependency and `server_port` churns in Prometheus. Set it in
`slurm.conf` (e.g. `SrunPortRange=60001-63000`; firewalls between the nodes
usually need it anyway), and give the same range to the connector in
`dynamic_ports`. Without a range, list the services in
`port_agnostic_services` instead, e.g. `[srun, salloc, slurm-job]`, where
`slurm-job` stands for the processes of jobs, such as MPI ranks over TCP
that listen on ports of their own. Their dependencies then have port 0 in
Prometheus and in the dependencies between services in PostgreSQL, while
the edges keep their ports (`docs/design.md` §5.3). Every connector needs
the same rules. To find the services to list, the table "Listeners on
ports the kernel chose" of the changes dashboard (`shawk_v1.kernel_chosen_ports`)
shows those that listened on ports the kernel chose in the last 30 days
and that no rule covers yet; it misses listeners shorter than the interval
of the agents. A server on every address (`0.0.0.0`) stays listed until the
`hosts` of `dynamic_ports` hold every address of its host but loopback and
link-local, since clients may reach it at any of them.

### Metrics per peer host

`peer_hosts: true` adds the metrics `shawk_host_*`, with the host of each
peer (`shawk_peer_host`), and the dashboard "Peer hosts": which nodes
slurmctld fails to reach, and how, or which storage server a node talks
to. They multiply the series with the hosts each service talks to:
restrict them with `peer_host_services` (e.g. `[slurmctld, slurm-job]`,
either end of a dependency) and measure before enabling them widely
(`docs/design.md` §5.3).

`networks` names the ranges of the networks of the cluster, e.g.
`mgmt: 10.0.0.0/16`, `ib: 10.10.0.0/16` and `storage: 10.20.0.0/16`. The
metrics per peer host then carry the networks of the two addresses of each
edge (`shawk_local_network`, `shawk_peer_network`; `src_network` and
`dst_network` in the recording rules), and the dashboard "Peer hosts" a
table of the traffic by network: NFS traffic that goes over the management
network rather than the storage network shows there. An address in no
range is `~unknown`, or `~external` if it is public. The networks name the
addresses at the two ends, not the path or the interface, and do not tell
the NICs of one subnet or of a bond apart. A Unix socket has no address,
so its metrics carry no network.

### Users of jobs

With `-job-users` on the agents and `job_users` in the connector,
PostgreSQL keeps the users of the processes of Slurm jobs, in
`shawk_v1.job_edges`, which only administrators read: see
[PostgreSQL](#postgresql).

### Compute nodes: `-max-flows`, alerts and reserved CPUs

Measured in a VM, not yet on a cluster:
[docs/research/hpc-compute-nodes/compute_nodes.md](../docs/research/hpc-compute-nodes/compute_nodes.md)
(#172).

- Size `-max-flows` of the agent for the jobs whose ranks talk over TCP
  (§7 of the note): 32768 for ranks that each talk to one rank of every
  other node of 190, 65536 for all to all when the ranks of a step share a
  cgroup. Each slot costs 2.7 KiB of kernel memory. A full table drops the
  same flows in every interval, those of the infrastructure too.
- `grafana/provisioning/alerting/shawk-compute-nodes.yaml.example` is an
  opt-in rule that fires once for the compute nodes partly observed in the
  last 30 minutes, rather than once per node.
- `systemd/shawk-agent-reserved-cpus.conf` is a drop-in that runs the
  agent on the CPUs Slurm reserves for the system (`CpuSpecList`,
  `CoreSpecCount`); reserving them is what removed the effect of the agent
  on jobs.
