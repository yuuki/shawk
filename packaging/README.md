# Packaging examples

Example deployment of shawk. The files are tested (`make test`) but meant
to be adapted. Their comments explain each setting; this page gives the
order of the steps and what the files leave out.

| path | what |
|---|---|
| `systemd/` | units of the agent and the collector, and their environment files |
| `collector/config.yaml` | the collector: `otlp/shawk` for agents, `otlp` for OBI, the shawk connector, exporters to Prometheus and a trace store |
| `postgres/` | roles (`shawk_owner`, `shawk_connector`, `shawk_grafana`), database and privileges |
| `prometheus/` | settings for the OTLP push, TLS and users (`web.yml`), recording rules and alerts (`shawk-rules.yml`) |
| `grafana/` | data sources (uids `shawk-postgres`, `shawk-prometheus`), dashboards and alert rules |

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

## Upgrading

The connector of the example does not migrate (`migrate: false`). It waits
until the schema is at least its own version, and warns when the schema is
newer. Run `shawk-migrate` and `grants.sql` before or while upgrading the
collectors, and upgrade all of them, along with the agents.

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
the same rules.

### Metrics per peer host

`peer_hosts: true` adds the metrics `shawk_host_*`, with the host of each
peer (`shawk_peer_host`), and the dashboard "Peer hosts": which nodes
slurmctld fails to reach, and how, or which storage server a node talks
to. They multiply the series with the hosts each service talks to:
restrict them with `peer_host_services` (e.g. `[slurmctld, slurm-job]`,
either end of a dependency) and measure before enabling them widely
(`docs/design.md` §5.3).

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
