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

## PostgreSQL

```sh
psql -v ON_ERROR_STOP=1 -f packaging/postgres/setup.sql                        # as a superuser, in a terminal
shawk-migrate -dsn 'postgres://shawk_owner:...@db/shawk?sslmode=verify-full'
psql -v ON_ERROR_STOP=1 -d shawk -U shawk_owner -f packaging/postgres/grants.sql
```

`setup.sql` asks for the password of each role. Run `shawk-migrate` and
`grants.sql` again whenever an upgrade brings new migrations.

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
(#170); each subsection below is one topic.

### What is observed

shawk observes TCP and UDP sockets, so "not used" means "no TCP or UDP".
RDMA verbs (InfiniBand, RoCE) bypass the sockets: the RDMA transports of
MPI (UCX) and NCCL, Lustre o2ib, GPFS verbs and NFS over RDMA are not
seen, even when their control connections over TCP are, while TCP over
IPoIB is. A storage server used only over o2ib looks observed and unused.

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

### A stable machine id per node

PostgreSQL keys a host by its machine id and host name, and the machine id
is `host_id` in Prometheus. A stateless node whose machine id changes at
every boot becomes a new host at each boot, and its old ids show gaps
although the node was observed. Give every node a stable machine id when
it is provisioned, e.g. `systemd.machine_id=` on the kernel command line or
a file per node in the image overlay. See #178.

### `SrunPortRange`

Without `SrunPortRange`, srun and salloc listen on a random port at every
run, and slurmctld and slurmstepd connect to it, so each run tends to show
as a new dependency and `server_port` churns in Prometheus. Set it in
`slurm.conf` (e.g. `SrunPortRange=60001-63000`; firewalls between the nodes
usually need it anyway). How shawk aggregates these ports is #174.
