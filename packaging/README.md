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
