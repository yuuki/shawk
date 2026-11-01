# Packaging examples

Examples of how to deploy shawk and use its two contracts: the PostgreSQL
views of the schema `shawk_v1` and the metrics in Prometheus. They are
tested (`make test`) but meant to be adapted.

| Path | What |
|---|---|
| `systemd/shawk-agent.service`, `systemd/agent.env` | The agent on every host; options in `/etc/shawk/agent.env`. |
| `systemd/shawk-collector.service` | The collector built with `make collector`. |
| `collector/config.yaml` | Collector configuration: the `otlp/shawk` receiver for agents, the shawk connector, Prometheus and OBI pipelines. |
| `postgres/setup.sql`, `postgres/grants.sql` | Roles (`shawk_owner`, `shawk_connector`, `shawk_grafana`), database and privileges. |
| `prometheus/prometheus.yml` | Settings Prometheus needs for the OTLP push of the collector. |
| `prometheus/shawk-rules.yml` | Recording rules that count each dependency once, and alerts. |
| `grafana/provisioning/` | Data sources (uids `shawk-postgres`, `shawk-prometheus`), the dashboard provider and SQL alert rules. |
| `grafana/dashboards/` | Dashboards: fleet, dependency map, dependency details, changes, application layer (OBI). |

Setting up PostgreSQL:

```sh
psql -v ON_ERROR_STOP=1 -f packaging/postgres/setup.sql          # as a superuser; edit the passwords first
shawk-migrate -dsn 'postgres://shawk_owner:...@db/shawk'          # make shawk-migrate
psql -v ON_ERROR_STOP=1 -d shawk -U shawk_owner -f packaging/postgres/grants.sql
```

Prometheus must run with `--web.enable-otlp-receiver`.

The release packages `shawk-collector` install the collector as the
systemd service `shawk-collector` running as the user `shawk-collector`,
with its configuration in `/etc/shawk/collector.yaml`. Write the connection
string of the role `shawk_connector` to `/etc/shawk/postgres-dsn`, readable
by that user only:

```sh
sudo install -m 0640 -g shawk-collector /dev/stdin /etc/shawk/postgres-dsn <<<'postgres://shawk_connector:...@db/shawk?sslmode=require'
```

Both receivers of the example configuration require TLS with client
certificates. The certificate, key and CA of the collector in
`/etc/shawk/tls/` must be readable by the user of the collector
(`shawk-collector`; uid 65532 in the container image), e.g. the key with
mode 0640 and group `shawk-collector`. Agents present theirs with
`-otlp-cert-file` and `-otlp-key-file` (`systemd/agent.env`); OBI with the
variables of the OpenTelemetry SDK:

```sh
# /etc/obi/app.env
OTEL_EXPORTER_OTLP_ENDPOINT=https://collector.example:4318
OTEL_EXPORTER_OTLP_CERTIFICATE=/etc/obi/tls/collector-ca.crt
OTEL_EXPORTER_OTLP_CLIENT_CERTIFICATE=/etc/obi/tls/obi.crt
OTEL_EXPORTER_OTLP_CLIENT_KEY=/etc/obi/tls/obi.key
```

A connector that does not migrate (`migrate: false`) waits until the schema
is at least its own version: run `shawk-migrate`, then `grants.sql` again,
before or while upgrading the collectors. The schema written by a newer
connector may not suit an older one; upgrade them together.
