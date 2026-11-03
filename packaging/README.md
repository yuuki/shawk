# Packaging examples

Examples of how to deploy shawk and use its two contracts: the PostgreSQL
views of the schema `shawk_v1` and the metrics in Prometheus. They are
tested (`make test`) but meant to be adapted.

| Path | What |
|---|---|
| `systemd/shawk-agent.service`, `systemd/agent.env` | The agent on every host, as root with only the capabilities it needs and sandboxed; options in `/etc/shawk/agent.env`. |
| `systemd/shawk-collector.service`, `systemd/collector.env` | The collector built with `make collector`, as the user `shawk-collector`, sandboxed; secrets in `/etc/shawk/collector.env`. |
| `collector/config.yaml` | Collector configuration: the `otlp/shawk` receiver for agents, the shawk connector, Prometheus and OBI pipelines. |
| `postgres/setup.sql`, `postgres/grants.sql` | Roles (`shawk_owner`, `shawk_connector`, `shawk_grafana`), database and privileges. |
| `prometheus/prometheus.yml` | Settings Prometheus needs for the OTLP push of the collector. |
| `prometheus/web.yml` | Web configuration of Prometheus: TLS, and users with passwords, so that only its clients can push. |
| `prometheus/shawk-rules.yml` | Recording rules that count each dependency once (connections, failures and their reasons, bytes, RTT, time to connect, retransmissions), and alerts. |
| `grafana/provisioning/` | Data sources (uids `shawk-postgres`, `shawk-prometheus`), the dashboard provider and SQL alert rules. |
| `grafana/dashboards/` | Dashboards: fleet, dependency map, dependency details, changes, application layer (OBI). |

Setting up PostgreSQL:

```sh
psql -v ON_ERROR_STOP=1 -f packaging/postgres/setup.sql          # as a superuser; edit the passwords first
shawk-migrate -dsn 'postgres://shawk_owner:...@db/shawk'          # make shawk-migrate
psql -v ON_ERROR_STOP=1 -d shawk -U shawk_owner -f packaging/postgres/grants.sql
```

`grants.sql` runs after `shawk-migrate`, and again after an upgrade that
brings new migrations; it also sets default privileges for the tables that
later migrations create. `shawk-migrate` and the connector refuse a
database with the schema of v0.8.0 or of a development build before
`0001_schema.sql`. Dropping the schemas `shawk` and `shawk_v1` (`DROP
SCHEMA shawk, shawk_v1 CASCADE`, which also drops views of your own on
them) deletes the history they hold, so back them up first if you need it
(`pg_dump -n shawk -n shawk_v1`); then migrate and run `grants.sql` again.

Prometheus must run with `--web.enable-otlp-receiver`, and with the web
configuration of `prometheus/web.yml` (`--web.config.file`). The OTLP
receiver writes whatever series it is sent: without that configuration,
anyone who can reach Prometheus can push `shawk_agent_up` or any other
series, bypassing the client certificates the collector requires, and
silence the alerts on agents. `web.yml` serves every endpoint of
Prometheus over TLS, to the users of `basic_auth_users` only; replace the
placeholders with bcrypt hashes of their passwords
(`htpasswd -nBC 12 '' | tr -d ':\n'`), or Prometheus refuses to start.
Prometheus does not tell readers from writers, so every user can also
push: give each client its own user.

* The collector verifies Prometheus with
  `/etc/shawk/tls/prometheus-ca.crt` and sends the header `Authorization`
  from the variable `SHAWK_PROMETHEUS_AUTHORIZATION` (`otlp_http/prometheus`
  in `collector/config.yaml`). The unit reads it from
  `/etc/shawk/collector.env`, which the packages install readable by root
  only; the container image takes it with `docker run --env-file`. Its
  value is `Basic` and the base64 of the user and password:

  ```sh
  printf 'Basic %s\n' "$(printf '%s' 'shawk-collector:PASSWORD' | base64 -w0)"
  ```

  Without it, Prometheus refuses the metrics and the collector logs the
  error (HTTP status 401).
* Grafana logs in as `grafana`, with the password in
  `$SHAWK_GRAFANA_PROMETHEUS_PASSWORD`, and verifies Prometheus with
  `/etc/grafana/tls/prometheus-ca.crt` (`grafana/provisioning/datasources/shawk.yaml`).
* People, and Prometheus itself if it scrapes itself (`basic_auth` and
  `tls_config` in the scrape configuration), log in as users of their own.

Prometheus can require client certificates instead of passwords
(`client_auth_type` and `client_ca_file` in `web.yml`), but then of every
client, Grafana and browsers included; the collector presents its own with
`tls.cert_file` and `tls.key_file` instead of the header. To let only the
collector push, put a proxy in front of Prometheus that passes
`/api/v1/otlp/` from the collector alone.

The trace exporter `otlp_grpc/traces` verifies the trace store with
`/etc/shawk/tls/tempo-ca.crt` and presents the client certificate
`/etc/shawk/tls/collector-client.crt`, which the store should require (in
Tempo, `tls.client_ca_file` of the `otlp` receiver of the distributor).

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

A connector that does not migrate (`migrate: false`, as in the example)
waits until the schema is at least its own version, and warns when the
schema is newer than itself: a schema written by a newer connector may not
suit an older one. When upgrading, run `shawk-migrate` and then
`grants.sql` before or while upgrading the collectors, and upgrade all of
them.
