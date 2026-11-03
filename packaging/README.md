# Packaging examples

Examples of how to deploy shawk and use its two contracts: the PostgreSQL
views of the schema `shawk_v1` and the metrics in Prometheus. They are
tested (`make test`) but meant to be adapted.

| Path | What |
|---|---|
| `systemd/shawk-agent.service`, `systemd/agent.env` | The agent on every host, as root with only the capabilities it needs and sandboxed; options in `/etc/shawk/agent.env`. |
| `systemd/shawk-collector.service` | The collector built with `make collector`, as the user `shawk-collector`, sandboxed. |
| `collector/config.yaml` | Collector configuration: the `otlp/shawk` receiver for agents, the shawk connector, Prometheus and OBI pipelines. |
| `postgres/setup.sql`, `postgres/grants.sql` | Roles (`shawk_owner`, `shawk_connector`, `shawk_grafana`), database and privileges. |
| `prometheus/prometheus.yml` | Settings Prometheus needs for the OTLP push of the collector. |
| `prometheus/shawk-rules.yml` | Recording rules that count each dependency once (connections, failures and their reasons, bytes, RTT, time to connect, retransmissions), and alerts. |
| `grafana/provisioning/` | Data sources (uids `shawk-postgres`, `shawk-prometheus`), the dashboard provider and SQL alert rules. |
| `grafana/dashboards/` | Dashboards: fleet, dependency map, dependency details, changes, application layer (OBI). |

Setting up PostgreSQL:

```sh
psql -v ON_ERROR_STOP=1 -f packaging/postgres/setup.sql                        # as a superuser; asks for the passwords
shawk-migrate -dsn 'postgres://shawk_owner:...@db/shawk?sslmode=verify-full'   # make shawk-migrate
psql -v ON_ERROR_STOP=1 -d shawk -U shawk_owner -f packaging/postgres/grants.sql
```

`setup.sql` creates the roles without passwords; then psql asks for the
password of each role, twice, and sends it hashed, so that it is in neither
the script, the command line nor the server log. Run it in a terminal. A
role without a password cannot log in with one: if psql stops at a password
that did not match, set the passwords left in psql, e.g.
`\password shawk_grafana`.

`grants.sql` runs after `shawk-migrate`, and again after an upgrade that
brings new migrations; it also sets default privileges for the tables that
later migrations create. `shawk-migrate` and the connector refuse a
database with the schema of v0.8.0 or of a development build before
`0001_schema.sql`. Dropping the schemas `shawk` and `shawk_v1` (`DROP
SCHEMA shawk, shawk_v1 CASCADE`, which also drops views of your own on
them) deletes the history they hold, so back them up first if you need it
(`pg_dump -n shawk -n shawk_v1`); then migrate and run `grants.sql` again.

`setup.sql` gives the sessions of `shawk_grafana` read-only transactions
and a statement timeout of 30 seconds. These are defaults, not limits: a
session can lift them (`SET statement_timeout = 0`, `BEGIN READ WRITE`),
and anyone who can view the dashboards can send SQL of their own through
the data source. What holds are the privileges: `shawk_grafana` reads
`shawk_v1` only, and neither it nor `shawk_connector` may create objects
of their own in the database: `setup.sql` revokes from `PUBLIC` the
creation of tables and functions in the schema `public` (which PostgreSQL
14 grants it) and of large objects, and `grants.sql` that of temporary
tables.

A session can still run a long query. To bound what Grafana uses, set
limits that its sessions cannot change, as a superuser, for example:

```sql
-- No fewer than the maxOpenConns of the data source times the Grafana servers.
ALTER ROLE shawk_grafana CONNECTION LIMIT 10;
-- Temporary files of a sort or a hash per session; only a superuser can change it.
ALTER ROLE shawk_grafana SET temp_file_limit = '1GB';
```

and cancel the queries that run longer than the timeout would allow, e.g.
every minute as a member of `pg_signal_backend`:

```sql
SELECT pg_cancel_backend(pid) FROM pg_stat_activity
WHERE usename = 'shawk_grafana' AND state = 'active' AND now() - query_start > interval '1 minute';
```

Prometheus must run with `--web.enable-otlp-receiver`.

The release packages `shawk-collector` install the collector as the
systemd service `shawk-collector` running as the user `shawk-collector`,
with its configuration in `/etc/shawk/collector.yaml`. Write the connection
string of the role `shawk_connector` to `/etc/shawk/postgres-dsn`, readable
by that user only:

```sh
sudo install -m 0640 -g shawk-collector /dev/stdin /etc/shawk/postgres-dsn <<<'postgres://shawk_connector:...@db/shawk?sslmode=verify-full&sslrootcert=/etc/shawk/tls/postgres-ca.crt'
```

With `sslmode=verify-full`, the connector and `shawk-migrate` check that the
certificate of PostgreSQL is signed by the CA in the file that `sslrootcert`
names (without `sslrootcert`, by a CA of the system) and names the host of
the connection string. With `sslmode=require` they accept any certificate,
so whoever can intercept the connection can pose as the server and be sent
the password. The Grafana data source names its CA with `sslRootCertFile`.

Both receivers of the example configuration require TLS with client
certificates, each from its own CA: `otlp/shawk` accepts those of
`agents-ca.crt`, `otlp` those of `obi-ca.crt`. Issue the certificates of
OBI from another CA than those of the agents: OBI often runs on hosts or in
containers trusted less than the agents, and with a certificate of their CA
it could send to `otlp/shawk` as an agent. The collector does not start
without `obi-ca.crt`; one that receives no OBI can leave out the receiver
`otlp` and the pipelines `metrics/obi` and `traces/obi` instead. The
certificate and key of the collector and the two CAs in `/etc/shawk/tls/`
must be readable by the user of the collector (`shawk-collector`; uid
65532 in the container image), e.g. the key with mode 0640 and group
`shawk-collector`. Agents present theirs with `-otlp-cert-file` and
`-otlp-key-file` (`systemd/agent.env`); OBI with the variables of the
OpenTelemetry SDK:

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
