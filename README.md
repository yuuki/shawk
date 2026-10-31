# shawk

<img alt="shawk-logo" src="docs/images/logo.png" width="160">

**The record of network dependencies of your servers.** shawk traces which
process talks to which network service on every host with eBPF, keeps the
record in PostgreSQL with the periods each host was observed, sends the
traffic of every dependency to Prometheus, and shows both in Grafana — so
that you can answer the questions you ask before changing a system:
*who still uses this database? what appeared after the deployment? did
anything use this host in the last 90 days, and were we watching?*

* **Zero instrumentation.** Dependencies are observed at TCP/UDP sockets in
  the kernel, so every process is covered — your code, middleware,
  third-party software, cron jobs — whatever language or protocol.
* **Low overhead, always on.** Flows to the same service are bundled in the
  kernel; TCP is traced at connection state changes only, with no hook on the
  send/receive path. Rare dependencies such as monthly batch jobs are not
  missed by sampling.
* **History with known coverage.** Every dependency has its first and last
  seen times, and every host its observation segments, so that "not used"
  is told apart from "not observed".
* **Standard building blocks.** Agents speak OTLP; a component of the
  OpenTelemetry Collector writes PostgreSQL and forwards metrics to
  Prometheus; Grafana dashboards and alerts are included. Services are
  named like OBI (OpenTelemetry eBPF Instrumentation) names them, so the
  network dependencies of shawk and the application metrics of OBI meet on
  the same `job`.

shawk implements the socket-based tracing with in-kernel flow bundling from
[Low Overhead TCP/UDP Socket-based Tracing for Discovering Network Services
Dependencies](https://yuuk.io/papers/transtracer_jip2022.pdf) (JIP, 2022).
See [docs/design.md](docs/design.md) for the design.

## How it fits together

```
 every host: eBPF ─ shawk agent ── OTLP ──→ collector with the shawk connector ─┬─→ PostgreSQL ─┐
                                                                               └─→ Prometheus ─┴─→ Grafana
```

| component | what it does |
|---|---|
| `shawk agent` | traces the dependencies of its host and sends them every 15 s as OTLP metrics; no database, no open port |
| shawk connector | writes dependencies, listeners and observation segments to PostgreSQL, names the peer of every dependency (`service.peer.name`), and forwards aggregated metrics without addresses to Prometheus |
| PostgreSQL | whether a dependency exists, since when and until when: the views of the schema `shawk_v1` |
| Prometheus | how much flows: connections, failures, bytes, RTT and retransmissions per dependency |
| Grafana | dashboards (fleet, dependency map, dependency details, changes, application layer) and alerts |

## Requirements

* Hosts: Linux with BTF (`/sys/kernel/btf/vmlinux`): Rocky Linux / RHEL 9,
  or upstream 5.14 or later (best 5.19 or later). The programs are tested by
  loading them on Ubuntu kernels 6.8 to 7.0 and checked statically against
  the Rocky Linux 9.6 kernel; they have not yet run on a Rocky Linux kernel,
  on upstream 5.14 to 5.18, or on arm64. See [the design](docs/design.md#35-kernel-requirements-and-features-used).
  The agent runs as root in the host PID namespace. UDP tracing
  additionally needs BPF trampolines (fentry), available on x86_64 and on
  arm64 since Linux 6.0; without them only TCP is traced.
* PostgreSQL 14 or later.
* Prometheus 3 with the OTLP receiver (`--web.enable-otlp-receiver`), or
  another store that accepts OTLP metrics.
* Grafana for the dashboards and alerts.

## Install

### Agent

shawk is a single static binary. The deb and rpm packages of a release
install it as `/usr/bin/shawk` with the systemd unit `shawk-agent.service`.
To install a build by hand:

```bash
make build                      # builds ./shawk (needs Go only)
sudo install -m 0755 shawk /usr/local/bin/shawk
sed 's|/usr/bin/shawk|/usr/local/bin/shawk|' packaging/systemd/shawk-agent.service |
  sudo tee /etc/systemd/system/shawk-agent.service >/dev/null
sudo install -D -m 0644 packaging/systemd/agent.env /etc/shawk/agent.env   # set -otlp-endpoint
sudo systemctl daemon-reload
sudo systemctl enable --now shawk-agent
```

Run the agent on every host you want to observe:

| flag | |
|---|---|
| `-otlp-endpoint` | URL of the `otlp/shawk` receiver of the collector; `http://` disables TLS (default `$OTEL_EXPORTER_OTLP_ENDPOINT` or `http://localhost:4327`) |
| `-otlp-protocol` | `grpc` (default) or `http/protobuf` |
| `-otlp-ca-file` | CA bundle that verifies the collector |
| `-service-name-fallback` | name of a service without `OTEL_SERVICE_NAME`: `exe` (executable name, as OBI) or `unit` (systemd unit) |
| `-interval`, `-idle-ttl` | export interval (15 s) and how long a dependency is sent after its last activity (15 min) |
| `-netns`, `-max-flows`, `-bpf-stats` | network namespaces to trace, capacity of the in-kernel flow table, BPF run time statistics |

Services that share an executable on a host (`ruby`, `python`, `java`,
`php-fpm`) should set `OTEL_SERVICE_NAME`, e.g. with `Environment=` in a
systemd drop-in; OBI uses the same name.

### Collector

The shawk connector is a component of the OpenTelemetry Collector. Build a
collector that includes it with the OpenTelemetry Collector Builder:

```bash
make collector                  # collector/_build/shawk-collector
make shawk-migrate              # ./shawk-migrate
```

Then set up PostgreSQL, the collector and Prometheus with the examples in
[packaging/](packaging/README.md):

```bash
psql -v ON_ERROR_STOP=1 -f packaging/postgres/setup.sql          # roles and database; edit the passwords
./shawk-migrate -dsn 'postgres://shawk_owner:...@db/shawk'        # the schema
psql -v ON_ERROR_STOP=1 -d shawk -U shawk_owner -f packaging/postgres/grants.sql
```

`packaging/collector/config.yaml` receives the agents on `otlp/shawk`
(port 4327) and OBI on `otlp` (port 4317), writes PostgreSQL with the role
`shawk_connector` and pushes metrics to Prometheus;
`packaging/prometheus/` has the Prometheus settings and the recording rules
that count each dependency once; `packaging/grafana/` has data sources,
dashboards and alert rules.

## Using it

In Grafana:

* **shawk / Fleet**: agents alive, observation gaps, dropped flows, new
  dependencies.
* **shawk / Dependency map**: services reached from the selected ones,
  upstream, downstream or both, to a depth.
* **shawk / Dependency details**: connections, failure ratio, bytes, RTT and
  retransmissions from Prometheus, with both ends, first and last seen
  times and how long each side has been observed from PostgreSQL.
* **shawk / Changes**: dependencies that appeared or disappeared.
* **shawk / Application layer (OBI)**: OBI's RED metrics next to the
  network dependencies of the same service.

In SQL, against the contract views of `shawk_v1`:

```sql
-- Who used postgres on db-01 in the last 90 days, and were they watching?
SELECT client_host, client_service, port, last_seen, client_observed_until, observed_by
FROM shawk_v1.dependencies_between(now() - interval '90 days', now())
WHERE server_host = 'db-01' AND server_service = 'postgres';

-- When was db-01 not observed?
SELECT * FROM shawk_v1.unobserved(now() - interval '90 days', now()) WHERE host = 'db-01';
```

In PromQL, with the recording rules:

```promql
shawk:dependency_connections:rate5m{dst="postgres"}
```

`shawk flows` shows the bundled flows of the local host live, without a
collector, for debugging.

## Development

```bash
make generate   # compile the BPF programs (needs clang and llvm-strip)
make test       # unit tests of all modules; BPF tests run as root,
                # PostgreSQL tests with SHAWK_TEST_POSTGRES_DSN=postgres://...
make test-root  # load the BPF programs into the running kernel (sudo)
make e2e        # multi-host test with network namespaces, a collector and
                # PostgreSQL (sudo, SHAWK_E2E_POSTGRES_DSN)
make compat     # check CO-RE relocations against the Rocky Linux 9 kernel
make check-object  # check that the committed BPF object matches the source
```

The repository has three Go modules: the agent (`.`), the shawk connector
(`collector/`, which keeps the dependencies of the collector out of the
agent) and the tests of the packaging examples (`test/packaging/`). The
generated BPF object (`internal/tracer/bpf_bpfel.o`) is committed, so
building shawk needs only Go.

## History

shawk started as *Transtracer* ([IOTS 2019](https://yuuk.io/papers/transtracer_iots2019.pdf))
and was rewritten from scratch in 2026, replacing the previous polling and
streaming probes, the central PostgreSQL CMDB and
[go-conntracer-bpf](https://github.com/yuuki/go-conntracer-bpf).

## License

shawk is licensed under the [Apache License 2.0](LICENSE).

The eBPF programs (`internal/tracer/bpf/shawk.bpf.c` and `shawk.h`) are
dual-licensed under [GPL-2.0-only](LICENSES/GPL-2.0-only.txt) OR
[BSD-2-Clause](LICENSES/BSD-2-Clause.txt): the kernel requires a
GPL-compatible license to load them, and the BSD option lets their compiled
object ship inside the Apache-2.0 binary. See [NOTICE](NOTICE) for the
licenses of the bundled libbpf headers and the generated `vmlinux.h`.
