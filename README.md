# shawk

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
  seen times, and every host its observation segments and the periods in
  which its agent dropped flows, so that "not used" is told apart from "not
  observed" and "partly observed".
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

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="docs/images/architecture-dark.svg">
  <img alt="On every host, eBPF programs in the kernel trace the sockets of all processes, and the shawk agent sends the bundled flows as OTLP metrics every 15 seconds to an OpenTelemetry Collector with the shawk connector. The connector writes dependencies, listeners and observation segments to PostgreSQL and metrics per service without addresses to Prometheus; Grafana shows both. OBI can send application-layer metrics to the same collector." src="docs/images/architecture-light.svg">
</picture>

| component | what it does |
|---|---|
| `shawk agent` | traces the dependencies of its host and sends them every 15 s as OTLP metrics; no database, no open port |
| shawk connector | writes dependencies, listeners and observation segments to PostgreSQL, names the peer of every dependency (`service.peer.name`), and forwards aggregated metrics without addresses to Prometheus |
| PostgreSQL | whether a dependency exists, since when and until when: the views of the schema `shawk_v1` |
| Prometheus | how much flows: connections, failures by reason, bytes, RTT, time to connect and retransmissions per dependency |
| Grafana | dashboards (fleet, dependency map, dependency details, changes, application layer) and alerts |

## Requirements

* Hosts: Linux with BTF (`/sys/kernel/btf/vmlinux`): Rocky Linux / RHEL 9,
  or upstream 5.14 or later (best 5.19 or later). The programs are tested in
  virtual machines on the kernels of Rocky Linux 9.6 (x86_64, aarch64) and
  upstream 5.14 (x86_64) and 5.15 (x86_64, aarch64), and on the kernels of
  the Ubuntu CI runners (x86_64, arm64). See
  [the design](docs/design.md#35-kernel-requirements-and-features-used).
  The agent runs as root in the host PID namespace; its systemd unit
  sandboxes it and limits it to `CAP_BPF`, `CAP_PERFMON`, `CAP_SYS_ADMIN`
  (to enter other network namespaces), `CAP_SYS_PTRACE` and
  `CAP_DAC_READ_SEARCH` (to read `/proc` of other processes). UDP tracing
  additionally needs BPF trampolines (fentry), available on x86_64 and on
  arm64 since Linux 6.0 (not on Rocky Linux 9 on arm64); without them only
  TCP is traced. Learning translations of addresses from conntrack needs
  kprobes (`CONFIG_KPROBES`), which the unit allows with `perf_event_open`.
* PostgreSQL 14 or later.
* Prometheus 3 with the OTLP receiver (`--web.enable-otlp-receiver`), or
  another store that accepts OTLP metrics.
* Grafana for the dashboards and alerts.

## Install

### Agent

shawk is a single static binary. The deb and rpm packages of a release
install it as `/usr/bin/shawk` with the systemd unit `shawk-agent.service`.
To install a release tarball, which contains `shawk` and `packaging/systemd/`,
or a build by hand:

```bash
make build                      # builds ./shawk (needs Go only); or extract the tarball
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
| `-otlp-cert-file`, `-otlp-key-file` | client certificate for a collector that requires one (the example configuration does) |
| `-max-series-per-request` | dependencies, listeners and translations per request (1000); a request also stays below 3 MiB, and a busy host sends several per interval |
| `-service-name-fallback` | name of a service without `OTEL_SERVICE_NAME`: `exe` (executable name, as OBI) or `unit` (systemd unit, or the name of the container); a container of Kubernetes is named after the workload of its pod either way |
| `-interval`, `-idle-ttl` | export interval (15 s, at most 1 min) and how long a dependency is sent after its last activity (15 min) |
| `-netns`, `-max-flows`, `-bpf-stats` | network namespaces to trace, capacity of the in-kernel flow table (also sizing the tables of listening ports), BPF run time statistics |
| `-learn-translations` | learn the translations of addresses the host makes (Docker published ports and masquerade, kube-proxy, IPVS, any DNAT or SNAT) from conntrack, once nf_conntrack is loaded (default `true`); see [the design](docs/design.md#37-translations-of-addresses-learned-from-conntrack) |
| `-internal-peers`, `-fold-external` | address ranges whose peers are kept exact (`private`: the ranges not routed on the Internet), and which flows fold the other peers into one dependency per local endpoint: `in` (the clients of local servers, default), `all` or `none`; see [the design](docs/design.md#36-folding-external-peers) |

Services that share an executable on a host (`ruby`, `python`, `java`,
`php-fpm`) should set `OTEL_SERVICE_NAME`, e.g. with `Environment=` in a
systemd drop-in; OBI uses the same name.

### Collector

The shawk connector is a component of the OpenTelemetry Collector. A
release ships a collector that includes it, of the same version as the
agent:

* the deb and rpm packages `shawk-collector`: `/usr/bin/shawk-collector`,
  `/usr/bin/shawk-migrate`, the systemd unit `shawk-collector.service`
  (user `shawk-collector`), `/etc/shawk/collector.yaml` and the PostgreSQL
  scripts in `/usr/share/shawk-collector/postgres`;
* the container image `ghcr.io/yuuki/shawk-collector` (amd64 and arm64),
  which also contains `/shawk-migrate`.

To build it yourself with the OpenTelemetry Collector Builder:

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
(port 4327) and OBI on `otlp` (port 4317), both with TLS and client certificates, writes PostgreSQL with the role
`shawk_connector` and pushes metrics to Prometheus;
`packaging/prometheus/` has the Prometheus settings and the recording rules
that count each dependency once; `packaging/grafana/` has data sources,
dashboards and alert rules.

Connections through a load balancer, a virtual address or a proxy without an
agent end at its address, on one side only, unless the agent of the host
that translates the addresses learns the translation from conntrack (Docker
published ports, kube-proxy, IPVS, NAT rules), or `translations` in the
configuration of the connector describes it: its virtual addresses, its
backends and, if it replaces the addresses of the clients, the addresses the
backends see them at ([design §5.4](docs/design.md#54-translations-of-addresses)).

## Using it

In Grafana:

* **shawk / Fleet**: agents alive, observation gaps, partly observed
  periods, dropped flows, new dependencies.
* **shawk / Dependency map**: services reached from the selected ones,
  upstream, downstream or both, to a depth.
* **shawk / Dependency details**: connections, failure ratio, bytes, RTT,
  retransmissions, mean connect time, SYN retransmissions and failures by
  reason (refused, timeout, unreachable, ...) from Prometheus, with both
  ends, first and last seen times and how long each side has been observed
  from PostgreSQL.
* **shawk / Changes**: dependencies that appeared or disappeared.
* **shawk / Application layer (OBI)**: OBI's RED metrics next to the
  network dependencies of the same service.

The screenshots below, from Grafana 13.3, are of a demo: nine hosts, the
network namespaces of one machine with an agent each, over an hour in which
the agent of `cache-01` stopped for a few minutes, `legacy-cron` stopped
using `postgres`, a `nightly-report` ran for five minutes, and `storefront`
was deployed to use `redis-server` instead of `memcached` and a new
`recommend` service, started three minutes later. The kernel of the demo
cannot trace UDP.

The dependency map of `haproxy`, upstream and downstream. Clients without an
agent are named `~external` (outside the internal ranges) and `~unresolved`,
and the payment API by `peer_cidrs`:

![The dependency map: ~external to haproxy on lb-01, to storefront on web-01 and web-02, to catalog, memcached, redis-server, recommend and postgres; order-worker to postgres, redis-server and payment-gateway; legacy-cron, nightly-report and ~unresolved to postgres](docs/images/grafana-dependency-map.png)

The dependency details of `storefront`. After the deployment its open
connections move from `memcached` to `redis-server`, and until `recommend`
started, its connections to that port failed and had no service to be named
after (`~unresolved`). The red band is the period in which `cache-01` was not
observed:

![The dependency details of storefront: connections, connection failure ratio, request and response bytes, mean RTT, retransmitted segments and open connections per dependency over the hour](docs/images/grafana-dependency-details.png)

The fleet, with the observation gap of `cache-01` and the dependencies that
appeared today:

![The fleet: 9 agents alive, 0 silent, 9 without UDP tracing, 15 new dependencies today; the agents, the observation gap of cache-01 and the dependencies that appeared today](docs/images/grafana-fleet.png)

The table of the changes of the hour:

![The changes: nightly-report to postgres appeared and disappeared, recommend to redis-server and storefront to redis-server and recommend appeared, storefront to memcached and legacy-cron to postgres disappeared](docs/images/grafana-changes.png)

In SQL, against the contract views of `shawk_v1`:

```sql
-- Who used postgres on db-01 in the last 90 days, and were they watching?
SELECT client_host, client_service, port, last_seen, client_observed_until, observed_by
FROM shawk_v1.dependencies_between(now() - interval '90 days', now())
WHERE server_host = 'db-01' AND server_service = 'postgres';

-- When was db-01 not observed?
SELECT * FROM shawk_v1.unobserved(now() - interval '90 days', now()) WHERE host = 'db-01';

-- When did the agent of db-01 drop flows?
SELECT * FROM shawk_v1.partly_observed(now() - interval '90 days', now()) WHERE host = 'db-01';
```

In PromQL, with the recording rules:

```promql
shawk:dependency_connections:rate5m{dst="postgres"}

# The mean time to connect to postgres, from connect(2) to the SYN-ACK, and
# the clients whose connects time out.
shawk:dependency_handshake_seconds_sum:rate5m{dst="postgres"}
  / shawk:dependency_handshake_seconds_count:rate5m{dst="postgres"}
shawk:dependency_connection_failures_by_reason:rate5m{dst="postgres", error_type="timeout"} > 0
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
make compat     # check CO-RE relocations against the Rocky Linux 9 kernel,
                # whose RPM is downloaded once to build/ and checksummed
make check-object  # check that the committed BPF object matches the source
make vmlinux    # regenerate the kernel types (vmlinux.h) from the running
                # kernel with bpftool
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
