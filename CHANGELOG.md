## [v0.8.0](https://github.com/yuuki/shawk/compare/v0.7.1...v0.8.0) (2026-11-01)

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
