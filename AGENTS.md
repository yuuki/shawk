# AGENTS.md

The guide for coding agents (and people) working on this repository. The
user-facing documentation is [README.md](README.md); the design, with the
reasons for it, is [docs/design.md](docs/design.md), which is the source of
truth: read the section of what you change before changing it.

## 1. Overview and architecture

shawk records the network dependencies of servers: which process talks to
which TCP/UDP service, or Unix stream socket, on every host, since when,
until when and how much.

```
host:  eBPF programs (internal/tracer/bpf) -> tracer (internal/tracer)
       -> identities of processes and services (internal/procinfo, internal/agent)
       -> cumulative OTLP series (internal/otlp) -> gRPC/HTTP every 15 s
collector: shawk connector (collector/shawkconnector)
       -> PostgreSQL (schema shawk, contract shawk_v1)
       -> aggregated metrics without addresses -> Prometheus -> Grafana
```

- **Agent** (`shawk agent`, `cmd/shawk`, `internal/cli`): loads the BPF
  programs, collects the bundled flows every interval
  (`Tracer.Collect`), names their processes and services, and exports all
  live series as cumulative OTLP metrics. No database, no open port; runs as
  root with the capabilities of `packaging/systemd/shawk-agent.service`.
  `shawk flows` prints the flows of the host.
- **Connector** (`collector/shawkconnector`, a separate Go module so that the
  agent does not depend on the collector): an OpenTelemetry Collector
  connector built into a collector by OCB (`make collector`). It decodes
  the requests of agents (`input.go`), names peers (`peers.go`), writes
  dependencies, listeners and observation segments to PostgreSQL
  (`pending.go`, `store.go`, `migrations/`), and forwards aggregated metrics
  (`aggregate.go`). `collector/cmd/shawk-migrate` applies the schema.
- **Packaging** (`packaging/`): systemd units, collector configuration,
  PostgreSQL setup, Prometheus rules and Grafana dashboards; checked by the
  tests of `test/packaging`.

## 2. Directory layout

| path | content |
|---|---|
| `cmd/shawk` | the binary: `shawk agent`, `shawk flows` |
| `internal/tracer` | BPF loading, maps, iterators, conversion of flows; `bpf/shawk.bpf.c`, `bpf/shawk.h`, vendored headers in `bpf/include`; generated `bpf_bpfel.go` and `bpf_bpfel.o` (committed) |
| `internal/procinfo` | cgroup paths to units, containers, `/proc` reads, service names |
| `internal/agent` | the loop of the agent, identities, RDMA counters, sd_notify |
| `internal/otlp` | series state, OTLP requests, gRPC and HTTP exporters |
| `internal/cli`, `internal/version` | flags and commands; the version set by ldflags |
| `collector/` | module of the connector; `cmd/shawk-migrate`; `Dockerfile` of the released image |
| `packaging/` | units, configuration, SQL, rules, dashboards |
| `test/packaging` | module: tests of `packaging/` (Prometheus rules, dashboards, units) |
| `test/e2e` | multi-host test in network namespaces (`make e2e`) |
| `test/vm` | the BPF tests in QEMU on other kernels (`make vm-test`) |
| `test/harness` | disposable PostgreSQL and a Slurm cluster in Lima ([README](test/harness/README.md)) |
| `test/hookcost`, `test/nodeload` | research tools: cost of kernel hooks (module of its own, bindings generated, not committed), load generators |
| `scripts/` | BPF object check, kernel BTF download, collector generation, notices |
| `docs/` | design; `proposals/` not implemented; `research/` not maintained |

## 3. Build

```bash
make build           # ./shawk, needs Go only: the BPF object is committed
make generate        # recompile the BPF programs (clang, llvm-strip)
make vmlinux         # regenerate vmlinux.h from the running kernel (bpftool)
make collector       # collector/_build/shawk-collector with the connector (downloads OCB)
make shawk-migrate   # ./shawk-migrate
```

Go comes from `go.mod` (`go 1.27.3`; `GOTOOLCHAIN=auto` downloads it). There
are four modules: `.`, `collector`, `test/packaging`, `test/hookcost`.

## 4. Test

| command | what | needs |
|---|---|---|
| `make test` | unit tests of `.`, `collector`, `test/packaging` | Linux; as root it also runs the BPF tests of `internal/tracer` |
| `make test-race` | the same with `-race` | as above |
| `make test-fuzz` | every `Fuzz*` target for `FUZZTIME` (default 30s), new inputs minimized for at most `FUZZMINIMIZETIME` (10s) | nothing |
| `make bench` | benchmarks into `bench.txt` (compare with benchstat) | nothing |
| `make test-root` | the tests that load the BPF programs into the running kernel | sudo, BTF |
| `make pg-up`, `make pg-test`, `make pg-down` | the connector's `TestPG*` tests against a disposable PostgreSQL | not root (initdb refuses it); as root, run `postgres:16` in a container and set `SHAWK_TEST_POSTGRES_DSN` |
| `make test-integration` | `test-root` and `pg-test` | both of the above |
| `make e2e` | multi-host test with network namespaces | sudo, `psql`, `SHAWK_E2E_POSTGRES_DSN` |
| `make compat` | the BPF programs against the BTF of Rocky Linux 9 | downloads a kernel RPM, `rpm2cpio` |
| `make check-object` | the committed BPF object matches the source | clang, llvm-strip |
| `make vm-test KERNEL=rocky9\|5.14\|5.15 ARCH=x86_64\|aarch64` | `test-root` on other kernels in QEMU | QEMU, KVM for the host arch |
| `make slurm-up`, `make slurm-check`, `make slurm-down` | Slurm cluster in a VM of Lima | Lima, QEMU/KVM |

- PostgreSQL tests are skipped without `SHAWK_TEST_POSTGRES_DSN`; BPF tests
  are skipped without root, and fail instead with `SHAWK_TEST_STRICT=1`.
  [test/harness/README.md](test/harness/README.md) lists every variable.
- `internal/agent`, `internal/otlp`, `internal/procinfo`, `internal/tracer`
  and `collector/shawkconnector` check for leaked goroutines (goleak in
  `main_test.go`): stop what a test starts.
- Fuzz targets are in `fuzz_test.go` of `internal/tracer` (names of Unix
  sockets, iterator records), `internal/procinfo` (cgroup paths, mountinfo,
  environments), `internal/otlp` (requests) and `collector/shawkconnector`
  (requests of agents). A failing input is written to
  `testdata/fuzz/FuzzXxx/`: keep it as a regression seed with the fix.
- CI (`.github/workflows/test.yml`) runs lint, fuzz, the workflows audit,
  the unit tests with race and PostgreSQL, `test-root`, `e2e`, the packaged
  unit, `compat`, `check-object`, and the VM kernels; `security.yml` runs
  CodeQL and govulncheck.

## 5. Static analysis

```bash
make check          # lint, lint-actions, test-race: the gate before a pull request
make lint           # golangci-lint (.golangci.yml) in ., collector, test/packaging; go mod tidy -diff in all four modules
make fmt            # gofmt through golangci-lint
make vet            # go vet and the gofmt check that CI runs
make lint-actions   # actionlint and zizmor (offline unless GH_TOKEN is set)
make vuln           # govulncheck in ., collector, test/packaging
make complexity     # cccc ranking (cccc.toml); CI tracks it with octocov
```

`test/hookcost` is not linted (its bindings need `go generate` with clang).
Where `GH_TOKEN` is set but the GitHub API cannot be reached, run
`env -u GH_TOKEN make check`. Tool versions are pinned in the Makefile and
the workflows; bump them together.

## 6. Coding conventions

- Comments and docs in English, in full sentences, saying why rather than
  what; match the density and style of the surrounding code.
- Logging: the agent uses `log/slog` (the logger of `agent.Config`), the
  connector `zap` (the logger of the collector). Warnings that can repeat
  are rate-limited (see `warnOnce`, the `last*Log` fields of the
  connector).
- Errors: wrap with `%w`; usage errors wrap `errUsage` (exit status 2).
- Every new parser of input from the kernel, `/proc`, the files of
  container runtimes or the network gets a test, and a fuzz target when it
  takes arbitrary bytes.
- Commits: short scoped subjects (`tracer: ...`, `connector: ...`,
  `procinfo: ...`, `agent: ...`, `docs: ...`, `ci: ...`, `chore: ...`),
  the reason in the body. User-visible changes go to the `Unreleased`
  section of [CHANGELOG.md](CHANGELOG.md).

## 7. Compatibility contracts

What must not change silently (design §2: the contracts are the PostgreSQL
views and functions and the Prometheus names and labels; the rest is kept
in agreement between agent and connector, which are released together):

- **PostgreSQL**: the schema `shawk_v1` (views and functions) of
  `collector/shawkconnector/migrations/` (design §6.2); a change of the
  schema is a migration, and `SchemaVersion` in `migrate.go`.
- **Prometheus**: the metric names and attributes the connector outputs
  (`outMetrics` in `aggregate.go`, `names.go`), the recording rules and
  alerts of `packaging/prometheus/shawk-rules.yml` and the dashboards of
  `packaging/grafana/`, which `test/packaging` checks.
- **Agent to connector OTLP** (internal, but both sides must agree): the
  names in `internal/otlp/names.go` and `collector/shawkconnector/names.go`,
  the golden request `collector/shawkconnector/testdata/agent-request.json`
  (rewritten by `go test ./internal/otlp -run TestGoldenRequest -update`),
  the BPF programs listed in `bpfPrograms` (`TestBPFProgramsOfTheAgent`).
- **BPF**: the structs of `internal/tracer/bpf/shawk.h`, their generated Go
  types in `bpf_bpfel.go` and their conversions in `collect.go`, `iter.go`
  and `conntrack.go`; the enums mirrored in `types.go` (`FoldMode`,
  `FailReason`, `KernelComm`, `ProtoUnix`).
- **Command line and configuration**: the flags of `shawk agent` and
  `shawk flows` (`internal/cli/cli.go`, `packaging/systemd/agent.env`); the
  configuration keys of the connector (`config.go`,
  `packaging/collector/config.yaml`, validated in CI); the systemd units and
  their sandbox (`packaging/systemd`).
- **Names of units and services** (`procinfo.Unit`, `ServiceName`): they
  are kept in PostgreSQL and become `job` in Prometheus; the units of Slurm
  jobs (`slurm/<kind>`) select how jobs are named and grouped.

## 8. Concurrency and resource management

- Agent: one loop (`agent.Run`) collects and exports every interval; each
  export has a deadline of its own. Reads of `/proc` that can hang (the
  environment of a process) run with a timeout and a bound on outstanding
  reads (`procinfo.OTelEnv`, `MaxEnvironReads`); reads of the state of
  containers go through a bounded queue (`Resolver.queueRead`).
- Tracer: `Tracer.Close` closes links, maps and the reader of the ring
  buffer of cgroup events and waits for it. `openInNetNS` enters other
  network namespaces on a locked OS thread, which is discarded if it cannot
  return.
- Connector: `ConsumeMetrics` runs on the receiver's goroutines and holds
  `c.mu` for the aggregator and pending changes; the loop started by
  `Start` and stopped by `Shutdown` writes to PostgreSQL every
  `write_interval`, with a deadline per write. Everything the connector
  holds per agent is bounded (design §5.5: `max_hosts`,
  `max_series_per_host`, `max_pending_rows`, string and label sizes); keep
  new state bounded too.
- Strings of agents are cleaned for PostgreSQL (`cleanString`: valid UTF-8,
  no NUL) and cut (`maxStringBytes`, `maxLabelValue`); the agent sends valid
  UTF-8 only (`str` in `internal/otlp/request.go`).

## 9. Performance constraints

- The BPF programs run in the kernel for every process: TCP is traced at
  state changes and walks, never per message; UDP pays per datagram, so
  keep its programs short. Flows are bundled in the kernel, keyed without
  the ephemeral port; the maps are sized by `-max-flows`.
- A request of the agent stays below `MaxRequestBytes` (3 MiB) and
  `-max-series-per-request`.
- Prometheus outputs carry no addresses (unless `keep_peer_address`) and
  bounded label values; new labels need a bound on their cardinality.

## 10. Before opening a pull request

- `make check` passes (needs no PostgreSQL, VM or root).
- Touching the connector's SQL or store: the `TestPG*` tests
  (`make pg-test`, or `SHAWK_TEST_POSTGRES_DSN`).
- Touching the BPF programs: `make generate` (commit both `bpf_bpfel.*`),
  `make check-object`, `make test-root`, `make compat`, and `make vm-test`
  for the kernels you can.
- Touching `packaging/`: `make test` runs `test/packaging`; `make e2e` for
  the collector configuration.
- Touching `.github/`: `make lint-actions`.

## 11. Rules for AI agents

Do not:

- disable, skip, delete or weaken tests, fuzz targets, lint rules or CI
  checks to get green, or hide failures (`|| true`, `continue-on-error`);
- edit generated files by hand (`bpf_bpfel.go`, `bpf_bpfel.o`, the
  generated collector in `collector/_build`), or the vendored headers of
  `internal/tracer/bpf/include`;
- add dependencies without a justification, or runtime dependencies to the
  agent's module for what the connector needs;
- change a contract of §7 without saying so in the pull request and the
  CHANGELOG;
- loosen the permissions of workflows, unpin actions or tools, or add
  third-party services;
- commit secrets (the harness makes its passwords and keys where they are
  used), rewrite published history, force-push, tag or publish releases.

## 12. Changes that need human review

Even with CI green: workflows and `.goreleaser.yml`, permissions and
secrets; the BPF programs and what they read from the kernel; parsers of
input from the network, `/proc`, cgroups and container runtimes; the
systemd units and their sandbox; the schema and its grants; the contracts
of §7; dependency additions; large refactors.
