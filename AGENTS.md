# AGENTS.md

## Rules
- `docs/design.md` is the source of truth for the design and its reasons: read the section of what you change first.
- The connector (`collector/`) is a separate module so the agent never depends on the collector: add nothing it needs to the agent's module.
- Everything the connector holds per agent is bounded (design §5.5): give any new state a bound too.
- Strings from agents go through `cleanString` and the size cuts before PostgreSQL; the agent sends valid UTF-8 only.
- BPF programs run for every process: trace TCP at state changes and walks, never per message; keep the per-datagram UDP programs short.
- Prometheus outputs carry no addresses (unless `keep_peer_address`); every new label needs a bound on its cardinality.

## Compatibility contracts
- PostgreSQL schema `shawk_v1`, public: `collector/shawkconnector/migrations/`; a change is a new migration.
- Prometheus names and labels, public: `collector/shawkconnector/names.go`, `aggregate.go`, `packaging/prometheus/shawk-rules.yml`, `packaging/grafana/`.
- Unit and service names (`procinfo.Unit`, `ServiceName`): stored in PostgreSQL and used as `job` in Prometheus.
- Agent ↔ connector, released together: `internal/otlp/names.go` ↔ `collector/shawkconnector/names.go`, golden `collector/shawkconnector/testdata/agent-request.json`.
- BPF: structs of `internal/tracer/bpf/shawk.h` ↔ `bpf_bpfel.go` ↔ `collect.go`, `iter.go`, `conntrack.go`; enums mirrored in `types.go`.
- Agent flags (`internal/cli/cli.go`, `packaging/systemd/agent.env`); connector configuration keys (`config.go`, `packaging/collector/config.yaml`).
- The systemd units and their sandbox: `packaging/systemd/`.

## Before opening a pull request
- `make check`; also the connector's SQL or store → `make pg-test` (initdb refuses root: as root, run `postgres:16`, set `SHAWK_TEST_POSTGRES_DSN`).
- BPF programs → `make generate` (commit both `bpf_bpfel.*`), `make check-object test-root compat`, and `make vm-test` for the kernels you can.
- `packaging/` (collector configuration) → `make e2e`.

## Git conventions
- Branches: `<type>/<issue>-<summary>` (`<type>/<summary>` without an issue); tools' `agent/*`, `claude/*`, `copilot/*`, `dependabot/*` keep their names.
- Commits and PR titles: Conventional Commits 1.0.0, types `feat` `fix` `perf` `refactor` `test` `docs` `build` `ci` `chore` `revert`; scopes: `tracer`, `connector`, `procinfo`, `agent`, `otlp`, `cli`, `packaging`.
