# AGENTS.md

This file holds only what the code does not show: rules, contracts and
conventions. [docs/design.md](docs/design.md) is the source of truth for the
design and its reasons: read the section of what you change before changing
it.

## Rules the code does not show

- Comments and docs in English.
- The connector is a separate Go module (`collector/`) so that the agent does
  not depend on the collector: never add what the connector needs to the
  agent's module.
- Everything the connector holds per agent is bounded (design §5.5); give any
  new state a bound too.
- Strings from agents go through `cleanString` (valid UTF-8, no NUL) and the
  size cuts before PostgreSQL; the agent sends valid UTF-8 only.
- `/proc` reads that can hang need a timeout and a bound on outstanding reads;
  warnings that can repeat are rate-limited.
- BPF programs run for every process: trace TCP at state changes and walks,
  never per message; keep the UDP programs (per datagram) short.
- Prometheus outputs carry no addresses (unless `keep_peer_address`); every
  new label needs a bound on its cardinality.
- Every new parser of input from the kernel, `/proc`, container runtime files
  or the network gets a test, and a fuzz target when it takes arbitrary bytes.
- User-visible changes go to the `Unreleased` section of `CHANGELOG.md`.

## Compatibility contracts

The public contracts are the PostgreSQL views and functions and the
Prometheus names and labels (design §2); the agent and the connector are
released together, so the rest only has to agree between them. Never change
any of these silently:

- PostgreSQL schema `shawk_v1` (views and functions):
  `collector/shawkconnector/migrations/`; a change is a new migration and a
  new `SchemaVersion` (`migrate.go`).
- Prometheus metric names and attributes (`collector/shawkconnector/names.go`,
  `aggregate.go`), `packaging/prometheus/shawk-rules.yml`,
  `packaging/grafana/`.
- Agent ↔ connector OTLP: `internal/otlp/names.go` ↔
  `collector/shawkconnector/names.go`; the connector's golden request
  `testdata/agent-request.json` is written by `TestGoldenRequest` of
  `internal/otlp`.
- BPF: the structs of `internal/tracer/bpf/shawk.h` ↔ `bpf_bpfel.go` ↔ their
  conversions in `collect.go`, `iter.go`, `conntrack.go`; the enums mirrored
  in `types.go`.
- Flags of `shawk agent` and `shawk flows` (`internal/cli/cli.go`,
  `packaging/systemd/agent.env`); connector configuration keys (`config.go`,
  `packaging/collector/config.yaml`).
- The systemd units and their sandbox: `packaging/systemd/`.
- Names of units and services (`procinfo.Unit`, `ServiceName`): stored in
  PostgreSQL and used as `job` in Prometheus.

## Before opening a pull request

Run `make check`. Also, when you touch:

- the connector's SQL or store: `make pg-test`.
- the BPF programs: `make generate` (commit both `bpf_bpfel.*`),
  `make check-object test-root compat`, and `make vm-test` for the kernels you
  can.
- `packaging/` (collector configuration): `make e2e`.

## Git conventions

Branches: `<type>/<issue>-<summary>`, or `<type>/<summary>` without an issue
(`fix/166-connect-errors`, `feat/qp-counters`). `<type>` is a commit type
below; `<summary>` is 2–5 lowercase ASCII words joined by `-`. Branches named
by tools keep their names (`agent/*`, `claude/*`, `copilot/*`,
`dependabot/*`). Never push to the default branch.

Commits follow [Conventional Commits 1.0.0](https://www.conventionalcommits.org/en/v1.0.0/):

    <type>(<scope>)!: <subject>

    <body>

    <footer>

- `type`: `feat` (new user-visible behaviour), `fix` (bug fix), `perf`,
  `refactor` (no behaviour change), `test`, `docs`, `build` (build system,
  dependencies, packaging), `ci` (workflows), `chore` (anything else, e.g.
  `chore(release): prepare v1.2.3`), `revert`.
- `scope`: optional; the package or area changed: `tracer`, `connector`,
  `procinfo`, `agent`, `otlp`, `cli`, `packaging`.
- `!` and a `BREAKING CHANGE: <what changed and how to migrate>` footer for
  any change to a compatibility contract above.
- `subject`: imperative, lower case (except identifiers), no final period,
  at most 72 characters including the prefix.
- `body`: why the change is needed and what it affects, wrapped at 72
  columns; required unless the subject says everything.
- `footer`: `Fixes #N` / `Refs #N`, `BREAKING CHANGE:`, trailers such as
  `Co-Authored-By:`.
- One logical change per commit; regenerated files go in the commit that
  changes their source. Pull request titles use the same format (they become
  the squash commit).

## Forbidden

- Disabling, skipping, deleting or weakening tests, fuzz targets, lint rules
  or CI checks to get green, or hiding failures (`|| true`,
  `continue-on-error`).
- Editing generated files by hand (`bpf_bpfel.go`, `bpf_bpfel.o`, the
  generated collector) or the vendored headers of
  `internal/tracer/bpf/include`.
- Adding dependencies without a justification.
- Changing a compatibility contract without saying so in the pull request and
  the CHANGELOG.
- Loosening the permissions of workflows, unpinning actions or tools, or
  adding third-party services.
- Committing secrets, rewriting published history, force-pushing, tagging or
  publishing releases.

## Needs human review

Even with CI green: workflows and `.goreleaser.yml`, permissions and secrets;
the BPF programs and what they read from the kernel; parsers of input from the
network, `/proc`, cgroups and container runtimes; the systemd units and their
sandbox; the schema and its grants; the compatibility contracts; dependency
additions; large refactors.

## Environment notes

- With `GH_TOKEN` set but the GitHub API unreachable:
  `env -u GH_TOKEN make check`.
- As root, `make pg-test` fails (initdb refuses root): run `postgres:16` in a
  container and set `SHAWK_TEST_POSTGRES_DSN` instead.
