# Contributing

Issues and pull requests are welcome. For a larger change, open an issue
first: the design in [docs/design.md](docs/design.md) explains why shawk
works the way it does, and [docs/proposals/](docs/proposals/) holds designs
not implemented yet.

1. Make the change with tests. Building needs Go only; the BPF programs
   need clang to recompile (`make generate`).
2. Run `make check` (lint, the workflows audit and the tests with the race
   detector). Depending on what you touched, also run the tests that need
   root, PostgreSQL or a VM (`make test-root`, `make pg-test`, `make e2e`,
   `make vm-test`); [AGENTS.md](AGENTS.md) lists which to run for what you
   touched.
3. Describe user-visible changes in the `Unreleased` section of
   [CHANGELOG.md](CHANGELOG.md).
4. Commits, branches and pull request titles follow the Git conventions in
   [AGENTS.md](AGENTS.md#git-conventions).

Report vulnerabilities privately, as [SECURITY.md](SECURITY.md) describes.
