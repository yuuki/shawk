## What and why

<!-- What changes, and the reason. Link the issue (#...). -->

## How it was tested

<!-- Commands run and their results: make check, make test-root, make pg-test, make e2e, make vm-test KERNEL=... -->

## Checklist

- [ ] `make check` passes.
- [ ] Changed behaviour has tests; parsers of new input have a fuzz target.
- [ ] The docs (`docs/design.md`, README, `packaging/README.md`) and the `Unreleased` section of `CHANGELOG.md` are updated.
- [ ] The contracts (the `shawk_v1` schema, metric names and labels, flags, configuration keys; AGENTS.md §7) are unchanged, or the change is called out above.
- [ ] Changes assisted by an AI agent were reviewed by a human.
