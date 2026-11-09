VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
# The version without the v of the tag (0.8.0), as in the release binaries,
# packages and collector built by goreleaser, also when given as v0.8.0.
override VERSION := $(patsubst v%,%,$(VERSION))
LDFLAGS := -s -w -X github.com/yuuki/shawk/internal/version.Version=$(VERSION)
GO ?= go

# The Go modules that build with Go alone, and test/hookcost, whose BPF
# bindings are generated with clang (go generate) and not committed: it is
# only kept tidy here.
MODULES := . collector test/packaging
ALL_MODULES := $(MODULES) test/hookcost

# Tool versions. CI pins the same versions (.github/workflows); bump together.
GOLANGCI_LINT_VERSION ?= v2.15.0
GOVULNCHECK_VERSION ?= v1.9.0
ACTIONLINT_VERSION ?= v1.7.12
ZIZMOR_VERSION ?= 1.32.0
GH_ACTIONS_LOCK_VERSION ?= v0.4.1
FUZZTIME ?= 30s
# New inputs of the corpus are minimized for at most this long, so that a
# short run spends its time fuzzing (the inputs of the connector are
# requests of kilobytes).
FUZZMINIMIZETIME ?= 10s
BENCH_COUNT ?= 6

# The tools that go run builds are built with the toolchain of go.mod: built
# with the older one of its own go.mod, golangci-lint refuses the modules.
GO_TOOLCHAIN = $(shell $(GO) env GOVERSION)
GO_RUN_TOOL = GOTOOLCHAIN=$(GO_TOOLCHAIN) $(GO) run
GOLANGCI_LINT ?= $(GO_RUN_TOOL) github.com/golangci/golangci-lint/v2/cmd/golangci-lint@$(GOLANGCI_LINT_VERSION)
# uvx or pipx (preinstalled on GitHub-hosted runners) runs the pinned zizmor.
ZIZMOR ?= $(if $(shell command -v uvx 2>/dev/null),uvx zizmor@$(ZIZMOR_VERSION),pipx run zizmor==$(ZIZMOR_VERSION))
# gh-actions-lock (the `gh actions-lock` extension) runs through `go run` too.
GH_ACTIONS_LOCK ?= $(GO_RUN_TOOL) github.com/github/gh-actions-lock/cmd/gh-actions-lock@$(GH_ACTIONS_LOCK_VERSION)

.PHONY: all
all: build

.PHONY: generate
generate: ## compile the BPF programs (needs clang)
	$(GO) generate ./internal/tracer/

.PHONY: vmlinux
vmlinux: ## regenerate the kernel types the BPF programs include from the running kernel (needs bpftool)
	scripts/gen-vmlinux.sh

.PHONY: build
build:
	CGO_ENABLED=0 $(GO) build -trimpath -ldflags "$(LDFLAGS)" -o shawk ./cmd/shawk

.PHONY: vet
vet:
	$(GO) vet ./...
	cd collector && $(GO) vet ./...
	cd test/packaging && $(GO) vet ./...
	test -z "$$(gofmt -l cmd internal collector/shawkconnector collector/cmd test/packaging test/vm test/hookcost test/harness test/nodeload)"

.PHONY: test
test: ## unit tests; BPF tests need root, PostgreSQL tests need SHAWK_TEST_POSTGRES_DSN
	$(GO) test ./...
	cd collector && $(GO) test ./...
	cd test/packaging && $(GO) test ./...

.PHONY: test-race
test-race: ## the tests of make test with the race detector
	$(GO) test -race ./...
	cd collector && $(GO) test -race ./...
	cd test/packaging && $(GO) test -race ./...

.PHONY: check
check: lint lint-actions test-race ## the checks to pass before a pull request; needs no PostgreSQL, VM or root (as root, test-race also loads the BPF programs)

.PHONY: lint
lint: ## golangci-lint (.golangci.yml) in every module, and go.mod and go.sum tidy
	@set -e; for m in $(MODULES); do echo "== golangci-lint $$m"; (cd $$m && $(GOLANGCI_LINT) run ./...); done
	@set -e; for m in $(ALL_MODULES); do echo "== go mod tidy -diff $$m"; (cd $$m && $(GO) mod tidy -diff); done

.PHONY: fmt
fmt: ## format the Go code of every module (gofmt, through golangci-lint)
	@set -e; for m in $(MODULES); do (cd $$m && $(GOLANGCI_LINT) fmt ./...); done

# gh-actions-lock checks that .github/workflows/actions.lock pins every
# action the workflows use; with GH_TOKEN it also verifies each pin upstream.
.PHONY: lint-actions
lint-actions: ## lint (actionlint) and audit (zizmor) the workflows of .github, and check their lockfile
	$(GO_RUN_TOOL) github.com/rhysd/actionlint/cmd/actionlint@$(ACTIONLINT_VERSION)
	$(ZIZMOR) $(if $(GH_TOKEN),,--offline) .
	$(GH_ACTIONS_LOCK) $(if $(GH_TOKEN),--verify,--verify-local)

# Pin the actions in .github/workflows/actions.lock after a `uses:` changed,
# then review the diff. Needs a GitHub token (GH_TOKEN or `gh auth login`).
.PHONY: lock-actions
lock-actions: ## Update .github/workflows/actions.lock after changing a uses: line
	$(GH_ACTIONS_LOCK)

.PHONY: test-fuzz
test-fuzz: ## run every fuzz target for FUZZTIME (default 30s)
	@set -e; for m in $(MODULES); do \
		for pkg in $$(cd $$m && $(GO) list ./...); do \
			list=$$(cd $$m && $(GO) test -list '^Fuzz' $$pkg); \
			for f in $$(printf '%s\n' "$$list" | grep '^Fuzz' || true); do \
				echo "== $$pkg $$f"; \
				(cd $$m && $(GO) test -run='^$$' -fuzz="^$$f\$$" -fuzztime=$(FUZZTIME) -fuzzminimizetime=$(FUZZMINIMIZETIME) $$pkg); \
			done; \
		done; \
	done

.PHONY: bench
bench: ## benchmarks, written to bench.txt for benchstat (BENCH_COUNT runs of each)
	@set -e; : > bench.txt; for m in $(MODULES); do \
		(cd $$m && $(GO) test -run='^$$' -bench=. -benchmem -count=$(BENCH_COUNT) ./... >> $(CURDIR)/bench.txt) || { cat bench.txt; exit 1; }; \
	done; cat bench.txt

.PHONY: vuln
vuln: ## known vulnerabilities that the code of every module reaches (govulncheck)
	@set -e; for m in $(MODULES); do echo "== govulncheck $$m"; (cd $$m && $(GO_RUN_TOOL) golang.org/x/vuln/cmd/govulncheck@$(GOVULNCHECK_VERSION) ./...); done

.PHONY: complexity
complexity: ## rank the most complex functions with cccc (https://github.com/moznion/cccc); settings in cccc.toml
	cccc --table --top-cognitive 20 .

OCB_VERSION ?= v0.164.0

.PHONY: collector
collector: ## build the collector with the shawk connector and VERSION (collector/_build/shawk-collector)
	OCB_VERSION=$(OCB_VERSION) sh scripts/generate-collector.sh $(VERSION)
	cd collector/_build && CGO_ENABLED=0 $(GO) build -trimpath -ldflags "-s -w" -o shawk-collector .

.PHONY: shawk-migrate
shawk-migrate: ## build the command that applies the PostgreSQL schema
	cd collector && CGO_ENABLED=0 $(GO) build -trimpath -o ../shawk-migrate ./cmd/shawk-migrate

.PHONY: test-root
test-root: ## tests that load the BPF programs into the running kernel
	$(GO) test -c -o tracer.test ./internal/tracer/
	sudo --preserve-env=SHAWK_TEST_STRICT,SHAWK_TEST_NO_UDP,SHAWK_TEST_NO_TRAMPOLINES,SHAWK_TEST_NO_NFS ./tracer.test -test.v -test.count=1 -test.timeout=10m
	rm -f tracer.test

.PHONY: test-integration
test-integration: test-root pg-test ## the tests make test skips: those that load the BPF programs (root) and those of PostgreSQL (pg-up)

KERNEL ?= rocky9
ARCH ?= $(shell uname -m)

.PHONY: vm-test
vm-test: ## the tests of test-root in a virtual machine with KERNEL (rocky9, 5.14, 5.15) for ARCH (x86_64, aarch64)
	test/vm/run.sh $(KERNEL) $(ARCH)

# The environments of test/harness (see test/harness/README.md), per
# workspace: a disposable PostgreSQL on the host and a Slurm cluster in a VM.
.PHONY: pg-up
pg-up: ## start a disposable PostgreSQL for this workspace and print its DSNs
	test/harness/postgres.sh up

.PHONY: pg-test
pg-test: pg-up ## the tests of the connector, which use PostgreSQL, against that of pg-up
	test/harness/postgres.sh run sh -c 'cd collector && $(GO) test ./...'

.PHONY: pg-down
pg-down: ## stop the PostgreSQL of pg-up and delete its data
	test/harness/postgres.sh down

.PHONY: slurm-up
slurm-up: ## a Slurm cluster in a VM of Lima: SLURM_VERSION, SLURM_CGROUP_JOB_ID_PATHS, SLURM_SRUN_PORT_RANGE, ...
	test/harness/slurm.sh up

.PHONY: slurm-check
slurm-check: ## run jobs on the cluster of slurm-up and check the units of their processes
	test/harness/slurm.sh check

.PHONY: slurm-down
slurm-down: ## delete the VM of slurm-up
	test/harness/slurm.sh down

.PHONY: e2e
e2e: build collector ## multi-host test with network namespaces; needs SHAWK_E2E_POSTGRES_DSN
	sudo --preserve-env=SHAWK_E2E_POSTGRES_DSN,SHAWK_TEST_STRICT test/e2e/run.sh ./shawk collector/_build/shawk-collector

.PHONY: check-object
check-object: ## check that the committed BPF object matches the source
	scripts/check-bpf-object.sh

# The kernel RPM is cached in build/kernel and checked against its SHA-256.
rocky9.btf:
	scripts/fetch-kernel-btf.sh "" $@

# The module of the programs that learn translations (conntrack).
rocky9-nf_conntrack.btf:
	scripts/fetch-module-btf.sh net/netfilter/nf_conntrack "" $@

.PHONY: compat
compat: rocky9.btf rocky9-nf_conntrack.btf ## check the BPF programs against the Rocky Linux 9 kernel
	SHAWK_TARGET_BTF=$(CURDIR)/rocky9.btf SHAWK_TARGET_MODULE_BTF=$(CURDIR)/rocky9-nf_conntrack.btf \
		$(GO) test -run TestKernelCompatibility -v ./internal/tracer/

# build/harness holds the state of the environments of test/harness, which
# may run, also when this runs in the VM of slurm-up that mounts build:
# pg-down and slurm-down remove it.
.PHONY: clean
clean:
	rm -rf shawk shawk-migrate tracer.test bench.txt rocky9.btf rocky9-nf_conntrack.btf collector/_build \
		$(filter-out build/harness,$(wildcard build/*))
