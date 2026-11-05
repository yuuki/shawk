VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
# The version without the v of the tag (0.8.0), as in the release binaries,
# packages and collector built by goreleaser, also when given as v0.8.0.
override VERSION := $(patsubst v%,%,$(VERSION))
LDFLAGS := -s -w -X github.com/yuuki/shawk/internal/version.Version=$(VERSION)
GO ?= go

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
	sudo --preserve-env=SHAWK_TEST_STRICT,SHAWK_TEST_NO_UDP,SHAWK_TEST_NO_NFS ./tracer.test -test.v -test.count=1 -test.timeout=10m
	rm -f tracer.test

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
	rm -rf shawk shawk-migrate tracer.test rocky9.btf rocky9-nf_conntrack.btf collector/_build \
		$(filter-out build/harness,$(wildcard build/*))
