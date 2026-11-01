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
	test -z "$$(gofmt -l cmd internal collector/shawkconnector collector/cmd test/packaging test/vm)"

.PHONY: test
test: ## unit tests; BPF tests need root, PostgreSQL tests need SHAWK_TEST_POSTGRES_DSN
	$(GO) test ./...
	cd collector && $(GO) test ./...
	cd test/packaging && $(GO) test ./...

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
	sudo --preserve-env=SHAWK_TEST_STRICT ./tracer.test -test.v -test.count=1
	rm -f tracer.test

KERNEL ?= rocky9
ARCH ?= $(shell uname -m)

.PHONY: vm-test
vm-test: ## the tests of test-root in a virtual machine with KERNEL (rocky9, 5.14, 5.15) for ARCH (x86_64, aarch64)
	test/vm/run.sh $(KERNEL) $(ARCH)

.PHONY: e2e
e2e: build collector ## multi-host test with network namespaces; needs SHAWK_E2E_POSTGRES_DSN
	sudo --preserve-env=SHAWK_E2E_POSTGRES_DSN test/e2e/run.sh ./shawk collector/_build/shawk-collector

.PHONY: check-object
check-object: ## check that the committed BPF object matches the source
	scripts/check-bpf-object.sh

# The kernel RPM is cached in build/kernel and checked against its SHA-256.
rocky9.btf:
	scripts/fetch-kernel-btf.sh "" $@

.PHONY: compat
compat: rocky9.btf ## check the BPF programs against the Rocky Linux 9 kernel
	SHAWK_TARGET_BTF=$(CURDIR)/rocky9.btf $(GO) test -run TestKernelCompatibility -v ./internal/tracer/

.PHONY: clean
clean:
	rm -rf shawk shawk-migrate tracer.test rocky9.btf build collector/_build
