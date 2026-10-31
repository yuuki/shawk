VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -s -w -X github.com/yuuki/shawk/internal/version.Version=$(VERSION)
GO ?= go

.PHONY: all
all: build

.PHONY: generate
generate: ## compile the BPF programs (needs clang)
	$(GO) generate ./internal/tracer/

.PHONY: build
build:
	CGO_ENABLED=0 $(GO) build -trimpath -ldflags "$(LDFLAGS)" -o shawk ./cmd/shawk

.PHONY: vet
vet:
	$(GO) vet ./...
	cd collector && $(GO) vet ./...
	test -z "$$(gofmt -l cmd internal collector/shawkconnector collector/cmd)"

.PHONY: test
test: ## unit tests; BPF tests need root, PostgreSQL tests need SHAWK_TEST_POSTGRES_DSN
	$(GO) test ./...
	cd collector && $(GO) test ./...

OCB_VERSION ?= v0.164.0

.PHONY: collector
collector: ## build the collector with the shawk connector (collector/_build/shawk-collector)
	$(GO) install go.opentelemetry.io/collector/cmd/builder@$(OCB_VERSION)
	cd collector && $$($(GO) env GOPATH)/bin/builder --config builder-config.yaml

.PHONY: shawk-migrate
shawk-migrate: ## build the command that applies the PostgreSQL schema
	cd collector && CGO_ENABLED=0 $(GO) build -trimpath -o ../shawk-migrate ./cmd/shawk-migrate

.PHONY: test-root
test-root: ## tests that load the BPF programs into the running kernel
	$(GO) test -c -o tracer.test ./internal/tracer/
	sudo ./tracer.test -test.v -test.count=1
	rm -f tracer.test

.PHONY: e2e
e2e: build ## multi-host test with network namespaces
	sudo test/e2e/run.sh ./shawk

.PHONY: check-object
check-object: ## check that the committed BPF object matches the source
	scripts/check-bpf-object.sh

rocky9.btf:
	scripts/fetch-kernel-btf.sh "" $@

.PHONY: compat
compat: rocky9.btf ## check the BPF programs against the Rocky Linux 9 kernel
	SHAWK_TARGET_BTF=$(CURDIR)/rocky9.btf $(GO) test -run TestKernelCompatibility -v ./internal/tracer/

.PHONY: clean
clean:
	rm -rf shawk shawk-migrate tracer.test rocky9.btf collector/_build
