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
	test -z "$$(gofmt -l .)"

.PHONY: test
test: ## unit tests; tests that load BPF programs are skipped without root
	$(GO) test ./...

.PHONY: test-root
test-root: ## tests that load the BPF programs into the running kernel
	$(GO) test -c -o tracer.test ./internal/tracer/
	sudo ./tracer.test -test.v -test.count=1
	rm -f tracer.test

.PHONY: e2e
e2e: build ## multi-host test with network namespaces
	sudo test/e2e/run.sh ./shawk

rocky9.btf:
	scripts/fetch-kernel-btf.sh "" $@

.PHONY: compat
compat: rocky9.btf ## check the BPF programs against the Rocky Linux 9 kernel
	SHAWK_TARGET_BTF=$(CURDIR)/rocky9.btf $(GO) test -run TestKernelCompatibility -v ./internal/tracer/

.PHONY: clean
clean:
	rm -f shawk tracer.test rocky9.btf
