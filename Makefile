export GO111MODULE=on
export GOFLAGS=-mod=vendor

PROJECT = transtracer
PKG = github.com/yuuki/$(PROJECT)
COMMIT = $$(git describe --tags --always)
DATE = $$(date -u '+%Y-%m-%d_%H:%M:%S')
BUILD_LDFLAGS = -X $(PKG)/version.commit=$(COMMIT) -X $(PKG)/version.date=$(DATE)
CREDITS = ./assets/CREDITS

.PHONY: build
build: build-deps credits
	go generate ./...
	go build -ldflags="$(BUILD_LDFLAGS)" ./cmd/ttracerd/
	go build -ldflags="$(BUILD_LDFLAGS)" ./cmd/ttctl/

.PHONY: build-deps
build-deps: _build-deps tidy-module

.PHONY: _build-deps
_build-deps:
	go get github.com/rakyll/statik

.PHONY: tidy-module
tidy-module:
	go mod tidy
	go mod vendor

.PHONY: install
install:
	go install $(PKG)/cmd/...

.PHONY: test
test:
	go test -v ./...

.PHONY: devel-deps
devel-deps: _devel-deps tidy-module

.PHONY: _devel-deps
_devel-deps:
	go get \
        golang.org/x/tools/cmd/cover \
        github.com/mattn/goveralls \
        github.com/x-motemen/gobump/cmd/gobump \
        github.com/Songmu/ghch/cmd/ghch \
        github.com/Songmu/gocredits/cmd/gocredits

.PHONY: credits
credits:
	gocredits > $(CREDITS)
ifneq (,$(git status -s $(CREDITS)))
	go generate -x ./...
endif

.PHONY: lint
lint:
	golangci-lint run ./...

.PHONY: release
release: devel-deps
	_tools/release
