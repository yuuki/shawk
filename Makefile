export GO111MODULE=on
export GOFLAGS=-mod=vendor

PROJECT = transtracer
PKG = github.com/yuuki/$(PROJECT)
COMMIT = $$(git describe --tags --always)
DATE = $$(date -u '+%Y-%m-%d_%H:%M:%S')
BUILD_LDFLAGS = -X $(PKG)/version.commit=$(COMMIT) -X $(PKG)/version.date=$(DATE)
CREDITS = ./assets/CREDITS

.PHONY: build
build: build-deps tidy-module credits
	go generate ./...
	go build -ldflags="$(BUILD_LDFLAGS)" ./cmd/ttracerd/
	go build -ldflags="$(BUILD_LDFLAGS)" ./cmd/ttctl/

.PHONY: build-deps
build-deps:
	go get github.com/rakyll/statik
	go mod tidy

.PHONY: tidy-module
tidy-module:
	go mod tidy
	go mod vendor

.PHONY: install
install:
	go install $(PKG)/cmd/...

.PHONY: test
test: tidy-module
	go test -v ./...

.PHONY: devel-deps
devel-deps:
	go get \
        golang.org/x/tools/cmd/cover \
        github.com/mattn/goveralls \
        github.com/motemen/gobump/cmd/gobump \
        github.com/Songmu/ghch/cmd/ghch
	go mod tidy

.PHONY: credits
credits:
	gocredits > $(CREDITS)
ifneq (,$(git status -s $(CREDITS)))
	go generate -x ./...
endif

.PHONY: lint
lint:
	golangci-lint run ./...

.PHONY: check-deps
check-deps:
	go get \
        honnef.co/go/tools/cmd/staticcheck \
		github.com/kisielk/errcheck \
		gitlab.com/opennota/check/cmd/aligncheck \
		gitlab.com/opennota/check/cmd/structcheck \
		gitlab.com/opennota/check/cmd/varcheck
	go mod tidy

.PHONY: check
check: check-deps
	errcheck -asserts -blank -ignoretests -ignoregenerated -ignore 'Close,Fprint' ./... || true
	staticcheck ./... || true
	aligncheck ./... || true
	structcheck ./... || true
	varcheck ./... || true

.PHONY: release
release: devel-deps
	_tools/release
