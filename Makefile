export GO111MODULE=on

PROJECT = transtracer
PKG = github.com/yuuki/$(PROJECT)
COMMIT = $$(git describe --tags --always)
DATE = $$(date --utc '+%Y-%m-%d_%H:%M:%S')
BUILD_LDFLAGS = -X $(PKG).commit=$(COMMIT) -X $(PKG).date=$(DATE)
CREDITS = ./assets/CREDITS

.PHONY: build
build:
	go generate ./...
	go build -ldflags="$(BUILD_LDFLAGS)" ./cmd/ttracerd/
	go build -ldflags="$(BUILD_LDFLAGS)" ./cmd/ttctl/

.PHONY: install
install:
	go install $(PKG)/cmd/...

.PHONY: test
test:
	go test -v ./...

.PHONY: devel-deps
devel-deps:
	GO111MODULE=off go get -v \
        golang.org/x/tools/cmd/cover \
        github.com/mattn/goveralls \
        github.com/motemen/gobump/cmd/gobump \
        github.com/Songmu/ghch/cmd/ghch \
        github.com/Songmu/goxz/cmd/goxz \
        github.com/tcnksm/ghr \
        github.com/Songmu/gocredits/cmd/gocredits

.PHONY: credits
credits: devel-deps
	gocredits > $(CREDITS)
ifneq (,$(git status -s $(CREDITS)))
	go generate -x ./...
endif

.PHONY: lint
lint:
	go vet ./...
	golint -set_exit_status ./...

.PHONY: check-deps
check-deps:
	GO111MODULE=off go get -v \
        honnef.co/go/tools/cmd/staticcheck \
		github.com/kisielk/errcheck \
		gitlab.com/opennota/check/cmd/aligncheck \
		gitlab.com/opennota/check/cmd/structcheck \
		gitlab.com/opennota/check/cmd/varcheck

.PHONY: check
check:
	errcheck -asserts -blank -ignoretests -ignoregenerated -ignore 'Close,Fprint' ./... || true
	staticcheck ./... || true
	aligncheck ./... || true
	structcheck ./... || true
	varcheck ./... || true
