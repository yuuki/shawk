export GO111MODULE=on

PROJECT = transtracer
PKG = github.com/yuuki/$(PROJECT)
COMMIT = $$(git describe --tags --always)
DATE = $$(date --utc '+%Y-%m-%d_%H:%M:%S')
BUILD_LDFLAGS = -X $(PKG).commit=$(COMMIT) -X $(PKG).date=$(DATE)
CREDITS = ./CREDITS

.PHONY: build
build: deps
	go generate ./...
	go build -ldflags="$(BUILD_LDFLAGS)" ./cmd/ttracerd/

.PHONY: install
install:
	go install $(PKG)/cmd/...

.PHONY: test
test:
	go test -v ./...

.PHONY: deps
deps:
	GO111MODULE=off go get -v github.com/go-bindata/go-bindata/...

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
	GO111MODULE=off go get -v \
		github.com/go-bindata/go-bindata/...
	gocredits -w .
ifneq (,$(git status -s $(CREDITS)))
	go generate -x ./...
endif
