export GO111MODULE=on
export GOOS=linux

PROJECT = shawk
PKG = github.com/yuuki/$(PROJECT)
COMMIT = $$(git describe --tags --always)
DATE = $$(date -u '+%Y-%m-%d_%H:%M:%S')
BUILD_LDFLAGS = -X $(PKG)/version.commit=$(COMMIT) -X $(PKG)/version.date=$(DATE)
CREDITS = ./assets/CREDITS

GOLINT = $$(go env GOPATH)/bin/golint -set_exit_status $$(go list -mod=vendor ./...)
GOTEST = go test -v ./...

DOCKER_IMAGE_NAME="shawk-test"
DOCKER_CONTAINER_NAME="shawk-test-container"
DOCKER = docker run --rm -v $$(PWD):/go/src/github.com/yuuki/shawk --name $(DOCKER_CONTAINER_NAME) $(DOCKER_IMAGE_NAME)
container = docker ps -a -q -f "name=$(DOCKER_CONTAINER_NAME)"

all: init build

.PHONY: clean
clean:
	@if [ "$(container || true)" != "" ] ; then \
		docker rm -f $(DOCKER_CONTAINER_NAME) 2>/dev/null; \
	fi

.PHONY: build
build: clean
	go generate ./...
	$(DOCKER) go build -ldflags="$(BUILD_LDFLAGS)" ./cmd/ttracerd/
	$(DOCKER) go build -ldflags="$(BUILD_LDFLAGS)" ./cmd/ttctl/
	go mod tidy

.PHONY: install
install:
	go install $(PKG)/cmd/...

.PHONY: test
test:
	$(DOCKER) $(GOTEST)
	go mod tidy

.PHONY: ci-test
ci-test:
	$(GOTEST)

.PHONY: lint
lint:
	# golangci-lint run ./... error: failed prerequisites:
	$(DOCKER) $(GOLINT)

.PHONY: ci-lint
ci-lint:
	$(GOLINT)

.PHONY: credits
credits: deps
	gocredits > $(CREDITS)
ifneq (,$(git status -s $(CREDITS)))
	go generate -x ./...
endif

.PHONY: release
release: credits
	_tools/release

init: deps docker-build

.PHONY: deps
deps:
	sh -c '\
		tmpdir=$$(mktemp -d); \
		cd $$tmpdir; \
		go get -u \
			github.com/rakyll/statik \
			golang.org/x/lint/golint \
			github.com/x-motemen/gobump/cmd/gobump \
			github.com/Songmu/ghch/cmd/ghch \
			github.com/Songmu/gocredits/cmd/gocredits; \
		rm -rf $$tmpdir'

.PHONY: docker-build
docker-build:
	docker build -t $(DOCKER_IMAGE_NAME) .
