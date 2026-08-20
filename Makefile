BINARY  := global-egress
PKG     := ./cmd/global-egress
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -X main.version=$(VERSION)

# Local development config; ignored by git.
LOCAL_CONFIG ?= config.local.toml

GOBIN := $(shell go env GOPATH)/bin
GOFILES := $(shell find cmd internal -name '*.go')

IMAGE   ?= global-egress
# Override for a registry path, e.g. ghcr.io/minpeter/global-egress.
DOCKER_IMAGE ?= $(IMAGE)

.PHONY: all build build-static install test race vet fmt fmtcheck lint vulncheck tools tidy outdated check run probe inspect relays clean docker docker-run

all: check build

build:
	CGO_ENABLED=0 go build -trimpath -ldflags "$(LDFLAGS)" -o bin/$(BINARY) $(PKG)

# Static build for copying into a container or LXC guest.
build-static:
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath \
		-ldflags "$(LDFLAGS) -s -w" -o dist/$(BINARY)-linux-amd64 $(PKG)

# Local image; multi-arch publish happens in .github/workflows/release.yaml.
docker:
	docker build \
		--build-arg VERSION=$(VERSION) \
		-t $(DOCKER_IMAGE):$(VERSION) \
		-t $(DOCKER_IMAGE):latest \
		.

docker-run: docker
	docker run --rm $(DOCKER_IMAGE):$(VERSION) version

install: build
	install -m 0755 bin/$(BINARY) /usr/local/bin/$(BINARY)

test:
	go test ./...

race:
	go test -race ./...

vet:
	go vet ./...

# Formatting runs through golangci-lint, which has gofumpt and goimports
# configured as formatters in .golangci.yaml. One binary and one config means CI
# and local runs cannot disagree.
fmt: tools
	$(GOBIN)/golangci-lint fmt ./...

fmtcheck: tools
	$(GOBIN)/golangci-lint fmt --diff ./...

lint: tools
	$(GOBIN)/golangci-lint run ./...

vulncheck:
	go run golang.org/x/vuln/cmd/govulncheck@latest ./...

# Pinned to the version CI uses.
tools:
	@command -v $(GOBIN)/golangci-lint >/dev/null || \
		go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@v2.12.2

tidy:
	go mod tidy

# `go list -m -u all` walks gvisor's whole module graph (containerd, k8s, grpc)
# and drowns the handful of modules we actually build against, so list only those.
outdated:
	@go list -m -u $$(go list -deps ./... | xargs go list -f '{{if .Module}}{{.Module.Path}}{{end}}' | sort -u | grep -vE "^$$|^$$(go list -m)$$") 2>/dev/null | grep '\[' || echo "all build dependencies are current"

check: fmtcheck vet lint test

run: build
	./bin/$(BINARY) serve -config $(LOCAL_CONFIG)

inspect: build
	./bin/$(BINARY) inspect -catalog $(CATALOG)

relays: build
	./bin/$(BINARY) relays -cache .local-state/relays.json

probe: build
	./bin/$(BINARY) probe -catalog $(CATALOG) -limit $(or $(LIMIT),25) -concurrency $(or $(CONCURRENCY),8)

clean:
	rm -rf bin dist
