.PHONY: all clean gecit-linux-amd64 gecit-linux-arm64 gecit-darwin-arm64 gecit-darwin-amd64 gecit-windows-amd64 \
        bpf-all bpf-clean bpf-translate bpf-compile install-gobee

all: gecit-linux-amd64 gecit-linux-arm64

# Resolve gobee from $PATH first (the way a normal user gets it via
# `go install ...@latest`), then fall back to $GOBIN / $GOPATH/bin.
GOBIN := $(or $(shell go env GOBIN),$(shell go env GOPATH)/bin)
GOBEE := $(or $(shell command -v gobee 2>/dev/null),$(GOBIN)/gobee)

install-gobee:
	@command -v gobee >/dev/null 2>&1 || go install github.com/boratanrikulu/gobee/cmd/gobee@latest

bpf-translate: install-gobee
	$(GOBEE) translate --bindings-dir ./pkg/ebpf/bpf ./pkg/ebpf/bpf/src

bpf-compile: bpf-translate
	$(MAKE) -C pkg/ebpf/bpf/src bpf-all

bpf-all: bpf-compile

bpf-clean:
	$(MAKE) -C pkg/ebpf/bpf/src bpf-clean
	@rm -f pkg/ebpf/bpf/src/sockops.bpf.c \
	       pkg/ebpf/bpf/src/sockops.bpf.c.map \
	       pkg/ebpf/bpf/sockops_bindings.go

gecit-linux-amd64: bpf-all
	GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -o bin/gecit-linux-amd64 ./cmd/gecit

gecit-linux-arm64: bpf-all
	GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build -o bin/gecit-linux-arm64 ./cmd/gecit

gecit-darwin-arm64:
	GOOS=darwin GOARCH=arm64 go build -tags with_gvisor -o bin/gecit-darwin-arm64 ./cmd/gecit

gecit-darwin-amd64:
	GOOS=darwin GOARCH=amd64 go build -tags with_gvisor -o bin/gecit-darwin-amd64 ./cmd/gecit

gecit-windows-amd64:
	GOOS=windows GOARCH=amd64 go build -tags with_gvisor -o bin/gecit-windows-amd64.exe ./cmd/gecit

lint:
	golangci-lint run ./...

fmt:
	gofmt -w .

clean: bpf-clean
	rm -rf bin/
