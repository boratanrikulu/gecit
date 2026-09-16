DARWIN_ARM64_CC ?= clang -arch arm64
DARWIN_AMD64_CC ?= clang -arch x86_64

.PHONY: all clean vet lint fmt gecit-linux-amd64 gecit-linux-arm64 gecit-darwin-arm64 gecit-darwin-amd64 gecit-windows-amd64 \
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
	GOOS=darwin GOARCH=arm64 CGO_ENABLED=1 CC="$(DARWIN_ARM64_CC)" \
		CGO_CFLAGS="-mmacosx-version-min=11.0" \
		CGO_LDFLAGS="-mmacosx-version-min=11.0" \
		go build -tags with_gvisor -o bin/gecit-darwin-arm64 ./cmd/gecit

gecit-darwin-amd64:
	GOOS=darwin GOARCH=amd64 CGO_ENABLED=1 CC="$(DARWIN_AMD64_CC)" \
		CGO_CFLAGS="-mmacosx-version-min=11.0" \
		CGO_LDFLAGS="-mmacosx-version-min=11.0" \
		go build -tags with_gvisor -o bin/gecit-darwin-amd64 ./cmd/gecit

# No cgo and no Npcap SDK. gopacket's Windows implementation has no cgo in it
# and resolves wpcap.dll at runtime, so linking against the SDK buys nothing
# and CGO_ENABLED=1 needs a toolchain that a cross-compile does not have.
# Npcap is still required on the machine that runs gecit.
gecit-windows-amd64:
	GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go build -tags with_gvisor -o bin/gecit-windows-amd64.exe ./cmd/gecit

vet:
	go vet -tags with_gvisor ./...

lint:
	golangci-lint run ./...

fmt:
	gofmt -w .

clean: bpf-clean
	rm -rf bin/
