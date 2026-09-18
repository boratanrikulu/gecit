DARWIN_ARM64_CC ?= clang -arch arm64
DARWIN_AMD64_CC ?= clang -arch x86_64

.PHONY: all clean vet lint fmt gecit-linux-amd64 gecit-linux-arm64 gecit-darwin-arm64 gecit-darwin-amd64 gecit-windows-amd64 \
        bpf-all bpf-clean bpf-translate bpf-compile install-gobee install-nfpm \
        packages-linux tarball-darwin cask

all: gecit-linux-amd64 gecit-linux-arm64

# Stamped into the binary, reported by `gecit version`. The release workflow
# passes the tag with its leading v stripped; nfpm and the Homebrew cask need
# the same bare number, so every target reads this one variable.
VERSION ?= dev
LDFLAGS := -X github.com/boratanrikulu/gecit/cmd/gecit/app.version=$(VERSION)

# nfpm strips a leading v out of the metadata but the filename keeps it, so
# VERSION=v0.2.0 yields gecit_v0.2.0_... holding Version: 0.2.0. render.sh
# rejects the same shape for the same reason.
require-version = @case "$(VERSION)" in \
	dev|v*) echo "set VERSION without a leading v, for example: make $@ VERSION=0.2.0"; exit 1 ;; \
	esac

require-binary = @test -f "$(1)" || { echo "$(1) is missing, run: make $(2)"; exit 1; }

# Resolve gobee from $PATH first (the way a normal user gets it via
# `go install ...@latest`), then fall back to $GOBIN / $GOPATH/bin.
GOBIN := $(or $(shell go env GOBIN),$(shell go env GOPATH)/bin)
GOBEE := $(or $(shell command -v gobee 2>/dev/null),$(GOBIN)/gobee)

NFPM_VERSION ?= v2.47.0
NFPM := $(or $(shell command -v nfpm 2>/dev/null),$(GOBIN)/nfpm)

install-gobee:
	@command -v gobee >/dev/null 2>&1 || go install github.com/boratanrikulu/gobee/cmd/gobee@latest

install-nfpm:
	@command -v nfpm >/dev/null 2>&1 || go install github.com/goreleaser/nfpm/v2/cmd/nfpm@$(NFPM_VERSION)

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
	GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -ldflags "$(LDFLAGS)" -o bin/gecit-linux-amd64 ./cmd/gecit

gecit-linux-arm64: bpf-all
	GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build -ldflags "$(LDFLAGS)" -o bin/gecit-linux-arm64 ./cmd/gecit

gecit-darwin-arm64:
	GOOS=darwin GOARCH=arm64 CGO_ENABLED=1 CC="$(DARWIN_ARM64_CC)" \
		CGO_CFLAGS="-mmacosx-version-min=11.0" \
		CGO_LDFLAGS="-mmacosx-version-min=11.0" \
		go build -tags with_gvisor -ldflags "$(LDFLAGS)" -o bin/gecit-darwin-arm64 ./cmd/gecit

gecit-darwin-amd64:
	GOOS=darwin GOARCH=amd64 CGO_ENABLED=1 CC="$(DARWIN_AMD64_CC)" \
		CGO_CFLAGS="-mmacosx-version-min=11.0" \
		CGO_LDFLAGS="-mmacosx-version-min=11.0" \
		go build -tags with_gvisor -ldflags "$(LDFLAGS)" -o bin/gecit-darwin-amd64 ./cmd/gecit

# No cgo and no Npcap SDK. gopacket's Windows implementation has no cgo in it
# and resolves wpcap.dll at runtime, so linking against the SDK buys nothing
# and CGO_ENABLED=1 needs a toolchain that a cross-compile does not have.
# Npcap is still required on the machine that runs gecit.
gecit-windows-amd64:
	GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go build -tags with_gvisor -ldflags "$(LDFLAGS)" -o bin/gecit-windows-amd64.exe ./cmd/gecit

# Packages the binaries already in bin/ rather than building them, because that
# is what the release does: the packaging job downloads the matrix artifacts and
# never sees a compiler. nfpm itself has no cgo, so this runs on macOS too.
packages-linux: install-nfpm
	$(require-version)
	$(call require-binary,bin/gecit-linux-amd64,gecit-linux-amd64)
	$(call require-binary,bin/gecit-linux-arm64,gecit-linux-arm64)
	@mkdir -p dist
	@for arch in amd64 arm64; do \
		for format in deb rpm apk; do \
			VERSION="$(VERSION)" ARCH="$$arch" BINARY="bin/gecit-linux-$$arch" \
				$(NFPM) pkg -f packaging/linux/nfpm.yaml -p $$format \
					-t "dist/gecit_$(VERSION)_linux_$$arch.$$format" || exit 1; \
		done; \
	done

# The Homebrew cask needs an archive, not the bare binary the release also
# publishes, and it expects to find `gecit` at the root of it.
tarball-darwin:
	$(require-version)
	$(call require-binary,bin/gecit-darwin-amd64,gecit-darwin-amd64)
	$(call require-binary,bin/gecit-darwin-arm64,gecit-darwin-arm64)
	@mkdir -p dist
	@for arch in amd64 arm64; do \
		stage=$$(mktemp -d) || exit 1; \
		cp bin/gecit-darwin-$$arch "$$stage/gecit" && \
		cp LICENSE README.md "$$stage/" && \
		tar -czf "dist/gecit_$(VERSION)_darwin_$$arch.tar.gz" -C "$$stage" gecit LICENSE README.md || \
			{ rm -rf "$$stage"; exit 1; }; \
		rm -rf "$$stage"; \
	done

cask: tarball-darwin
	@packaging/homebrew/render.sh "$(VERSION)" \
		"dist/gecit_$(VERSION)_darwin_amd64.tar.gz" \
		"dist/gecit_$(VERSION)_darwin_arm64.tar.gz"

vet:
	go vet -tags with_gvisor ./...

lint:
	golangci-lint run ./...

fmt:
	gofmt -w .

clean: bpf-clean
	rm -rf bin/ dist/
