//go:build linux && arm64

package bpf

import _ "embed"

//go:embed bin/arm64/sockops.bpf.o
var Program []byte
