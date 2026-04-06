//go:build linux && arm64

package ebpf

import _ "embed"

//go:embed bpf/bin/arm64/sockops.bpf.o
var SockopsProgram []byte
