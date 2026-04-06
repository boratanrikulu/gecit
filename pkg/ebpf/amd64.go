//go:build linux && amd64

package ebpf

import _ "embed"

//go:embed bpf/bin/x86/sockops.bpf.o
var SockopsProgram []byte
