//go:build linux

package ebpf

import (
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/features"
)

// HaveSockOps checks if sock_ops programs are supported.
func HaveSockOps() bool {
	return features.HaveProgramType(ebpf.SockOps) == nil
}

// HaveSockOpsSetsockopt checks if bpf_setsockopt is available in sock_ops
// programs. This is the core helper we need for TCP_MAXSEG manipulation.
func HaveSockOpsSetsockopt() bool {
	return features.HaveProgramHelper(ebpf.SockOps, asm.FnSetsockopt) == nil
}
