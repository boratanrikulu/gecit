//go:build ignore

// gecit BPF sock_ops program — DPI bypass via TCP MSS shrinking and
// userspace fake-ClientHello injection. Source-of-truth for the kernel
// side: gobee transpiles this to sockops.bpf.c, which clang compiles
// to sockops.bpf.o, which the userspace driver embeds and loads.
//
// Pipeline summary:
//   1. ACTIVE_ESTABLISHED_CB fires on a new outgoing TCP handshake.
//   2. If the destination matches our port set and isn't excluded,
//      shrink TCP_MAXSEG to force ClientHello fragmentation, then
//      emit a perf event so userspace can inject a fake ClientHello
//      with the correct seq/ack.
//   3. WRITE_HDR_OPT_CB fires for each outgoing TCP segment. Once the
//      ClientHello has been transmitted, restore normal MSS.

package main

import (
	"unsafe"

	"github.com/boratanrikulu/gobee/bpf"
)

//bpf:license GPL

// Config mirrors struct gecit_config_t. Layout must match the userspace
// view exactly (16 bytes: 2+2+4+1+7).
type Config struct {
	MSS               uint16
	RestoreMSS        uint16
	RestoreAfterBytes uint32
	Enabled           uint8
	Reserved          [7]uint8
}

// ConnEvent is the perf-event payload sent to userspace on each
// intercepted connection. Field order matches the userspace decoder.
type ConnEvent struct {
	SrcIP   uint32
	DstIP   uint32
	SrcPort uint16
	DstPort uint16
	Seq     uint32
	Ack     uint32
}

// ConnState is the per-connection state used to track bytes sent and
// gate MSS restoration.
type ConnState struct {
	BytesSent   uint32
	MssRestored uint8
	Reserved    [3]uint8
}

// IPPROTO_TCP = 6, TCP_MAXSEG = 2 (Linux UAPI).
const (
	ipprotoTCP int32 = 6
	tcpMaxSeg  int32 = 2
)

var ConfigMap = bpf.ArrayMap[uint32, Config]{MaxEntries: 1}
var TargetPorts = bpf.HashMap[uint16, uint8]{MaxEntries: 64}
var ExcludeIps = bpf.HashMap[uint32, uint8]{MaxEntries: 64}
var ConnEvents = bpf.PerfEventArray[ConnEvent]{}
var Connections = bpf.LruHashMap[uint64, ConnState]{MaxEntries: 65536}

func handleEstablished(ctx *bpf.SockOpsMd, cfg *Config) bpf.SockOpsReturn {
	var dstIP uint32 = ctx.RemoteIp4
	_, excluded := ExcludeIps.Lookup(&dstIP)
	if excluded {
		return bpf.SockOpsOk
	}

	var dstPort uint16 = uint16(bpf.Ntohl(ctx.RemotePort))
	_, isTarget := TargetPorts.Lookup(&dstPort)
	if !isTarget {
		return bpf.SockOpsOk
	}

	var mss int32 = int32(cfg.MSS)
	bpf.Setsockopt(unsafe.Pointer(ctx), ipprotoTCP, tcpMaxSeg, unsafe.Pointer(&mss), 4)

	var evt ConnEvent
	evt.SrcIP = ctx.LocalIp4
	evt.DstIP = ctx.RemoteIp4
	evt.SrcPort = uint16(ctx.LocalPort)
	evt.DstPort = dstPort
	evt.Seq = ctx.SndNxt
	evt.Ack = ctx.RcvNxt
	ConnEvents.Output(unsafe.Pointer(ctx), &evt)

	var cookie uint64 = bpf.GetSocketCookie(unsafe.Pointer(ctx))
	var state ConnState
	Connections.Update(&cookie, &state)

	var flags uint32 = ctx.BpfSockOpsCbFlags | bpf.BpfSockOpsWriteHdrOptCbFlag
	bpf.SockOpsCbFlagsSet(unsafe.Pointer(ctx), int32(flags))

	return bpf.SockOpsOk
}

func handleHdrOptLen(ctx *bpf.SockOpsMd) bpf.SockOpsReturn {
	bpf.ReserveHdrOpt(unsafe.Pointer(ctx), 0, 0)
	return bpf.SockOpsOk
}

func handleWriteHdrOpt(ctx *bpf.SockOpsMd, cfg *Config) bpf.SockOpsReturn {
	var cookie uint64 = bpf.GetSocketCookie(unsafe.Pointer(ctx))
	state, ok := Connections.Lookup(&cookie)
	if !ok {
		return bpf.SockOpsOk
	}
	if state.MssRestored != 0 {
		return bpf.SockOpsOk
	}

	state.BytesSent = state.BytesSent + ctx.SkbLen

	if state.BytesSent > cfg.RestoreAfterBytes {
		var normalMSS int32 = 1460
		if cfg.RestoreMSS != 0 {
			normalMSS = int32(cfg.RestoreMSS)
		}
		bpf.Setsockopt(unsafe.Pointer(ctx), ipprotoTCP, tcpMaxSeg, unsafe.Pointer(&normalMSS), 4)

		state.MssRestored = 1

		var flags uint32 = ctx.BpfSockOpsCbFlags & ^bpf.BpfSockOpsWriteHdrOptCbFlag
		bpf.SockOpsCbFlagsSet(unsafe.Pointer(ctx), int32(flags))

		Connections.Delete(&cookie)
	}

	return bpf.SockOpsOk
}

//bpf:section sockops
func GecitSockops(ctx *bpf.SockOpsMd) bpf.SockOpsReturn {
	var key uint32 = 0
	cfg, ok := ConfigMap.Lookup(&key)
	if !ok {
		return bpf.SockOpsOk
	}
	if cfg.Enabled == 0 {
		return bpf.SockOpsOk
	}

	var op uint32 = ctx.Op
	if op == bpf.BpfSockOpsActiveEstablishedCb {
		return handleEstablished(ctx, cfg)
	}
	if op == bpf.BpfSockOpsHdrOptLenCb {
		return handleHdrOptLen(ctx)
	}
	if op == bpf.BpfSockOpsWriteHdrOptCb {
		return handleWriteHdrOpt(ctx, cfg)
	}

	return bpf.SockOpsOk
}

func main() {}
