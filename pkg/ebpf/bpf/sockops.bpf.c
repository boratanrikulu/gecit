// gecit — eBPF sock_ops program for DPI bypass.
//
// Attaches to cgroup v2 and intercepts outgoing TCP connections to target ports
// (default: 443). On connection establishment:
//   1. Notifies userspace via perf event (for fake ClientHello injection)
//   2. Sets a small TCP_MAXSEG for ClientHello fragmentation
//   3. Restores normal MSS after the handshake completes
//
// CO-RE: compiles against vmlinux headers for kernel portability.
// Kernel requirement: 5.10+ for BPF_SOCK_OPS_WRITE_HDR_OPT_CB (MSS restoration).

#if defined(__TARGET_ARCH_x86)
#include "../../../vmlinux/x86.h"
#elif defined(__TARGET_ARCH_arm64)
#include "../../../vmlinux/arm.h"
#endif

#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

#ifndef IPPROTO_TCP
#define IPPROTO_TCP 6
#endif
#ifndef TCP_MAXSEG
#define TCP_MAXSEG 2
#endif
#ifndef AF_INET
#define AF_INET 2
#endif

#include "maps.h"

static __always_inline int is_target_flow(struct bpf_sock_ops *skops)
{
	if (skops->family != AF_INET)
		return 0;

	__u32 dst_ip = skops->remote_ip4;
	if (bpf_map_lookup_elem(&exclude_ips, &dst_ip))
		return 0;

	__u16 dst_port = (__u16)bpf_ntohl(skops->remote_port);
	if (!bpf_map_lookup_elem(&target_ports, &dst_port))
		return 0;

	return 1;
}

static __always_inline void record_mss_error(int err, int restore)
{
	if (err >= 0)
		return;

	__u32 key = 0;
	struct gecit_stats_t *stats = bpf_map_lookup_elem(&gecit_stats, &key);
	if (!stats)
		return;

	if (restore) {
		__sync_fetch_and_add(&stats->mss_restore_failures, 1);
		stats->last_mss_restore_error = err;
	} else {
		__sync_fetch_and_add(&stats->mss_set_failures, 1);
		stats->last_mss_set_error = err;
	}
}

static __always_inline int set_small_mss(struct bpf_sock_ops *skops,
                                         struct gecit_config_t *cfg)
{
	int mss = cfg->mss;
	int ret = bpf_setsockopt(skops, IPPROTO_TCP, TCP_MAXSEG, &mss, sizeof(mss));
	record_mss_error(ret, 0);
	return ret;
}

// handle_established is called when an outgoing TCP connection completes the
// handshake. If the destination port is in the target_ports map, notify
// userspace and set a small MSS to force ClientHello fragmentation.
static __always_inline int handle_established(struct bpf_sock_ops *skops,
                                              struct gecit_config_t *cfg)
{
	if (!is_target_flow(skops))
		return 1;

	// Set small MSS — kernel will fragment outgoing data into tiny segments.
	set_small_mss(skops, cfg);

	// Notify userspace via perf event for fake ClientHello injection.
	struct conn_event evt = {};
	evt.src_ip   = skops->local_ip4;
	evt.dst_ip   = skops->remote_ip4;
	evt.src_port = skops->local_port;
	evt.dst_port = (__u16)bpf_ntohl(skops->remote_port);
	evt.seq      = skops->snd_nxt;
	evt.ack      = skops->rcv_nxt;
	bpf_perf_event_output(skops, &conn_events, BPF_F_CURRENT_CPU,
			      &evt, sizeof(evt));

	// Track this connection for MSS restoration after the handshake.
	__u64 cookie = bpf_get_socket_cookie(skops);
	struct conn_state state = {};
	bpf_map_update_elem(&connections, &cookie, &state, BPF_ANY);

	// Enable the WRITE_HDR_OPT callback for byte counting + MSS restoration.
	bpf_sock_ops_cb_flags_set(skops,
		skops->bpf_sock_ops_cb_flags |
		BPF_SOCK_OPS_WRITE_HDR_OPT_CB_FLAG);

	return 1;
}

static __always_inline int handle_connect(struct bpf_sock_ops *skops,
                                          struct gecit_config_t *cfg)
{
	if (!is_target_flow(skops))
		return 1;

	set_small_mss(skops, cfg);
	return 1;
}

static __always_inline int handle_hdr_opt_len(struct bpf_sock_ops *skops)
{
	bpf_reserve_hdr_opt(skops, 0, 0);
	return 1;
}

// handle_write_hdr_opt fires for each outgoing TCP segment. Count bytes sent
// and restore normal MSS once the ClientHello has been fully transmitted.
static __always_inline int handle_write_hdr_opt(struct bpf_sock_ops *skops,
                                                struct gecit_config_t *cfg)
{
	__u64 cookie = bpf_get_socket_cookie(skops);
	struct conn_state *state = bpf_map_lookup_elem(&connections, &cookie);
	if (!state || state->mss_restored)
		return 1;

	state->bytes_sent += skops->skb_len;

	if (state->bytes_sent > cfg->restore_after_bytes) {
		int normal_mss = cfg->restore_mss ? cfg->restore_mss : 1460;
		int ret = bpf_setsockopt(skops, IPPROTO_TCP, TCP_MAXSEG,
					 &normal_mss, sizeof(normal_mss));
		record_mss_error(ret, 1);

		state->mss_restored = 1;

		bpf_sock_ops_cb_flags_set(skops,
			skops->bpf_sock_ops_cb_flags &
			~BPF_SOCK_OPS_WRITE_HDR_OPT_CB_FLAG);

		bpf_map_delete_elem(&connections, &cookie);
	}

	return 1;
}

SEC("sockops")
int gecit_sockops(struct bpf_sock_ops *skops)
{
	__u32 key = 0;
	struct gecit_config_t *cfg = bpf_map_lookup_elem(&gecit_config, &key);
	if (!cfg || !cfg->enabled)
		return 1;

	switch (skops->op) {
	case BPF_SOCK_OPS_TCP_CONNECT_CB:
		return handle_connect(skops, cfg);
	case BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB:
		return handle_established(skops, cfg);
	case BPF_SOCK_OPS_HDR_OPT_LEN_CB:
		return handle_hdr_opt_len(skops);
	case BPF_SOCK_OPS_WRITE_HDR_OPT_CB:
		return handle_write_hdr_opt(skops, cfg);
	}

	return 1;
}

char LICENSE[] SEC("license") = "GPL";
