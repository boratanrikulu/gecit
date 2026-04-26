#pragma once

#include <bpf/bpf_helpers.h>

// gecit_config_t must match gecitConfig in Go exactly.
// Pushed from userspace at startup and on runtime config changes.
struct gecit_config_t {
	__u16 mss;                // small MSS to force fragmentation (default: 40)
	__u16 restore_mss;        // normal MSS to restore after handshake (default: 0 = auto)
	__u32 restore_after_bytes; // restore normal MSS after this many bytes sent
	__u8  enabled;            // master switch: 0 = passthrough, 1 = active
	__u8  reserved[7];
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct gecit_config_t);
} gecit_config SEC(".maps");

// Target destination ports to intercept (e.g., 443 for HTTPS).
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 64);
	__type(key, __u16);
	__type(value, __u8);
} target_ports SEC(".maps");

// Destination IPs to exclude from fake injection (e.g. DoH upstreams).
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 64);
	__type(key, __u32);   // IPv4 address in network byte order
	__type(value, __u8);
} exclude_ips SEC(".maps");

// Perf event array for notifying userspace of new connections.
struct conn_event {
	__u32 src_ip;
	__u32 dst_ip;
	__u16 src_port;
	__u16 dst_port;
	__u32 seq;       // snd_nxt — TCP seq the real ClientHello will use
	__u32 ack;       // rcv_nxt — correct ACK number for this connection
};

struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
	__uint(key_size, sizeof(__u32));
	__uint(value_size, sizeof(__u32));
} conn_events SEC(".maps");

// Per-connection state for tracking bytes sent and MSS restoration.
struct conn_state {
	__u32 bytes_sent;
	__u8  mss_restored;
	__u8  reserved[3];
};

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 65536);
	__type(key, __u64);
	__type(value, struct conn_state);
} connections SEC(".maps");

struct gecit_stats_t {
	__u64 mss_set_failures;
	__u64 mss_restore_failures;
	__s32 last_mss_set_error;
	__s32 last_mss_restore_error;
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct gecit_stats_t);
} gecit_stats SEC(".maps");
