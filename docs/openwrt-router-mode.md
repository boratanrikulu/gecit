# OpenWrt Router Mode Skeleton

This document tracks a router-wide mode for OpenWrt and similar Linux gateways. The current Linux path in gecit uses cgroup `sock_ops`, which works well for locally created sockets but does not naturally cover forwarded and NATed transit traffic. Router mode therefore needs a separate packet path built around netfilter and NFQUEUE.

## Goals

- Provide one-box DPI bypass for LAN clients behind an OpenWrt router.
- Keep the current fake-packet approach rather than turning gecit into a generic proxy or VPN.
- Start with TCP `443`, then add UDP `443` only after probe-backed validation.
- Reuse as much of the existing fake TLS and DNS logic as possible.

## Non-goals

- Replacing the current desktop and host-local Linux modes.
- Hiding source IPs or adding anonymity features.
- Claiming universal support for every OpenWrt target in the first version.
- Shipping QUIC desync before probe-driven strategy selection exists.

## Why this needs a separate mode

- `sock_ops` sees local sockets, not arbitrary forwarded flows.
- Router deployments must cooperate with conntrack, NAT, packet marks, and flow offload.
- OpenWrt targets are more fragmented than desktop Linux, so CO-RE and BTF assumptions are weaker.
- The right interception point for a gateway is nftables or iptables plus NFQUEUE, not a cgroup hook.

## Proposed package layout

- `pkg/router`: high-level router engine and shared config.
- `pkg/router/nfq`: NFQUEUE lifecycle, packet decode or encode, and nftables ownership.
- `pkg/router/mangle`: TCP or QUIC desync strategies that operate on queued packets.
- `pkg/router/probe`: blockcheck-style active probe that scores candidate strategies.
- `cmd/gecit/app/run_router.go`: future CLI entrypoint for router mode.
- `cmd/gecit/app/router_probe.go`: future CLI entrypoint for probe mode.

## Intended data path

1. nftables selects the first packets of matching `tcp/443` and `udp/443` flows on the router egress path.
2. Selected packets are queued to NFQUEUE with a stable queue number and bypass flag.
3. The router engine classifies protocol, direction, and candidate desync profile.
4. For TCP, gecit emits one or more fake packets before allowing the real handshake to continue.
5. Generated packets are marked to avoid requeue loops and NAT corruption.
6. When a probe has not yet confirmed a safe QUIC strategy, UDP `443` is passed through unchanged.
7. Start and stop paths install and remove nftables state atomically.

## Code scaffold in this fork

- `pkg/router/config.go` defines the future config surface.
- `pkg/router/engine.go` validates config and exposes dry-run ruleset rendering.
- `pkg/router/packet.go` and `pkg/router/processor.go` parse queued packets and decide when a fake should be injected once per flow.
- `pkg/router/nftables.go` renders nftables setup and teardown commands for an NFQUEUE path.
- `pkg/router/nfq/runner_linux.go` consumes NFQUEUE packets and reuses the existing raw socket sender for low-TTL fake packets.
- `pkg/router/probe/probe.go` and `pkg/router/probe/dryrun.go` define a small blockcheck-style dry-run workflow.
- `cmd/gecit/app/router_linux.go` wires experimental Linux commands for `router run`, `router plan`, and `router probe`.

## Detailed TODOs

### Phase 0: baseline and scope

- [ ] Confirm the minimal OpenWrt target matrix to support first: `x86_64`, `aarch64`, and a clear answer on `mips` or `mipsel`.
- [ ] Decide whether v1 is nftables-only or if legacy iptables compatibility is required.
- [ ] Decide whether router mode lives behind `gecit run --mode router` or a dedicated `gecit router run` command.
- [ ] Define a rollback contract so every nftables and sysctl change is reversible on failure.

### Phase 1: packet interception

- [ ] Implement nftables rule rendering for `postrouting` and `postnat` queue paths.
- [ ] Add packet marks for generated packets so the router never requeues its own synthetic traffic.
- [ ] Capture only the first packets of each flow to keep CPU cost bounded.
- [ ] Keep UDP disabled by default until probe results show a safe strategy on the current network.
- [ ] Add explicit detection and warnings for flow offload, hardware NAT, and fast path features.

### Phase 2: router engine

- [ ] Implement `pkg/router/nfq` around a maintained Go binding or a small local wrapper.
- [ ] Parse IPv4, IPv6, TCP, and UDP headers without depending on desktop-only assumptions.
- [ ] Reuse the existing fake TLS generation code instead of duplicating handshake logic.
- [ ] Add a per-flow state table with bounded lifetime and memory limits.
- [ ] Keep the engine fail-open so broken router mode does not blackhole household traffic.

### Phase 3: desync strategies

- [ ] Start with one conservative TCP strategy: fake ClientHello plus low TTL.
- [ ] Add profile selection so the fake SNI and handshake template are not static across every flow.
- [ ] Evaluate whether fragmentation or reordered sends are needed only after baseline TCP succeeds.
- [ ] Add a QUIC strategy interface, but leave all implementations probe-gated until validated.
- [ ] Keep strategy metrics so failed candidates can be disabled automatically.

### Phase 4: probe tool

- [ ] Implement a small `router probe` command that tests candidate strategies against configured targets.
- [ ] Produce a human-readable report that records the winning TCP and UDP strategy per network.
- [ ] Separate probe traffic from normal household traffic with marks and queue ownership.
- [ ] Persist probe results to a local config file so the router can boot into the last known good profile.
- [ ] Include a dry-run mode that prints nftables commands and selected targets without changing state.

### Phase 5: OpenWrt integration

- [ ] Add packaging notes for procd, UCI defaults, and firewall include files.
- [ ] Decide where config lives on OpenWrt and how secrets or probe history are stored.
- [ ] Detect missing kernel modules such as `nfnetlink_queue` and fail with a precise message.
- [ ] Keep binary size and dependency count low enough for flash-constrained devices.
- [ ] Document how users should exempt management traffic, local subnets, and DoH upstream endpoints.

### Phase 6: validation and hardening

- [ ] Build a test matrix covering DNS poisoning, SNI filtering, NATed LAN clients, and offload enabled or disabled cases.
- [ ] Add packet-loop regression tests so generated traffic cannot recurse into NFQUEUE.
- [ ] Add memory and queue-depth limits to protect weaker routers from sustained handshake storms.
- [ ] Add logging tiers that default to concise summaries and keep per-packet logs behind debug mode.
- [ ] Compare success rate and CPU cost against zapret-style NFQUEUE setups on the same links.

## External references

- Original feature request: https://github.com/boratanrikulu/gecit/issues/1
- zapret project: https://github.com/bol-van/zapret
- zapret nftables and NFQUEUE notes: https://github.com/bol-van/zapret/blob/master/docs/readme.en.md
- zapret quick start and blockcheck context: https://github.com/bol-van/zapret/blob/master/docs/quick_start.md
