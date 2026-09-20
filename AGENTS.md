# AGENTS.md

Notes for agents working in this repo. Facts here were verified against the
code, not assumed. If you verify something non-obvious, add it.

## What gecit is

DPI bypass. Injects fake TLS ClientHello packets with a low TTL so a
middlebox sees them and the real server does not. Bundles a DoH resolver to
sidestep DNS poisoning. One binary, one command, and defaults that work with
no config file.

## Layout

```
cmd/gecit/app/     cobra commands: run, status, cleanup, config, service
pkg/panel/         local web panel: HTTP API, log ring, embedded page
pkg/engine/        Engine interface (Start/Stop/Mode/Stats) + Config struct
pkg/ebpf/          Linux engine: sock_ops, kernel side written in Go via gobee
pkg/tun/           macOS/Windows engine: sing-tun + gVisor netstack
pkg/rawsock/       raw packet injection, per-OS
pkg/capture/       new-connection detection, per-OS
pkg/seqtrack/      seq/ack extraction feeding the fake packets
pkg/dns/           DoH server + system DNS takeover/restore, per-OS
pkg/fake/          fake ClientHello construction
```

Two engines behind one interface (`pkg/engine/engine.go:7`, Start/Stop/Mode/Stats): eBPF sock_ops on
Linux, TUN transparent proxy on macOS and Windows. `newPlatformEngine` has one
definition per platform: `run_linux.go` by filename suffix, `run_tun.go` by
`//go:build (darwin || windows) && with_gvisor`.

## Build tags

- `with_gvisor` is required for every macOS and Windows build. `pkg/tun` is
  `//go:build (darwin || windows) && with_gvisor`. Without it the TUN engine
  does not compile in and the binary is useless on those platforms.
- `integration` gates `pkg/ebpf/manager_integration_test.go`, which needs root.
- `pkg/capture` and `pkg/rawsock` select Windows files by filename suffix.
  Windows builds are pure Go: build them with `CGO_ENABLED=0`.

## Commands

```bash
make bpf-all                 # gobee translate + clang compile, required before Linux build
make gecit-linux-amd64       # implies bpf-all
make gecit-windows-amd64
make vet                     # go vet -tags with_gvisor ./...
make fmt
go test -race -tags with_gvisor -timeout 60s ./...
```

Without `-tags with_gvisor` the suite fails to build on macOS and Windows:
`cmd/gecit/app` imports `pkg/tun`, which is `(darwin || windows) &&
with_gvisor`. Cross-check every target before calling anything done:

```bash
go vet -tags with_gvisor ./...                                    # darwin
GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go vet -tags with_gvisor ./...
GOOS=linux  GOARCH=amd64 CGO_ENABLED=0 go vet ./...               # needs bpf-translate
```

`GOOS=windows ... ./...` only works when the gobee bindings are absent. gobee
generates `pkg/ebpf/bpf/sockops_bindings.go` with no build constraint while it
imports `golang.org/x/sys/unix`, so once `make bpf-all` has run in a tree, that
package breaks any whole-module Windows command. The binary is unaffected;
nothing imports it on Windows.

`make bpf-all` needs clang, llvm, libbpf-dev. The compiled objects are
committed under `pkg/ebpf/bpf/bin/` and `.gitignore` whitelists them.

## Windows facts

Verified, and each one changes a decision somewhere. Paths naming
`internal/wintun/...` or `pcap_windows.go` are in `$(go env GOMODCACHE)`, not
in this repo.

- **wintun.dll is embedded in the binary.** sing-tun memory-loads it:
  `internal/wintun/dll_windows_amd64.go` is a `//go:embed amd64/wintun.dll`,
  loaded through `memmod.LoadLibrary` in `dll_windows.go:86`. Nothing has to
  ship or install a wintun DLL.

- **gopacket/pcap needs no cgo on Windows.** `pcap_windows.go` contains zero
  cgo; it `LoadLibrary`s `wpcap.dll` at runtime (`LoadWinPCAP`,
  `pcap_windows.go:161`) after pointing the DLL search path at
  `%SystemRoot%\System32\Npcap` (`initDllPath`, `pcap_windows.go:29`). Only
  `pcap_unix.go` is cgo.

- Consequence: the Windows binary cross-compiles from Linux or macOS with
  `CGO_ENABLED=0`, and CI needs neither MinGW nor the Npcap SDK. Npcap is
  still required at runtime.

- windows/arm64 cannot build at all: gopacket ships `defs_windows_386.go` and
  `defs_windows_amd64.go` only. The failure is in the dependency, not in
  gecit, which is why the release matrix is amd64 only.

- **Npcap absence does not crash.** `pcapFindAllDevs` calls `LoadWinPCAP()`
  and returns its error (`pcap_windows.go:642`), so `capture.NpcapAvailable()`
  reports false instead of dereferencing a null proc address.

- `C:\ProgramData` lets any user create a subdirectory and own what they
  create. `gecit`'s data directory holds the config a LocalSystem service
  reads, so it is created with an explicit DACL (SYSTEM and Administrators
  full, everyone else read) in `cmd/gecit/app/datadir_windows.go`, and the MSI
  applies the same one. Do not replace either with a plain `os.MkdirAll`.

- gecit takes over system DNS by pointing the active interface at `127.0.0.1`
  via `netsh` and leaves a breadcrumb at `%ProgramData%\gecit-dns-backup`
  (`pkg/dns/system_windows.go:12`). A hard kill leaves the machine without
  working DNS until `gecit cleanup` runs.

## Conventions

- Comments describe the current state. No "used to be X", no phase or plan
  references in code, CLI help, or docs.
- No em dashes anywhere, including code comments and commit messages.
- Short functions, no premature helpers, no docstrings on obvious functions.
- Commits: conventional-commits, imperative, lowercase subject, no trailing
  period, no AI attribution.
- Branches: `feat/<author>_<description>`, `fix/<author>_<description>`.
- Format with `gofmt` before calling anything done.
- Release tags are `vX.Y.Z`, candidates `vX.Y.Z-rc.N`. The dot is required:
  it makes the number a numeric identifier under SemVer, so `rc.10` sorts after
  `rc.2`. Written `rc10` it is one alphanumeric identifier compared as text and
  `rc10` sorts before `rc2`, which matters because gecit is a Go module people
  `go install`. The release workflow only builds an MSI for these two shapes.
- The MSI version drops the `v` and turns a candidate into a fourth field, so
  `v0.2.0-rc.1` builds `0.2.0.1`. MSI compares only the first three fields,
  which is why a release installs over its own candidate and why `gecit.wxs`
  needs `AllowSameVersionUpgrades`.
- Config lives in `config.yaml`: `/etc/gecit/` on unix, `%ProgramData%\gecit\`
  on Windows. Adding a key means adding it to `configKeys` in
  `cmd/gecit/app/config.go`, or the loader rejects it as unknown. A key a flag
  binds to also needs an entry in `flagForKey` in `cmd/gecit/app/runner.go`, so
  the panel can say which flag is overriding it.

## The web panel

`pkg/panel` is pure Go with no build tags, so it compiles on all three targets.
It talks to `cmd/gecit/app`'s `runner` through the `panel.Controller` interface;
everything that knows about gecit lives on the cmd side.

- **The runner owns the engine, not `supervise`.** The panel has to outlive an
  engine restart, so `supervise_unix.go` and `supervise_windows.go` drive the
  runner and the runner swaps engines underneath. Driving the Windows SCM to
  restart the process serving the page does not work.

- **`runner.Apply` stops before it builds.** `newPlatformEngine` resolves the
  DoH upstream hostname with `net.LookupIP` (`cmd/gecit/app/run_linux.go:66`), and while gecit
  runs the system resolver is gecit. Building the new engine first sends that
  lookup into a resolver that is being torn down.

- **The activity feed comes from the log hook, not from `PopDomain`.**
  `pkg/dns.PopDomain` deletes what it returns and both injectors already consume
  it, so a second reader would steal the domain from the injector. The three
  call sites that matter tag their log line with an `event` field, which is what
  `Ring.Activity` filters on.

- **logrus checks the level before firing a hook.** DNS resolutions are logged
  at debug, so the panel cannot show them unless the logger is at debug. That is
  why the panel has a level toggle instead of a scheme that keeps stderr quiet.

- **The panel's name needs no DNS.** `gecit.localhost` is in the Host allowlist
  and is what `URL` prints. Anything under `.localhost` is reserved by RFC 6761
  and mapped to loopback by the browser, so it works with `--doh=false` and in a
  browser doing its own DoH. A lookalike like `gecit.localhost.evil.example` is
  not allowed.

- **The token file gates a root process.** Whoever reads
  `<datadir>/panel.token` can rewrite the config and restart the engine, so a
  mode allowing group or other is refused rather than repaired. On Windows the
  data directory grants Builtin\Users read so an operator can open the log, and
  that entry inherits, so the token is created through `windows.CreateFile` with
  its own protected SD rather than created and then repaired.

  Known gap, inherited from the data directory: `%ProgramData%` lets any user
  create `gecit\` and own it. `createDataDir` reasserts that directory's DACL on
  every start but not its owner, and an owner keeps `WRITE_DAC` whatever the
  DACL says. Fixing it means passing `OWNER_SECURITY_INFORMATION` in
  `applyDataDirACL`. Someone who reaches that far can also plant a junction
  where a file is about to be created, which is why the token create passes
  `FILE_FLAG_OPEN_REPARSE_POINT`.

## Two invariants that look like cleanup opportunities

Both were bugs once. Neither failure is visible without a Windows box.

- **Only `run` loads the config file.** Do not hang `loadConfig` off
  `rootCmd.PersistentPreRunE`. `cleanup` is what gives a machine its resolver
  back after gecit took it, and the uninstaller calls it; a typo in
  `config.yaml` must not be able to stop that. `status` and the `service` verbs
  are the same argument.

- **The service restart policy lives in `gecit service set-recovery`, not in
  the MSI.** Restart actions alone do nothing here: the SCM runs them for a
  reported stop only when `FailureActionsOnNonCrashFailures` is set, and a
  failed engine start reports a stop with an exit code. MSI cannot set that
  flag, so the installer calls the CLI. Moving this back into
  `util:ServiceConfig` would compile, install, and never restart anything.
