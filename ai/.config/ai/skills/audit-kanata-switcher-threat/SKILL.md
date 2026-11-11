---
name: audit-kanata-switcher-threat
description: >-
  Audit the kanata-switcher repository (Rust + Nix + GNOME Shell extension +
  GitHub Actions daemon for focus-based kanata layer switching) for hidden
  malware, backdoors, persistence, risky process execution, and supply-chain
  threats, including Cargo dependency execution, release-binary tampering, and
  a rootless dynamic network trace, and produce a complete inventory of every
  network request or local IPC connection it can make. Use when the user asks
  to audit this repo, asks "is kanata-switcher safe", asks what network
  connections it makes, wants a threat model or pre-install review, or asks
  to re-check a newer checkout or PR against the pinned clean baseline.
---

# kanata-switcher Threat & Network Audit

Repo-specific audit workflow. It combines a static scanner, a Cargo
supply-chain audit, release-binary analysis, a pinned network / execution /
filesystem baseline, a rootless dynamic network harness, and a manual review
pass. The goal is to detect *changes* that introduce hidden behavior, not to
re-litigate the documented features of the application.

**Default target:** `/media/d_drive/dev/local-builds/kanata-switcher`
**Audited baseline:** commit `6957867` (`69578672fce32ac5b69aed393f6981d4fbad3999`), tag `v1.2.0`, 2026-11-10
**Baseline does not auto-trust newer commits.** Re-run the scanner and review
every diff after this commit before calling a checkout clean.

**Default workflow:** static source scan → Cargo dependency audit → release
binary analysis → baseline comparison → manual review. Dynamic execution is
the final confirmation, not the first step, and needs explicit permission plus
an isolated network namespace. The dynamic harness is rootless by default and
does not install the GNOME extension or touch a live desktop session.

## What this repo is

A Rust daemon that watches the focused window through the desktop environment
and tells `kanata` which layer or virtual key to use. It is a desktop
integration daemon, not a network service. It does **not** spawn `kanata`; it
connects to kanata's TCP server. It also ships a GNOME Shell extension, KDE
KWin scripting helpers, an optional StatusNotifierItem tray icon, and
NixOS/Home Manager modules.

The audit answers two independent questions:

1. **Is there hidden malicious behavior?** (backdoor, exfiltration,
   persistence, payload drop, obfuscation, compromised dependency/CI).
2. **What network I/O and local IPC exists, on every protocol?** (including
   D-Bus, Wayland, X11, and child processes, so a "no network" answer is
   accurate and complete).

## Step 1 — Confirm scope and authorization

- Confirm the path. If it is not the path above, ask before scanning.
- Confirm whether the user wants **static review only** (default) or also
  **runtime verification**. The full workflow is static + dependencies +
  binary; runtime is opt-in. Never execute an untrusted checkout, package, or
  release binary, and never install its GNOME extension, without explicit
  permission and an isolated environment.
- Note whether dependencies and CI/Nix files are in scope. They are part of the
  supply-chain answer even when runtime code is clean.
- Check the checkout identity first:

```bash
git -C <repo> remote -v
git -C <repo> status --porcelain=v1 -b
git -C <repo> log -5 --oneline --decorate
git -C <repo> diff --stat
```

A dirty tree, a changed remote, or a single unexplained new commit is a review
event. The pinned baseline assumes upstream `7mind/kanata-switcher` over SSH
(`git@github.com:...`).

## Step 2 — Run the static scanner

```bash
SKILL=~/.config/ai/skills/audit-kanata-switcher-threat
python3 "$SKILL/scripts/scan_kanata_switcher.py" <repo> \
  --json /tmp/opencode/kanata-switcher-audit.json --verbose
```

Useful flags:

- `--include-deps` — additionally scan `vendor/` if it exists (this repo does
  not vendor dependencies, so this is normally a no-op).
- `--fail-on high` — exit non-zero at high/critical; useful for CI/PR checks.
- `--json` — full machine-readable result; the terminal summary is for humans.
- `--verbose` — print evidence and accepted-finding reasons.

The scanner is stdlib-only Python, does not execute the repo, and:

- Enumerates Rust network/IPC sinks: `TcpStream`/`TcpListener`, UDP, DNS
  lookup, `UnixStream`/`UnixListener`, `zbus`, `ksni`, Wayland/X11 client
  connection APIs, HTTP/TLS/WebSocket/gRPC libraries, raw socket APIs.
- Enumerates process-execution sinks (`Command::new`, `exec*`, shell wrappers)
  and filesystem writes/removals (`fs::write`, `fs::copy`, `remove_file`,
  `create_dir_all`, `OpenOptions`, destructive APIs).
- Enumerates JavaScript `Gio.DBus`/`Gio.Settings` use and dangerous JS APIs
  (`eval`, `import()`, `Gio.Subprocess`, network modules) in the GNOME
  extension.
- Compares network, exec, write, direct-crate, and URL lists with
  `references/network-baseline.json`.
- Checks `Cargo.toml` for non-`=` pins, patches, path/git dependencies, and
  unknown registry sources; checks `Cargo.lock` for git sources.
- Checks GitHub Actions for mutable refs, `pull_request_target`, `write-all`,
  missing permissions, secrets in PR jobs, and fetch-pipe-to-shell.
- Checks Nix for unpinned fetches, `--impure`, extra substituters, network in
  install phases, and unquoted systemd `ExecStart` construction.
- Inspects committed images for magic/extension mismatch, trailing bytes, and
  embedded executable/archive/script headers; flags committed binaries.
- Checks active `.git/hooks`, insecure git remotes, submodules, hardcoded
  secrets, persistence strings, bidi-control characters, and decode+exec
  combinations.
- Verifies SHA-256 hashes of supply-chain-sensitive files against the baseline.

Read the JSON; do not just copy the terminal summary. The scanner is
recall-biased and can produce false positives. The baseline has an
`accepted_findings` list for reviewed, intentional findings; the scanner
removes those from the severity counts and reports them separately.

## Step 3 — Audit the Cargo dependency graph

The daemon is mostly third-party code. A clean `src/` does not prove a clean
binary, so inventory every locked crate and inspect the crates that can execute
code at build time or open sockets at runtime.

```bash
SKILL=~/.config/ai/skills/audit-kanata-switcher-threat
python3 "$SKILL/scripts/scan_cargo_deps.py" <repo> \
  --json /tmp/opencode/kanata-switcher-deps.json --verbose
```

Run `cargo fetch --locked` first if the local registry cache is cold; the
script reads crate sources from `$CARGO_HOME/registry/src` and reports every
crate it could not inspect. "Not cached" is not "clean". The script is
stdlib-only, does not execute the repository, and checks:

- every `Cargo.lock` package has a crates.io source and a 64-hex SHA-256
  checksum; git/path/other registries are findings;
- cached `.crate` archives match the lockfile checksum when present;
- direct/dev/build dependency pins are still `=` and match
  `expected_dependencies` in the baseline;
- `[patch]`/`[replace]` and `.cargo/config.toml` source replacement;
- build scripts (`build.rs`) for downloaders, HTTP clients, sockets, shell
  execution, remote URLs, and out-of-crate `include_bytes!`/`include_str!`;
- proc-macro crates, crates with `links =`, `cc`/`pkg-config`/`bindgen`/
  `cmake`/`nasm` build dependencies;
- crates with network-capable APIs (HTTP/TLS/DNS/SSH/DB/queue/socket).

Triage: a new network-capable crate, a new build script, a non-crates.io
source, a missing checksum, or a lockfile hash change is at least **High** until
the diff is understood. A new proc-macro or native `links` crate is **Medium**
unless it also has network/build-script risk.

| Rule | Meaning |
|------|---------|
| `DEP-LOCK-DRIFT` / `DEP-COUNT-DRIFT` | lockfile hash or package count changed |
| `DEP-DIRECT-DRIFT` / `DEP-DEV-DRIFT` | manifest direct/dev set differs from baseline |
| `DEP-LOCK-NO-SOURCE` / `DEP-LOCK-NONREGISTRY` / `DEP-LOCK-NO-CHECKSUM` / `DEP-LOCK-BAD-CHECKSUM` | source or checksum integrity |
| `DEP-CACHE-CHECKSUM-MISMATCH` | cached `.crate` archive does not match the lockfile |
| `DEP-UNEXPECTED-NETWORK-CRATE` / `DEP-UNEXPECTED-BUILD-SCRIPT` | new network-capable or build-script crate |
| `DEP-UNEXPECTED-PROC-MACRO` / `DEP-UNEXPECTED-NATIVE` | new proc-macro or native-linking crate |
| `DEP-BUILD-SCRIPT-RISK` | build script downloads, opens a socket, runs a shell, or embeds outside the crate |
| `DEP-MANIFEST-UNPINNED` / `DEP-MANIFEST-OVERRIDE` | unpinned dependency or `[patch]`/`[replace]` |
| `DEP-CARGO-SOURCE-REPLACEMENT` / `DEP-CARGO-PATCH` | `.cargo/config.toml` redirects crate sources |

## Step 4 — Analyze the release binary

Build the artifact from a clean `git archive` of the audited commit, not from a
dirty working tree. The dynamic harness does this automatically; for a
standalone pass:

```bash
git -C <repo> archive --format=tar <commit> | tar -x -C /tmp/opencode/ks-src
CARGO_TARGET_DIR=/tmp/opencode/ks-target cargo build --release --locked \
  --manifest-path /tmp/opencode/ks-src/Cargo.toml
python3 "$SKILL/scripts/analyze_release_binary.py" \
  /tmp/opencode/ks-target/release/kanata-switcher \
  --json /tmp/opencode/kanata-switcher-binary.json --markdown /tmp/opencode/kanata-switcher-binary.md
```

If the user supplies a release artifact, use `--binary` and state that its
provenance is unverified. The analyzer reads the ELF only (no execution) and
checks:

- writable+executable `PT_LOAD` segments, `DT_TEXTREL`, `RPATH`/`RUNPATH`;
- bytes after the last segment/section (overlay) and embedded ELF/PE/ZIP/gzip/
  script/Mach-O signatures;
- high-entropy sections and stripped/debug state;
- `NEEDED` shared libraries and dangerous imported symbols (`system`, `popen`,
  `execve`, `socket`, `connect`, `dlopen`, `ptrace`, `memfd_create`, `bpf`, …);
- printable ASCII/UTF-16 strings for remote URLs, IPs, domains, telemetry
  keywords, webhooks, wallet/key material, and shell commands;
- build provenance (`rustc` comment, GNU build-id) and baseline size/library/
  overlay limits.

A release binary is not byte-reproducible across machines. Do **not** require
a matching SHA-256 by default; compare invariants (`expected_binary`). A changed
build-id alone is not a finding. An unexpected `NEEDED` library, overlay,
embedded payload, remote URL, or size blow-up is.

## Step 5 — Verify the network inventory against the baseline

The expected runtime surface is deliberately small. Confirm each item is still
present, still local, and still gated the same way:

| ID | Direction | Protocol | Endpoint | Gate | Data |
|----|-----------|----------|----------|------|------|
| `kanata-tcp-client` | outbound | newline-delimited JSON over plain TCP | `{host}:{port}`, default `127.0.0.1:10000` | every daemon start | `ChangeLayer`, `RequestLayerNames`, `RequestFakeKeyNames`, `ActOnFakeKey`; layer/key events in |
| D-Bus session bus | local IPC | D-Bus over unix socket | user session bus | desktop integration / control | focus events, status, pause/restart/unpause, SNI, GNOME extension probe |
| D-Bus system bus | local IPC | D-Bus over unix socket | system bus | logind lifecycle | read active session, display, sleep/lock signals |
| `wayland-display-override` | local IPC | AF_UNIX | `$XDG_RUNTIME_DIR/$WAYLAND_DISPLAY` | Wayland backend | focus data from compositor |
| Wayland client | local IPC | AF_UNIX | compositor socket from `WAYLAND_DISPLAY` | Wayland backend | toplevel/focus events |
| X11 client | local IPC | AF_UNIX (normally) | `$DISPLAY` | X11 backend | window focus/property events |
| GNOME extension | local IPC | D-Bus over unix socket | session bus | extension loaded in GNOME Shell | `GetFocus`, `FocusChanged`, daemon status |
| KDE KWin helper | local IPC + temp file | D-Bus + JavaScript file | session bus; `/tmp/kanata-switcher-kwin-*.js` | KDE backend | focus push/query; file deleted on cleanup |

**Expected:** no inbound TCP listener, no HTTP client/server, no TLS, no UDP,
no explicit DNS API, no SMTP/SSH/FTP/WebSocket/gRPC, no telemetry, no
auto-update, and no remote URL fetched at runtime. The only IP socket is the
outbound kanata TCP connection. The only runtime URL literal is the clone URL
in printed GNOME install instructions; it is documentation, not a fetch. If
`--host` is a hostname rather than an IP, the OS resolver will resolve it; the
default is the literal `127.0.0.1`.

If the scanner reports **any** of these, stop and triage as a finding:

- a network/IPC sink not in the baseline (`NET-UNEXPECTED-SINK`);
- a baseline endpoint changed to `all-interfaces`/`remote`
  (`NET-ENDPOINT-CHANGED`);
- a remote URL/host literal in runtime source (`NET-REMOTE-HOST`);
- a new exec sink (`EXEC-UNEXPECTED-SINK`) or write sink
  (`FS-UNEXPECTED-WRITE`);
- a new direct dependency (`DEP-NEW-DIRECT`) or build-file drift
  (`SUPPLY-FILE-DRIFT`).

Baseline matching is by file + direction + protocol family, not line number, so
moved code is flagged as missing/unexpected for manual review. That is
intentional. `kanata-tcp-client` is classified as `configurable`: the default is
loopback, but `--host` / the Nix `kanataHost` option can point it at another
machine. Treat a non-loopback value as a deliberate operator choice, not
malware, but verify who can set it.

## Step 6 — Manual repo-specific review

Do not rely on the scanner alone. Check these in the actual checkout:

| Area | What to verify |
|------|----------------|
| **Entry point** | `src/daemon/main.rs` parses CLI, loads config, connects to kanata, starts the persistent D-Bus service, signal handlers, SNI, then the lifecycle supervisor. No hidden network or exec path before these documented stages. |
| **Config** | `src/daemon/config.rs` reads JSON with `serde` and `deny_unknown_fields`. Rules contain class/title/layer/virtual-key strings only; no code evaluation. Default path is `~/.config/kanata/kanata-switcher.json`. |
| **CLI / autostart** | `src/daemon/args.rs` defaults host `127.0.0.1`, port `10000`. `--install-autostart` writes `~/.config/autostart/kanata-switcher.desktop` with a quoted absolute binary path and passthrough args; `--uninstall-autostart` removes it. Check for new passthrough options or unquoted `Exec=`. |
| **kanata TCP client** | `src/daemon/kanata.rs` is the only IP socket: `TokioTcpStream::connect("{host}:{port}")`, plain TCP, newline-delimited JSON. It never spawns kanata. Responses are deserialized with `serde`; layer/key names are used for matching and `ActOnFakeKey`, not passed to a shell. |
| **D-Bus control service** | `src/daemon/control/server.rs` exports `com.github.kanata.Switcher` methods `WindowFocus`, `GetStatus`, `GetPaused`, `Restart`, `Pause`, `Unpause` on the session bus. No authentication; any same-user process can call them. This is expected local desktop integration, but it is a real local attack surface. |
| **D-Bus control client** | `src/daemon/control/client.rs` enumerates `com.github.kanata.Switcher.instances.*` and calls control methods; no arbitrary method/name injection. `--dbus-suffix` is sanitized to `[A-Za-z0-9_-]`. |
| **Lifecycle / logind** | `src/daemon/lifecycle/logind.rs` and `display_override.rs` use the **system** bus for logind only: `GetUserByPID`, session `Type`/`Display`, properties-changed signals. Read-only, no privileged operations. |
| **GNOME backend** | `src/daemon/backends/gnome.rs` uses the session bus to query GNOME Shell focus; `src/daemon/gnome_ext/` may auto-install the bundled extension by default, invoking `gnome-extensions pack/install/enable` and `gsettings`. It does not download the extension. `--no-install-gnome-extension` disables auto-install. |
| **GNOME extension JS** | `src/gnome-extension/*.js` uses `Gio.DBus` and `Gio.Settings` only. Check for new network modules, `Gio.Subprocess`, `eval`, dynamic imports, or writes outside the extension's own settings. |
| **KDE backend** | `src/daemon/backends/kde/` writes generated KWin JavaScript to unguessable `/tmp/kanata-switcher-kwin-{uid}-{uuid}.js`, loads it via `org.kde.KWin` D-Bus, and removes it on cleanup. Check that the script still contains only `callDBus` focus reporting and that the path keeps uid + UUID. |
| **Wayland / X11** | `src/daemon/backends/wayland/mod.rs` connects to the compositor socket derived from `$XDG_RUNTIME_DIR`/`WAYLAND_DISPLAY`; `x11.rs` uses `x11rb::connect`. A remote `$DISPLAY` would use TCP, but that is an explicit operator choice. |
| **SNI / tray** | `src/daemon/sni/` uses `ksni` on the session bus and shells out to `dconf` for the focus-only key. Args are fixed; no user data reaches the command line. |
| **Dependencies** | `Cargo.toml` pins every direct dependency with `=`. Compare additions against the baseline; be suspicious of HTTP clients, telemetry SDKs, gRPC/WebSocket, crypto wallets, or new `build.rs` behavior. `Cargo.lock` has 212 packages including the root crate (211 external, all crates.io) and no git/path sources at baseline. |
| **CI** | Only `.github/workflows/ci.yml`: `7mind/github-env@minimal`, `permissions: contents: read`, no `pull_request_target`, no secrets, no release publish. The action is ref-pinned, not SHA-pinned — a known medium supply-chain risk, accepted in the baseline but worth reporting. |
| **Nix** | `flake.lock` pins `nixpkgs`, `flake-utils`, `crane`, and `rust-overlay` with `rev` + `narHash`; `tests/flake.lock` pins `home-manager` plus a path input to `..`. No `fetchurl`/`fetchgit`/`--impure`/extra substituters. The module's `ExecStart = lib.concatStringsSep " " ...` does not quote args; low-risk hardening note accepted in the baseline. |
| **Shell scripts** | `build.sh`/`run.sh` are `cargo build/run` wrappers; `install-gnome-shell-ext.sh` runs `glib-compile-schemas` and `gnome-extensions` on the local extension; `devops/release.sh` and `update-libraries.sh` mutate versions/lockfile only. No `curl \| bash`. |
| **Assets** | `enterprise-quality.svg` is a static joke badge with only the SVG namespace URL. Screenshots are valid PNGs with no trailing data or embedded payloads. Re-check after replacing assets. |
| **Git metadata** | No active `.git/hooks` beyond `*.sample`; remote is SSH; no submodules or unexpected symlinks. `.envrc` is just `use flake`. |

Useful manual greps:

```bash
rg -n 'TcpStream|TcpListener|UdpSocket|UnixStream|UnixListener|lookup_host|to_socket_addrs' src
rg -n 'reqwest|ureq|hyper|tungstenite|tonic|axum|actix|surf|curl|wget|http::' src Cargo.toml
rg -n 'Command::new|std::process::Command|sh -c|bash -c|/bin/sh|exec\(' src build.rs
rg -n 'fs::(write|copy|remove|create|rename)|OpenOptions|File::create|set_permissions|symlink' src build.rs
rg -n 'eval\(|new Function|import\(|Gio\.Subprocess|Gio\.AppInfo|GLib\.spawn|Soup|WebSocket|XMLHttpRequest' src/gnome-extension
rg -n 'fetchurl|fetchgit|builtins\.fetch|--impure|substituters|postInstall|installPhase' flake.nix tests/flake.nix
rg -n 'curl|wget|base64|eval|chmod|/bin/sh|powershell|nc |ncat' .github devops qa *.sh
```

## Step 7 — Dynamic network verification (opt-in)

Only with explicit user approval. The harness runs the binary in a rootless
network namespace with no route except loopback, captures every network and
process syscall from the daemon and its children, and compares the result with
the pinned policy. It never installs the GNOME extension and never touches a
live desktop session unless `--host-desktop` is explicitly selected.

```bash
SKILL=~/.config/ai/skills/audit-kanata-switcher-threat
"$SKILL/scripts/run_dynamic_network_audit.sh" \
  --repo <repo> --out /tmp/opencode/ks-dynamic --timeout 15
```

What the harness does:

1. Resolves the audited commit and exports a clean tree with `git archive` into
   the output directory. A dirty working tree is recorded but not executed.
2. Runs `cargo fetch --locked` (network is allowed only for this fetch) and
   `cargo build --release --locked --offline` into an isolated target dir.
3. Starts `mock_kanata.py` on `127.0.0.1:<port>` inside the namespace.
4. Runs `bwrap --unshare-net --unshare-pid --unshare-ipc --unshare-uts` with
   `--ro-bind / /`, a private `/tmp`, a private `HOME`/`XDG_RUNTIME_DIR`, and
   only the output directory writable. The namespace has only `lo`.
5. Runs the daemon under `strace -ff -ttt -s 512 -v` tracing `%network`,
   `%process`, `openat`, `open`, `memfd_create`, `io_uring_*`, `bpf`,
   `init_module`, `finit_module`, `ptrace`, `unshare`, `setns`, `keyctl`,
   `add_key`, `request_key`, `mount`, `pivot_root`, and `chroot`.
6. Takes `ss -tanp`, `ss -uanp`, `ss -lxnp`, and `/proc/net/{tcp,tcp6,udp,
   udp6,packet,netlink,unix,raw,raw6}` snapshots while the daemon runs, and
   calls `GetStatus` over the private session bus.
7. Parses the evidence with `analyze_dynamic_logs.py` and writes
   `report.json` / `report.md` plus the raw logs.

Scenarios:

- `--scenario baseline` (default): private session bus, `XDG_CURRENT_DESKTOP=
  GNOME`, no GNOME extension install, SNI enabled. This exercises the documented
  desktop IPC without a real desktop.
- `--scenario minimal`: no desktop environment variables and `--no-indicator`;
  the daemon connects to kanata and exits. Useful for a low-noise baseline.
- `--scenario host-desktop`: opt-in; binds the real session bus, `$DISPLAY`,
  `$WAYLAND_DISPLAY`, and `$XDG_RUNTIME_DIR` into the isolated netns. Use only
  when the user explicitly wants real focus events. It can drive the live
  desktop; do not enable it on an untrusted checkout.
- `--binary PATH`: audit a supplied artifact; provenance is then unverified.
- `--command 'CMD'`: run an arbitrary probe under the same isolation; used by
  `selftest_dynamic.sh`. It skips the daemon/mock expectations.

Expected result: exactly the configured kanata TCP endpoint (default
`127.0.0.1:10000`) over IP, plus documented local D-Bus/Wayland/X11 Unix
sockets. No UDP, no raw/AF_PACKET socket, no IP listener, no DNS resolver
contact, no non-loopback connect (including failed attempts), and no
undocumented Unix socket. The analyzer is strict: a failed `connect()` is still
a finding.

Common rules and what they mean:

| Rule | Meaning |
|------|---------|
| `DYN-NONLOOPBACK-CONNECT` | connect/send to an address outside `127.0.0.0/8`, `::1`, or IPv4-mapped loopback. High even if it failed. |
| `DYN-LOOPBACK-UNEXPECTED` | loopback traffic to a port other than the configured kanata port. |
| `DYN-UDP` / `DYN-DNS` | any UDP socket/traffic, or port 53. The baseline has no UDP. |
| `DYN-AF-PACKET` / `DYN-RAW-SOCKET` | layer-2 or raw socket. Critical. |
| `DYN-IP-BIND` / `DYN-LISTEN` / `DYN-SS-LISTENER` / `DYN-PROCNET-LISTENER` | inbound IP surface. The daemon must not listen. |
| `DYN-UNIX-UNEXPECTED` / `DYN-UNIX-LISTENER` | undocumented Unix socket or a daemon-created Unix listener. |
| `DYN-NETLINK` | local kernel IPC, informational; not IP egress. |
| `DYN-SUSPICIOUS-SYSCALL` | `bpf`, module load, `ptrace`, namespace change, `memfd_create`, `io_uring`, keyring, mount. |
| `DYN-CHILD-IP-NETWORK` | a child process, not the main daemon, performed IP I/O. |
| `DYN-NETWORK-TOOL-EXEC` / `DYN-SHELL-EXEC` | `curl`/`wget`/`ssh`/`nc` or `sh -c` execution. |
| `DYN-KANATA-MISSING` / `DYN-KANATA-NO-CONNECT` | the expected kanata connection never appeared in daemon mode. |
| `DYN-KANATA-TOO-FEW-CONNECTS` / `DYN-KANATA-TOO-MANY-CONNECTS` | connection count outside the baseline range. |

Optional privileged corroboration (not required, needs root): run `tcpdump -i
any -nn -s0 -w capture.pcap` or a `bpftrace` syscall/`kprobe` script around the
same harness, then compare the pcap with the strace endpoints. Record that this
was done separately; the default harness is rootless and does not claim packet
capture.

Negative-control self-test (run after changing the harness or analyzer):

```bash
"$SKILL/scripts/selftest_dynamic.sh"
```

It must detect non-loopback TCP, UDP/DNS, `AF_PACKET`, an IP listener, and a
child-process connect, and must report a clean no-op as clean. A self-test that
does not fail on the controls means the analyzer is broken, not that the target
is clean.

Manual path coverage when the harness cannot run: start a mock kanata server,
then trigger focus changes, GNOME/KDE backend startup, pause/unpause/restart,
and autostart install/uninstall. Re-check `ss -ltnp`, `ss -lunp`, and
`/proc/<pid>/net/*`. Do not run `--install-gnome-extension` against a live Shell
on an untrusted checkout; it installs code into GNOME Shell.

## Step 8 — Triage and report

Use this structure:

```markdown
# Threat Audit: kanata-switcher @ <commit>

**Scope:** <path, clean/dirty, deps included Y/N, static/runtime>
**Overall risk:** Critical / High / Medium / Low / Clean

## Summary
2–4 sentences: hidden behavior found or not; network surface; headline
recommendation (e.g. "safe modulo ref-pinned CI action", "do not run this
checkout", "baseline drift at X").

## Network and IPC inventory
| Direction | Protocol | Endpoint | Gate | Data | Assessment |
|-----------|----------|----------|------|------|------------|
(fill from scanner + manual verification; include "none" for absent protocols)

## Supply chain
- Cargo.lock SHA-256, package count, crates.io-only Y/N, checksums missing Y/N.
- New/direct/build dependencies vs baseline; build scripts; proc-macro/native
  crates; network-capable crates; cached-source coverage.
- `.cargo/config.toml`, patches/replacements, CI/Nix pinning.

## Release binary
- Path, SHA-256, size, build-id, rustc comment, stripped/debug.
- NEEDED libraries vs baseline; W^X segments; textrel; overlay; embedded
  payloads; high-entropy sections.
- Remote URL/IP/domain strings and suspicious keywords; provenance limits.

## Dynamic network trace
- Scenario, namespace, timeout, commit/binary, harness output path.
- IP endpoints observed (expected kanata + anything else); UDP/raw/listeners.
- Unix sockets observed; execs; suspicious syscalls; child-process network.
- Analyzer result: clean / findings; self-test status.

## Findings

### Critical
**<rule id> — <description>**
`path:line`
```
<minimal snippet>
```
Why this matters here: <context, data flow, whether reachable by default>.
What to confirm: <maintainer question or remediation>.

(repeat High / Medium / Low)

## Reviewed and dismissed
One line per scanner hit that is legitimate, with the reason (documented D-Bus
IPC, loopback kanata client, GNOME install helper, KWin script cleanup, CI ref
pin, documentation URL, valid screenshot, etc.).

## Baseline drift
List unexpected/changed/missing sinks and accepted findings; state whether the
pinned baseline still applies.

## Limits of this audit
Static/heuristic plus a rootless syscall trace, not a proof; no CVE/dependency-
vulnerability scan; dynamic run not performed unless stated; dependency sources
not cached are not deeply scanned; `--include-deps` state; GNOME Shell/KWin/
desktop-environment behavior, compiler/runtime behavior, and privileged packet
capture are out of scope unless explicitly recorded. A dynamic trace sees the
paths that were exercised, not every branch; static review still owns unexercised
code. `--host-desktop` is not the default and changes the trust boundary.
```

### Severity rubric for this repo

- **Critical** — remote fetch-and-execute, decode-then-execute, hidden payload
  in an image/asset, hardcoded credential with an exfil path, release artifact
  replaced, active malicious git hook, new code that installs a remote GNOME
  extension or runs downloaded code; a non-crates.io/git/path dependency with
  no checksum; a cached `.crate` checksum mismatch; `AF_PACKET`/raw socket or
  an IP listener on a non-loopback address; an embedded ELF/PE payload in the
  release binary.
- **High** — new remote host or outbound sink not in baseline; a listener
  changed to `0.0.0.0`; new exec sink; shell execution with data from the
  kanata peer or config; `pull_request_target` with secrets/PR code; unpinned
  Nix fetch without a hash; remote `--host` silently introduced; new
  network-capable dependency or build script; lockfile/direct-dependency drift;
  binary overlay, unexpected `NEEDED` library, or unexpected remote URL;
  dynamic non-loopback connect (even failed), UDP/DNS, or child-process IP I/O.
- **Medium** — ref-pinned GitHub Actions; missing `permissions:`; non-direct
  dependency or build-file drift after review; local D-Bus control methods with no authentication; GNOME
  auto-install enabled by default; KWin script writes under `/tmp`; unquoted
  systemd `ExecStart` args; new proc-macro/native dependency; undocumented Unix
  socket; `memfd_create`/`io_uring`/keyring/mount syscall; suspicious binary
  string or dangerous imported symbol not in baseline.
- **Low** — documentation URLs, expected D-Bus/Unix IPC, expected
  `gnome-extensions`/`gsettings`/`dconf` helper execution, expected autostart
  feature, valid committed screenshots.

Keep the distinction between **malware** and **hardening/design risk** explicit.
An unauthenticated same-user D-Bus control interface is a real security issue,
not evidence of malicious intent. Auto-installing the bundled GNOME extension
and writing KWin scripts are documented features; they become findings when
their content, source, or destination changes unexpectedly.

### Known false positives / dismissed-by-default

- The `gi://Gio`, `gi://GLib`, `gi://St`, etc. imports in the GNOME extension
  are GObject-introspection URIs, not network URLs. The scanner filters them.
- `http://www.w3.org/2000/svg` in `enterprise-quality.svg` is an XML namespace,
  not a fetched resource. The scanner filters benign XML namespaces.
- `http://www.freedesktop.org/standards/dbus/1.0/busconfig.dtd` is a DOCTYPE
  in a test fixture; it is not fetched by the daemon.
- `https://github.com/7mind/kanata-switcher.git` in
  `src/daemon/gnome_ext/mod.rs` is printed install guidance, not a runtime
  fetch.
- Bytes that look like `MZ` inside compressed PNG data are random. The scanner
  only flags structural PE headers or signatures in appended data.
- `Command::new("gnome-extensions")`, `gsettings`, `dconf`, and
  `glib-compile-schemas` are standard local desktop helpers. They are expected
  exec sinks; new commands or user-controlled arguments are the finding.
- `zbus`/`ksni` session-bus traffic and logind system-bus traffic are local
  Unix-socket IPC, not IP network traffic.
- The `7mind/github-env@minimal` action and the systemd unit comment are
  accepted in the baseline with written reasons. Re-review them if the
  workflow or unit changes.
- The `NIX-EXEC-ARGS-UNQUOTED` hits are a low-risk hardening note about
  operator-supplied Nix strings, not remote code execution.
- `DYN-NETLINK` / `AF_NETLINK` is local kernel IPC (address/route enumeration),
  not IP egress. `socketpair(AF_UNIX)` is internal IPC, not a socket path.
- The mock kanata listener on `127.0.0.1:<port>` appears in `ss` and
  `/proc/net/tcp`; it is the harness, not the daemon. The analyzer allows a
  loopback listener on the configured mock port and reports every other one.
- `libdbus-1.so`, `libwayland-client.so`, and `libc.so` in `NEEDED` are expected
  because `ksni`/`dbus` and `wayland-client` link them. A new library is the
  finding, not the presence of these.
- `socket`/`connect`/`bind` in the dynamic symbol table are expected libc
  imports for the kanata client and D-Bus; compare against
  `expected_binary.allowed_dangerous_symbols` before treating them as findings.
- Docs/crates.io/GitHub URLs embedded by Rust dependencies are not runtime
  fetches. The binary baseline allows the known documentation prefixes; a URL
  outside those prefixes is still a finding.
- Build-id, `.comment` rustc version, and byte size vary across machines and
  toolchains. Only baseline `max_size_bytes`, `NEEDED` libraries, overlay, and
  allowed URL patterns are invariants by default.
- `DYN-UNEXPECTED-EXEC` is intentionally skipped in `--command` mode because the
  probe itself is launched through `bash -c`; daemon mode still checks execs.

## Re-baselining procedure

Only after reviewing the diff:

1. Run the scanner on the new commit and confirm every unexpected/changed/
   missing entry is understood.
2. Update `audited_commit`, `audited_commit_short`, `audited_tag`, and
   `audited_date` in `references/network-baseline.json`.
3. Regenerate `expected_network`, `expected_exec`, `expected_fs_writes`,
   `expected_non_ip_ipc`, `expected_build_time_network`, the top-level
   `direct_crates`/`dev_crates` used by the static scanner, and `hashes` from
   the reviewed tree. Keep the descriptive `notes` fields current.
4. Update `expected_dependencies` (lock SHA-256, package count, direct/dev
   lists, network-capable, build-script, proc-macro, and native crate lists)
   from the reviewed `scan_cargo_deps.py --json` output. Do not add a crate
   merely to silence a finding; write down why it is trusted.
5. Update `expected_binary` (allowed/required `NEEDED` prefixes, allowed URL
   patterns, allowed dangerous symbols, max size, overlay limit) from a binary
   built from the reviewed commit. Do not pin a machine-specific SHA-256 as a
   trust anchor.
6. Update `dynamic_policy` / `expected_dynamic` (expected TCP endpoint, allowed
   Unix globs, forbidden families, trace syscalls) and run the harness plus
   `selftest_dynamic.sh`. The baseline is only valid if the controls still fail.
7. Add a written `reason` to `accepted_findings` for every intentional finding
   you choose to suppress. Never suppress an unexplained critical/high finding.
8. Re-run the static, dependency, and binary scanners with `--verbose` until
   the baseline has zero unexpected/changed/missing entries and only accepted
   findings remain. Re-run the dynamic harness and `selftest_dynamic.sh` if
   runtime scope was included.
9. Update `references/network-surfaces.md`, `references/threat-model.md`,
   `references/dynamic-analysis.md`, and `references/release-binary-analysis.md`
   if the data flow or trust boundaries changed.

## Reference files

- `references/network-baseline.json` — pinned expected network/IPC, exec,
  filesystem-write, crate, URL, file-hash, dependency, binary, and dynamic
  policy inventory, with accepted findings and reasons.
- `references/network-surfaces.md` — detailed protocol/data-flow map and
  runtime-verification notes.
- `references/threat-model.md` — trust boundaries, attack surfaces, and
  repo-specific abuse cases.
- `references/dynamic-analysis.md` — harness design, isolation model, trace
  coverage, rule semantics, privileged capture, and limits.
- `references/release-binary-analysis.md` — ELF checks, baseline invariants,
  provenance, and false positives.
- `scripts/scan_kanata_switcher.py` — the static source scanner.
- `scripts/scan_cargo_deps.py` — Cargo.lock/manifest/cache supply-chain audit.
- `scripts/analyze_release_binary.py` — offline ELF/strings/payload analyzer.
- `scripts/run_dynamic_network_audit.sh` — rootless bwrap+strace harness.
- `scripts/analyze_dynamic_logs.py` — strace/ss/procnet/mock log analyzer.
- `scripts/mock_kanata.py` — loopback-only kanata protocol mock.
- `scripts/selftest_dynamic.sh` — negative controls for the dynamic analyzer.
