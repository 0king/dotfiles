---
name: audit-kanata-switcher-threat
description: >-
  Audit the kanata-switcher repository (Rust + Nix + GNOME Shell extension +
  GitHub Actions daemon for focus-based kanata layer switching) for hidden
  malware, backdoors, persistence, risky process execution, and supply-chain
  threats, and produce a complete inventory of every network request or local
  IPC connection it can make. Use when the user asks to audit this repo, asks
  "is kanata-switcher safe", asks what network connections it makes, wants a
  threat model or pre-install review, or asks to re-check a newer checkout or
  PR against the pinned clean baseline.
---

# kanata-switcher Threat & Network Audit

Repo-specific audit workflow. It combines a static scanner, a pinned network /
execution / filesystem baseline, and a manual review pass. The goal is to
detect *changes* that introduce hidden behavior, not to re-litigate the
documented features of the application.

**Default target:** `/media/d_drive/dev/local-builds/kanata-switcher`
**Audited baseline:** commit `6957867` (`69578672fce32ac5b69aed393f6981d4fbad3999`), tag `v1.2.0`, 2026-11-10
**Baseline does not auto-trust newer commits.** Re-run the scanner and review
every diff after this commit before calling a checkout clean.

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
  **runtime verification**. Never execute an untrusted checkout, package, or
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

## Step 3 — Verify the network inventory against the baseline

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

## Step 4 — Manual repo-specific review

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
| **Dependencies** | `Cargo.toml` pins every direct dependency with `=`. Compare additions against the baseline; be suspicious of HTTP clients, telemetry SDKs, gRPC/WebSocket, crypto wallets, or new `build.rs` behavior. `Cargo.lock` has 212 crates.io-only packages and no git/path sources at baseline. |
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

## Step 5 — Optional runtime verification

Only with explicit user approval, in an isolated VM/container or network
namespace, with no secrets mounted and egress blocked or captured. Static
review is usually enough. Runtime verification is for confirming a suspicious
diff or validating the inventory.

Linux example:

```bash
# Build first (do not run an untrusted prebuilt binary).
cargo build --release

# Capture every network syscall from the daemon and its children.
strace -ff -e trace=network,execve,openat -o /tmp/opencode/ks-runtime.log -- \
  ./target/release/kanata-switcher --quiet-focus -p 10000

# From another terminal, inspect sockets owned by the process tree.
ss -ltnp | grep -E '10000'
ss -lunp
lsof -p <pid> -a -i
```

Trigger each path and re-check:

1. Start with a mock kanata TCP server on `127.0.0.1:10000`: exactly one
   outbound TCP connection to that port; no listener, no UDP, no external DNS.
2. Switch focus in GNOME/KDE/Wayland/X11: only D-Bus/Unix-socket traffic plus
   the existing kanata connection.
3. GNOME first run: `gnome-extensions` and `gsettings` child processes, and the
   extension installed under the user's extension directory. No network fetch.
4. KDE first run: a `/tmp/kanata-switcher-kwin-*.js` file appears and is
   removed at cleanup; `org.kde.KWin` D-Bus calls only.
5. `--pause`, `--unpause`, `--restart`: D-Bus calls to the existing daemon; no
   new IP sockets.
6. `--install-autostart` / `--uninstall-autostart`: one local `.desktop` file
   write/remove; no network.
7. Do not run `--install-gnome-extension` against a live Shell on an untrusted
   checkout without a disposable VM; it installs code into GNOME Shell.

Expected: only the configured kanata endpoint (default `127.0.0.1:10000`) for
IP traffic, and local D-Bus/Unix sockets for desktop integration. If you see
anything else, map it to a process/file/line and treat it as a finding.

## Step 6 — Triage and report

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
Static/heuristic, not a sandbox or proof; no CVE/dependency-vulnerability scan;
runtime not performed unless stated; `--include-deps` state; GNOME Shell/KWin/
desktop-environment behavior and compiler/runtime behavior are out of scope.
```

### Severity rubric for this repo

- **Critical** — remote fetch-and-execute, decode-then-execute, hidden payload
  in an image/asset, hardcoded credential with an exfil path, release artifact
  replaced, active malicious git hook, new code that installs a remote GNOME
  extension or runs downloaded code.
- **High** — new remote host or outbound sink not in baseline; a listener
  changed to `0.0.0.0`; new exec sink; shell execution with data from the
  kanata peer or config; `pull_request_target` with secrets/PR code; unpinned
  Nix fetch without a hash; remote `--host` silently introduced.
- **Medium** — ref-pinned GitHub Actions; missing `permissions:`; dependency or
  build-file drift; local D-Bus control methods with no authentication; GNOME
  auto-install enabled by default; KWin script writes under `/tmp`; unquoted
  systemd `ExecStart` args.
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

## Re-baselining procedure

Only after reviewing the diff:

1. Run the scanner on the new commit and confirm every unexpected/changed/
   missing entry is understood.
2. Update `audited_commit`, `audited_commit_short`, `audited_tag`, and
   `audited_date` in `references/network-baseline.json`.
3. Regenerate `expected_network`, `expected_exec`, `expected_fs_writes`,
   `direct_crates`, and `hashes` from the reviewed tree. Keep the descriptive
   `notes` fields and the `expected_non_ip_ipc` / `expected_build_time_network`
   sections current.
4. Add a written `reason` to `accepted_findings` for every intentional finding
   you choose to suppress. Never suppress an unexplained critical/high finding.
5. Re-run with `--verbose` until the baseline has zero unexpected/changed/
   missing entries and only accepted findings remain.
6. Update `references/network-surfaces.md` and `references/threat-model.md` if
   the data flow or trust boundaries changed.

## Reference files

- `references/network-baseline.json` — pinned expected network/IPC, exec,
  filesystem-write, crate, URL, and file-hash inventory, with accepted findings
  and reasons.
- `references/network-surfaces.md` — detailed protocol/data-flow map and
  runtime-verification notes.
- `references/threat-model.md` — trust boundaries, attack surfaces, and
  repo-specific abuse cases.
- `scripts/scan_kanata_switcher.py` — the static scanner used above.
