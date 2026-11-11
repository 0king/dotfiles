# kanata-switcher Threat Model

Snapshot: `6957867` (`69578672fce32ac5b69aed393f6981d4fbad3999`), tag `v1.2.0`,
2026-11-10.

## What the software is trusted to do

The daemon runs as the logged-in user. It:

- reads a JSON rule file;
- connects to a kanata TCP server (default loopback);
- asks the desktop environment which window is focused;
- asks kanata to switch layers or act on virtual keys;
- exposes a same-user D-Bus control service;
- optionally installs/enables its bundled GNOME extension;
- optionally writes a per-user autostart entry;
- generates short-lived KWin scripts for KDE focus tracking.

It is a desktop convenience tool. It does not need root, does not install a
system service by itself, does not fetch updates, and does not run a network
listener.

## Assets worth protecting

| Asset | Why it matters |
|-------|----------------|
| User session / desktop | The daemon runs with the user's privileges and can drive kanata layer/virtual-key actions. |
| kanata configuration and behavior | Compromised layer switching can cause unwanted key actions; kanata itself may have broader capabilities depending on its config. |
| `~/.config/kanata/kanata-switcher.json` | Controls which windows trigger which layers/keys. Not code, but security-relevant configuration. |
| GNOME Shell | The bundled extension runs inside the Shell process with the user's session privileges. |
| KWin | Generated scripts run inside the window manager. |
| Autostart / systemd units | Persistence mechanism; unexpected writes here are high-signal. |
| Build inputs | `Cargo.lock`, `flake.lock`, CI actions, `build.rs`, shell release scripts. |

## Trust boundaries

### 1. The kanata TCP peer (`{host}:{port}`)

**Trust:** semi-trusted local service by default; fully operator-chosen if
`--host`/`kanataHost` points elsewhere.

The daemon sends JSON commands and parses JSON replies with `serde`. It does not
execute anything received from kanata. A malicious peer can:

- lie about available layers and virtual-key names;
- send malformed/oversized messages (handled by `serde`/read limits in the
  process; a DoS is possible);
- influence which layer/key names the daemon later sends back.

It cannot directly make the daemon run a command, write a file, or open a new
connection **unless** a code change introduces such a data flow. That is the
main thing to review when the TCP client changes.

**Default:** `127.0.0.1:10000`. If the host is changed to a remote address, the
traffic is plain TCP with no TLS or authentication. Treat that as an explicit
operator decision and review the network path.

### 2. Local JSON configuration

**Trust:** user-controlled.

`src/daemon/config.rs` uses `serde` with `deny_unknown_fields`. Rules contain
`class`, `title`, `layer`, `virtual_key`, `raw_vk_action`, `fallthrough`, and
`on_native_terminal`. There is no expression language, template expansion, or
shell interpolation. A malicious config can choose which layers/keys are
triggered, but it cannot execute code through this parser.

### 3. Session D-Bus

**Trust:** same-user processes; effectively no authentication.

The daemon exports `com.github.kanata.Switcher` on the session bus. Methods:
`WindowFocus(class, title)`, `GetStatus`, `GetPaused`, `Restart`, `Pause`,
`Unpause`. Signals: `StatusChanged`, `PausedChanged`.

Any same-user process can call these. `WindowFocus` can make the daemon treat an
arbitrary class/title as focused and drive kanata actions; `Restart`/`Pause`
can disrupt the service. This is expected for a desktop session service and is
not a remote vulnerability by itself, but it is a local trust boundary. Do not
describe the daemon as "authenticated" or "only its own extension can call it".

The GNOME extension and the daemon's own CLI are normal clients. The KDE
backend additionally exports a temporary `KdeQuery` object for focus replies.

### 4. System D-Bus / logind

**Trust:** trusted system service.

The daemon makes read-only logind queries: `GetUserByPID`, session `Type` and
`Display`, and property-change subscriptions. It does not call privileged
methods, does not manage systemd units at runtime, and has no polkit action.
A compromised system bus is outside this application's trust model.

### 5. GNOME Shell extension

**Trust:** the extension runs inside GNOME Shell with the user's privileges.

The bundled JS uses `Gio.DBus` and `Gio.Settings` only. It does not fetch
network resources, spawn processes, or evaluate dynamic code. The daemon may
auto-install this bundled extension by invoking `gnome-extensions` on first run
unless `--no-install-gnome-extension` is used. The install source is the
binary's embedded data or the adjacent `gnome/` directory, not a download.

A compromised extension could read session data or call the daemon's D-Bus
methods. Review any new import, subprocess, `eval`, network module, or write
outside the extension's settings.

### 6. KDE / KWin scripts

**Trust:** generated code executed by KWin as the user.

The daemon writes a generated JS file to a UUID-scoped `/tmp` path and asks
`org.kde.KWin` to load/run it. The script calls back into the daemon's session
bus with focus data. The bus name is sanitized; paths are internally generated.
The file is removed on cleanup, but a hard kill can leave it behind. A stale
file contains only the generated `callDBus` report.

Review any change that interpolates config, network data, or unsanitized
strings into the script, changes the `/tmp` path to a predictable name, or
writes outside `/tmp`.

### 7. Subprocess helpers

**Trust:** local `PATH`.

`gnome-extensions`, `gsettings`, `dconf`, and `glib-compile-schemas` are
standard desktop/build helpers. They receive fixed or internally generated
arguments. A poisoned `PATH` can substitute a malicious helper, but that is the
normal local-environment boundary. New commands, `sh -c`, or arguments derived
from kanata/config/network data are the review trigger.

### 8. Build and release supply chain

**Trust:** pinned inputs, reviewed diffs.

- `Cargo.toml` pins direct dependencies with `=`.
- `Cargo.lock` at baseline has 212 packages including the root crate (211
  external, all crates.io) and no git/path sources.
- `flake.lock` and `tests/flake.lock` pin GitHub inputs with `rev` + `narHash`;
  `tests/flake.lock` also has a path input to `..`.
- The only CI workflow uses `7mind/github-env@minimal`, has
  `permissions: contents: read`, no `pull_request_target`, no secrets, and no
  release publish. The action is ref-pinned, not SHA-pinned: a real but
  accepted medium supply-chain risk.
- `build.rs` copies the bundled GNOME extension/schema into `OUT_DIR` and runs
  `glib-compile-schemas`. It does not fetch network data.

### 9. Dependency execution surface

**Trust:** crates.io checksums, reviewed lockfile, local registry cache.

A dependency can act at three points: in `build.rs` (build machine), in a
proc-macro (compile time, inside rustc), or at runtime. The dependency audit
therefore inventories every locked crate, verifies crates.io sources and
SHA-256 checksums, verifies cached `.crate` archives when present, and
deep-scans build scripts, proc-macro crates, native `links` crates, and
network-capable crates. A new build script that downloads, opens a socket, runs
a shell, or embeds a file from outside its crate is a direct supply-chain
finding. A new network-capable crate is a runtime-surface finding even if the
first-party code never calls it.

### 10. Release artifact surface

**Trust:** clean build from the audited commit.

The release binary can diverge from source through a compromised build script,
linker input, appended payload, or replaced artifact. The binary audit checks
ELF structure (W^X segments, textrel, RPATH/RUNPATH), overlays and embedded
ELF/PE/ZIP/gzip/script payloads, high-entropy sections, `NEEDED` libraries,
dangerous imported symbols, and printable remote URLs/IPs/domains/telemetry
strings. A supplied `--binary` has unverified provenance. A rebuild is not
byte-reproducible, so the baseline pins invariants, not one machine's hash.

### 11. Dynamic network surface

**Trust:** isolated netns + veth, mandatory privileged capture, explicit
approval.

The dynamic harness runs the binary as the invoking user inside a dedicated
network namespace connected by a veth pair to a capture namespace. There is no
NAT and no route to the real network. `tcpdump` on the capture-side veth is
mandatory; DNS/TCP sinkholes log every query, connection, and payload preview;
the private session bus and system bus are monitored with `dbus-monitor`; and
`strace` traces every network/process/sensitive syscall from the target and its
children. `ss`/`/proc/net` snapshots corroborate the trace. The source build is
traced twice: `cargo fetch` on the host network and `cargo build --offline`
inside the veth namespace with its own pcap.

Any UDP, DNS, raw/AF_PACKET socket, IP listener, non-loopback connect (including
a failed attempt), target-sourced packet on the veth, undocumented Unix socket,
or child-process IP I/O is a finding. `--host-desktop` is a different trust
boundary: it binds the real bus/display into the netns and can drive the live
desktop, so it is opt-in and not used on an untrusted checkout.

The bundled GNOME extension is audited separately: statically, and by running
it in a nested headless GNOME Shell under a private session bus, with a mock
daemon that proves the extension loads and calls the expected interface. This
does not touch the host's extension state or live session.

## Abuse cases to check in a diff

1. **Exfiltration:** a new HTTP client, DNS lookup, UDP socket, or URL literal
   that receives config/focus/window data.
2. **Remote code execution:** download-and-run, base64/hex decode then
   `Command`, `sh -c` with kanata/config data, or installing a remote GNOME
   extension.
3. **Persistence:** writes to shell rc files, systemd units, cron, SSH
   `authorized_keys`, or system-wide autostart; a new hidden autostart path.
4. **Privilege escalation:** `sudo`/`pkexec`/polkit, setuid files, writes to
   `/etc`, systemd system units, or loading code into a more privileged process.
5. **Defense evasion / obfuscation:** bidi controls, large encoded blobs,
   dynamic `eval`, unusual build scripts, or hidden files.
6. **Supply-chain compromise:** new crate with network/telemetry behavior,
   git/path dependency, changed lockfile source, mutable CI action with
   secrets, unpinned Nix fetch, or modified release script.
7. **Local abuse:** a new unauthenticated D-Bus method that takes a command,
   path, URL, or arbitrary bytes; KDE script injection; a KWin/GNOME helper
   writing to a predictable path.
8. **Build-time execution:** a new `build.rs` that downloads, shells out,
   opens a socket, or embeds an out-of-crate binary; a proc-macro or native
   `links` crate that did not exist at baseline.
9. **Artifact tampering:** appended overlay, embedded ELF/PE, unexpected
   `NEEDED` library, remote URL string, or size blow-up in the release binary.
10. **Runtime egress:** dynamic evidence of UDP/DNS, raw/AF_PACKET, an IP
    listener, a non-loopback connect (even failed), a child-process connect, or
    an undocumented Unix socket.

## What is *not* a finding by itself

- The outbound kanata TCP connection. It is the core feature.
- Session/system D-Bus traffic for desktop integration and logind.
- `gnome-extensions`, `gsettings`, `dconf`, and `glib-compile-schemas` helper
  execution with fixed args.
- Auto-installing the **bundled** GNOME extension. It is documented behavior;
  a remote install source would be the finding.
- KDE writing generated KWin JS to a UUID-scoped `/tmp` path and cleaning it up.
- Autostart install/remove when the user explicitly asks for it.
- The GitHub clone URL in printed help text.
- Valid PNG screenshots and the static SVG joke badge.
- The ref-pinned CI action and unquoted Nix `ExecStart`: report them as
  hardening/supply-chain risks, not malware.

## Residual risks

- The session D-Bus control API has no authentication or caller verification.
- The kanata TCP connection is plaintext and unauthenticated, including when
  `--host` is remote.
- GNOME auto-install runs by default on first use; users who do not want the
  extension installed must pass `--no-install-gnome-extension`.
- KWin helper scripts live in `/tmp`; a hard kill can leave stale files.
- A poisoned `PATH` can substitute the helper binaries.
- CI actions are ref-pinned, not SHA-pinned.
- The Nix module's `ExecStart` joins args with spaces; paths/values containing
  spaces can change argument boundaries.
- Static analysis cannot prove the absence of malicious behavior in
  dependencies or in the Rust/desktop stack; use `cargo audit`/Nix tooling and
  runtime observation when the stakes justify it.
- Dependency sources not present in the local Cargo cache are inventoried but
  not deeply scanned. `cargo fetch --locked` is required for the full pass.
- The dynamic harness requires root/`sudo` and `tcpdump`; without them it fails
  closed rather than producing a syscall-only result. A host that cannot grant
  privileged namespaces/capture has no privileged dynamic evidence.
- The harness sees the paths that were exercised, not every branch. A clean
  trace is evidence, not proof; static review owns unexercised code.
- `tcpdump` sees veth traffic, not traffic that stays on loopback inside the
  daemon namespace; loopback is covered by `strace`, `ss`, and `/proc/net`.
- The DNS/TCP sinkhole is not the real Internet. A payload that requires a
  valid TLS certificate or a specific application response may stop earlier
  than it would on the real network, but the attempt is still captured.
- The GNOME audit runs in a nested headless Shell, not the user's live session;
  behavior that depends on real windows, portals, or session services may not
  be exercised.
- `--host-desktop` binds the real session bus/display and can drive the live
  desktop; it is not equivalent to the isolated default run.

## Severity mapping for this repo

| Severity | Examples |
|----------|----------|
| Critical | remote fetch-and-exec, decode-and-exec, hidden payload in an asset, active malicious git hook, replaced release artifact, non-crates.io/git/path dependency with no checksum, cached crate checksum mismatch, AF_PACKET/raw socket, non-loopback IP listener, embedded ELF/PE in the release binary, target-sourced packet on the veth, payload to the TCP sinkhole, IP activity during the offline build, sensitive D-Bus method |
| High | new remote host/outbound sink, listener on `0.0.0.0`, new exec sink with untrusted args, `pull_request_target` with secrets, unpinned Nix fetch, remote `--host` introduced silently, new network-capable/build-script dependency, lockfile/direct-dependency drift, binary overlay/unexpected NEEDED/remote URL, dynamic non-loopback/UDP/DNS/child IP I/O, DNS/TCP sinkhole contact, sensitive D-Bus destination, D-Bus URL in a method call, GNOME extension load failure, Shell-reported not enabled, or unexercised daemon interface |
| Medium | ref-pinned CI action, missing CI permissions, non-direct dependency/build-file drift, unauthenticated same-user D-Bus control, GNOME auto-install default, KWin `/tmp` writes, unquoted systemd args, new proc-macro/native dependency, undocumented Unix socket, `memfd_create`/`io_uring`/keyring/mount syscall (the GNOME Shell's `memfd_create` is a note; `DYN-MEMFD-EXEC` is critical), undocumented D-Bus destination, system-bus eavesdrop fallback, build-log URL |
| Low | documentation URLs, expected D-Bus/Unix IPC, expected helper execution, explicit autostart feature, valid images, build-id/rustc-version changes, expected libc networking symbols |
