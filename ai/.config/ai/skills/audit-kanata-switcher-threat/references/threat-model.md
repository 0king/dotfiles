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
- `Cargo.lock` at baseline has 212 crates.io-only packages and no git/path
  sources.
- `flake.lock` and `tests/flake.lock` pin GitHub inputs with `rev` + `narHash`;
  `tests/flake.lock` also has a path input to `..`.
- The only CI workflow uses `7mind/github-env@minimal`, has
  `permissions: contents: read`, no `pull_request_target`, no secrets, and no
  release publish. The action is ref-pinned, not SHA-pinned: a real but
  accepted medium supply-chain risk.
- `build.rs` copies the bundled GNOME extension/schema into `OUT_DIR` and runs
  `glib-compile-schemas`. It does not fetch network data.

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

## Severity mapping for this repo

| Severity | Examples |
|----------|----------|
| Critical | remote fetch-and-exec, decode-and-exec, hidden payload in an asset, active malicious git hook, replaced release artifact |
| High | new remote host/outbound sink, listener on `0.0.0.0`, new exec sink with untrusted args, `pull_request_target` with secrets, unpinned Nix fetch, remote `--host` introduced silently |
| Medium | ref-pinned CI action, missing CI permissions, dependency/build-file drift, unauthenticated same-user D-Bus control, GNOME auto-install default, KWin `/tmp` writes, unquoted systemd args |
| Low | documentation URLs, expected D-Bus/Unix IPC, expected helper execution, explicit autostart feature, valid images |
