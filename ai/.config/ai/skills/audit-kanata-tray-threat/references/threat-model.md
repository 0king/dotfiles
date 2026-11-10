# kanata-tray threat model

This document explains what "malware" would look like in this specific repo,
what is merely a design/hardening risk, and where a hidden change would most
likely hide.  It complements the network map in `network-surfaces.md`.

## 1. What the program is trusted with

kanata-tray is a local desktop utility.  A compromise or malicious change could
reach:

- The user's kanata config (keyboard layouts, macros, potentially sensitive
  strings).
- The user's environment (`os.Environ()` is passed to children; `env()` is
  exposed to the autorun expression).
- The ability to launch arbitrary local binaries (`kanata_executable`, hooks).
- The user's config directory, icons, and log files.
- The tray UI (what the user sees and clicks).
- On release, the binaries users download from GitHub.

The app does **not** need the network to perform any of its core functions.  That
makes any new outbound connection suspicious by default.

## 2. Trust boundaries

| Boundary | Trusted side | Untrusted / attacker-controlled side | What crosses it |
|----------|--------------|--------------------------------------|-----------------|
| Repo → user | Reviewed source and release artifact | A compromised checkout, dependency, CI action, or release upload | Code that runs with the user's privileges |
| Config → app | User's `kanata-tray.toml` | Anyone who can write the config dir (local attacker, sync folder, malicious preset) | Hooks, `kanata_executable`, args, env, icon paths, autorun |
| Local process → control server | kanata-tray | Any local process; a browser page via loopback HTTP | Start/stop/toggle commands |
| Child process → app | `kanata` and hooks | The configured binary/script; a compromised PATH entry | Exit status, stdout/stderr (logged), kanata TCP messages |
| GUI toolkit → app | systray/GTK/AppKit/Win32 | Platform libraries and their parsers | Menu/icon events, image decoding |
| CI → release | Maintainers | Marketplace actions, secrets, build runners, tag pushes | Binaries, checksums, release assets |
| Module proxy/VCS → build | Go toolchain + `go.sum` | Module proxy, upstream repos, `replace` targets | Compiled dependency code |

The most important line for this audit: **the repo is not allowed to send user
data anywhere.**  Local IPC is expected; remote egress is not.

## 3. Malicious behaviors to look for

### 3.1 Hidden outbound network

The highest-signal change is a new outbound sink in a code path that runs by
default:

- `net/http` `Get`/`Post`/`Do`/`NewRequest`, `net.Dial*`, `net.Lookup*`,
  `tls.Dial`, UDP `ListenPacket`/`DialUDP`, WebSocket, gRPC, SMTP, SSH, FTP.
- A hard-coded remote host, IP, or URL in runtime Go code.
- A request in `init()`, `main()`, `SystrayApp` startup, or a menu callback.
- A request fired after reading a config, environment variable, log, or icon.
- DNS-only beacons via `net.Lookup*` (easy to miss in a TCP-focused review).
- A new dependency that is an HTTP client, telemetry SDK, tunnel, proxy, or
  socket library.

What would make it credible malware rather than a feature: it is undocumented,
not gated by a config option, sends file/env data, runs on startup, or is
obfuscated/encoded.

### 3.2 Hidden process execution

`exec.CommandContext` already exists for kanata and hooks.  A malicious change
would add a **new** exec sink, especially one that:

- runs a shell with a decoded/downloaded command;
- writes an executable to a temp/config path and runs it;
- resolves a command from `PATH` unexpectedly;
- passes network response data, env secrets, or file contents as arguments;
- runs from `init()` or before the tray is ready.

The legitimate existing sink is in `runner/runner.go` and is fed by config.
`open.Start` is also expected, with local paths only.

### 3.3 Persistence

This app has no legitimate need to install itself.  Look for:

- writes to `~/.config/autostart`, systemd user units, LaunchAgents,
  `crontab`, `.bashrc`/`.zshrc`/`.profile`, Windows `Run` keys, `schtasks`;
- `LD_PRELOAD`/`/etc/ld.so.preload`;
- active `.git/hooks/*` (persistence in the developer environment);
- a new `postInstall`/`preBuild` that modifies shell startup files;
- an `autorun = true` default preset shipped in the repo's default config
  (the baseline default has no presets/hooks enabled).

### 3.4 Payload hiding

- Icons/PNGs with trailing bytes, embedded PE/ELF/ZIP/script data, or a
  magic/extension mismatch.
- Long base64/hex blobs in Go source followed by decode+exec.
- Unicode bidi control characters or invisible text in source.
- `//go:linkname`, `//go:cgo_import_dynamic`, or unexplained CGo.
- A committed binary without reproducible source.

### 3.5 Supply-chain compromise

- A new direct dependency, `replace` directive, or `go.sum` change with no
  review.
- A tag-pinned GitHub Action changed to a branch/mutable tag; a new
  `pull_request_target`; secrets exposed to PR code; release upload from a PR.
- An unpinned Nix `fetchurl`/`fetchgit`/`fetchTarball`, `builtins.fetch*`, or
  `--impure`.
- A changed `flake.lock`, `vendorHash`, or release recipe that pulls a different
  source.
- A release artifact/checksum that does not match a clean rebuild.

### 3.6 Data exfiltration through non-obvious channels

- Writing secrets into a tray tooltip/title or log that is then uploaded by a
  separate compromised process is possible but not a repo-level network path.
  The audit should still note if new code exposes env/config data in UI/logs.
- `open.Start` with a URL would hand data to a browser; current call sites pass
  only local paths.
- The control server is inbound; it does not send data out.

## 4. Design/hardening risks that are not malware

These are worth reporting, but do not call them malicious:

1. **Unauthenticated loopback control server** (`general.control_server_enable`).
   Any local process can start/stop presets.  A browser page can trigger simple
   requests (CSRF); no Host/Origin check means DNS rebinding is a concern.  It is
   off by default.  Remediation: auth token, Host/Origin validation, or a Unix
   socket.
2. **pprof build tag** exposes runtime internals on loopback.  Dev-only; exclude
   from release builds.
3. **Hooks / `kanata_executable`** are arbitrary code execution by design.  A
   malicious config is a config compromise, not repo malware.
4. **Autorun expr `env()`** can read any environment variable, but only returns a
   boolean for the autorun decision; it has no network primitive.  If the config
   is attacker-controlled, hooks are the bigger issue.
5. **Icon path traversal / arbitrary absolute icon path** lets a config read a
   local file into a tray icon.  It is local-only and does not transmit the
   bytes.
6. **`KANATA_TRAY_LOG_DIR=/tmp` in the Nix wrapper** plus `os.Create` can truncate
   a symlink target as the user.  Local symlink hardening issue.
7. **`open.Start` argument injection** if a path starts with `-`; inputs are
   local paths chosen by the app/user, not remote data.
8. **Old/unmaintained dependencies** (`getlantern/systray`, `open-golang`) are a
   maintenance/supply-chain risk, not evidence of backdooring.
9. **Tag-pinned CI actions and unsigned release artifacts** are supply-chain
   risks.  They matter because a compromised action could inject a binary into a
   release; they are not malicious code in this repo.
10. **Config dir / log dir environment overrides** are standard local attack
    surface; a local attacker who can set the environment can already run code.

## 5. Where a hidden change would most likely hide

Given the codebase, the highest-value places to diff against the baseline are:

- `main.go` startup (new network/exec before `systray.Run`).
- `app/app.go` menu callbacks and `StartProcessingLoop`.
- `app/controlserver/*` (new routes, broader bind, auth bypass, proxy).
- `runner/*` and `runner/tcp_client/*` (new host, new message payload,
  exfil through kanata TCP).
- `config/config.go` (new expression functions, hooks, env exposure).
- `status_icons/*` and `app/custom_icons.go` (asset payloads, path reads).
- `go.mod`/`go.sum` and `vendor/` (new network/telemetry dependency).
- `.github/workflows/*` and `nix/*` (build/release compromise).
- A new top-level file with `init()` or a build tag that is easy to overlook.
- A new image/binary under `status_icons/` or a new config default with
  `autorun`/hooks.

## 6. Review questions

For every suspicious hit:

1. Does the file's documented purpose require this behavior?
2. Is it gated by a config option or build tag, and what is the default?
3. Is the endpoint loopback or remote?  Is TLS/auth present?
4. What data leaves the process, and where does it come from?
5. Is the value hard-coded, config-derived, env-derived, file-derived, or
   network-derived?
6. Is there a legitimate existing equivalent in the baseline?  If yes, why is
   this one different?
7. Does the change also add a dependency, CI action, Nix fetch, or asset?  If
   so, review the whole chain, not just the Go line.
8. Could a local unprivileged attacker trigger it, or does it require the user
   to enable/click something?

## 7. Verdict language

Use precise language in the report:

- **Malware finding** — intentional hidden behavior: remote fetch-and-execute,
  decode-and-execute, exfiltration, persistence, payload in an asset, tampered
  release.
- **Security finding** — a real weakness without malicious intent:
  unauthenticated local control server, pprof in release, symlink log write,
  missing CI permissions.
- **Supply-chain finding** — mutable CI actions, unsigned artifacts, unpinned
  fetch, dependency drift.
- **Expected/dismissed** — documented hook execution, loopback IPC, GUI IPC,
  documentation URLs, `$schema`, valid icons.

Mixing these categories is the most common audit mistake for this repo.
