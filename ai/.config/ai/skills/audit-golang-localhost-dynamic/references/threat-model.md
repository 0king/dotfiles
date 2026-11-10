# Generic golang threat model

This document explains what "malware" would look like in a golang repository,
what is merely a design/hardening risk, and where a hidden change would most
likely hide.

## 1. What the program is trusted with

A compromise or malicious change could reach:
- User config and data files.
- The user's environment (passed to child processes).
- The ability to launch arbitrary local binaries.
- Local files chosen by config.
- The UI the user sees and clicks.
- Released binaries users download.

The app should not need the network to perform its core functions. Any new
outbound connection is suspicious by default.

## 2. Trust boundaries

| Boundary | Trusted side | Untrusted side | What crosses it |
|----------|--------------|----------------|-----------------|
| Repo → user | Reviewed source + artifact | Compromised checkout, dep, CI, release upload | Code running with user privileges |
| Config → app | User config | Anyone who can write config dir | Hooks, executable paths, args, env |
| Local process → server | App | Any local process / browser via loopback | Commands sent to local server |
| Child process → app | Configured binary/script | Compromised PATH entry | Exit status, stdout/stderr |
| GUI toolkit → app | Platform libraries | Platform parsers | Menu/icon events, image decoding |
| CI → release | Maintainers | Marketplace actions, secrets, runners | Binaries, checksums, assets |
| Module proxy → build | Go toolchain + go.sum | Module proxy, upstream repos, replace targets | Compiled dependency code |

The most important line: the repo is not allowed to send user data anywhere.
Local IPC is expected; remote egress is not.

## 3. Malicious behaviors to look for

### 3.1 Hidden outbound network
- `net/http` Get/Post/Do/NewRequest, `net.Dial*`, `net.Lookup*`, `tls.Dial`,
  UDP `ListenPacket`/`DialUDP`, WebSocket, gRPC, SMTP, SSH, FTP.
- A hard-coded remote host, IP, or URL in runtime Go code.
- A request in `init()`, `main()`, startup, or a menu callback.
- DNS-only beacons via `net.Lookup*`.
- A new dependency that is an HTTP client, telemetry SDK, tunnel, proxy, or
  socket library.

Credible malware signals: undocumented, not gated by config, sends file/env
data, runs on startup, or is obfuscated/encoded.

### 3.2 Hidden process execution
- A new exec sink running a shell with a decoded/downloaded command.
- Writing an executable to temp/config and running it.
- Resolving a command from PATH unexpectedly.
- Passing network response data, env secrets, or file contents as arguments.
- Running from `init()` or before the app is ready.

### 3.3 Persistence
- Writes to autostart dirs, systemd user units, LaunchAgents, crontab,
  `.bashrc`/`.zshrc`/`.profile`, Windows Run keys, `schtasks`.
- `LD_PRELOAD`/`/etc/ld.so.preload`.
- Active `.git/hooks/*`.
- A new `postInstall`/`preBuild` modifying shell startup files.

### 3.4 Payload hiding
- Icons/PNGs with trailing bytes, embedded PE/ELF/ZIP/script, magic mismatch.
- Long base64/hex blobs in Go source followed by decode+exec.
- Unicode bidi control characters or invisible text in source.
- `//go:linkname`, `//go:cgo_import_dynamic`, unexplained CGo.
- A committed binary without reproducible source.

### 3.5 Supply-chain compromise
- A new direct dependency, replace directive, or go.sum change without review.
- A tag-pinned GitHub Action changed to a branch/mutable tag; a new
  `pull_request_target`; secrets exposed to PR code; release upload from a PR.
- An unpinned Nix `fetchurl`/`fetchgit`/`fetchTarball`, `builtins.fetch*`, or
  `--impure`.
- A changed lock file or release recipe pulling a different source.
- A release artifact/checksum that does not match a clean rebuild.

### 3.6 Data exfiltration through non-obvious channels
- Writing secrets into UI/tooltips/logs later uploaded by a separate process.
- `open.Start` handed a URL.
- Any channel that moves local data off-host.

## 4. Design/hardening risks that are not malware

- Unauthenticated loopback server (local CSRF, DNS rebinding).
- pprof build tag exposing internals.
- Hooks / configurable executable = arbitrary code execution by design.
- Expression language exposing env() or host data.
- Arbitrary absolute file reads into UI assets.
- Log dir in /tmp with symlink risk.
- Old/unmaintained dependencies (maintenance risk, not backdoor evidence).
- Tag-pinned CI actions and unsigned release artifacts (supply-chain risk).
- Config/log dir environment overrides (standard local surface).

## 5. Where a hidden change would most likely hide

- `main.go` startup (new network/exec before app init).
- Server handler files (new routes, broader bind, auth bypass, proxy).
- Client/connectors files (new host, new payload, exfil).
- Config files (new expression functions, hooks, env exposure).
- Asset/icon files (payloads, path reads).
- `go.mod`/`go.sum`/`vendor/` (new network/telemetry dependency).
- CI workflows and Nix files (build/release compromise).
- A new top-level file with `init()` or an easy-to-overlook build tag.
- A new image/binary under assets or a new default config with autorun/hooks.

## 6. Review questions

For every suspicious hit:
1. Does the file's documented purpose require this behavior?
2. Is it gated by a config option or build tag, and what is the default?
3. Is the endpoint loopback or remote? Is TLS/auth present?
4. What data leaves the process, and where does it come from?
5. Is the value hard-coded, config-derived, env-derived, file-derived, or
   network-derived?
6. Is there a legitimate existing equivalent? If yes, why is this different?
7. Does the change also add a dependency, CI action, Nix fetch, or asset?
8. Could a local unprivileged attacker trigger it, or does it require the user
   to enable/click something?

## 7. Verdict language

- **Malware finding** — intentional hidden behavior: remote fetch-and-execute,
  decode-and-execute, exfiltration, persistence, payload in an asset, tampered
  release.
- **Security finding** — a real weakness without malicious intent:
  unauthenticated local server, pprof in release, symlink log write, missing CI
  permissions.
- **Supply-chain finding** — mutable CI actions, unsigned artifacts, unpinned
  fetch, dependency drift.
- **Expected/dismissed** — documented hook execution, loopback IPC, GUI IPC,
  documentation URLs, $schema, valid icons.
