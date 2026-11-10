---
name: audit-kanata-tray-threat
description: >-
  Audit the kanata-tray repository (Go + Nix + GitHub Actions tray wrapper for
  kanata) for hidden malware, backdoors, persistence, risky process execution,
  and supply-chain threats, and produce a complete inventory of every network
  request/connection it can make over any protocol. Use when the user asks to
  audit this repo, asks "is kanata-tray safe", asks what network connections it
  makes, wants a threat model or pre-install review, or asks to re-check a
  newer checkout/PR against the pinned clean baseline.
---

# kanata-tray Threat & Network Audit

Repo-specific audit workflow.  It combines a static scanner, a pinned network
and execution baseline, and a manual review pass.  The goal is to detect
*changes* that introduce hidden behavior, not to re-litigate the documented
features of the application.

**Default target:** `/media/d_drive/dev/local-builds/kanata-tray`
**Audited baseline:** commit `138545c` (`138545c67bf66a7cf6507e85ea62fc3234cbf0e2`), 2026-11-10
**Baseline does not auto-trust newer commits.** Re-run the scanner and review
every diff after this commit before calling a checkout clean.

## What this repo is

A small Go program that puts a tray icon in front of the `kanata` keyboard
remapper.  It launches `kanata` as a child process, talks to kanata's local TCP
server, optionally exposes a local HTTP control server, and runs user-configured
hooks.  It is a desktop tray app, not a network service.  It must never need
outbound internet access at runtime.

The audit has two independent questions:

1. **Is there hidden malicious behavior?** (backdoor, exfiltration, persistence,
   payload drop, obfuscation, compromised dependency/CI).
2. **What network I/O exists, on every protocol?** (including loopback IPC and
   non-IP mechanisms, so a "no network" answer is accurate and complete).

## Step 1 — Confirm scope and authorization

- Confirm the path.  If it is not the path above, ask before scanning.
- Confirm whether the user wants **static review only** (default) or also
  **runtime verification**.  Never execute an untrusted checkout, hook, or
  release binary without explicit permission and an isolated environment.
- Note whether dependencies (`vendor/`, module cache) and CI/release files are
  in scope.  They are part of the supply-chain answer even when runtime code is
  clean.
- Check the checkout identity first:

```bash
git -C <repo> remote -v
git -C <repo> status --porcelain=v1 -b
git -C <repo> log -5 --oneline --decorate
git -C <repo> diff --stat
```

A dirty tree, a changed remote, or a single unexplained new commit is a review
event.  The pinned baseline assumes upstream `rszyma/kanata-tray`.

## Step 2 — Run the static scanner

From this skill directory:

```bash
SKILL=~/.config/ai/skills/audit-kanata-tray-threat
python3 "$SKILL/scripts/scan_kanata_tray.py" <repo> \
  --json /tmp/opencode/kanata-tray-audit.json --verbose
```

Useful flags:

- `--include-deps` — scan `vendor/` too (no-op here unless vendoring is added).
- `--fail-on high` — exit non-zero at high/critical; useful for CI/PR checks.
- `--json` — full result for machine comparison; the terminal summary is for
  humans.

The scanner is stdlib-only Python and does not execute the repo.  It:

- Enumerates Go network sinks (`net`, `net/http`, `net/http/pprof`, `crypto/tls`,
  websocket/gRPC/SMTP/SSH/FTP, raw syscalls) with direction, endpoint, and
  endpoint class (loopback / all-interfaces / remote / unix).
- Enumerates process-execution sinks (`os/exec`, `os.StartProcess`, `open-golang`,
  `syscall.Exec/ForkExec`).
- Compares both lists with `references/network-baseline.json`.
- Flags remote host literals in runtime Go code.
- Checks `go.mod` direct dependencies, `replace` directives, `go.sum` drift, and
  hashes of build files.
- Checks GitHub Actions for mutable action refs, `pull_request_target`,
  `write-all`, missing permissions, and fetch-pipe-to-shell.
- Checks Nix for unpinned fetches, `--impure`, custom substituters, and
  network/decode-to-shell in build phases.
- Inspects committed images for magic/extension mismatch, trailing bytes, and
  embedded executable/archive/script signatures; flags committed binaries.
- Checks active `.git/hooks`, insecure git remotes, hardcoded secrets,
  persistence strings, bidi-control characters, and decode+exec combinations.

Read the JSON; do not just copy the summary.  The scanner is recall-biased and
will produce false positives (especially CI tag pins and documentation URLs).

## Step 3 — Verify the network inventory against the baseline

The expected runtime surface is small.  Confirm each item is still present,
still loopback-only, and still gated the same way:

| ID | Direction | Protocol | Endpoint | Gate | Data |
|----|-----------|----------|----------|------|------|
| `control-server-inbound-http` | inbound | HTTP/1.1 over TCP | `127.0.0.1:${control_server_port:-8100}` | `general.control_server_enable = true` (default **false**) | Preset start/stop/toggle commands; JSON status |
| `pprof-inbound-http` | inbound | HTTP/1.1 over TCP | `localhost:6060` | `go build -tags pprof` (not default) | `/debug/pprof` runtime profiles |
| `kanata-tcp-client-outbound` | outbound | newline-delimited JSON over TCP | `localhost:${tcp_port:-5829}` | when a preset starts kanata | `RequestLayerNames` out; layer/reload events in |
| GUI IPC (dependency) | local IPC | D-Bus / Unix socket / X11 / Wayland; Win32 messages; Cocoa/Mach | platform-specific | app start | Tray menu/icon events |
| OS opener (dependency) | local process | `xdg-open` / `open` / `rundll32` | local file or folder path | user clicks "Open logs"/"Configure" | No URL is passed by this repo |

**Expected:** no runtime HTTP client, no DNS lookups to external names, no UDP,
no TLS, no SMTP/SSH/FTP/WebSocket/gRPC, no auto-update, no telemetry.  The only
TCP activity is loopback: kanata's port, the optional control server, and the
optional pprof server.  `localhost` resolution may consult the OS resolver for
`localhost`, but should not generate external DNS traffic.

If the scanner reports **any** of these, stop and triage as a finding:

- a network sink not in the baseline (`NET-UNEXPECTED-SINK`);
- a baseline endpoint changed from `loopback` to `all-interfaces`/`remote`
  (`NET-ENDPOINT-CHANGED`);
- a remote host literal in Go code (`NET-REMOTE-HOST`);
- a new exec sink (`EXEC-UNEXPECTED-SINK`);
- a direct dependency change (`DEP-NEW-DIRECT`, `SUPPLY-FILE-DRIFT`).

Baseline matching is by file + direction + protocol family, not line number, so
moved code is flagged as missing/unexpected for manual review.  That is
intentional.

## Step 4 — Manual repo-specific review

Do not rely on the scanner alone.  Check these in the actual checkout:

| Area | What to verify |
|------|----------------|
| **Entry point / config** | `main.go` reads `KANATA_TRAY_CONFIG_DIR`, `KANATA_TRAY_LOG_DIR`; creates a log file and changes cwd.  No hidden startup branch, no network before tray init. |
| **Control server** | `app/controlserver/tcp_control_server.go` binds `127.0.0.1` only; routes are the documented six; no auth, no TLS, any HTTP method.  Confirm it is gated by `general.control_server_enable` and default false. |
| **Kanata TCP client** | `runner/tcp_client/tcp_client.go` dials `localhost:<tcp_port>` only.  Host must stay hard-coded.  JSON messages are the documented three. |
| **pprof** | `pprof.go` must stay behind `//go:build pprof`; `localhost:6060` only; never included in release builds. |
| **Process execution** | `runner/runner.go` `exec.CommandContext` runs the configured `kanata` binary and config hooks.  This is arbitrary local code by design.  Look for new call sites, shell wrappers, downloaded executables, or arguments derived from network data. |
| **Hooks** | `config/config.go` turns hook strings into `/bin/sh -c` (or the configured `cmd_template`).  A malicious config is equivalent to code execution; that is not malware in the repo, but it is the main trust boundary.  Default config has no hooks. |
| **Autorun DSL** | `expr-lang/expr` evaluates config strings with `env()`, OS booleans, and hostname.  It is not Go `eval` and has no network functions.  Check for new environment variables or functions exposed to the expression. |
| **Openers** | `app/app.go` calls `open.Start` only on the config folder, the tray log, and a per-preset temp log.  No preset name or remote URL reaches the opener. |
| **Config/icon reads** | `app/custom_icons.go` and `status_icons/status_icons.go` read local files chosen by config.  Absolute/relative paths are allowed; file contents become tray icon bytes.  No exfil path. |
| **Dependencies** | Compare direct modules with `references/network-baseline.json`; check for `replace`, new pseudo-versions, `getlantern/*` additions, and any HTTP/telemetry/gRPC/socket library.  `getlantern/systray` is GUI-only; its `example/` and `webview_example/` are not imported. |
| **CI / release** | Actions are tag-pinned, not SHA-pinned (known medium risk).  Check for `pull_request_target`, secrets in PR-triggered jobs, `curl \| bash`, artifact upload from PRs, and release jobs that publish unsigned binaries. |
| **Nix** | `flake.lock` pins nixpkgs with `rev` + `narHash`; `vendorHash` is pinned.  Check for new `fetchurl`/`fetchgit` without hashes, `builtins.fetch*`, `--impure`, or network in `postInstall`/build phases. |
| **Assets** | Icons are embedded via `//go:embed` and copied to the config dir.  Verify PNG/ICO magic, no trailing data, no embedded PE/ELF/ZIP/script, and hashes match the baseline. |
| **Git metadata** | No active `.git/hooks/*` beyond `*.sample`; remote is SSH (`git@github.com:...`), not `http://`/`git://`; no unexpected submodules. |

Useful manual greps:

```bash
rg -n 'net\.|net/http|http\.|Dial|Listen|Lookup|Resolve|syscall\.(Socket|Connect|Bind|Listen)|tls\.|websocket|grpc|smtp|ssh\.|ftp\.' --glob '*.go' <repo>
rg -n 'exec\.|os\.StartProcess|syscall\.(Exec|ForkExec)|open\.(Start|Run)' --glob '*.go' <repo>
rg -n 'os\.Getenv|os\.Environ|os\.ReadFile|os\.WriteFile|os\.Create|os\.OpenFile' --glob '*.go' <repo>
rg -n 'curl|wget|base64|eval|chmod \+x|/bin/sh|powershell' .github nix justfile <repo>
```

## Step 5 — Optional runtime verification

Only with user approval, in an isolated VM/container, with no secrets mounted and
egress blocked or captured.  Static review is usually sufficient for this repo;
runtime is for confirming a suspicious diff or validating the inventory.

Linux example:

```bash
# Terminal 1: capture every network syscall from the app and its children.
strace -ff -e trace=network -o /tmp/kt-net.log -- \
  env KANATA_TRAY_CONFIG_DIR=/tmp/kt-config go run . --log-level=1

# Terminal 2: list listeners/connections owned by the process tree.
ss -ltnp | grep -E '8100|5829|6060'
lsof -p <pid> -a -i
ss -lunp                       # confirm no UDP listeners

# Loopback + all-interface capture.
sudo tcpdump -ni lo  -s0 -w /tmp/kt-lo.pcap
sudo tcpdump -ni any -s0 -w /tmp/kt-any.pcap
```

Trigger each path and re-check:

1. Start idle: no connections except GUI IPC.
2. Start a preset: one TCP connection to `localhost:5829`.
3. Enable `control_server_enable = true`, restart, `curl` each route: one
   listener on `127.0.0.1:8100`; no outbound connection.
4. Build with `-tags pprof`, request `/debug/pprof/`: listener on
   `localhost:6060` only.
5. Click "Open logs"/"Configure": child `xdg-open`/`open`/`rundll32` with a
   local path, no URL.
6. Do **not** run untrusted hooks.  If testing hooks, use a harmless command
   that writes a marker file and confirm no unexpected child network activity.

Expected: only `127.0.0.1` / `::1` endpoints; no external IPs, no external DNS,
no TLS, no UDP.  If you see anything else, map it to a process/file/line and
treat it as a finding.

Windows/macOS equivalents: `netstat -ano` + TCPView + Wireshark on Windows;
`lsof -i`, `nettop`, `tcpdump` on macOS.  GUI IPC (named pipes, Mach ports,
D-Bus, X11/Wayland) is local and is not IP traffic.

## Step 6 — Triage and report

Use this structure:

```markdown
# Threat Audit: kanata-tray @ <commit>

**Scope:** <path, clean/dirty, deps included Y/N, static/runtime>
**Overall risk:** Critical / High / Medium / Low / Clean

## Summary
2–4 sentences: hidden behavior found or not; network surface; headline
recommendation (e.g. "safe modulo tag-pinned CI actions", "do not run this
checkout", "baseline drift at X").

## Network inventory
| Direction | Protocol | Endpoint | Gate | Data | Assessment |
|-----------|----------|----------|------|------|------------|
(fill from scanner + manual verification; include "none" for protocols absent)

## Findings

### Critical
**<rule id> — <description>**
`path:line`
```
<minimal snippet>
```
Why this matters here: <context, data flow, whether it is reachable by default>.
What to confirm: <maintainer question or remediation>.

(repeat High / Medium / Low)

## Reviewed and dismissed
One line per scanner hit that is legitimate, with the reason (expected hook,
localhost-only listener, documentation URL, CI tag pin, icon file, etc.).

## Baseline drift
List unexpected/changed/missing sinks and exec sinks; state whether the pinned
baseline still applies.

## Limits of this audit
Static/heuristic, not a sandbox or proof; no CVE/dependency-vulnerability scan;
runtime not performed unless stated; `--include-deps` state; GUI/OS code and
compiler/runtime behavior are out of scope.
```

### Severity rubric for this repo

- **Critical** — remote fetch-and-execute, decode-then-execute, hidden payload
  in an image/asset, hardcoded credential with an exfil path, release artifact
  replaced, active malicious git hook.
- **High** — new remote host or outbound sink not in baseline; listener changed
  to `0.0.0.0`; new exec sink; `pull_request_target` with secrets/PR code;
  unpinned Nix fetch without hash; pprof included in a release build; control
  server reachable off-host.
- **Medium** — tag-pinned GitHub Actions; missing `permissions:`; dependency or
  build-file drift; control server enabled without auth (local CSRF/hardening);
  plain HTTP on loopback; new opener path.
- **Low** — documentation URLs, `$schema` fetch by an editor, expected hooks,
  expected `kanata`/`open` execution, local GUI IPC, valid committed icons.

Adjust by context, but keep the distinction between **malware** and
**hardening/design risk** explicit.  A local unauthenticated control server is
a real security issue, not evidence of malicious intent.  Hooks and
`kanata_executable` are arbitrary code execution by design.

### Known false positives / dismissed-by-default

- `net/http` in `app/controlserver` is an inbound loopback server, not an
  outbound client.
- `net.Dialer` to `localhost` is the kanata IPC, expected.
- `pprof.go` is build-tag-gated and absent from normal builds.
- `exec.CommandContext` in `runner/runner.go` is the documented kanata/hooks
  runner; it is not a hidden downloader.
- `open.Start` receives local paths only.
- `getlantern/systray` and `getlantern/golog` are GUI/logging libraries; no
  network calls in the imported package.  The `getlantern` name is not a signal
  by itself.
- `$schema = https://raw.githubusercontent.com/...` is consumed by TOML editors,
  not by the running binary.
- URLs in `README.md`, `doc/`, comments, and `config_schema.json` are
  documentation.
- `go.sum` contains base64-looking hashes; they are not secrets.
- `status_icons/*.ico`/`*.png` are valid images with no trailing payload.
- CI action tag pins are a supply-chain risk, not malware; report them as
  medium and note the mitigation.

## Reference files

- `references/network-baseline.json` — pinned expected network/exec inventory,
  direct modules, file hashes, and documented non-IP IPC.
- `references/network-surfaces.md` — detailed protocol/data-flow map and
  runtime-verification notes.
- `references/threat-model.md` — trust boundaries, attack surfaces, and
  repo-specific abuse cases.
- `scripts/scan_kanata_tray.py` — the static scanner used above.
