---
name: audit-golang-localhost-dynamic
description: >-
  Comprehensive generic audit skill for a golang-based repository, covering
  static analysis (module graph, vendored deps, network sink scan, CGO/native
  audit, binary artifact scan) and dynamic/runtime network analysis (tcpdump,
  ss, /proc/net/*, Xvfb). Produces a documented network inventory plus residual
  risk under a localhost-only constraint. Use for any Go repo you want to audit
  for hidden network behavior, malware, persistence, or supply-chain risk.
---

# Generic Golang Localhost-Dynamic Network Audit

Reusable audit workflow for any Go repository. It combines a static scanner, a
pinned network/exec baseline, a manual review pass, and required dynamic runtime
analysis. The goal is to produce a defensible inventory of every network
request/connection the binary can make (any protocol, any socket layer), plus an
honest statement of what cannot be ruled out.

**Default target:** `<repo path>` — confirm with the user before scanning.
**Localhost-only constraint:** the app must not send or receive any traffic to/
from non-localhost addresses (127.0.0.0/8, ::1, Unix domain sockets only). Any
observed non-localhost socket, packet, or connection is a finding.
**OS target:** Linux only (document Windows/macOS systray surface as out of scope).
**Build:** `CGO_ENABLED=1 go build` (most tray/GUI Go apps need CGO).

## What this skill answers

1. **Is there hidden malicious behavior?** (backdoor, exfiltration, persistence,
   payload drop, obfuscation, compromised dependency/CI).
2. **What network I/O exists, on every protocol?** (including loopback IPC and
   non-IP mechanisms, so a "no network" answer is accurate and complete).

**Bottom line:** you cannot guarantee completeness (encryption, runtime-computed
destinations, CGO/native code, toolchain injection, future compromised deps). You
can achieve high-coverage static inventory plus empirical confirmation via dynamic
analysis, but not a proof of absence. Acceptance criterion = a documented network
inventory + residual-risk list, not a guarantee.

## Step 1 — Confirm scope and authorization

- Confirm the repo path. If it is not the expected path, ask before scanning.
- Confirm whether the user wants **static review only** (default) or also
  **runtime verification**. Never execute an untrusted checkout, hook, or release
  binary without explicit permission and an isolated environment.
- Note whether dependencies (`vendor/`, module cache) and CI/release files are
  in scope — they are part of the supply-chain answer even when runtime code is
  clean.
- Check the checkout identity first:

```bash
git -C <repo> remote -v
git -C <repo> status --porcelain=v1 -b
git -C <repo> log -5 --oneline --decorate
git -C <repo> diff --stat
```

A dirty tree, a changed remote, or an unexplained new commit is a review event.

## Step 2 — Enumerate the module graph and vendor dependencies

```bash
# 1. Capture every direct + transitive module and version.
go -C <repo> list -m all > /tmp/go-mod-graph.txt

# 2. Commit go.sum; pin versions; disallow `go get -u` in prod builds.
#    go.sum must match vendored modules (go mod verify).

# 3. Vendor dependencies and commit the vendor tree so builds are reproducible
#    and independent of the public module proxy.
go -C <repo> mod vendor
```

All subsequent static scans run against `vendor/` (what actually gets compiled).

## Step 3 — Static source scan for network APIs (all protocols/layers)

Run the scanner from this skill directory:

```bash
SKILL=~/.config/ai/skills/audit-golang-localhost-dynamic
python3 "$SKILL/scripts/scan_golang_network.py" <repo> \
  --vendor <repo>/vendor \
  --json /tmp/golang-audit.json --verbose
```

Useful flags:

- `--include-deps` — scan `vendor/` too.
- `--fail-on high` — exit non-zero at high/critical; useful for CI/PR checks.
- `--json` — full result for machine comparison; terminal summary is for humans.

The scanner is stdlib-only Python and does not execute the repo. It:

- Enumerates Go network sinks (`net`, `net/http`, `net/http/pprof`, `crypto/tls`,
  `net/rpc`, websocket/gRPC/SMTP/SSH/FTP, raw syscalls) with direction, endpoint,
  and endpoint class (loopback / all-interfaces / remote / unix).
- Enumerates process-execution sinks (`os/exec`, `os.StartProcess`,
  `syscall.Exec/ForkExec`).
- Compares both lists with `references/network-baseline.json`.
- Flags remote host literals in runtime Go code.
- Checks `go.mod` direct dependencies, `replace` directives, `go.sum` drift, and
  hashes of build files.
- Checks GitHub Actions for mutable action refs, `pull_request_target`,
  `write-all`, missing permissions, and fetch-pipe-to-shell.
- Inspects committed images/assets for magic/extension mismatch, trailing bytes,
  and embedded executable/archive/script signatures; flags committed binaries.
- Checks active `.git/hooks`, insecure git remotes, hardcoded secrets,
  persistence strings, bidi-control characters, and decode+exec combinations.

Record each call site, file:line, protocol family (AF_INET/AF_INET6/AF_UNIX/
AF_PACKET), socket type, and any string-literal destination (host/IP/port/URL).
Flag any string-literal or computed destination that is not localhost
(127.0.0.0/8, ::1, Unix domain socket) as a finding. Flag runtime-computed
destinations (env vars, config fields, DNS lookups) as "unresolvable statically."

Manual greps to cross-check:

```bash
rg -n 'net\.|net/http|http\.|Dial|Listen|Lookup|Resolve|syscall\.(Socket|Connect|Bind|Listen)|tls\.|websocket|grpc|smtp|ssh\.|ftp\.' --glob '*.go' <repo>
rg -n 'exec\.|os\.StartProcess|syscall\.(Exec|ForkExec)' --glob '*.go' <repo>
rg -n 'os\.Getenv|os\.Environ|os\.ReadFile|os\.WriteFile|os\.Create|os\.OpenFile' --glob '*.go' <repo>
rg -n 'curl|wget|base64|eval|chmod \+x|/bin/sh|powershell' .github nix justfile <repo>
```

Read the JSON; do not just copy the summary. The scanner is recall-biased and will
produce false positives (especially CI tag pins and documentation URLs).

## Step 4 — CGO / native dependency audit

- Identify all C/C++/assembly/syso files pulled into the build (primarily via
  GUI toolkit deps such as `getlantern/systray`).
- Scan native sources for socket/syscall/network APIs at all layers:
  `socket`, `connect`, `bind`, `sendto`, `recvfrom`, `setsockopt`, `ioctl`,
  `SOCK_RAW`, `AF_PACKET`, `AF_INET`, `AF_INET6`, `AF_UNIX`, `IPPROTO_*`,
  `WinInet`, `WinHTTP`, `libcurl`, `libpcap`, `BPF`, `ioctl(SIOCGIF*)`,
  `ioctl(SIOCSIFFLAGS)`.
- Document that native binaries cannot be fully verified by Go source scan.

## Step 5 — Binary-level network artifact scan

- Build the binary: `CGO_ENABLED=1 go build -o <binary> .`
- Run `strings`/`nm`/`objdump` or a binary scanner (trivy/syft/grype) on the
  artifact to find embedded IPs, domains, URLs, and network-related imports/
  symbols (including raw-socket symbols: `socket`, `connect`, `sendto`,
  `recvfrom`, `setsockopt`, `ioctl`, `pcap_open`, `libnet`, `libpcap`).
- Compare against static source findings; delta = native-only or linker-introduced
  network surface.

## Step 6 — Dynamic / runtime network analysis (required — all protocols, all sockets)

Prerequisites: `go`, `gcc`, `tcpdump`, `ss`, `xvfb` (install if missing).

Linux example:

```bash
# Terminal 1: packet capture at the link layer upward (all protocols).
sudo tcpdump -i any -s 0 -w /tmp/capture.pcap &

# Terminal 2: socket enumeration before launch.
ss -tulpn; ss -tulnp; ss -x; ss -s
cat /proc/net/{tcp,tcp6,udp,udp6,raw,raw6,netlink,unix}

# Give the tray a display session (X11 only; not Wayland).
Xvfb :99 -screen 0 1024x768x16 &
export DISPLAY=:99

# Build and run in an isolated environment (container/VM), no secrets mounted.
CGO_ENABLED=1 go build -o <binary> .
env <app-env-vars> ./<binary>

# Exercise UI paths: open menus, click items, hit any local HTTP endpoints.
# Leave running ≥5 min to catch delayed/periodic beacons.

# Stop tcpdump, then parse.
sudo tcpdump -r /tmp/capture.pcap -nn

# Re-enumerate sockets during and after exercise.
ss -tulpn; ss -tulnp; ss -x
cat /proc/net/{tcp,tcp6,udp,udp6,raw,raw6,netlink,unix}
```

Cross-correlate pcap packets with socket table entries by local address:port and
pid. Record every observed connection/socket/packet: timestamp, src/dst IP:port,
protocol (IP protocol number + transport), socket type, state, pid, DNS name
resolved.

Enforce localhost-only: any socket, packet, or connection with a remote address
outside 127.0.0.0/8, ::1, or a Unix domain socket is a failing finding. Merge
observed destinations/sockets into the inventory. Any socket or packet not in the
static inventory is a finding to investigate.

Windows/macOS equivalents: `netstat -ano` + TCPView + Wireshark (Windows);
`lsof -i`, `nettop`, `tcpdump` (macOS). Named pipes, Mach ports, D-Bus, X11/
Wayland sockets are local IPC, not IP traffic.

## Step 7 — Document findings

Report structure:

```markdown
# Network Audit: <repo> @ <commit>

**Scope:** <path, clean/dirty, deps included Y/N, static/runtime>
**Overall risk:** Critical / High / Medium / Low / Clean

## Summary
2–4 sentences: hidden behavior found or not; network surface; headline
recommendation.

## Network inventory
| ID | Direction | Protocol | Endpoint | Gate | Data | Confidence |
|----|-----------|----------|----------|------|------|------------|
(fill from scanner + manual verification; include "none" for absent protocols)

## Findings
### Critical
**<rule id> — <description>**
`path:line`
```
<minimal snippet>
```
Why this matters here: <context, data flow, reachability>.
What to confirm: <remediation>.

(repeat High / Medium / Low)

## Reviewed and dismissed
One line per scanner hit that is legitimate, with the reason.

## Baseline drift
List unexpected/changed/missing sinks and exec sinks; state whether the baseline
still applies.

## Limits of this audit
Static/heuristic, not a sandbox or proof; runtime not performed unless stated;
GUI/OS code and compiler/runtime behavior out of scope.
```

## Validation / acceptance criteria

- Every static network call site (all protocol families, socket types, raw-socket
  syscalls) has a corresponding inventory row.
- `go.sum` matches vendored modules (`go mod verify`).
- Binary artifact contains no unexpected embedded IP/domain strings or raw-socket
  symbols beyond the inventory.
- Dynamic run captures: (a) every packet at link layer upward via tcpdump pcap
  (any IP protocol number, Ethernet type), (b) every socket via `ss` and
  `/proc/net/*` (tcp/tcp6/udp/udp6/raw/raw6/netlink/unix), cross-correlated by
  address:port and pid.
- All observed sockets/packets/connections must be localhost-only
  (127.0.0.0/8, ::1, Unix domain socket). Any non-localhost traffic is a failing
  finding.
- Any socket, packet, or connection not in the static inventory is a finding and
  investigated.

## Resolved decisions / defaults

- Dynamic runtime analysis: in scope, using tcpdump.
- Xvfb: in scope for GUI/tray apps (X11 only; not Wayland).
- OS target: Linux only.
- Build toolchain: Go + gcc; `CGO_ENABLED=1` required for GUI/systray apps.
- Socket inspection: `ss` + `/proc/net/*`.
- localhost-only constraint: any socket/packet/connection outside
  127.0.0.0/8, ::1, or Unix domain socket is a failing finding.

## Severity rubric

- **Critical** — remote fetch-and-execute, decode-then-execute, hidden payload
  in an asset, hardcoded credential with an exfil path, release artifact replaced,
  active malicious git hook.
- **High** — new remote host or outbound sink not in baseline; listener changed
  to `0.0.0.0`; new exec sink; `pull_request_target` with secrets/PR code;
  unpinned fetch without hash; pprof in a release build; control server reachable
  off-host.
- **Medium** — tag-pinned CI actions; missing `permissions:`; dependency or
  build-file drift; control server enabled without auth (local CSRF); plain HTTP
  on loopback; new opener path.
- **Low** — documentation URLs, `$schema` fetch by an editor, expected hooks,
  expected local execution, local GUI IPC, valid committed icons.

Keep the distinction between **malware** and **hardening/design risk** explicit.

## Known false positives / dismissed-by-default

- `net/http` in an inbound loopback server is not an outbound client.
- `net.Dialer` to `localhost` is expected loopback IPC.
- `pprof` behind a build tag is absent from normal builds.
- `exec.CommandContext` feeding a documented local binary/hooks runner.
- `open.Start` receiving local paths only.
- GUI libraries (`systray`, etc.) with no network calls in imported packages.
- `$schema = https://...` consumed by editors, not the binary.
- URLs in `README.md`, `doc/`, comments, config schemas are documentation.
- `go.sum` base64-looking hashes are not secrets.
- Valid committed icons with no trailing payload.
- CI action tag pins are a supply-chain risk, not malware; report as medium.

## Reference files

- `references/network-baseline.json` — pinned expected network/exec inventory,
  direct modules, file hashes, and documented non-IP IPC. Re-derive per repo.
- `references/network-surfaces.md` — detailed protocol/data-flow map and
  runtime-verification notes. Adapt per repo.
- `references/threat-model.md` — trust boundaries, attack surfaces, and repo-
  specific abuse cases. Adapt per repo.
- `scripts/scan_golang_network.py` — the static scanner used above.
