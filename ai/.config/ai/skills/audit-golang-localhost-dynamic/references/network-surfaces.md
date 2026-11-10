# Generic golang network surfaces

Template for mapping every network-capable path in a golang repository. Adapt
file names, symbols, and line numbers to the repo under audit. This is a static
source review, not a runtime capture.

## Executive summary template

| Direction | Transport | Endpoint | Default | Protocol | Purpose |
|-----------|-----------|----------|---------|----------|---------|
|           |           |          |         |          |         |

There should be no outbound HTTP client, external DNS, UDP, TLS, SMTP, SSH, FTP,
WebSocket, gRPC, telemetry, or auto-update code unless documented and gated.

## 1. Inbound servers

Document each listener: file, symbol, bind address (must be 127.0.0.1/localhost/
::1 or a Unix socket), port, gate (config flag / build tag), protocol, auth,
routes, request data, response data, and risk. Confirm no listener binds to
0.0.0.0 or an empty host.

## 2. Outbound clients

Document each outbound connection: file, symbol, destination (host/IP/port),
gate, protocol, TLS, data sent, data received. Host must be localhost-only unless
explicitly documented and approved. Flag any runtime-computed destination as
"unresolvable statically."

## 3. Process execution

Document each exec sink: file, API (`exec.CommandContext`, `os.StartProcess`,
`syscall.Exec`), command class, whether input can be network-derived, and risk.

## 4. CGO / native / GUI dependencies

Document GUI toolkits and native code (C/C++/asm/syso). Note platform-specific
IPC mechanisms (D-Bus/X11/Wayland on Linux, Cocoa/Mach on macOS, Win32 on
Windows) and confirm they are local IPC, not IP traffic. Note that native code
cannot be fully verified by Go source scan.

## 5. Build-time and CI network

Document network that occurs at build/CI time: module proxy downloads, Nix
fetches, CI action runtime, artifact publishing. Confirm pins (go.sum, flake.lock
narHash, action SHAs).

## 6. What would change the verdict

Treat any of these as a new finding:
- A new network import or call site.
- A host other than localhost/127.0.0.1/::1 in runtime code.
- A listener changed to 0.0.0.0/empty.
- A network request in init()/main()/startup with no documented gate.
- A new go.mod direct dependency, replace, or go.sum change without review.
- A CI action on a mutable ref, a new pull_request_target, a secret exposed to
  PR code, or a release step downloading/executing an artifact.
- An unpinned Nix fetch, builtins.fetch*, --impure, or a new substituter.
- An asset with trailing bytes, embedded PE/ELF/ZIP/script, or magic mismatch.
- An active .git/hooks/*, a new submodule, or a remote changed to http:///git://.

## 7. Runtime verification cheat sheet

Run only with explicit permission, in an isolated VM/container, with no secrets
and network capture/egress control:

```bash
sudo tcpdump -i any -s 0 -w /tmp/capture.pcap &
ss -tulpn; ss -tulnp; ss -x; ss -s
cat /proc/net/{tcp,tcp6,udp,udp6,raw,raw6,netlink,unix}
Xvfb :99 -screen 0 1024x768x16 &
export DISPLAY=:99
CGO_ENABLED=1 go build -o <binary> .
env <app-env> ./<binary>
# exercise UI paths, wait >= 5 min
sudo tcpdump -r /tmp/capture.pcap -nn
```

Expected: only 127.0.0.1/::1/Unix-domain endpoints; no external IPs, no external
DNS, no TLS, no UDP. Map anything else to a process/file/line and treat as a
finding.
