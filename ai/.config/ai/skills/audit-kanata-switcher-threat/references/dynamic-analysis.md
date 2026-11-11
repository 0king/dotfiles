# Dynamic Network Analysis

This document defines how `scripts/run_dynamic_network_audit.sh` produces
runtime evidence for kanata-switcher, what it can and cannot prove, and how to
read the analyzer output.

## Contract

The application is treated as offline. The only permitted IP traffic is the
documented kanata control connection to `{host}:{port}` (default
`127.0.0.1:10000`). Loopback is `127.0.0.0/8`, `::1`, and IPv4-mapped loopback.
Documented local IPC is D-Bus (session/system bus), Wayland, and X11 over Unix
sockets. Everything else is a finding, including a **failed** connect attempt:
the attempt itself proves intent and code path.

Forbidden even on loopback:

- UDP and DNS (port 53) traffic;
- raw sockets and `AF_PACKET` layer-2 access;
- IP listeners (`bind`/`listen`) and accepted inbound connections;
- a child process performing IP I/O;
- undocumented Unix socket paths;
- `bpf`, kernel module load, `ptrace`, namespace changes, `memfd_create`,
  `io_uring`, keyring, mount, `pivot_root`, and `chroot` unless reviewed.

`AF_NETLINK` is local kernel IPC (address/route enumeration), not IP egress. It
is reported as informational. `socketpair(AF_UNIX)` is internal IPC and is not
a socket path.

## Isolation model

The default run is rootless:

```
bwrap --unshare-net --unshare-pid --unshare-ipc --unshare-uts \
  --die-with-parent --new-session \
  --ro-bind / / --dev /dev --proc /proc --tmpfs /tmp \
  --bind <out> <out> --tmpfs /dev/shm \
  --setenv HOME <out>/home --setenv XDG_RUNTIME_DIR <out>/runtime \
  -- dbus-run-session -- <out>/inner.sh ...
```

- `--unshare-net` creates a network namespace with only `lo`; there is no route
  to a remote network. A non-loopback `connect()` fails locally but is still
  traced.
- A private session bus is started with `dbus-run-session`; the daemon does not
  see the real session bus in the default scenario.
- `HOME`, `XDG_CONFIG_HOME`, `XDG_CACHE_HOME`, `XDG_DATA_HOME`,
  `XDG_RUNTIME_DIR`, and `TMPDIR` point inside the output directory. The host
  home is read-only at most.
- The output directory is the only writable bind. The rest of `/` is read-only.
- No secrets are mounted by the harness. The caller is still responsible for
  not passing a secret-bearing environment or command.

`--scenario host-desktop` is a different trust boundary. It keeps the network
namespace but uses the real `DBUS_SESSION_BUS_ADDRESS`, `$XDG_RUNTIME_DIR`,
`$DISPLAY`, and `$WAYLAND_DISPLAY`, and binds `/tmp/.X11-unix` read-only. It can
drive the live desktop and must not be used on an untrusted checkout without a
disposable session. The harness still passes `--no-install-gnome-extension`.

The harness does **not** install the GNOME extension, does not run
`gnome-extensions enable`, and does not use the real session bus by default.

## Build provenance

For the default daemon run the harness:

1. resolves `--commit` or `HEAD`;
2. exports a clean tree with `git archive` into `<out>/src`;
3. runs `cargo fetch --locked` (the only step allowed to use the network);
4. builds with `cargo build --release --locked --offline` into `<out>/target`;
5. records commit, tag, dirty status, lockfile SHA-256, binary SHA-256, cargo
   and rustc versions in `meta.json`.

A dirty working tree is recorded but not executed. `--binary PATH` copies a
supplied artifact and records its hash; provenance is then unverified.
`--skip-build` requires an existing `<out>/target/release/kanata-switcher`.

## Capture

`strace -ff -ttt -s 512 -v` traces the daemon and every child/thread. The
syscall set is:

```
%network,%process,openat,open,memfd_create,io_uring_setup,io_uring_enter,
io_uring_register,bpf,init_module,finit_module,ptrace,unshare,setns,keyctl,
add_key,request_key,mount,pivot_root,chroot
```

`%network` covers `socket`, `socketpair`, `connect`, `bind`, `listen`,
`accept`, `sendto`, `recvfrom`, `sendmsg`, `recvmsg`, `getsockname`,
`getpeername`, `setsockopt`, and related calls. `%process` covers `execve`,
`clone`, `fork`, `vfork`, and exits.

While the daemon runs, the inner script snapshots:

- `ss -tanp`, `ss -uanp`, `ss -lxnp`;
- `/proc/net/{tcp,tcp6,udp,udp6,packet,netlink,unix,raw,raw6}`.

`ss` and `/proc/net` are corroboration, not the primary attribution: the
namespace also contains the mock kanata listener and the private D-Bus daemon.
The analyzer allows a loopback listener on the configured mock port and does
not attribute it to kanata-switcher.

## Mock kanata

`scripts/mock_kanata.py` binds `127.0.0.1:<port>` and speaks the small
newline-delimited JSON subset:

- sends `{"LayerChange":{"new":"default"}}` on connect;
- answers `RequestLayerNames` with
  `{"LayerNames":{"names":["default","browser","terminal","vim"]}}`;
- answers `RequestFakeKeyNames` with
  `{"FakeKeyNames":{"names":["vk_browser","vk_terminal","vk_vim"]}}`;
- logs `ChangeLayer` and `ActOnFakeKey` messages.

`--legacy` simulates an older kanata that does not understand
`RequestFakeKeyNames` (it returns an error and closes). The harness uses the
normal mode.

## Analyzer rules

| Rule | Severity | Meaning |
|------|----------|---------|
| `DYN-NONLOOPBACK-CONNECT` | high | connect/send to an address outside loopback; includes failed attempts |
| `DYN-LOOPBACK-UNEXPECTED` | high | loopback traffic to a port other than the expected kanata port |
| `DYN-UDP` | high | UDP socket or sendto/recvfrom |
| `DYN-DNS` | high | port 53 traffic |
| `DYN-AF-PACKET` | critical | `AF_PACKET` socket or operation |
| `DYN-RAW-SOCKET` | critical | `SOCK_RAW` socket |
| `DYN-IP-BIND` | high/critical | explicit IP bind; critical for wildcard/non-loopback |
| `DYN-LISTEN` | high | `listen()` syscall observed |
| `DYN-SS-LISTENER` / `DYN-PROCNET-LISTENER` | high/critical | listener evidence in `ss` / `/proc/net` |
| `DYN-IP-ACCEPT` | high | accepted inbound IP connection |
| `DYN-UNIX-UNEXPECTED` | medium | Unix socket path not in the documented globs |
| `DYN-UNIX-LISTENER` | high | daemon-created Unix listener |
| `DYN-NETLINK` | info | local kernel IPC |
| `DYN-OTHER-FAMILY` | high | `AF_VSOCK`, `AF_BLUETOOTH`, `AF_XDP`, `AF_CAN`, etc. |
| `DYN-SUSPICIOUS-SYSCALL` | medium/high/critical | bpf, module load, ptrace, namespace, memfd, io_uring, keyring, mount |
| `DYN-SENSITIVE-FILE` | high | opened SSH/AWS/GPG/shadow/key material |
| `DYN-NETWORK-TOOL-EXEC` | high | curl/wget/nc/ssh/scp/rsync/dig/... executed |
| `DYN-SHELL-EXEC` | high | `sh -c`/`bash -c` executed |
| `DYN-UNEXPECTED-EXEC` | medium | daemon executed a command not in `expected_exec` |
| `DYN-CHILD-IP-NETWORK` | high | a child process performed IP I/O |
| `DYN-KANATA-MISSING` | high | no connection to the expected endpoint in daemon mode |
| `DYN-KANATA-NO-CONNECT` | high | mock kanata saw no connection |
| `DYN-KANATA-TOO-FEW-CONNECTS` / `DYN-KANATA-TOO-MANY-CONNECTS` | medium | connection count outside `expected_connect_min`/`max` |
| `DYN-KANATA-CONNECT-FAILED` | medium | expected endpoint was attempted but failed |
| `DYN-PROCNET-*` / `DYN-SS-*` | high/critical | corroborating socket-table evidence |
| `DYN-MOCK-*` | low/medium/high | malformed or unexpected mock-kanata protocol traffic |

`connect()` returning `-1 EINPROGRESS` or `-1 EALREADY` on a non-blocking
socket is in progress, not a failure. `DYN-KANATA-CONNECT-FAILED` is emitted
only for terminal errno values; a failed expected connection also shows up as
`DYN-KANATA-NO-CONNECT` because the mock never sees it.

`--fail-on` defaults to `medium`, so informational `DYN-NETLINK` does not fail a
clean run. Use `--fail-on info` for a maximally strict review.

## Expected clean result

For v1.2.0 in `baseline` or `minimal` scenario:

- exactly one TCP connection from the daemon to `127.0.0.1:<port>`;
- no IP listener owned by the daemon (the mock's own listener is allowed);
- no UDP, DNS, raw, or `AF_PACKET` activity;
- no non-loopback endpoint, successful or failed;
- D-Bus traffic on the private session bus and, if the system bus is reachable,
  read-only logind traffic;
- no undocumented Unix socket;
- no child IP network;
- no shell or network-tool execution; auto-install is disabled by
  `--no-install-gnome-extension`, and any GNOME helper execution is limited to
  the reviewed commands in `expected_exec`.

The mock log should show exactly one `connect` event, the initial
`LayerChange`, and the expected `RequestLayerNames` / `RequestFakeKeyNames`
exchange. More than one connection is a reconnect event and is reported by
`DYN-KANATA-TOO-MANY-CONNECTS`. A `RequestFakeKeyNames` error is not expected in
normal mode; it is the `--legacy` behavior.

## Negative controls

`scripts/selftest_dynamic.sh` runs five probes under the same isolation and one
clean probe:

| Probe | Expected rule |
|-------|---------------|
| connect to `192.0.2.1:9` | `DYN-NONLOOPBACK-CONNECT` |
| UDP sendto `127.0.0.53:53` | `DYN-UDP` (and `DYN-DNS`) |
| `socket(AF_PACKET, SOCK_RAW)` | `DYN-AF-PACKET` |
| bind/listen `127.0.0.1:0` | `DYN-IP-BIND` |
| fork child connect to `192.0.2.1:9` | `DYN-CHILD-IP-NETWORK` |
| no-op Python | status 0, no findings at `medium` |

If a control does not fail, the analyzer or harness is broken. Do not treat a
green target run as meaningful until the controls pass.

## Privileged corroboration (optional)

The default harness is rootless and does not capture packets. If the user wants
packet-level evidence, run one of these **as root** around the same harness:

```bash
# Full packet capture in the host namespace. The bwrap netns is separate, so
# capture on the host side of the veth/bridge, or run tcpdump inside the
# namespace with `bwrap ... -- tcpdump ...` if the tool is available there.
sudo tcpdump -i any -nn -s0 -w /tmp/opencode/ks.pcap

# Syscall-level corroboration with bpftrace (root).
sudo bpftrace -e 'tracepoint:syscalls:sys_enter_connect { printf("%d %s\n", pid, comm); }'
```

Record the command, interface, and time window in the report. Do not claim
packet capture from a rootless run. `tshark` is optional; `tcpdump -r` is enough
to list endpoints.

## Limits

- The trace covers the executed paths, not every branch. A clean run does not
  prove unexercised code is clean.
- `strace` can miss data that never reaches a syscall (e.g., a library that
  computes a payload but is never invoked).
- The default scenario uses a private bus and no real compositor. GNOME/KDE/
  Wayland/X11 focus paths may not be exercised; use `host-desktop` only with
  explicit approval.
- `ss`/`/proc/net` are snapshots; a short-lived socket between snapshots may be
  missed. The syscall trace is the primary record.
- The namespace shares the host kernel. Kernel-level compromise is out of scope.
- The mock server is not kanata; protocol differences can change behavior. It
  implements the subset used by the integration tests.
- A supplied `--binary` may have unverified provenance even if the trace is
  clean.
- The harness does not install the GNOME extension and does not test the
  extension's runtime network behavior inside GNOME Shell. That is a separate
  disposable-VM test.

## Troubleshooting

- `bwrap: Creating new namespace failed`: user namespaces are disabled; use a
  disposable VM or a privileged namespace with explicit approval.
- `dbus-run-session: command not found`: install `dbus-daemon`/`dbus-tools`, or
  use `--scenario host-desktop` with an existing session bus (opt-in).
- `cargo fetch` fails: the build step needs network or a pre-populated
  `CARGO_HOME`; the runtime step itself remains offline.
- No strace logs: check `<out>/daemon/stderr.log` and the bwrap exit status.
- `DYN-KANATA-MISSING`: the daemon may have exited before connecting (missing
  config, unknown environment). Check stdout/stderr and `meta.json`.
- `DYN-UNIX-UNEXPECTED` for a path that is actually documented: add a precise
  glob to `dynamic_policy.allowed_unix_socket_globs` only after reviewing the
  path; do not add a broad `/tmp/*` or `/run/*` glob.
- `DYN-PROCNET-LISTENER` for the mock port: confirm it is `127.0.0.1:<port>`;
  the analyzer already allows that case. A wildcard listener is a real finding.

## Re-baselining

After reviewing a diff:

1. Build from the new commit and run the harness in `baseline` and `minimal`.
2. Run `selftest_dynamic.sh`; all controls must still fail and the clean probe
   must pass.
3. Update `dynamic_policy` / `expected_dynamic` only for reviewed changes
   (new documented Unix socket, new expected endpoint, new expected helper).
4. Never add a broad Unix glob or allow UDP/raw/non-loopback traffic to silence
   a finding.
5. Record the harness version (commit of the skill) and the binary hash in the
   report.
