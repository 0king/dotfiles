# Dynamic Network Analysis

This document defines how the privileged harnesses produce runtime evidence for
kanata-switcher, what the evidence can and cannot prove, and how to read the
analyzer output.

The dynamic layer is deliberately **not** a rootless convenience run:

- `tcpdump` packet capture is mandatory;
- the target runs in a real network namespace behind a veth pair;
- DNS and TCP sinkholes log every egress attempt;
- the private session bus and the system bus are monitored with `dbus-monitor`;
- the source build is traced both on the host network and inside the veth
  namespace;
- the GNOME extension is audited statically and inside a nested headless Shell.

If root/`sudo`, `tcpdump`, or a required monitor is unavailable, the harness
exits with status 2. It never silently downgrades to a syscall-only trace.

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

A cooperating local service can turn an allowed Unix socket into remote egress.
That is why D-Bus destinations, methods, and message payloads are audited
separately from IP traffic.

## Privileged preflight (fail closed)

The harness requires:

| Requirement | Why |
|-------------|-----|
| root or `sudo` | create network namespaces, veth pair, and run `tcpdump` |
| `tcpdump` | packet-level evidence; a syscall trace alone can miss kernel/protocol behavior |
| `ip` | namespace and veth management |
| `setpriv` | drop from root to the invoking uid/gid inside the namespace |
| `bwrap` | pid/ipc/uts/mount isolation without unsharing the network namespace |
| `strace` | syscall attribution for the target and every child/thread |
| `dbus-monitor` / `dbus-daemon` | session and system bus evidence |
| `ss` | socket-table snapshots |
| `python3` | sinkholes, mocks, analyzer |
| `cargo` / `rustc` / `git` | source build (unless `--binary` or `--skip-build`) |
| `gnome-shell` / `gjs` / `gsettings` / `glib-compile-schemas` | GNOME extension audit (`--gnome-extension`) |

Preflight behavior:

- If `sudo -n true` works, the harness uses `sudo -n`.
- Otherwise, with a TTY it runs `sudo -v` once. Without a TTY it exits 2.
- `--check` performs the same root/tool preflight and prints versions, then
  exits 0. It does **not** bypass the root requirement.
- A missing or empty pcap (fewer than 24 bytes, the libpcap file header) is a
  harness error, not a clean result.
- A missing sinkhole log, session monitor log, or expected system monitor log is
  an analyzer finding.

`--allow-unmonitored-system-bus` is the only override. Use it only on a host
that genuinely has no system bus, and record the exception in the report.

## Isolation topology

The harness creates two namespaces per run:

```
host
├── capture netns (ks-c-*, 10.213.0.1/24, fd42:6b73:6175:6469::1/64)
│   ├── veth capture side (kc*)
│   ├── tcpdump -i kc* -nn -s0 -U -w <out>/pcap/daemon.pcap
│   └── DNS/TCP sinkholes, running as the invoking uid
└── daemon netns (ks-d-*, 10.213.0.2/24, fd42:6b73:6175:6469::2/64)
    ├── veth daemon side (kd*), default route via the capture side
    ├── private dbus-daemon (socket under <out>/dbus/session.sock)
    ├── mock kanata on 127.0.0.1:<port>
    └── bwrap (pid/ipc/uts/mount only, no --unshare-net)
        └── target, running as the invoking uid via setpriv
```

Properties:

- The daemon namespace has no route to the real network. Its default route
  points at the capture namespace, which has no forwarding and no default
  route. Packets cannot leave the veth pair.
- IPv6 link-local generation, router solicitation, autoconf, and DAD are
  disabled so IPv6 packets are attributable to the target.
- `ip_forward` and IPv6 forwarding are disabled in both namespaces.
- The capture namespace has no NAT. The sinkhole answers only from its own
  addresses.
- The target is **not** root. `setpriv --reuid=<uid> --regid=<gid>
  --init-groups` drops privileges before the target starts.
- `bwrap` deliberately does **not** use `--unshare-net`; it inherits the
  root-created daemon namespace. It does unshare pid/ipc/uts, mounts a
  read-only `/`, a private `/tmp`, a private `/dev/shm`, and binds the output
  directory writable.
- `HOME`, `XDG_CONFIG_HOME`, `XDG_CACHE_HOME`, `XDG_DATA_HOME`, `TMPDIR`, and
  (except in `host-desktop`) `XDG_RUNTIME_DIR` point inside the output
  directory. The host home is read-only at most.
- The private session bus socket lives at `<out>/dbus/session.sock`, inside the
  writable output bind, so it remains visible inside `bwrap`. The bus config
  allows the test user, name ownership, method calls, signals, returns, errors,
  and eavesdropping.

The GNOME audit uses a second, independent pair (`ksg-d-*`/`ksg-c-*`,
`10.214.0.0/24` and `fd42:6b73:6773:6e6f::/64`) with the same properties.

`--scenario host-desktop` is a different trust boundary. It keeps the network
namespace but uses the real `DBUS_SESSION_BUS_ADDRESS`, `$XDG_RUNTIME_DIR`,
`$DISPLAY`, and `$WAYLAND_DISPLAY`, and binds `/tmp/.X11-unix` read-only. It can
drive the live desktop and must not be used on an untrusted checkout without a
disposable session. The harness still passes `--no-install-gnome-extension`.

## Packet capture

`netns_admin.sh capture-start` runs:

```bash
ip netns exec <capture-ns> tcpdump -i <capture-if> -nn -s 0 -U -w <pcap>
```

The pcap is mandatory for every privileged run:

- daemon/command profile: `pcap/daemon.pcap` must exist and contain at least
  the libpcap header;
- GNOME profile: at least one pcap file must exist;
- build tracing: `pcap/build.pcap` must exist when `build_traced` is true.

Attribution is by source MAC **or** source IP:

- `meta.json` records the daemon-side MAC, capture-side MAC, and the
  daemon/capture IPv4 and IPv6 addresses;
- a packet whose source MAC equals the daemon MAC, or whose source IP equals a
  daemon address, is treated as target egress;
- because the expected kanata connection is loopback, any packet sourced from
  the daemon MAC/IP on the veth is unexpected egress. The packet does not need
  to be routable or successful.

The analyzer parses `tcpdump -nn -tttt -e -v -r` text output. With `-v`,
tcpdump prints IP header details on the first line and the transport line
indented underneath; the parser joins continuation lines before matching. It
does not require `tshark`.

Rules:

| Rule | Severity | Meaning |
|------|----------|---------|
| `DYN-PCAP-MISSING` | critical (daemon/command), high (GNOME) | privileged capture was promised but no pcap exists |
| `DYN-BUILD-PCAP-MISSING` | high | build tracing was enabled but `build.pcap` is missing |
| `DYN-PCAP-TCP` | high | target-sourced TCP packet |
| `DYN-PCAP-UDP` | high | target-sourced UDP packet |
| `DYN-PCAP-DNS` | high | target-sourced TCP/UDP port 53 packet |
| `DYN-PCAP-DNS-QUERY` | high | DNS question extracted from a captured packet |
| `DYN-PCAP-ICMP` | high | target-sourced ICMP |
| `DYN-PCAP-ARP` | medium | target-sourced ARP |
| `DYN-PCAP-NDP` | medium | target-sourced ICMPv6/neighbor discovery |
| `DYN-PCAP-NON-IP` | high | unknown/non-IP ethertype sourced by the target |
| `DYN-BUILD-PCAP-EGRESS` | critical | any packet sourced by the target during the offline build |

A clean pcap contains only capture-side traffic (DNS answers, TCP sinkhole
responses, ARP from the capture side) or no packets at all. The analyzer notes
the packet count.

## DNS and TCP sinkholes

`scripts/capture_sinkhole.py` runs in the capture namespace as the invoking
uid. It makes the isolated network look usable without forwarding anything:

- DNS over UDP and TCP on port 53, IPv4 and IPv6;
- every A query is answered with the capture address (`10.213.0.1` by default);
- every other query type gets NOERROR/NODATA;
- every query is logged to `net/dns.jsonl`;
- TCP listeners on common service ports (21, 22, 25, 80, 110, 143, 443, 465,
  587, 993, 995, 1080, 3128, 5222, 5228, 8080, 8443, 8888, 9418 by default);
- each accepted connection is logged to `net/tcp.jsonl`;
- up to 64 KiB per connection is read; the first 512 bytes are kept as a text
  preview and the first 128 bytes as hex;
- a TCP connection that sends data is the highest-signal event: it proves the
  target tried to speak a protocol, not merely resolve a name.

`netns_admin.sh setup` writes `/etc/netns/<daemon-ns>/resolv.conf` and
`/etc/netns/<capture-ns>/resolv.conf` pointing at the sinkhole addresses.
`ip netns exec` bind-mounts those files over `/etc/resolv.conf`, so a host
resolver stub such as `127.0.0.53` cannot silently swallow queries inside the
namespace. Teardown removes the per-namespace files.

The sinkhole logs are independent evidence from the pcap. A missing log is a
finding; an existing but empty log is a clean result.

| Rule | Severity | Meaning |
|------|----------|---------|
| `DYN-SINKHOLE-MISSING` | high | `dns.jsonl` or `tcp.jsonl` is absent |
| `DYN-SINKHOLE-DNS` | high | a DNS query reached the sinkhole |
| `DYN-SINKHOLE-TCP` | high | a TCP connection reached the sinkhole |
| `DYN-SINKHOLE-DATA` | critical | payload bytes were sent to the sinkhole |

## D-Bus monitoring

The harness starts a private `dbus-daemon` from a generated config. The socket
is under the output directory, and the address is
`unix:path=<out>/dbus/session.sock`. `dbus-monitor --address ...` records the
session traffic to `dbus/session.monitor.log`.

When `/run/dbus/system_bus_socket` exists, the harness starts
`dbus-monitor --system` **as root** and records `dbus/system.monitor.log`. A
user-level monitor cannot become a full monitor on the system bus; it falls
back to eavesdropping. The harness records that state as
`eavesdrop-fallback` and the analyzer emits `DYN-DBUS-SYSTEM-EAVESDROP`
(medium) because coverage is incomplete. If the monitor cannot start and
`--allow-unmonitored-system-bus` was not passed, the harness exits 2.

Policy is in `dynamic_policy.dbus`:

- **Allowed destinations** are documented desktop integration endpoints
  (`org.freedesktop.DBus`, logind, GNOME Shell, the daemon's names, and the
  GNOME extension interface). Unknown destinations are medium findings in
  daemon/command mode.
- **Sensitive destinations** are high in daemon/command mode: portals, systemd,
  NetworkManager, resolve1, Avahi, ModemManager, Telepathy, Secret Service,
  UDisks2, UPower, BlueZ, OnlineAccounts, Evolution, KWin, and GNOME Shell.
  In the GNOME profile they are notes (see below).
- **Sensitive methods** are critical regardless of destination: `OpenURI`,
  `Launch`, `Spawn`, `StartUnit`, `StopUnit`, `RestartUnit`, `Reload`,
  `PowerOff`, `Reboot`, `Suspend`, `Hibernate`, `SetLinkUp`,
  `ActivateConnection`, `ResolveHostname`, `SetDNS`, `Eval`, `Call`, and the
  related list in the baseline.
- **Read-only allowlist** suppresses reviewed property/info calls:
  `org.gnome.Shell` may use `Get`, `GetAll`, `GetExtensionInfo`,
  `ListExtensions`, and `GetExtensionState`;
  `org.gnome.Shell.Extensions` may use `Get`, `GetAll`, `GetExtensionInfo`,
  and `ListExtensions`.
- **logind** allows `GetSession`, `GetSessionByPID`, `GetUser`, `GetUserByPID`,
  `Get`, and `GetAll`. Any other logind method is high.
- **URLs in D-Bus method calls** are high, even to an otherwise allowed
  destination. A URL passed to a portal is a classic launch/exfiltration path.
  In the GNOME profile, URLs in method returns or broadcast metadata signals
  are notes: core Shell extension metadata legitimately contains project URLs.
  Only URLs the Shell/extension sends outward in a method call are actionable.

In the `gnome-extension` profile, sensitive destinations are recorded as notes
instead of failures, because a nested Shell activates and talks to many core
desktop services on its own and the monitor cannot attribute a call to the
extension rather than to the Shell. Sensitive methods, logind methods outside
the allowlist, and URLs in method calls still fail. New extension D-Bus
destinations are caught by the static scanner and its baseline drift rules.
This keeps the dynamic extension audit focused on behavior rather than Shell
startup noise.

| Rule | Severity | Meaning |
|------|----------|---------|
| `DYN-DBUS-MONITOR-MISSING` | high | expected session or system monitor log is missing |
| `DYN-DBUS-SYSTEM-EAVESDROP` | medium | system monitor fell back to eavesdropping |
| `DYN-DBUS-SYSTEM-UNAVAILABLE` | info | explicit `--allow-unmonitored-system-bus` override |
| `DYN-DBUS-SYSTEM-ABSENT` | info | no system bus socket on this host |
| `DYN-DBUS-SENSITIVE-DEST` | high (daemon/command); note (gnome-extension) | call to a sensitive destination |
| `DYN-DBUS-SENSITIVE-METHOD` | critical | call to a sensitive method |
| `DYN-DBUS-UNEXPECTED-DEST` | medium | undocumented destination in daemon/command mode |
| `DYN-DBUS-METHOD` | medium | unexpected `org.freedesktop.DBus` method |
| `DYN-DBUS-LOGIND-METHOD` | high | logind method outside the read-only allowlist |
| `DYN-DBUS-URL` | high (method call); note (GNOME metadata) | URL sent outward in a D-Bus method call |

## Build tracing

For a source run the harness:

1. resolves `--commit` or `HEAD`;
2. exports a clean tree with `git archive` into `<out>/src` (a dirty working
   tree is recorded in `meta.json` but not executed);
3. runs `cargo fetch --locked` on the host network under
   `strace -ff -e trace=%network`, writing `build/fetch.strace.*`;
4. starts `tcpdump` on the capture-side veth;
5. runs `cargo build --release --locked --offline` **inside the daemon
   namespace** as the invoking uid, under `strace -ff -e trace=%network`,
   writing `build/build.strace.*` and `pcap/build.pcap`;
6. records commit, tag, dirty status, lockfile SHA-256, binary SHA-256, cargo
   and rustc versions, trace syscalls, and monitor state in `meta.json`.

`cargo fetch` is the only step allowed to use the real network. Its trace is
checked against `build_time_network`:

- expected ports: 53, 80, 443;
- expected hosts: `crates.io`, `index.crates.io`, `static.crates.io`,
  `github.com`, `codeload.github.com`, `objects.githubusercontent.com`;
- a `connect`/`sendto` to any other port is high;
- a `bind`/`listen`/`accept` during fetch is high;
- a fetch log URL outside the allowed hosts is high.

The offline build is different: **any** `AF_INET`/`AF_INET6` socket,
`connect`, `bind`, `listen`, `accept`, or send/receive event is critical. A
build script or proc macro that phones home is exactly what this layer exists
to catch. The build log is also scanned for URLs (medium, because build output
can echo a URL without fetching it), and `build.pcap` must contain no packet
sourced by the daemon namespace (critical).

| Rule | Severity | Meaning |
|------|----------|---------|
| `DYN-BUILD-FETCH-TRACE-MISSING` | high | `build_traced` is set but fetch strace is missing |
| `DYN-BUILD-TRACE-MISSING` | high | `build_traced` is set but build strace is missing |
| `DYN-BUILD-FETCH-EGRESS` | high | fetch used an unexpected port |
| `DYN-BUILD-FETCH-LISTENER` | high | fetch opened a listener |
| `DYN-BUILD-FETCH-URL` | high | fetch log contacted an undocumented host |
| `DYN-BUILD-SCRIPT-EGRESS` | critical | offline build used an IP socket |
| `DYN-BUILD-SCRIPT-URL` | medium | offline build log contains a URL |
| `DYN-BUILD-PCAP-EGRESS` | critical | offline build emitted a packet |

`--skip-build` requires an existing `<out>/target/release/kanata-switcher`.
`--binary PATH` copies a supplied artifact and records its hash; provenance is
then unverified, and build tracing is skipped.

## Runtime tracing

`strace -ff -ttt -s 512 -v` traces the target and every child/thread. The base
syscall set is:

```
%network,%process,openat,open,memfd_create,io_uring_setup,io_uring_enter,
io_uring_register,bpf,init_module,finit_module,ptrace,unshare,setns,keyctl,
add_key,request_key,mount,pivot_root,chroot
```

The harness probes and adds these when supported:
`openat2`, `execveat`, `pidfd_getfd`, `process_vm_readv`, `process_vm_writev`,
`sendmmsg`, `recvmmsg`, `sendfile`, `splice`, `ioctl`.

Coverage details:

- `%network` includes `socket`, `socketpair`, `connect`, `bind`, `listen`,
  `accept`, `accept4`, `sendto`, `recvfrom`, `sendmsg`, `recvmsg`,
  `getsockname`, `getpeername`, and `setsockopt`.
- `sendmmsg`/`recvmmsg`, `sendfile`, and `splice` are tied back to the
  `socket()` family by file descriptor, so a payload sent through those calls
  is still attributed to IP.
- `%process` includes `execve`, `clone`, `fork`, `vfork`, and exits. Child
  PIDs are compared with the main target PID; a child performing IP I/O is
  `DYN-CHILD-IP-NETWORK`.
- `openat`/`open` are checked for sensitive files (SSH keys, cloud
  credentials, GPG, shadow, key material).
- Namespace changes, `bpf`, module load, `ptrace`, `io_uring`, keyring, mount,
  `pivot_root`, and `chroot` are suspicious-syscall findings.
- `memfd_create` is a finding in daemon/command/build traces. In the
  `gnome-extension` profile it is a note, because Mutter, Mesa, GLib,
  PulseAudio, and the Wayland cursor cache legitimately create memfds for
  dmabuf/GL/anonymous data and the extension runs in the Shell process.
  Executing from a memfd is still critical: `DYN-MEMFD-EXEC` fires for
  `execveat` on a tracked memfd or on a `/proc/self/fd/` path.

While the target runs, a snapshot loop records:

- `ss -tanp`, `ss -uanp`, `ss -lxnp`;
- `/proc/net/{tcp,tcp6,udp,udp6,packet,netlink,unix,raw,raw6}`.

`ss` and `/proc/net` are corroboration, not primary attribution: the namespace
also contains the mock kanata listener and the private D-Bus daemon. The
analyzer allows a loopback listener on the configured mock port and reports
every other listener.

## Modes and scenarios

| Option | Behavior |
|--------|----------|
| default (daemon) | build the audited commit, run the daemon with a mock kanata server |
| `--binary PATH` | audit a supplied artifact; provenance unverified |
| `--command 'CMD'` | run a probe under the same isolation; used by the harness selftest |
| `--skip-build` | reuse `<out>/target/release/kanata-switcher` |
| `--scenario baseline` | private session bus, `XDG_CURRENT_DESKTOP=GNOME`, SNI enabled, no extension install |
| `--scenario minimal` | no desktop environment variables, `--no-indicator` |
| `--scenario host-desktop` | opt-in; real session bus, display, and runtime dir |
| `--gnome-extension` | also run the nested GNOME Shell audit |
| `--keep-netns` | retain namespaces for manual inspection (cleanup is then manual) |

Daemon mode passes `--host`, `--port`, `--dbus-suffix audit`, and
`--no-install-gnome-extension`. The harness calls `GetStatus` over the private
session bus to exercise the control service. The mock kanata server logs
connections and protocol messages.

`--command` mode skips daemon/mock expectations and allows the command's own
executable plus the `bash -c` wrapper the harness uses to launch it. A shell
spawned later by the probe is still `DYN-SHELL-EXEC`. Daemon mode still checks
every exec.

## GNOME extension audit

`scripts/run_gnome_extension_audit.sh` is a separate privileged harness. It:

1. runs `scan_gnome_extension.py` on the extension source;
2. copies the extension into a private **system** data directory
   (`<out>/sysdata/gnome-shell/extensions/...`) and compiles its schema, so the
   Shell loads it as a system extension while `allow-extension-installation`
   stays false;
3. creates its own veth pair, sinkholes, and packet capture;
4. starts a private session bus inside the daemon namespace;
5. pre-enables `kanata-switcher@7mind.io` with the GSettings keyfile backend,
   disables every other system mode extension, and disables the
   `extensions.gnome.org` update check;
6. starts `mock_gnome_daemon.py`, which owns
   `com.github.kanata.Switcher.instances.audit` and exports `GetStatus`,
   `GetPaused`, `Restart`, `Pause`, `Unpause`, `StatusChanged`, and
   `PausedChanged`;
7. starts `gnome-shell --headless --wayland --no-x11` inside the namespace;
8. probes `org.gnome.Shell.Extensions.GetExtensionInfo`, the extension's
   `GetFocus`, and the mock daemon's method/signal log;
9. parses the evidence with the `gnome-extension` analyzer profile.

The parent harness's `--gnome-extension` flag runs this audit after its own
report and propagates its exit status: a GNOME finding makes the combined run
fail, and a GNOME harness error makes it status 2. Evidence is written under
`<out>/gnome`; the GNOME report is `<out>/gnome/report.md`, the static report
is `<out>/gnome/gnome-audit/static.md`.

See `references/gnome-extension-audit.md` for the static rules, nested-Shell
procedure, mock contract, and limitations.

## Analyzer rules

The full rule list is generated from `scripts/analyze_dynamic_logs.py`. The
main families are:

| Family | Examples | Meaning |
|--------|----------|---------|
| IP intent | `DYN-NONLOOPBACK-CONNECT`, `DYN-LOOPBACK-UNEXPECTED`, `DYN-UDP`, `DYN-DNS` | syscall-level egress, including failed attempts |
| Raw/inbound | `DYN-AF-PACKET`, `DYN-RAW-SOCKET`, `DYN-IP-BIND`, `DYN-LISTEN`, `DYN-IP-ACCEPT` | layer-2/raw access or inbound IP surface |
| Corroboration | `DYN-SS-*`, `DYN-PROCNET-*` | socket-table evidence from snapshots |
| Unix IPC | `DYN-UNIX-UNEXPECTED`, `DYN-UNIX-LISTENER` | undocumented Unix socket or listener |
| Process | `DYN-CHILD-IP-NETWORK`, `DYN-NETWORK-TOOL-EXEC`, `DYN-SHELL-EXEC`, `DYN-UNEXPECTED-EXEC` | child network or risky execution |
| Syscalls/files | `DYN-SUSPICIOUS-SYSCALL`, `DYN-SENSITIVE-FILE` | bpf/module/ptrace/namespace/memfd/io_uring/keyring/mount, key material |
| Kanata | `DYN-KANATA-MISSING`, `DYN-KANATA-NO-CONNECT`, `DYN-KANATA-TOO-FEW-CONNECTS`, `DYN-KANATA-TOO-MANY-CONNECTS`, `DYN-KANATA-CONNECT-FAILED` | expected connection and count |
| Mock protocol | `DYN-MOCK-*` | malformed or unexpected mock-kanata traffic |
| Packet capture | `DYN-PCAP-*`, `DYN-BUILD-PCAP-*` | packet-level egress |
| Sinkholes | `DYN-SINKHOLE-*` | DNS/TCP attempts and payloads |
| D-Bus | `DYN-DBUS-*` | destinations, methods, logind, URLs, monitor coverage |
| Build | `DYN-BUILD-*` | fetch/build traces and build-time egress |
| GNOME | `DYN-GNOME-*` | nested Shell load, errors, `GetFocus`, mock methods/signals |

`connect()` returning `-1 EINPROGRESS` or `-1 EALREADY` on a non-blocking
socket is in progress, not a failure. `DYN-KANATA-CONNECT-FAILED` is emitted
only for terminal errno values; a failed expected connection also shows up as
`DYN-KANATA-NO-CONNECT` because the mock never sees it.

`--fail-on` defaults to the baseline `expected_dynamic.fail_on` (`medium`), so
informational `DYN-NETLINK` and `DYN-DBUS-SYSTEM-ABSENT` do not fail a clean
run. Use `--fail-on info` for a maximally strict review.

## Expected clean result

For v1.2.0 in `baseline` or `minimal` scenario:

- exactly one TCP connection from the daemon to `127.0.0.1:<port>`;
- no IP listener owned by the daemon (the mock's own listener is allowed);
- no UDP, DNS, raw, or `AF_PACKET` activity;
- no non-loopback endpoint, successful or failed;
- a pcap with no packet sourced by the daemon MAC/IP;
- empty DNS and TCP sinkhole logs;
- D-Bus traffic on the private session bus and, if the system bus is reachable,
  read-only logind traffic;
- no undocumented Unix socket;
- no child IP network;
- no shell or network-tool execution; auto-install is disabled by
  `--no-install-gnome-extension`, and any GNOME helper execution is limited to
  the reviewed commands in `expected_exec`;
- no build-time IP activity during the offline build.

The mock log should show exactly one `connect` event, the initial
`LayerChange`, and the expected `RequestLayerNames` / `RequestFakeKeyNames`
exchange. More than one connection is a reconnect event and is reported by
`DYN-KANATA-TOO-MANY-CONNECTS`. A `RequestFakeKeyNames` error is not expected in
normal mode; it is the `--legacy` behavior.

## Negative controls

`scripts/selftest_dynamic.sh` has two layers:

```bash
# No root needed. Synthetic evidence directories exercise the analyzer and the
# extension scanner, including clean/negative cases.
scripts/selftest_dynamic.sh --synthetic-only

# Root needed. Tiny probes run through the real veth+tcpdump+bwrap harness.
scripts/selftest_dynamic.sh --harness-only
```

Synthetic controls (14):

| Control | Expected |
|---------|----------|
| clean command run | status 0 |
| missing pcap/sinkhole/session monitor | `DYN-PCAP-MISSING`, `DYN-SINKHOLE-MISSING`, `DYN-DBUS-MONITOR-MISSING` |
| DNS packet sourced by the daemon MAC | `DYN-PCAP-UDP`, `DYN-PCAP-DNS`, `DYN-PCAP-DNS-QUERY` |
| sinkhole DNS/TCP/data records | `DYN-SINKHOLE-DNS`, `DYN-SINKHOLE-TCP`, `DYN-SINKHOLE-DATA` |
| sensitive D-Bus destination/method/URL | `DYN-DBUS-SENSITIVE-DEST`, `DYN-DBUS-SENSITIVE-METHOD`, `DYN-DBUS-URL` |
| build fetch/build traces, URL, pcap | `DYN-BUILD-SCRIPT-EGRESS`, `DYN-BUILD-SCRIPT-URL`, `DYN-BUILD-PCAP-EGRESS` |
| child-process connect | `DYN-NONLOOPBACK-CONNECT`, `DYN-CHILD-IP-NETWORK` |
| `sendmmsg` on an IP socket | `DYN-IP-SENDMMSG`, `DYN-UDP` |
| clean GNOME evidence | status 0 |
| missing GNOME shell/mock logs | `DYN-GNOME-SHELL-LOG-MISSING`, `DYN-GNOME-MOCK-MISSING` |
| execution from a memfd | `DYN-MEMFD-EXEC` |
| Shell reports `enabled=false` | `DYN-GNOME-EXTENSION-NOT-ENABLED` |
| clean extension source | scanner status 0 |
| malicious extension fixture | 13 `GEXT-*` rules |

Harness controls (6):

| Probe | Expected rule |
|-------|---------------|
| connect to `192.0.2.1:9` | `DYN-NONLOOPBACK-CONNECT` |
| UDP sendto `127.0.0.53:53` | `DYN-UDP` |
| `socket(AF_PACKET, SOCK_RAW)` | `DYN-AF-PACKET` |
| bind/listen `127.0.0.1:0` | `DYN-IP-BIND` |
| fork child connect to `192.0.2.1:9` | `DYN-CHILD-IP-NETWORK` |
| no-op Python | status 0, no findings at `medium` |

If a control does not fail, the analyzer or harness is broken. Do not treat a
green target run as meaningful until the controls pass. On a host without
passwordless `sudo`, run `--synthetic-only` and record that the privileged
controls were not executed.

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
- The sinkhole is not a real Internet: it answers DNS with one address and
  accepts TCP without completing application protocols. A payload that requires
  a valid TLS certificate or a specific HTTP response may stop earlier than it
  would on the real network. The attempt is still captured.
- `tcpdump` sees packets on the veth, not traffic that stays on loopback inside
  the daemon namespace. Loopback is covered by strace, `ss`, and `/proc/net`.
- The mock server is not kanata; protocol differences can change behavior. It
  implements the subset used by the integration tests.
- A supplied `--binary` may have unverified provenance even if the trace is
  clean.
- The GNOME audit uses a nested headless Shell, not the user's live session.
  Shell extensions, portals, and session services may behave differently under
  a real desktop. See `references/gnome-extension-audit.md`.

## Troubleshooting

- `error: passwordless sudo is not available and stdin is not a TTY`: run from
  an interactive terminal, run as root, or configure sudo. The harness will not
  downgrade to a rootless run.
- `error: tcpdump is not usable`: install `tcpdump`; packet capture is
  mandatory.
- `error: packet capture is missing or empty`: inspect
  `<out>/pcap/*.tcpdump.log`. The capture interface may be down or the
  namespace may have been torn down early.
- `error: DNS/TCP sinkhole did not become ready`: inspect
  `<out>/net/sinkhole.stderr.log`. Port 53 may already be in use on the
  capture address, or the unprivileged port setting failed.
- `error: system bus monitor is mandatory`: the system bus exists but the
  monitor could not start. Fix the root/system-bus setup, or pass
  `--allow-unmonitored-system-bus` as a documented exception.
- `error: no strace logs were produced`: check `<out>/daemon/stderr.log` and
  the bwrap exit status.
- `DYN-KANATA-MISSING`: the daemon may have exited before connecting (missing
  config, unknown environment). Check stdout/stderr and `meta.json`.
- `DYN-UNIX-UNEXPECTED` for a path that is actually documented: add a precise
  glob to `dynamic_policy.allowed_unix_socket_globs` only after reviewing the
  path; do not add a broad `/tmp/*` or `/run/*` glob.
- `DYN-PROCNET-LISTENER` for the mock port: confirm it is `127.0.0.1:<port>`;
  the analyzer already allows that case. A wildcard listener is a real finding.
- `DYN-DBUS-SYSTEM-EAVESDROP`: the monitor is not a full monitor. On a shared
  system bus, root `dbus-monitor --system` normally becomes a monitor; if it
  does not, coverage is incomplete and the run should not be called complete.

## Re-baselining

After reviewing a diff:

1. Build from the new commit and run the harness in `baseline` and `minimal`.
2. Run `selftest_dynamic.sh`; all selected controls must still fail and the
   clean probes must pass.
3. Update `dynamic_policy` / `expected_dynamic` only for reviewed changes
   (new documented Unix socket, new expected endpoint, new expected helper).
4. Update `build_time_network` only for a reviewed registry/host change.
5. Update `gnome_extension` only for reviewed extension changes.
6. Never add a broad Unix glob or allow UDP/raw/non-loopback traffic to silence
   a finding.
7. Record the harness version (commit of the skill), the binary hash, and the
   capture interface in the report.
