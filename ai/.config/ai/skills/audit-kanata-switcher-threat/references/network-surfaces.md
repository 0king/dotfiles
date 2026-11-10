# kanata-switcher Network & IPC Surfaces

Snapshot: `6957867` (`69578672fce32ac5b69aed393f6981d4fbad3999`), tag `v1.2.0`,
2026-11-10. This is a static map of every network and IPC path found in the
tree. It is not a runtime trace.

## Executive answer

At this commit kanata-switcher has **one IP socket**: an outbound plain-TCP
connection to kanata at `{host}:{port}` (default `127.0.0.1:10000`). Everything
else is local IPC over Unix sockets or subprocesses that use local files and
the user's desktop session:

- no inbound TCP listener;
- no HTTP or HTTPS client/server;
- no TLS;
- no UDP;
- no explicit DNS API (the default host is a literal IP; a hostname passed to
  `--host` would be resolved by the OS);
- no SMTP, SSH, FTP, WebSocket, gRPC, Redis, or database client;
- no telemetry, analytics, crash reporting, or auto-update;
- no runtime fetch of the repository or GNOME extension.

The daemon does **not** launch `kanata`. It connects to kanata's TCP server and
sends newline-delimited JSON commands.

## Protocol coverage matrix

What was searched, and what the tree contains. "None" means no code path or
capability was found by the static checks below, not that the protocol is
impossible in principle (see [Limits of this check](#limits-of-this-check)).

| Protocol / family | How it was checked | Result in this tree |
|-------------------|--------------------|---------------------|
| TCP over IPv4/IPv6 | Rust `TcpStream`/`TcpListener`, `std::net`, `tokio::net`, `socket2` use, lockfile | One outbound `TcpStream::connect` to kanata; listeners only in tests |
| UDP | `UdpSocket`, `sendto`/`recvfrom`, `SOCK_DGRAM` | None |
| Raw IP / ICMP | `libc::socket`, `SOCK_RAW`, `nix::sys::socket`, `ping` | None |
| DNS | `ToSocketAddrs`, `lookup_host`, resolver crates, `dig`/`nslookup`/`host` | No explicit lookup; OS resolver only if `--host` is a hostname |
| HTTP / HTTPS | `reqwest`/`ureq`/`hyper`/`curl`, `http` crates, JS `fetch`/`XMLHttpRequest` | None |
| TLS / SSL | `rustls`, `native-tls`, `openssl`, `webpki`, `ring` | None |
| HTTP/2 and gRPC | `h2`, `tonic`, `grpc`, `prost` service code | None |
| WebSocket | `tungstenite`, JS `WebSocket`, `Soup` | None |
| QUIC / HTTP/3 | `quinn`, `quiche`, `s2n-quic` | None |
| SSH / SFTP / SCP | `ssh2`, `openssh`, `ssh`/`scp`/`sftp` commands | None |
| FTP / TFTP | FTP crates, `ftp`/`tftp` commands | None |
| SMTP / IMAP / POP3 | `lettre`, mail crates, `sendmail` | None |
| Database wire protocols | `sqlx`, `postgres`, `mysql`, `mongodb`, `rusqlite` | None |
| Redis / Memcached | `redis`, `memcache` crates | None |
| MQTT / AMQP / NATS / ZeroMQ | `rumqtt`, `lapin`, `async-nats`, `zmq` | None |
| NTP / time sync | time-sync crates, `ntp`/`chrony` calls | None |
| Netlink | `netlink`, `rtnetlink`, `neli` | None |
| Bluetooth | BlueZ D-Bus APIs, `bluetoothctl`, `bluer` | None |
| D-Bus session bus | zbus/ksni, `Gio.DBus` | Yes, local `AF_UNIX` session bus only |
| D-Bus system bus | zbus system connection | Yes, logind read-only queries/signals only |
| Unix domain sockets | `UnixStream`/`UnixListener`, `AF_UNIX` | Yes, Wayland and D-Bus; no daemon listener outside tests |
| X11 | `x11rb::connect`, `DISPLAY` handling | Yes, local Unix socket by default; TCP only with a remote `DISPLAY` |
| Wayland | `wayland-client`, `UnixStream` | Yes, local compositor socket only |

The scanner enforces the same families as patterns (`network` rules in
`scripts/scan_kanata_switcher.py`), so a new API or crate in any row above
shows up as an unexpected finding unless it is added to the accepted baseline.

## Limits of this check

This is a static review of this checkout, not a packet capture. It does **not**
prove the absence of all network traffic:

1. **Transitive dependency source was not audited.** `Cargo.lock` contains no
   HTTP/TLS/DNS/SSH/WebSocket/gRPC/database/queue crate, but a full
   `cargo tree --locked` could not run offline in this environment (`ksni` was
   missing from the local index). A dependency can implement a protocol without
   a recognizable crate name.
2. **External helper binaries are not audited.** `gnome-extensions`,
   `gsettings`, `dconf`, and `glib-compile-schemas` are trusted local desktop
   tools; they use D-Bus/GSettings, but their own code is outside this repo.
3. **Separate programs are out of scope.** `kanata`, GNOME Shell, KWin, and the
   X11/Wayland compositors have their own network behavior.
4. **Environment overrides can add TCP.** Besides `--host` and remote
   `$DISPLAY`, `DBUS_SESSION_BUS_ADDRESS` can name a TCP bus address; zbus and
   Gio would honor it. That is an operator/environment choice, not code in this
   tree.
5. **No runtime trace was performed.** Packet capture/`strace` verification is
   listed below and requires explicit approval plus an isolated environment.

## Runtime IP network

### `kanata-tcp-client`

| Field | Value |
|-------|-------|
| Source | `src/daemon/kanata.rs`, `KanataClient::try_connect` |
| API | `tokio::net::TcpStream::connect(&addr)` |
| Direction | outbound |
| Protocol | plain TCP |
| Payload | newline-delimited JSON |
| Endpoint | `{host}:{port}` |
| Default | `127.0.0.1:10000` |
| Gate | every daemon start; retries until kanata is reachable |
| TLS | no |
| Auth | none |

Commands sent by the daemon (serialized with `serde`):

- `{"ChangeLayer":{"new":"<layer>"}}`
- `{"RequestLayerNames":{}}`
- `{"RequestFakeKeyNames":{}}`
- `{"ActOnFakeKey":{"name":"<key>","action":"Press|Release|Tap|Toggle"}}`

Messages read from kanata:

- `LayerChange`, `LayerNames`, `FakeKeyNames`.

Layer and key names are used for matching and for `ActOnFakeKey`. They are not
passed to a shell, a path, or an exec API. A malicious peer can influence which
layer/keys the daemon asks kanata to use (and can lie about available layers),
but the static code does not turn that into code execution.

`--host` / `-H` and the Nix `kanataHost` option are operator-controlled. The
default is loopback. Pointing this at a remote host is a deliberate choice;
verify who can change the CLI/Nix option before treating it as benign.

## Local IPC

### D-Bus session bus

All session-bus traffic uses zbus/ksni or Gio.DBus over the user's session bus
Unix socket. There is no TCP D-Bus address.

| Component | File | Purpose |
|-----------|------|---------|
| Daemon control service | `src/daemon/control/server.rs` | Exports `com.github.kanata.Switcher` on `/com/github/kanata/Switcher`: `WindowFocus`, `GetStatus`, `GetPaused`, `Restart`, `Pause`, `Unpause`, plus `StatusChanged`/`PausedChanged` signals. |
| Persistent service / reconnect | `src/daemon/control/persistent.rs` | Owns a well-known name `com.github.kanata.Switcher.instances.<suffix>` and reconnects on bus loss. |
| Control client | `src/daemon/control/client.rs` | `--restart`/`--pause`/`--unpause`; unicast to one instance or broadcast under `instances.*`. |
| GNOME backend | `src/daemon/backends/gnome.rs` | Queries `org.gnome.Shell` for the focused window. |
| GNOME extension | `src/gnome-extension/extension.js`, `dbus.js` | Talks to the daemon's `WindowFocus` method and listens for status/focus signals. No network APIs. |
| KDE backend | `src/daemon/backends/kde/mod.rs` | Calls `org.kde.KWin` scripting interfaces; also exports a temporary `com.github.kanata.Switcher.KdeQuery` object for focus replies. |
| SNI / tray | `src/daemon/sni/indicator.rs`, `guard.rs` | `ksni` StatusNotifierItem/DBusMenu on the session bus. |
| Capability probe | `src/daemon/supervisor/capabilities.rs` | Detects GNOME/KDE bus owners. |
| Extension detection | `src/daemon/gnome_ext/detection.rs` | `GetExtensionInfo` on `org.gnome.Shell.Extensions`; fallback to `gnome-extensions info` + `gsettings get`. |

The D-Bus control methods are **unauthenticated**. Any process running as the
same user (or otherwise able to talk to that user's session bus) can call
`WindowFocus`, `Pause`, `Unpause`, or `Restart` on a daemon instance. This is
normal for a desktop session service, but it is a local attack surface: a
compromised same-user process can already do most things the daemon can, yet
`WindowFocus` can drive kanata layer/virtual-key actions and `Restart` can
interrupt the service. No method takes a path, command, or URL.

### D-Bus system bus

Only logind:

| File | Calls | Purpose |
|------|-------|---------|
| `src/daemon/lifecycle/logind.rs` | `GetUserByPID`, session/user property reads, `PropertiesChanged` signals | Track the active session, sleep/lock transitions. |
| `src/daemon/display_override.rs` | session `Type`, `Display` properties | Refresh the Wayland/X11 display endpoint after a session change. |

These are read-only queries and signal subscriptions. There is no privileged
method call, no systemd unit manipulation, no `org.freedesktop.systemd1`, and
no polkit action in the tree.

### Wayland

| File | Mechanism | Endpoint |
|------|-----------|----------|
| `src/daemon/backends/wayland/mod.rs` | `UnixStream::connect(socket_path)` where `socket_path = $XDG_RUNTIME_DIR/$WAYLAND_DISPLAY` | local AF_UNIX socket |
| `src/daemon/backends/wayland/mod.rs` | `WaylandConnection::connect_to_env()` | compositor socket named by `WAYLAND_DISPLAY` |

`is_valid_wayland_display_override` accepts absolute paths or simple names and
rejects values containing `/` (unless absolute) or starting with `:`. The
display override can also come from logind. There is no TCP Wayland path.

### X11

`src/daemon/backends/x11.rs` uses `x11rb::connect`. With a normal local
`DISPLAY=:0` this is a Unix socket. If an operator sets `DISPLAY=host:0`, X11
itself would use TCP; that is an explicit environment choice, not code in this
repo. The scanner classifies the baseline as `unix` and will flag a hard-coded
remote display.

### GNOME extension install path

`src/daemon/gnome_ext/` manages the bundled extension:

- `install.rs` runs `gnome-extensions pack`, `gnome-extensions install`,
  `gnome-extensions enable`;
- `detection.rs` may run `gnome-extensions info` and `gsettings get`;
- `embed.rs` writes the embedded extension files and schema into a temp dir,
  then runs `glib-compile-schemas`;
- `mod.rs` prints manual install instructions containing the GitHub clone URL.

Auto-install is enabled by default (`resolve_install_gnome_extension` returns
true unless `--no-install-gnome-extension` is passed). It installs the
**bundled** extension from the binary or adjacent `gnome/` directory; it does
not download anything. The clone URL is only printed for manual installs.

The extension JS uses `Gio.DBus`, `Gio.Settings`, `St`, `Clutter`, `Gtk`, and
`Adw`; no `Soup`, `WebSocket`, `XMLHttpRequest`, `Gio.Subprocess`, `eval`, or
dynamic import in runtime JS. Test files use dynamic `import()` to load local
modules, which is expected.

### KDE / KWin

`src/daemon/backends/kde/` generates JavaScript and asks KWin to load it:

- runtime focus-push script: `/tmp/kanata-switcher-kwin-{uid}-{uuid}.js`;
- query script: `/tmp/kanata-switcher-kwin-query-{uid}-{query_id}-{uuid}.js`;
- probe script: `/tmp/kanata-switcher-kwin-query-probe-{uid}-{probe_id}-{uuid}.js`.

The script body contains a `callDBus(...)` to the daemon's session-bus name
with `WindowFocus` (push) or a temporary `KdeQuery.Focus` method (query). The
bus name is sanitized to `[A-Za-z0-9_-]`; paths are generated internally. Files
are removed by `KwinScriptGuard::drop` or the probe cleanup path. If the daemon
is killed hard, a stale `/tmp` file can remain; it contains only the generated
`callDBus` report and no secrets.

This is dynamic code execution in KWin by design. The review question is
whether the generated string still comes only from the fixed template plus
sanitized identifiers.

### Subprocess execution

| File | Command | Input | Purpose |
|------|---------|-------|---------|
| `build.rs` | `glib-compile-schemas` | build paths | compile bundled schema at build time |
| `src/daemon/gnome_ext/install.rs` | `gnome-extensions` | extension path/UUID | pack/install/enable bundled extension |
| `src/daemon/gnome_ext/detection.rs` | `gnome-extensions`, `gsettings` | fixed args | extension status fallback |
| `src/daemon/gnome_ext/embed.rs` | `glib-compile-schemas` | temp dir | compile embedded schema |
| `src/daemon/sni/settings.rs` | `dconf` | fixed key + bool | SNI focus-only preference |

All commands are resolved via `PATH`. A poisoned `PATH` could substitute a
different helper, but that is the standard local-environment trust boundary,
not a hidden downloader. No command is built with `sh -c` or string
concatenation from network/config data.

### Filesystem writes

Reviewed baseline writes:

- build output: `OUT_DIR` gnome extension + schema (`build.rs`);
- user autostart: `~/.config/autostart/kanata-switcher.desktop` (only with
  `--install-autostart`);
- KDE helper scripts under `/tmp` (UUID-scoped, cleaned up);
- temporary GNOME extension staging dir + embedded files;
- `dconf` preference via CLI (not a direct file write).

There is no write to shell rc files, systemd unit directories, `/etc`, SSH
configuration, cron, or system-wide autostart. `--install-autostart` writes only
the per-user XDG autostart entry and quotes its arguments.

## Build-time and CI network

These are not runtime daemon surfaces, but they matter for supply-chain review:

| Trigger | Endpoint | Integrity |
|---------|----------|-----------|
| `cargo build` with cold cache | crates.io / static.crates.io over HTTPS | `Cargo.lock`, direct deps pinned with `=`; 212 crates.io-only packages, no git sources |
| `nix build` / `nix develop` | GitHub inputs pinned by `flake.lock`; `cache.nixos.org` | `rev` + `narHash` in `flake.lock` and `tests/flake.lock` |
| GitHub Actions | `7mind/github-env@minimal`, GitHub API, Nix cache | single workflow, `contents: read`, no secrets, no `pull_request_target`; action is ref-pinned, not SHA-pinned |

The Nix flake inputs use branch names in `flake.nix` (`nixos-unstable`, etc.),
but the lockfile is the effective pin. Re-check the lockfile when auditing a
new checkout.

## Runtime verification notes

If runtime verification is approved:

1. Use a disposable user/VM or a network namespace. Do not install the GNOME
   extension into a live shell on an untrusted checkout.
2. Run the daemon with a mock kanata server on loopback and capture
   `strace -ff -e trace=network,execve`.
3. Expect exactly one outbound TCP connection to the configured kanata
   endpoint; everything else should be `AF_UNIX` (D-Bus/Wayland/X11) or local
   file/exec activity.
4. Exercise pause/unpause/restart, GNOME/KDE/Wayland/X11 focus changes,
   autostart install/remove, and (in a disposable VM) GNOME extension install.
5. Confirm no listener appears on `0.0.0.0`, no UDP socket, no external DNS
   query, and no HTTP/TLS handshake.

## What would change this answer

Treat any of these as a new review event:

- a new `TcpListener`, `UdpSocket`, HTTP/TLS/WebSocket/gRPC dependency, or DNS
  lookup;
- a remote URL/host literal in runtime code (not docs or printed help);
- `--host` gaining a non-loopback default or being set from config/network
  data;
- a new D-Bus method that takes a path, command, URL, or arbitrary bytes;
- KDE script generation interpolating unsanitized data, or writing outside the
  UUID-scoped `/tmp` path;
- GNOME extension code gaining network, subprocess, or dynamic-eval APIs;
- a new shell/exec sink with user, config, or network-controlled arguments;
- a new write to shell rc, systemd, cron, SSH, or system-wide paths;
- a CI action that runs PR code with secrets or publishes releases;
- a Nix fetch without a hash or an added substituter.
