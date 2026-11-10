# kanata-tray network surfaces

Detailed map of every network-capable path in the repository, as of commit
`138545c` (2026-11-10).  This is a static source review, not a runtime capture.
Line numbers are from that commit; use the symbols and file names when the code
has moved.

## Executive summary

| Direction | Transport | Endpoint | Default | Protocol | Purpose |
|-----------|-----------|----------|---------|----------|---------|
| inbound | TCP | `127.0.0.1:8100` (config `control_server_port`) | **off** | HTTP/1.1, plain | Optional control server: start/stop/toggle presets |
| inbound | TCP | `localhost:6060` | **off** (build tag `pprof`) | HTTP/1.1, plain | Go pprof/debug endpoints |
| outbound | TCP | `localhost:5829` (config `tcp_port`) | on when a preset runs | newline-delimited JSON | kanata IPC: layer names/events |
| local IPC | Unix socket / Mach / Win32 | platform GUI | on | D-Bus/GTK, X11/Wayland, Cocoa, Win32 | Tray icon/menu (third-party `systray`) |
| outbound | process launch | local file/folder path | on user click | `xdg-open` / `open` / `rundll32` | Open logs/config folder |

There is **no** outbound HTTP client, external DNS, UDP, TLS, SMTP, SSH, FTP,
WebSocket, gRPC, telemetry, or auto-update code in the application.

## 1. Inbound HTTP control server

**Files:** `app/controlserver/tcp_control_server.go`,
`app/controlserver/utils.go`; started from `main.go:210-215`.

```go
srv := &http.Server{
    Addr:         fmt.Sprintf("127.0.0.1:%d", port),
    Handler:      mux,
    ReadTimeout:  10 * time.Second,
    WriteTimeout: 10 * time.Second,
    IdleTimeout:  60 * time.Second,
}
...
return srv.ListenAndServe()
```

- **Gate:** `general.control_server_enable = true`; default is `false`
  (`config/default_config/default_config.toml:4-7`).
- **Port:** `general.control_server_port`, default `8100`.
- **Bind:** hard-coded `127.0.0.1`; the port is the only configurable part.
- **Protocol:** plain HTTP/1.1 over TCP.  No TLS, no auth, no CSRF/Origin/Host
  validation.
- **Routes:**
  - `/stop/{preset_name}`
  - `/stop_all`
  - `/start/{preset_name}`
  - `/start_all_default`
  - `/toggle/{preset_name}`
  - `/toggle_all_default`
- **Methods:** any method is accepted; routes are registered with
  `mux.HandleFunc`, and the docs explicitly say any HTTP method is allowed.
- **Request data:** only the URL path/preset name.
- **Response data:** JSON `{IsSuccess, Message?, Data?}`; no secrets.
- **Risk:** local unauthenticated state-change endpoint.  Any local process can
  start/stop kanata.  A browser page can issue simple cross-origin GET requests
  to `127.0.0.1:8100` (CSRF-style); DNS rebinding could make the Host look
  external, and there is no Host check.  This is a hardening issue, not
  malware.  It is off by default.
- **Not present:** request body parsing, file upload, proxy behavior, outbound
  fetch, dynamic command execution beyond the fixed preset actions.

## 2. Inbound pprof server (build-tag only)

**File:** `pprof.go`.

```go
//go:build pprof
...
func init() {
    fmt.Print("Profiling is enabled!\n")
    go func() {
        fmt.Println(http.ListenAndServe("localhost:6060", nil))
    }()
}
```

- **Gate:** `go build -tags pprof` / `go run -tags=pprof .`; the file is excluded
  from normal builds by the `//go:build pprof` constraint.
- **Bind:** `localhost:6060` (loopback; Go resolves localhost).
- **Protocol:** plain HTTP/1.1; `net/http/pprof` default mux.
- **Data:** goroutine dumps, heap/CPU profiles, command line, environment
  metadata exposed by pprof.  Sensitive, but local-only and dev-only.
- **Risk:** do not ship release binaries with this tag.  The Nix/`just` release
  recipes do not include it.

## 3. Outbound kanata TCP client

**File:** `runner/tcp_client/tcp_client.go`; called from
`runner/kanata.go:104`.

```go
conn, err := (&net.Dialer{
    Timeout: connectTimeout,
}).DialContext(ctx, "tcp", fmt.Sprintf("localhost:%d", port))
...
log.Infof("Connected to kanata via TCP (%s)", conn.LocalAddr().String())
```

- **Gate:** whenever a preset starts kanata; `tcp_port` is per-preset/default
  `5829`.
- **Bind/source:** ephemeral local port; destination is hard-coded `localhost`.
  The host cannot be changed by config; only the port is configurable.
- **Protocol:** raw TCP, newline-delimited JSON (`bufio.Scanner`).
- **Outbound data:** only `{"RequestLayerNames":{}}` (plus the initial
  connection), via `ClientMessage.Bytes()`.
- **Inbound data:** `LayerChange`, `LayerNames`, `ConfigFileReload` JSON
  objects.  Unknown JSON is logged and ignored.
- **No TLS, no auth, no HTTP, no arbitrary payload.**  A malicious local process
  that wins the race for port 5829 could impersonate kanata and feed crafted
  layer names to the tray; that is local IPC trust, not exfiltration.
- **DNS:** Go may resolve `localhost` via the OS resolver (`/etc/hosts`,
  nsswitch).  No external hostname is used.

## 4. GUI IPC (third-party, non-IP)

`github.com/getlantern/systray v1.2.2` is a CGo GUI library:

- **Linux:** GTK3 + libayatana-appindicator (`systray_linux.c`), which uses
  D-Bus and the display server socket (X11 or Wayland).  No `socket()` /
  `connect()` / HTTP in the imported package.
- **macOS:** Cocoa/AppKit (`systray_darwin.m`), Mach ports/window server.
- **Windows:** Win32 `Shell_NotifyIcon` message loop (`systray_windows.go`).

The module also contains `example/` and `webview_example/`, which open URLs and
embed WebKit.  Those are separate `main` packages and are **not imported** by
`kanata-tray`; they are not compiled into the binary.

The `getlantern/golog` dependency is a logging wrapper (`go.uber.org/zap`
output), not a network client.  `getlantern/context`, `errors`, `hidden`, `hex`,
`ops`, and `oxtoacart/bpool` are support libraries; no network calls were found
in the imported packages.

## 5. OS opener (third-party, local process)

**File:** `app/app.go:279-292`.

```go
case i := <-a.openPresetLogsCh:
    ...
    open.Start(filename)
case <-a.mOptions.ClickedCh:
    open.Start(configFolder)
case <-a.mShowLogs.ClickedCh:
    open.Start(a.logFilepath)
```

`github.com/skratchdot/open-golang/open` chooses:

- Linux: `exec.Command("xdg-open", input)`
- macOS: `exec.Command("open", input)`
- Windows: `rundll32.exe url.dll,FileProtocolHandler <input>` (or `cmd /C start`)

The inputs are local paths: the config directory, the tray log path, and a
`CreateTemp` per-preset log file.  No preset name, URL, or network response is
passed.  The handler itself could open a URL if a malicious caller changed the
input, but the current call sites cannot.

## 6. Process execution (documented feature)

**Files:** `runner/runner.go:168-183`, `runner/hooks.go`, `runner/kanata.go`,
`config/config.go:258-276`.

```go
cmd := exec.CommandContext(ctx, name, args...)
...
cmd.Env = os.Environ()
```

- `name` is either the configured `kanata_executable` or `exec.LookPath("kanata")`.
- `args` include `-c <kanata_config>`, `--port <tcp_port>`, and config
  `extra_args`.
- Hooks are config strings expanded into `cmd_template` (default
  `/bin/sh -c "{}"` on Unix, `["{}"]` on Windows) and run before/after
  start/stop.
- `extra_env` adds environment variables.
- This is arbitrary local code execution by design.  A malicious
  `kanata-tray.toml` is equivalent to running a script; the repo itself does not
  fetch or decode commands.
- No network response is interpolated into a command; no remote shell.

## 7. Config / icon / log file I/O

- `main.go:84-98`: `KANATA_TRAY_CONFIG_DIR` overrides config dir; otherwise the
  executable dir (if it contains `kanata-tray.toml`) or
  `configdir.LocalConfig("kanata-tray")`.
- `main.go:121-141`: `KANATA_TRAY_LOG_DIR` overrides log dir; default executable
  dir; `os.Create(kanata_tray_lastrun.log)` truncates/creates the log.
  The Nix wrapper defaults this to `/tmp` (`nix/package.nix:41-43`), so a local
  symlink attack on `/tmp/kanata_tray_lastrun.log` is a local hardening issue,
  not network behavior.
- `main.go:168`: `os.Chdir(configFolder)`, so relative config/icon paths resolve
  there.
- `config/config.go:290-304`: creates the default config with mode `0600` if
  missing; reads it otherwise.
- `app/custom_icons.go:118-135`: reads a config-chosen icon path; absolute paths
  are allowed, relative paths join the `icons/` folder.  Arbitrary local file
  read into tray icon bytes, no exfil.
- `status_icons/status_icons.go:63-105`: reads `status_icons/*` files by prefix;
  the embedded defaults are copied there on first run.
- `app/app.go:134`: `os.CreateTemp("", "kanata_lastrun_*.log")` for per-preset
  kanata logs; opened later via `open.Start`.

## 8. Build-time and CI network

These are not runtime app connections, but they are part of the supply-chain
answer:

| Trigger | Traffic | Pin/notes |
|---------|---------|-----------|
| `go build`, `go run`, `nix build` with cold cache | HTTPS to `proxy.golang.org` or direct VCS hosts | `go.sum` hashes; check for `replace` and `go.sum` drift |
| `nix build` / `nix develop` | GitHub `NixOS/nixpkgs` + `cache.nixos.org` | `flake.lock` has `rev` + `narHash`; flake input ref is `nixpkgs-unstable` but lock is the effective pin |
| CI (`.github/workflows/*`) | GitHub Actions marketplace, GitHub API, `cachix.org` | Actions are tag-pinned, not SHA-pinned; release job publishes unsigned artifacts; Cachix token only on push to main |
| Editor opening config | `https://raw.githubusercontent.com/.../config_schema.json` | `$schema` is for TOML language servers; the binary never fetches it |

No `curl | bash`, no unpinned Nix fetch, no `pull_request_target`, and no PR
workflow with secrets was present at the baseline.  The main CI weakness is
mutable action tags.

## 9. What would change the verdict

Treat any of these as a new finding, even if the code looks small:

- A new `net`, `net/http`, `crypto/tls`, `os/exec`, `syscall` socket, WebSocket,
  gRPC, SMTP, SSH, FTP, or `open.Start` call site.
- A host other than `localhost`/`127.0.0.1`/`::1` in runtime Go code.
- A listener changed from `127.0.0.1`/`localhost` to `0.0.0.0`/`:`/empty.
- A network request in `init()`, `main()` startup, or a GUI event with no
  documented gate.
- A new `go.mod` direct dependency, `replace`, or `go.sum` change without a
  matching code review.
- A CI action changed to a mutable ref/branch, a new `pull_request_target`
  workflow, a secret exposed to PR code, or a release step that downloads and
  executes an artifact.
- A Nix fetch without `hash`/`sha256`, `builtins.fetch*`, `--impure`, or a new
  substituter/trusted key.
- An image/icon with trailing bytes, an embedded PE/ELF/ZIP/script, or a magic
  mismatch.
- An active `.git/hooks/*` script, a new submodule, or a remote changed from SSH
  to `http://`/`git://`.

## 10. Runtime verification cheat sheet

Run only with explicit permission, in an isolated VM/container, with no secrets
and network capture/egress control:

```bash
strace -ff -e trace=network -o /tmp/kt-net.log -- env KANATA_TRAY_CONFIG_DIR=/tmp/kt-config ./kanata-tray --log-level=1
ss -ltnp | grep -E '8100|5829|6060'
ss -lunp
lsof -p <pid> -a -i
sudo tcpdump -ni lo -s0 -w /tmp/kt-lo.pcap
sudo tcpdump -ni any -s0 -w /tmp/kt-any.pcap
```

Expected syscalls: `socket(AF_INET/AF_INET6, SOCK_STREAM)` for loopback TCP,
`connect()` to `127.0.0.1`/`::1` only, `bind()`/`listen()` on loopback only,
and Unix-domain sockets for GUI IPC.  No `AF_INET` connect to a non-loopback
address, no UDP sendto, no external DNS, no TLS handshake.

GUI note: a tray app needs a display.  On a headless box use `xvfb-run` or a
desktop VM.  A missing `kanata` binary is fine for checking startup listeners;
preset start will report a spawn error but should not produce network traffic.

Windows/macOS: `netstat -ano` + TCPView + Wireshark; `lsof -i`, `nettop`,
`tcpdump`.  Named pipes (Windows), Mach ports (macOS), D-Bus and X11/Wayland
sockets are local IPC, not IP traffic.
