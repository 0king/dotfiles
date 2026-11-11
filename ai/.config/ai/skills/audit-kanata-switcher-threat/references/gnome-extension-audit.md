# GNOME Shell Extension Audit

The bundled extension runs inside GNOME Shell, not in the daemon process. A
compromised or careless change therefore has more authority than an ordinary
app: it can read the focused window title, register keybindings, talk to every
session-bus service, read files, use the clipboard, and spawn processes. The
audit has two layers: a static scanner and a nested headless Shell run.

## Static scanner

```bash
SKILL=~/.config/ai/skills/audit-kanata-switcher-threat
python3 "$SKILL/scripts/scan_gnome_extension.py" \
  <repo>/src/gnome-extension \
  --json /tmp/opencode/ks-gnome-static.json \
  --markdown /tmp/opencode/ks-gnome-static.md --verbose
```

The scanner is stdlib-only Python and does not execute the extension. It
inventories:

- every file and its SHA-256;
- ES module imports (`import ... from 'gi://...'`) and legacy
  `imports.*` access;
- process execution (`Gio.Subprocess`, `GLib.spawn*`, `Shell.util_spawn*`,
  `Util.spawn*`, `Gio.UnixFDList`);
- dynamic code and obfuscation (`eval`, `Function`, string `setTimeout`,
  `require`, `imports.searchPath`, `WebAssembly`, `atob`/`btoa`,
  `String.fromCharCode`, long encoded-looking strings, hex escapes);
- network APIs (`Gio.SocketClient`, `Gio.Socket`, `Gio.NetworkAddress`,
  `Gio.Resolver`, `Gio.ProxyResolver`, TLS connections, `Soup`, `fetch`,
  `XMLHttpRequest`, `WebSocket`, `EventSource`, `sendBeacon`);
- file APIs (`Gio.File`, `Gio.FileInfo`, `GLib.file_get_contents`,
  `load_contents`, `replace_contents`, `enumerate_children`, async reads/writes);
- clipboard APIs (`St.Clipboard`, `Gtk.Clipboard`, `get_content`,
  `set_content`);
- keybinding APIs (`add_keybinding`, `remove_keybinding`,
  `Meta.KeyBindingFlags`, `allow_keybinding`);
- system-bus use (`Gio.DBus.system`, `Gio.BusType.SYSTEM`);
- D-Bus destinations, interfaces, and object paths extracted from string
  literals and `*_INTERFACE` / `*_PATH` constants;
- `metadata.json` fields, shell-version format, UUID, settings schema, URL, and
  unknown keys;
- GSettings keys used by JS versus keys defined in the schema XML;
- schema XML validity and boolean/string defaults;
- URLs in executable code (comments are notes, not findings).

### Rule families

| Rule | Severity | Meaning |
|------|----------|---------|
| `GEXT-NETWORK-IMPORT` | critical | `gi://Soup`, `Gst`, `GstNet`, etc. |
| `GEXT-NETWORK-API` | critical | socket, resolver, proxy, TLS, fetch, WebSocket |
| `GEXT-EXEC-API` | critical | subprocess/spawn/fd-passing APIs |
| `GEXT-DBUS-SYSTEM` | critical | system bus access |
| `GEXT-DYNAMIC-CODE` | high | `eval`, `Function`, `require`, `imports.searchPath`, `WebAssembly` |
| `GEXT-DYNAMIC-IMPORT` | high | `import('...')` |
| `GEXT-FILE-API` | high | file read/write/enumeration |
| `GEXT-URL` | high | URL in executable code |
| `GEXT-UNEXPECTED-IMPORT` | medium/high | module outside the expected GObject set or non-relative import |
| `GEXT-LEGACY-IMPORT` | medium | legacy `imports.*` access |
| `GEXT-OBFUSCATION` | medium | encoding/decoding helpers |
| `GEXT-CLIPBOARD-API` | medium | clipboard access |
| `GEXT-KEYBINDING-API` | medium | keybinding registration |
| `GEXT-HEX-ESCAPES` | medium | 8+ hex escape sequences |
| `GEXT-LONG-ENCODED-STRING` | medium | 200+ character base64/hex-like literal |
| `GEXT-UNEXPECTED-FILE` | medium | unexpected file type |
| `GEXT-SETTINGS-KEY-MISSING` | high | JS uses a settings key the schema does not define |
| `GEXT-SCHEMA-MISMATCH` | high | `settings-schema` has no matching schema XML |
| `GEXT-SCHEMA-INVALID` / `GEXT-SCHEMA-KEY` / `GEXT-SCHEMA-ID` | critical/high | malformed schema |
| `GEXT-SCHEMA-DEFAULT` | medium | boolean/string default is malformed |
| `GEXT-METADATA-*` | medium/high/critical | invalid or incomplete metadata |
| `GEXT-UUID-DIRECTORY` | medium | UUID does not match the extension directory |
| `GEXT-IMPORT-DRIFT` | high | import not in the baseline |
| `GEXT-DBUS-DEST-DRIFT` | high | D-Bus name not in the baseline |
| `GEXT-DBUS-IFACE-DRIFT` | medium | D-Bus interface not in the baseline |
| `GEXT-UUID-DRIFT` / `GEXT-SCHEMA-DRIFT` | high | identity changed from the baseline |
| `GEXT-SETTINGS-KEY-UNUSED` | low | baseline key no longer used |
| `GEXT-HASH-DRIFT` | info | file hash differs from the recorded baseline |

`gi://Gio`, `gi://GLib`, `gi://St`, `gi://Clutter`, `gi://Gtk`, and `gi://Adw`
are GObject-introspection URIs, not network URLs. `resource:///org/gnome/...`
imports are Shell resources. Relative `./` and `../` imports are local modules.
Comments containing URLs are recorded as notes; only executable URLs are
findings.

Exit codes: 0 = no findings at/above `--fail-on` (default `high`), 1 =
findings, 2 = usage/scan error.

## Dynamic audit

```bash
"$SKILL/scripts/run_gnome_extension_audit.sh" \
  --repo <repo> --out /tmp/opencode/ks-gnome --timeout 30
```

The harness requires root/`sudo`, `tcpdump`, `ip`, `setpriv`, `strace`,
`dbus-monitor`, `dbus-daemon`, `gdbus`, `gsettings`, `glib-compile-schemas`,
`gnome-shell`, `gjs`, and `timeout`. It fails closed when root or `tcpdump` is
unavailable.

### Procedure

1. **Static scan.** Runs `scan_gnome_extension.py` and writes
   `<out>/gnome-audit/static.json` and `static.md`. A static finding does not
   stop the dynamic run; the final exit combines both.
2. **Extension staging.** Copies the extension into a private **system** data
   directory, `<out>/sysdata/gnome-shell/extensions/kanata-switcher@7mind.io`,
   and runs `glib-compile-schemas` on its schema directory. The Shell is started
   with `XDG_DATA_DIRS=<out>/sysdata:/usr/local/share:/usr/share`, so the
   extension is loaded as a system extension. This is what allows the harness
   to set `allow-extension-installation false`: GNOME Shell only loads per-user
   extensions when that key is true, and the same key gates the
   `extensions.gnome.org` update check. A system extension is loaded while the
   update check is disabled, so the nested Shell makes no extension-repository
   connection.
3. **Network isolation.** Creates `ksg-d-*`/`ksg-c-*` namespaces with
   `10.214.0.2/24`/`10.214.0.1/24` and
   `fd42:6b73:6773:6e6f::2/64`/`::1/64`, a veth pair, mandatory `tcpdump` on
   the capture side, and DNS/TCP sinkholes. The system bus is monitored as root
   when present.
4. **Private session bus.** Starts `dbus-daemon` **inside the daemon
   namespace** so activated services inherit the isolated network. The socket
   is `<out>/dbus/session.sock`, and a host-side `dbus-monitor --address ...`
   records the traffic.
5. **Pre-enable with GSettings keyfile.** Sets
   `org.gnome.shell disable-user-extensions false`,
   `org.gnome.shell enabled-extensions ['kanata-switcher@7mind.io']`, and
   `org.gnome.shell allow-extension-installation false` using
   `GSETTINGS_BACKEND=keyfile`. It also writes `disabled-extensions` for every
   system extension found in `/usr/local/share` and `/usr/share` except the
   target, so Ubuntu mode extensions (dock, app indicators, search providers)
   do not load and add noise. This avoids `gnome-extensions enable`, the host's
   extension state, and the extensions service.
6. **Mock daemon.** Starts `mock_gnome_daemon.py` in the daemon namespace. It
   owns `com.github.kanata.Switcher.instances.audit` on the private session bus
   and exports the real daemon interface.
7. **Nested Shell.** Starts
   `gnome-shell --headless --wayland --no-x11` under `env -i` with a minimal,
   controlled environment: private `HOME`, `XDG_CONFIG_HOME`, `XDG_DATA_HOME`,
   `XDG_CACHE_HOME`, `XDG_RUNTIME_DIR`, and `TMPDIR`;
   `XDG_DATA_DIRS=<out>/sysdata:/usr/local/share:/usr/share`;
   `XDG_CURRENT_DESKTOP=GNOME`; `XDG_SESSION_TYPE=wayland`;
   `GSETTINGS_BACKEND=keyfile`; software GL; and `NO_AT_BRIDGE=1`. Host
   variables such as `DISPLAY`, `WAYLAND_DISPLAY`, `DBUS_SYSTEM_BUS_ADDRESS`,
   `GTK_MODULES`, `XMODIFIERS`, `SSH_AUTH_SOCK`, and keyring pointers are not
   inherited. It runs under `strace -ff -e trace=<network/process/sensitive>`
   and `timeout`. IBus is still started by the Shell; `ibus-*` execs are
   expected in this profile.
8. **Probes.** Waits for `org.gnome.Shell` to appear, calls
   `org.gnome.Shell.Extensions.GetExtensionInfo kanata-switcher@7mind.io`,
   calls the extension's
   `com.github.kanata.Switcher.extensions.GNOME.GetFocus` at
   `/com/github/kanata/Switcher/extensions/GNOME`, and waits for the mock log to
   show `GetStatus` and `GetPaused`.
9. **Cleanup and analysis.** Terminates the Shell, mock, monitor, bus, and
   namespace processes; stops the capture; verifies the pcap is non-empty;
   writes `meta.json`; runs `analyze_dynamic_logs.py --profile gnome-extension`.

The nested Shell is not the user's live session. It uses a private data home,
config home, cache, runtime dir, and bus. It does not install the extension into
the host profile.

### Mock daemon contract

| Item | Value |
|------|-------|
| Bus name | `com.github.kanata.Switcher.instances.audit` |
| Object path | `/com/github/kanata/Switcher` |
| Interface | `com.github.kanata.Switcher` |
| Methods | `GetStatus() -> (sass)`, `GetPaused() -> b`, `Restart()`, `Pause()`, `Unpause()`, `WindowFocus(s, s)` |
| Signals | `StatusChanged(sass)`, `PausedChanged(b)` |
| Default status | layer `browser`, empty virtual-key list, source `focus` |
| Emit schedule | `StatusChanged` after `--emit-delay` seconds, `PausedChanged` 250 ms later |
| Log | JSONL records: `ready`, `method`, `signal`, `exit` |
| Ready file | written after the bus name is owned |

The extension discovers the instance by enumerating
`com.github.kanata.Switcher.instances.*`, calls `GetStatus`/`GetPaused`, and
subscribes to the two signals. The analyzer requires both methods and both
signals; a missing one means the extension did not exercise the expected path.

### D-Bus policy in this profile

The `gnome-extension` profile records **all** sensitive destinations as notes,
not failures, because a nested Shell activates and talks to many core desktop
services on its own (UPower, NetworkManager, BlueZ, ModemManager, Secret
Service, portals, logind) and the bus monitor cannot tell an extension call from
a Shell call: both are sent by the Shell process. It still fails on:

- sensitive methods (`OpenURI`, `Launch`, `Spawn`, `StartUnit`, `Eval`, etc.);
- URLs in D-Bus **method calls**;
- logind methods outside the read-only allowlist.

URLs in method returns or broadcast extension-metadata signals are notes, not
findings: core Shell extension metadata legitimately contains project URLs.
Only a URL the Shell/extension sends outward in a method call is actionable.

New D-Bus destinations introduced by the extension are caught statically by
`scan_gnome_extension.py` (`GEXT-DBUS-DEST-DRIFT` / `GEXT-DBUS-IFACE-DRIFT`).

### Expected clean result

- static scanner: no findings at/above `high`;
- Shell log contains `[KanataSwitcher] Extension enabled`;
- `GetExtensionInfo` reports `enabled: true`;
- `GetFocus` returns a tuple (even `('', '')` is acceptable in the headless
  Shell with no focused window);
- mock log shows `GetStatus`, `GetPaused`, `StatusChanged`, and
  `PausedChanged`;
- no extension `JS ERROR`/`Gjs-CRITICAL` lines;
- pcap has no packet sourced by the GNOME Shell/daemon namespace;
- empty DNS and TCP sinkhole logs;
- no sensitive D-Bus method or URL in a method call;
- no `extensions.gnome.org` connection (the update check is disabled by
  `allow-extension-installation false`);
- `memfd_create` is a note; `DYN-MEMFD-EXEC` would be critical.

The analyzer rules are:

| Rule | Severity | Meaning |
|------|----------|---------|
| `DYN-GNOME-SHELL-LOG-MISSING` | high | no nested Shell log |
| `DYN-GNOME-EXTENSION-NOT-LOADED` | high | no successful enable log line |
| `DYN-GNOME-EXTENSION-NOT-ENABLED` | high | `GetExtensionInfo` answered with `enabled` not true |
| `DYN-GNOME-EXTENSION-ERROR` | high | extension JS error/critical |
| `DYN-GNOME-FOCUS-MISSING` | medium | `GetFocus` did not answer |
| `DYN-GNOME-MOCK-MISSING` | high | mock daemon log missing |
| `DYN-GNOME-MOCK-METHOD` | high | extension never called `GetStatus`/`GetPaused` |
| `DYN-GNOME-MOCK-SIGNAL` | medium | mock never emitted `StatusChanged`/`PausedChanged` |
| `DYN-MEMFD-EXEC` | critical | `execveat` from a memfd or `/proc/self/fd/` path |

## Limits

- The nested Shell is a fresh headless compositor. Extension behavior that
  depends on a real session (existing windows, portals, user services,
  accessibility bus, lock state) may not be exercised.
- The mock daemon implements the status/pause/focus interface, not the full
  daemon. A code path that requires real layer names, real kanata responses, or
  the real supervisor is not covered.
- The extension is pre-enabled through the keyfile backend. A packaging or
  install-script bug outside the extension source is not covered; use the
  daemon's `gnome_ext` install path review for that.
- The scanner is pattern-based. Obfuscation that avoids the listed APIs, or
  behavior hidden in a native library loaded by GJS, is not detected.
- The static hash list is an informational drift marker, not a trust anchor.
- The session bus is private and runs inside the daemon namespace, but the
  **system bus is the host bus**. Shell logind/systemd/portal calls are
  monitored as root and sensitive destinations are notes in this profile.
  Services activated on the host system bus do not inherit the veth isolation.
  The extension itself is statically checked for `Gio.DBus.system`.
- Update-check suppression relies on GNOME Shell's
  `allow-extension-installation` gate. If a future Shell decouples the update
  check from that key, run a control Shell without the extension and diff the
  network evidence instead of relaxing the profile.
- A clean nested run does not prove the extension is safe in a live Shell. It
  proves the audited revision loads, enables, talks to the expected daemon
  interface, and does not attempt network egress in that environment.

## Troubleshooting

- `error: nested gnome-shell did not start`: inspect
  `<out>/gnome-audit/shell.log`. Common causes are a missing private runtime
  dir, a stale `GSETTINGS_BACKEND`, or no software GL.
- `warning: extension is not reported as enabled`: the analyzer records this
  as `DYN-GNOME-EXTENSION-NOT-ENABLED` (high). Check the keyfile settings
  under `<out>/config/glib-2.0/settings/keyfile` and the Shell log. The
  extension UUID must match `metadata.json`.
- `DYN-GNOME-MOCK-METHOD`: the extension did not discover the mock. Check that
  the mock owns the bus name on the private bus and that the extension enumerates
  `instances.*`.
- `DYN-GNOME-FOCUS-MISSING`: `GetFocus` may return an error before the
  extension's focus provider is initialized; increase `--timeout` and re-check.
- `DYN-DBUS-SENSITIVE-METHOD` for a GNOME core method: inspect the message. The
  profile only allows GNOME/portal destinations as notes; sensitive methods are
  still failures.
- `error: packet capture is missing or empty`: inspect
  `<out>/pcap/daemon.tcpdump.log`.
