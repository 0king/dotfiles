#!/usr/bin/env bash
# Negative controls for the dynamic harness and analyzer.
#
# Two layers of tests:
#
#   * synthetic  - build evidence directories from known-bad and known-clean
#                  fixtures and run analyze_dynamic_logs.py / the extension
#                  scanner. These need no root and run everywhere.
#   * harness    - run tiny Python controls through the real privileged
#                  veth+tcpdump+bwrap harness. These prove the capture path,
#                  not just the parser.
#
# Run after changing the harness, analyzer, scanner, or baseline. Use
# --synthetic-only on a host without passwordless sudo; the harness layer
# fails closed by design, so it cannot run there.
#
# Exit codes: 0 = all selected controls passed, 1 = a control failed,
#             2 = setup/usage error.

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SKILL_DIR="$(dirname "$SCRIPT_DIR")"
HARNESS="$SCRIPT_DIR/run_dynamic_network_audit.sh"
ANALYZER="$SCRIPT_DIR/analyze_dynamic_logs.py"
SCANNER="$SCRIPT_DIR/scan_gnome_extension.py"
BASELINE="$SKILL_DIR/references/network-baseline.json"
ROOT="$(mktemp -d /tmp/opencode/kanata-switcher-selftest.XXXXXX)"
PASS=0
FAIL=0
SYNTHETIC_ONLY=0
HARNESS_ONLY=0

usage() {
    sed -n '2,/^$/p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --synthetic-only) SYNTHETIC_ONLY=1; shift ;;
        --harness-only) HARNESS_ONLY=1; shift ;;
        -h|--help) usage; exit 0 ;;
        *) echo "error: unknown argument: $1" >&2; usage >&2; exit 2 ;;
    esac
done

if [[ "$SYNTHETIC_ONLY" -eq 1 && "$HARNESS_ONLY" -eq 1 ]]; then
    echo "error: --synthetic-only and --harness-only are mutually exclusive" >&2
    exit 2
fi

cleanup() {
    echo "[selftest] evidence kept in $ROOT"
}
trap cleanup EXIT

pass() {
    echo "[selftest] PASS $1"
    PASS=$((PASS + 1))
}

fail() {
    echo "[selftest] FAIL $1: $2"
    FAIL=$((FAIL + 1))
}

write_file() {
    local path="$1" body="$2"
    mkdir -p "$(dirname "$path")"
    printf '%s\n' "$body" > "$path"
}

# ---------------------------------------------------------------------------
# Synthetic evidence helpers
# ---------------------------------------------------------------------------

make_pcap() {
    python3 - "$@" <<'PY'
import struct
import sys

path, src_mac, dst_mac, src_ip, dst_ip, sport, dport, proto = sys.argv[1:9]
proto = proto.lower()
dns_name = sys.argv[9] if len(sys.argv) > 9 else "example.com"


def mac(value):
    return bytes(int(part, 16) for part in value.split(":"))


def checksum(data):
    if len(data) % 2:
        data += b"\x00"
    total = sum(struct.unpack(f"!{len(data) // 2}H", data))
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


def dns_query(name):
    header = struct.pack("!HHHHHH", 0x1234, 0x0100, 1, 0, 0, 0)
    qname = b"".join(bytes([len(part)]) + part.encode() for part in name.split(".")) + b"\x00"
    return header + qname + struct.pack("!HH", 1, 1)


if proto == "udp":
    payload = dns_query(dns_name)
    transport = struct.pack("!HHHH", int(sport), int(dport), 8 + len(payload), 0) + payload
    ip_proto = 17
elif proto == "tcp":
    transport = struct.pack("!HHIIBBHHH", int(sport), int(dport), 1, 0, 0x50, 0x02, 65535, 0, 0)
    ip_proto = 6
else:
    raise SystemExit(f"unsupported protocol: {proto}")

total = 20 + len(transport)
ip = struct.pack(
    "!BBHHHBBH4s4s",
    0x45, 0, total, 0x1234, 0, 64, ip_proto, 0,
    bytes(int(part) for part in src_ip.split(".")),
    bytes(int(part) for part in dst_ip.split(".")),
)
ip = ip[:10] + struct.pack("!H", checksum(ip)) + ip[12:]
ethernet = mac(dst_mac) + mac(src_mac) + struct.pack("!H", 0x0800)
frame = ethernet + ip + transport
header = struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
record = struct.pack("<IIII", 1704067200, 0, len(frame), len(frame))
with open(path, "wb") as handle:
    handle.write(header + record + frame)
PY
}

new_evidence() {
    local dir="$1"
    mkdir -p "$dir"/{strace,pcap,net,dbus,mock,gnome-audit,build}
    : > "$dir/net/dns.jsonl"
    : > "$dir/net/tcp.jsonl"
    : > "$dir/dbus/session.monitor.log"
    write_file "$dir/strace/daemon.1000" 'execve("/usr/bin/python3", ["python3", "control.py"], 0x7ffd) = 0'
}

write_meta() {
    local dir="$1" body="$2"
    printf '%s\n' "$body" > "$dir/meta.json"
}

check_report() {
    local name="$1" dir="$2" expect_status="$3"
    shift 3
    local rules=("$@")
    local json="$dir/report.json"
    local status=0
    python3 "$ANALYZER" "$dir" --unix-glob "$dir/runtime/*" --json "$json" >"$dir/analyzer.log" 2>&1 || status=$?
    if [[ "$status" -ne "$expect_status" ]]; then
        fail "$name" "analyzer status $status, expected $expect_status (see $dir/analyzer.log)"
        return
    fi
    local missing=()
    for rule in "${rules[@]}"; do
        if ! python3 - "$json" "$rule" <<'PY'
import json, sys
try:
    report = json.load(open(sys.argv[1], encoding="utf-8"))
except (OSError, json.JSONDecodeError):
    raise SystemExit(1)
raise SystemExit(0 if any(f.get("rule") == sys.argv[2] for f in report.get("findings", [])) else 1)
PY
        then
            missing+=("$rule")
        fi
    done
    if [[ ${#missing[@]} -gt 0 ]]; then
        fail "$name" "missing rule(s): ${missing[*]} (see $json)"
        return
    fi
    pass "$name"
}

check_scanner() {
    local name="$1" dir="$2" baseline="$3" expect_status="$4"
    shift 4
    local rules=("$@")
    local outdir
    outdir="$(mktemp -d "$ROOT/scanner-output.XXXXXX")"
    local json="$outdir/report.json"
    local status=0
    python3 "$SCANNER" "$dir" --baseline "$baseline" --json "$json" >"$outdir/scanner.log" 2>&1 || status=$?
    if [[ "$status" -ne "$expect_status" ]]; then
        fail "$name" "scanner status $status, expected $expect_status (see $outdir/scanner.log)"
        return
    fi
    local missing=()
    for rule in "${rules[@]}"; do
        if ! python3 - "$json" "$rule" <<'PY'
import json, sys
try:
    report = json.load(open(sys.argv[1], encoding="utf-8"))
except (OSError, json.JSONDecodeError):
    raise SystemExit(1)
raise SystemExit(0 if any(f.get("rule") == sys.argv[2] for f in report.get("findings", [])) else 1)
PY
        then
            missing+=("$rule")
        fi
    done
    if [[ ${#missing[@]} -gt 0 ]]; then
        fail "$name" "missing rule(s): ${missing[*]} (see $json)"
        return
    fi
    pass "$name"
}

# ---------------------------------------------------------------------------
# Synthetic analyzer controls
# ---------------------------------------------------------------------------

synthetic_analyzer() {
    local base="$ROOT/synthetic"
    mkdir -p "$base"

    # Clean command run: only a capture-side packet, no sinkhole activity, a
    # private session bus, and no system bus. This is the false-positive gate.
    local clean="$base/clean"
    new_evidence "$clean"
    write_file "$clean/strace/daemon.1000" 'execve("/usr/bin/timeout", ["timeout", "5", "bash", "-c", "/usr/bin/python3 control.py"], 0x7ffd) = 0
execve("/usr/bin/bash", ["bash", "-c", "/usr/bin/python3 control.py"], 0x7ffd) = 0
execve("/usr/bin/python3", ["python3", "control.py"], 0x7ffd) = 0'
    write_meta "$clean" '{
  "mode": "command", "profile": "command",
  "command": "/usr/bin/python3 control.py",
  "privileged_capture": true, "system_bus_monitor": "absent",
  "build_traced": false,
  "daemon_mac": "02:00:00:00:00:02", "daemon_ip4": "10.213.0.2"
}'
    make_pcap "$clean/pcap/daemon.pcap" aa:bb:cc:dd:ee:ff 02:00:00:00:00:02 10.213.0.1 10.213.0.2 40000 53 udp
    check_report clean-command "$clean" 0

    # Missing privileged evidence must fail closed.
    local missing="$base/missing"
    new_evidence "$missing"
    write_meta "$missing" '{
  "mode": "command", "profile": "command",
  "command": "/usr/bin/python3 control.py",
  "privileged_capture": true, "system_bus_monitor": "absent",
  "build_traced": false
}'
    rm -f "$missing/pcap/daemon.pcap" "$missing/net/dns.jsonl" "$missing/net/tcp.jsonl" "$missing/dbus/session.monitor.log"
    check_report missing-evidence "$missing" 1 \
        DYN-PCAP-MISSING DYN-SINKHOLE-MISSING DYN-DBUS-MONITOR-MISSING

    # A packet sourced by the daemon MAC is egress even when it is only a DNS
    # query to the sinkhole.
    local pcap="$base/pcap"
    new_evidence "$pcap"
    write_meta "$pcap" '{
  "mode": "command", "profile": "command",
  "command": "/usr/bin/python3 control.py",
  "privileged_capture": true, "system_bus_monitor": "absent",
  "build_traced": false,
  "daemon_mac": "02:00:00:00:00:02", "daemon_ip4": "10.213.0.2"
}'
    make_pcap "$pcap/pcap/daemon.pcap" 02:00:00:00:00:02 aa:bb:cc:dd:ee:ff 10.213.0.2 10.213.0.1 40000 53 udp
    check_report pcap-egress "$pcap" 1 DYN-PCAP-UDP DYN-PCAP-DNS DYN-PCAP-DNS-QUERY

    # Sinkhole records prove DNS and TCP payload behavior independently of the
    # packet capture.
    local sink="$base/sinkhole"
    new_evidence "$sink"
    write_meta "$sink" '{
  "mode": "command", "profile": "command",
  "command": "/usr/bin/python3 control.py",
  "privileged_capture": false, "system_bus_monitor": "absent",
  "build_traced": false
}'
    write_file "$sink/net/dns.jsonl" '{"event":"dns_query","name":"evil.example","qtype":"A","transport":"udp"}'
    write_file "$sink/net/tcp.jsonl" '{"event":"tcp_connect","port":443,"peer":"10.213.0.2:5555"}
{"event":"tcp_data","port":443,"bytes":12,"preview_text":"GET / HTTP/1.1"}'
    check_report sinkhole "$sink" 1 DYN-SINKHOLE-DNS DYN-SINKHOLE-TCP DYN-SINKHOLE-DATA

    # Sensitive D-Bus destinations, methods, and URLs.
    local dbus="$base/dbus"
    new_evidence "$dbus"
    write_meta "$dbus" '{
  "mode": "command", "profile": "command",
  "command": "/usr/bin/python3 control.py",
  "privileged_capture": false, "system_bus_monitor": "enabled",
  "build_traced": false
}'
    write_file "$dbus/dbus/session.monitor.log" 'method call time=1.0 sender=:1.5 -> destination=org.freedesktop.portal.Desktop serial=2 path=/org/freedesktop/portal/desktop; interface=org.freedesktop.portal.OpenURI; member=OpenURI
   string "https://evil.example/payload"'
    write_file "$dbus/dbus/system.monitor.log" 'method call time=2.0 sender=:1.5 -> destination=org.freedesktop.systemd1 serial=3 path=/org/freedesktop/systemd1; interface=org.freedesktop.systemd1.Manager; member=StartUnit
   string "evil.service"'
    check_report dbus "$dbus" 1 DYN-DBUS-SENSITIVE-DEST DYN-DBUS-SENSITIVE-METHOD DYN-DBUS-URL

    # Build-time egress: the fetch trace is allowed on registry ports, but the
    # offline build trace, a URL in the build log, and a build pcap packet are
    # all findings.
    local build="$base/build"
    new_evidence "$build"
    write_meta "$build" '{
  "mode": "command", "profile": "command",
  "command": "/usr/bin/python3 control.py",
  "privileged_capture": false, "system_bus_monitor": "absent",
  "build_traced": true,
  "daemon_mac": "02:00:00:00:00:02", "daemon_ip4": "10.213.0.2"
}'
    write_file "$build/build/fetch.strace.2000" 'socket(AF_INET, SOCK_STREAM|SOCK_CLOEXEC, IPPROTO_TCP) = 3
connect(3, {sa_family=AF_INET, sin_port=htons(443), sin_addr=inet_addr("151.101.1.6")}, 16) = 0'
    write_file "$build/build/build.strace.2001" 'socket(AF_INET, SOCK_STREAM|SOCK_CLOEXEC, IPPROTO_TCP) = 3
connect(3, {sa_family=AF_INET, sin_port=htons(443), sin_addr=inet_addr("192.0.2.1")}, 16) = -1 ENETUNREACH'
    write_file "$build/build/build.log" 'build script fetched https://evil.example/payload'
    make_pcap "$build/pcap/build.pcap" 02:00:00:00:00:02 aa:bb:cc:dd:ee:ff 10.213.0.2 10.213.0.1 40000 443 udp
    check_report build "$build" 1 DYN-BUILD-SCRIPT-EGRESS DYN-BUILD-SCRIPT-URL DYN-BUILD-PCAP-EGRESS

    # Child-process network I/O must be attributed through strace -ff.
    local child="$base/child"
    new_evidence "$child"
    write_meta "$child" '{
  "mode": "command", "profile": "command",
  "command": "/usr/bin/python3 control.py",
  "daemon_pid": 1000,
  "privileged_capture": false, "system_bus_monitor": "absent",
  "build_traced": false
}'
    write_file "$child/strace/daemon.1001" 'connect(3, {sa_family=AF_INET, sin_port=htons(9), sin_addr=inet_addr("192.0.2.1")}, 16) = -1 ENETUNREACH'
    check_report child-network "$child" 1 DYN-NONLOOPBACK-CONNECT DYN-CHILD-IP-NETWORK

    # sendmmsg on an IP socket must be tied back to the socket() family.
    local mmsg="$base/sendmmsg"
    new_evidence "$mmsg"
    write_meta "$mmsg" '{
  "mode": "command", "profile": "command",
  "command": "/usr/bin/python3 control.py",
  "privileged_capture": false, "system_bus_monitor": "absent",
  "build_traced": false
}'
    write_file "$mmsg/strace/daemon.1002" 'socket(AF_INET, SOCK_DGRAM|SOCK_CLOEXEC, IPPROTO_UDP) = 3
sendmmsg(3, [{msg_hdr={msg_name={sa_family=AF_INET, sin_port=htons(53), sin_addr=inet_addr("192.0.2.1")}}}], 1, 0) = 1'
    check_report sendmmsg "$mmsg" 1 DYN-IP-SENDMMSG DYN-UDP

    # GNOME extension: the mock daemon proves the extension loaded and called
    # GetStatus/GetPaused; a clean capture is not a finding.
    local gnome="$base/gnome"
    new_evidence "$gnome"
    write_meta "$gnome" '{
  "mode": "gnome-extension", "profile": "gnome-extension",
  "binary": "/usr/bin/gnome-shell",
  "privileged_capture": false, "system_bus_monitor": "absent",
  "build_traced": false,
  "daemon_mac": "02:00:00:00:00:02", "daemon_ip4": "10.213.0.2"
}'
    write_file "$gnome/gnome-audit/shell.log" '[KanataSwitcher] Extension enabled (multi-indicator)'
    write_file "$gnome/gnome-audit/focus.log" "('firefox', 'Example')"
    write_file "$gnome/strace/daemon.1000" "execve(\"/usr/bin/gnome-shell\", [\"gnome-shell\"], 0x7ffd) = 0
memfd_create(\"mutter-anonymous-file-dmabuf-format-table\", MFD_CLOEXEC|MFD_ALLOW_SEALING) = 12
socket(AF_UNIX, SOCK_STREAM|SOCK_CLOEXEC, 0) = 9
bind(9, {sa_family=AF_UNIX, sun_path=\"$gnome/runtime/wayland-0\"}, 110) = 0
listen(9, 128) = 0"
    write_file "$gnome/mock/mock.jsonl" '{"event":"method","name":"GetStatus"}
{"event":"method","name":"GetPaused"}
{"event":"signal","name":"StatusChanged"}
{"event":"signal","name":"PausedChanged"}'
    check_report gnome-clean "$gnome" 0

    local gnome_neg="$base/gnome-negative"
    new_evidence "$gnome_neg"
    write_meta "$gnome_neg" '{
  "mode": "gnome-extension", "profile": "gnome-extension",
  "binary": "/usr/bin/gnome-shell",
  "privileged_capture": false, "system_bus_monitor": "absent",
  "build_traced": false
}'
    rm -f "$gnome_neg/gnome-audit/shell.log" "$gnome_neg/mock/mock.jsonl"
    check_report gnome-negative "$gnome_neg" 1 DYN-GNOME-SHELL-LOG-MISSING DYN-GNOME-MOCK-MISSING

    # Executing from a memfd is never legitimate shell startup behavior and
    # must remain critical even in the GNOME profile.
    local gnome_exec="$base/gnome-memfd-exec"
    cp -a "$gnome" "$gnome_exec"
    printf '%s\n' \
        'memfd_create("payload", MFD_CLOEXEC) = 12' \
        'execveat(12, "", 0x0, 0x0, AT_EMPTY_PATH) = 0' \
        >> "$gnome_exec/strace/daemon.1000"
    check_report gnome-memfd-exec "$gnome_exec" 1 DYN-MEMFD-EXEC

    # A Shell that answers GetExtensionInfo but reports enabled=false means the
    # extension was staged or enabled incorrectly; the audit did not exercise it.
    local gnome_disabled="$base/gnome-not-enabled"
    cp -a "$gnome" "$gnome_disabled"
    write_file "$gnome_disabled/gnome-audit/extension-info.txt" "({'enabled': <false>, 'state': <1>},)"
    check_report gnome-not-enabled "$gnome_disabled" 1 DYN-GNOME-EXTENSION-NOT-ENABLED
}

# ---------------------------------------------------------------------------
# Synthetic scanner controls
# ---------------------------------------------------------------------------

synthetic_scanner() {
    local base="$ROOT/scanner"
    mkdir -p "$base"

    local clean="$base/clean/kanata-switcher@7mind.io"
    mkdir -p "$clean/schemas"
    write_file "$clean/metadata.json" '{
  "uuid": "kanata-switcher@7mind.io",
  "name": "Kanata Switcher",
  "description": "test",
  "shell-version": ["45"],
  "settings-schema": "org.gnome.shell.extensions.kanata-switcher",
  "version": 1
}'
    write_file "$clean/schemas/org.gnome.shell.extensions.kanata-switcher.gschema.xml" '<?xml version="1.0" encoding="UTF-8"?>
<schemalist>
  <schema id="org.gnome.shell.extensions.kanata-switcher" path="/org/gnome/shell/extensions/kanata-switcher/">
    <key name="show-top-bar-icon" type="b"><default>true</default></key>
  </schema>
</schemalist>'
    write_file "$clean/extension.js" 'import Gio from "gi://Gio";
const BUS = "com.github.kanata.Switcher.instances.audit";
const proxy = Gio.DBus.session.call_sync(BUS, "/com/github/kanata/Switcher", "com.github.kanata.Switcher", "GetStatus", null, null, Gio.DBusCallFlags.NONE, -1, null);
settings.get_boolean("show-top-bar-icon");'
    local clean_baseline="$base/clean-baseline.json"
    write_file "$clean_baseline" '{
  "gnome_extension": {
    "uuid": "kanata-switcher@7mind.io",
    "settings_schema": "org.gnome.shell.extensions.kanata-switcher",
    "allowed_imports": ["gi://Gio"],
    "allowed_dbus_destinations": ["com.github.kanata.Switcher", "com.github.kanata.Switcher.instances.audit"],
    "allowed_dbus_interfaces": ["com.github.kanata.Switcher"],
    "expected_settings_keys": ["show-top-bar-icon"]
  }
}'
    check_scanner ext-clean "$clean" "$clean_baseline" 0

    local evil="$base/evil/evil@example"
    mkdir -p "$evil/schemas"
    write_file "$evil/metadata.json" '{
  "uuid": "evil@example",
  "name": "Evil",
  "description": "test",
  "shell-version": ["45"],
  "settings-schema": "org.example.evil",
  "version": 1
}'
    write_file "$evil/schemas/org.example.evil.gschema.xml" '<?xml version="1.0" encoding="UTF-8"?>
<schemalist>
  <schema id="org.example.evil" path="/org/example/evil/">
    <key name="safe-key" type="b"><default>true</default></key>
  </schema>
</schemalist>'
    write_file "$evil/extension.js" 'import Gio from "gi://Gio";
import Soup from "gi://Soup";
const BUS = "org.evil.Agent";
const conn = Gio.DBus.system;
Gio.Subprocess.new(["sh", "-c", "id"], Gio.SubprocessFlags.NONE);
eval("1+1");
const f = Gio.File.new_for_path("/etc/passwd");
St.Clipboard.get_default();
global.display.add_keybinding("evil", settings, 0, () => {});
const url = "https://evil.example/payload";
settings.get_boolean("evil-key");'
    local evil_baseline="$base/evil-baseline.json"
    write_file "$evil_baseline" '{
  "gnome_extension": {
    "uuid": "kanata-switcher@7mind.io",
    "settings_schema": "org.gnome.shell.extensions.kanata-switcher",
    "allowed_imports": ["gi://Gio"],
    "allowed_dbus_destinations": ["org.freedesktop.DBus"],
    "allowed_dbus_interfaces": [],
    "expected_settings_keys": []
  }
}'
    check_scanner ext-malicious "$evil" "$evil_baseline" 1 \
        GEXT-NETWORK-IMPORT GEXT-EXEC-API GEXT-DYNAMIC-CODE GEXT-FILE-API \
        GEXT-CLIPBOARD-API GEXT-KEYBINDING-API GEXT-DBUS-SYSTEM GEXT-URL \
        GEXT-SETTINGS-KEY-MISSING GEXT-IMPORT-DRIFT GEXT-DBUS-DEST-DRIFT \
        GEXT-UUID-DRIFT GEXT-SCHEMA-DRIFT
}

# ---------------------------------------------------------------------------
# Privileged harness controls
# ---------------------------------------------------------------------------

write_control() {
    local path="$1" body="$2"
    mkdir -p "$(dirname "$path")"
    printf '%s\n' "$body" > "$path"
}

run_control() {
    local name="$1" expected_rule="$2" expect_status="$3" body="$4"
    local out="$ROOT/harness/$name"
    mkdir -p "$out"
    write_control "$out/control.py" "$body"
    echo "[selftest] $name: expecting status $expect_status ${expected_rule:+(rule $expected_rule)}"
    local status=0
    "$HARNESS" --command "python3 $out/control.py" --out "$out" --timeout 5 >"$ROOT/harness/$name.log" 2>&1 || status=$?
    if [[ "$status" -ne "$expect_status" ]]; then
        fail "$name" "harness status $status, expected $expect_status (see $ROOT/harness/$name.log)"
        return
    fi
    if [[ -n "$expected_rule" ]]; then
        if python3 - "$out/report.json" "$expected_rule" <<'PY'
import json, sys
try:
    report = json.load(open(sys.argv[1], encoding="utf-8"))
except (OSError, json.JSONDecodeError):
    raise SystemExit(1)
raise SystemExit(0 if any(f.get("rule") == sys.argv[2] for f in report.get("findings", [])) else 1)
PY
        then
            pass "$name"
        else
            fail "$name" "rule $expected_rule not found in $out/report.json"
        fi
    else
        pass "$name"
    fi
}

harness_controls() {
    mkdir -p "$ROOT/harness"

    # Clean control: no sockets, no execs beyond the Python interpreter.
    run_control clean "" 0 'import time; time.sleep(0.5)'

    # Non-loopback TCP connect (TEST-NET-1, guaranteed not routable). Even a
    # failed attempt must be reported.
    run_control nonloopback DYN-NONLOOPBACK-CONNECT 1 '
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.settimeout(0.5)
try:
    s.connect(("192.0.2.1", 9))
except OSError:
    pass
s.close()
'

    # UDP DNS probe to a loopback resolver: still forbidden because the
    # baseline has no UDP at all.
    run_control dns DYN-UDP 1 '
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.sendto(b"\x00\x00\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00\x01", ("127.0.0.53", 53))
s.close()
'

    # Raw layer-2 socket. It may fail with EPERM; the attempt is the finding.
    run_control af_packet DYN-AF-PACKET 1 '
import socket
try:
    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, 0)
    s.close()
except OSError:
    pass
'

    # Inbound listener: the daemon must never listen on an IP socket.
    run_control listener DYN-IP-BIND 1 '
import socket, time
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.bind(("127.0.0.1", 0))
s.listen(1)
time.sleep(0.5)
s.close()
'

    # Child process network: strace -ff must attribute the connect to the child.
    run_control child DYN-CHILD-IP-NETWORK 1 '
import os, socket, time
pid = os.fork()
if pid == 0:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(0.5)
    try:
        s.connect(("192.0.2.1", 9))
    except OSError:
        pass
    s.close()
    os._exit(0)
os.waitpid(pid, 0)
time.sleep(0.2)
'
}

# ---------------------------------------------------------------------------

echo "[selftest] evidence root: $ROOT"
if [[ "$HARNESS_ONLY" -eq 0 ]]; then
    synthetic_analyzer
    synthetic_scanner
fi
if [[ "$SYNTHETIC_ONLY" -eq 0 ]]; then
    harness_controls
fi

echo "[selftest] passed=$PASS failed=$FAIL"
[[ "$FAIL" -eq 0 ]]
