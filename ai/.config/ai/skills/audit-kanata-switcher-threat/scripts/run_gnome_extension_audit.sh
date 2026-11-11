#!/usr/bin/env bash
# Privileged GNOME Shell extension audit for kanata-switcher.
#
# Runs the real extension inside a nested headless GNOME Shell under a private
# session bus and a veth-isolated network namespace. tcpdump on the capture
# side is mandatory, DNS/TCP sinkholes log every egress attempt, and both the
# private session bus and the system bus are monitored with dbus-monitor.
#
# The extension is pre-enabled through the GSettings keyfile backend so the
# audit does not depend on `gnome-extensions` or the host's extension state.
# A mock daemon owns `com.github.kanata.Switcher.instances.audit` and records
# the extension's GetStatus/GetPaused calls and signal handling.
#
# Usage:
#   run_gnome_extension_audit.sh [--repo PATH] [--out DIR] [--timeout SECONDS]
#       [--extension-dir PATH] [--skip-static] [--allow-unmonitored-system-bus]
#       [--check] [--keep-netns]
#
# Exit codes: 0 = clean, 1 = findings, 2 = harness/setup error.

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SKILL_DIR="$(dirname "$SCRIPT_DIR")"
REPO="${KANATA_SWITCHER_REPO:-$PWD}"
OUT=""
TIMEOUT=30
EXTENSION_DIR=""
SKIP_STATIC=0
CHECK_ONLY=0
KEEP_NETNS=0
ALLOW_UNMONITORED_SYSTEM_BUS=0

usage() {
    sed -n '2,/^$/p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --repo) REPO="$2"; shift 2 ;;
        --out) OUT="$2"; shift 2 ;;
        --timeout) TIMEOUT="$2"; shift 2 ;;
        --extension-dir) EXTENSION_DIR="$2"; shift 2 ;;
        --skip-static) SKIP_STATIC=1; shift ;;
        --allow-unmonitored-system-bus) ALLOW_UNMONITORED_SYSTEM_BUS=1; shift ;;
        --check) CHECK_ONLY=1; shift ;;
        --keep-netns) KEEP_NETNS=1; shift ;;
        -h|--help) usage; exit 0 ;;
        *) echo "error: unknown argument: $1" >&2; usage >&2; exit 2 ;;
    esac
done

if [[ -z "$EXTENSION_DIR" ]]; then
    EXTENSION_DIR="$REPO/src/gnome-extension"
fi

if [[ -n "$OUT" ]]; then
    mkdir -p "$OUT" || { echo "error: cannot create --out $OUT" >&2; exit 2; }
    OUT="$(cd "$OUT" && pwd)"
else
    mkdir -p /tmp/opencode
    OUT="$(mktemp -d /tmp/opencode/kanata-switcher-gnome.XXXXXX)"
fi
mkdir -p "$OUT"/{bin,data,sysdata,config,cache,home,runtime,tmp,strace,pcap,net,dbus,gnome-audit,logs,mock,snapshots,extension,build}
chmod 700 "$OUT/runtime" 2>/dev/null || true

need() {
    command -v "$1" >/dev/null 2>&1 || { echo "error: required tool not found: $1" >&2; exit 2; }
}

need ip
need tcpdump
need python3
need strace
need ss
need setpriv
need dbus-monitor
need dbus-daemon
need gdbus
need gsettings
need glib-compile-schemas
need gnome-shell
need gjs
need timeout

if [[ ! -d "$EXTENSION_DIR" ]]; then
    echo "error: extension directory does not exist: $EXTENSION_DIR" >&2
    exit 2
fi

SUDO=()
if [[ ${EUID} -ne 0 ]]; then
    need sudo
    if sudo -n true 2>/dev/null; then
        SUDO=(sudo -n)
    elif [[ -t 0 ]]; then
        echo "[preflight] root is required for the veth and tcpdump; requesting sudo" >&2
        if sudo -v; then
            SUDO=(sudo)
        else
            echo "error: sudo authentication failed; privileged packet capture is mandatory" >&2
            exit 2
        fi
    else
        echo "error: passwordless sudo is not available and stdin is not a TTY." >&2
        echo "       Privileged packet capture is mandatory; run as root or configure sudo." >&2
        exit 2
    fi
fi

TCPDUMP_VERSION="$(tcpdump --version 2>&1 | head -n 1)"
IP_VERSION="$(ip -V 2>&1 | head -n 1)"
if ! tcpdump --version >/dev/null 2>&1; then
    echo "error: tcpdump is not usable" >&2
    exit 2
fi

if [[ "$CHECK_ONLY" -eq 1 ]]; then
    echo "[check] root access: ok"
    echo "[check] tcpdump: $TCPDUMP_VERSION"
    echo "[check] ip: $IP_VERSION"
    echo "[check] gnome-shell: $(gnome-shell --version 2>&1 | head -n 1)"
    echo "[check] gjs: $(gjs --version 2>&1 | head -n 1)"
    echo "[check] strace: $(strace --version 2>&1 | head -n 1)"
    echo "[check] python: $(python3 --version 2>&1)"
    echo "[check] extension: $EXTENSION_DIR"
    if [[ -S /run/dbus/system_bus_socket ]]; then
        echo "[check] system bus: present"
    else
        echo "[check] system bus: absent"
    fi
    echo "[check] preflight passed"
    exit 0
fi

SUFFIX="$$-$RANDOM"
D_NS="ksg-d-${SUFFIX}"
C_NS="ksg-c-${SUFFIX}"
D_IF="kg$(printf '%04x' $((RANDOM % 65536)))"
C_IF="kh$(printf '%04x' $((RANDOM % 65536)))"
while [[ "$D_IF" == "$C_IF" ]]; do
    C_IF="kh$(printf '%04x' $((RANDOM % 65536)))"
done

SINK_PIDFILE=""
SYS_MON_PIDFILE=""
CAP_PIDFILE=""
SHELL_PID=""
MOCK_PID=""
MON_PID=""
BUS_PID=""
SYS_MON_STATE="unknown"
STATIC_STATUS=0
ANALYZE_STATUS=0
GNOME_PID=""

cleanup() {
    local status=$?
    trap - EXIT INT TERM
    if [[ -n "${SHELL_PID}" ]]; then
        kill -TERM "$SHELL_PID" 2>/dev/null || true
        wait "$SHELL_PID" 2>/dev/null || true
    fi
    if [[ -n "${MOCK_PID}" ]]; then
        kill -TERM "$MOCK_PID" 2>/dev/null || true
        wait "$MOCK_PID" 2>/dev/null || true
    fi
    if [[ -n "${MON_PID}" ]]; then
        kill -TERM "$MON_PID" 2>/dev/null || true
        wait "$MON_PID" 2>/dev/null || true
    fi
    if [[ -n "${BUS_PID}" ]]; then
        "${SUDO[@]}" kill -TERM "$BUS_PID" 2>/dev/null || true
    fi
    if [[ -n "${SYS_MON_PIDFILE}" ]]; then
        "${SUDO[@]}" "$SCRIPT_DIR/netns_admin.sh" stop-pid "$SYS_MON_PIDFILE" >/dev/null 2>&1 || true
    fi
    if [[ -n "${SINK_PIDFILE}" ]]; then
        "${SUDO[@]}" "$SCRIPT_DIR/netns_admin.sh" stop-pid "$SINK_PIDFILE" >/dev/null 2>&1 || true
    fi
    if [[ -n "${CAP_PIDFILE}" ]]; then
        "${SUDO[@]}" "$SCRIPT_DIR/netns_admin.sh" capture-stop "$CAP_PIDFILE" >/dev/null 2>&1 || true
    fi
    if [[ "$KEEP_NETNS" -eq 0 ]]; then
        "${SUDO[@]}" "$SCRIPT_DIR/netns_admin.sh" teardown "$D_NS" "$C_NS" >/dev/null 2>&1 || true
    else
        echo "[keep] network namespaces retained: $D_NS $C_NS" >&2
    fi
    exit "$status"
}
trap cleanup EXIT INT TERM

cat > "$OUT/dbus/session.conf" <<EOF
<!DOCTYPE busconfig PUBLIC "-//freedesktop//DTD D-Bus Bus Configuration 1.0//EN"
 "http://www.freedesktop.org/standards/dbus/1.0/busconfig.dtd">
<busconfig>
  <type>session</type>
  <listen>unix:path=$OUT/dbus/session.sock</listen>
  <auth>EXTERNAL</auth>
  <policy context="default">
    <allow user="*"/>
    <allow own="*"/>
    <allow send_type="method_call"/>
    <allow send_type="signal"/>
    <allow send_type="method_return"/>
    <allow send_type="error"/>
    <allow eavesdrop="true"/>
  </policy>
  <servicedir>/usr/share/dbus-1/services</servicedir>
  <servicedir>/usr/local/share/dbus-1/services</servicedir>
  <servicedir>$OUT/home/.local/share/dbus-1/services</servicedir>
</busconfig>
EOF

if [[ "$SKIP_STATIC" -eq 0 ]]; then
    echo "[static] scanning $EXTENSION_DIR"
    python3 "$SCRIPT_DIR/scan_gnome_extension.py" "$EXTENSION_DIR" \
        --json "$OUT/gnome-audit/static.json" \
        --markdown "$OUT/gnome-audit/static.md"
    STATIC_STATUS=$?
fi

# Install the extension as a *system* extension in a private XDG_DATA_DIRS
# entry. GNOME Shell only loads per-user extensions when
# allow-extension-installation is true, and that setting also enables the
# extensions.gnome.org update check. A system extension lets the audit disable
# installation/update checks without disabling the extension itself.
EXT_DEST="$OUT/sysdata/gnome-shell/extensions/kanata-switcher@7mind.io"
rm -rf "$EXT_DEST"
mkdir -p "$EXT_DEST"
cp -a "$EXTENSION_DIR"/. "$EXT_DEST"/
if [[ -d "$EXT_DEST/schemas" ]]; then
    glib-compile-schemas "$EXT_DEST/schemas" || { echo "error: glib-compile-schemas failed" >&2; exit 2; }
fi

echo "[setup] daemon netns=$D_NS if=$D_IF; capture netns=$C_NS if=$C_IF"
"${SUDO[@]}" "$SCRIPT_DIR/netns_admin.sh" setup \
    "$D_NS" "$C_NS" "$D_IF" "$C_IF" \
    "10.214.0.2/24" "10.214.0.1/24" \
    "fd42:6b73:6773:6e6f::2/64" "fd42:6b73:6773:6e6f::1/64" \
    "$OUT" || { echo "error: network namespace setup failed" >&2; exit 2; }

D_MAC="$(cat "$OUT/net/daemon.mac")"
C_MAC="$(cat "$OUT/net/capture.mac")"
echo "[setup] daemon mac=$D_MAC capture mac=$C_MAC"

SINK_PIDFILE="$OUT/net/sinkhole.pid"
"${SUDO[@]}" "$SCRIPT_DIR/netns_admin.sh" sinkhole-start \
    "$C_NS" "$(id -u)" "$(id -g)" \
    "$SCRIPT_DIR/capture_sinkhole.py" "$SINK_PIDFILE" "$OUT/net/sinkhole.stderr.log" -- \
    --dns-address 10.214.0.1 \
    --dns-address6 fd42:6b73:6773:6e6f::1 \
    --tcp-address 10.214.0.1 \
    --tcp-address6 fd42:6b73:6773:6e6f::1 \
    --answer-ip 10.214.0.1 \
    --dns-log "$OUT/net/dns.jsonl" \
    --tcp-log "$OUT/net/tcp.jsonl" \
    --ready-file "$OUT/net/sinkhole.ready"
for _ in $(seq 1 60); do
    [[ -s "$OUT/net/sinkhole.ready" ]] && break
    sleep 0.1
done
if [[ ! -s "$OUT/net/sinkhole.ready" ]]; then
    echo "error: DNS/TCP sinkhole did not become ready" >&2
    cat "$OUT/net/sinkhole.stderr.log" >&2 || true
    exit 2
fi
echo "[setup] sinkhole ready"

if [[ -S /run/dbus/system_bus_socket ]]; then
    SYS_MON_PIDFILE="$OUT/dbus/system.monitor.pid"
    if "${SUDO[@]}" "$SCRIPT_DIR/netns_admin.sh" system-monitor-start \
        "$OUT/dbus/system.monitor.log" "$SYS_MON_PIDFILE"; then
        SYS_MON_STATE="enabled"
        if grep -qE "Falling back to eavesdropping|Failed to become monitor" "$OUT/dbus/system.monitor.log" 2>/dev/null; then
            SYS_MON_STATE="eavesdrop-fallback"
            echo "[warn] system bus monitor could not become a full monitor; using eavesdropping" >&2
        fi
    elif [[ "$ALLOW_UNMONITORED_SYSTEM_BUS" -eq 1 ]]; then
        SYS_MON_STATE="unavailable-allowed"
        echo "[warn] system bus monitor unavailable; continuing because --allow-unmonitored-system-bus was passed" >&2
    else
        echo "error: system bus monitor is mandatory." >&2
        echo "       Use --allow-unmonitored-system-bus only for a documented exception." >&2
        exit 2
    fi
else
    SYS_MON_STATE="absent"
    echo "[warn] no /run/dbus/system_bus_socket; system bus monitor not applicable" >&2
fi

"${SUDO[@]}" "$SCRIPT_DIR/netns_admin.sh" capture-start \
    "$C_NS" "$C_IF" "$OUT/pcap/daemon.pcap" "$OUT/pcap/daemon.tcpdump.log" || exit 2
CAP_PIDFILE="$OUT/pcap/daemon.pcap.pid"

echo "[bus] starting private session bus inside $D_NS"
BUS_PID="$("${SUDO[@]}" "$SCRIPT_DIR/netns_admin.sh" run-as "$D_NS" "$(id -u)" "$(id -g)" -- \
    dbus-daemon --config-file "$OUT/dbus/session.conf" --fork --print-pid=1 2>"$OUT/logs/bus.stderr.log")"
for _ in $(seq 1 60); do
    [[ -S "$OUT/dbus/session.sock" ]] && break
    sleep 0.1
done
if [[ ! -S "$OUT/dbus/session.sock" ]]; then
    echo "error: private session bus did not start" >&2
    cat "$OUT/logs/bus.stderr.log" >&2 || true
    exit 2
fi
SESSION_ADDRESS="unix:path=$OUT/dbus/session.sock"
echo "[bus] $SESSION_ADDRESS pid=$BUS_PID"

dbus-monitor --address "$SESSION_ADDRESS" > "$OUT/dbus/session.monitor.log" 2>&1 &
MON_PID=$!
sleep 0.3
if ! kill -0 "$MON_PID" 2>/dev/null; then
    echo "error: session bus monitor failed" >&2
    cat "$OUT/dbus/session.monitor.log" >&2 || true
    exit 2
fi

echo "[settings] pre-enabling kanata-switcher@7mind.io via keyfile backend"
env HOME="$OUT/home" \
    XDG_CONFIG_HOME="$OUT/config" \
    XDG_DATA_HOME="$OUT/data" \
    XDG_CACHE_HOME="$OUT/cache" \
    GSETTINGS_BACKEND=keyfile \
    gsettings set org.gnome.shell disable-user-extensions false || exit 2
env HOME="$OUT/home" \
    XDG_CONFIG_HOME="$OUT/config" \
    XDG_DATA_HOME="$OUT/data" \
    XDG_CACHE_HOME="$OUT/cache" \
    GSETTINGS_BACKEND=keyfile \
    gsettings set org.gnome.shell enabled-extensions "['kanata-switcher@7mind.io']" || exit 2
env HOME="$OUT/home" \
    XDG_CONFIG_HOME="$OUT/config" \
    XDG_DATA_HOME="$OUT/data" \
    XDG_CACHE_HOME="$OUT/cache" \
    GSETTINGS_BACKEND=keyfile \
    gsettings set org.gnome.shell allow-extension-installation false || exit 2

# GNOME Shell always enables system "mode" extensions (Ubuntu's dock, app
# indicators, search providers, etc.). They are not part of this audit and
# their metadata signals add noise, so disable every system extension except
# the target. The target itself is installed in the private system data dir.
mapfile -t SYSTEM_EXT_UUIDS < <(
    for dir in /usr/local/share/gnome-shell/extensions /usr/share/gnome-shell/extensions; do
        [[ -d "$dir" ]] || continue
        find "$dir" -mindepth 1 -maxdepth 1 -type d -printf '%f\n'
    done | sort -u | grep -vx 'kanata-switcher@7mind.io' || true
)
DISABLED_EXTENSIONS="$(python3 -c 'import sys; print("[" + ", ".join(repr(x) for x in sys.argv[1:]) + "]")' "${SYSTEM_EXT_UUIDS[@]}")"
env HOME="$OUT/home" \
    XDG_CONFIG_HOME="$OUT/config" \
    XDG_DATA_HOME="$OUT/data" \
    XDG_CACHE_HOME="$OUT/cache" \
    GSETTINGS_BACKEND=keyfile \
    gsettings set org.gnome.shell disabled-extensions "$DISABLED_EXTENSIONS" || exit 2

echo "[mock] starting mock daemon in $D_NS"
"${SUDO[@]}" "$SCRIPT_DIR/netns_admin.sh" run-as "$D_NS" "$(id -u)" "$(id -g)" -- \
    env HOME="$OUT/home" \
        XDG_RUNTIME_DIR="$OUT/runtime" \
        DBUS_SESSION_BUS_ADDRESS="$SESSION_ADDRESS" \
        PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin" \
        python3 "$SCRIPT_DIR/mock_gnome_daemon.py" \
        --log "$OUT/mock/mock.jsonl" \
        --ready-file "$OUT/mock/ready" \
        --emit-delay 3 \
        --exit-after "$((TIMEOUT + 15))" \
    >"$OUT/logs/mock.stderr.log" 2>&1 &
MOCK_PID=$!
for _ in $(seq 1 60); do
    [[ -s "$OUT/mock/ready" ]] && break
    sleep 0.1
done
if [[ ! -s "$OUT/mock/ready" ]]; then
    echo "error: mock daemon did not start" >&2
    cat "$OUT/logs/mock.stderr.log" >&2 || true
    exit 2
fi
echo "[mock] ready"

TRACE_EVENTS="%network,%process,openat,open,memfd_create,io_uring_setup,io_uring_enter,io_uring_register,bpf,init_module,finit_module,ptrace,unshare,setns,keyctl,add_key,request_key,mount,pivot_root,chroot"
for extra in openat2 execveat pidfd_getfd process_vm_readv process_vm_writev sendmmsg recvmmsg sendfile splice ioctl; do
    if strace -qq -e trace="$extra" /bin/true >/dev/null 2>&1; then
        TRACE_EVENTS+=",$extra"
    fi
done

echo "[run] nested gnome-shell timeout=${TIMEOUT}s out=$OUT"
"${SUDO[@]}" "$SCRIPT_DIR/netns_admin.sh" run-as "$D_NS" "$(id -u)" "$(id -g)" -- \
    env -i \
        HOME="$OUT/home" \
        USER="$(id -un)" \
        LOGNAME="$(id -un)" \
        SHELL=/bin/sh \
        LANG=C.UTF-8 \
        LC_ALL=C.UTF-8 \
        PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin" \
        XDG_CONFIG_HOME="$OUT/config" \
        XDG_CONFIG_DIRS=/etc/xdg \
        XDG_DATA_HOME="$OUT/data" \
        XDG_DATA_DIRS="$OUT/sysdata:/usr/local/share:/usr/share" \
        XDG_CACHE_HOME="$OUT/cache" \
        XDG_RUNTIME_DIR="$OUT/runtime" \
        TMPDIR="$OUT/tmp" \
        GSETTINGS_BACKEND=keyfile \
        DBUS_SESSION_BUS_ADDRESS="$SESSION_ADDRESS" \
        XDG_CURRENT_DESKTOP=GNOME \
        XDG_SESSION_DESKTOP=gnome \
        XDG_SESSION_TYPE=wayland \
        MUTTER_DEBUG_DUMMY_MODE_SPECS=1280x720 \
        LIBGL_ALWAYS_SOFTWARE=1 \
        NO_AT_BRIDGE=1 \
        strace -ff -ttt -s 256 -v -o "$OUT/strace/daemon" -e trace="$TRACE_EVENTS" \
        timeout -s TERM -k 5 "$TIMEOUT" gnome-shell --headless --wayland --no-x11 \
    >"$OUT/gnome-audit/shell.log" 2>&1 &
SHELL_PID=$!

for _ in $(seq 1 120); do
    gdbus call --address "$SESSION_ADDRESS" \
        --dest org.freedesktop.DBus \
        --object-path /org/freedesktop/DBus \
        --method org.freedesktop.DBus.NameHasOwner org.gnome.Shell 2>/dev/null | grep -q true && break
    sleep 0.25
done

if ! gdbus call --address "$SESSION_ADDRESS" \
    --dest org.freedesktop.DBus \
    --object-path /org/freedesktop/DBus \
    --method org.freedesktop.DBus.NameHasOwner org.gnome.Shell 2>/dev/null | grep -q true; then
    echo "error: nested gnome-shell did not start" >&2
    tail -n 60 "$OUT/gnome-audit/shell.log" >&2 || true
    exit 2
fi

echo "[probe] extension state"
for _ in $(seq 1 40); do
    if gdbus call --address "$SESSION_ADDRESS" \
        --dest org.gnome.Shell.Extensions \
        --object-path /org/gnome/Shell/Extensions \
        --method org.gnome.Shell.Extensions.GetExtensionInfo kanata-switcher@7mind.io \
        >"$OUT/gnome-audit/extension-info.txt" 2>&1 \
        && grep -q "'enabled': <true>" "$OUT/gnome-audit/extension-info.txt"; then
        break
    fi
    sleep 0.25
done
grep -q "'enabled': <true>" "$OUT/gnome-audit/extension-info.txt" 2>/dev/null \
    || echo "warning: extension is not reported as enabled" >&2

echo "[probe] extension GetFocus"
OWNER="$(gdbus call --address "$SESSION_ADDRESS" \
    --dest org.freedesktop.DBus \
    --object-path /org/freedesktop/DBus \
    --method org.freedesktop.DBus.GetNameOwner org.gnome.Shell 2>/dev/null \
    | sed "s/^('//;s/',)$//")"
if [[ -n "$OWNER" ]]; then
    if ! gdbus call --address "$SESSION_ADDRESS" \
        --dest "$OWNER" \
        --object-path /com/github/kanata/Switcher/extensions/GNOME \
        --method com.github.kanata.Switcher.extensions.GNOME.GetFocus \
        >"$OUT/gnome-audit/focus.log" 2>"$OUT/gnome-audit/focus.stderr.log"; then
        # A failed call leaves only stderr; the analyzer treats a missing
        # focus.log as the extension not answering GetFocus.
        rm -f "$OUT/gnome-audit/focus.log"
    fi
fi

echo "[probe] waiting for extension -> mock daemon calls"
for _ in $(seq 1 60); do
    if grep -q '"name": "GetStatus"' "$OUT/mock/mock.jsonl" 2>/dev/null \
        && grep -q '"name": "GetPaused"' "$OUT/mock/mock.jsonl" 2>/dev/null; then
        break
    fi
    sleep 0.25
done

sleep 1
grep -E "KanataSwitcher.*(error|Error|failed|Failed)|JS ERROR.*KanataSwitcher" \
    "$OUT/gnome-audit/shell.log" >"$OUT/gnome-audit/extension-errors.log" 2>/dev/null || true

GNOME_PID=""
while read -r pid; do
    [[ -n "$pid" ]] || continue
    if [[ "$(cat "/proc/$pid/comm" 2>/dev/null)" == "gnome-shell" ]]; then
        GNOME_PID="$pid"
        break
    fi
done < <("${SUDO[@]}" ip netns pids "$D_NS" 2>/dev/null || true)

echo "[stop] terminating nested gnome-shell and its namespace processes"
"${SUDO[@]}" ip netns pids "$D_NS" 2>/dev/null | xargs -r "${SUDO[@]}" kill -TERM 2>/dev/null || true
for _ in $(seq 1 60); do
    if ! "${SUDO[@]}" ip netns pids "$D_NS" 2>/dev/null | grep -q .; then
        break
    fi
    sleep 0.1
done
"${SUDO[@]}" ip netns pids "$D_NS" 2>/dev/null | xargs -r "${SUDO[@]}" kill -KILL 2>/dev/null || true
wait "$SHELL_PID" 2>/dev/null || true
wait "$MOCK_PID" 2>/dev/null || true

if [[ -n "$CAP_PIDFILE" ]]; then
    "${SUDO[@]}" "$SCRIPT_DIR/netns_admin.sh" capture-stop "$CAP_PIDFILE" || true
    CAP_PIDFILE=""
fi
if [[ ! -s "$OUT/pcap/daemon.pcap" ]] || [[ "$(stat -c %s "$OUT/pcap/daemon.pcap" 2>/dev/null || echo 0)" -lt 24 ]]; then
    echo "error: packet capture is missing or empty" >&2
    cat "$OUT/pcap/daemon.tcpdump.log" 2>/dev/null >&2 || true
    exit 2
fi

if [[ -n "$MON_PID" ]]; then
    kill -TERM "$MON_PID" 2>/dev/null || true
    wait "$MON_PID" 2>/dev/null || true
    MON_PID=""
fi

META_MODE="gnome-extension" META_BIN="$(command -v gnome-shell)" META_REPO="$REPO" META_OUT="$OUT" \
META_D_MAC="$D_MAC" META_C_MAC="$C_MAC" META_D_NS="$D_NS" META_C_NS="$C_NS" \
META_D_IF="$D_IF" META_C_IF="$C_IF" META_TCPDUMP="$TCPDUMP_VERSION" META_IP="$IP_VERSION" \
META_SYS_MON="$SYS_MON_STATE" META_TIMEOUT="$TIMEOUT" META_GNOME_PID="$GNOME_PID" \
META_TRACE_EVENTS="$TRACE_EVENTS" \
python3 - "$OUT/meta.json" <<'PY'
import json, os, sys, datetime
keys = {
    "mode": "META_MODE", "binary": "META_BIN", "repo": "META_REPO", "out": "META_OUT",
    "daemon_mac": "META_D_MAC", "capture_mac": "META_C_MAC",
    "daemon_ns": "META_D_NS", "capture_ns": "META_C_NS",
    "daemon_if": "META_D_IF", "capture_if": "META_C_IF",
    "tcpdump": "META_TCPDUMP", "ip": "META_IP",
    "system_bus_monitor": "META_SYS_MON", "timeout": "META_TIMEOUT",
    "daemon_pid": "META_GNOME_PID", "trace_events": "META_TRACE_EVENTS",
}
data = {key: os.environ.get(env, "") for key, env in keys.items()}
data["expected_host"] = "127.0.0.1"
data["expected_port"] = 0
data["daemon_ip4"] = "10.214.0.2"
data["capture_ip4"] = "10.214.0.1"
data["daemon_ip6"] = "fd42:6b73:6773:6e6f::2"
data["capture_ip6"] = "fd42:6b73:6773:6e6f::1"
data["privileged_capture"] = True
data["build_traced"] = False
data["session_bus"] = "private"
data["network_namespace"] = "veth pair; no NAT; sinkhole capture"
data["started_at"] = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
data["pcap_files"] = ["daemon.pcap"]
with open(sys.argv[1], "w", encoding="utf-8") as handle:
    json.dump(data, handle, indent=2, sort_keys=True)
    handle.write("\n")
PY

echo "[analyze] parsing strace, pcap, sinkhole, D-Bus, and GNOME evidence"
python3 "$SKILL_DIR/scripts/analyze_dynamic_logs.py" "$OUT" \
    --profile gnome-extension \
    --strace-dir "$OUT/strace" \
    --pcap-dir "$OUT/pcap" \
    --sinkhole-dir "$OUT/net" \
    --dbus-dir "$OUT/dbus" \
    --build-dir "$OUT/build" \
    --gnome-dir "$OUT/gnome-audit" \
    --snapshots-dir "$OUT/snapshots" \
    --mock-dir "$OUT/mock" \
    --unix-glob "$OUT/dbus/session.sock" \
    --unix-glob "$OUT/runtime/*" \
    --unix-glob "$OUT/cache/ibus/*" \
    --unix-glob "/run/user/*/keyring/*" \
    --json "$OUT/report.json" --markdown "$OUT/report.md"
ANALYZE_STATUS=$?

if [[ "$STATIC_STATUS" -eq 1 || "$ANALYZE_STATUS" -eq 1 ]]; then
    echo "[done] findings: static=$STATIC_STATUS dynamic=$ANALYZE_STATUS"
    echo "[done] evidence: $OUT"
    exit 1
fi
if [[ "$STATIC_STATUS" -ne 0 || "$ANALYZE_STATUS" -ne 0 ]]; then
    echo "[error] static=$STATIC_STATUS dynamic=$ANALYZE_STATUS; see $OUT" >&2
    exit 2
fi

echo "[done] clean: static=0 dynamic=0"
echo "[done] evidence: $OUT"
echo "[done] report: $OUT/report.md  static: $OUT/gnome-audit/static.md"
exit 0
