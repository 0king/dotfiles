#!/usr/bin/env bash
# Privileged dynamic network audit for kanata-switcher.
#
# The target runs as the invoking user inside a dedicated network namespace.
# A veth pair connects that namespace to a capture namespace with no NAT and
# no route to the real network. tcpdump on the capture-side veth is mandatory;
# DNS and TCP sinkholes make the network look usable and log every attempt.
# The private session bus and the system bus are monitored with dbus-monitor,
# and a source build is traced both during `cargo fetch` (host network) and
# during `cargo build --offline` (inside the veth namespace).
#
# The harness fails closed when root/sudo, tcpdump, or the system bus monitor
# is unavailable. Use --allow-unmonitored-system-bus only for a documented
# exception on a host that genuinely has no system bus.
#
# Usage:
#   run_dynamic_network_audit.sh [--repo PATH] [--out DIR] [--host HOST]
#       [--port PORT] [--timeout SECONDS] [--commit REV]
#       [--scenario baseline|minimal|host-desktop]
#       [--binary PATH | --command 'CMD'] [--skip-build]
#       [--gnome-extension] [--allow-unmonitored-system-bus]
#       [--check] [--keep-netns]
#
# Exit codes: 0 = analyzer clean, 1 = findings, 2 = harness/setup error.

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SKILL_DIR="$(dirname "$SCRIPT_DIR")"
REPO="${KANATA_SWITCHER_REPO:-$PWD}"
OUT=""
PORT=10000
HOST=127.0.0.1
TIMEOUT=15
SCENARIO=baseline
BINARY=""
COMMAND=""
COMMIT=""
SKIP_BUILD=0
MODE=daemon
RUN_GNOME=0
ALLOW_UNMONITORED_SYSTEM_BUS=0
CHECK_ONLY=0
KEEP_NETNS=0

usage() {
    sed -n '2,/^$/p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --repo) REPO="$2"; shift 2 ;;
        --out) OUT="$2"; shift 2 ;;
        --port) PORT="$2"; shift 2 ;;
        --host) HOST="$2"; shift 2 ;;
        --timeout) TIMEOUT="$2"; shift 2 ;;
        --scenario) SCENARIO="$2"; shift 2 ;;
        --binary) BINARY="$2"; MODE=daemon; shift 2 ;;
        --command) COMMAND="$2"; MODE=command; shift 2 ;;
        --commit) COMMIT="$2"; shift 2 ;;
        --skip-build) SKIP_BUILD=1; shift ;;
        --gnome-extension) RUN_GNOME=1; shift ;;
        --allow-unmonitored-system-bus) ALLOW_UNMONITORED_SYSTEM_BUS=1; shift ;;
        --check) CHECK_ONLY=1; shift ;;
        --keep-netns) KEEP_NETNS=1; shift ;;
        -h|--help) usage; exit 0 ;;
        *) echo "error: unknown argument: $1" >&2; usage >&2; exit 2 ;;
    esac
done

if [[ -n "$BINARY" && -n "$COMMAND" ]]; then
    echo "error: --binary and --command are mutually exclusive" >&2
    exit 2
fi
if [[ "$SCENARIO" != "baseline" && "$SCENARIO" != "minimal" && "$SCENARIO" != "host-desktop" ]]; then
    echo "error: --scenario must be baseline, minimal, or host-desktop" >&2
    exit 2
fi
if [[ "$MODE" == "command" ]]; then
    SKIP_BUILD=1
fi
if [[ -n "$OUT" ]]; then
    mkdir -p "$OUT" || { echo "error: cannot create --out $OUT" >&2; exit 2; }
    OUT="$(cd "$OUT" && pwd)"
else
    mkdir -p /tmp/opencode
    OUT="$(mktemp -d /tmp/opencode/kanata-switcher-dynamic.XXXXXX)"
fi
mkdir -p "$OUT"/{bin,src,target,build,pcap,strace,snapshots,mock,daemon,home,runtime,tmp,logs,net,dbus,gnome}
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
need bwrap
if [[ "$SCENARIO" != "host-desktop" ]]; then
    need gdbus
fi
if [[ "$MODE" == "daemon" && -z "$BINARY" && "$SKIP_BUILD" -eq 0 ]]; then
    need git
    need cargo
    need rustc
fi
if [[ "$RUN_GNOME" -eq 1 ]]; then
    need gnome-shell
    need gjs
    need glib-compile-schemas
    need gsettings
    need gdbus
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
    echo "[check] bwrap: $(bwrap --version 2>&1 | head -n 1)"
    echo "[check] strace: $(strace --version 2>&1 | head -n 1)"
    echo "[check] python: $(python3 --version 2>&1)"
    if [[ -S /run/dbus/system_bus_socket ]]; then
        echo "[check] system bus: present"
    else
        echo "[check] system bus: absent"
    fi
    echo "[check] preflight passed"
    exit 0
fi

SUFFIX="$$-$RANDOM"
D_NS="ks-d-${SUFFIX}"
C_NS="ks-c-${SUFFIX}"
D_IF="kd$(printf '%04x' $((RANDOM % 65536)))"
C_IF="kc$(printf '%04x' $((RANDOM % 65536)))"
while [[ "$D_IF" == "$C_IF" ]]; do
    C_IF="kc$(printf '%04x' $((RANDOM % 65536)))"
done

D_MAC=""
C_MAC=""
SINK_PIDFILE=""
SYS_MON_PIDFILE=""
CAP_PIDFILE=""
SYS_MON_STATE="unknown"

cleanup() {
    local status=$?
    trap - EXIT INT TERM
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

cat > "$OUT/net/resolv.conf" <<'EOF'
nameserver 10.213.0.1
options timeout:1 attempts:1
EOF
cat > "$OUT/net/hosts" <<'EOF'
127.0.0.1 localhost
::1 localhost
10.213.0.2 audit-daemon
EOF

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

echo "[setup] daemon netns=$D_NS if=$D_IF; capture netns=$C_NS if=$C_IF"
"${SUDO[@]}" "$SCRIPT_DIR/netns_admin.sh" setup \
    "$D_NS" "$C_NS" "$D_IF" "$C_IF" \
    "10.213.0.2/24" "10.213.0.1/24" \
    "fd42:6b73:6175:6469::2/64" "fd42:6b73:6175:6469::1/64" \
    "$OUT" || { echo "error: network namespace setup failed" >&2; exit 2; }

D_MAC="$(cat "$OUT/net/daemon.mac")"
C_MAC="$(cat "$OUT/net/capture.mac")"
echo "[setup] daemon mac=$D_MAC capture mac=$C_MAC"

SINK_PIDFILE="$OUT/net/sinkhole.pid"
"${SUDO[@]}" "$SCRIPT_DIR/netns_admin.sh" sinkhole-start \
    "$C_NS" "$(id -u)" "$(id -g)" \
    "$SCRIPT_DIR/capture_sinkhole.py" "$SINK_PIDFILE" "$OUT/net/sinkhole.stderr.log" -- \
    --dns-address 10.213.0.1 \
    --dns-address6 fd42:6b73:6175:6469::1 \
    --tcp-address 10.213.0.1 \
    --tcp-address6 fd42:6b73:6175:6469::1 \
    --answer-ip 10.213.0.1 \
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

start_capture() {
    local pcap="$1" log="$2"
    CAP_PIDFILE="${pcap}.pid"
    "${SUDO[@]}" "$SCRIPT_DIR/netns_admin.sh" capture-start "$C_NS" "$C_IF" "$pcap" "$log" || exit 2
}

stop_capture() {
    local pcap="$1"
    if [[ -n "${CAP_PIDFILE}" ]]; then
        "${SUDO[@]}" "$SCRIPT_DIR/netns_admin.sh" capture-stop "$CAP_PIDFILE" || true
        CAP_PIDFILE=""
    fi
    local size
    size="$(stat -c %s "$pcap" 2>/dev/null || echo 0)"
    if [[ "$size" -lt 24 ]]; then
        echo "error: packet capture is missing or empty: $pcap" >&2
        cat "${pcap}.log" 2>/dev/null >&2 || true
        exit 2
    fi
}

TRACE_EVENTS="%network,%process,openat,open,memfd_create,io_uring_setup,io_uring_enter,io_uring_register,bpf,init_module,finit_module,ptrace,unshare,setns,keyctl,add_key,request_key,mount,pivot_root,chroot"
for extra in openat2 execveat pidfd_getfd process_vm_readv process_vm_writev sendmmsg recvmmsg sendfile splice ioctl; do
    if strace -qq -e trace="$extra" /bin/true >/dev/null 2>&1; then
        TRACE_EVENTS+=",$extra"
    fi
done

BIN="$BINARY"
BUILD_TRACED=0
if [[ -n "$BIN" ]]; then
    BIN="$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")"
    [[ -f "$BIN" ]] || { echo "error: --binary is not a file: $BIN" >&2; exit 2; }
    cp -f "$BIN" "$OUT/bin/kanata-switcher"
    BIN="$OUT/bin/kanata-switcher"
    chmod +x "$BIN"
elif [[ "$MODE" == "daemon" ]]; then
    [[ -f "$REPO/Cargo.toml" ]] || { echo "error: no Cargo.toml under --repo $REPO" >&2; exit 2; }
    if [[ -z "$COMMIT" ]]; then
        COMMIT="$(git -C "$REPO" rev-parse HEAD)"
    fi
    if [[ "$SKIP_BUILD" -eq 0 ]]; then
        echo "[build] archiving $COMMIT from $REPO"
        rm -rf "$OUT/src"
        mkdir -p "$OUT/src"
        git -C "$REPO" archive --format=tar "$COMMIT" | tar -x -C "$OUT/src" || {
            echo "error: git archive failed" >&2; exit 2;
        }
        echo "[build] cargo fetch --locked under strace (host network)"
        (
            cd "$OUT/src" || exit 2
            CARGO_HOME="${CARGO_HOME:-$HOME/.cargo}" \
                strace -ff -ttt -s 256 -v -o "$OUT/build/fetch.strace" -e trace=%network \
                cargo fetch --locked
        ) >"$OUT/build/fetch.log" 2>&1 || {
            echo "error: cargo fetch failed; see $OUT/build/fetch.log" >&2
            tail -n 40 "$OUT/build/fetch.log" >&2 || true
            exit 2
        }
        echo "[build] cargo build --release --locked --offline inside $D_NS under capture"
        start_capture "$OUT/pcap/build.pcap" "$OUT/pcap/build.tcpdump.log"
        (
            "${SUDO[@]}" "$SCRIPT_DIR/netns_admin.sh" run-as "$D_NS" "$(id -u)" "$(id -g)" -- \
                env HOME="$OUT/home" \
                    CARGO_HOME="${CARGO_HOME:-$HOME/.cargo}" \
                    CARGO_TARGET_DIR="$OUT/target" \
                    PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin" \
                    strace -ff -ttt -s 256 -v -o "$OUT/build/build.strace" -e trace=%network \
                    cargo build --release --locked --offline --manifest-path "$OUT/src/Cargo.toml"
        ) >"$OUT/build/build.log" 2>&1 || {
            echo "error: release build failed; see $OUT/build/build.log" >&2
            tail -n 60 "$OUT/build/build.log" >&2 || true
            stop_capture "$OUT/pcap/build.pcap"
            exit 2
        }
        stop_capture "$OUT/pcap/build.pcap"
        BUILD_TRACED=1
    fi
    BIN="$OUT/target/release/kanata-switcher"
    [[ -f "$BIN" ]] || { echo "error: built binary not found: $BIN" >&2; exit 2; }
else
    BIN=""
fi

BIN_SHA=""
if [[ -n "$BIN" ]]; then
    BIN_SHA="$(sha256sum "$BIN" | awk '{print $1}')"
fi
LOCK_SHA=""
if [[ -f "$OUT/src/Cargo.lock" ]]; then
    LOCK_SHA="$(sha256sum "$OUT/src/Cargo.lock" | awk '{print $1}')"
elif [[ -f "$REPO/Cargo.lock" ]]; then
    LOCK_SHA="$(sha256sum "$REPO/Cargo.lock" | awk '{print $1}')"
fi

TAG="$(git -C "$REPO" describe --tags --always 2>/dev/null || true)"
DIRTY="$(git -C "$REPO" status --porcelain 2>/dev/null | head -n 20 | tr '\n' ';')"
CARGO_VERSION="$(cargo --version 2>/dev/null || true)"
RUSTC_VERSION="$(rustc --version 2>/dev/null || true)"
TIMESTAMP="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
SESSION_BUS_KIND="private"
if [[ "$SCENARIO" == "host-desktop" ]]; then
    SESSION_BUS_KIND="host"
fi

META_MODE="$MODE" META_BIN="$BIN" META_REPO="$REPO" META_OUT="$OUT" \
META_COMMIT="$COMMIT" META_TAG="$TAG" META_DIRTY="$DIRTY" \
META_BIN_SHA="$BIN_SHA" META_LOCK_SHA="$LOCK_SHA" \
META_HOST="$HOST" META_PORT="$PORT" META_SCENARIO="$SCENARIO" \
META_COMMAND="$COMMAND" META_TIMESTAMP="$TIMESTAMP" \
META_CARGO="$CARGO_VERSION" META_RUSTC="$RUSTC_VERSION" \
META_D_MAC="$D_MAC" META_C_MAC="$C_MAC" \
META_D_NS="$D_NS" META_C_NS="$C_NS" META_D_IF="$D_IF" META_C_IF="$C_IF" \
META_TCPDUMP="$TCPDUMP_VERSION" META_IP="$IP_VERSION" \
META_SYS_MON="$SYS_MON_STATE" META_BUILD_TRACED="$BUILD_TRACED" \
META_SESSION_BUS="$SESSION_BUS_KIND" META_TRACE_EVENTS="$TRACE_EVENTS" \
python3 - "$OUT/meta.json" <<'PY'
import json, os, sys
keys = {
    "mode": "META_MODE", "binary": "META_BIN", "repo": "META_REPO",
    "out": "META_OUT", "commit": "META_COMMIT", "tag": "META_TAG",
    "dirty": "META_DIRTY", "binary_sha256": "META_BIN_SHA",
    "lock_sha256": "META_LOCK_SHA", "expected_host": "META_HOST",
    "expected_port": "META_PORT", "scenario": "META_SCENARIO",
    "command": "META_COMMAND", "started_at": "META_TIMESTAMP",
    "cargo": "META_CARGO", "rustc": "META_RUSTC",
    "daemon_mac": "META_D_MAC", "capture_mac": "META_C_MAC",
    "daemon_ns": "META_D_NS", "capture_ns": "META_C_NS",
    "daemon_if": "META_D_IF", "capture_if": "META_C_IF",
    "tcpdump": "META_TCPDUMP", "ip": "META_IP",
    "system_bus_monitor": "META_SYS_MON",
    "build_traced": "META_BUILD_TRACED",
    "session_bus": "META_SESSION_BUS",
    "trace_events": "META_TRACE_EVENTS",
}
data = {key: os.environ.get(env, "") for key, env in keys.items()}
data["expected_port"] = int(data["expected_port"] or 0)
data["build_traced"] = data["build_traced"] == "1"
data["network_namespace"] = "veth pair; no NAT; sinkhole capture"
data["privileged_capture"] = True
data["daemon_ip4"] = "10.213.0.2"
data["capture_ip4"] = "10.213.0.1"
data["daemon_ip6"] = "fd42:6b73:6175:6469::2"
data["capture_ip6"] = "fd42:6b73:6175:6469::1"
data["pcap_files"] = ["daemon.pcap"] + (["build.pcap"] if data["build_traced"] else [])
with open(sys.argv[1], "w", encoding="utf-8") as handle:
    json.dump(data, handle, indent=2, sort_keys=True)
    handle.write("\n")
PY

mkdir -p "$OUT/home/.config/kanata"
cat > "$OUT/home/.config/kanata/kanata-switcher.json" <<'JSON'
[
  {"default": "default"},
  {"class": "firefox", "layer": "browser"},
  {"class": "alacritty", "title": "vim", "layer": "vim"}
]
JSON

cat > "$OUT/inner.sh" <<'INNER_EOF'
#!/usr/bin/env bash
set -uo pipefail
OUT="$1"; BIN="$2"; MODE="$3"; PORT="$4"; HOST="$5"; TIMEOUT="$6"; SCENARIO="$7"; SKILL_DIR="$8"; COMMAND="$9"
D_MAC="${10}"; C_MAC="${11}"

mkdir -p "$OUT"/{strace,snapshots,mock,daemon,home,runtime,tmp,logs,dbus}
export HOME="$OUT/home"
export XDG_CONFIG_HOME="$OUT/home/.config"
export XDG_CACHE_HOME="$OUT/home/.cache"
export XDG_DATA_HOME="$OUT/home/.local/share"
export TMPDIR="$OUT/tmp"
if [[ "$SCENARIO" != "host-desktop" ]]; then
    export XDG_RUNTIME_DIR="$OUT/runtime"
fi
export PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
export NO_AT_BRIDGE=1
export RUST_BACKTRACE=1

if [[ "$SCENARIO" == "baseline" ]]; then
    export XDG_CURRENT_DESKTOP=GNOME
    unset WAYLAND_DISPLAY DISPLAY KDE_SESSION_VERSION GNOME_SETUP_DISPLAY
elif [[ "$SCENARIO" == "minimal" ]]; then
    unset XDG_CURRENT_DESKTOP WAYLAND_DISPLAY DISPLAY KDE_SESSION_VERSION GNOME_SETUP_DISPLAY
fi

BUS_PID=""
MON_PID=""
MOCK_PID=""
RUN_PID=""
EXIT_CODE=0

stop_bus() {
    if [[ -n "$MON_PID" ]]; then
        kill -TERM "$MON_PID" 2>/dev/null || true
        wait "$MON_PID" 2>/dev/null || true
    fi
    if [[ -n "$BUS_PID" ]]; then
        kill -TERM "$BUS_PID" 2>/dev/null || true
        for _ in $(seq 1 20); do kill -0 "$BUS_PID" 2>/dev/null || break; sleep 0.1; done
        kill -KILL "$BUS_PID" 2>/dev/null || true
    fi
}

if [[ "$SCENARIO" == "host-desktop" ]]; then
    if [[ -z "${DBUS_SESSION_BUS_ADDRESS:-}" ]]; then
        echo "error: host-desktop requires DBUS_SESSION_BUS_ADDRESS" >&2
        exit 2
    fi
else
    BUS_PID="$(dbus-daemon --config-file "$OUT/dbus/session.conf" --fork --print-pid=1)"
    export DBUS_SESSION_BUS_ADDRESS="unix:path=$OUT/dbus/session.sock"
    for _ in $(seq 1 40); do
        [[ -S "$OUT/dbus/session.sock" ]] && break
        sleep 0.1
    done
    if [[ ! -S "$OUT/dbus/session.sock" ]]; then
        echo "error: private session bus did not start" >&2
        exit 2
    fi
fi

dbus-monitor --address "$DBUS_SESSION_BUS_ADDRESS" > "$OUT/dbus/session.monitor.log" 2>&1 &
MON_PID=$!
sleep 0.3
if ! kill -0 "$MON_PID" 2>/dev/null; then
    echo "error: session bus monitor failed" >&2
    cat "$OUT/dbus/session.monitor.log" >&2 || true
    stop_bus
    exit 2
fi

if [[ "$MODE" == "daemon" ]]; then
    python3 "$SKILL_DIR/scripts/mock_kanata.py" \
        --host 127.0.0.1 --port "$PORT" \
        --port-file "$OUT/mock/port" --log "$OUT/mock/kanata.log" \
        >"$OUT/mock/stdout.log" 2>"$OUT/mock/stderr.log" &
    MOCK_PID=$!
    for _ in $(seq 1 40); do
        [[ -s "$OUT/mock/port" ]] && break
        sleep 0.25
    done
    if [[ ! -s "$OUT/mock/port" ]]; then
        echo "error: mock kanata did not start" >&2
        kill -TERM "$MOCK_PID" 2>/dev/null || true
        stop_bus
        exit 2
    fi
fi

BWRAP_ARGS=(
    --unshare-pid --unshare-ipc --unshare-uts
    --die-with-parent --new-session
    --ro-bind / /
    --dev /dev
    --proc /proc
    --tmpfs /tmp
    --dir /tmp/opencode
    --dir "$OUT"
    --bind "$OUT" "$OUT"
    --ro-bind "$OUT/net/resolv.conf" /etc/resolv.conf
    --ro-bind "$OUT/net/hosts" /etc/hosts
    --tmpfs /dev/shm
    --setenv HOME "$OUT/home"
    --setenv XDG_CONFIG_HOME "$OUT/home/.config"
    --setenv XDG_CACHE_HOME "$OUT/home/.cache"
    --setenv XDG_DATA_HOME "$OUT/home/.local/share"
    --setenv TMPDIR "$OUT/tmp"
    --setenv PATH "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
    --setenv DBUS_SESSION_BUS_ADDRESS "$DBUS_SESSION_BUS_ADDRESS"
    --setenv NO_AT_BRIDGE "1"
    --setenv RUST_BACKTRACE "1"
    --chdir "$OUT"
)
if [[ -S /run/dbus/system_bus_socket ]]; then
    BWRAP_ARGS+=(--bind /run/dbus/system_bus_socket /run/dbus/system_bus_socket)
fi
if [[ "$SCENARIO" == "host-desktop" ]]; then
    BWRAP_ARGS+=(--setenv XDG_RUNTIME_DIR "${XDG_RUNTIME_DIR:-/run/user/$(id -u)}")
    if [[ -d /tmp/.X11-unix ]]; then
        BWRAP_ARGS+=(--ro-bind /tmp/.X11-unix /tmp/.X11-unix)
    fi
    if [[ -n "${WAYLAND_DISPLAY:-}" ]]; then
        BWRAP_ARGS+=(--setenv WAYLAND_DISPLAY "$WAYLAND_DISPLAY")
    fi
    if [[ -n "${DISPLAY:-}" ]]; then
        BWRAP_ARGS+=(--setenv DISPLAY "$DISPLAY")
    fi
else
    BWRAP_ARGS+=(--setenv XDG_RUNTIME_DIR "$OUT/runtime")
fi

snapshot_loop() {
    local i=0
    while kill -0 "$RUN_PID" 2>/dev/null; do
        i=$((i + 1))
        ss -tanp > "$OUT/snapshots/ss-tcp-$i.txt" 2>/dev/null || true
        ss -uanp > "$OUT/snapshots/ss-udp-$i.txt" 2>/dev/null || true
        ss -lxnp > "$OUT/snapshots/ss-unix-$i.txt" 2>/dev/null || true
        for table in tcp tcp6 udp udp6 packet netlink unix raw raw6; do
            if [[ -r "/proc/net/$table" ]]; then
                cp "/proc/net/$table" "$OUT/snapshots/procnet-$table-$i.txt" 2>/dev/null || true
            fi
        done
        sleep 0.5
    done
}

if [[ "$MODE" == "daemon" ]]; then
    DAEMON_ARGS=(--host "$HOST" --port "$PORT" --dbus-suffix audit --no-install-gnome-extension)
    if [[ "$SCENARIO" == "minimal" ]]; then
        DAEMON_ARGS+=(--no-indicator)
    fi
    bwrap "${BWRAP_ARGS[@]}" \
        strace -ff -ttt -s 512 -v -o "$OUT/strace/daemon" -e trace="$AUDIT_TRACE_EVENTS" \
        timeout -s TERM -k 5 "$TIMEOUT" "$BIN" "${DAEMON_ARGS[@]}" \
        >"$OUT/daemon/stdout.log" 2>"$OUT/daemon/stderr.log" &
    RUN_PID=$!
else
    bwrap "${BWRAP_ARGS[@]}" \
        strace -ff -ttt -s 512 -v -o "$OUT/strace/daemon" -e trace="$AUDIT_TRACE_EVENTS" \
        timeout -s TERM -k 2 "$TIMEOUT" bash -c "$COMMAND" \
        >"$OUT/daemon/stdout.log" 2>"$OUT/daemon/stderr.log" &
    RUN_PID=$!
fi

for _ in $(seq 1 80); do
    compgen -G "$OUT/strace/daemon.*" >/dev/null && break
    kill -0 "$RUN_PID" 2>/dev/null || break
    sleep 0.1
done

DAEMON_PID=""
if compgen -G "$OUT/strace/daemon.*" >/dev/null; then
    for f in "$OUT"/strace/daemon.*; do
        if [[ -n "$BIN" ]] && grep -q "execve(\"$BIN\"" "$f" 2>/dev/null; then
            DAEMON_PID="${f##*.}"
            break
        fi
    done
    if [[ -z "$DAEMON_PID" ]]; then
        DAEMON_PID="$(for f in "$OUT"/strace/daemon.*; do echo "${f##*.}"; done | sort -n | head -n 1)"
    fi
fi
DAEMON_HOST_PID=""
if [[ -n "$BIN" ]]; then
    DAEMON_HOST_PID="$(pgrep -f "$BIN" 2>/dev/null | head -n 1 || true)"
fi

snapshot_loop &
SNAP_PID=$!

if [[ "$MODE" == "daemon" ]]; then
    for _ in $(seq 1 120); do
        if gdbus call --session \
            --dest org.freedesktop.DBus \
            --object-path /org/freedesktop/DBus \
            --method org.freedesktop.DBus.NameHasOwner \
            com.github.kanata.Switcher.instances.audit 2>/dev/null | grep -q true; then
            break
        fi
        kill -0 "$RUN_PID" 2>/dev/null || break
        sleep 0.25
    done
    if gdbus call --session \
        --dest com.github.kanata.Switcher.instances.audit \
        --object-path /com/github/kanata/Switcher \
        --method com.github.kanata.Switcher.GetStatus \
        >>"$OUT/logs/gdbus.log" 2>&1; then
        :
    fi
fi

wait "$RUN_PID" 2>/dev/null
EXIT_CODE=$?
kill "$SNAP_PID" 2>/dev/null || true
wait "$SNAP_PID" 2>/dev/null || true

if [[ -n "$MOCK_PID" ]]; then
    kill -TERM "$MOCK_PID" 2>/dev/null || true
    wait "$MOCK_PID" 2>/dev/null || true
fi
stop_bus

MODE="$MODE" BIN="$BIN" PORT="$PORT" HOST="$HOST" SCENARIO="$SCENARIO" \
DAEMON_PID="$DAEMON_PID" DAEMON_HOST_PID="$DAEMON_HOST_PID" \
RUN_PID="$RUN_PID" MOCK_PID="$MOCK_PID" EXIT_CODE="$EXIT_CODE" \
SESSION_BUS="$DBUS_SESSION_BUS_ADDRESS" \
python3 - "$OUT/daemon/runtime.json" <<'PY'
import json, os, sys
keys = ["MODE", "BIN", "PORT", "HOST", "SCENARIO", "DAEMON_PID", "DAEMON_HOST_PID",
        "RUN_PID", "MOCK_PID", "EXIT_CODE", "SESSION_BUS"]
data = {key.lower(): os.environ.get(key, "") for key in keys}
data["exit_code"] = int(data["exit_code"] or 0)
with open(sys.argv[1], "w", encoding="utf-8") as handle:
    json.dump(data, handle, indent=2, sort_keys=True)
    handle.write("\n")
PY
INNER_EOF
chmod +x "$OUT/inner.sh"

start_capture "$OUT/pcap/daemon.pcap" "$OUT/pcap/daemon.tcpdump.log"

echo "[run] scenario=$SCENARIO mode=$MODE timeout=${TIMEOUT}s out=$OUT"
if [[ "$SCENARIO" == "host-desktop" ]]; then
    "${SUDO[@]}" "$SCRIPT_DIR/netns_admin.sh" run-as "$D_NS" "$(id -u)" "$(id -g)" -- \
        env HOME="$OUT/home" \
            XDG_CONFIG_HOME="$OUT/home/.config" \
            XDG_CACHE_HOME="$OUT/home/.cache" \
            XDG_DATA_HOME="$OUT/home/.local/share" \
            TMPDIR="$OUT/tmp" \
            XDG_RUNTIME_DIR="${XDG_RUNTIME_DIR:-/run/user/$(id -u)}" \
            DBUS_SESSION_BUS_ADDRESS="${DBUS_SESSION_BUS_ADDRESS:-}" \
            PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin" \
            AUDIT_TRACE_EVENTS="$TRACE_EVENTS" \
            "$OUT/inner.sh" "$OUT" "$BIN" "$MODE" "$PORT" "$HOST" "$TIMEOUT" "$SCENARIO" "$SKILL_DIR" "$COMMAND" "$D_MAC" "$C_MAC"
    RUN_STATUS=$?
else
    "${SUDO[@]}" "$SCRIPT_DIR/netns_admin.sh" run-as "$D_NS" "$(id -u)" "$(id -g)" -- \
        env HOME="$OUT/home" \
            XDG_CONFIG_HOME="$OUT/home/.config" \
            XDG_CACHE_HOME="$OUT/home/.cache" \
            XDG_DATA_HOME="$OUT/home/.local/share" \
            TMPDIR="$OUT/tmp" \
            XDG_RUNTIME_DIR="$OUT/runtime" \
            PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin" \
            AUDIT_TRACE_EVENTS="$TRACE_EVENTS" \
            "$OUT/inner.sh" "$OUT" "$BIN" "$MODE" "$PORT" "$HOST" "$TIMEOUT" "$SCENARIO" "$SKILL_DIR" "$COMMAND" "$D_MAC" "$C_MAC"
    RUN_STATUS=$?
fi

stop_capture "$OUT/pcap/daemon.pcap"

if [[ -f "$OUT/daemon/runtime.json" ]]; then
    python3 - "$OUT/meta.json" "$OUT/daemon/runtime.json" <<'PY'
import json, sys
meta_path, runtime_path = sys.argv[1], sys.argv[2]
try:
    meta = json.load(open(meta_path, encoding="utf-8"))
    runtime = json.load(open(runtime_path, encoding="utf-8"))
except (OSError, json.JSONDecodeError):
    raise SystemExit(0)
meta.update(runtime)
with open(meta_path, "w", encoding="utf-8") as handle:
    json.dump(meta, handle, indent=2, sort_keys=True)
    handle.write("\n")
PY
fi

if [[ ! -d "$OUT/strace" ]] || ! compgen -G "$OUT/strace/daemon.*" >/dev/null; then
    echo "error: no strace logs were produced (bwrap/strace failed; status=$RUN_STATUS)" >&2
    echo "       see $OUT/daemon/stderr.log" >&2
    tail -n 40 "$OUT/daemon/stderr.log" >&2 || true
    exit 2
fi

echo "[analyze] parsing strace, pcap, sinkhole, D-Bus, build, and mock logs"
python3 "$SKILL_DIR/scripts/analyze_dynamic_logs.py" "$OUT" \
    --profile "$MODE" \
    --expected-host "$HOST" --expected-port "$PORT" \
    --unix-glob "$OUT/dbus/session.sock" \
    --unix-glob "$OUT/runtime/*" \
    --json "$OUT/report.json" --markdown "$OUT/report.md"
ANALYZE_STATUS=$?

if [[ "$RUN_GNOME" -eq 1 ]]; then
    echo "[gnome] running the nested GNOME Shell extension audit"
    GNOME_STATUS=0
    GNOME_ARGS=(--repo "$REPO" --out "$OUT/gnome" --timeout "$TIMEOUT")
    if [[ "$ALLOW_UNMONITORED_SYSTEM_BUS" -eq 1 ]]; then
        GNOME_ARGS+=(--allow-unmonitored-system-bus)
    fi
    "$SCRIPT_DIR/run_gnome_extension_audit.sh" "${GNOME_ARGS[@]}" || GNOME_STATUS=$?
    if [[ "$GNOME_STATUS" -eq 1 ]]; then
        echo "[gnome] findings reported in $OUT/gnome/report.md"
        [[ "$ANALYZE_STATUS" -eq 0 ]] && ANALYZE_STATUS=1
    elif [[ "$GNOME_STATUS" -ne 0 ]]; then
        echo "error: GNOME extension audit failed to run; see $OUT/gnome" >&2
        ANALYZE_STATUS=2
    fi
fi

echo "[done] evidence: $OUT"
echo "[done] report: $OUT/report.md  json: $OUT/report.json"
if [[ "$RUN_GNOME" -eq 1 ]]; then
    echo "[done] GNOME report: $OUT/gnome/report.md"
fi
echo "[note] evidence is kept for review; remove $OUT manually when finished"
exit "$ANALYZE_STATUS"
