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
TIMEOUT=3600
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
FAULT_INJECT=0
SCENARIO_TIMEOUT=8
BPFTRACE_AVAILABLE=0
CAPTURE_METHOD="tcpdump-only"

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
        --fault-inject) FAULT_INJECT=1; shift ;;
        --scenario-timeout) SCENARIO_TIMEOUT="$2"; shift 2 ;;
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
if [[ "$FAULT_INJECT" -eq 1 ]]; then
    TIMEOUT=30
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

if command -v bpftrace >/dev/null 2>&1; then
    BPFTRACE_AVAILABLE=1
    CAPTURE_METHOD="ebpf+tcpdump"
fi

if [[ "$CHECK_ONLY" -eq 1 ]]; then
    echo "[check] root access: ok"
    echo "[check] tcpdump: $TCPDUMP_VERSION"
    echo "[check] ip: $IP_VERSION"
    echo "[check] bwrap: $(bwrap --version 2>&1 | head -n 1)"
    echo "[check] strace: $(strace --version 2>&1 | head -n 1)"
    echo "[check] python: $(python3 --version 2>&1)"
    echo "[check] bpftrace: $([[ $BPFTRACE_AVAILABLE -eq 1 ]] && echo available || echo unavailable)"
    echo "[check] capture_method: $CAPTURE_METHOD"
    if [[ -S /run/dbus/system_bus_socket ]]; then
        echo "[check] system bus: present"
    else
        echo "[check] system bus: absent"
    fi
    echo "[check] preflight passed"
    exit 0
fi

run_scenario() {
    local out_dir="$1" scenario_label="$2" host="$3" port="$4" timeout="$5"

    local SUFFIX D_NS C_NS D_IF C_IF
    SUFFIX="$$-$RANDOM-$RANDOM"
    D_NS="ks-d-${scenario_label}-${SUFFIX}"
    C_NS="ks-c-${scenario_label}-${SUFFIX}"
    D_IF="kd$(printf '%04x' $((RANDOM % 65536)))"
    C_IF="kc$(printf '%04x' $((RANDOM % 65536)))"
    while [[ "$D_IF" == "$C_IF" ]]; do
        C_IF="kc$(printf '%04x' $((RANDOM % 65536)))"
    done

    local D_MAC="" C_MAC="" SINK_PIDFILE="" SYS_MON_PIDFILE="" CAP_PIDFILE="" LOOP_CAP_PIDFILE="" BPF_PIDFILE=""
    local SYS_MON_STATE="unknown"
    local BPFTRACE_RAN=0
    local scenario_status=0

    cleanup_scenario() {
        local st=$?
        trap - EXIT INT TERM
        [[ -n "${SYS_MON_PIDFILE}" ]] && "${SUDO[@]}" "$SCRIPT_DIR/netns_admin.sh" stop-pid "$SYS_MON_PIDFILE" >/dev/null 2>&1 || true
        [[ -n "${SINK_PIDFILE}" ]] && "${SUDO[@]}" "$SCRIPT_DIR/netns_admin.sh" stop-pid "$SINK_PIDFILE" >/dev/null 2>&1 || true
        [[ -n "${CAP_PIDFILE}" ]] && "${SUDO[@]}" "$SCRIPT_DIR/netns_admin.sh" capture-stop "$CAP_PIDFILE" >/dev/null 2>&1 || true
        [[ -n "${LOOP_CAP_PIDFILE}" ]] && "${SUDO[@]}" "$SCRIPT_DIR/netns_admin.sh" capture-stop "$LOOP_CAP_PIDFILE" >/dev/null 2>&1 || true
        [[ -n "${BPF_PIDFILE}" ]] && { kill -TERM "$(cat "$BPF_PIDFILE" 2>/dev/null)" 2>/dev/null || true; rm -f "$BPF_PIDFILE"; }
        if [[ "$KEEP_NETNS" -eq 0 ]]; then
            "${SUDO[@]}" "$SCRIPT_DIR/netns_admin.sh" teardown "$D_NS" "$C_NS" >/dev/null 2>&1 || true
        else
            echo "[keep] network namespaces retained: $D_NS $C_NS" >&2
        fi
        return "$st"
    }
    trap cleanup_scenario EXIT INT TERM

    mkdir -p "$out_dir/net" "$out_dir/pcap" "$out_dir/strace" "$out_dir/dbus" "$out_dir/mock" "$out_dir/build" "$out_dir/snapshots"

    cat > "$out_dir/net/resolv.conf" <<'EOF'
nameserver 10.213.0.1
options timeout:1 attempts:1
EOF
    cat > "$out_dir/net/hosts" <<'EOF'
127.0.0.1 localhost
::1 localhost
10.213.0.2 audit-daemon
EOF

    cat > "$out_dir/dbus/session.conf" <<EOF
<!DOCTYPE busconfig PUBLIC "-//freedesktop//DTD D-Bus Bus Configuration 1.0//EN"
 "http://www.freedesktop.org/standards/dbus/1.0/busconfig.dtd">
<busconfig>
  <type>session</type>
  <listen>unix:path=$out_dir/dbus/session.sock</listen>
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
  <servicedir>$out_dir/home/.local/share/dbus-1/services</servicedir>
</busconfig>
EOF

    echo "[setup] scenario=$scenario_label daemon netns=$D_NS if=$D_IF; capture netns=$C_NS if=$C_IF"
    "${SUDO[@]}" "$SCRIPT_DIR/netns_admin.sh" setup \
        "$D_NS" "$C_NS" "$D_IF" "$C_IF" \
        "10.213.0.2/24" "10.213.0.1/24" \
        "fd42:6b73:6175:6469::2/64" "fd42:6b73:6175:6469::1/64" \
        "$out_dir" || { echo "error: network namespace setup failed" >&2; exit 2; }

    D_MAC="$(cat "$out_dir/net/daemon.mac")"
    C_MAC="$(cat "$out_dir/net/capture.mac")"
    echo "[setup] daemon mac=$D_MAC capture mac=$C_MAC"

    # Optional network blackhole: drop the default route so the daemon cannot
    # reach any non-loopback endpoint through the veth.
    if [[ "$scenario_label" == "network-blackhole" ]]; then
        "${SUDO[@]}" ip netns exec "$D_NS" route del default 2>/dev/null || true
        "${SUDO[@]}" ip -6 netns exec "$D_NS" route del default 2>/dev/null || true
        echo "[setup] default route removed (network-blackhole)"
    fi

    SINK_PIDFILE="$out_dir/net/sinkhole.pid"
    "${SUDO[@]}" "$SCRIPT_DIR/netns_admin.sh" sinkhole-start \
        "$C_NS" "$(id -u)" "$(id -g)" \
        "$SCRIPT_DIR/capture_sinkhole.py" "$SINK_PIDFILE" "$out_dir/net/sinkhole.stderr.log" -- \
        --dns-address 10.213.0.1 \
        --dns-address6 fd42:6b73:6175:6469::1 \
        --tcp-address 10.213.0.1 \
        --tcp-address6 fd42:6b73:6175:6469::1 \
        --answer-ip 10.213.0.1 \
        --dns-log "$out_dir/net/dns.jsonl" \
        --tcp-log "$out_dir/net/tcp.jsonl" \
        --ready-file "$out_dir/net/sinkhole.ready"
    for _ in $(seq 1 60); do
        [[ -s "$out_dir/net/sinkhole.ready" ]] && break
        sleep 0.1
    done
    if [[ ! -s "$out_dir/net/sinkhole.ready" ]]; then
        echo "error: DNS/TCP sinkhole did not become ready" >&2
        cat "$out_dir/net/sinkhole.stderr.log" >&2 || true
        exit 2
    fi
    echo "[setup] sinkhole ready"

    if [[ -S /run/dbus/system_bus_socket ]]; then
        SYS_MON_PIDFILE="$out_dir/dbus/system.monitor.pid"
        if "${SUDO[@]}" "$SCRIPT_DIR/netns_admin.sh" system-monitor-start \
            "$out_dir/dbus/system.monitor.log" "$SYS_MON_PIDFILE"; then
            SYS_MON_STATE="enabled"
            if grep -qE "Falling back to eavesdropping|Failed to become monitor" "$out_dir/dbus/system.monitor.log" 2>/dev/null; then
                SYS_MON_STATE="eavesdrop-fallback"
                echo "[warn] system bus monitor could not become a full monitor; using eavesdropping" >&2
            fi
        elif [[ "$ALLOW_UNMONITORED_SYSTEM_BUS" -eq 1 ]]; then
            SYS_MON_STATE="unavailable-allowed"
            echo "[warn] system bus monitor unavailable; continuing because --allow-unmonitored-system-bus was passed" >&2
        else
            echo "error: system bus monitor is mandatory." >&2
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

    # --- binary / build (build happens once, in the baseline scenario) ---
    local BUILD_TRACED=0
    if [[ -n "$BINARY" ]]; then
        BIN="$(cd "$(dirname "$BINARY")" && pwd)/$(basename "$BINARY")"
        [[ -f "$BIN" ]] || { echo "error: --binary is not a file: $BINARY" >&2; exit 2; }
        cp -f "$BINARY" "$out_dir/bin/kanata-switcher"
        BIN="$out_dir/bin/kanata-switcher"
        chmod +x "$BIN"
    elif [[ "$MODE" == "daemon" && "${BUILD_DONE:-0}" -eq 0 && "$SKIP_BUILD" -eq 0 ]]; then
        [[ -f "$REPO/Cargo.toml" ]] || { echo "error: no Cargo.toml under --repo $REPO" >&2; exit 2; }
        if [[ -z "$COMMIT" ]]; then
            COMMIT="$(git -C "$REPO" rev-parse HEAD)"
        fi
        echo "[build] archiving $COMMIT from $REPO"
        rm -rf "$out_dir/src"
        mkdir -p "$out_dir/src"
        git -C "$REPO" archive --format=tar "$COMMIT" | tar -x -C "$out_dir/src" || {
            echo "error: git archive failed" >&2; exit 2;
        }
        echo "[build] cargo fetch --locked under strace (host network)"
        (
            cd "$out_dir/src" || exit 2
            CARGO_HOME="${CARGO_HOME:-$HOME/.cargo}" \
                strace -ff -ttt -s 256 -v -o "$out_dir/build/fetch.strace" -e trace=%network \
                cargo fetch --locked
        ) >"$out_dir/build/fetch.log" 2>&1 || {
            echo "error: cargo fetch failed; see $out_dir/build/fetch.log" >&2
            tail -n 40 "$out_dir/build/fetch.log" >&2 || true
            exit 2
        }
        echo "[build] cargo build --release --locked --offline inside $D_NS under capture"
        start_capture "$out_dir/pcap/build.pcap" "$out_dir/pcap/build.tcpdump.log"
        (
            "${SUDO[@]}" "$SCRIPT_DIR/netns_admin.sh" run-as "$D_NS" "$(id -u)" "$(id -g)" -- \
                env HOME="$out_dir/home" \
                    CARGO_HOME="${CARGO_HOME:-$HOME/.cargo}" \
                    CARGO_TARGET_DIR="$out_dir/target" \
                    PATH="/home/dj/.cargo/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin" \
                    strace -ff -ttt -s 256 -v -o "$out_dir/build/build.strace" -e trace=%network \
                    cargo build --release --locked --offline --manifest-path "$out_dir/src/Cargo.toml"
        ) >"$out_dir/build/build.log" 2>&1 || {
            echo "error: release build failed; see $out_dir/build/build.log" >&2
            tail -n 60 "$out_dir/build/build.log" >&2 || true
            stop_capture "$out_dir/pcap/build.pcap"
            exit 2
        }
        stop_capture "$out_dir/pcap/build.pcap"
        BUILD_TRACED=1
        BUILD_DONE=1
        BIN="$out_dir/target/release/kanata-switcher"
        [[ -f "$BIN" ]] || { echo "error: built binary not found: $BIN" >&2; exit 2; }
    elif [[ "$MODE" == "daemon" ]]; then
        BIN="$out_dir/target/release/kanata-switcher"
        if [[ ! -f "$BIN" && -n "${BASE_BIN:-}" ]]; then
            BIN="$BASE_BIN"
        fi
        [[ -f "$BIN" ]] || { echo "error: built binary not found: $BIN" >&2; exit 2; }
    else
        BIN=""
    fi

    local BIN_SHA="" LOCK_SHA=""
    if [[ -n "$BIN" ]]; then
        BIN_SHA="$(sha256sum "$BIN" | awk '{print $1}')"
    fi
    if [[ -f "$out_dir/src/Cargo.lock" ]]; then
        LOCK_SHA="$(sha256sum "$out_dir/src/Cargo.lock" | awk '{print $1}')"
    elif [[ -f "$REPO/Cargo.lock" ]]; then
        LOCK_SHA="$(sha256sum "$REPO/Cargo.lock" | awk '{print $1}')"
    fi

    local TAG DIRTY CARGO_VERSION RUSTC_VERSION TIMESTAMP SESSION_BUS_KIND
    TAG="$(git -C "$REPO" describe --tags --always 2>/dev/null || true)"
    DIRTY="$(git -C "$REPO" status --porcelain 2>/dev/null | head -n 20 | tr '\n' ';')"
    CARGO_VERSION="$(cargo --version 2>/dev/null || true)"
    RUSTC_VERSION="$(rustc --version 2>/dev/null || true)"
    TIMESTAMP="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    SESSION_BUS_KIND="private"
    if [[ "$SCENARIO" == "host-desktop" ]]; then
        SESSION_BUS_KIND="host"
    fi

    local local_pcap_files=("daemon.pcap")
    [[ "$BUILD_TRACED" -eq 1 ]] && local_pcap_files+=("build.pcap")

    META_MODE="$MODE" META_BIN="$BIN" META_REPO="$REPO" META_OUT="$out_dir" \
    META_COMMIT="$COMMIT" META_TAG="$TAG" META_DIRTY="$DIRTY" \
    META_BIN_SHA="$BIN_SHA" META_LOCK_SHA="$LOCK_SHA" \
    META_HOST="$host" META_PORT="$port" META_SCENARIO="$scenario_label" \
    META_COMMAND="$COMMAND" META_TIMESTAMP="$TIMESTAMP" \
    META_CARGO="$CARGO_VERSION" META_RUSTC="$RUSTC_VERSION" \
    META_D_MAC="$D_MAC" META_C_MAC="$C_MAC" \
    META_D_NS="$D_NS" META_C_NS="$C_NS" META_D_IF="$D_IF" META_C_IF="$C_IF" \
    META_TCPDUMP="$TCPDUMP_VERSION" META_IP="$IP_VERSION" \
    META_SYS_MON="$SYS_MON_STATE" META_BUILD_TRACED="$BUILD_TRACED" \
    META_SESSION_BUS="$SESSION_BUS_KIND" META_TRACE_EVENTS="$TRACE_EVENTS" \
    META_BPFTRACE_AVAILABLE="$BPFTRACE_AVAILABLE" META_CAPTURE_METHOD="$CAPTURE_METHOD" \
    python3 - "$out_dir/meta.json" <<'PY'
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
    "bpftrace_available": "META_BPFTRACE_AVAILABLE",
    "capture_method": "META_CAPTURE_METHOD",
}
data = {key: os.environ.get(env, "") for key, env in keys.items()}
data["expected_port"] = int(data["expected_port"] or 0)
data["build_traced"] = data["build_traced"] == "1"
data["bpftrace_available"] = data["bpftrace_available"] == "1"
data["network_namespace"] = "veth pair; no NAT; sinkhole capture"
data["privileged_capture"] = True
data["daemon_ip4"] = "10.213.0.2"
data["capture_ip4"] = "10.213.0.1"
data["daemon_ip6"] = "fd42:6b73:6175:6469::2"
data["capture_ip6"] = "fd42:6b73:6175:6469::1"
data["pcap_files"] = ["daemon.pcap"] + (["build.pcap"] if data["build_traced"] else [])
if data["bpftrace_available"]:
    data["pcap_files"].append("daemon-loopback.pcap")
with open(sys.argv[1], "w", encoding="utf-8") as handle:
    json.dump(data, handle, indent=2, sort_keys=True)
    handle.write("\n")
PY

    mkdir -p "$out_dir/home/.config/kanata"
    cat > "$out_dir/home/.config/kanata/kanata-switcher.json" <<'JSON'
[
  {"default": "default"},
  {"class": "firefox", "layer": "browser"},
  {"class": "alacritty", "title": "vim", "layer": "vim"}
]
JSON

    cat > "$out_dir/inner.sh" <<'INNER_EOF'
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
    local i=0 elapsed=0
    while [[ $elapsed -lt "$TIMEOUT" ]]; do
        i=$((i + 1))
        ss -tanp > "$OUT/snapshots/ss-tcp-$i.txt" 2>/dev/null || true
        ss -uanp > "$OUT/snapshots/ss-udp-$i.txt" 2>/dev/null || true
        ss -lxnp > "$OUT/snapshots/ss-unix-$i.txt" 2>/dev/null || true
        for table in tcp tcp6 udp udp6 packet netlink unix raw raw6; do
            if [[ -r "/proc/net/$table" ]]; then
                cp "/proc/net/$table" "$OUT/snapshots/procnet-$table-$i.txt" 2>/dev/null || true
            fi
        done
        sleep 1
        elapsed=$((elapsed + 1))
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

    # kanata-kill-restart: kill the mock kanata once the daemon has connected,
    # wait, then restart it on the same port to observe reconnect behaviour.
    if [[ "$SCENARIO" == "kanata-kill-restart" ]]; then
        for _ in $(seq 1 80); do
            [[ -s "$OUT/mock/port" ]] && break
            kill -0 "$RUN_PID" 2>/dev/null || break
            sleep 0.25
        done
        sleep 1
        if [[ -n "$MOCK_PID" ]] && kill -0 "$MOCK_PID" 2>/dev/null; then
            kill -TERM "$MOCK_PID" 2>/dev/null || true
            wait "$MOCK_PID" 2>/dev/null || true
            echo "[fault-inject] mock kanata killed" >&2
            sleep 3
            python3 "$SKILL_DIR/scripts/mock_kanata.py" \
                --host 127.0.0.1 --port "$PORT" \
                --port-file "$OUT/mock/port" --log "$OUT/mock/kanata.log" \
                >"$OUT/mock/stdout2.log" 2>"$OUT/mock/stderr2.log" &
            MOCK_PID=$!
            echo "[fault-inject] mock kanata restarted (pid=$MOCK_PID)" >&2
        fi
    fi
fi

# Run the daemon for the full timeout duration, restarting it if it exits
# early. This keeps tcpdump, mock kanata, and the session bus alive for the
# entire window so any network behavior is captured for the full duration.
ELAPSED=0
while [[ $ELAPSED -lt "$TIMEOUT" ]]; do
    if ! kill -0 "$RUN_PID" 2>/dev/null; then
        echo "[run] daemon exited after ${ELAPSED}s, restarting" >&2
        bwrap "${BWRAP_ARGS[@]}" \
            strace -ff -ttt -s 512 -v -o "$OUT/strace/daemon.restart.$ELAPSED" -e trace="$AUDIT_TRACE_EVENTS" \
            "$BIN" "${DAEMON_ARGS[@]}" \
            >>"$OUT/daemon/stdout.log" 2>>"$OUT/daemon/stderr.log" &
        RUN_PID=$!
        for _ in $(seq 1 40); do
            compgen -G "$OUT/strace/daemon.restart.*" >/dev/null && break
            kill -0 "$RUN_PID" 2>/dev/null || break
            sleep 0.1
        done
    fi
    sleep 1
    ELAPSED=$((ELAPSED + 1))
done
# Reap any remaining daemon process
kill -TERM "$RUN_PID" 2>/dev/null || true
wait "$RUN_PID" 2>/dev/null || true
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
python3 - "$out_dir/daemon/runtime.json" <<'PY'
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
chmod +x "$out_dir/inner.sh"

    # --- capture: bpftrace + loopback tcpdump + daemon pcap ---
    if [[ "$BPFTRACE_AVAILABLE" -eq 1 ]]; then
        BPF_PIDFILE="$out_dir/net/ebpf-trace.pid"
        "${SUDO[@]}" "$SCRIPT_DIR/netns_admin.sh" run-as "$D_NS" "$(id -u)" "$(id -g)" -- \
            bpftrace -e '
kprobe:tcp_connect   { printf("%d %s %d %d %d tcp_connect %d\n", pid, comm, ((struct sock *)arg0)->sk_family, ((struct sock *)arg0)->sk_rcv_saddr, ((struct sock *)arg0)->sk_rcv_port, ret); }
kprobe:tcp_v4_connect{ printf("%d %s %d %d %d tcp_v4_connect %d\n", pid, comm, ((struct sock *)arg0)->sk_family, ((struct sock *)arg0)->sk_rcv_saddr, ((struct sock *)arg0)->sk_rcv_port, ret); }
kprobe:tcp_v6_connect{ printf("%d %s %d %d %d tcp_v6_connect %d\n", pid, comm, ((struct sock *)arg0)->sk_family, ((struct sock *)arg0)->sk_rcv_saddr, ((struct sock *)arg0)->sk_rcv_port, ret); }
kprobe:udp_sendmsg   { printf("%d %s udp_sendmsg\n", pid, comm, ret); }
kprobe:udpv6_sendmsg { printf("%d %s udpv6_sendmsg\n", pid, comm, ret); }
kprobe:raw_sendto    { printf("%d %s raw_sendto\n", pid, comm, ret); }
' >"$out_dir/net/ebpf-trace.log" 2>"$out_dir/net/ebpf-trace.stderr" &
        echo $! > "$BPF_PIDFILE"
        sleep 0.5
        if ! kill -0 "$(cat "$BPF_PIDFILE" 2>/dev/null)" 2>/dev/null; then
            echo "[warn] bpftrace failed to attach; continuing with tcpdump-only capture" >&2
            cat "$out_dir/net/ebpf-trace.stderr" 2>/dev/null >&2 || true
            rm -f "$BPF_PIDFILE" "$out_dir/net/ebpf-trace.log"
            BPFTRACE_RAN=0
            CAPTURE_METHOD="tcpdump-only"
        else
            BPFTRACE_RAN=1
            echo "[capture] bpftrace tracing network syscalls inside $D_NS"
        fi
    fi

    # tcpdump on loopback inside the daemon namespace (captures 127.0.0.1 traffic
    # that the veth capture never sees).
    LOOP_CAP_PIDFILE="$out_dir/pcap/daemon-loopback.pcap.pid"
    : > "$out_dir/pcap/daemon-loopback.pcap"
    : > "$out_dir/pcap/daemon-loopback.tcpdump.log"
    "${SUDO[@]}" "$SCRIPT_DIR/netns_admin.sh" run-as "$D_NS" "$(id -u)" "$(id -g)" -- \
        tcpdump -i lo -nn -s 0 -U -w "$out_dir/pcap/daemon-loopback.pcap" >"$out_dir/pcap/daemon-loopback.tcpdump.log" 2>&1 &
    echo $! > "$LOOP_CAP_PIDFILE"
    sleep 0.3
    if ! kill -0 "$(cat "$LOOP_CAP_PIDFILE" 2>/dev/null)" 2>/dev/null; then
        echo "[warn] loopback tcpdump failed to start; see $out_dir/pcap/daemon-loopback.tcpdump.log" >&2
        rm -f "$LOOP_CAP_PIDFILE"
    else
        echo "[capture] tcpdump on lo inside $D_NS -> $out_dir/pcap/daemon-loopback.pcap"
    fi

    start_capture "$out_dir/pcap/daemon.pcap" "$out_dir/pcap/daemon.tcpdump.log"

    echo "[run] scenario=$scenario_label mode=$MODE timeout=${timeout}s out=$out_dir"
    "${SUDO[@]}" "$SCRIPT_DIR/netns_admin.sh" run-as "$D_NS" "$(id -u)" "$(id -g)" -- \
        env HOME="$out_dir/home" \
            XDG_CONFIG_HOME="$out_dir/home/.config" \
            XDG_CACHE_HOME="$out_dir/home/.cache" \
            XDG_DATA_HOME="$out_dir/home/.local/share" \
            TMPDIR="$out_dir/tmp" \
            XDG_RUNTIME_DIR="$out_dir/runtime" \
            PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin" \
            AUDIT_TRACE_EVENTS="$TRACE_EVENTS" \
            "$out_dir/inner.sh" "$out_dir" "$BIN" "$MODE" "$port" "$host" "$timeout" "$scenario_label" "$SKILL_DIR" "$COMMAND" "$D_MAC" "$C_MAC"
    RUN_STATUS=$?

    stop_capture "$out_dir/pcap/daemon.pcap"
    [[ -n "${LOOP_CAP_PIDFILE}" ]] && "${SUDO[@]}" "$SCRIPT_DIR/netns_admin.sh" capture-stop "$LOOP_CAP_PIDFILE" >/dev/null 2>&1 || true
    [[ -n "${BPF_PIDFILE}" ]] && { kill -TERM "$(cat "$BPF_PIDFILE" 2>/dev/null)" 2>/dev/null || true; rm -f "$BPF_PIDFILE"; }

    if [[ -f "$out_dir/daemon/runtime.json" ]]; then
        python3 - "$out_dir/meta.json" "$out_dir/daemon/runtime.json" <<'PY'
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

    if [[ ! -d "$out_dir/strace" ]] || ! compgen -G "$out_dir/strace/daemon.*" >/dev/null; then
        echo "error: no strace logs were produced (bwrap/strace failed; status=$RUN_STATUS)" >&2
        echo "       see $out_dir/daemon/stderr.log" >&2
        tail -n 40 "$out_dir/daemon/stderr.log" >&2 || true
        exit 2
    fi

    echo "[analyze] scenario=$scenario_label parsing strace, pcap, sinkhole, D-Bus, build, and mock logs"
    python3 "$SKILL_DIR/scripts/analyze_dynamic_logs.py" "$out_dir" \
        --profile "$MODE" \
        --expected-host "$host" --expected-port "$port" \
        --unix-glob "$out_dir/dbus/session.sock" \
        --unix-glob "$out_dir/runtime/*" \
        --json "$out_dir/report.json" --markdown "$out_dir/report.md"
    scenario_status=$?

    trap - EXIT INT TERM
    cleanup_scenario >/dev/null 2>&1 || true
    return "$scenario_status"
}

# --- build first (daemon mode), then run scenarios ---
if [[ "$MODE" == "daemon" && -z "$BINARY" && "$SKIP_BUILD" -eq 0 ]]; then
    BUILD_DONE=0
else
    BUILD_DONE=1
fi

BASE_BIN=""
if [[ -n "$BINARY" ]]; then
    BASE_BIN="$OUT/bin/kanata-switcher"
elif [[ "$MODE" == "daemon" ]]; then
    BASE_BIN="$OUT/target/release/kanata-switcher"
fi

COMBINED_STATUS=0
run_scenario "$OUT" "${SCENARIO}" "$HOST" "$PORT" "$TIMEOUT" || COMBINED_STATUS=$?

if [[ "$FAULT_INJECT" -eq 1 ]]; then
    FI_BASE="$OUT/fault-inject"
    mkdir -p "$FI_BASE"
    for fi_scenario in kanata-kill-restart network-blackhole remote-host; do
        FI_OUT="$FI_BASE/$fi_scenario"
        case "$fi_scenario" in
            kanata-kill-restart) FI_HOST=127.0.0.1 FI_PORT="$PORT" ;;
            network-blackhole)   FI_HOST=127.0.0.1 FI_PORT="$PORT" ;;
            remote-host)         FI_HOST=192.0.2.1 FI_PORT=9 ;;
        esac
        echo "[fault-inject] scenario=$fi_scenario out=$FI_OUT"
        run_scenario "$FI_OUT" "$fi_scenario" "$FI_HOST" "$FI_PORT" "$SCENARIO_TIMEOUT" || COMBINED_STATUS=$?
    done
    FI_REPORTS=()
    for fi_scenario in kanata-kill-restart network-blackhole remote-host; do
        FI_REPORTS+=("$FI_BASE/$fi_scenario/report.json")
    done
    echo "[fault-inject] merging scenario reports"
    python3 "$SKILL_DIR/scripts/analyze_dynamic_logs.py" --merge "${FI_REPORTS[@]}" \
        --json "$FI_BASE/combined.report.json" --markdown "$FI_BASE/combined.report.md"
    MERGE_STATUS=$?
    [[ "$MERGE_STATUS" -gt "$COMBINED_STATUS" ]] && COMBINED_STATUS="$MERGE_STATUS"
fi

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
        [[ "$COMBINED_STATUS" -eq 0 ]] && COMBINED_STATUS=1
    elif [[ "$GNOME_STATUS" -ne 0 ]]; then
        echo "error: GNOME extension audit failed to run; see $OUT/gnome" >&2
        COMBINED_STATUS=2
    fi
fi

echo "[done] evidence: $OUT"
echo "[done] report: $OUT/report.md  json: $OUT/report.json"
if [[ "$FAULT_INJECT" -eq 1 ]]; then
    echo "[done] fault-inject evidence: $OUT/fault-inject/*"
fi
if [[ "$RUN_GNOME" -eq 1 ]]; then
    echo "[done] GNOME report: $OUT/gnome/report.md"
fi
echo "[note] evidence is kept for review; remove $OUT manually when finished"
exit "$COMBINED_STATUS"
