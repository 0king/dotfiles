#!/usr/bin/env bash
# Rootless dynamic network audit for kanata-switcher.
#
# Builds the release binary from a clean `git archive` of the audited commit
# (or accepts --binary), then runs it inside `bwrap --unshare-net` with only a
# loopback interface. strace records every network/process syscall; `ss` and
# /proc/net snapshots corroborate the trace. A mock kanata server on
# 127.0.0.1:<port> satisfies the daemon's only documented IP connection.
#
# Privileged packet capture (tcpdump/bpftrace) is deliberately NOT required.
# For that layer, run the optional commands documented in
# references/dynamic-analysis.md as root, with the same output directory.
#
# Usage:
#   run_dynamic_network_audit.sh [--repo PATH] [--out DIR] [--host 127.0.0.1]
#       [--port 10000] [--timeout 15] [--commit REV]
#       [--scenario baseline|minimal|host-desktop]
#       [--binary PATH | --command 'CMD'] [--skip-build]
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

usage() {
    sed -n '2,21p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
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
if [[ -z "$OUT" ]]; then
    mkdir -p /tmp/opencode
    OUT="$(mktemp -d /tmp/opencode/kanata-switcher-dynamic.XXXXXX)"
fi
OUT="$(cd "$OUT" 2>/dev/null && pwd || (mkdir -p "$OUT" && cd "$OUT" && pwd))"
mkdir -p "$OUT"/{bin,src,target,strace,snapshots,mock,daemon,home,runtime,tmp,logs}

need() {
    command -v "$1" >/dev/null 2>&1 || { echo "error: required tool not found: $1" >&2; exit 2; }
}
need bwrap
need strace
need python3
need ss

if [[ "$MODE" == "daemon" && -z "$BINARY" && "$SKIP_BUILD" -eq 0 ]]; then
    need git
    need cargo
fi
if [[ "$SCENARIO" != "host-desktop" ]]; then
    need dbus-run-session
fi

BIN="$BINARY"
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
        echo "[build] cargo fetch --locked (network allowed only for this step)"
        cargo fetch --locked --manifest-path "$OUT/src/Cargo.toml" || {
            echo "error: cargo fetch failed; run with network access or pre-populate CARGO_HOME" >&2; exit 2;
        }
        echo "[build] cargo build --release --locked --offline"
        CARGO_TARGET_DIR="$OUT/target" cargo build --release --locked --offline \
            --manifest-path "$OUT/src/Cargo.toml" || {
            echo "error: release build failed" >&2; exit 2;
        }
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

META_MODE="$MODE" META_BIN="$BIN" META_REPO="$REPO" META_OUT="$OUT" \
META_COMMIT="$COMMIT" META_TAG="$TAG" META_DIRTY="$DIRTY" \
META_BIN_SHA="$BIN_SHA" META_LOCK_SHA="$LOCK_SHA" \
META_HOST="$HOST" META_PORT="$PORT" META_SCENARIO="$SCENARIO" \
META_COMMAND="$COMMAND" META_TIMESTAMP="$TIMESTAMP" \
META_CARGO="$CARGO_VERSION" META_RUSTC="$RUSTC_VERSION" \
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
}
data = {key: os.environ.get(env, "") for key, env in keys.items()}
data["expected_port"] = int(data["expected_port"] or 0)
data["network_namespace"] = "bwrap --unshare-net (loopback only)"
data["privileged_capture"] = False
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

mkdir -p "$OUT"/{strace,snapshots,mock,daemon,home,runtime,tmp,logs}
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

STRACE_PID=""
DAEMON_PID=""
MOCK_PID=""
EXIT_CODE=0
TRACE_EVENTS="%network,%process,openat,open,memfd_create,io_uring_setup,io_uring_enter,io_uring_register,bpf,init_module,finit_module,ptrace,unshare,setns,keyctl,add_key,request_key,mount,pivot_root,chroot"

snapshot_loop() {
    local i=0
    while kill -0 "$STRACE_PID" 2>/dev/null; do
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

stop_daemon() {
    if [[ -n "$DAEMON_PID" ]]; then
        kill -TERM "$DAEMON_PID" 2>/dev/null || true
    fi
    for _ in $(seq 1 20); do
        kill -0 "$STRACE_PID" 2>/dev/null || break
        sleep 0.25
    done
    if [[ -n "$DAEMON_PID" ]] && kill -0 "$DAEMON_PID" 2>/dev/null; then
        kill -KILL "$DAEMON_PID" 2>/dev/null || true
    fi
    if [[ -n "$STRACE_PID" ]] && kill -0 "$STRACE_PID" 2>/dev/null; then
        kill -KILL "$STRACE_PID" 2>/dev/null || true
    fi
}

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
        exit 2
    fi

    DAEMON_ARGS=(--host "$HOST" --port "$PORT" --dbus-suffix audit --no-install-gnome-extension)
    if [[ "$SCENARIO" == "minimal" ]]; then
        DAEMON_ARGS+=(--no-indicator)
    fi
    strace -ff -ttt -s 512 -v -o "$OUT/strace/daemon" -e trace="$TRACE_EVENTS" \
        "$BIN" "${DAEMON_ARGS[@]}" >"$OUT/daemon/stdout.log" 2>"$OUT/daemon/stderr.log" &
    STRACE_PID=$!
    for _ in $(seq 1 40); do
        DAEMON_PID="$(pgrep -P "$STRACE_PID" | head -n 1 || true)"
        [[ -n "$DAEMON_PID" ]] && break
        sleep 0.25
    done
    if [[ -z "$DAEMON_PID" ]]; then
        DAEMON_PID="$(pgrep -f "$BIN" | head -n 1 || true)"
    fi
    snapshot_loop &
    SNAPSHOT_PID=$!
    sleep 2
    if command -v gdbus >/dev/null 2>&1; then
        for _ in $(seq 1 10); do
            if gdbus call --session \
                --dest com.github.kanata.Switcher.instances.audit \
                --object-path /com/github/kanata/Switcher \
                --method com.github.kanata.Switcher.GetStatus \
                >>"$OUT/logs/gdbus.log" 2>&1; then
                break
            fi
            sleep 0.5
        done
    fi
    for _ in $(seq 1 "$TIMEOUT"); do
        kill -0 "$STRACE_PID" 2>/dev/null || break
        sleep 1
    done
    stop_daemon
    wait "$STRACE_PID" 2>/dev/null || EXIT_CODE=$?
    kill "$SNAPSHOT_PID" 2>/dev/null || true
    wait "$SNAPSHOT_PID" 2>/dev/null || true
    kill -TERM "$MOCK_PID" 2>/dev/null || true
    wait "$MOCK_PID" 2>/dev/null || true
else
    strace -ff -ttt -s 512 -v -o "$OUT/strace/daemon" -e trace="$TRACE_EVENTS" \
        bash -c "$COMMAND" >"$OUT/daemon/stdout.log" 2>"$OUT/daemon/stderr.log" &
    STRACE_PID=$!
    for _ in $(seq 1 40); do
        DAEMON_PID="$(pgrep -P "$STRACE_PID" | head -n 1 || true)"
        [[ -n "$DAEMON_PID" ]] && break
        sleep 0.05
    done
    snapshot_loop &
    SNAPSHOT_PID=$!
    for _ in $(seq 1 "$TIMEOUT"); do
        kill -0 "$STRACE_PID" 2>/dev/null || break
        sleep 1
    done
    if kill -0 "$STRACE_PID" 2>/dev/null; then
        DAEMON_PID="$(pgrep -P "$STRACE_PID" | head -n 1 || true)"
        stop_daemon
    fi
    wait "$STRACE_PID" 2>/dev/null || EXIT_CODE=$?
    kill "$SNAPSHOT_PID" 2>/dev/null || true
    wait "$SNAPSHOT_PID" 2>/dev/null || true
fi

MODE="$MODE" BIN="$BIN" PORT="$PORT" HOST="$HOST" SCENARIO="$SCENARIO" \
DAEMON_PID="$DAEMON_PID" STRACE_PID="$STRACE_PID" MOCK_PID="$MOCK_PID" EXIT_CODE="$EXIT_CODE" \
python3 - "$OUT/daemon/runtime.json" <<'PY'
import json, os, sys
keys = ["MODE", "BIN", "PORT", "HOST", "SCENARIO", "DAEMON_PID", "STRACE_PID", "MOCK_PID", "EXIT_CODE"]
data = {key.lower(): os.environ.get(key, "") for key in keys}
data["exit_code"] = int(data["exit_code"] or 0)
with open(sys.argv[1], "w", encoding="utf-8") as handle:
    json.dump(data, handle, indent=2, sort_keys=True)
    handle.write("\n")
PY
INNER_EOF
chmod +x "$OUT/inner.sh"

BWRAP_ARGS=(
    --unshare-net --unshare-pid --unshare-ipc --unshare-uts
    --die-with-parent --new-session
    --ro-bind / /
    --dev /dev
    --proc /proc
    --tmpfs /tmp
    --dir /tmp/opencode
    --dir "$OUT"
    --bind "$OUT" "$OUT"
    --dir /dev/shm
    --tmpfs /dev/shm
    --setenv HOME "$OUT/home"
    --setenv XDG_CONFIG_HOME "$OUT/home/.config"
    --setenv XDG_CACHE_HOME "$OUT/home/.cache"
    --setenv XDG_DATA_HOME "$OUT/home/.local/share"
    --setenv TMPDIR "$OUT/tmp"
    --setenv PATH "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
    --chdir "$OUT"
)
if [[ "$SCENARIO" == "host-desktop" ]]; then
    HOST_RUNTIME="${XDG_RUNTIME_DIR:-/run/user/$(id -u)}"
    if [[ ! -d "$HOST_RUNTIME" ]]; then
        echo "error: --scenario host-desktop requires an existing XDG_RUNTIME_DIR ($HOST_RUNTIME)" >&2
        exit 2
    fi
    BWRAP_ARGS+=(--setenv XDG_RUNTIME_DIR "$HOST_RUNTIME")
    if [[ -d /tmp/.X11-unix ]]; then
        BWRAP_ARGS+=(--dir /tmp/.X11-unix --ro-bind /tmp/.X11-unix /tmp/.X11-unix)
    fi
else
    BWRAP_ARGS+=(--setenv XDG_RUNTIME_DIR "$OUT/runtime")
fi

echo "[run] scenario=$SCENARIO mode=$MODE timeout=${TIMEOUT}s out=$OUT"
if [[ "$SCENARIO" == "host-desktop" ]]; then
    bwrap "${BWRAP_ARGS[@]}" "$OUT/inner.sh" \
        "$OUT" "$BIN" "$MODE" "$PORT" "$HOST" "$TIMEOUT" "$SCENARIO" "$SKILL_DIR" "$COMMAND"
    RUN_STATUS=$?
else
    bwrap "${BWRAP_ARGS[@]}" dbus-run-session -- "$OUT/inner.sh" \
        "$OUT" "$BIN" "$MODE" "$PORT" "$HOST" "$TIMEOUT" "$SCENARIO" "$SKILL_DIR" "$COMMAND"
    RUN_STATUS=$?
fi

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
    exit 2
fi

echo "[analyze] parsing strace, ss, /proc/net, and mock logs"
python3 "$SKILL_DIR/scripts/analyze_dynamic_logs.py" "$OUT" \
    --expected-host "$HOST" --expected-port "$PORT" \
    --json "$OUT/report.json" --markdown "$OUT/report.md"
ANALYZE_STATUS=$?

echo "[done] evidence: $OUT"
echo "[done] report: $OUT/report.md  json: $OUT/report.json"
echo "[note] evidence is kept for review; remove $OUT manually when finished"
exit "$ANALYZE_STATUS"
