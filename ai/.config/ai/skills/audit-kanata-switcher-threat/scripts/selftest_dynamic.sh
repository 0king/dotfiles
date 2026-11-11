#!/usr/bin/env bash
# Negative controls for the dynamic harness.
#
# Each control is a tiny Python program run under the same bwrap+strace
# isolation as the real daemon. The analyzer must report the expected rule.
# A clean control must produce no findings at the default threshold.
#
# This is intentionally separate from the normal audit: run it after changing
# the harness or analyzer, not on every audit.

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
HARNESS="$SCRIPT_DIR/run_dynamic_network_audit.sh"
ROOT="$(mktemp -d /tmp/opencode/kanata-switcher-selftest.XXXXXX)"
PASS=0
FAIL=0

cleanup() {
    echo "[selftest] evidence kept in $ROOT"
}
trap cleanup EXIT

write_control() {
    local path="$1" body="$2"
    mkdir -p "$(dirname "$path")"
    printf '%s\n' "$body" > "$path"
}

run_control() {
    local name="$1" expected_rule="$2" expect_status="$3" body="$4"
    local out="$ROOT/$name"
    mkdir -p "$out"
    write_control "$out/control.py" "$body"
    echo "[selftest] $name: expecting status $expect_status ${expected_rule:+(rule $expected_rule)}"
    if "$HARNESS" --command "python3 $out/control.py" --out "$out" --timeout 5 >"$ROOT/$name.log" 2>&1; then
        status=0
    else
        status=$?
    fi
    if [[ "$status" -ne "$expect_status" ]]; then
        echo "[selftest] FAIL $name: harness status $status, expected $expect_status (see $ROOT/$name.log)"
        FAIL=$((FAIL + 1))
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
            echo "[selftest] PASS $name"
            PASS=$((PASS + 1))
        else
            echo "[selftest] FAIL $name: rule $expected_rule not found in $out/report.json"
            FAIL=$((FAIL + 1))
        fi
    else
        echo "[selftest] PASS $name"
        PASS=$((PASS + 1))
    fi
}

# Clean control: no sockets, no execs beyond the Python interpreter.
run_control clean "" 0 'import time; time.sleep(0.5)'

# Non-loopback TCP connect (TEST-NET-1, guaranteed not routable). Even a failed
# attempt must be reported.
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

# UDP DNS probe to a loopback resolver: still forbidden because the baseline
# has no UDP at all.
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

echo "[selftest] passed=$PASS failed=$FAIL"
[[ "$FAIL" -eq 0 ]]
