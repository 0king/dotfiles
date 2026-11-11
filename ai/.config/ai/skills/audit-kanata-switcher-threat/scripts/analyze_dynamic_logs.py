#!/usr/bin/env python3
"""Analyze dynamic network-audit logs produced by run_dynamic_network_audit.sh.

Inputs (all optional except the strace directory):

  strace/daemon.*        strace -ff output for the daemon and its children
  snapshots/ss-*.txt     `ss` snapshots taken while the daemon was alive
  snapshots/procnet-*    copies of /proc/net/{tcp,tcp6,udp,udp6,packet,netlink,unix,raw}
  mock/kanata.log        JSONL log from the mock kanata server
  daemon/stdout.log      daemon stdout
  daemon/stderr.log      daemon stderr
  meta.json              harness metadata (binary, command, pids, expected endpoint)

The analyzer is deliberately strict: a failed connect attempt still counts.
Loopback is 127.0.0.0/8, ::1, and IPv4-mapped loopback. Only the configured
kanata TCP endpoint is allowed over IP; every UDP/raw/packet socket, every IP
listener, every non-loopback endpoint, and every DNS resolver contact is a
finding. Unknown Unix sockets are findings too, because the audit contract
allows only the documented desktop IPC sockets.

Exit codes: 0 = no findings at/above --fail-on, 1 = findings, 2 = usage error.
"""

from __future__ import annotations

import argparse
import fnmatch
import ipaddress
import json
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable

SEVERITY_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}

DEFAULT_UNIX_GLOBS = [
    "/run/user/*/bus",
    "/run/user/*/wayland-*",
    "/run/user/*/.wayland-*",
    "/tmp/dbus-*",
    "@/tmp/dbus-*",
    "/tmp/.X11-unix/X*",
    "@/tmp/.X11-unix/X*",
    "/run/dbus/system_bus_socket",
    "/var/run/dbus/system_bus_socket",
    "/dev/log",
]

NETWORK_TOOLS = {
    "curl", "wget", "nc", "ncat", "netcat", "socat", "ssh", "scp", "sftp",
    "rsync", "ftp", "telnet", "dig", "nslookup", "host", "ping", "traceroute",
    "openssl", "gnutls-cli", "http", "https", "aria2c", "yt-dlp",
}

SENSITIVE_PATHS = [
    "/etc/shadow", "/etc/gshadow", "/etc/sudoers", "/root/.ssh",
    "/.ssh/", "id_rsa", "id_ed25519", "id_ecdsa", "/.aws/credentials",
    "/.gnupg/", "wallet.dat", "keystore", "private_key", "seed.txt",
]

SUSPICIOUS_SYSCALLS = {
    "bpf": ("high", "BPF syscall (kernel program loading)"),
    "init_module": ("critical", "kernel module load"),
    "finit_module": ("critical", "kernel module load from fd"),
    "ptrace": ("high", "process tracing/injection"),
    "unshare": ("high", "namespace change"),
    "setns": ("high", "namespace change"),
    "memfd_create": ("medium", "anonymous executable-capable file"),
    "io_uring_setup": ("medium", "io_uring submission queue"),
    "keyctl": ("medium", "kernel keyring operation"),
    "add_key": ("medium", "kernel keyring operation"),
    "mount": ("medium", "filesystem mount"),
    "pivot_root": ("high", "root filesystem change"),
    "chroot": ("medium", "root filesystem change"),
}

SOCKET_RE = re.compile(r"\bsocket\((?P<family>AF_[A-Z0-9_]+),\s*(?P<type>SOCK_[A-Z0-9_|]+)(?:,\s*(?P<proto>[A-Z0-9_]+))?\)\s*=\s*(?P<fd>-?\d+)")
SOCKETPAIR_RE = re.compile(r"\bsocketpair\((?P<family>AF_[A-Z0-9_]+),\s*(?P<type>SOCK_[A-Z0-9_|]+)(?:,\s*(?P<proto>[A-Z0-9_]+))?,\s*\[(?P<fds>[^\]]+)\]\)\s*=\s*(?P<ret>-?\d+)")
SEND_RE = re.compile(r"\b(?P<call>sendto|recvfrom|sendmsg|recvmsg)\((?P<fd>\d+),.*?(?P<sockaddr>\{sa_family=[^}]*\})")
CONNECT_RE = re.compile(r"\b(?P<call>connect|bind|sendto|recvfrom|accept4?|getpeername|getsockname)\((?P<fd>\d+),\s*(?P<sockaddr>\{[^}]*\})(?:,\s*(?P<len>\d+))?.*?\)\s*=\s*(?P<ret>-?\d+)(?:\s+(?P<errno>[A-Z][A-Z0-9_]+))?")
EXEC_RE = re.compile(r"\bexecve\(\"(?P<path>[^\"]+)\",\s*\[(?P<args>[^\]]*)\]")
OPEN_RE = re.compile(r"\b(?:open|openat)\((?:[^,]+,\s*)?\"(?P<path>[^\"]+)\"")
SIMPLE_CALL_RE = re.compile(r"\b(?P<name>[a-z_][a-z0-9_]*)\((?:[^)]*)\)\s*=\s*(?P<ret>-?\d+)")


@dataclass
class Finding:
    rule: str
    severity: str
    detail: str
    pid: int | None = None
    file: str = ""

    def as_dict(self) -> dict[str, Any]:
        return {"rule": self.rule, "severity": self.severity, "detail": self.detail, "pid": self.pid, "file": self.file}


@dataclass
class Event:
    kind: str
    family: str = ""
    sock_type: str = ""
    protocol: str = ""
    address: str = ""
    port: int | None = None
    path: str = ""
    result: str = ""
    errno: str = ""
    pid: int | None = None
    file: str = ""
    raw: str = ""


@dataclass
class Report:
    directory: str
    meta: dict[str, Any] = field(default_factory=dict)
    events: list[Event] = field(default_factory=list)
    execs: list[dict[str, Any]] = field(default_factory=list)
    suspicious: list[dict[str, Any]] = field(default_factory=list)
    sensitive_files: list[str] = field(default_factory=list)
    procnet: dict[str, Any] = field(default_factory=dict)
    ss: list[str] = field(default_factory=list)
    mock: list[dict[str, Any]] = field(default_factory=list)
    thread_pids: set[int] = field(default_factory=set)
    findings: list[Finding] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)

    def add(self, rule: str, severity: str, detail: str, pid: int | None = None, file: str = "") -> None:
        self.findings.append(Finding(rule, severity, detail, pid, file))

    def as_dict(self) -> dict[str, Any]:
        return {
            "directory": self.directory,
            "meta": self.meta,
            "events": [e.__dict__ for e in self.events],
            "execs": self.execs,
            "suspicious": self.suspicious,
            "sensitive_files": self.sensitive_files,
            "procnet": self.procnet,
            "ss": self.ss,
            "mock": self.mock,
            "findings": [f.as_dict() for f in self.findings],
            "notes": self.notes,
        }


def parse_pid(path: Path) -> int | None:
    suffix = path.name.rsplit(".", 1)[-1]
    return int(suffix) if suffix.isdigit() else None


def is_loopback(address: str) -> bool:
    try:
        value = ipaddress.ip_address(address)
    except ValueError:
        return False
    if isinstance(value, ipaddress.IPv6Address) and value.ipv4_mapped:
        value = value.ipv4_mapped
    return value.is_loopback


def unix_allowed(path: str, globs: Iterable[str]) -> bool:
    if not path or path in ("", "<unbound>"):
        return True
    if path.startswith("socket:[") or path.startswith("anon_inode:"):
        return True
    return any(fnmatch.fnmatch(path, pattern) for pattern in globs)


def parse_sockaddr(text: str) -> tuple[str, str, int | None, str]:
    """Return (family, address, port, path) from a strace sockaddr literal."""
    family_match = re.search(r"sa_family=(AF_[A-Z0-9_]+)", text)
    family = family_match.group(1) if family_match else ""
    if family == "AF_UNIX":
        path_match = re.search(r"sun_path=(@?)\"([^\"]*)\"", text)
        if path_match:
            prefix = "@" if path_match.group(1) else ""
            return family, "", None, prefix + path_match.group(2)
        return family, "", None, ""
    if family == "AF_INET6":
        addr_match = re.search(r"inet_pton\(AF_INET6,\s*\"([^\"]+)\"", text)
        port_match = re.search(r"sin6_port=htons\((\d+)\)", text)
        return family, addr_match.group(1) if addr_match else "", int(port_match.group(1)) if port_match else None, ""
    if family == "AF_INET":
        addr_match = re.search(r"inet_addr\(\"([^\"]+)\"\)", text)
        port_match = re.search(r"sin_port=htons\((\d+)\)", text)
        return family, addr_match.group(1) if addr_match else "", int(port_match.group(1)) if port_match else None, ""
    if family == "AF_NETLINK":
        return family, "", None, ""
    if family == "AF_PACKET":
        return family, "", None, ""
    return family, "", None, ""


def parse_strace_file(path: Path, report: Report) -> None:
    pid = parse_pid(path)
    try:
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError as exc:
        report.notes.append(f"could not read {path}: {exc}")
        return
    for line in lines:
        clone_match = re.search(r"\bclone3?\(.*\)\s*=\s*(\d+)", line)
        if clone_match and "CLONE_THREAD" in line:
            report.thread_pids.add(int(clone_match.group(1)))
        socket_match = SOCKET_RE.search(line)
        if socket_match:
            report.events.append(Event(
                kind="socket", family=socket_match.group("family"),
                sock_type=socket_match.group("type"), protocol=socket_match.group("proto") or "",
                result=socket_match.group("fd"), pid=pid, file=path.name, raw=line,
            ))
        socketpair_match = SOCKETPAIR_RE.search(line)
        if socketpair_match:
            report.events.append(Event(
                kind="socketpair", family=socketpair_match.group("family"),
                sock_type=socketpair_match.group("type"), result=socketpair_match.group("ret"),
                pid=pid, file=path.name, raw=line,
            ))
        for call_match in CONNECT_RE.finditer(line):
            family, address, port, unix_path = parse_sockaddr(call_match.group("sockaddr"))
            report.events.append(Event(
                kind=call_match.group("call"), family=family, address=address, port=port,
                path=unix_path, result=call_match.group("ret"),
                errno=call_match.group("errno") or "", pid=pid, file=path.name, raw=line,
            ))
        for send_match in SEND_RE.finditer(line):
            family, address, port, unix_path = parse_sockaddr(send_match.group("sockaddr"))
            report.events.append(Event(
                kind=send_match.group("call"), family=family, address=address, port=port,
                path=unix_path, result="", pid=pid, file=path.name, raw=line,
            ))
        listen_match = re.search(r"\blisten\((\d+),\s*(\d+)\)\s*=\s*(-?\d+)", line)
        if listen_match:
            report.events.append(Event(kind="listen", result=listen_match.group(3), pid=pid, file=path.name, raw=line))
        exec_match = EXEC_RE.search(line)
        if exec_match:
            args = exec_match.group("args")
            report.execs.append({
                "pid": pid, "file": path.name, "path": exec_match.group("path"),
                "args": args[:1000], "raw": line[:2000],
            })
        open_match = OPEN_RE.search(line)
        if open_match:
            opened = open_match.group("path")
            if any(marker in opened for marker in SENSITIVE_PATHS):
                report.sensitive_files.append(f"pid={pid} {opened}")
                report.add("DYN-SENSITIVE-FILE", "high", f"opened sensitive path: {opened}", pid, path.name)
        simple_match = SIMPLE_CALL_RE.search(line)
        if simple_match and simple_match.group("name") in SUSPICIOUS_SYSCALLS:
            name = simple_match.group("name")
            severity, description = SUSPICIOUS_SYSCALLS[name]
            report.suspicious.append({"pid": pid, "file": path.name, "call": name, "raw": line[:1000]})
            report.add("DYN-SUSPICIOUS-SYSCALL", severity, f"{name}: {description}", pid, path.name)
        if "io_uring_enter(" in line or "io_uring_register(" in line:
            report.suspicious.append({"pid": pid, "file": path.name, "call": "io_uring", "raw": line[:1000]})
            report.add("DYN-SUSPICIOUS-SYSCALL", "medium", "io_uring operation", pid, path.name)


def analyze_events(report: Report, expected_host: str, expected_port: int, unix_globs: list[str], mode: str) -> None:
    seen_kanata = False
    expected_hosts = {expected_host}
    if expected_host == "localhost":
        expected_hosts.update({"127.0.0.1", "::1"})
    raw_main_pid = report.meta.get("daemon_pid") or report.meta.get("main_pid")
    try:
        main_pid = int(raw_main_pid) if raw_main_pid not in (None, "") else None
    except (TypeError, ValueError):
        main_pid = None
    for event in report.events:
        if event.kind == "listen":
            report.add("DYN-LISTEN", "high", f"listen() syscall observed (result={event.result})", event.pid, event.file)
            continue
        if event.kind in ("getpeername", "getsockname"):
            # These report the socket's own/peer address and are not new I/O.
            continue
        if event.kind in ("connect", "bind", "sendto", "recvfrom", "accept", "accept4"):
            if event.family in ("AF_INET", "AF_INET6"):
                endpoint = f"{event.address}:{event.port}" if event.address else f"port {event.port}"
                loopback = is_loopback(event.address)
                expected = event.address in expected_hosts and event.port == expected_port
                is_tcp_expected = expected and loopback and event.kind not in ("bind", "listen", "sendto", "recvfrom")
                if event.kind == "connect" and loopback and expected:
                    seen_kanata = True
                    if event.result != "0" and event.errno not in ("EINPROGRESS", "EALREADY"):
                        report.add("DYN-KANATA-CONNECT-FAILED", "medium", f"connect to expected endpoint failed: {endpoint} result={event.result} {event.errno}".strip(), event.pid, event.file)
                if event.kind == "bind":
                    severity = "critical" if not loopback or event.address in ("0.0.0.0", "::") else "high"
                    report.add("DYN-IP-BIND", severity, f"IP bind to {endpoint} (family={event.family})", event.pid, event.file)
                elif event.kind in ("accept", "accept4"):
                    report.add("DYN-IP-ACCEPT", "high", f"accepted inbound IP connection from {endpoint}", event.pid, event.file)
                elif event.kind in ("sendto", "recvfrom"):
                    severity = "high"
                    label = "UDP/raw sendto" if event.kind == "sendto" else "UDP/raw recvfrom"
                    if event.port == 53:
                        report.add("DYN-DNS", "high", f"{label} to DNS endpoint {endpoint}", event.pid, event.file)
                    report.add("DYN-UDP", severity, f"{label} to {endpoint} (family={event.family})", event.pid, event.file)
                elif not loopback:
                    report.add("DYN-NONLOOPBACK-CONNECT", "high", f"{event.kind} to non-loopback endpoint {endpoint} (result={event.result})", event.pid, event.file)
                elif not is_tcp_expected:
                    report.add("DYN-LOOPBACK-UNEXPECTED", "high", f"{event.kind} to loopback endpoint {endpoint}; expected {expected_host}:{expected_port}", event.pid, event.file)
                if event.port == 53 and event.kind not in ("sendto", "recvfrom"):
                    report.add("DYN-DNS", "high", f"TCP DNS connection to {endpoint}", event.pid, event.file)
                if main_pid and event.pid and event.pid != main_pid and event.pid not in report.thread_pids and event.kind in ("connect", "sendto"):
                    report.add("DYN-CHILD-IP-NETWORK", "high", f"child pid {event.pid} performed IP network I/O to {endpoint}", event.pid, event.file)
            elif event.family == "AF_UNIX":
                if event.kind == "bind":
                    report.add("DYN-UNIX-LISTENER", "high", f"daemon bound a Unix socket at {event.path or '<unnamed>'}", event.pid, event.file)
                elif event.path and not unix_allowed(event.path, unix_globs):
                    report.add("DYN-UNIX-UNEXPECTED", "medium", f"{event.kind} to undocumented Unix socket {event.path}", event.pid, event.file)
            elif event.family == "AF_PACKET":
                report.add("DYN-AF-PACKET", "critical", f"AF_PACKET {event.kind} (raw layer-2 access)", event.pid, event.file)
            elif event.family == "AF_NETLINK":
                report.add("DYN-NETLINK", "info", f"AF_NETLINK {event.kind} (local kernel IPC)", event.pid, event.file)
            elif event.family and event.family not in ("AF_UNIX", "AF_INET", "AF_INET6", "AF_NETLINK", "AF_PACKET"):
                report.add("DYN-OTHER-FAMILY", "high", f"{event.kind} on {event.family}", event.pid, event.file)

        if event.kind == "socket":
            if event.family == "AF_NETLINK":
                report.add("DYN-NETLINK", "info", f"AF_NETLINK socket created (type={event.sock_type})", event.pid, event.file)
            elif event.family == "AF_PACKET":
                report.add("DYN-AF-PACKET", "critical", f"AF_PACKET socket created (type={event.sock_type})", event.pid, event.file)
            elif "SOCK_RAW" in event.sock_type:
                report.add("DYN-RAW-SOCKET", "critical", f"raw socket created (family={event.family}, type={event.sock_type})", event.pid, event.file)
            elif event.family not in ("AF_INET", "AF_INET6", "AF_UNIX", "AF_NETLINK", "AF_PACKET", "AF_UNSPEC"):
                report.add("DYN-OTHER-FAMILY", "high", f"socket family {event.family} (type={event.sock_type})", event.pid, event.file)
            elif event.family == "AF_INET" and "SOCK_DGRAM" in event.sock_type:
                report.add("DYN-UDP", "high", "UDP socket created", event.pid, event.file)
            elif event.family == "AF_INET6" and "SOCK_DGRAM" in event.sock_type:
                report.add("DYN-UDP", "high", "UDP/IPv6 socket created", event.pid, event.file)

    if mode == "daemon" and not seen_kanata:
        report.add("DYN-KANATA-MISSING", "high", f"no connect to expected kanata endpoint {expected_host}:{expected_port} observed")
    if seen_kanata:
        report.notes.append(f"observed expected kanata TCP connect to {expected_host}:{expected_port}")


def analyze_execs(report: Report, baseline: dict[str, Any]) -> None:
    allowed = {entry.get("command", "") for entry in baseline.get("expected_exec", []) if entry.get("command")}
    target = Path(str(report.meta.get("binary") or "")).name
    for entry in report.execs:
        path = entry["path"]
        base = Path(path).name
        args = entry["args"]
        if target and base == target:
            report.notes.append(f"target binary exec: {path}")
            continue
        if base in NETWORK_TOOLS:
            report.add("DYN-NETWORK-TOOL-EXEC", "high", f"executed network tool {path} {args[:200]}", entry["pid"], entry["file"])
        elif base in ("sh", "bash", "dash", "zsh", "ksh") and ("-c" in args or " -c " in args):
            report.add("DYN-SHELL-EXEC", "high", f"executed shell with -c: {path} {args[:200]}", entry["pid"], entry["file"])
        elif base not in allowed:
            report.add("DYN-UNEXPECTED-EXEC", "medium", f"executed {path} {args[:200]}", entry["pid"], entry["file"])
        else:
            report.notes.append(f"expected exec: {path}")


def hex_to_ipv4(value: str) -> str:
    try:
        raw = bytes.fromhex(value)
    except ValueError:
        return value
    return ".".join(str(byte) for byte in reversed(raw))


def hex_to_ipv6(value: str) -> str:
    try:
        raw = bytes.fromhex(value)
    except ValueError:
        return value
    if len(raw) != 16:
        return value
    words = [raw[index:index + 4][::-1] for index in range(0, 16, 4)]
    return str(ipaddress.IPv6Address(b"".join(words)))


def parse_procnet_file(path: Path, report: Report, expected_host: str, expected_port: int) -> None:
    name = path.name
    if name.startswith("procnet-"):
        name = name[len("procnet-"):]
    name = re.sub(r"-\d+\.txt$", "", name)
    family = "ipv6" if "6" in name else "ipv4"
    entries: list[dict[str, Any]] = []
    try:
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError as exc:
        report.notes.append(f"could not read {path}: {exc}")
        return
    for line in lines[1:]:
        parts = line.split()
        if len(parts) < 4:
            continue
        if name == "packet":
            report.add("DYN-PROCNET-PACKET", "critical", "AF_PACKET socket present")
            continue
        if name == "netlink":
            report.notes.append("procnet: AF_NETLINK socket present (local kernel IPC)")
            continue
        if name == "unix":
            unix_path = parts[7] if len(parts) > 7 else ""
            entries.append({"path": unix_path, "state": parts[5] if len(parts) > 5 else "", "file": name})
            continue
        local, remote, state = parts[1], parts[2], parts[3]
        if ":" not in local:
            continue
        local_addr, local_port_hex = local.rsplit(":", 1)
        remote_addr, remote_port_hex = remote.rsplit(":", 1) if ":" in remote else (remote, "0")
        try:
            local_port = int(local_port_hex, 16)
            remote_port = int(remote_port_hex, 16)
        except ValueError:
            continue
        if name.startswith("tcp") or name.startswith("udp") or name.startswith("raw"):
            decode = hex_to_ipv6 if family == "ipv6" else hex_to_ipv4
            entry = {
                "local": f"{decode(local_addr)}:{local_port}",
                "remote": f"{decode(remote_addr)}:{remote_port}",
                "state": state, "family": family, "file": name,
            }
            entries.append(entry)
            if name.startswith("tcp") and state == "0A":
                if local_port == expected_port and (is_loopback(decode(local_addr)) or decode(local_addr) in ("0.0.0.0", "::")):
                    report.notes.append(f"procnet: mock kanata listener on {entry['local']}")
                elif decode(local_addr) in ("0.0.0.0", "::") or not is_loopback(decode(local_addr)):
                    report.add("DYN-PROCNET-LISTENER", "critical", f"non-loopback TCP listener {entry['local']}")
                else:
                    report.add("DYN-PROCNET-LISTENER", "high", f"unexpected loopback TCP listener {entry['local']}")
            if name.startswith("udp"):
                report.add("DYN-PROCNET-UDP", "high", f"UDP socket {entry['local']} -> {entry['remote']}")
            if name.startswith("raw"):
                report.add("DYN-PROCNET-RAW", "high", f"raw socket {entry['local']} -> {entry['remote']}")
            if name.startswith("tcp") and state not in ("0A", "07") and not is_loopback(decode(remote_addr)):
                report.add("DYN-PROCNET-REMOTE", "high", f"TCP connection to non-loopback {entry['remote']}")
    report.procnet[name] = entries


def analyze_ss(report: Report, expected_host: str, expected_port: int) -> None:
    for line in report.ss:
        if not line or line.startswith(("State", "Netid", "Ref")):
            continue
        fields = line.split()
        if not fields:
            continue
        state = fields[0]
        if state not in ("LISTEN", "ESTAB", "UNCONN", "SYN-SENT", "TIME-WAIT"):
            continue
        local = fields[3] if len(fields) > 3 else ""
        peer = fields[4] if len(fields) > 4 else ""
        if state == "LISTEN":
            if f":{expected_port}" in local and ("127.0.0.1" in local or "[::1]" in local):
                report.notes.append(f"ss: mock kanata listener {local}")
            elif local.startswith(("0.0.0.0:", "[::]:", "*:")) or not any(x in local for x in ("127.", "[::1]")):
                report.add("DYN-SS-LISTENER", "critical", f"non-loopback listener {local}")
            else:
                report.add("DYN-SS-LISTENER", "high", f"unexpected loopback listener {local}")
        elif state == "UNCONN":
            report.add("DYN-SS-UDP", "high", f"UDP/unconnected socket {local}")
        elif state in ("ESTAB", "SYN-SENT", "TIME-WAIT"):
            local_host, _, local_port = local.rpartition(":")
            peer_host = peer.rsplit(":", 1)[0].strip("[]")
            if local_port == str(expected_port) and is_loopback(local_host.strip("[]")):
                report.notes.append(f"ss: mock kanata side {local} -> {peer}")
                continue
            if not is_loopback(peer_host):
                report.add("DYN-SS-REMOTE", "high", f"TCP peer is not loopback: {local} -> {peer}")
            elif f":{expected_port}" not in peer:
                report.add("DYN-SS-UNEXPECTED", "high", f"loopback TCP peer is not the expected kanata port: {local} -> {peer}")


def analyze_mock(report: Report, mock_path: Path, expected_min: int = 1, expected_max: int | None = None) -> None:
    if not mock_path.is_file():
        report.notes.append("no mock kanata log; daemon-mode connection count cannot be confirmed")
        return
    connects = 0
    for line in mock_path.read_text(encoding="utf-8", errors="replace").splitlines():
        try:
            record = json.loads(line)
        except json.JSONDecodeError:
            report.add("DYN-MOCK-BAD-LOG", "low", f"unparseable mock log line: {line[:200]}")
            continue
        report.mock.append(record)
        if record.get("event") == "connect":
            connects += 1
        if record.get("event") == "invalid_json":
            report.add("DYN-MOCK-INVALID-JSON", "low", "daemon sent invalid JSON to kanata")
        if record.get("event") == "message":
            message = record.get("message", {})
            if not isinstance(message, dict) or not any(key in message for key in ("ChangeLayer", "ActOnFakeKey", "RequestLayerNames", "RequestFakeKeyNames")):
                report.add("DYN-MOCK-UNKNOWN-COMMAND", "medium", f"unexpected command to kanata: {message}")
    if report.meta.get("mode") == "daemon":
        if connects == 0:
            report.add("DYN-KANATA-NO-CONNECT", "high", "mock kanata saw no connection from the daemon")
        elif connects < expected_min:
            report.add("DYN-KANATA-TOO-FEW-CONNECTS", "medium", f"mock kanata saw {connects} connection(s); expected at least {expected_min}")
        elif expected_max is not None and connects > expected_max:
            report.add("DYN-KANATA-TOO-MANY-CONNECTS", "medium", f"mock kanata saw {connects} connection(s); expected at most {expected_max}")
    report.notes.append(f"mock kanata accepted {connects} connection(s)")


def dedupe(report: Report) -> None:
    seen: set[tuple[str, str, int | None]] = set()
    unique: list[Finding] = []
    for finding in report.findings:
        key = (finding.rule, finding.detail, finding.pid)
        if key in seen:
            continue
        seen.add(key)
        unique.append(finding)
    report.findings = unique


def load_inputs(directory: Path, report: Report) -> None:
    meta_path = directory / "meta.json"
    if meta_path.is_file():
        try:
            report.meta = json.loads(meta_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            report.notes.append(f"could not read meta.json: {exc}")
    strace_dir = directory / "strace"
    if not strace_dir.is_dir():
        raise SystemExit(f"error: {strace_dir} does not exist")
    files = sorted(strace_dir.glob("daemon.*")) + sorted(strace_dir.glob("trace.*"))
    if not files:
        raise SystemExit(f"error: no strace logs in {strace_dir}")
    for path in files:
        parse_strace_file(path, report)
    if not report.meta.get("daemon_pid"):
        # The tracee started by strace has the lowest pid in the -ff output.
        # This fallback lets --command mode still distinguish a child connect.
        pids = sorted(pid for pid in (parse_pid(path) for path in files) if pid)
        if pids:
            report.meta["daemon_pid"] = pids[0]
    for path in sorted((directory / "snapshots").glob("ss-*.txt")):
        try:
            report.ss.extend(path.read_text(encoding="utf-8", errors="replace").splitlines())
        except OSError as exc:
            report.notes.append(f"could not read {path}: {exc}")
    for path in sorted((directory / "snapshots").glob("procnet-*")):
        parse_procnet_file(path, report, str(report.meta.get("expected_host", "127.0.0.1")), int(report.meta.get("expected_port", 10000)))


def print_report(report: Report, verbose: bool) -> None:
    print(f"directory: {report.directory}")
    print(f"mode: {report.meta.get('mode', 'unknown')}  binary: {report.meta.get('binary', 'n/a')}")
    print(f"strace events: {len(report.events)}  execs: {len(report.execs)}  suspicious syscalls: {len(report.suspicious)}")
    print(f"mock records: {len(report.mock)}  procnet files: {len(report.procnet)}  ss lines: {len(report.ss)}")
    if verbose:
        for event in report.events:
            if event.kind in ("connect", "bind", "listen", "sendto", "recvfrom"):
                endpoint = f"{event.address}:{event.port}" if event.address else event.path
                print(f"  pid={event.pid} {event.kind} {event.family} {endpoint} result={event.result}")
        for entry in report.execs:
            print(f"  exec pid={entry['pid']} {entry['path']} {entry['args'][:160]}")
    counts = {severity: 0 for severity in SEVERITY_ORDER}
    for finding in report.findings:
        counts[finding.severity] = counts.get(finding.severity, 0) + 1
    print("findings: " + "  ".join(f"{k}={v}" for k, v in counts.items() if v))
    for finding in sorted(report.findings, key=lambda f: -SEVERITY_ORDER.get(f.severity, 0)):
        location = f" pid={finding.pid}" if finding.pid else ""
        print(f"[{finding.severity.upper():8}] {finding.rule}{location}: {finding.detail}")


def write_markdown(report: Report, path: Path) -> None:
    lines = [
        "# Dynamic Network Audit",
        "",
        f"- Directory: `{report.directory}`",
        f"- Mode: `{report.meta.get('mode', 'unknown')}`",
        f"- Binary: `{report.meta.get('binary', 'n/a')}`",
        f"- Expected endpoint: `{report.meta.get('expected_host', '127.0.0.1')}:{report.meta.get('expected_port', 10000)}`",
        f"- Strace events: {len(report.events)}; execs: {len(report.execs)}; mock records: {len(report.mock)}",
        "",
        "## Findings",
        "",
    ]
    if not report.findings:
        lines.append("No findings at the configured threshold.")
    for finding in sorted(report.findings, key=lambda f: -SEVERITY_ORDER.get(f.severity, 0)):
        lines.append(f"- **{finding.severity.upper()}** `{finding.rule}` — {finding.detail}")
    lines += ["", "## IP endpoints observed", ""]
    endpoints = {
        f"{event.family} {event.address}:{event.port} ({event.kind})"
        for event in report.events
        if event.family in ("AF_INET", "AF_INET6") and event.address
    }
    lines += [f"- `{endpoint}`" for endpoint in sorted(endpoints)] or ["- none"]
    lines += ["", "## Unix sockets observed", ""]
    unix = {
        f"{event.path} ({event.kind})"
        for event in report.events
        if event.family == "AF_UNIX" and event.path
    }
    lines += [f"- `{socket}`" for socket in sorted(unix)] or ["- none"]
    lines += ["", "## Executions", ""]
    lines += [f"- `{entry['path']}` {entry['args'][:200]}" for entry in report.execs] or ["- none"]
    lines += ["", "## Notes", ""]
    lines += [f"- {note}" for note in report.notes] or ["- none"]
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("directory", nargs="?", default=".", type=Path, help="harness output directory")
    parser.add_argument("--baseline", type=Path, help="baseline JSON (default: ../references/network-baseline.json)")
    parser.add_argument("--expected-host", help="expected kanata host (default: meta.json or 127.0.0.1)")
    parser.add_argument("--expected-port", type=int, help="expected kanata port (default: meta.json or 10000)")
    parser.add_argument("--unix-glob", action="append", default=[], help="additional allowed Unix socket glob")
    parser.add_argument("--json", type=Path, help="write the full report as JSON")
    parser.add_argument("--markdown", type=Path, help="write a Markdown report")
    parser.add_argument("--verbose", action="store_true", help="print every IP/Unix event and execution")
    parser.add_argument("--fail-on", choices=list(SEVERITY_ORDER), default=None, help="exit 1 at/above this severity (default: baseline expected_dynamic.fail_on or medium)")
    args = parser.parse_args(argv)

    directory = args.directory.resolve()
    report = Report(directory=str(directory))
    try:
        load_inputs(directory, report)
    except SystemExit as exc:
        print(str(exc), file=sys.stderr)
        return 2

    baseline_path = args.baseline or Path(__file__).resolve().parent.parent / "references" / "network-baseline.json"
    baseline: dict[str, Any] = {}
    if baseline_path.is_file():
        try:
            baseline = json.loads(baseline_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            report.notes.append(f"baseline could not be loaded: {exc}")
    else:
        report.notes.append(f"baseline not found: {baseline_path}")

    host = args.expected_host or str(report.meta.get("expected_host", "127.0.0.1"))
    port = args.expected_port or int(report.meta.get("expected_port", 10000))
    globs = list(baseline.get("dynamic_policy", {}).get("allowed_unix_socket_globs", DEFAULT_UNIX_GLOBS)) + args.unix_glob
    mode = str(report.meta.get("mode", "daemon"))
    dynamic = baseline.get("expected_dynamic", {})
    expected_min = int(dynamic.get("expected_connect_min", 1))
    expected_max_raw = dynamic.get("expected_connect_max")
    expected_max = int(expected_max_raw) if expected_max_raw is not None else None
    analyze_mock(report, directory / "mock" / "kanata.log", expected_min, expected_max)
    analyze_events(report, host, port, globs, mode)
    if mode == "daemon":
        analyze_execs(report, baseline)
    analyze_ss(report, host, port)
    dedupe(report)

    print_report(report, args.verbose)
    if args.json:
        args.json.parent.mkdir(parents=True, exist_ok=True)
        args.json.write_text(json.dumps(report.as_dict(), indent=2) + "\n", encoding="utf-8")
        print(f"json: {args.json}")
    if args.markdown:
        args.markdown.parent.mkdir(parents=True, exist_ok=True)
        write_markdown(report, args.markdown)
        print(f"markdown: {args.markdown}")

    fail_on = args.fail_on or str(dynamic.get("fail_on", "medium"))
    if fail_on not in SEVERITY_ORDER:
        fail_on = "medium"
    threshold = SEVERITY_ORDER[fail_on]
    return 1 if any(SEVERITY_ORDER.get(f.severity, 0) >= threshold for f in report.findings) else 0


if __name__ == "__main__":
    raise SystemExit(main())
