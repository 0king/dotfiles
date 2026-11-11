#!/usr/bin/env python3
"""Analyze dynamic network-audit logs produced by the privileged harnesses.

Inputs (all optional except the strace directory):

  strace/daemon.*        strace -ff output for the daemon and its children
  pcap/*.pcap            tcpdump capture on the capture-side veth
  net/dns.jsonl          DNS sinkhole query log
  net/tcp.jsonl          TCP sinkhole connection/payload log
  dbus/*.log             dbus-monitor output for the private session/system bus
  build/fetch.strace.*   cargo fetch network trace (host network)
  build/build.strace.*   cargo build --offline network trace (veth netns)
  snapshots/ss-*.txt     `ss` snapshots taken while the daemon was alive
  snapshots/procnet-*    copies of /proc/net/{tcp,tcp6,udp,udp6,packet,netlink,unix,raw}
  mock/kanata.log        JSONL log from the mock kanata server
  gnome/shell.log        nested GNOME Shell stdout/stderr
  meta.json              harness metadata (binary, command, pids, expected endpoint)

The analyzer is deliberately strict: a failed connect attempt still counts.
Loopback is 127.0.0.0/8, ::1, and IPv4-mapped loopback. Only the configured
kanata TCP endpoint is allowed over IP; every UDP/raw/packet socket, every IP
listener, every non-loopback endpoint, and every DNS resolver contact is a
finding. The veth is a real-world-looking network, so any packet the target
sends over it is egress even if the sinkhole answers it. Unknown Unix sockets
are findings too, because the audit contract allows only the documented desktop
IPC sockets. D-Bus destinations and methods are checked because a cooperating
service can turn an allowed local socket into remote egress.

Exit codes: 0 = no findings at/above --fail-on, 1 = findings, 2 = usage error.
"""

from __future__ import annotations

import argparse
import fnmatch
import ipaddress
import json
import re
import shlex
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable
from urllib.parse import urlparse

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

# The harness wraps the target in `timeout`; it is not part of the application.
HARNESS_EXECS = {"timeout"}

DEFAULT_DBUS_ALLOWED_DESTINATIONS = [
    "org.freedesktop.DBus",
    "org.freedesktop.login1",
    "com.github.kanata.Switcher",
    "com.github.kanata.Switcher.instances.audit",
    "com.github.kanata.Switcher.extensions.GNOME",
]

DEFAULT_DBUS_SENSITIVE_DESTINATIONS = [
    "org.freedesktop.portal.",
    "org.freedesktop.systemd1",
    "org.freedesktop.NetworkManager",
    "org.freedesktop.resolve1",
    "org.freedesktop.Avahi",
    "org.freedesktop.ModemManager1",
    "org.freedesktop.Telepathy",
    "org.freedesktop.Secret",
    "org.freedesktop.UDisks2",
    "org.freedesktop.UPower",
    "org.bluez",
    "org.gnome.OnlineAccounts",
    "org.gnome.evolution.",
    "org.kde.KWin",
    "org.kde.kwin.",
    "org.gnome.Shell",
    "org.gnome.Shell.Extensions",
]

DEFAULT_DBUS_SENSITIVE_METHODS = [
    "OpenURI",
    "Launch",
    "Spawn",
    "StartTransientUnit",
    "StartUnit",
    "StopUnit",
    "RestartUnit",
    "Reload",
    "PowerOff",
    "Reboot",
    "Suspend",
    "Hibernate",
    "HybridSleep",
    "SetLinkUp",
    "ActivateConnection",
    "AddAndActivateConnection",
    "ResolveHostname",
    "SetDNS",
    "SetDefaultRoute",
    "UpdateActivationEnvironment",
    "Eval",
    "Call",
]

DEFAULT_LOGIND_ALLOWED_METHODS = [
    "GetSession",
    "GetSessionByPID",
    "GetUser",
    "GetUserByPID",
    "Get",
    "GetAll",
]

URL_RE = re.compile(r"\b(?:https?|ftps?|sftp|ssh|ws|wss|telnet|gopher)://[^\s\"'<>]+", re.IGNORECASE)
DNS_QUESTION_RE = re.compile(r"\b(?:A|AAAA|HTTPS|CNAME|PTR|MX|TXT|SRV)\?\s+(?P<name>[A-Za-z0-9_.-]+)\.?")
SENDMMSG_RE = re.compile(r"\b(?P<call>sendmmsg|recvmmsg)\((?P<fd>\d+)")
SENDFILE_RE = re.compile(r"\b(?P<call>sendfile)\((?P<out>\d+),\s*(?P<in>\d+)")
SPLICE_RE = re.compile(r"\bsplice\((?P<in>\d+),[^,]*,\s*(?P<out>\d+)")

SOCKET_RE = re.compile(r"\bsocket\((?P<family>AF_[A-Z0-9_]+),\s*(?P<type>SOCK_[A-Z0-9_|]+)(?:,\s*(?P<proto>[A-Z0-9_]+))?\)\s*=\s*(?P<fd>-?\d+)")
SOCKETPAIR_RE = re.compile(r"\bsocketpair\((?P<family>AF_[A-Z0-9_]+),\s*(?P<type>SOCK_[A-Z0-9_|]+)(?:,\s*(?P<proto>[A-Z0-9_]+))?,\s*\[(?P<fds>[^\]]+)\]\)\s*=\s*(?P<ret>-?\d+)")
SEND_RE = re.compile(r"\b(?P<call>sendto|recvfrom|sendmsg|recvmsg)\((?P<fd>\d+),.*?(?P<sockaddr>\{sa_family=[^}]*\})")
CONNECT_RE = re.compile(r"\b(?P<call>connect|bind|sendto|recvfrom|accept4?|getpeername|getsockname)\((?P<fd>\d+),\s*(?P<sockaddr>\{[^}]*\})(?:,\s*(?P<len>\d+))?.*?\)\s*=\s*(?P<ret>-?\d+)(?:\s+(?P<errno>[A-Z][A-Z0-9_]+))?")
EXEC_RE = re.compile(r"\b(?:execve|execveat)\((?:(?:AT_FDCWD|\d+),\s*)?\"(?P<path>[^\"]+)\",\s*\[(?P<args>[^\]]*)\]")
OPEN_RE = re.compile(r"\b(?:open|openat|openat2)\((?:[^,]+,\s*)?\"(?P<path>[^\"]+)\"")
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
    pcap: list[dict[str, Any]] = field(default_factory=list)
    pcap_files: list[str] = field(default_factory=list)
    sinkhole_dns: list[dict[str, Any]] = field(default_factory=list)
    sinkhole_tcp: list[dict[str, Any]] = field(default_factory=list)
    sinkhole_files: list[str] = field(default_factory=list)
    dbus: list[dict[str, Any]] = field(default_factory=list)
    dbus_files: list[str] = field(default_factory=list)
    build: dict[str, Any] = field(default_factory=dict)
    gnome: dict[str, Any] = field(default_factory=dict)
    fd_families: dict[tuple[int | None, int], str] = field(default_factory=dict)
    fd_paths: dict[tuple[int | None, int], str] = field(default_factory=dict)
    memfd_fds: set[tuple[int | None, int]] = field(default_factory=set)
    thread_pids: set[int] = field(default_factory=set)
    findings: list[Finding] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)

    def add(self, rule: str, severity: str, detail: str, pid: int | None = None, file: str = "") -> None:
        self.findings.append(Finding(rule, severity, detail, pid, file))

    def as_dict(self) -> dict[str, Any]:
        build = dict(self.build)
        for key in ("fetch_events", "build_events"):
            build[key] = [
                event.__dict__ if isinstance(event, Event) else event
                for event in build.get(key, [])
            ]
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
            "pcap": self.pcap,
            "pcap_files": self.pcap_files,
            "sinkhole_dns": self.sinkhole_dns,
            "sinkhole_tcp": self.sinkhole_tcp,
            "sinkhole_files": self.sinkhole_files,
            "dbus": self.dbus,
            "dbus_files": self.dbus_files,
            "build": build,
            "gnome": self.gnome,
            "findings": [f.as_dict() for f in self.findings],
            "notes": self.notes,
        }


@dataclass
class EvidenceDirs:
    strace: Path
    pcap: Path
    sinkhole: Path
    dbus: Path
    build: Path
    gnome: Path
    snapshots: Path
    mock: Path

    @classmethod
    def default(cls, directory: Path) -> "EvidenceDirs":
        return cls(
            strace=directory / "strace",
            pcap=directory / "pcap",
            sinkhole=directory / "net",
            dbus=directory / "dbus",
            build=directory / "build",
            gnome=directory / "gnome-audit",
            snapshots=directory / "snapshots",
            mock=directory / "mock",
        )


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


def parse_strace_file(path: Path, report: Report, profile: str = "daemon") -> None:
    pid = parse_pid(path)
    try:
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError as exc:
        report.notes.append(f"could not read {path}: {exc}")
        return
    for line in lines:
        memfd_match = re.search(r'\bmemfd_create\("([^"]*)".*\)\s*=\s*(\d+)', line)
        if memfd_match:
            try:
                report.memfd_fds.add((pid, int(memfd_match.group(2))))
            except ValueError:
                pass
        execveat_match = re.search(r'\bexecveat\((AT_FDCWD|-?\d+),\s*"([^"]*)"', line)
        if execveat_match:
            fd_text, exec_path = execveat_match.group(1), execveat_match.group(2)
            from_memfd = exec_path.startswith("/proc/self/fd/")
            if not from_memfd and fd_text not in ("AT_FDCWD", ""):
                try:
                    from_memfd = (pid, int(fd_text)) in report.memfd_fds
                except ValueError:
                    from_memfd = False
            if from_memfd:
                report.add(
                    "DYN-MEMFD-EXEC", "critical",
                    f"execveat from anonymous/memfd file (fd={fd_text}, path={exec_path or '<empty>'})",
                    pid, path.name,
                )
        clone_match = re.search(r"\bclone3?\(.*\)\s*=\s*(\d+)", line)
        if clone_match and "CLONE_THREAD" in line:
            report.thread_pids.add(int(clone_match.group(1)))
        socket_match = SOCKET_RE.search(line)
        if socket_match:
            family = socket_match.group("family")
            fd_text = socket_match.group("fd")
            report.events.append(Event(
                kind="socket", family=family,
                sock_type=socket_match.group("type"), protocol=socket_match.group("proto") or "",
                result=fd_text, pid=pid, file=path.name, raw=line,
            ))
            try:
                fd = int(fd_text)
            except ValueError:
                fd = -1
            if fd >= 0:
                report.fd_families[(pid, fd)] = family
                report.fd_paths.pop((pid, fd), None)
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
            if call_match.group("call") == "bind" and family == "AF_UNIX" and unix_path:
                try:
                    report.fd_paths[(pid, int(call_match.group("fd")))] = unix_path
                except ValueError:
                    pass
        for send_match in SEND_RE.finditer(line):
            family, address, port, unix_path = parse_sockaddr(send_match.group("sockaddr"))
            report.events.append(Event(
                kind=send_match.group("call"), family=family, address=address, port=port,
                path=unix_path, result="", pid=pid, file=path.name, raw=line,
            ))
        listen_match = re.search(r"\blisten\((\d+),\s*(\d+)\)\s*=\s*(-?\d+)", line)
        if listen_match:
            try:
                listen_fd = int(listen_match.group(1))
            except ValueError:
                listen_fd = -1
            report.events.append(Event(
                kind="listen",
                family=report.fd_families.get((pid, listen_fd), ""),
                path=report.fd_paths.get((pid, listen_fd), ""),
                result=listen_match.group(3), pid=pid, file=path.name, raw=line,
            ))
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
            if name == "memfd_create" and profile == "gnome-extension":
                # Mutter, Mesa, GLib, PulseAudio and the Wayland cursor cache
                # legitimately create memfds for dmabuf/GL/anonymous data. The
                # extension runs inside gnome-shell, so a plain memfd_create is
                # not attributable to the extension. Executing from a memfd is
                # still caught above (DYN-MEMFD-EXEC).
                report.notes.append(f"GNOME Shell memfd_create: {line[:300]}")
            else:
                report.add("DYN-SUSPICIOUS-SYSCALL", severity, f"{name}: {description}", pid, path.name)
        if "io_uring_enter(" in line or "io_uring_register(" in line:
            report.suspicious.append({"pid": pid, "file": path.name, "call": "io_uring", "raw": line[:1000]})
            report.add("DYN-SUSPICIOUS-SYSCALL", "medium", "io_uring operation", pid, path.name)
        for mmsg in SENDMMSG_RE.finditer(line):
            try:
                fd = int(mmsg.group("fd"))
            except ValueError:
                continue
            family = report.fd_families.get((pid, fd), "")
            if family in ("AF_INET", "AF_INET6"):
                report.add("DYN-IP-SENDMMSG", "high", f"{mmsg.group('call')} on IP socket fd={fd} ({family})", pid, path.name)
        sendfile_match = SENDFILE_RE.search(line)
        if sendfile_match:
            out_fd = int(sendfile_match.group("out"))
            family = report.fd_families.get((pid, out_fd), "")
            if family in ("AF_INET", "AF_INET6"):
                report.add("DYN-IP-SENDFILE", "high", f"sendfile to IP socket fd={out_fd} ({family})", pid, path.name)
        splice_match = SPLICE_RE.search(line)
        if splice_match:
            for fd_text in (splice_match.group("in"), splice_match.group("out")):
                fd = int(fd_text)
                family = report.fd_families.get((pid, fd), "")
                if family in ("AF_INET", "AF_INET6"):
                    report.add("DYN-IP-SPLICE", "high", f"splice to/from IP socket fd={fd} ({family})", pid, path.name)


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
            if (mode == "gnome-extension" and event.family == "AF_UNIX"
                    and event.path and unix_allowed(event.path, unix_globs)):
                report.notes.append(f"expected GNOME Shell Unix listener: {event.path}")
            else:
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
                    if mode == "gnome-extension" and event.path and unix_allowed(event.path, unix_globs):
                        report.notes.append(f"expected GNOME Shell Unix listener: {event.path}")
                    else:
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


def analyze_execs(report: Report, baseline: dict[str, Any], profile: str = "daemon") -> None:
    key = "expected_exec_gnome" if profile == "gnome-extension" else "expected_exec"
    entries = baseline.get(key, [])
    allowed = {entry.get("command", "") for entry in entries if entry.get("command")}
    if profile == "gnome-extension":
        allowed.update({
            "gnome-shell", "gjs", "dbus-daemon", "dbus-monitor", "python3",
            "gsettings", "glib-compile-schemas", "gdbus", "bash", "sh", "env",
            "timeout", "strace", "cat", "grep", "sed", "head", "sort", "cp",
            "stat", "date", "sha256sum", "pgrep", "ss", "ip", "setpriv",
            "dconf-service", "gnome-shell-portal-helper", "ibus-*",
        })
    if profile == "command":
        command = str(report.meta.get("command") or "")
        try:
            tokens = shlex.split(command)
        except ValueError:
            tokens = command.split()
        if tokens:
            allowed.add(Path(tokens[0]).name)
    target = Path(str(report.meta.get("binary") or "")).name
    harness_command = str(report.meta.get("command") or "")
    for entry in report.execs:
        path = entry["path"]
        base = Path(path).name
        args = entry["args"]
        if base in HARNESS_EXECS:
            report.notes.append(f"harness wrapper exec: {path}")
            continue
        if profile == "command" and base in ("sh", "bash", "dash", "zsh", "ksh") \
                and harness_command and harness_command in args:
            # The harness runs `--command` through `bash -c`. That wrapper is
            # the operator's probe launcher, not a shell sink inside the target.
            report.notes.append(f"harness command wrapper exec: {path}")
            continue
        if target and base == target:
            report.notes.append(f"target binary exec: {path}")
            continue
        allowed_match = base in allowed or any(fnmatch.fnmatch(base, pattern) for pattern in allowed if "*" in pattern)
        if base in NETWORK_TOOLS:
            report.add("DYN-NETWORK-TOOL-EXEC", "high", f"executed network tool {path} {args[:200]}", entry["pid"], entry["file"])
        elif base in ("sh", "bash", "dash", "zsh", "ksh") and ("-c" in args or " -c " in args) and not allowed_match:
            report.add("DYN-SHELL-EXEC", "high", f"executed shell with -c: {path} {args[:200]}", entry["pid"], entry["file"])
        elif not allowed_match:
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


PCAP_LINE_RE = re.compile(
    r"^(?P<ts>\d{4}-\d\d-\d\d \d\d:\d\d:\d\d\.\d+)\s+"
    r"(?P<src_mac>[0-9a-fA-F:]{17}) > (?P<dst_mac>[0-9a-fA-F:]{17}), "
    r"ethertype (?P<ether>[^,(]+)(?: \(0x[0-9a-fA-F]+\))?, length \d+: (?P<body>.*)$"
)
PCAP_IP_PORT_RE = re.compile(
    r"(?P<src>[0-9a-fA-F:.]+)\.(?P<sport>\d+) > (?P<dst>[0-9a-fA-F:.]+)\.(?P<dport>\d+):"
)
PCAP_IP_ONLY_RE = re.compile(r"(?P<src>[0-9a-fA-F:.]+) > (?P<dst>[0-9a-fA-F:.]+):")
PCAP_FLAGS_RE = re.compile(r"Flags \[(?P<flags>[^\]]+)\]")
PCAP_ARP_TELL_RE = re.compile(r"\btell (?P<ip>\d+\.\d+\.\d+\.\d+)")

DBUS_HEADER_RE = re.compile(
    r"^(?P<kind>method call|method return|error|signal) time=(?P<time>[\d.]+) "
    r"sender=(?P<sender>\S+) -> destination=(?P<dest>\(null destination\)|\S+) "
    r"serial=(?P<serial>\d+) path=(?P<path>\S+); interface=(?P<iface>\S+); member=(?P<member>\S+)"
)

DBUS_SAFE_METHODS = {
    "Hello", "AddMatch", "RemoveMatch", "GetNameOwner", "NameHasOwner",
    "ListNames", "ListActivatableNames", "RequestName", "ReleaseName",
    "StartServiceByName", "GetConnectionUnixProcessID", "GetConnectionCredentials",
    "GetConnectionUnixUser", "GetId", "BecomeMonitor", "Get", "GetAll",
    "UpdateActivationEnvironment", "ReloadConfig",
    "Introspect", "GetStatus", "GetPaused", "Restart", "Pause", "Unpause",
    "GetFocus", "WindowFocus",
}


def load_jsonl(path: Path, report: Report) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    if not path.is_file():
        return records
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            value = json.loads(line)
        except json.JSONDecodeError:
            report.notes.append(f"unparseable JSONL line in {path}: {line[:160]}")
            continue
        if isinstance(value, dict):
            records.append(value)
    return records


def tcpdump_text(path: Path, report: Report) -> list[str]:
    try:
        result = subprocess.run(
            ["tcpdump", "-nn", "-tttt", "-e", "-v", "-r", str(path)],
            capture_output=True, text=True, timeout=120,
        )
    except FileNotFoundError:
        report.notes.append("tcpdump not found; pcap evidence cannot be parsed")
        return []
    except subprocess.TimeoutExpired:
        report.notes.append(f"tcpdump timed out reading {path}")
        return []
    if result.returncode != 0:
        report.notes.append(f"tcpdump could not read {path}: {result.stderr.strip()[:300]}")
        return []
    # With -v, tcpdump prints IP header details on the first line and the
    # transport line indented underneath. Join continuations so each record is
    # one line for the parser.
    lines: list[str] = []
    for line in result.stdout.splitlines():
        if not line.strip():
            continue
        if line.startswith((" ", "\t")) and lines:
            lines[-1] += " " + line.strip()
        else:
            lines.append(line)
    return lines


def parse_pcap_file(path: Path, report: Report) -> list[dict[str, Any]]:
    packets: list[dict[str, Any]] = []
    for line in tcpdump_text(path, report):
        match = PCAP_LINE_RE.match(line)
        if not match:
            continue
        body = match.group("body")
        ether = match.group("ether").strip()
        packet: dict[str, Any] = {
            "file": path.name, "src_mac": match.group("src_mac").lower(),
            "dst_mac": match.group("dst_mac").lower(), "ethertype": ether,
            "src_ip": "", "dst_ip": "", "sport": None, "dport": None,
            "protocol": "other", "flags": "", "dns_name": "", "raw": line[:1200],
        }
        if ether == "ARP" or "ARP" in body:
            packet["protocol"] = "arp"
            tell = PCAP_ARP_TELL_RE.search(body)
            if tell:
                packet["src_ip"] = tell.group("ip")
        elif "IPv6" in ether or "ICMP6" in body or "ICMPv6" in body:
            if "ICMP6" in body or "ICMPv6" in body or "neighbor solicitation" in body or "neighbor advertisement" in body:
                packet["protocol"] = "icmp6"
            port_match = PCAP_IP_PORT_RE.search(body)
            if port_match:
                packet.update({
                    "src_ip": port_match.group("src"), "dst_ip": port_match.group("dst"),
                    "sport": int(port_match.group("sport")), "dport": int(port_match.group("dport")),
                })
                if "UDP" in body:
                    packet["protocol"] = "udp"
                elif "TCP" in body or "Flags [" in body:
                    packet["protocol"] = "tcp"
            else:
                only = PCAP_IP_ONLY_RE.search(body)
                if only:
                    packet["src_ip"] = only.group("src")
                    packet["dst_ip"] = only.group("dst")
            flags = PCAP_FLAGS_RE.search(body)
            if flags:
                packet["flags"] = flags.group("flags")
            dns = DNS_QUESTION_RE.search(body)
            if dns:
                packet["dns_name"] = dns.group("name")
        elif "IPv4" in ether or "IP" in ether:
            if "ICMP" in body:
                packet["protocol"] = "icmp"
            port_match = PCAP_IP_PORT_RE.search(body)
            if port_match:
                packet.update({
                    "src_ip": port_match.group("src"), "dst_ip": port_match.group("dst"),
                    "sport": int(port_match.group("sport")), "dport": int(port_match.group("dport")),
                })
                if "UDP" in body:
                    packet["protocol"] = "udp"
                elif "TCP" in body or "Flags [" in body:
                    packet["protocol"] = "tcp"
            else:
                only = PCAP_IP_ONLY_RE.search(body)
                if only:
                    packet["src_ip"] = only.group("src")
                    packet["dst_ip"] = only.group("dst")
            flags = PCAP_FLAGS_RE.search(body)
            if flags:
                packet["flags"] = flags.group("flags")
            dns = DNS_QUESTION_RE.search(body)
            if dns:
                packet["dns_name"] = dns.group("name")
        packets.append(packet)
    report.pcap.extend(packets)
    if path.name not in report.pcap_files:
        report.pcap_files.append(path.name)
    return packets


def parse_pcap_dir(directory: Path, report: Report) -> None:
    if not directory.is_dir():
        return
    for path in sorted(directory.glob("*.pcap")):
        parse_pcap_file(path, report)


def analyze_pcap(report: Report, profile: str) -> None:
    privileged = bool(report.meta.get("privileged_capture"))
    files = set(report.pcap_files)
    if profile in ("daemon", "command"):
        if privileged and "daemon.pcap" not in files:
            report.add("DYN-PCAP-MISSING", "critical", "privileged packet capture is mandatory but daemon.pcap is missing")
    elif profile == "gnome-extension":
        if privileged and not files:
            report.add("DYN-PCAP-MISSING", "high", "GNOME Shell packet capture is missing")
    if report.meta.get("build_traced") and "build.pcap" not in files:
        report.add("DYN-BUILD-PCAP-MISSING", "high", "build tracing was enabled but build.pcap is missing")

    daemon_mac = str(report.meta.get("daemon_mac") or "").lower()
    daemon_ips = {
        str(report.meta.get("daemon_ip4") or ""),
        str(report.meta.get("daemon_ip6") or ""),
    } - {""}
    for packet in report.pcap:
        src_mac = str(packet.get("src_mac") or "").lower()
        src_ip = str(packet.get("src_ip") or "")
        outbound = bool(daemon_mac and src_mac == daemon_mac) or bool(src_ip and src_ip in daemon_ips)
        if not outbound:
            continue
        phase = "build" if packet.get("file") == "build.pcap" else "runtime"
        detail = (
            f"{packet.get('protocol')} {src_ip or src_mac} -> "
            f"{packet.get('dst_ip') or packet.get('dst_mac')}"
        )
        if packet.get("sport") is not None:
            detail += f":{packet['sport']}"
        if packet.get("dport") is not None:
            detail += f":{packet['dport']}"
        if packet.get("flags"):
            detail += f" flags={packet['flags']}"
        if phase == "build":
            report.add("DYN-BUILD-PCAP-EGRESS", "critical", f"build emitted a packet: {detail}")
            continue
        proto = str(packet.get("protocol"))
        if proto == "arp":
            report.add("DYN-PCAP-ARP", "medium", f"ARP request: {detail}")
        elif proto == "icmp6":
            report.add("DYN-PCAP-NDP", "medium", f"ICMPv6/NDP: {detail}")
        elif proto == "tcp":
            report.add("DYN-PCAP-TCP", "high", f"TCP egress: {detail}")
            if packet.get("dport") == 53:
                report.add("DYN-PCAP-DNS", "high", f"TCP DNS egress: {detail}")
        elif proto == "udp":
            report.add("DYN-PCAP-UDP", "high", f"UDP egress: {detail}")
            if packet.get("dport") == 53:
                report.add("DYN-PCAP-DNS", "high", f"UDP DNS egress: {detail}")
            if packet.get("dns_name"):
                report.add("DYN-PCAP-DNS-QUERY", "high", f"DNS query for {packet['dns_name']}: {detail}")
        elif proto in ("icmp",):
            report.add("DYN-PCAP-ICMP", "high", f"ICMP egress: {detail}")
        else:
            report.add("DYN-PCAP-NON-IP", "high", f"non-IP/unknown egress: {detail}")
    if not report.pcap:
        report.notes.append("pcap files contained no packets")
    else:
        report.notes.append(f"pcap packets parsed: {len(report.pcap)} from {len(report.pcap_files)} file(s)")


def parse_sinkhole(directory: Path, report: Report) -> None:
    for name, target in (("dns.jsonl", report.sinkhole_dns), ("tcp.jsonl", report.sinkhole_tcp)):
        path = directory / name
        if path.is_file():
            report.sinkhole_files.append(name)
            target.extend(load_jsonl(path, report))


def analyze_sinkhole(report: Report, profile: str) -> None:
    if profile in ("daemon", "command", "gnome-extension"):
        if "dns.jsonl" not in report.sinkhole_files:
            report.add("DYN-SINKHOLE-MISSING", "high", "DNS sinkhole log is missing (capture cannot prove DNS behavior)")
        if "tcp.jsonl" not in report.sinkhole_files:
            report.add("DYN-SINKHOLE-MISSING", "high", "TCP sinkhole log is missing (capture cannot prove TCP behavior)")
    for record in report.sinkhole_dns:
        if record.get("event") != "dns_query":
            continue
        report.add(
            "DYN-SINKHOLE-DNS", "high",
            f"DNS query {record.get('name', '?')} type={record.get('qtype', '?')} via {record.get('transport', '?')}",
        )
    for record in report.sinkhole_tcp:
        event = record.get("event")
        if event == "tcp_connect":
            report.add(
                "DYN-SINKHOLE-TCP", "high",
                f"TCP connection to sinkhole port {record.get('port')} from {record.get('peer')}",
            )
        elif event == "tcp_data" and int(record.get("bytes") or 0) > 0:
            preview = str(record.get("preview_text") or "").replace("\n", "\\n")[:160]
            report.add(
                "DYN-SINKHOLE-DATA", "critical",
                f"payload sent to sinkhole port {record.get('port')} ({record.get('bytes')} bytes): {preview}",
            )


def parse_dbus_dir(directory: Path, report: Report) -> None:
    if not directory.is_dir():
        return
    for path in sorted(directory.glob("*.log")):
        report.dbus_files.append(path.name)
        current: dict[str, Any] | None = None
        try:
            lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError as exc:
            report.notes.append(f"could not read {path}: {exc}")
            continue
        for line in lines:
            header = DBUS_HEADER_RE.match(line)
            if header:
                if current is not None:
                    report.dbus.append(current)
                destination = header.group("dest")
                if destination == "(null destination)":
                    destination = ""
                current = {
                    "file": path.name, "kind": header.group("kind"),
                    "sender": header.group("sender"), "destination": destination,
                    "path": header.group("path"), "interface": header.group("iface"),
                    "member": header.group("member"), "args": [],
                }
            elif current is not None and line.startswith((" ", "\t")):
                current["args"].extend(re.findall(r'"((?:[^"\\]|\\.)*)"', line))
        if current is not None:
            report.dbus.append(current)
        if not lines:
            report.notes.append(f"D-Bus monitor log is empty: {path}")


def analyze_dbus(report: Report, baseline: dict[str, Any], profile: str) -> None:
    policy = baseline.get("dynamic_policy", {}).get("dbus", {})
    allowed = set(DEFAULT_DBUS_ALLOWED_DESTINATIONS) | set(policy.get("allowed_destinations", []))
    sensitive = list(policy.get("sensitive_destinations", DEFAULT_DBUS_SENSITIVE_DESTINATIONS))
    sensitive_methods = set(policy.get("sensitive_methods", DEFAULT_DBUS_SENSITIVE_METHODS))
    read_only_methods = policy.get("read_only_methods", {})
    logind_allowed = set(policy.get("logind_allowed_methods", DEFAULT_LOGIND_ALLOWED_METHODS))
    gnome_allow = profile == "gnome-extension"

    files = set(report.dbus_files)
    if "session.monitor.log" not in files:
        report.add("DYN-DBUS-MONITOR-MISSING", "high", "private session bus monitor log is missing")
    system_state = str(report.meta.get("system_bus_monitor") or "")
    if system_state == "enabled" and "system.monitor.log" not in files:
        report.add("DYN-DBUS-MONITOR-MISSING", "high", "system bus monitor log is missing")
    elif system_state == "eavesdrop-fallback":
        report.add("DYN-DBUS-SYSTEM-EAVESDROP", "medium", "system bus monitor fell back to eavesdropping; coverage is incomplete")
    elif system_state == "unavailable-allowed":
        report.add("DYN-DBUS-SYSTEM-UNAVAILABLE", "info", "system bus monitor unavailable by explicit operator override")
    elif system_state == "absent":
        report.add("DYN-DBUS-SYSTEM-ABSENT", "info", "no system bus socket was present")

    for record in report.dbus:
        destination = str(record.get("destination") or "")
        iface = str(record.get("interface") or "")
        member = str(record.get("member") or "")
        args = [str(arg) for arg in record.get("args", [])]
        if not destination and record.get("kind") != "signal":
            continue
        if destination == "org.freedesktop.DBus":
            if member not in DBUS_SAFE_METHODS:
                report.add("DYN-DBUS-METHOD", "medium", f"unexpected org.freedesktop.DBus method {member}")
            continue
        urls = [arg for arg in args if URL_RE.search(arg)]
        sensitive_dest = any(destination == item or destination.startswith(item) for item in sensitive)
        logind = destination == "org.freedesktop.login1" or destination.startswith("org.freedesktop.login1.")
        if logind:
            if member in logind_allowed or iface == "org.freedesktop.DBus.Properties":
                report.notes.append(f"D-Bus logind read: {iface}.{member}")
            else:
                report.add("DYN-DBUS-LOGIND-METHOD", "high", f"logind method {iface}.{member}")
        elif sensitive_dest:
            if gnome_allow:
                report.notes.append(f"GNOME Shell/session D-Bus destination: {destination} {iface}.{member}")
            elif member in set(read_only_methods.get(destination, [])):
                report.notes.append(f"reviewed read-only D-Bus call: {destination} {iface}.{member}")
            else:
                report.add("DYN-DBUS-SENSITIVE-DEST", "high", f"method call to sensitive destination {destination} ({iface}.{member})")
        if member in sensitive_methods:
            report.add("DYN-DBUS-SENSITIVE-METHOD", "critical", f"sensitive D-Bus method {iface}.{member} on {destination}")
        if urls:
            if profile == "gnome-extension" and record.get("kind") != "method call":
                # Core Shell metadata (ExtensionStateChanged, ListExtensions
                # replies) contains project URLs. Only URLs the extension sends
                # outward in a method call are actionable.
                report.notes.append(
                    f"URL in GNOME Shell D-Bus {record.get('kind')} to {destination or '<broadcast>'}: {urls[0][:300]}"
                )
            else:
                report.add("DYN-DBUS-URL", "high", f"URL in D-Bus message to {destination or '<broadcast>'}: {urls[0][:300]}")
        if destination and not destination.startswith(":") and destination not in allowed:
            # A nested GNOME Shell activates many core services on its own; the
            # extension audit therefore records destinations without failing on
            # them, and relies on the sensitive-destination/method rules above.
            if gnome_allow:
                report.notes.append(f"GNOME Shell D-Bus destination: {destination} ({iface}.{member})")
            else:
                report.add("DYN-DBUS-UNEXPECTED-DEST", "medium", f"undocumented D-Bus destination {destination} ({iface}.{member})")
    report.notes.append(f"D-Bus messages parsed: {len(report.dbus)}")


def parse_build(directory: Path, report: Report, pcap_dir: Path | None = None) -> None:
    build: dict[str, Any] = {
        "fetch_events": [], "build_events": [], "fetch_urls": [], "build_urls": [],
        "pcap": [], "files": [],
    }
    for pattern, key in (("fetch.strace.*", "fetch_events"), ("build.strace.*", "build_events")):
        for path in sorted(directory.glob(pattern)):
            build["files"].append(path.name)
            temp = Report(directory=str(directory))
            parse_strace_file(path, temp, "build")
            build[key].extend(temp.events)
    for name, key in (("fetch.log", "fetch_urls"), ("build.log", "build_urls")):
        path = directory / name
        if path.is_file():
            text = path.read_text(encoding="utf-8", errors="replace")
            build[key].extend(URL_RE.findall(text))
    pcap = (pcap_dir or directory) / "build.pcap"
    if pcap.is_file():
        if pcap.name in report.pcap_files:
            build["pcap"] = [packet for packet in report.pcap if packet.get("file") == pcap.name]
        else:
            build["pcap"] = parse_pcap_file(pcap, report)
    report.build = build


def analyze_build(report: Report, baseline: dict[str, Any]) -> None:
    build = report.build
    if not report.meta.get("build_traced"):
        if build.get("files"):
            report.notes.append("build traces are present but build_traced is false")
        return
    if not any(str(name).startswith("fetch.strace.") for name in build.get("files", [])):
        report.add("DYN-BUILD-FETCH-TRACE-MISSING", "high", "build_traced is set but cargo fetch strace is missing")
    if not any(str(name).startswith("build.strace.") for name in build.get("files", [])):
        report.add("DYN-BUILD-TRACE-MISSING", "high", "build_traced is set but cargo build strace is missing")

    for event in build.get("fetch_events", []):
        family = getattr(event, "family", "")
        kind = getattr(event, "kind", "")
        if family in ("AF_INET", "AF_INET6"):
            if kind in ("connect", "sendto"):
                port = getattr(event, "port", None)
                if port in (80, 443):
                    report.notes.append(f"cargo fetch {kind} to allowed registry port {port}")
                elif port == 53:
                    report.notes.append("cargo fetch DNS lookup")
                else:
                    report.add("DYN-BUILD-FETCH-EGRESS", "high", f"cargo fetch {kind} to unexpected port {port}")
            elif kind in ("bind", "listen", "accept", "accept4"):
                report.add("DYN-BUILD-FETCH-LISTENER", "high", f"cargo fetch {kind} on {family}")

    allowed_hosts = set(baseline.get("build_time_network", {}).get("allowed_hosts", []))
    if not allowed_hosts:
        allowed_hosts = {
            "crates.io", "index.crates.io", "static.crates.io",
            "github.com", "codeload.github.com", "objects.githubusercontent.com",
        }
    for url in build.get("fetch_urls", []):
        host = urlparse(url).hostname or ""
        if host and host not in allowed_hosts:
            report.add("DYN-BUILD-FETCH-URL", "high", f"cargo fetch contacted undocumented host {host}: {url[:300]}")
    for url in build.get("build_urls", []):
        report.add("DYN-BUILD-SCRIPT-URL", "medium", f"build log contains a URL: {url[:300]}")

    for event in build.get("build_events", []):
        family = getattr(event, "family", "")
        kind = getattr(event, "kind", "")
        if family in ("AF_INET", "AF_INET6"):
            if kind in ("socket", "connect", "bind", "listen", "accept", "accept4", "sendto", "recvfrom"):
                report.add("DYN-BUILD-SCRIPT-EGRESS", "critical", f"offline build attempted {kind} on {family}")
            else:
                report.add("DYN-BUILD-SCRIPT-EGRESS", "critical", f"offline build used {family} ({kind})")
    if build.get("pcap"):
        report.notes.append(f"build pcap packets: {len(build['pcap'])}")


def parse_gnome(directory: Path, report: Report) -> None:
    gnome: dict[str, Any] = {"shell_log": "", "loaded": False, "errors": [], "focus": "", "extension_info": ""}
    candidate = directory / "shell.log"
    if candidate.is_file():
        gnome["shell_log"] = candidate.read_text(encoding="utf-8", errors="replace")
    text = gnome["shell_log"]
    gnome["loaded"] = "[KanataSwitcher] Extension enabled" in text
    gnome["errors"] = [
        line for line in text.splitlines()
        if ("JS ERROR" in line or "Gjs-CRITICAL" in line) and "KanataSwitcher" in line
    ]
    focus = directory / "focus.log"
    if focus.is_file():
        gnome["focus"] = focus.read_text(encoding="utf-8", errors="replace").strip()
    info = directory / "extension-info.txt"
    if info.is_file():
        gnome["extension_info"] = info.read_text(encoding="utf-8", errors="replace").strip()
    report.gnome = gnome


def analyze_gnome_mock(report: Report, directory: Path) -> None:
    path = directory / "mock.jsonl"
    records = load_jsonl(path, report) if path.is_file() else []
    report.gnome["mock_records"] = len(records)
    methods = {str(record.get("name")) for record in records if record.get("event") == "method"}
    signals = {str(record.get("name")) for record in records if record.get("event") == "signal"}
    report.gnome["mock_methods"] = sorted(methods)
    report.gnome["mock_signals"] = sorted(signals)
    if not path.is_file():
        report.add("DYN-GNOME-MOCK-MISSING", "high", "GNOME mock daemon log is missing")
        return
    for required in ("GetStatus", "GetPaused"):
        if required not in methods:
            report.add("DYN-GNOME-MOCK-METHOD", "high", f"the extension never called {required} on the mock daemon")
    for required in ("StatusChanged", "PausedChanged"):
        if required not in signals:
            report.add("DYN-GNOME-MOCK-SIGNAL", "medium", f"the mock daemon never emitted {required}")
    report.notes.append(f"GNOME mock methods: {sorted(methods)} signals: {sorted(signals)}")


def analyze_gnome(report: Report, profile: str) -> None:
    if profile != "gnome-extension":
        return
    gnome = report.gnome
    if not gnome.get("shell_log"):
        report.add("DYN-GNOME-SHELL-LOG-MISSING", "high", "nested GNOME Shell log is missing")
        return
    if not gnome.get("loaded"):
        report.add("DYN-GNOME-EXTENSION-NOT-LOADED", "high", "the extension did not log a successful enable")
    info = str(gnome.get("extension_info") or "")
    if info and "'enabled': <true>" not in info:
        report.add(
            "DYN-GNOME-EXTENSION-NOT-ENABLED",
            "high",
            f"the Shell reports the extension as not enabled: {info[:300]}",
        )
    elif not info:
        report.notes.append("extension-info.txt was not captured; Shell-reported enablement was not verified")
    for line in gnome.get("errors", []):
        report.add("DYN-GNOME-EXTENSION-ERROR", "high", f"extension error: {line[:300]}")
    if not gnome.get("focus"):
        report.add("DYN-GNOME-FOCUS-MISSING", "medium", "the extension did not answer GetFocus on its D-Bus interface")
    else:
        report.notes.append(f"extension GetFocus: {gnome['focus'][:200]}")


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


def load_inputs(directory: Path, report: Report, dirs: EvidenceDirs | None = None,
                profile: str | None = None) -> None:
    dirs = dirs or EvidenceDirs.default(directory)
    meta_path = directory / "meta.json"
    if meta_path.is_file():
        try:
            report.meta = json.loads(meta_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            report.notes.append(f"could not read meta.json: {exc}")
    trace_profile = profile or str(report.meta.get("profile") or report.meta.get("mode") or "daemon")
    strace_dir = dirs.strace
    if not strace_dir.is_dir():
        raise SystemExit(f"error: {strace_dir} does not exist")
    files = sorted(strace_dir.glob("daemon.*")) + sorted(strace_dir.glob("trace.*"))
    if not files:
        raise SystemExit(f"error: no strace logs in {strace_dir}")
    for path in files:
        parse_strace_file(path, report, trace_profile)
    if not report.meta.get("daemon_pid"):
        # The tracee started by strace has the lowest pid in the -ff output.
        # This fallback lets --command mode still distinguish a child connect.
        pids = sorted(pid for pid in (parse_pid(path) for path in files) if pid)
        if pids:
            report.meta["daemon_pid"] = pids[0]
    for path in sorted(dirs.snapshots.glob("ss-*.txt")):
        try:
            report.ss.extend(path.read_text(encoding="utf-8", errors="replace").splitlines())
        except OSError as exc:
            report.notes.append(f"could not read {path}: {exc}")
    for path in sorted(dirs.snapshots.glob("procnet-*")):
        parse_procnet_file(path, report, str(report.meta.get("expected_host", "127.0.0.1")), int(report.meta.get("expected_port", 10000)))
    parse_pcap_dir(dirs.pcap, report)
    parse_sinkhole(dirs.sinkhole, report)
    parse_dbus_dir(dirs.dbus, report)
    parse_build(dirs.build, report, dirs.pcap)
    parse_gnome(dirs.gnome, report)


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
    parser.add_argument("--profile", choices=["daemon", "command", "gnome-extension"], help="evidence profile (default: meta.json mode)")
    parser.add_argument("--strace-dir", type=Path, help="strace directory (default: <directory>/strace)")
    parser.add_argument("--pcap-dir", type=Path, help="pcap directory (default: <directory>/pcap)")
    parser.add_argument("--sinkhole-dir", type=Path, help="sinkhole log directory (default: <directory>/net)")
    parser.add_argument("--dbus-dir", type=Path, help="D-Bus monitor directory (default: <directory>/dbus)")
    parser.add_argument("--build-dir", type=Path, help="build trace directory (default: <directory>/build)")
    parser.add_argument("--gnome-dir", type=Path, help="GNOME evidence directory (default: <directory>/gnome-audit)")
    parser.add_argument("--snapshots-dir", type=Path, help="ss/procnet directory (default: <directory>/snapshots)")
    parser.add_argument("--mock-dir", type=Path, help="mock daemon directory (default: <directory>/mock)")
    parser.add_argument("--fail-on", choices=list(SEVERITY_ORDER), default=None, help="exit 1 at/above this severity (default: baseline expected_dynamic.fail_on or medium)")
    args = parser.parse_args(argv)

    directory = args.directory.resolve()
    report = Report(directory=str(directory))
    dirs = EvidenceDirs.default(directory)
    for name in ("strace", "pcap", "sinkhole", "dbus", "build", "gnome", "snapshots", "mock"):
        override = getattr(args, f"{name}_dir", None)
        if override is not None:
            setattr(dirs, name, override.resolve())
    try:
        load_inputs(directory, report, dirs, args.profile)
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
    profile = args.profile or str(report.meta.get("profile") or mode)
    if profile not in ("daemon", "command", "gnome-extension"):
        profile = "daemon"
    dynamic = baseline.get("expected_dynamic", {})
    expected_min = int(dynamic.get("expected_connect_min", 1))
    expected_max_raw = dynamic.get("expected_connect_max")
    expected_max = int(expected_max_raw) if expected_max_raw is not None else None
    if profile == "daemon":
        analyze_mock(report, dirs.mock / "kanata.log", expected_min, expected_max)
    analyze_events(report, host, port, globs, profile)
    analyze_execs(report, baseline, profile)
    analyze_ss(report, host, port)
    analyze_pcap(report, profile)
    analyze_sinkhole(report, profile)
    analyze_dbus(report, baseline, profile)
    analyze_build(report, baseline)
    analyze_gnome(report, profile)
    if profile == "gnome-extension":
        analyze_gnome_mock(report, dirs.mock)
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
