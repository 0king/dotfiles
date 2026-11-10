#!/usr/bin/env python3
"""Static threat and network audit for the kanata-tray repository.

This scanner is intentionally dependency-free (Python 3 stdlib only).  It does
not execute the target repository.  Its job is recall: enumerate network sinks,
process-execution sinks, supply-chain signals, and obvious malware patterns,
then compare the result with the skill's pinned baseline.  A human/agent must
triage every finding in context.

Usage:
    python3 scan_kanata_tray.py /path/to/kanata-tray
    python3 scan_kanata_tray.py /path/to/kanata-tray --json /tmp/out.json --verbose
    python3 scan_kanata_tray.py /path/to/kanata-tray --include-deps
    python3 scan_kanata_tray.py /path/to/kanata-tray --fail-on high
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import urllib.parse
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Iterable, Optional

SCANNER_VERSION = "1.0.0"

SKIP_DIRS = {
    ".git",
    ".hg",
    ".svn",
    "__pycache__",
    ".idea",
    ".vscode-test",
    "node_modules",
    "dist",
    "build",
    "target",
    "out",
    "bin",
    "obj",
}

TEXT_EXTENSIONS = {
    ".go",
    ".mod",
    ".sum",
    ".nix",
    ".lock",
    ".toml",
    ".json",
    ".yml",
    ".yaml",
    ".sh",
    ".bash",
    ".zsh",
    ".fish",
    ".ps1",
    ".bat",
    ".cmd",
    ".py",
    ".js",
    ".ts",
    ".just",
    ".mk",
    ".service",
    ".desktop",
    ".plist",
    ".md",
    ".txt",
    "",
}

IMAGE_EXTENSIONS = {".png", ".ico", ".jpg", ".jpeg", ".gif", ".webp", ".bmp", ".svg", ".icns"}

BINARY_EXTENSIONS = {
    ".exe",
    ".dll",
    ".so",
    ".dylib",
    ".wasm",
    ".class",
    ".jar",
    ".o",
    ".a",
    ".lib",
    ".bin",
    ".dat",
    ".node",
    ".msi",
    ".deb",
    ".rpm",
    ".apk",
    ".dmg",
    ".iso",
}

LOCAL_HOSTS = {
    "localhost",
    "127.0.0.1",
    "::1",
    "0:0:0:0:0:0:0:1",
    "[::1]",
}

URL_SCHEME_RE = re.compile(r"\b([a-zA-Z][a-zA-Z0-9+.-]*://[^\s\"'`<>]+)")
IP_PORT_RE = re.compile(r"\b((?:\d{1,3}\.){3}\d{1,3})(?::(\d{1,5}))?\b")

# Security-defence list.  Any hit is a review prompt, not a verdict.
SUSPICIOUS_DEP_RE = re.compile(
    r"(telemetry|analytics|sentry|datadog|newrelic|bugsnag|rollbar|posthog|"
    r"segment|mixpanel|amplitude|hotjar|fullstory|logrocket|smartlook|"
    r"http-client|resty|reqwest|websocket|gorilla/websocket|grpc|"
    r"ssh|ftp|smtp|dns|resolver|tor|onion|proxy|tunnel|tcp|udp)",
    re.IGNORECASE,
)

SECRET_PATTERNS = [
    ("PEM private key", re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----")),
    ("AWS access key", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("GitHub token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{20,}\b")),
    ("Slack token", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b")),
    ("Stripe live key", re.compile(r"\bsk_live_[0-9A-Za-z]{20,}\b")),
    ("Google API key", re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b")),
]

PERSISTENCE_PATTERNS = [
    ("cron", re.compile(r"(?:/etc/cron|crontab\s+-|cron\.d)", re.IGNORECASE)),
    ("systemd user unit", re.compile(r"(?:systemctl\s+--user|~?/?\.config/systemd/user|/etc/systemd/system)", re.IGNORECASE)),
    ("desktop autostart", re.compile(r"(?:\.config/autostart|/etc/xdg/autostart)", re.IGNORECASE)),
    ("macOS LaunchAgent", re.compile(r"(?:Library/LaunchAgents|Library/LaunchDaemons|launchctl\s+load)", re.IGNORECASE)),
    ("Windows Run key", re.compile(r"(?:CurrentVersion\\\\Run|reg\s+add[^\n]*Run|schtasks\s+/create)", re.IGNORECASE)),
    ("shell rc file", re.compile(r"(?:\.bashrc|\.bash_profile|\.zshrc|\.zprofile|\.profile|\.config/fish/config\.fish)", re.IGNORECASE)),
    ("SSH authorized_keys", re.compile(r"(?:authorized_keys|\.ssh/config)", re.IGNORECASE)),
    ("LD_PRELOAD", re.compile(r"\bLD_PRELOAD\b|/etc/ld\.so\.preload")),
]

SHELL_NAMES = {"sh", "bash", "zsh", "dash", "ksh", "fish", "cmd", "cmd.exe", "powershell", "powershell.exe", "pwsh"}
OPENER_NAMES = {"open", "xdg-open", "rundll32", "rundll32.exe", "start"}

FORBIDDEN_BIDI = re.compile(r"[\u202a-\u202e\u2066-\u2069]")


@dataclass
class Finding:
    rule: str
    severity: str
    file: str
    line: int
    message: str
    evidence: str = ""
    category: str = "threat"
    confidence: str = "medium"


@dataclass
class NetworkSink:
    file: str
    line: int
    symbol: str
    direction: str
    api: str
    protocol: str
    transport: str
    endpoint: str
    endpoint_class: str
    tls: bool
    gate: str
    evidence: str


@dataclass
class ExecSink:
    file: str
    line: int
    symbol: str
    api: str
    command: str
    command_class: str
    evidence: str


@dataclass
class AssetInfo:
    file: str
    size: int
    detected_type: str
    extension: str
    trailing_bytes: int
    embedded_signatures: list[str] = field(default_factory=list)
    urls: list[str] = field(default_factory=list)
    finding: str = ""


@dataclass
class AuditResult:
    scanner_version: str
    repo: str
    git_head: str = ""
    git_dirty: bool = False
    git_remote: str = ""
    files_scanned: int = 0
    network_sinks: list[NetworkSink] = field(default_factory=list)
    exec_sinks: list[ExecSink] = field(default_factory=list)
    remote_hosts: list[dict] = field(default_factory=list)
    direct_modules: list[str] = field(default_factory=list)
    replace_directives: list[str] = field(default_factory=list)
    workflows: list[dict] = field(default_factory=list)
    assets: list[AssetInfo] = field(default_factory=list)
    baseline_matched: list[str] = field(default_factory=list)
    baseline_missing: list[str] = field(default_factory=list)
    baseline_unexpected: list[str] = field(default_factory=list)
    baseline_changed: list[str] = field(default_factory=list)
    baseline_exec_matched: list[str] = field(default_factory=list)
    baseline_exec_missing: list[str] = field(default_factory=list)
    baseline_exec_unexpected: list[str] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)

    def add(self, finding: Finding) -> None:
        self.findings.append(finding)


# ---------------------------------------------------------------------------
# Generic helpers


def read_text(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    try:
        with path.open("rb") as fh:
            for chunk in iter(lambda: fh.read(1024 * 1024), b""):
                h.update(chunk)
    except OSError:
        return ""
    return h.hexdigest()


def rel(path: Path, root: Path) -> str:
    try:
        return path.relative_to(root).as_posix()
    except ValueError:
        return path.as_posix()


def strip_go_comments_line(line: str, in_block: bool) -> tuple[str, bool]:
    """Remove Go comments while preserving strings and line length roughly."""
    out: list[str] = []
    i = 0
    quote: Optional[str] = None
    escaped = False
    while i < len(line):
        ch = line[i]
        if in_block:
            if ch == "*" and i + 1 < len(line) and line[i + 1] == "/":
                in_block = False
                i += 2
                continue
            i += 1
            continue
        if quote is not None:
            out.append(ch)
            if escaped:
                escaped = False
            elif ch == "\\" and quote != "`":
                escaped = True
            elif ch == quote:
                quote = None
            i += 1
            continue
        if ch in ('"', "'", "`"):
            quote = ch
            out.append(ch)
            i += 1
            continue
        if ch == "/" and i + 1 < len(line) and line[i + 1] == "/":
            break
        if ch == "/" and i + 1 < len(line) and line[i + 1] == "*":
            in_block = True
            i += 2
            continue
        out.append(ch)
        i += 1
    return "".join(out), in_block


def go_strings(text: str) -> list[str]:
    values: list[str] = []
    for m in re.finditer(r'"((?:\\.|[^"\\])*)"', text):
        raw = m.group(1)
        try:
            values.append(json.loads('"' + raw + '"'))
        except json.JSONDecodeError:
            values.append(raw)
    for m in re.finditer(r"`([^`]*)`", text):
        values.append(m.group(1))
    return values


def go_code_without_comments(lines: list[str]) -> list[str]:
    out: list[str] = []
    in_block = False
    for line in lines:
        stripped, in_block = strip_go_comments_line(line, in_block)
        out.append(stripped)
    return out


def find_call(lines: list[str], start: int, column: int) -> tuple[str, int]:
    """Return a call expression starting at column on line `start`."""
    chunk: list[str] = []
    depth = 0
    started = False
    end = start
    for idx in range(start, min(len(lines), start + 40)):
        line = lines[idx]
        begin = column if idx == start else 0
        chunk.append(line[begin:])
        for ch in line[begin:]:
            if ch == "(":
                depth += 1
                started = True
            elif ch == ")":
                depth -= 1
        end = idx
        if started and depth <= 0:
            break
    return " ".join(chunk), end


def split_top_level_args(expr: str) -> list[str]:
    start = expr.find("(")
    if start == -1:
        return []
    depth = 0
    quote: Optional[str] = None
    escaped = False
    args: list[str] = []
    current: list[str] = []
    for ch in expr[start + 1 :]:
        if quote is not None:
            current.append(ch)
            if escaped:
                escaped = False
            elif ch == "\\" and quote != "`":
                escaped = True
            elif ch == quote:
                quote = None
            continue
        if ch in ('"', "'", "`"):
            quote = ch
            current.append(ch)
            continue
        if ch in "([{":
            depth += 1
            current.append(ch)
            continue
        if ch in ")]}":
            if ch == ")" and depth == 0:
                args.append("".join(current).strip())
                return [a for a in args if a]
            depth -= 1
            current.append(ch)
            continue
        if ch == "," and depth == 0:
            args.append("".join(current).strip())
            current = []
            continue
        current.append(ch)
    if current:
        args.append("".join(current).strip())
    return [a for a in args if a]


def unquote_go(expr: str) -> Optional[str]:
    expr = expr.strip()
    if expr.startswith("`") and expr.endswith("`"):
        return expr[1:-1]
    strings = go_strings(expr)
    if strings:
        return strings[0]
    return None


def infer_format_string(expr: str) -> Optional[str]:
    m = re.search(r"fmt\.Sprintf\(\s*(\"(?:\\.|[^\"\\])*\"|`[^`]*`)", expr)
    if not m:
        return None
    return unquote_go(m.group(1))


def endpoint_display(expr: str) -> str:
    expr = expr.strip()
    fmt = infer_format_string(expr)
    if fmt:
        return fmt.replace("%d", "<dynamic>").replace("%s", "<dynamic>").replace("%v", "<dynamic>")
    literal = unquote_go(expr)
    if literal is not None:
        return literal
    if "net.JoinHostPort" in expr:
        return "<net.JoinHostPort>"
    # Keep a short, readable expression instead of a huge call.
    compact = re.sub(r"\s+", " ", expr)
    return compact[:120]


def classify_endpoint(expr: str, direction: str) -> tuple[str, str]:
    """Return (display, class) where class is loopback/all-interfaces/remote/unix/unknown."""
    display = endpoint_display(expr)
    low = display.lower()
    raw = expr.lower()

    if not display:
        return ("<all-interfaces>" if direction == "inbound" else "<unspecified>",
                "all-interfaces" if direction == "inbound" else "unknown")

    if "unix" in raw or display.startswith("/") or display.endswith(".sock"):
        return display, "unix"
    if "0.0.0.0" in low or "[::]" in low or low.startswith(":") or low.startswith("*:"):
        return display, "all-interfaces"
    if "localhost" in low or "127.0.0.1" in low or "::1" in low:
        return display, "loopback"

    # URL form.
    if "://" in display:
        try:
            parsed = urllib.parse.urlsplit(display)
        except ValueError:
            return display, "unknown"
        host = (parsed.hostname or "").lower()
        if host in {"localhost", "127.0.0.1", "::1"}:
            return display, "loopback"
        if host in {"0.0.0.0", "::", ""}:
            return display, "all-interfaces"
        return display, "remote"

    # host:port form.
    m = re.match(r"^\[?([^\]/:]+)\]?:(\d+|<dynamic>)?$", display)
    if m:
        host = m.group(1).lower()
        if host in {"localhost", "127.0.0.1", "::1"}:
            return display, "loopback"
        if host in {"0.0.0.0", "::", ""}:
            return display, "all-interfaces"
        return display, "remote"

    if display in LOCAL_HOSTS:
        return display, "loopback"
    if IP_PORT_RE.fullmatch(display):
        ip = IP_PORT_RE.fullmatch(display).group(1)  # type: ignore[union-attr]
        return display, "loopback" if ip.startswith("127.") else "remote"
    return display, "unknown"


def transport_from_network_arg(expr: str) -> str:
    value = (unquote_go(expr) or expr).lower()
    if value.startswith("tcp"):
        return "tcp"
    if value.startswith("udp"):
        return "udp"
    if value.startswith("unix"):
        return "unix"
    if value.startswith("ip"):
        return "ip"
    return "unknown"


def function_context(code_lines: list[str]) -> list[str]:
    current = "<package>"
    result: list[str] = []
    for line in code_lines:
        m = re.match(r"^func\s+(?:\([^)]*\)\s*)?([A-Za-z_]\w*)\s*\(", line)
        if m:
            current = m.group(1)
        result.append(current)
    return result


def go_build_tags(lines: list[str]) -> str:
    tags: list[str] = []
    for line in lines[:12]:
        m = re.match(r"\s*//go:build\s+(.+)", line)
        if m:
            tags.append(m.group(1).strip())
        m = re.match(r"\s*//\s*\+build\s+(.+)", line)
        if m:
            tags.append(m.group(1).strip())
    return "; ".join(tags)


def parse_imports(lines: list[str]) -> set[str]:
    imports: set[str] = set()
    in_block = False
    for line in lines:
        stripped = line.strip()
        if not in_block and stripped.startswith("import ("):
            in_block = True
            continue
        if in_block:
            if stripped.startswith(")"):
                in_block = False
                continue
            m = re.match(r'(?:[A-Za-z_.]+\s+)?"([^"]+)"', stripped)
            if m:
                imports.add(m.group(1))
            continue
        m = re.match(r'import\s+(?:[A-Za-z_.]+\s+)?"([^"]+)"', stripped)
        if m:
            imports.add(m.group(1))
    return imports


def detect_asset_type(data: bytes) -> str:
    if data.startswith(b"\x89PNG\r\n\x1a\n"):
        return "png"
    if data.startswith(b"\x00\x00\x01\x00"):
        return "ico"
    if data.startswith(b"\xff\xd8\xff"):
        return "jpeg"
    if data.startswith(b"GIF87a") or data.startswith(b"GIF89a"):
        return "gif"
    if data.startswith(b"RIFF") and b"WEBP" in data[:16]:
        return "webp"
    if data.startswith(b"BM"):
        return "bmp"
    if data.startswith(b"icns"):
        return "icns"
    if data.startswith(b"\x7fELF"):
        return "elf"
    if data.startswith(b"MZ"):
        return "pe"
    if data.startswith(b"\xcf\xfa\xed\xfe") or data.startswith(b"\xce\xfa\xed\xfe") or data.startswith(b"\xca\xfe\xba\xbe"):
        return "macho"
    if data.startswith(b"PK\x03\x04"):
        return "zip"
    if data.startswith(b"\x1f\x8b"):
        return "gzip"
    if data.startswith(b"#!/"):
        return "script"
    if data.startswith(b"<svg") or b"<svg" in data[:512].lower():
        return "svg"
    return "unknown"


def trailing_image_bytes(data: bytes, kind: str) -> int:
    if kind == "png":
        idx = data.rfind(b"IEND")
        return max(0, len(data) - (idx + 8)) if idx != -1 else 0
    if kind == "jpeg":
        idx = data.rfind(b"\xff\xd9")
        return max(0, len(data) - (idx + 2)) if idx != -1 else 0
    if kind == "gif":
        idx = data.rfind(b"\x3b")
        return max(0, len(data) - (idx + 1)) if idx != -1 else 0
    if kind == "ico":
        if len(data) < 6:
            return 0
        count = int.from_bytes(data[4:6], "little")
        end = 6 + count * 16
        for i in range(count):
            entry = 6 + i * 16
            if entry + 16 > len(data):
                break
            size = int.from_bytes(data[entry + 8 : entry + 12], "little")
            offset = int.from_bytes(data[entry + 12 : entry + 16], "little")
            end = max(end, offset + size)
        return max(0, len(data) - end)
    return 0


# ---------------------------------------------------------------------------
# Go source scanning


def scan_go_file(path: Path, root: Path, result: AuditResult) -> None:
    text = read_text(path)
    lines = text.splitlines()
    code_lines = go_code_without_comments(lines)
    symbols = function_context(code_lines)
    tags = go_build_tags(lines)
    imports = parse_imports(lines)
    has_http = "net/http" in imports
    has_net = "net" in imports
    has_tls = "crypto/tls" in imports
    has_exec = "os/exec" in imports
    has_syscall = "syscall" in imports
    has_open = "github.com/skratchdot/open-golang/open" in imports

    file_rel = rel(path, root)
    seen_network: set[tuple[int, str]] = set()
    server_addrs: dict[str, tuple[str, int, str]] = {}
    http_servers: list[tuple[str, str, int, str]] = []

    for i, line in enumerate(code_lines):
        symbol = symbols[i]
        original = lines[i].rstrip()

        # Record http.Server{Addr: ...} so a later srv.ListenAndServe()
        # inherits the bind address.
        if has_http and "http.Server{" in line:
            var_match = re.search(r"(\w+)\s*:?=\s*&?\s*http\.Server\s*\{", line)
            var_name = var_match.group(1) if var_match else "<anonymous>"
            addr_expr = ""
            for j in range(i, min(len(code_lines), i + 25)):
                m = re.search(r"Addr:\s*([^,\n]+)", code_lines[j])
                if m:
                    addr_expr = m.group(1).strip()
                    break
            if addr_expr:
                server_addrs[var_name] = (addr_expr, i + 1, original)
            else:
                http_servers.append((var_name, "", i + 1, original))

        # Inbound HTTP: direct http.ListenAndServe / ListenAndServeTLS.
        if has_http:
            m = re.search(r"\bhttp\.(ListenAndServeTLS|ListenAndServe)\s*\(", line)
            if m:
                call, _ = find_call(code_lines, i, m.start())
                args = split_top_level_args(call)
                addr = args[0] if args else ""
                endpoint, cls = classify_endpoint(addr, "inbound")
                sink = NetworkSink(
                    file=file_rel,
                    line=i + 1,
                    symbol=symbol,
                    direction="inbound",
                    api="http." + m.group(1),
                    protocol="https" if m.group(1).endswith("TLS") else "http",
                    transport="tcp",
                    endpoint=endpoint,
                    endpoint_class=cls,
                    tls=m.group(1).endswith("TLS"),
                    gate=("build tag: " + tags) if tags else "",
                    evidence=original,
                )
                result.network_sinks.append(sink)
                seen_network.add((i + 1, sink.api))

            # Server.ListenAndServe on a tracked *http.Server.
            m = re.search(r"\b(\w+)\.(ListenAndServeTLS|ListenAndServe)\s*\(", line)
            if m and m.group(1) in server_addrs:
                addr_expr, addr_line, addr_evidence = server_addrs[m.group(1)]
                endpoint, cls = classify_endpoint(addr_expr, "inbound")
                sink = NetworkSink(
                    file=file_rel,
                    line=i + 1,
                    symbol=symbol,
                    direction="inbound",
                    api="http.Server." + m.group(2),
                    protocol="https" if m.group(2).endswith("TLS") else "http",
                    transport="tcp",
                    endpoint=endpoint,
                    endpoint_class=cls,
                    tls=m.group(2).endswith("TLS"),
                    gate=("build tag: " + tags) if tags else "",
                    evidence=original + " | Addr: " + addr_evidence.strip(),
                )
                result.network_sinks.append(sink)
                seen_network.add((i + 1, sink.api))

            # Outbound HTTP helpers.
            m = re.search(r"\bhttp\.(Get|Post|PostForm|Head)\s*\(", line)
            if m:
                call, _ = find_call(code_lines, i, m.start())
                args = split_top_level_args(call)
                url = args[0] if args else ""
                endpoint, cls = classify_endpoint(url, "outbound")
                result.network_sinks.append(
                    NetworkSink(
                        file=file_rel,
                        line=i + 1,
                        symbol=symbol,
                        direction="outbound",
                        api="http." + m.group(1),
                        protocol="https" if endpoint.lower().startswith("https://") else "http",
                        transport="tcp",
                        endpoint=endpoint,
                        endpoint_class=cls,
                        tls=endpoint.lower().startswith("https://"),
                        gate="",
                        evidence=original,
                    )
                )

            m = re.search(r"\bhttp\.NewRequest(?:WithContext)?\s*\(", line)
            if m:
                call, _ = find_call(code_lines, i, m.start())
                args = split_top_level_args(call)
                url = args[1] if len(args) > 1 else ""
                endpoint, cls = classify_endpoint(url, "outbound")
                result.network_sinks.append(
                    NetworkSink(
                        file=file_rel,
                        line=i + 1,
                        symbol=symbol,
                        direction="outbound",
                        api="http.NewRequest",
                        protocol="https" if endpoint.lower().startswith("https://") else "http",
                        transport="tcp",
                        endpoint=endpoint,
                        endpoint_class=cls,
                        tls=endpoint.lower().startswith("https://"),
                        gate="",
                        evidence=original,
                    )
                )

            # Client.Do with a request built elsewhere.
            if re.search(r"\b(?:http\.DefaultClient|\w+)\.Do\s*\(", line) and (
                "http.DefaultClient" in line or "http.Client" in text
            ):
                result.network_sinks.append(
                    NetworkSink(
                        file=file_rel,
                        line=i + 1,
                        symbol=symbol,
                        direction="outbound",
                        api="http.Client.Do",
                        protocol="http",
                        transport="tcp",
                        endpoint="<request object>",
                        endpoint_class="unknown",
                        tls=False,
                        gate="",
                        evidence=original,
                    )
                )

            if re.search(r"\bhttp\.(?:DefaultClient|Client)\b", line) and ".Do(" not in line:
                # A client alone is not a request; record a note so a manual
                # reviewer follows the request target.
                result.notes.append(f"{file_rel}:{i + 1}: http.Client constructed; verify request target manually")

        # Inbound raw net listeners.
        if has_net:
            m = re.search(r"\bnet\.(ListenMulticastUDP|ListenPacket|ListenTCP|ListenUDP|ListenUnix|Listen)\s*\(", line)
            if m:
                call, _ = find_call(code_lines, i, m.start())
                args = split_top_level_args(call)
                network = args[0] if args else ""
                addr = args[1] if len(args) > 1 else ""
                transport = transport_from_network_arg(network)
                endpoint, cls = classify_endpoint(addr, "inbound")
                result.network_sinks.append(
                    NetworkSink(
                        file=file_rel,
                        line=i + 1,
                        symbol=symbol,
                        direction="inbound",
                        api="net." + m.group(1),
                        protocol=transport,
                        transport=transport,
                        endpoint=endpoint,
                        endpoint_class=cls,
                        tls=False,
                        gate=("build tag: " + tags) if tags else "",
                        evidence=original,
                    )
                )

            # Outbound raw net dials.
            m = re.search(r"\bnet\.(DialContext|DialTimeout|DialTCP|DialUDP|DialUnix|DialIP|Dial)\s*\(", line)
            if m:
                call, _ = find_call(code_lines, i, m.start())
                args = split_top_level_args(call)
                if m.group(1) == "DialContext":
                    network = args[1] if len(args) > 1 else ""
                    addr = args[2] if len(args) > 2 else ""
                else:
                    network = args[0] if args else ""
                    addr = args[1] if len(args) > 1 else ""
                transport = transport_from_network_arg(network)
                endpoint, cls = classify_endpoint(addr, "outbound")
                result.network_sinks.append(
                    NetworkSink(
                        file=file_rel,
                        line=i + 1,
                        symbol=symbol,
                        direction="outbound",
                        api="net." + m.group(1),
                        protocol=transport,
                        transport=transport,
                        endpoint=endpoint,
                        endpoint_class=cls,
                        tls=False,
                        gate=("build tag: " + tags) if tags else "",
                        evidence=original,
                    )
                )

            # Dialer methods: (&net.Dialer{...}).DialContext(...) does not
            # contain the literal "net.DialContext", so catch the method form
            # whenever this file constructs a net.Dialer.
            if "net.Dialer" in text:
                m = re.search(r"\)\.(DialContext|Dial)\s*\(", line)
                if m:
                    call, _ = find_call(code_lines, i, m.start())
                    args = split_top_level_args(call)
                    if m.group(1) == "DialContext":
                        network = args[1] if len(args) > 1 else ""
                        addr = args[2] if len(args) > 2 else ""
                    else:
                        network = args[0] if args else ""
                        addr = args[1] if len(args) > 1 else ""
                    transport = transport_from_network_arg(network)
                    endpoint, cls = classify_endpoint(addr, "outbound")
                    result.network_sinks.append(
                        NetworkSink(
                            file=file_rel,
                            line=i + 1,
                            symbol=symbol,
                            direction="outbound",
                            api="net.Dialer." + m.group(1),
                            protocol=transport,
                            transport=transport,
                            endpoint=endpoint,
                            endpoint_class=cls,
                            tls=False,
                            gate=("build tag: " + tags) if tags else "",
                            evidence=original,
                        )
                    )

            m = re.search(r"\bnet\.(LookupHost|LookupIP|LookupAddr|LookupCNAME|LookupMX|LookupNS|LookupSRV|LookupTXT|ResolveIPAddr|ResolveTCPAddr|ResolveUDPAddr|ResolveUnixAddr)\s*\(", line)
            if m:
                call, _ = find_call(code_lines, i, m.start())
                args = split_top_level_args(call)
                addr = args[-1] if args else ""
                endpoint, cls = classify_endpoint(addr, "outbound")
                result.network_sinks.append(
                    NetworkSink(
                        file=file_rel,
                        line=i + 1,
                        symbol=symbol,
                        direction="outbound",
                        api="net." + m.group(1),
                        protocol="dns",
                        transport="udp/tcp",
                        endpoint=endpoint,
                        endpoint_class=cls,
                        tls=False,
                        gate="",
                        evidence=original,
                    )
                )

        # TLS, websocket, grpc, SMTP, SSH, FTP.
        if has_tls:
            m = re.search(r"\btls\.(Dial|DialWithDialer|Listen|Client|Server)\s*\(", line)
            if m:
                call, _ = find_call(code_lines, i, m.start())
                args = split_top_level_args(call)
                network = args[0] if args else ""
                addr = args[1] if len(args) > 1 else ""
                transport = transport_from_network_arg(network)
                endpoint, cls = classify_endpoint(addr, "outbound" if m.group(1).startswith("Dial") else "inbound")
                result.network_sinks.append(
                    NetworkSink(
                        file=file_rel,
                        line=i + 1,
                        symbol=symbol,
                        direction="outbound" if m.group(1).startswith("Dial") else "inbound",
                        api="tls." + m.group(1),
                        protocol="tls",
                        transport=transport,
                        endpoint=endpoint,
                        endpoint_class=cls,
                        tls=True,
                        gate="",
                        evidence=original,
                    )
                )

        for pkg, pattern, proto in [
            ("websocket", r"\b(?:websocket|ws)\.(?:Dial|Dialer|DefaultDialer)\b", "websocket"),
            ("grpc", r"\bgrpc\.(?:Dial|DialContext|NewClient|NewServer)\b", "grpc"),
            ("smtp", r"\bsmtp\.SendMail\s*\(", "smtp"),
            ("ssh", r"\bssh\.Dial\s*\(", "ssh"),
            ("ftp", r"\bftp\.Dial\s*\(", "ftp"),
        ]:
            if re.search(pattern, line):
                result.network_sinks.append(
                    NetworkSink(
                        file=file_rel,
                        line=i + 1,
                        symbol=symbol,
                        direction="outbound",
                        api=pkg,
                        protocol=proto,
                        transport="tcp",
                        endpoint="<see code>",
                        endpoint_class="unknown",
                        tls=proto in {"https", "grpc", "ssh"},
                        gate="",
                        evidence=original,
                    )
                )

        # Raw socket syscalls.
        if has_syscall:
            m = re.search(r"\bsyscall\.(Socket|Connect|Bind|Listen|Sendto|Recvfrom|Socketpair)\s*\(", line)
            if m:
                direction = "inbound" if m.group(1) in {"Bind", "Listen"} else "outbound"
                result.network_sinks.append(
                    NetworkSink(
                        file=file_rel,
                        line=i + 1,
                        symbol=symbol,
                        direction=direction,
                        api="syscall." + m.group(1),
                        protocol="raw-socket",
                        transport="unknown",
                        endpoint="<syscall>",
                        endpoint_class="unknown",
                        tls=False,
                        gate="",
                        evidence=original,
                    )
                )

        # Process execution sinks.
        if has_exec:
            m = re.search(r"\bexec\.(CommandContext|Command)\s*\(", line)
            if m:
                call, _ = find_call(code_lines, i, m.start())
                args = split_top_level_args(call)
                name = args[1] if m.group(1) == "CommandContext" and len(args) > 1 else (args[0] if args else "")
                cmd = unquote_go(name) or re.sub(r"\s+", " ", name)[:80]
                cmd_class = "shell" if cmd.lower() in SHELL_NAMES else ("variable" if not unquote_go(name) else "program")
                result.exec_sinks.append(
                    ExecSink(
                        file=file_rel,
                        line=i + 1,
                        symbol=symbol,
                        api="exec." + m.group(1),
                        command=cmd,
                        command_class=cmd_class,
                        evidence=original,
                    )
                )

        if has_open:
            m = re.search(r"\bopen\.(StartWith|Start|RunWith|Run)\s*\(", line)
            if m:
                call, _ = find_call(code_lines, i, m.start())
                args = split_top_level_args(call)
                arg = args[0] if args else ""
                cmd = unquote_go(arg) or re.sub(r"\s+", " ", arg)[:80]
                result.exec_sinks.append(
                    ExecSink(
                        file=file_rel,
                        line=i + 1,
                        symbol=symbol,
                        api="open." + m.group(1),
                        command=cmd,
                        command_class="opener",
                        evidence=original,
                    )
                )

        if has_syscall:
            m = re.search(r"\bsyscall\.(Exec|ForkExec)\s*\(", line)
            if m:
                call, _ = find_call(code_lines, i, m.start())
                args = split_top_level_args(call)
                name = args[0] if args else ""
                cmd = unquote_go(name) or re.sub(r"\s+", " ", name)[:80]
                result.exec_sinks.append(
                    ExecSink(
                        file=file_rel,
                        line=i + 1,
                        symbol=symbol,
                        api="syscall." + m.group(1),
                        command=cmd,
                        command_class="program" if unquote_go(name) else "variable",
                        evidence=original,
                    )
                )

        # Remote hosts in real Go code (comments already stripped).
        for value in go_strings(line):
            for url in URL_SCHEME_RE.findall(value):
                try:
                    parsed = urllib.parse.urlsplit(url)
                except ValueError:
                    continue
                host = (parsed.hostname or "").lower()
                if not host:
                    continue
                if host not in {"localhost", "127.0.0.1", "::1"}:
                    result.remote_hosts.append(
                        {"file": file_rel, "line": i + 1, "url": url, "host": host, "evidence": original.strip()}
                    )

    # http.Server values that never got a ListenAndServe sink.
    for var_name, addr_expr, line_no, evidence in http_servers:
        endpoint, cls = classify_endpoint(addr_expr, "inbound")
        result.network_sinks.append(
            NetworkSink(
                file=file_rel,
                line=line_no,
                symbol=symbols[line_no - 1] if line_no - 1 < len(symbols) else "<package>",
                direction="inbound",
                api="http.Server",
                protocol="http",
                transport="tcp",
                endpoint=endpoint,
                endpoint_class=cls,
                tls=False,
                gate=("build tag: " + tags) if tags else "",
                evidence=evidence,
            )
        )

    # Deduplicate identical sinks produced by overlapping patterns.
    deduped: list[NetworkSink] = []
    seen: set[tuple[str, int, str, str]] = set()
    for sink in result.network_sinks:
        key = (sink.file, sink.line, sink.direction, sink.api)
        if key in seen:
            continue
        seen.add(key)
        deduped.append(sink)
    result.network_sinks = deduped


# ---------------------------------------------------------------------------
# Supply chain, CI, Nix, assets


def scan_go_mod(path: Path, root: Path, result: AuditResult) -> None:
    text = read_text(path)
    direct: list[str] = []
    in_require = False
    for line in text.splitlines():
        stripped = line.strip()
        if stripped.startswith("require ("):
            in_require = True
            continue
        if in_require and stripped == ")":
            in_require = False
            continue
        if stripped.startswith("//") or not stripped:
            continue
        candidate = ""
        if in_require:
            candidate = stripped
        elif stripped.startswith("require "):
            candidate = stripped[len("require ") :].strip()
        else:
            continue
        if "// indirect" in candidate:
            continue
        m = re.match(r"([^\s]+)\s+(v[^\s]+)", candidate)
        if not m:
            continue
        module, version = m.group(1), m.group(2)
        if module in {"require", "replace", "exclude", "retract"}:
            continue
        direct.append(f"{module} {version}")
    result.direct_modules = direct

    for line in text.splitlines():
        if re.match(r"^\s*replace\b", line):
            result.replace_directives.append(line.strip())
        for module, _ in [d.split(" ", 1) for d in direct if " " in d]:
            if SUSPICIOUS_DEP_RE.search(module):
                result.add(
                    Finding(
                        rule="DEP-SUSPICIOUS-NAME",
                        severity="medium",
                        file=rel(path, root),
                        line=0,
                        message=f"Direct dependency name matches a network/telemetry heuristic: {module}",
                        evidence=module,
                        category="supply-chain",
                    )
                )


def scan_workflows(root: Path, result: AuditResult) -> None:
    wf_dir = root / ".github" / "workflows"
    if not wf_dir.is_dir():
        return
    for path in sorted(wf_dir.glob("*")):
        if path.suffix.lower() not in {".yml", ".yaml"}:
            continue
        text = read_text(path)
        lines = text.splitlines()
        file_rel = rel(path, root)
        actions: list[str] = []
        has_permissions = False
        has_pull_request_target = False
        for i, line in enumerate(lines):
            stripped = line.strip()
            if re.match(r"^permissions\s*:", stripped):
                has_permissions = True
            if "pull_request_target" in stripped:
                has_pull_request_target = True
            if re.match(r"^permissions\s*:\s*write-all", stripped):
                result.add(
                    Finding(
                        rule="CI-WRITE-ALL",
                        severity="high",
                        file=file_rel,
                        line=i + 1,
                        message="Workflow grants write-all token permissions.",
                        evidence=stripped,
                        category="supply-chain",
                    )
                )
            m = re.match(r"-?\s*uses:\s*([^\s#]+)", stripped)
            if m:
                action = m.group(1)
                actions.append(action)
                ref = action.rsplit("@", 1)[-1] if "@" in action else ""
                if "@" in action and not re.fullmatch(r"[0-9a-fA-F]{40}", ref):
                    result.add(
                        Finding(
                            rule="CI-ACTION-UNPINNED",
                            severity="medium",
                            file=file_rel,
                            line=i + 1,
                            message=f"Action is pinned to a mutable ref, not a commit SHA: {action}",
                            evidence=stripped,
                            category="supply-chain",
                            confidence="high",
                        )
                    )

        if has_pull_request_target:
            result.add(
                Finding(
                    rule="CI-PULL-REQUEST-TARGET",
                    severity="high",
                    file=file_rel,
                    line=0,
                    message="Workflow uses pull_request_target; verify it never checks out or executes PR-controlled code with secrets.",
                    evidence="pull_request_target",
                    category="supply-chain",
                )
            )
        if not has_permissions:
            result.add(
                Finding(
                    rule="CI-NO-PERMISSIONS",
                    severity="low",
                    file=file_rel,
                    line=0,
                    message="No explicit permissions block; token scope depends on repository defaults.",
                    evidence="",
                    category="supply-chain",
                )
            )

        # Scan run blocks (including folded and inline forms) for
        # fetch-and-execute / decode-and-execute patterns.
        def check_run_text(combined: str, line_no: int) -> None:
            if re.search(r"(?:curl|wget)\b[^\n|]*\|\s*(?:sudo\s+)?(?:ba|z|da|k)?sh\b", combined):
                result.add(
                    Finding(
                        rule="CI-FETCH-EXEC",
                        severity="critical",
                        file=file_rel,
                        line=line_no,
                        message="Workflow pipes a network download directly into a shell.",
                        evidence=combined.strip()[:400],
                        category="malware",
                    )
                )
            if re.search(r"\bbase64\s+(?:-d|--decode)\b", combined) and re.search(r"\b(?:sh|bash|exec|eval)\b", combined):
                result.add(
                    Finding(
                        rule="CI-DECODE-EXEC",
                        severity="high",
                        file=file_rel,
                        line=line_no,
                        message="Workflow decodes base64 and invokes a shell/exec.",
                        evidence=combined.strip()[:400],
                        category="malware",
                    )
                )

        run_indent: Optional[int] = None
        run_lines: list[tuple[int, str]] = []
        for i, line in enumerate(lines):
            inline_run = re.match(r"^\s*(?:-\s*)?run:\s*(?!\||>)(.+)$", line)
            if inline_run:
                check_run_text(inline_run.group(1), i + 1)
                continue
            if re.match(r"^\s*(?:-\s*)?run:\s*[|>]", line):
                run_indent = len(line) - len(line.lstrip())
                run_lines = []
                for j in range(i + 1, len(lines)):
                    nxt = lines[j]
                    if nxt.strip() and (len(nxt) - len(nxt.lstrip())) <= run_indent:
                        break
                    run_lines.append((j + 1, nxt))
                combined = "\n".join(t for _, t in run_lines)
                check_run_text(combined, run_lines[0][0] if run_lines else i + 1)

        result.workflows.append(
            {
                "file": file_rel,
                "actions": actions,
                "has_permissions": has_permissions,
                "pull_request_target": has_pull_request_target,
            }
        )


def scan_nix(root: Path, result: AuditResult) -> None:
    files = [root / "flake.nix", root / "flake.lock"]
    files.extend(sorted((root / "nix").glob("*.nix")) if (root / "nix").is_dir() else [])
    for path in files:
        if not path.is_file():
            continue
        text = read_text(path)
        lines = text.splitlines()
        file_rel = rel(path, root)
        code_lines = [l for l in lines if not l.lstrip().startswith("#")]
        for i, line in enumerate(code_lines):
            if re.search(r"\b(fetchurl|fetchgit|fetchTarball|fetchzip|fetchFromGitHub)\s*[\(\{]", line):
                window = "\n".join(code_lines[i : i + 12])
                if not re.search(r"\b(hash|sha256|narHash)\s*=", window):
                    result.add(
                        Finding(
                            rule="NIX-UNPINNED-FETCH",
                            severity="high",
                            file=file_rel,
                            line=i + 1,
                            message="Nix fetch appears to lack a hash/integrity pin.",
                            evidence=line.strip(),
                            category="supply-chain",
                        )
                    )
            if "builtins.fetchTarball" in line or "builtins.fetchGit" in line or "builtins.fetchurl" in line:
                result.add(
                    Finding(
                        rule="NIX-IMPURE-FETCH",
                        severity="high",
                        file=file_rel,
                        line=i + 1,
                        message="Impure builtins.fetch* bypasses flake pinning.",
                        evidence=line.strip(),
                        category="supply-chain",
                    )
                )
            if "--impure" in line:
                result.add(
                    Finding(
                        rule="NIX-IMPURE-EVAL",
                        severity="medium",
                        file=file_rel,
                        line=i + 1,
                        message="Nix evaluation uses --impure.",
                        evidence=line.strip(),
                        category="supply-chain",
                    )
                )
            if re.search(r"extra-substituters|trusted-public-keys", line):
                result.add(
                    Finding(
                        rule="NIX-EXTRA-SUBSTITUTER",
                        severity="medium",
                        file=file_rel,
                        line=i + 1,
                        message="Custom binary cache/trusted key; verify the cache is intentional and trusted.",
                        evidence=line.strip(),
                        category="supply-chain",
                    )
                )
            if re.search(r"\b(postInstall|preBuild|installPhase|buildPhase|checkPhase|preInstall)\b", line):
                window = "\n".join(code_lines[i : i + 25])
                if re.search(r"\b(curl|wget)\b|\|\s*(?:ba|z)?sh\b|base64\s+-d", window):
                    result.add(
                        Finding(
                            rule="NIX-INSTALL-NETWORK",
                            severity="high",
                            file=file_rel,
                            line=i + 1,
                            message="Nix build/install phase contains a network download or decode-to-shell pattern.",
                            evidence=window.strip()[:400],
                            category="malware",
                        )
                    )


def scan_assets(path: Path, root: Path, result: AuditResult) -> None:
    data = path.read_bytes()
    ext = path.suffix.lower()
    kind = detect_asset_type(data)
    trailing = trailing_image_bytes(data, kind)
    embedded: list[str] = []
    for sig, name in [
        (b"\x7fELF", "ELF"),
        (b"MZ", "PE"),
        (b"PK\x03\x04", "ZIP"),
        (b"#!/", "script"),
    ]:
        if sig in data[4:]:
            embedded.append(name)
    urls = [u.decode("utf-8", "replace") for u in re.findall(rb"https?://[^\s\"'<>]{4,}", data[: 1024 * 1024])]
    info = AssetInfo(
        file=rel(path, root),
        size=len(data),
        detected_type=kind,
        extension=ext,
        trailing_bytes=trailing,
        embedded_signatures=sorted(set(embedded)),
        urls=sorted(set(urls))[:20],
    )
    if ext in IMAGE_EXTENSIONS:
        expected = ext.lstrip(".").replace("jpg", "jpeg")
        if kind not in {expected, "svg" if expected == "svg" else expected}:
            info.finding = "extension/magic mismatch"
            result.add(
                Finding(
                    rule="ASSET-MAGIC-MISMATCH",
                    severity="high",
                    file=info.file,
                    line=0,
                    message=f"Image extension {ext} contains {kind} data.",
                    evidence=f"detected={kind}",
                    category="malware",
                )
            )
        if trailing > 0:
            info.finding = "trailing bytes after image end"
            result.add(
                Finding(
                    rule="ASSET-TRAILING-DATA",
                    severity="high",
                    file=info.file,
                    line=0,
                    message=f"{trailing} byte(s) of appended data after the image end marker.",
                    evidence=f"size={len(data)}",
                    category="malware",
                )
            )
        if embedded:
            info.finding = "embedded executable/archive signature"
            result.add(
                Finding(
                    rule="ASSET-EMBEDDED-PAYLOAD",
                    severity="critical",
                    file=info.file,
                    line=0,
                    message="Image asset contains an embedded executable/archive/script signature.",
                    evidence=", ".join(sorted(set(embedded))),
                    category="malware",
                )
            )
        if urls:
            info.finding = "URLs in image asset"
            result.add(
                Finding(
                    rule="ASSET-EMBEDDED-URL",
                    severity="medium",
                    file=info.file,
                    line=0,
                    message="Image asset contains URL text; verify it is metadata, not a loader.",
                    evidence=", ".join(sorted(set(urls))[:5]),
                    category="threat",
                )
            )
    result.assets.append(info)


def scan_committed_binaries(root: Path, result: AuditResult) -> None:
    for path in root.rglob("*"):
        if not path.is_file() or any(part in SKIP_DIRS for part in path.parts):
            continue
        if path.suffix.lower() in BINARY_EXTENSIONS:
            data = path.read_bytes()[:8]
            result.add(
                Finding(
                    rule="BINARY-COMMITTED",
                    severity="medium",
                    file=rel(path, root),
                    line=0,
                    message="Committed binary artifact; verify it is expected and reproducible from source.",
                    evidence=f"magic={detect_asset_type(data)}",
                    category="supply-chain",
                )
            )


def scan_git(root: Path, result: AuditResult) -> None:
    git_dir = root / ".git"
    if not git_dir.exists():
        return
    hooks = git_dir / "hooks"
    if hooks.is_dir():
        for path in hooks.iterdir():
            if path.is_file() and not path.name.endswith(".sample"):
                mode = path.stat().st_mode
                if mode & 0o111:
                    result.add(
                        Finding(
                            rule="GIT-ACTIVE-HOOK",
                            severity="high",
                            file=rel(path, root),
                            line=0,
                            message="Active executable git hook found; hooks run automatically on git operations.",
                            evidence=path.name,
                            category="persistence",
                        )
                    )
    config = read_text(git_dir / "config")
    for line in config.splitlines():
        m = re.search(r"url\s*=\s*(\S+)", line)
        if m:
            url = m.group(1)
            if url.startswith("http://") or url.startswith("git://"):
                result.add(
                    Finding(
                        rule="GIT-INSECURE-REMOTE",
                        severity="medium",
                        file=".git/config",
                        line=0,
                        message=f"Git remote uses an unencrypted transport: {url}",
                        evidence=url,
                        category="supply-chain",
                    )
                )


def scan_text_patterns(path: Path, root: Path, result: AuditResult) -> None:
    ext = path.suffix.lower()
    if ext in {".md", ".txt", ".license"} or path.name.upper().startswith("LICENSE"):
        return
    text = read_text(path)
    if not text:
        return
    file_rel = rel(path, root)
    lines = text.splitlines()
    for i, line in enumerate(lines):
        # Secrets.
        for name, pattern in SECRET_PATTERNS:
            if pattern.search(line):
                result.add(
                    Finding(
                        rule="SECRET-HARDCODED",
                        severity="critical",
                        file=file_rel,
                        line=i + 1,
                        message=f"Possible hardcoded secret ({name}).",
                        evidence="<redacted>",
                        category="secret",
                        confidence="high",
                    )
                )
        # Persistence strings.
        for name, pattern in PERSISTENCE_PATTERNS:
            if pattern.search(line):
                result.add(
                    Finding(
                        rule="PERSISTENCE-STRING",
                        severity="medium",
                        file=file_rel,
                        line=i + 1,
                        message=f"Persistence-related string ({name}); confirm it is documentation or expected feature.",
                        evidence=line.strip()[:200],
                        category="persistence",
                    )
                )
        # Obfuscation / dangerous Go directives.
        if "//go:linkname" in line or "//go:cgo_import_dynamic" in line:
            result.add(
                Finding(
                    rule="GO-UNSAFE-LINKNAME",
                    severity="high",
                    file=file_rel,
                    line=i + 1,
                    message="Go linkname/cgo dynamic import can reach unexported runtime internals.",
                    evidence=line.strip(),
                    category="malware",
                )
            )
        if FORBIDDEN_BIDI.search(line):
            result.add(
                Finding(
                    rule="OBF-BIDI-CONTROL",
                    severity="critical",
                    file=file_rel,
                    line=i + 1,
                    message="Unicode bidirectional control character in source.",
                    evidence="<bidi control>",
                    category="malware",
                )
            )

    # File-level decode+execute correlation.
    if ext == ".go":
        has_b64 = "encoding/base64" in text or "base64.StdEncoding" in text
        has_hex = "encoding/hex" in text and "DecodeString" in text
        has_exec = "os/exec" in text or "syscall.Exec" in text or "syscall.ForkExec" in text
        if (has_b64 or has_hex) and has_exec:
            result.add(
                Finding(
                    rule="OBF-DECODE-EXEC",
                    severity="critical",
                    file=file_rel,
                    line=0,
                    message="File decodes base64/hex and executes a process; inspect the data flow.",
                    evidence="decode + exec in same file",
                    category="malware",
                )
            )
        if "encoding/base64" in text and re.search(r"[A-Za-z0-9+/]{500,}={0,2}", text):
            result.add(
                Finding(
                    rule="OBF-LARGE-BASE64",
                    severity="medium",
                    file=file_rel,
                    line=0,
                    message="Large base64-looking blob in Go source; verify it is icon/test data.",
                    evidence=">=500 base64 chars",
                    category="malware",
                )
            )


def scan_vendor(root: Path, result: AuditResult) -> None:
    vendor = root / "vendor"
    if not vendor.is_dir():
        result.notes.append("--include-deps requested but no vendor/ directory exists; dependency source not scanned.")
        return
    count = 0
    for path in vendor.rglob("*.go"):
        if path.name.endswith("_test.go"):
            continue
        text = read_text(path)
        if re.search(r'"(net|net/http|net/rpc|net/smtp|crypto/tls|os/exec)"', text):
            file_rel = rel(path, root)
            result.notes.append(f"vendored dependency uses network/exec import: {file_rel}")
            count += 1
            if count >= 200:
                result.notes.append("dependency scan capped at 200 files")
                break


# ---------------------------------------------------------------------------
# Baseline comparison


def load_baseline(path: Path) -> dict:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        return {"_error": str(exc)}


def normalize_protocol(protocol: str) -> str:
    p = protocol.lower()
    if p.startswith("http") or p.startswith("https"):
        return "http"
    return p


def compare_baseline(result: AuditResult, baseline: dict) -> None:
    if "_error" in baseline:
        result.notes.append(f"baseline could not be loaded: {baseline['_error']}")
        return
    baseline_repo = baseline.get("repo", "")
    go_mod = Path(result.repo) / "go.mod"
    if baseline_repo and go_mod.is_file():
        module_match = re.search(r"^module\s+(\S+)", read_text(go_mod), re.MULTILINE)
        module = module_match.group(1) if module_match else ""
        if module and module != baseline_repo:
            result.notes.append(
                f"baseline belongs to {baseline_repo}, not {module}; baseline comparison skipped"
            )
            return
    expected = baseline.get("expected_network", [])
    used: set[int] = set()
    for sink in result.network_sinks:
        match_idx = None
        for idx, exp in enumerate(expected):
            if idx in used:
                continue
            if exp.get("file") != sink.file:
                continue
            if exp.get("direction") != sink.direction:
                continue
            if normalize_protocol(exp.get("protocol", "")) != normalize_protocol(sink.protocol):
                continue
            match_idx = idx
            break
        if match_idx is None:
            result.baseline_unexpected.append(
                f"{sink.file}:{sink.line} {sink.direction} {sink.protocol} {sink.endpoint}"
            )
            result.add(
                Finding(
                    rule="NET-UNEXPECTED-SINK",
                    severity="high" if sink.direction == "outbound" else "medium",
                    file=sink.file,
                    line=sink.line,
                    message=f"Network sink not present in the pinned baseline: {sink.direction} {sink.protocol} {sink.endpoint}",
                    evidence=sink.evidence,
                    category="network",
                )
            )
            continue
        used.add(match_idx)
        exp = expected[match_idx]
        result.baseline_matched.append(exp.get("id", f"{sink.file}:{sink.line}"))
        exp_class = exp.get("endpoint_class", "unknown")
        if exp_class != sink.endpoint_class:
            result.baseline_changed.append(
                f"{exp.get('id', sink.file)}: expected {exp_class}, found {sink.endpoint_class} ({sink.endpoint})"
            )
            result.add(
                Finding(
                    rule="NET-ENDPOINT-CHANGED",
                    severity="high" if sink.endpoint_class in {"remote", "all-interfaces"} else "medium",
                    file=sink.file,
                    line=sink.line,
                    message=f"Endpoint class changed from {exp_class} to {sink.endpoint_class}: {sink.endpoint}",
                    evidence=sink.evidence,
                    category="network",
                )
            )

    for idx, exp in enumerate(expected):
        if idx not in used:
            result.baseline_missing.append(exp.get("id", f"{exp.get('file')} ({exp.get('direction')})"))

    # Process-execution baseline: any new exec sink needs an explanation.
    expected_exec = baseline.get("expected_exec", [])
    used_exec: set[int] = set()
    for sink in result.exec_sinks:
        match_idx = None
        for idx, exp in enumerate(expected_exec):
            if idx in used_exec:
                continue
            if exp.get("file") != sink.file:
                continue
            if exp.get("api") and exp["api"] != sink.api:
                continue
            match_idx = idx
            break
        if match_idx is None:
            result.baseline_exec_unexpected.append(
                f"{sink.file}:{sink.line} {sink.api} {sink.command!r}"
            )
            result.add(
                Finding(
                    rule="EXEC-UNEXPECTED-SINK",
                    severity="high",
                    file=sink.file,
                    line=sink.line,
                    message=f"Process-execution sink not present in the pinned baseline: {sink.api} {sink.command!r}",
                    evidence=sink.evidence,
                    category="execution",
                )
            )
            continue
        used_exec.add(match_idx)
        result.baseline_exec_matched.append(expected_exec[match_idx].get("id", f"{sink.file}:{sink.line}"))
    for idx, exp in enumerate(expected_exec):
        if idx not in used_exec:
            result.baseline_exec_missing.append(exp.get("id", f"{exp.get('file')} ({exp.get('api')})"))

    # Direct dependency drift.
    expected_modules = set(baseline.get("direct_modules", []))
    actual_modules = set(result.direct_modules)
    for module in sorted(actual_modules - expected_modules):
        result.add(
            Finding(
                rule="DEP-NEW-DIRECT",
                severity="medium",
                file="go.mod",
                line=0,
                message=f"Direct dependency not present in the pinned baseline: {module}",
                evidence=module,
                category="supply-chain",
            )
        )
    for module in sorted(expected_modules - actual_modules):
        result.add(
            Finding(
                rule="DEP-REMOVED-DIRECT",
                severity="low",
                file="go.mod",
                line=0,
                message=f"Baseline direct dependency is no longer present: {module}",
                evidence=module,
                category="supply-chain",
            )
        )

    for host in result.remote_hosts:
        result.add(
            Finding(
                rule="NET-REMOTE-HOST",
                severity="high",
                file=host["file"],
                line=host["line"],
                message=f"Remote host literal in runtime Go code: {host['host']}",
                evidence=host["url"],
                category="network",
            )
        )

    expected_hashes = baseline.get("hashes", {})
    for name, expected_hash in expected_hashes.items():
        path = Path(result.repo) / name
        if path.is_file():
            actual = sha256_file(path)
            if actual != expected_hash:
                result.add(
                    Finding(
                        rule="SUPPLY-FILE-DRIFT",
                        severity="medium",
                        file=name,
                        line=0,
                        message=f"{name} differs from the pinned baseline; review dependency/build changes.",
                        evidence=f"expected {expected_hash[:12]}…, got {actual[:12]}…",
                        category="supply-chain",
                    )
                )


# ---------------------------------------------------------------------------
# Repo walking and reporting


def should_scan(path: Path, root: Path) -> bool:
    if any(part in SKIP_DIRS for part in path.parts):
        return False
    if path.is_symlink():
        return False
    return True


def git_info(root: Path, result: AuditResult) -> None:
    if not shutil.which("git"):
        return
    try:
        head = subprocess.run(
            ["git", "-C", str(root), "rev-parse", "--short=7", "HEAD"],
            capture_output=True, text=True, timeout=10, check=False,
        )
        result.git_head = head.stdout.strip()
        status = subprocess.run(
            ["git", "-C", str(root), "status", "--porcelain"],
            capture_output=True, text=True, timeout=10, check=False,
        )
        result.git_dirty = bool(status.stdout.strip())
        remote = subprocess.run(
            ["git", "-C", str(root), "remote", "-v"],
            capture_output=True, text=True, timeout=10, check=False,
        )
        result.git_remote = remote.stdout.strip().splitlines()[0] if remote.stdout.strip() else ""
    except (OSError, subprocess.SubprocessError):
        pass


def scan(root: Path, include_deps: bool) -> AuditResult:
    result = AuditResult(scanner_version=SCANNER_VERSION, repo=str(root))
    git_info(root, result)

    baseline_path = Path(__file__).resolve().parent.parent / "references" / "network-baseline.json"
    baseline = load_baseline(baseline_path)

    for path in sorted(root.rglob("*")):
        if not should_scan(path, root) or not path.is_file():
            continue
        result.files_scanned += 1
        ext = path.suffix.lower()
        try:
            if ext == ".go":
                scan_go_file(path, root, result)
            elif path.name in {"go.mod"}:
                scan_go_mod(path, root, result)
            elif ext in IMAGE_EXTENSIONS:
                scan_assets(path, root, result)
            if ext in TEXT_EXTENSIONS or path.name in {"justfile", "Justfile", "Makefile"}:
                scan_text_patterns(path, root, result)
        except OSError as exc:
            result.notes.append(f"could not read {rel(path, root)}: {exc}")

    scan_workflows(root, result)
    scan_nix(root, result)
    scan_committed_binaries(root, result)
    scan_git(root, result)
    if include_deps:
        scan_vendor(root, result)

    compare_baseline(result, baseline)

    # Deduplicate findings by (rule, file, line, message).
    unique: dict[tuple[str, str, int, str], Finding] = {}
    for finding in result.findings:
        key = (finding.rule, finding.file, finding.line, finding.message)
        unique.setdefault(key, finding)
    result.findings = sorted(
        unique.values(),
        key=lambda f: ({"critical": 0, "high": 1, "medium": 2, "low": 3}.get(f.severity, 9), f.file, f.line),
    )
    return result


def severity_counts(result: AuditResult) -> dict[str, int]:
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for finding in result.findings:
        counts[finding.severity] = counts.get(finding.severity, 0) + 1
    return counts


def print_summary(result: AuditResult, verbose: bool) -> None:
    counts = severity_counts(result)
    print(f"kanata-tray static audit — {result.repo}")
    print(f"HEAD: {result.git_head or 'unknown'}{' (dirty working tree)' if result.git_dirty else ''}")
    if result.git_remote:
        print(f"Remote: {result.git_remote}")
    print(f"Files scanned: {result.files_scanned}")
    print(f"Findings: {counts['critical']} critical, {counts['high']} high, {counts['medium']} medium, {counts['low']} low")
    print()

    print("Network inventory (static):")
    if not result.network_sinks:
        print("  (none found)")
    for sink in result.network_sinks:
        tls = " tls" if sink.tls else ""
        print(
            f"  [{sink.direction}] {sink.file}:{sink.line} {sink.api} "
            f"{sink.protocol}/{sink.transport}{tls} {sink.endpoint} ({sink.endpoint_class})"
        )
    if result.remote_hosts:
        print("Remote hosts in runtime Go code:")
        for host in result.remote_hosts:
            print(f"  {host['file']}:{host['line']} {host['host']} ({host['url']})")
    else:
        print("Remote hosts in runtime Go code: none")

    print()
    print("Process-execution sinks:")
    if not result.exec_sinks:
        print("  (none found)")
    for sink in result.exec_sinks:
        print(f"  {sink.file}:{sink.line} {sink.api} command={sink.command!r} class={sink.command_class}")

    print()
    print("Baseline:")
    print(f"  network matched: {len(result.baseline_matched)}")
    print(f"  network unexpected: {len(result.baseline_unexpected)}")
    print(f"  network changed: {len(result.baseline_changed)}")
    print(f"  network missing: {len(result.baseline_missing)}")
    print(f"  exec matched: {len(result.baseline_exec_matched)}")
    print(f"  exec unexpected: {len(result.baseline_exec_unexpected)}")
    print(f"  exec missing: {len(result.baseline_exec_missing)}")
    for item in result.baseline_unexpected:
        print(f"  UNEXPECTED {item}")
    for item in result.baseline_changed:
        print(f"  CHANGED {item}")
    for item in result.baseline_missing:
        print(f"  MISSING {item}")
    for item in result.baseline_exec_unexpected:
        print(f"  UNEXPECTED EXEC {item}")
    for item in result.baseline_exec_missing:
        print(f"  MISSING EXEC {item}")

    if counts["critical"] or counts["high"] or counts["medium"] or counts["low"]:
        print()
        print("Findings:")
        for finding in result.findings:
            if not verbose and finding.severity == "low":
                continue
            loc = f"{finding.file}:{finding.line}" if finding.line else finding.file
            print(f"  [{finding.severity.upper()}] {finding.rule} {loc}: {finding.message}")
            if verbose and finding.evidence:
                print(f"      evidence: {finding.evidence}")

    if result.notes:
        print()
        print("Notes:")
        for note in result.notes:
            print(f"  - {note}")


def main(argv: Optional[list[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Static threat and network audit for kanata-tray")
    parser.add_argument("repo", type=Path, help="Path to the kanata-tray checkout")
    parser.add_argument("--json", type=Path, help="Write full JSON result to this path")
    parser.add_argument("--include-deps", action="store_true", help="Scan vendor/ dependency source if present")
    parser.add_argument("--verbose", action="store_true", help="Print evidence for every finding")
    parser.add_argument(
        "--fail-on",
        choices=["none", "low", "medium", "high", "critical"],
        default="none",
        help="Exit non-zero if a finding at or above this severity exists",
    )
    args = parser.parse_args(argv)

    root = args.repo.resolve()
    if not root.is_dir():
        print(f"error: not a directory: {root}", file=sys.stderr)
        return 2
    if not (root / "go.mod").is_file() and not (root / ".git").exists():
        print(f"warning: {root} does not look like the kanata-tray repo (no go.mod/.git)", file=sys.stderr)

    result = scan(root, args.include_deps)
    print_summary(result, args.verbose)

    if args.json:
        payload = asdict(result)
        payload["severity_counts"] = severity_counts(result)
        args.json.parent.mkdir(parents=True, exist_ok=True)
        args.json.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
        print(f"\nJSON written to {args.json}")

    order = {"none": 99, "low": 0, "medium": 1, "high": 2, "critical": 3}
    if args.fail_on != "none":
        threshold = order[args.fail_on]
        worst = max((order.get(f.severity, 0) for f in result.findings), default=-1)
        if worst >= threshold:
            return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
