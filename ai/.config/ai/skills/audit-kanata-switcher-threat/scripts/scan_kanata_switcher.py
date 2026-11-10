#!/usr/bin/env python3
"""Static threat and network audit for the kanata-switcher repository.

This scanner is intentionally dependency-free (Python 3 stdlib only).  It does
not execute the target repository.  Its job is recall: enumerate network sinks,
local-IPC sinks, process-execution sinks, filesystem writes, supply-chain
signals, and obvious malware patterns, then compare the result with the skill's
pinned baseline.  A human/agent must triage every finding in context.

Usage:
    python3 scan_kanata_switcher.py /path/to/kanata-switcher
    python3 scan_kanata_switcher.py /path/to/kanata-switcher --json /tmp/out.json --verbose
    python3 scan_kanata_switcher.py /path/to/kanata-switcher --include-deps
    python3 scan_kanata_switcher.py /path/to/kanata-switcher --fail-on high
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import shutil
import subprocess
import sys
import urllib.parse
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Optional

SCANNER_VERSION = "1.0.0"

SKIP_DIR_NAMES = {
    ".git",
    ".hg",
    ".svn",
    ".direnv",
    ".codegraph",
    ".idea",
    ".vscode",
    "__pycache__",
    "node_modules",
    "target",
    "local",
    "worktrees",
    "dist",
    "build",
    "out",
    "obj",
}

TEST_PATH_PARTS = {"tests", "test", "integration_tests"}

TEXT_EXTENSIONS = {
    ".rs",
    ".js",
    ".mjs",
    ".cjs",
    ".nix",
    ".toml",
    ".lock",
    ".json",
    ".yml",
    ".yaml",
    ".sh",
    ".bash",
    ".zsh",
    ".fish",
    ".py",
    ".service",
    ".desktop",
    ".xml",
    ".md",
    ".txt",
    "",
}

SOURCE_EXTENSIONS = {".rs", ".js", ".mjs", ".cjs", ".nix", ".sh", ".bash", ".py", ".toml"}

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
NETWORK_URL_SCHEMES = {
    "http",
    "https",
    "ftp",
    "ftps",
    "ws",
    "wss",
    "ssh",
    "git",
    "git+ssh",
    "smb",
    "sftp",
    "telnet",
    "ldap",
    "ldaps",
    "gopher",
    "mqtt",
    "mqtts",
    "amqp",
    "amqps",
    "redis",
    "rediss",
    "postgres",
    "postgresql",
    "mysql",
    "mongodb",
    "mongodb+srv",
    "rtsp",
    "sip",
    "tcp",
    "udp",
}
BENIGN_XML_NAMESPACES = {
    "http://www.w3.org/2000/svg",
    "http://www.w3.org/1999/xlink",
    "http://www.w3.org/1999/xhtml",
    "http://www.w3.org/XML/1998/namespace",
    "http://www.w3.org/1998/Math/MathML",
}
IP_PORT_RE = re.compile(r"\b((?:\d{1,3}\.){3}\d{1,3})(?::(\d{1,5}))?\b")
IPV4_LITERAL_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")

# Crates that would add a network, telemetry, or remote-control surface.  Any
# hit is a review prompt, not a verdict.
SUSPICIOUS_CRATE_RE = re.compile(
    r"(telemetry|analytics|sentry|datadog|newrelic|bugsnag|rollbar|posthog|"
    r"segment|mixpanel|amplitude|hotjar|fullstory|logrocket|smartlook|"
    r"reqwest|ureq|hyper|isahc|surf|attohttpc|curl|"
    r"tungstenite|websocket|tonic|prost|"
    r"lettre|smtp|ssh2|suppaftp|ftp|"
    r"trust-dns|hickory|resolver|"
    r"quinn|rustls|native-tls|openssl|"
    r"tor|onion|proxy|tunnel|vpn|"
    r"socket|tcp|udp|dns)\b",
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
    ("shell rc file", re.compile(r"(?<![\w.])(?:\.bashrc|\.bash_profile|\.zshrc|\.zprofile|\.profile|\.config/fish/config\.fish)", re.IGNORECASE)),
    ("SSH authorized_keys", re.compile(r"(?:authorized_keys|\.ssh/config)", re.IGNORECASE)),
    ("LD_PRELOAD", re.compile(r"\bLD_PRELOAD\b|/etc/ld\.so\.preload")),
]

FORBIDDEN_BIDI = re.compile(r"[\u202a-\u202e\u2066-\u2069]")

SHELL_NAMES = {
    "sh",
    "bash",
    "zsh",
    "dash",
    "ksh",
    "fish",
    "cmd",
    "cmd.exe",
    "powershell",
    "powershell.exe",
    "pwsh",
}

NETWORK_TOOLS = {
    "curl",
    "wget",
    "nc",
    "ncat",
    "netcat",
    "socat",
    "telnet",
    "ssh",
    "scp",
    "sftp",
    "rsync",
}

OPENERS = {"open", "xdg-open", "gio", "rundll32", "rundll32.exe", "start"}

# Network APIs that should not exist in this repo at all.  Each match creates a
# direct finding and a network sink so the baseline reports it as unexpected.
HARD_NETWORK_PATTERNS = [
    (r"\breqwest::", "reqwest", "outbound", "http", "tcp", "high"),
    (r"\bureq::", "ureq", "outbound", "http", "tcp", "high"),
    (r"\bsurf::", "surf", "outbound", "http", "tcp", "high"),
    (r"\bisahc::", "isahc", "outbound", "http", "tcp", "high"),
    (r"\battohttpc::", "attohttpc", "outbound", "http", "tcp", "high"),
    (r"\bhttp::", "http", "outbound", "http", "tcp", "high"),
    (r"\bhyper::", "hyper", "outbound", "http", "tcp", "high"),
    (r"\btungstenite::", "tungstenite", "outbound", "websocket", "tcp", "high"),
    (r"\btokio_tungstenite::", "tokio_tungstenite", "outbound", "websocket", "tcp", "high"),
    (r"\btonic::", "tonic", "outbound", "grpc", "tcp", "high"),
    (r"\blettre::", "lettre", "outbound", "smtp", "tcp", "high"),
    (r"\bssh2::", "ssh2", "outbound", "ssh", "tcp", "high"),
    (r"\bsuppaftp::", "suppaftp", "outbound", "ftp", "tcp", "high"),
    (r"\bquinn::", "quinn", "outbound", "quic", "udp", "high"),
    (r"\brustls::", "rustls", "outbound", "tls", "tcp", "high"),
    (r"\bnative_tls::", "native_tls", "outbound", "tls", "tcp", "high"),
    (r"\bopenssl::ssl::", "openssl", "outbound", "tls", "tcp", "high"),
    (r"\btokio_rustls::", "tokio_rustls", "outbound", "tls", "tcp", "high"),
    (r"\bhickory_resolver::", "hickory_resolver", "outbound", "dns", "udp/tcp", "high"),
    (r"\btrust_dns_resolver::", "trust_dns_resolver", "outbound", "dns", "udp/tcp", "high"),
    (r"\blibc::(?:socket|connect|bind|listen|sendto|recvfrom|getaddrinfo)\b", "libc raw socket", "outbound", "raw-socket", "unknown", "critical"),
]

IPC_PATTERNS = [
    (r"\bConnection::session\s*\(", "zbus::Connection::session", "dbus", "session"),
    (r"\bzbus::blocking::Connection::session\s*\(", "zbus::blocking::Connection::session", "dbus", "session"),
    (r"\bConnection::system\s*\(", "zbus::Connection::system", "dbus", "system"),
    (r"\bzbus::blocking::Connection::system\s*\(", "zbus::blocking::Connection::system", "dbus", "system"),
    (r"\bGio\.DBus(?:\.session)?\b", "Gio.DBus.session", "dbus", "session"),
    (r"\bGio\.Settings\b", "Gio.Settings (dconf over D-Bus)", "dbus", "session"),
    (r"\bksni::", "ksni (StatusNotifierItem over D-Bus)", "dbus", "session"),
    (r"\bWaylandConnection::connect_to_env\b", "WaylandConnection::connect_to_env", "wayland", "unix"),
    (r"\bwayland_client::Connection\b", "wayland_client::Connection", "wayland", "unix"),
    (r"\bx11rb::connect\b", "x11rb::connect", "x11", "unix"),
    (r"\bRustConnection::connect\b", "x11rb RustConnection::connect", "x11", "unix"),
]

EXEC_PATTERNS = [
    (r"(?:(?:std::process|tokio::process)::)?Command::new\s*\(", "Command::new", "program"),
    (r"\blibc::(?:exec|execve|execv|execvp|execle|execlp|execl|system|posix_spawn|fork)\w*\s*\(", "libc::exec/system", "unknown"),
    (r"\bopener::(?:open|that)\w*\s*\(", "opener", "opener"),
    (r"\bopen::that\s*\(", "open::that", "opener"),
]

WRITE_PATTERNS = [
    (r"\b(?:std::)?fs::write\s*\(", "fs::write"),
    (r"\b(?:std::)?fs::remove_file\s*\(", "fs::remove_file"),
    (r"\b(?:std::)?fs::remove_dir_all\s*\(", "fs::remove_dir_all"),
    (r"\b(?:std::)?fs::create_dir_all\s*\(", "fs::create_dir_all"),
    (r"\b(?:std::)?fs::copy\s*\(", "fs::copy"),
    (r"\b(?:std::)?fs::rename\s*\(", "fs::rename"),
    (r"\bOpenOptions::new\s*\(", "OpenOptions::new"),
    (r"\bFile::create\s*\(", "File::create"),
    (r"\btempfile::tempdir\s*\(", "tempfile::tempdir"),
    (r"\btempfile::NamedTempFile\b", "tempfile::NamedTempFile"),
]


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
    test_only: bool = False
    build_time: bool = False


@dataclass
class ExecSink:
    file: str
    line: int
    symbol: str
    api: str
    command: str
    command_class: str
    evidence: str
    test_only: bool = False
    build_time: bool = False


@dataclass
class WriteSink:
    file: str
    line: int
    symbol: str
    api: str
    target: str
    target_class: str
    evidence: str
    test_only: bool = False
    build_time: bool = False


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
    write_sinks: list[WriteSink] = field(default_factory=list)
    remote_hosts: list[dict] = field(default_factory=list)
    direct_crates: list[str] = field(default_factory=list)
    dev_crates: list[str] = field(default_factory=list)
    cargo_patches: list[str] = field(default_factory=list)
    unpinned_crates: list[str] = field(default_factory=list)
    cargo_lock_git_sources: list[str] = field(default_factory=list)
    cargo_lock_packages: int = 0
    workflows: list[dict] = field(default_factory=list)
    assets: list[AssetInfo] = field(default_factory=list)
    baseline_matched: list[str] = field(default_factory=list)
    baseline_missing: list[str] = field(default_factory=list)
    baseline_unexpected: list[str] = field(default_factory=list)
    baseline_changed: list[str] = field(default_factory=list)
    baseline_exec_matched: list[str] = field(default_factory=list)
    baseline_exec_missing: list[str] = field(default_factory=list)
    baseline_exec_unexpected: list[str] = field(default_factory=list)
    baseline_write_missing: list[str] = field(default_factory=list)
    baseline_write_unexpected: list[str] = field(default_factory=list)
    baseline_urls_unexpected: list[str] = field(default_factory=list)
    suppressed_findings: list[str] = field(default_factory=list)
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


def is_test_path(file_rel: str) -> bool:
    parts = set(Path(file_rel).parts)
    return bool(parts & TEST_PATH_PARTS) or file_rel.endswith("_test.rs") or "/tests/" in file_rel


def rust_strings(text: str) -> list[str]:
    """Extract string literals from comment-stripped Rust source."""
    values: list[str] = []
    for m in re.finditer(r'(?<![A-Za-z0-9_])(?:br|rb|r)(#*)"(.*?)"\1', text, re.DOTALL):
        values.append(m.group(2))
    for m in re.finditer(r'"((?:\\.|[^"\\])*)"', text):
        raw = m.group(1)
        try:
            values.append(json.loads('"' + raw + '"'))
        except json.JSONDecodeError:
            values.append(raw)
    return values


def js_strings(text: str) -> list[str]:
    values: list[str] = []
    for quote in ('"', "'", "`"):
        for m in re.finditer(re.escape(quote) + r"((?:\\.|[^" + re.escape(quote) + r"\\])*)" + re.escape(quote), text):
            values.append(m.group(1))
    return values


def strip_rust_comments(text: str) -> str:
    """Remove Rust comments while preserving strings and line offsets."""
    out: list[str] = []
    i = 0
    n = len(text)
    block_depth = 0
    line_comment = False
    while i < n:
        ch = text[i]
        if block_depth > 0:
            if text.startswith("/*", i):
                block_depth += 1
                i += 2
                continue
            if text.startswith("*/", i):
                block_depth -= 1
                i += 2
                continue
            if ch == "\n":
                out.append(ch)
            i += 1
            continue
        if line_comment:
            if ch == "\n":
                line_comment = False
                out.append(ch)
            i += 1
            continue
        if text.startswith("//", i):
            line_comment = True
            i += 2
            continue
        if text.startswith("/*", i):
            block_depth = 1
            i += 2
            continue
        m = re.match(r'(?<![A-Za-z0-9_])(?:br|rb|r)(#*)"', text[i:])
        if m:
            hashes = m.group(1)
            delim = '"' + hashes
            end = text.find(delim, i + m.end())
            if end == -1:
                out.append(text[i:])
                break
            end += len(delim)
            out.append(text[i:end])
            i = end
            continue
        if ch == '"':
            j = i + 1
            while j < n:
                if text[j] == "\\":
                    j += 2
                    continue
                if text[j] == '"':
                    j += 1
                    break
                j += 1
            out.append(text[i:j])
            i = j
            continue
        if ch == "'":
            m2 = re.match(r"'(?:\\.|[^\\'])'", text[i:])
            if m2:
                out.append(m2.group(0))
                i += m2.end()
                continue
        out.append(ch)
        i += 1
    return "".join(out)


def strip_c_comments(text: str) -> str:
    """Remove // and /* */ comments (used for JS and Nix) preserving lines."""
    out: list[str] = []
    i = 0
    n = len(text)
    block = False
    line = False
    quote: Optional[str] = None
    escaped = False
    while i < n:
        ch = text[i]
        if block:
            if text.startswith("*/", i):
                block = False
                i += 2
                continue
            if ch == "\n":
                out.append(ch)
            i += 1
            continue
        if line:
            if ch == "\n":
                line = False
                out.append(ch)
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
        if text.startswith("//", i):
            line = True
            i += 2
            continue
        if text.startswith("/*", i):
            block = True
            i += 2
            continue
        out.append(ch)
        i += 1
    return "".join(out)


def function_context(lines: list[str]) -> list[str]:
    current = "<module>"
    result: list[str] = []
    for line in lines:
        m = re.search(r"\bfn\s+([A-Za-z_]\w*)\s*[<(]", line)
        if m:
            current = m.group(1)
        result.append(current)
    return result


def find_call(lines: list[str], start: int, column: int) -> tuple[str, int]:
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


def first_rust_string(expr: str) -> Optional[str]:
    expr = expr.strip()
    m = re.match(r'^"(?:\\.|[^"\\])*"', expr)
    if m:
        try:
            return json.loads(m.group(0))
        except json.JSONDecodeError:
            return m.group(0)[1:-1]
    m = re.match(r'^(?:br|rb|r)(#*)"(.*?)"\1', expr, re.DOTALL)
    if m:
        return m.group(2)
    return None


def compact(expr: str, limit: int = 100) -> str:
    return re.sub(r"\s+", " ", expr).strip()[:limit]


def classify_endpoint(expr: str, direction: str) -> tuple[str, str]:
    display = compact(expr)
    low = display.lower()
    raw = expr.lower()

    if not display:
        return (
            "<all-interfaces>" if direction == "inbound" else "<unspecified>",
            "all-interfaces" if direction == "inbound" else "unknown",
        )
    if "unix" in raw or display.startswith("/") or display.endswith(".sock"):
        return display, "unix"
    if "0.0.0.0" in low or "[::]" in low or low.startswith(":") or low.startswith("*:"):
        return display, "all-interfaces"
    if "localhost" in low or "127.0.0.1" in low or "::1" in low:
        return display, "loopback"
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
    m = IP_PORT_RE.fullmatch(display)
    if m:
        ip = m.group(1)
        return display, "loopback" if ip.startswith("127.") else "remote"
    return display, "unknown"


def target_class_for(expr: str, file_rel: str) -> str:
    low = expr.lower()
    if "autostart" in low:
        return "autostart"
    if "config" in low:
        return "config"
    if "tmp" in low or "tempdir" in low or file_rel.endswith("build.rs"):
        return "temp/build"
    if "gnome" in low or "extension" in low:
        return "gnome-extension"
    return "unknown"


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


def network_urls_in_text(value: str) -> list[tuple[str, str]]:
    """Return (url, host) pairs for URL literals that could reach the network.

    GObject-introspection URIs such as ``gi://Gio`` and XML namespace
    declarations are not network endpoints and are ignored here.
    """
    found: list[tuple[str, str]] = []
    for match in URL_SCHEME_RE.finditer(value):
        url = match.group(1).rstrip(".,);")
        if url in BENIGN_XML_NAMESPACES:
            continue
        try:
            parsed = urllib.parse.urlsplit(url)
        except ValueError:
            continue
        if parsed.scheme.lower() not in NETWORK_URL_SCHEMES:
            continue
        host = (parsed.hostname or "").lower()
        if not host or host in LOCAL_HOSTS:
            continue
        found.append((url, host))
    return found


def embedded_signatures(data: bytes, kind: str, trailing_start: int) -> list[str]:
    """Detect *structural* executable/archive payloads inside an image.

    Short magic strings such as ``MZ`` occur by chance in compressed image
    data, so signatures are only accepted when they sit in appended data or
    form a complete header.  This keeps the signal usable.
    """
    found: set[str] = set()
    regions = [data]
    if 0 < trailing_start < len(data):
        regions = [data[trailing_start:]]
    for region in regions:
        if region.startswith(b"\x7fELF"):
            found.add("ELF")
        if region.startswith(b"PK\x03\x04"):
            found.add("ZIP")
        if region.startswith(b"#!/"):
            found.add("script")
        # A real PE has "MZ" at the start and a PE\0\0 signature in the
        # DOS header.  Random "MZ" bytes do not.
        if region.startswith(b"MZ"):
            pe_offset = int.from_bytes(region[0x3C:0x40], "little") if len(region) >= 0x40 else 0
            if 0x40 <= pe_offset <= len(region) - 4 and region[pe_offset : pe_offset + 4] == b"PE\x00\x00":
                found.add("PE")
    return sorted(found)


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
# Rust source scanning


def scan_rust_file(path: Path, root: Path, result: AuditResult) -> None:
    text = read_text(path)
    code = strip_rust_comments(text)
    lines = code.splitlines()
    original = text.splitlines()
    symbols = function_context(lines)
    file_rel = rel(path, root)
    test_only = is_test_path(file_rel)
    build_time = file_rel == "build.rs"
    seen_network_keys: set[tuple[str, int]] = set()
    ipc_sites: dict[str, tuple[int, str, str]] = {}

    for i, line in enumerate(lines):
        symbol = symbols[i] if i < len(symbols) else "<module>"
        evidence = original[i].rstrip() if i < len(original) else line.rstrip()

        # ---------- Local IPC (D-Bus, Wayland, X11) ----------
        for pattern, api, protocol, bus in IPC_PATTERNS:
            m = re.search(pattern, line)
            if not m:
                continue
            key = f"{protocol}:{bus}" if protocol == "dbus" else protocol
            if key not in ipc_sites:
                if protocol == "dbus":
                    endpoint = f"{bus} bus (D-Bus over unix socket)"
                elif protocol == "wayland":
                    endpoint = "Wayland compositor unix socket"
                else:
                    endpoint = "$DISPLAY (unix socket; TCP only if DISPLAY names a remote host)"
                ipc_sites[key] = (i + 1, api, evidence)
            break

        # ---------- Raw TCP / UDP / HTTP / TLS / DNS ----------
        raw_network = [
            (r"\bTokioTcpStream::connect\s*\(", "TokioTcpStream::connect", "outbound", "tcp", "tcp", False, ""),
            (r"\bTcpStream::connect\s*\(", "TcpStream::connect", "outbound", "tcp", "tcp", False, ""),
            (r"\bTcpListener::bind\s*\(", "TcpListener::bind", "inbound", "tcp", "tcp", False, ""),
            (r"\bUdpSocket::bind\s*\(", "UdpSocket::bind", "inbound", "udp", "udp", False, "high"),
            (r"\bUdpSocket::connect\s*\(", "UdpSocket::connect", "outbound", "udp", "udp", False, "high"),
            (r"\bUnixStream::connect\s*\(", "UnixStream::connect", "outbound", "unix", "unix", False, ""),
            (r"\bUnixListener::bind\s*\(", "UnixListener::bind", "inbound", "unix", "unix", False, "medium"),
            (r"\blookup_host\s*\(", "lookup_host", "outbound", "dns", "udp/tcp", False, "high"),
            (r"\bto_socket_addrs\s*\(", "to_socket_addrs", "outbound", "dns", "udp/tcp", False, "high"),
        ]
        for pattern, api, direction, protocol, transport, tls, severity in raw_network:
            m = re.search(pattern, line)
            if not m:
                continue
            call, _ = find_call(lines, i, m.start())
            args = split_top_level_args(call)
            arg = args[0] if args else ""
            endpoint, endpoint_class = classify_endpoint(arg, direction)
            if protocol == "unix" and endpoint_class == "unknown":
                endpoint_class = "unix"
            gate = ""
            if file_rel == "src/daemon/kanata.rs" and "TcpStream::connect" in api:
                endpoint = "{host}:{port}"
                endpoint_class = "configurable"
                gate = "--host (default 127.0.0.1) / --port (default 10000)"
            sink = NetworkSink(
                file=file_rel,
                line=i + 1,
                symbol=symbol,
                direction=direction,
                api=api,
                protocol=protocol,
                transport=transport,
                endpoint=endpoint,
                endpoint_class=endpoint_class,
                tls=tls,
                gate=gate,
                evidence=evidence,
                test_only=test_only,
                build_time=build_time,
            )
            key = (sink.api, sink.line)
            if key not in seen_network_keys:
                seen_network_keys.add(key)
                result.network_sinks.append(sink)
            if severity:
                result.add(
                    Finding(
                        rule="NET-UNEXPECTED-STACK",
                        severity=severity,
                        file=file_rel,
                        line=i + 1,
                        message=f"Unexpected network primitive in runtime code: {api}",
                        evidence=evidence,
                        category="network",
                    )
                )

        # Explicit API-family use.
        for pattern, api, direction, protocol, transport, severity in HARD_NETWORK_PATTERNS:
            m = re.search(pattern, line)
            if not m:
                continue
            sink = NetworkSink(
                file=file_rel,
                line=i + 1,
                symbol=symbol,
                direction=direction,
                api=api,
                protocol=protocol,
                transport=transport,
                endpoint="<see code>",
                endpoint_class="unknown",
                tls=protocol in {"http", "tls", "grpc", "ssh"},
                gate="",
                evidence=evidence,
                test_only=test_only,
                build_time=build_time,
            )
            key = (sink.api, sink.line)
            if key not in seen_network_keys:
                seen_network_keys.add(key)
                result.network_sinks.append(sink)
            if not test_only:
                result.add(
                    Finding(
                        rule="NET-UNEXPECTED-STACK",
                        severity=severity,
                        file=file_rel,
                        line=i + 1,
                        message=f"Network/remote-control API used in Rust code: {api}",
                        evidence=evidence,
                        category="network",
                    )
                )

        # ---------- Process execution ----------
        for pattern, api, default_class in EXEC_PATTERNS:
            m = re.search(pattern, line)
            if not m:
                continue
            call, _ = find_call(lines, i, m.start())
            args = split_top_level_args(call)
            name_expr = args[0] if args else ""
            command = first_rust_string(name_expr)
            if command is None:
                command = compact(name_expr, 60) or "<dynamic>"
                command_class = "variable" if default_class == "program" else default_class
            else:
                command_class = default_class
                if command.lower() in SHELL_NAMES:
                    command_class = "shell"
            if command_class == "program" and "-c" in call and command.lower() in SHELL_NAMES:
                command_class = "shell"
            result.exec_sinks.append(
                ExecSink(
                    file=file_rel,
                    line=i + 1,
                    symbol=symbol,
                    api=api,
                    command=command,
                    command_class=command_class,
                    evidence=evidence,
                    test_only=test_only,
                    build_time=build_time,
                )
            )
            if command_class == "shell":
                result.add(
                    Finding(
                        rule="EXEC-SHELL",
                        severity="high",
                        file=file_rel,
                        line=i + 1,
                        message=f"Shell execution sink: {command}",
                        evidence=evidence,
                        category="execution",
                    )
                )
            if command.lower() in NETWORK_TOOLS:
                result.add(
                    Finding(
                        rule="EXEC-NETWORK-TOOL",
                        severity="critical",
                        file=file_rel,
                        line=i + 1,
                        message=f"Process execution of a network tool: {command}",
                        evidence=evidence,
                        category="malware",
                    )
                )

        # ---------- Filesystem writes ----------
        for pattern, api in WRITE_PATTERNS:
            m = re.search(pattern, line)
            if not m:
                continue
            call, _ = find_call(lines, i, m.start())
            args = split_top_level_args(call)
            target = compact(args[0], 90) if args else "<dynamic>"
            result.write_sinks.append(
                WriteSink(
                    file=file_rel,
                    line=i + 1,
                    symbol=symbol,
                    api=api,
                    target=target,
                    target_class=target_class_for(target, file_rel),
                    evidence=evidence,
                    test_only=test_only,
                    build_time=build_time,
                )
            )
            if api in {"fs::remove_dir_all", "OpenOptions::new"} and not test_only:
                result.add(
                    Finding(
                        rule="FS-DESTRUCTIVE-API",
                        severity="medium",
                        file=file_rel,
                        line=i + 1,
                        message=f"High-impact filesystem API in runtime code: {api}",
                        evidence=evidence,
                        category="persistence",
                    )
                )

        # ---------- Obfuscation and unsafe primitives ----------
        if FORBIDDEN_BIDI.search(original[i] if i < len(original) else line):
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
        if "include_bytes!" in line or "include_str!" in line:
            result.notes.append(f"{file_rel}:{i + 1}: compile-time embedded file; verify the included path is expected")
        if "//go:" in line:
            pass

    # Aggregate IPC sites into one sink per (protocol, bus) per file.
    for key, (line_no, api, evidence) in sorted(ipc_sites.items()):
        protocol, _, bus = key.partition(":")
        if protocol == "dbus":
            endpoint = f"{bus} bus (D-Bus over unix socket)"
            transport = "unix"
        elif protocol == "wayland":
            endpoint = "Wayland compositor unix socket"
            transport = "unix"
        else:
            endpoint = "$DISPLAY (unix socket; TCP only if DISPLAY names a remote host)"
            transport = "unix"
        result.network_sinks.append(
            NetworkSink(
                file=file_rel,
                line=line_no,
                symbol=symbols[line_no - 1] if line_no - 1 < len(symbols) else "<module>",
                direction="local",
                api=api,
                protocol=protocol,
                transport=transport,
                endpoint=endpoint,
                endpoint_class="unix",
                tls=False,
                gate="",
                evidence=evidence,
                test_only=test_only,
                build_time=build_time,
            )
        )

    # Remote host literals in runtime source (comments already stripped).
    for value in rust_strings(code):
        for url, host in network_urls_in_text(value):
            result.remote_hosts.append(
                {
                    "file": file_rel,
                    "line": 0,
                    "url": url,
                    "host": host,
                    "evidence": value[:200],
                    "test_only": test_only,
                }
            )

    # File-level decode + execute correlation.
    has_b64 = bool(re.search(r"\bbase64\b|\bBase64\b", code)) and bool(re.search(r"\bdecode\b", code, re.IGNORECASE))
    has_hex = bool(re.search(r"\bhex::(?:decode|from_hex)\b", code))
    has_exec = any(s.file == file_rel for s in result.exec_sinks)
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
    if has_b64 and re.search(r"[A-Za-z0-9+/]{500,}={0,2}", code):
        result.add(
            Finding(
                rule="OBF-LARGE-BASE64",
                severity="medium",
                file=file_rel,
                line=0,
                message="Large base64-looking blob in Rust source; verify it is test/font data.",
                evidence=">=500 base64 chars",
                category="malware",
            )
        )


# ---------------------------------------------------------------------------
# GNOME extension JavaScript scanning


def scan_js_file(path: Path, root: Path, result: AuditResult) -> None:
    text = read_text(path)
    code = strip_c_comments(text)
    lines = code.splitlines()
    original = text.splitlines()
    file_rel = rel(path, root)
    test_only = is_test_path(file_rel)
    ipc_sites: dict[str, tuple[int, str, str]] = {}

    dangerous = [
        (r"\bGLib\.spawn\w*\s*\(", "GLib.spawn", "critical", "process execution"),
        (r"\bGio\.Subprocess\b", "Gio.Subprocess", "critical", "process execution"),
        (r"\bGio\.SocketClient\b", "Gio.SocketClient", "high", "raw socket client"),
        (r"\bSoup\.", "Soup", "high", "HTTP client"),
        (r"\bXMLHttpRequest\b", "XMLHttpRequest", "high", "HTTP client"),
        (r"\bfetch\s*\(", "fetch", "high", "HTTP client"),
        (r"\bWebSocket\b", "WebSocket", "high", "WebSocket"),
        (r"\beval\s*\(", "eval", "critical", "dynamic code execution"),
        (r"\bnew\s+Function\s*\(", "new Function", "critical", "dynamic code execution"),
        (r"\bimports\.searchPath\b", "imports.searchPath", "high", "legacy import path manipulation"),
        (r"\bimports\.byteArray\b", "imports.byteArray", "medium", "legacy byte array API"),
    ]
    for i, line in enumerate(lines):
        for pattern, api, severity, label in dangerous:
            if re.search(pattern, line):
                result.add(
                    Finding(
                        rule="JS-DANGEROUS-API",
                        severity=severity,
                        file=file_rel,
                        line=i + 1,
                        message=f"GNOME extension uses {api} ({label}).",
                        evidence=(original[i].rstrip() if i < len(original) else line).strip(),
                        category="malware",
                    )
                )
        for pattern, api, protocol, bus in IPC_PATTERNS:
            if protocol != "dbus":
                continue
            if re.search(pattern, line):
                key = protocol
                if key not in ipc_sites:
                    ipc_sites[key] = (i + 1, api, (original[i].rstrip() if i < len(original) else line))
                break

    for _key, (line_no, api, evidence) in sorted(ipc_sites.items()):
        result.network_sinks.append(
            NetworkSink(
                file=file_rel,
                line=line_no,
                symbol="<js>",
                direction="local",
                api=api,
                protocol="dbus",
                transport="unix",
                endpoint="session bus (D-Bus over unix socket)",
                endpoint_class="unix",
                tls=False,
                gate="",
                evidence=evidence,
                test_only=test_only,
            )
        )

    for value in js_strings(code):
        for url, host in network_urls_in_text(value):
            result.remote_hosts.append(
                {
                    "file": file_rel,
                    "line": 0,
                    "url": url,
                    "host": host,
                    "evidence": value[:200],
                    "test_only": test_only,
                }
            )


# ---------------------------------------------------------------------------
# Cargo / supply chain


def scan_cargo_toml(path: Path, root: Path, result: AuditResult) -> None:
    text = read_text(path)
    file_rel = rel(path, root)
    section = ""
    in_table = False
    for i, line in enumerate(text.splitlines()):
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        m = re.match(r"^\[([^\]]+)\]", stripped)
        if m:
            section = m.group(1).strip()
            continue
        if "=" not in stripped:
            continue
        name, value = stripped.split("=", 1)
        name = name.strip().strip('"')
        value = value.strip()
        if section not in {"dependencies", "dev-dependencies", "build-dependencies", "workspace.dependencies"}:
            continue
        version = ""
        if value.startswith('"'):
            version = value.strip('"')
        else:
            vm = re.search(r'version\s*=\s*"([^"]+)"', value)
            version = vm.group(1) if vm else ""
            if re.search(r'\bgit\s*=', value):
                result.add(
                    Finding(
                        rule="DEP-GIT-SOURCE",
                        severity="high",
                        file=file_rel,
                        line=i + 1,
                        message=f"Dependency '{name}' is pulled from a git source.",
                        evidence=stripped,
                        category="supply-chain",
                    )
                )
            if re.search(r'\bpath\s*=', value):
                result.add(
                    Finding(
                        rule="DEP-PATH-SOURCE",
                        severity="medium",
                        file=file_rel,
                        line=i + 1,
                        message=f"Dependency '{name}' uses a local path source.",
                        evidence=stripped,
                        category="supply-chain",
                    )
                )
        entry = f"{name} {version}".strip()
        if section == "dependencies":
            result.direct_crates.append(entry)
        elif section == "dev-dependencies":
            result.dev_crates.append(entry)
        if version and not version.startswith("="):
            result.unpinned_crates.append(entry)
            result.add(
                Finding(
                    rule="DEP-UNPINNED",
                    severity="low",
                    file=file_rel,
                    line=i + 1,
                    message=f"Dependency '{name}' is not pinned with '='.",
                    evidence=stripped,
                    category="supply-chain",
                )
            )
        if SUSPICIOUS_CRATE_RE.search(name):
            result.add(
                Finding(
                    rule="DEP-SUSPICIOUS-NAME",
                    severity="medium",
                    file=file_rel,
                    line=i + 1,
                    message=f"Dependency name matches a network/telemetry heuristic: {name}",
                    evidence=stripped,
                    category="supply-chain",
                )
            )

    # Patch/replace sections are red flags in this repo.
    for i, line in enumerate(text.splitlines()):
        if re.match(r"^\[(?:patch|replace)", line.strip()):
            result.cargo_patches.append(line.strip())
            result.add(
                Finding(
                    rule="DEP-PATCH-OVERRIDE",
                    severity="high",
                    file=file_rel,
                    line=i + 1,
                    message="Cargo [patch]/[replace] overrides a dependency source.",
                    evidence=line.strip(),
                    category="supply-chain",
                )
            )


def scan_cargo_lock(path: Path, root: Path, result: AuditResult) -> None:
    text = read_text(path)
    file_rel = rel(path, root)
    result.cargo_lock_packages = len(re.findall(r"^\[\[package\]\]", text, re.MULTILINE))
    for i, line in enumerate(text.splitlines()):
        stripped = line.strip()
        if stripped.startswith("source = "):
            source = stripped.split("=", 1)[1].strip().strip('"')
            if source.startswith("git+"):
                result.cargo_lock_git_sources.append(source)
                result.add(
                    Finding(
                        rule="LOCK-GIT-SOURCE",
                        severity="high",
                        file=file_rel,
                        line=i + 1,
                        message=f"Cargo.lock contains a git source: {source}",
                        evidence=stripped,
                        category="supply-chain",
                    )
                )
            elif source.startswith("registry+") and "crates.io-index" not in source:
                result.add(
                    Finding(
                        rule="LOCK-UNKNOWN-REGISTRY",
                        severity="high",
                        file=file_rel,
                        line=i + 1,
                        message=f"Cargo.lock pulls a crate from a non-crates.io registry: {source}",
                        evidence=stripped,
                        category="supply-chain",
                    )
                )


def scan_nix_file(path: Path, root: Path, result: AuditResult) -> None:
    text = read_text(path)
    code = strip_c_comments(text)
    lines = code.splitlines()
    file_rel = rel(path, root)

    for i, line in enumerate(lines):
        if re.search(r"\b(fetchurl|fetchgit|fetchTarball|fetchzip|fetchFromGitHub)\s*[\(\{]", line):
            window = "\n".join(lines[i : i + 12])
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
        if re.search(r"builtins\.(?:fetchTarball|fetchGit|fetchurl)\b", line):
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
            window = "\n".join(lines[i : i + 25])
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
        # This repo builds systemd ExecStart by joining args with spaces; a
        # config/host value containing spaces can inject extra arguments.
        if "concatStringsSep \" \"" in line and "execArgs" in line:
            result.add(
                Finding(
                    rule="NIX-EXEC-ARGS-UNQUOTED",
                    severity="low",
                    file=file_rel,
                    line=i + 1,
                    message="systemd ExecStart is built by joining arguments with spaces; values with spaces can inject arguments.",
                    evidence=line.strip(),
                    category="hardening",
                )
            )

    if path.name == "flake.lock":
        try:
            lock = json.loads(text)
        except json.JSONDecodeError as exc:
            result.notes.append(f"{file_rel}: could not parse flake.lock: {exc}")
            return
        for node_name, node in (lock.get("nodes") or {}).items():
            locked = node.get("locked") if isinstance(node, dict) else None
            if not isinstance(locked, dict):
                continue
            node_type = locked.get("type", "")
            if node_type in {"path"}:
                continue
            if node_type in {"github", "git", "gitlab", "sourcehut"}:
                if not locked.get("rev"):
                    result.add(
                        Finding(
                            rule="NIX-LOCK-NO-REV",
                            severity="high",
                            file=file_rel,
                            line=0,
                            message=f"flake.lock node '{node_name}' has no pinned revision.",
                            evidence=json.dumps(locked)[:200],
                            category="supply-chain",
                        )
                    )
                if not locked.get("narHash"):
                    result.add(
                        Finding(
                            rule="NIX-LOCK-NO-NARHASH",
                            severity="high",
                            file=file_rel,
                            line=0,
                            message=f"flake.lock node '{node_name}' has no narHash.",
                            evidence=json.dumps(locked)[:200],
                            category="supply-chain",
                        )
                    )


def scan_workflow(path: Path, root: Path, result: AuditResult) -> None:
    text = read_text(path)
    lines = text.splitlines()
    file_rel = rel(path, root)
    actions: list[str] = []
    has_permissions = False
    has_pull_request_target = False
    uses_secrets = False

    for i, line in enumerate(lines):
        stripped = line.strip()
        if re.match(r"^permissions\s*:", stripped):
            has_permissions = True
        if "pull_request_target" in stripped:
            has_pull_request_target = True
        if re.search(r"\bsecrets\.", stripped):
            uses_secrets = True
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
    if uses_secrets and ("pull_request" in text or has_pull_request_target):
        result.add(
            Finding(
                rule="CI-SECRETS-IN-PR",
                severity="high",
                file=file_rel,
                line=0,
                message="Workflow references secrets and can run on PR-related events; verify PR code cannot read them.",
                evidence="secrets + pull_request",
                category="supply-chain",
            )
        )

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

    for i, line in enumerate(lines):
        inline_run = re.match(r"^\s*(?:-\s*)?run:\s*(?!\||>)(.+)$", line)
        if inline_run:
            check_run_text(inline_run.group(1), i + 1)
            continue
        if re.match(r"^\s*(?:-\s*)?run:\s*[|>]", line):
            run_indent = len(line) - len(line.lstrip())
            run_lines: list[tuple[int, str]] = []
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
            "uses_secrets": uses_secrets,
        }
    )


def scan_shell_file(path: Path, root: Path, result: AuditResult) -> None:
    text = read_text(path)
    code = strip_c_comments(text)
    file_rel = rel(path, root)
    test_only = is_test_path(file_rel)
    lines = code.splitlines()
    for i, line in enumerate(lines):
        stripped = line.strip()
        if not stripped or stripped.startswith("#!"):
            continue
        if re.search(r"\b(?:curl|wget)\b", stripped):
            result.add(
                Finding(
                    rule="SHELL-NETWORK-DOWNLOAD",
                    severity="high",
                    file=file_rel,
                    line=i + 1,
                    message="Shell script downloads from the network; verify the source and integrity check.",
                    evidence=stripped[:300],
                    category="network",
                )
            )
        if re.search(r"/dev/tcp/|/dev/udp/", stripped):
            result.add(
                Finding(
                    rule="SHELL-RAW-SOCKET",
                    severity="critical",
                    file=file_rel,
                    line=i + 1,
                    message="Shell script opens a raw TCP/UDP connection.",
                    evidence=stripped[:300],
                    category="malware",
                )
            )
        if re.search(r"\b(?:nc|ncat|netcat|socat)\b", stripped):
            result.add(
                Finding(
                    rule="SHELL-NETWORK-TOOL",
                    severity="high",
                    file=file_rel,
                    line=i + 1,
                    message="Shell script invokes a raw network tool.",
                    evidence=stripped[:300],
                    category="network",
                )
            )
        if re.search(r"\b(?:base64\s+(?:-d|--decode)|xxd\s+-r)\b", stripped) and re.search(r"\b(?:eval|sh|bash|exec)\b", stripped):
            result.add(
                Finding(
                    rule="SHELL-DECODE-EXEC",
                    severity="critical",
                    file=file_rel,
                    line=i + 1,
                    message="Shell script decodes data and executes it.",
                    evidence=stripped[:300],
                    category="malware",
                )
            )
        if re.search(r"\b(?:bash|sh|zsh)\s+-c\b", stripped) and re.search(r"\$\{?[A-Za-z_]", stripped):
            result.add(
                Finding(
                    rule="SHELL-DYNAMIC-COMMAND",
                    severity="medium",
                    file=file_rel,
                    line=i + 1,
                    message="Shell script builds a `sh -c` command from a variable; verify the input is trusted.",
                    evidence=stripped[:300],
                    category="execution",
                )
            )
        if FORBIDDEN_BIDI.search(line):
            result.add(
                Finding(
                    rule="OBF-BIDI-CONTROL",
                    severity="critical",
                    file=file_rel,
                    line=i + 1,
                    message="Unicode bidirectional control character in a shell script.",
                    evidence="<bidi control>",
                    category="malware",
                )
            )


# ---------------------------------------------------------------------------
# Assets, git, generic text


def scan_asset(path: Path, root: Path, result: AuditResult) -> None:
    data = path.read_bytes()
    ext = path.suffix.lower()
    kind = detect_asset_type(data)
    trailing = trailing_image_bytes(data, kind)
    trailing_start = len(data) - trailing if trailing else 0
    embedded = embedded_signatures(data, kind, trailing_start)
    raw_urls = [
        u.decode("utf-8", "replace")
        for u in re.findall(rb"https?://[^\s\"'<>]{4,}", data[: 1024 * 1024])
    ]
    urls = sorted(
        {url for url in raw_urls if url.rstrip("/") not in BENIGN_XML_NAMESPACES}
    )
    info = AssetInfo(
        file=rel(path, root),
        size=len(data),
        detected_type=kind,
        extension=ext,
        trailing_bytes=trailing,
        embedded_signatures=sorted(set(embedded)),
        urls=sorted(set(urls))[:20],
    )
    if kind == "svg":
        low = data[: 2 * 1024 * 1024].lower()
        if b"<script" in low or b"javascript:" in low:
            info.finding = "SVG contains script content"
            result.add(
                Finding(
                    rule="ASSET-SVG-SCRIPT",
                    severity="critical",
                    file=info.file,
                    line=0,
                    message="SVG asset contains script/javascript content.",
                    evidence="<script or javascript: in SVG",
                    category="malware",
                )
            )
        if b"<foreignobject" in low or b"xlink:href" in low or re.search(rb"\bhref\s*=\s*[\"']https?://", low):
            info.finding = "SVG references external content"
            result.add(
                Finding(
                    rule="ASSET-SVG-EXTERNAL",
                    severity="medium",
                    file=info.file,
                    line=0,
                    message="SVG asset references external content; verify it is a passive image.",
                    evidence="foreignObject/external href",
                    category="threat",
                )
            )
    if ext in IMAGE_EXTENSIONS:
        expected = ext.lstrip(".").replace("jpg", "jpeg")
        if kind != expected:
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
        if not path.is_file() or any(part in SKIP_DIR_NAMES for part in path.parts):
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
    if (root / ".gitmodules").is_file():
        result.add(
            Finding(
                rule="GIT-SUBMODULE",
                severity="medium",
                file=".gitmodules",
                line=0,
                message="Repository contains submodules; verify their remotes and pinned revisions.",
                evidence=".gitmodules",
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
    for i, line in enumerate(text.splitlines()):
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


def scan_vendor(root: Path, result: AuditResult) -> None:
    vendor = root / "vendor"
    if not vendor.is_dir():
        result.notes.append("--include-deps requested but no vendor/ directory exists; dependency source not scanned.")
        return
    count = 0
    for path in vendor.rglob("*"):
        if not path.is_file() or path.suffix not in {".rs", ".js"}:
            continue
        text = read_text(path)
        if re.search(r"\b(reqwest|ureq|hyper|tungstenite|tonic|std::process::Command|Connection::session)\b", text):
            result.notes.append(f"vendored dependency uses network/exec APIs: {rel(path, root)}")
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
    if p.startswith("http") or p == "https":
        return "http"
    return p


def compare_baseline(result: AuditResult, baseline: dict) -> None:
    if "_error" in baseline:
        result.notes.append(f"baseline could not be loaded: {baseline['_error']}")
        return

    expected_package = baseline.get("repo_package", "")
    cargo_toml = Path(result.repo) / "Cargo.toml"
    if expected_package and cargo_toml.is_file():
        name_match = re.search(r'^name\s*=\s*"([^"]+)"', read_text(cargo_toml), re.MULTILINE)
        package = name_match.group(1) if name_match else ""
        if package != expected_package:
            result.notes.append(
                f"baseline belongs to Cargo package '{expected_package}', not '{package}'; baseline comparison skipped"
            )
            return

    audited_commit = baseline.get("audited_commit", "")
    if result.git_head and audited_commit:
        if not result.git_head.startswith(audited_commit[:7]):
            result.notes.append(
                f"checkout HEAD {result.git_head} differs from audited commit {audited_commit}; "
                "review every change since that commit before calling it clean"
            )
            if shutil.which("git"):
                try:
                    ancestor = subprocess.run(
                        ["git", "-C", result.repo, "merge-base", "--is-ancestor", audited_commit, "HEAD"],
                        capture_output=True,
                        timeout=10,
                        check=False,
                    )
                    if ancestor.returncode == 0:
                        result.notes.append(
                            f"HEAD descends from the audited commit; audit the diff: "
                            f"git diff {audited_commit[:7]}..HEAD"
                        )
                    else:
                        result.notes.append(
                            "HEAD is not a descendant of the audited commit; the baseline may not apply."
                        )
                except (OSError, subprocess.SubprocessError):
                    pass

    # Network inventory.
    expected = baseline.get("expected_network", [])
    used: set[int] = set()
    for sink in result.network_sinks:
        if sink.test_only:
            continue
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
            severity = "medium"
            if sink.direction in {"outbound", "inbound"}:
                severity = "high"
            if sink.protocol in {"unix", "dbus", "wayland", "x11"}:
                severity = "low"
            result.add(
                Finding(
                    rule="NET-UNEXPECTED-SINK",
                    severity=severity,
                    file=sink.file,
                    line=sink.line,
                    message=f"Network/IPC sink not present in the pinned baseline: {sink.direction} {sink.protocol} {sink.endpoint}",
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

    # Process execution baseline (count per file + api + command).
    expected_exec = baseline.get("expected_exec", [])
    actual_exec: dict[tuple[str, str, str], list[ExecSink]] = {}
    for sink in result.exec_sinks:
        if sink.test_only:
            continue
        actual_exec.setdefault((sink.file, sink.api, sink.command), []).append(sink)

    matched_exec_keys: set[tuple[str, str, str]] = set()
    for exp in expected_exec:
        key = (exp.get("file", ""), exp.get("api", ""), exp.get("command", ""))
        exp_id = exp.get("id", f"{key[0]} ({key[1]})")
        expected_count = int(exp.get("count", 1))
        actual = actual_exec.get(key, [])
        matched_keys: list[tuple[str, str, str]] = [key] if actual else []
        if not actual and not exp.get("command"):
            # A baseline entry with no command matches every command for this
            # file+api, and counts them together.
            candidates = [
                (k, v)
                for k, v in actual_exec.items()
                if k[0] == key[0] and k[1] == key[1] and k not in matched_exec_keys
            ]
            matched_keys = [k for k, _ in candidates]
            actual = [sink for _, sinks in candidates for sink in sinks]
        if not actual:
            result.baseline_exec_missing.append(f"{exp_id} (expected {expected_count})")
            result.add(
                Finding(
                    rule="EXEC-BASELINE-MISSING",
                    severity="medium",
                    file=key[0],
                    line=0,
                    message=f"Expected process-execution sink is gone: {key[1]} {key[2]!r}.",
                    evidence=exp_id,
                    category="execution",
                )
            )
            continue
        matched_exec_keys.update(matched_keys)
        result.baseline_exec_matched.append(exp_id)
        if len(actual) != expected_count:
            result.baseline_exec_unexpected.append(
                f"{key[0]} {key[1]} {key[2]!r}: expected {expected_count}, found {len(actual)}"
            )
            result.add(
                Finding(
                    rule="EXEC-COUNT-CHANGED",
                    severity="medium",
                    file=key[0],
                    line=actual[0].line,
                    message=f"Process-execution count changed for {key[1]} {key[2]!r} (expected {expected_count}, found {len(actual)}).",
                    evidence=actual[0].evidence,
                    category="execution",
                )
            )
    for key, sinks in actual_exec.items():
        if key in matched_exec_keys:
            continue
        result.baseline_exec_unexpected.append(f"{sinks[0].file}:{sinks[0].line} {sinks[0].api} {sinks[0].command!r}")
        result.add(
            Finding(
                rule="EXEC-UNEXPECTED-SINK",
                severity="high",
                file=sinks[0].file,
                line=sinks[0].line,
                message=f"Process-execution sink not present in the pinned baseline: {sinks[0].api} {sinks[0].command!r}",
                evidence=sinks[0].evidence,
                category="execution",
            )
        )

    # Filesystem-write baseline (count per file + api).
    expected_writes = baseline.get("expected_fs_writes", [])
    actual_writes: dict[tuple[str, str], list[WriteSink]] = {}
    for sink in result.write_sinks:
        if sink.test_only:
            continue
        actual_writes.setdefault((sink.file, sink.api), []).append(sink)

    matched_write_keys: set[tuple[str, str]] = set()
    for exp in expected_writes:
        key = (exp.get("file", ""), exp.get("api", ""))
        exp_id = exp.get("id", f"{key[0]} ({key[1]})")
        expected_count = int(exp.get("count", 1))
        actual = actual_writes.get(key, [])
        if not actual:
            result.baseline_write_missing.append(f"{exp_id} (expected {expected_count})")
            result.add(
                Finding(
                    rule="FS-WRITE-BASELINE-MISSING",
                    severity="medium",
                    file=key[0],
                    line=0,
                    message=f"Expected filesystem write is gone: {key[1]}.",
                    evidence=exp_id,
                    category="persistence",
                )
            )
            continue
        matched_write_keys.add(key)
        if len(actual) != expected_count:
            result.baseline_write_unexpected.append(
                f"{key[0]} {key[1]}: expected {expected_count}, found {len(actual)}"
            )
            result.add(
                Finding(
                    rule="FS-WRITE-COUNT-CHANGED",
                    severity="medium",
                    file=key[0],
                    line=actual[0].line,
                    message=f"Filesystem-write count changed for {key[1]} (expected {expected_count}, found {len(actual)}).",
                    evidence=actual[0].evidence,
                    category="persistence",
                )
            )
    for key, sinks in actual_writes.items():
        if key in matched_write_keys:
            continue
        result.baseline_write_unexpected.append(f"{sinks[0].file}:{sinks[0].line} {sinks[0].api} {sinks[0].target}")
        result.add(
            Finding(
                rule="FS-UNEXPECTED-WRITE",
                severity="medium",
                file=sinks[0].file,
                line=sinks[0].line,
                message=f"Filesystem write not present in the pinned baseline: {sinks[0].api} {sinks[0].target}",
                evidence=sinks[0].evidence,
                category="persistence",
            )
        )

    # Direct crate drift.
    expected_crates = set(baseline.get("direct_crates", []))
    actual_crates = set(result.direct_crates)
    for crate in sorted(actual_crates - expected_crates):
        result.add(
            Finding(
                rule="DEP-NEW-DIRECT",
                severity="medium",
                file="Cargo.toml",
                line=0,
                message=f"Direct dependency not present in the pinned baseline: {crate}",
                evidence=crate,
                category="supply-chain",
            )
        )
    for crate in sorted(expected_crates - actual_crates):
        result.add(
            Finding(
                rule="DEP-REMOVED-DIRECT",
                severity="low",
                file="Cargo.toml",
                line=0,
                message=f"Baseline direct dependency is no longer present: {crate}",
                evidence=crate,
                category="supply-chain",
            )
        )

    # Remote URL allowlist.  URLs in runtime source must have been reviewed.
    allowed_urls = {entry.get("url") for entry in baseline.get("allowed_urls", [])}
    for host in result.remote_hosts:
        if host.get("test_only"):
            continue
        if host["url"] in allowed_urls:
            continue
        result.baseline_urls_unexpected.append(host["url"])
        result.add(
            Finding(
                rule="NET-REMOTE-HOST",
                severity="high",
                file=host["file"],
                line=host["line"],
                message=f"Remote URL/host literal in runtime source: {host['host']}",
                evidence=host["url"],
                category="network",
            )
        )

    # File integrity drift for supply-chain-sensitive files.
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
        else:
            result.add(
                Finding(
                    rule="SUPPLY-FILE-MISSING",
                    severity="medium",
                    file=name,
                    line=0,
                    message=f"Baseline file is missing from the checkout: {name}",
                    evidence="missing",
                    category="supply-chain",
                )
            )


# ---------------------------------------------------------------------------
# Repo walking and reporting


def should_scan(path: Path, root: Path) -> bool:
    if any(part in SKIP_DIR_NAMES for part in path.parts):
        return False
    if path.is_symlink():
        return False
    return True


def git_info(root: Path, result: AuditResult) -> None:
    if not shutil.which("git"):
        return
    try:
        head = subprocess.run(
            ["git", "-C", str(root), "rev-parse", "HEAD"],
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


def apply_suppressions(result: AuditResult, baseline: dict) -> None:
    """Drop findings that the baseline explicitly records as reviewed/accepted.

    An entry must name the rule and file, may pin the line and require an
    evidence substring, and must carry a reason.  Anything else stays visible.
    """
    accepted = baseline.get("accepted_findings", [])
    if not accepted:
        return
    remaining: list[Finding] = []
    for finding in result.findings:
        matched = None
        for entry in accepted:
            if entry.get("rule") != finding.rule:
                continue
            if entry.get("file") != finding.file:
                continue
            if entry.get("line") is not None and entry["line"] != finding.line:
                continue
            needle = entry.get("evidence_contains")
            if needle and needle not in finding.evidence:
                continue
            matched = entry
            break
        if matched is None:
            remaining.append(finding)
            continue
        result.suppressed_findings.append(
            f"{finding.rule} {finding.file}:{finding.line} — {matched.get('reason', 'accepted in baseline')}"
        )
    result.findings = remaining


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
            if ext == ".rs":
                scan_rust_file(path, root, result)
            elif ext in {".js", ".mjs", ".cjs"}:
                scan_js_file(path, root, result)
            elif path.name == "Cargo.toml":
                scan_cargo_toml(path, root, result)
            elif path.name == "Cargo.lock":
                scan_cargo_lock(path, root, result)
            elif ext == ".nix" or path.name == "flake.lock":
                scan_nix_file(path, root, result)
            elif ext in {".sh", ".bash"} or _has_shebang(path):
                scan_shell_file(path, root, result)
            elif ext in IMAGE_EXTENSIONS:
                scan_asset(path, root, result)
            if ext in TEXT_EXTENSIONS and ext not in IMAGE_EXTENSIONS:
                scan_text_patterns(path, root, result)
            if path.parent.name == "workflows" and path.parent.parent.name == ".github":
                scan_workflow(path, root, result)
        except OSError as exc:
            result.notes.append(f"could not read {rel(path, root)}: {exc}")

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
    apply_suppressions(result, baseline)
    return result


def _has_shebang(path: Path) -> bool:
    try:
        with path.open("rb") as fh:
            return fh.read(2) == b"#!"
    except OSError:
        return False


def severity_counts(result: AuditResult) -> dict[str, int]:
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for finding in result.findings:
        counts[finding.severity] = counts.get(finding.severity, 0) + 1
    return counts


def print_summary(result: AuditResult, verbose: bool) -> None:
    counts = severity_counts(result)
    print(f"kanata-switcher static audit — {result.repo}")
    print(f"HEAD: {result.git_head or 'unknown'}{' (dirty working tree)' if result.git_dirty else ''}")
    if result.git_remote:
        print(f"Remote: {result.git_remote}")
    print(f"Files scanned: {result.files_scanned}")
    print(f"Findings: {counts['critical']} critical, {counts['high']} high, {counts['medium']} medium, {counts['low']} low")
    print()

    print("Network / IPC inventory (static):")
    if not result.network_sinks:
        print("  (none found)")
    for sink in result.network_sinks:
        tls = " tls" if sink.tls else ""
        scope = " [test-only]" if sink.test_only else ""
        print(
            f"  [{sink.direction}] {sink.file}:{sink.line} {sink.api} "
            f"{sink.protocol}/{sink.transport}{tls} {sink.endpoint} ({sink.endpoint_class}){scope}"
        )
    if result.remote_hosts:
        print("Remote URL/host literals in runtime source:")
        for host in result.remote_hosts:
            scope = " [test-only]" if host.get("test_only") else ""
            print(f"  {host['file']}:{host['line']} {host['host']} ({host['url']}){scope}")
    else:
        print("Remote URL/host literals in runtime source: none")

    print()
    print("Process-execution sinks:")
    if not result.exec_sinks:
        print("  (none found)")
    for sink in result.exec_sinks:
        scope = " [test-only]" if sink.test_only else (" [build-time]" if sink.build_time else "")
        print(f"  {sink.file}:{sink.line} {sink.api} command={sink.command!r} class={sink.command_class}{scope}")

    print()
    print("Filesystem-write sinks:")
    if not result.write_sinks:
        print("  (none found)")
    for sink in result.write_sinks:
        scope = " [test-only]" if sink.test_only else (" [build-time]" if sink.build_time else "")
        print(f"  {sink.file}:{sink.line} {sink.api} target={sink.target!r} class={sink.target_class}{scope}")

    print()
    print("Baseline:")
    print(f"  network/IPC matched: {len(result.baseline_matched)}")
    print(f"  network/IPC unexpected: {len(result.baseline_unexpected)}")
    print(f"  network/IPC changed: {len(result.baseline_changed)}")
    print(f"  network/IPC missing: {len(result.baseline_missing)}")
    print(f"  exec matched: {len(result.baseline_exec_matched)}")
    print(f"  exec unexpected: {len(result.baseline_exec_unexpected)}")
    print(f"  exec missing: {len(result.baseline_exec_missing)}")
    print(f"  write missing: {len(result.baseline_write_missing)}")
    print(f"  write unexpected: {len(result.baseline_write_unexpected)}")
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
    for item in result.baseline_write_unexpected:
        print(f"  UNEXPECTED WRITE {item}")
    for item in result.baseline_write_missing:
        print(f"  MISSING WRITE {item}")
    for item in result.baseline_urls_unexpected:
        print(f"  UNEXPECTED URL {item}")
    if result.suppressed_findings:
        print(f"  accepted findings: {len(result.suppressed_findings)} (recorded in baseline)")

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

    if verbose and result.suppressed_findings:
        print()
        print("Accepted findings (baseline):")
        for item in result.suppressed_findings:
            print(f"  - {item}")

    if result.notes:
        print()
        print("Notes:")
        for note in result.notes:
            print(f"  - {note}")


def main(argv: Optional[list[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Static threat and network audit for kanata-switcher")
    parser.add_argument("repo", type=Path, help="Path to the kanata-switcher checkout")
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
    if not (root / "Cargo.toml").is_file() and not (root / ".git").exists():
        print(f"warning: {root} does not look like the kanata-switcher repo (no Cargo.toml/.git)", file=sys.stderr)

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
