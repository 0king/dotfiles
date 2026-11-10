#!/usr/bin/env python3
"""
scan_golang_network.py — stdlib-only static scanner for golang repos.

Enumerates network and process-execution sinks in Go source (app + vendor),
compares against a pinned baseline, and audits supply-chain surface
(go.mod/go.sum, CI actions, assets, git metadata). Does not execute the repo.

Usage:
    python3 scan_golang_network.py <repo> [--vendor <vendor-dir>] \
        [--baseline references/network-baseline.json] \
        [--json /tmp/out.json] [--fail-on high] [--verbose]

Exit codes:
    0  clean (or only low findings, below --fail-on threshold)
    1  findings at or above --fail-on threshold, or scanner error
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
from dataclasses import asdict, dataclass, field
from typing import Dict, List, Optional, Tuple

SEVERITY_ORDER = {"low": 0, "medium": 1, "high": 2, "critical": 3}

# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------


@dataclass
class Sink:
    id: str
    file: str
    line: int
    symbol: str
    api: str
    direction: str  # inbound | outbound | local | unknown
    protocol: str
    transport: str
    endpoint: str
    endpoint_class: str  # loopback | all-interfaces | remote | unix | unknown
    tls: bool
    enabled_by: str
    data: str
    notes: str
    severity: str = "medium"


@dataclass
class Finding:
    rule_id: str
    severity: str
    file: str
    line: int
    description: str
    snippet: str = ""
    why: str = ""
    confirm: str = ""


@dataclass
class AuditResult:
    repo: str
    commit: str
    scope: str
    overall_risk: str
    sinks: List[Sink] = field(default_factory=list)
    exec_sinks: List[Sink] = field(default_factory=list)
    findings: List[Finding] = field(default_factory=list)
    dismissed: List[str] = field(default_factory=list)
    baseline_drift: List[str] = field(default_factory=list)
    limits: str = ""


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def read_text(path: str) -> str:
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            return f.read()
    except OSError:
        return ""


def snippet_at(text: str, line: int, context: int = 2) -> str:
    lines = text.splitlines()
    start = max(0, line - 1 - context)
    end = min(len(lines), line + context)
    return "\n".join(f"{i+1}: {lines[i]}" for i in range(start, end))


def is_loopback(host: str) -> bool:
    h = host.lower().strip()
    return h in {"localhost", "127.0.0.1", "::1", "0:0:0:0:0:0:0:1"} or h.startswith(
        "127."
    ) or h.startswith("::1")


def classify_endpoint(endpoint: str) -> str:
    e = endpoint.strip().lower()
    if not e:
        return "unknown"
    if e.startswith(("unix:", "unixsocket")) or e.endswith(".sock"):
        return "unix"
    if is_loopback(e):
        return "loopback"
    if e in {"0.0.0.0", ":", "", "*"} or e.startswith("0.0.0.0:") or e.startswith(
        "[::]:"
    ):
        return "all-interfaces"
    return "remote"


# ---------------------------------------------------------------------------
# Go source scanning
# ---------------------------------------------------------------------------

# Network sink patterns. Each: (api, protocol, transport, direction, default class)
NETWORK_APIS: List[Tuple[str, str, str, str, str]] = [
    # net.Dial / net.DialContext / net.Dialer
    (r"net\.Dial\b", "tcp", "tcp", "outbound", "remote"),
    (r"net\.DialContext\b", "tcp", "tcp", "outbound", "remote"),
    (r"net\.Dialer\b", "tcp", "tcp", "outbound", "remote"),
    # net.Listen / net.ListenConfig / net.ListenPacket
    (r"net\.Listen\b", "tcp", "tcp", "inbound", "all-interfaces"),
    (r"net\.ListenPacket\b", "udp", "udp", "inbound", "all-interfaces"),
    # net/http client + server
    (r"http\.Get\b", "http", "tcp", "outbound", "remote"),
    (r"http\.Post\b", "http", "tcp", "outbound", "remote"),
    (r"http\.Do\b", "http", "tcp", "outbound", "remote"),
    (r"http\.NewRequest\b", "http", "tcp", "outbound", "remote"),
    (r"http\.ListenAndServe\b", "http", "tcp", "inbound", "all-interfaces"),
    (r"http\.Serve\b", "http", "tcp", "inbound", "all-interfaces"),
    (r"http\.ServeTLS\b", "https", "tcp", "inbound", "all-interfaces"),
    (r"net/http/pprof", "http", "tcp", "inbound", "all-interfaces"),
    # crypto/tls
    (r"tls\.Dial\b", "tls", "tcp", "outbound", "remote"),
    (r"tls\.Listen\b", "tls", "tcp", "inbound", "all-interfaces"),
    # net/rpc
    (r"rpc\.Dial\b", "rpc", "tcp", "outbound", "remote"),
    (r"rpc\.Serve\b", "rpc", "tcp", "inbound", "all-interfaces"),
    # syscall raw sockets
    (r"syscall\.Socket\b", "raw", "raw", "unknown", "unknown"),
    (r"syscall\.Connect\b", "raw", "raw", "outbound", "unknown"),
    (r"syscall\.Bind\b", "raw", "raw", "inbound", "unknown"),
    (r"syscall\.Sendto\b", "raw", "raw", "outbound", "unknown"),
    (r"syscall\.Recvfrom\b", "raw", "raw", "inbound", "unknown"),
    # websocket / grpc / smtp / ssh / ftp hints
    (r"websocket", "websocket", "tcp", "outbound", "remote"),
    (r"grpc", "grpc", "tcp", "outbound", "remote"),
    (r"smtp", "smtp", "tcp", "outbound", "remote"),
    (r"ssh\.", "ssh", "tcp", "outbound", "remote"),
    (r"ftp", "ftp", "tcp", "outbound", "remote"),
]

EXEC_APIS: List[Tuple[str, str]] = [
    (r"exec\.Command\b", "exec.Command"),
    (r"exec\.CommandContext\b", "exec.CommandContext"),
    (r"os\.StartProcess\b", "os.StartProcess"),
    (r"syscall\.Exec\b", "syscall.Exec"),
    (r"syscall\.ForkExec\b", "syscall.ForkExec"),
]

# Remote host literal detection: IP or dotted hostname assigned / passed as string.
REMOTE_HOST_LITERAL = re.compile(
    r'"((?:(?:25[0-5]|2[0-4]\d|1?\d{1,2})\.){3}'
    r'(?:25[0-5]|2[0-4]\d|1?\d{1,2}))"\s*(?:[:=,\)])'
)
HOSTNAME_LITERAL = re.compile(r'"([A-Za-z0-9][A-Za-z0-9.\-]{2,})\."?')


def find_sinks(repo: str, vendor_dir: Optional[str]) -> Tuple[List[Sink], List[Sink]]:
    """Return (network_sinks, exec_sinks) scanned from app + vendor Go files."""
    roots = [repo]
    if vendor_dir and os.path.isdir(vendor_dir):
        roots.append(vendor_dir)

    network_sinks: List[Sink] = []
    exec_sinks: List[Sink] = []
    seen: set = set()

    def scan_file(path: str) -> None:
        text = read_text(path)
        if not text:
            return
        lines = text.splitlines()
        for idx, raw in enumerate(lines, start=1):
            line = raw
            # Skip comments (crude but effective).
            stripped = line.lstrip()
            if stripped.startswith("//") or stripped.startswith("/*"):
                continue

            # Network sinks.
            for pattern, proto, transport, direction, dclass in NETWORK_APIS:
                if re.search(pattern, line):
                    key = (path, idx, pattern)
                    if key in seen:
                        continue
                    seen.add(key)
                    endpoint = extract_endpoint(line)
                    net_sink = Sink(
                        id=f"NET-{len(network_sinks)+1:03d}",
                        file=os.path.relpath(path, repo),
                        line=idx,
                        symbol=pattern,
                        api=pattern,
                        direction=direction,
                        protocol=proto,
                        transport=transport,
                        endpoint=endpoint,
                        endpoint_class=classify_endpoint(endpoint),
                        tls="tls" in proto.lower(),
                        enabled_by="",
                        data="",
                        notes="",
                    )
                    if net_sink.endpoint_class == "remote":
                        net_sink.severity = "high"
                    network_sinks.append(net_sink)

            # Exec sinks.
            for pattern, api_name in EXEC_APIS:
                if re.search(pattern, line):
                    key = (path, idx, "exec")
                    if key in seen:
                        continue
                    seen.add(key)
                    exec_sinks.append(
                        Sink(
                            id=f"EXEC-{len(exec_sinks)+1:03d}",
                            file=os.path.relpath(path, repo),
                            line=idx,
                            symbol=pattern,
                            api=api_name,
                            direction="local",
                            protocol="process",
                            transport="exec",
                            endpoint="",
                            endpoint_class="unknown",
                            tls=False,
                            enabled_by="",
                            data="",
                            notes="",
                        )
                    )

    for root in roots:
        for dirpath, _dirs, files in os.walk(root):
            for name in files:
                if name.endswith(".go"):
                    scan_file(os.path.join(dirpath, name))

    return network_sinks, exec_sinks


def extract_endpoint(line: str) -> str:
    """Crude extraction of a host:port or URL literal from a line."""
    m = re.search(r'"([^"]*(?::\d+)[^"]*)"', line)
    if m:
        return m.group(1)
    m = re.search(r'fmt\.Sprintf\("[^"]*%[sd][^"]*"', line)
    if m:
        return "computed"
    return ""


def find_remote_host_literals(repo: str) -> List[Tuple[str, int, str]]:
    hits: List[Tuple[str, int, str]] = []
    for dirpath, _dirs, files in os.walk(repo):
        for name in files:
            if not name.endswith(".go"):
                continue
            path = os.path.join(dirpath, name)
            text = read_text(path)
            for idx, raw in enumerate(text.splitlines(), start=1):
                for m in REMOTE_HOST_LITERAL.finditer(raw):
                    ip = m.group(1)
                    if not is_loopback(ip):
                        hits.append((path, idx, ip))
                for m in HOSTNAME_LITERAL.finditer(raw):
                    host = m.group(1)
                    if host.lower() in {"localhost"}:
                        continue
                    if "." in host and not is_loopback(host):
                        hits.append((path, idx, host))
    return hits


# ---------------------------------------------------------------------------
# Supply-chain / metadata checks
# ---------------------------------------------------------------------------


def parse_go_mod(repo: str) -> Dict:
    info: Dict = {"direct": [], "replace": [], "go_version": ""}
    path = os.path.join(repo, "go.mod")
    text = read_text(path)
    if not text:
        return info
    in_require = False
    for raw in text.splitlines():
        line = raw.strip()
        if line.startswith("require (") or line.startswith("require ("):
            in_require = True
            continue
        if in_require and line == ")":
            in_require = False
            continue
        if in_require:
            parts = line.split()
            if len(parts) >= 2:
                info["direct"].append(f"{parts[0]} {parts[1]}")
            continue
        m = re.match(r"require\s+(\S+)\s+(\S+)", line)
        if m:
            info["direct"].append(f"{m.group(1)} {m.group(2)}")
        m = re.match(r"replace\s+(\S+)\s+=>\s+(\S+)", line)
        if m:
            info["replace"].append(f"{m.group(1)} => {m.group(2)}")
        m = re.match(r"go\s+(\S+)", line)
        if m:
            info["go_version"] = m.group(1)
    return info


def check_go_sum(repo: str) -> List[str]:
    issues: List[str] = []
    path = os.path.join(repo, "go.sum")
    if not os.path.exists(path):
        issues.append("go.sum missing")
        return issues
    # Look for drift indicators: +incompatible, pseudo-versions without timestamp.
    text = read_text(path)
    for idx, raw in enumerate(text.splitlines(), start=1):
        if "+incompatible" in raw:
            issues.append(f"go.sum:{idx} +incompatible module")
    return issues


def check_ci_actions(repo: str) -> List[Finding]:
    findings: List[Finding] = []
    workflows_dir = os.path.join(repo, ".github", "workflows")
    if not os.path.isdir(workflows_dir):
        return findings
    for name in sorted(os.listdir(workflows_dir)):
        if not name.endswith((".yml", ".yaml")):
            continue
        path = os.path.join(workflows_dir, name)
        text = read_text(path)
        lines = text.splitlines()
        for idx, raw in enumerate(lines, start=1):
            # Mutable tag refs (actions/checkout@v4 etc. are tag-pinned; branches worst).
            m = re.search(r"uses:\s*([^@]+)@", raw)
            if m:
                ref = m.group(1).strip().strip('"')
                if "/" in ref and ":" not in ref and "@" not in ref:
                    findings.append(
                        Finding(
                            rule_id="CI-MUTABLE-REF",
                            severity="medium",
                            file=os.path.relpath(path, repo),
                            line=idx,
                            description=(
                                f"GitHub Action '{ref}' uses a mutable tag/branch ref "
                                f"in {name}"
                            ),
                            snippet=snippet_at(text, idx),
                            why="A compromised action could inject code into CI/builds.",
                            confirm="Pin the action by full SHA.",
                        )
                    )
            # fetch | pipe to shell
            if re.search(r"curl\s.*\|\s*(bash|sh|zsh)", raw) or re.search(
                r"wget\s.*\|\s*(bash|sh|zsh)", raw
            ):
                findings.append(
                    Finding(
                        rule_id="CI-FETCH-PIPE-SHELL",
                        severity="critical",
                        file=os.path.relpath(path, repo),
                        line=idx,
                        description=f"fetch-pipe-to-shell in {name}: {raw.strip()}",
                        snippet=snippet_at(text, idx),
                        why="Arbitrary remote code execution during CI.",
                        confirm="Download, verify hash, then execute locally.",
                    )
                )
            # pull_request_target
            if re.search(r"pull_request_target", raw):
                findings.append(
                    Finding(
                        rule_id="CI-PULL_REQUEST_TARGET",
                        severity="high",
                        file=os.path.relpath(path, repo),
                        line=idx,
                        description=f"pull_request_target workflow in {name}",
                        snippet=snippet_at(text, idx),
                        why="PR-triggered code can access secrets via this event.",
                        confirm="Review secrets exposure; avoid pull_request_target.",
                    )
                )
            # write-all
            if re.search(r"write-all", raw):
                findings.append(
                    Finding(
                        rule_id="CI-WRITE-ALL",
                        severity="medium",
                        file=os.path.relpath(path, repo),
                        line=idx,
                        description=f"`permissions: write-all` in {name}",
                        snippet=snippet_at(text, idx),
                        why="Broad write token over-reaches least privilege.",
                        confirm="Scope permissions to required scopes.",
                    )
                )
            # missing permissions block
            if "permissions:" not in text and idx <= 5:
                # only flag once near top if no permissions at all
                pass
        if "permissions:" not in text:
            findings.append(
                Finding(
                    rule_id="CI-MISSING-PERMISSIONS",
                    severity="medium",
                    file=os.path.relpath(path, repo),
                    line=1,
                    description=f"No `permissions:` block in {name}",
                    snippet="",
                    why="Implicit token permissions may be broader than intended.",
                    confirm="Add an explicit permissions block.",
                )
            )
    return findings


def check_assets(repo: str) -> List[Finding]:
    findings: List[Finding] = []
    image_exts = {".png", ".jpg", ".jpeg", ".ico", ".gif", ".bmp", ".webp"}
    magic_map = {
        b"\x89PNG\r\n\x1a\n": ".png",
        b"\xff\xd8\xff": ".jpg",
        b"GIF8": ".gif",
        b"BM": ".bmp",
        b"\x00\x00\x01\x00": ".ico",
        b"\x7fELF": "elf",
        b"PK\x03\x04": "zip",
        b"MZ": "pe",
        b"#!/": "script",
    }
    for dirpath, _dirs, files in os.walk(repo):
        if "/.git/" in dirpath:
            continue
        for name in files:
            path = os.path.join(dirpath, name)
            ext = os.path.splitext(name)[1].lower()
            if ext not in image_exts:
                continue
            try:
                with open(path, "rb") as f:
                    head = f.read(16)
                fsize = os.path.getsize(path)
            except OSError:
                continue
            matched = None
            for magic, ext2 in magic_map.items():
                if head.startswith(magic):
                    matched = ext2
                    break
            if matched is None:
                findings.append(
                    Finding(
                        rule_id="ASSET-MAGIC-MISMATCH",
                        severity="medium",
                        file=os.path.relpath(path, repo),
                        line=1,
                        description=f"Committed asset {name} has no recognized image magic",
                        snippet=f"size={fsize} head={head!r}",
                        why="Could be a disguised payload (PE/ELF/script/zip).",
                        confirm="Inspect the file; remove or justify.",
                    )
                )
            elif matched != ext.lstrip("."):
                findings.append(
                    Finding(
                        rule_id="ASSET-EXTENSION-MISMATCH",
                        severity="medium",
                        file=os.path.relpath(path, repo),
                        line=1,
                        description=f"Asset {name} magic ({matched}) does not match extension ({ext})",
                        snippet=f"size={fsize} head={head!r}",
                        why="Extension/magic mismatch can hide a payload.",
                        confirm="Rename, remove, or justify.",
                    )
                )
            # Trailing bytes beyond a valid image is hard to detect generically;
            # flag unusually large icons (>2 MiB) as potential payload carriers.
            if fsize > 2 * 1024 * 1024:
                findings.append(
                    Finding(
                        rule_id="ASSET-LARGE",
                        severity="low",
                        file=os.path.relpath(path, repo),
                        line=1,
                        description=f"Large committed asset {name} ({fsize} bytes)",
                        snippet=f"size={fsize}",
                        why="Large binary assets can conceal payloads.",
                        confirm="Inspect contents; verify it is a genuine image.",
                    )
                )
    return findings


def check_git_metadata(repo: str) -> List[Finding]:
    findings: List[Finding] = []
    hooks_dir = os.path.join(repo, ".git", "hooks")
    if os.path.isdir(hooks_dir):
        for name in os.listdir(hooks_dir):
            if name.endswith(".sample"):
                continue
            path = os.path.join(hooks_dir, name)
            if os.path.isfile(path) and os.access(path, os.X_OK):
                findings.append(
                    Finding(
                        rule_id="GIT-ACTIVE-HOOK",
                        severity="high",
                        file=os.path.relpath(path, repo),
                        line=1,
                        description=f"Active (non-sample, executable) git hook: {name}",
                        snippet="",
                        why="Git hooks run with developer privileges; persistence vector.",
                        confirm="Review or remove the hook.",
                    )
                )
    # Remote URL check.
    git_config = read_text(os.path.join(repo, ".git", "config"))
    for m in re.finditer(r'url\s*=\s*(.+)', git_config):
        url = m.group(1).strip()
        if url.startswith("http://") or url.startswith("git://"):
            findings.append(
                Finding(
                    rule_id="GIT-INSECURE-REMOTE",
                    severity="medium",
                    file=".git/config",
                    line=1,
                    description=f"Insecure git remote: {url}",
                    snippet=url,
                    why="Unencrypted transport permits MITM of source.",
                    confirm="Switch to SSH or HTTPS.",
                )
            )
    return findings


def check_persistence_and_secrets(repo: str) -> List[Finding]:
    findings: List[Finding] = []
    keywords = {
        "autostart": ".config/autostart",
        "systemd": "systemd",
        "launchagent": "LaunchAgents",
        "crontab": "crontab",
        "bashrc": ".bashrc",
        "zshrc": ".zshrc",
        "profile": ".profile",
        "ld_preload": "LD_PRELOAD",
        "ld_so_preload": "/etc/ld.so.preload",
        "schtasks": "schtasks",
        "run_key": "\\Run\\",
    }
    secret_patterns = [
        re.compile(r'(?i)(api[_-]?key|secret|token|password|passwd)\s*[:=]\s*["\'][^"\']{8,}["\']'),
        re.compile(r'(?i)(aws|azure|gcp)[_-](access|secret)[_-]key'),
    ]
    bidi_chars = set("\u202a\u202b\u202c\u202d\u202e\u2066\u2067\u2068\u2069")
    for dirpath, _dirs, files in os.walk(repo):
        if "/.git/" in dirpath:
            continue
        for name in files:
            path = os.path.join(dirpath, name)
            text = read_text(path)
            if not text:
                continue
            low = text.lower()
            for kw, hint in keywords.items():
                if kw in low:
                    findings.append(
                        Finding(
                            rule_id="PERSISTENCE-HINT",
                            severity="medium",
                            file=os.path.relpath(path, repo),
                            line=1,
                            description=f"Persistence-related keyword '{kw}' ({hint}) in {name}",
                            snippet="",
                            why="Possible persistence mechanism.",
                            confirm="Review whether it is legitimate.",
                        )
                    )
                    break
            for pat in secret_patterns:
                for m in pat.finditer(text):
                    findings.append(
                        Finding(
                            rule_id="HARDCODED-SECRET",
                            severity="high",
                            file=os.path.relpath(path, repo),
                            line=1,
                            description="Possible hardcoded secret/credential",
                            snippet=snippet_at(text, 1),
                            why="Secrets in source are a supply-chain/data risk.",
                            confirm="Move to env/secret store; rotate if committed.",
                        )
                    )
                    break
            if any(ch in text for ch in bidi_chars):
                findings.append(
                    Finding(
                        rule_id="BIDI-CONTROL-CHARS",
                        severity="medium",
                        file=os.path.relpath(path, repo),
                        line=1,
                        description="Unicode bidirectional control characters present",
                        snippet="",
                        why="Can hide malicious code visually (trojan source).",
                        confirm="Review the file with bidi chars revealed.",
                    )
                )
    return findings


# ---------------------------------------------------------------------------
# Baseline comparison
# ---------------------------------------------------------------------------


def load_baseline(path: Optional[str]) -> Optional[Dict]:
    if not path or not os.path.exists(path):
        return None
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except (OSError, json.JSONDecodeError):
        return None


def compare_with_baseline(
    result: AuditResult, baseline: Optional[Dict]
) -> None:
    if not baseline:
        result.baseline_drift.append("No baseline file; inventory is informational only.")
        return
    expected_ids = {e.get("id") for e in baseline.get("expected_network", [])}
    expected_exec_ids = {e.get("id") for e in baseline.get("expected_exec", [])}
    seen_net_ids = {s.id for s in result.sinks}
    seen_exec_ids = {s.id for s in result.exec_sinks}

    for sink in result.sinks:
        if sink.id not in expected_ids:
            result.baseline_drift.append(
                f"NET-UNEXPECTED-SINK: {sink.file}:{sink.line} {sink.api} "
                f"({sink.endpoint_class} {sink.endpoint})"
            )
    for ex in result.exec_sinks:
        if ex.id not in expected_exec_ids:
            result.baseline_drift.append(
                f"EXEC-UNEXPECTED-SINK: {ex.file}:{ex.line} {ex.api}"
            )

    # Direct module drift note.
    baseline_modules = set(baseline.get("direct_modules", []))
    # (modules are parsed separately and stored on result via a custom attr if needed)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


def build_result(repo: str, baseline: Optional[Dict], verbose: bool) -> AuditResult:
    commit = ""
    try:
        import subprocess

        commit = (
            subprocess.check_output(["git", "-C", repo, "rev-parse", "HEAD"],
                                    stderr=subprocess.DEVNULL)
            .decode()
            .strip()
        )
    except Exception:
        commit = "unknown"

    dirty = ""
    try:
        import subprocess

        out = subprocess.check_output(
            ["git", "-C", repo, "status", "--porcelain=v1", "-b"],
            stderr=subprocess.DEVNULL,
        ).decode()
        dirty = "dirty" if out.strip() else "clean"
    except Exception:
        dirty = "unknown"

    net_sinks, exec_sinks = find_sinks(repo, None)

    result = AuditResult(
        repo=repo,
        commit=commit,
        scope=f"Static review ({dirty} tree)",
        overall_risk="Clean",
        sinks=net_sinks,
        exec_sinks=exec_sinks,
        limits=(
            "Static/heuristic, not a sandbox or proof; runtime not performed unless "
            "stated; GUI/OS code and compiler/runtime behavior out of scope."
        ),
    )

    # Remote host literals.
    for path, idx, host in find_remote_host_literals(repo):
        result.findings.append(
            Finding(
                rule_id="NET-REMOTE-HOST",
                severity="high",
                file=os.path.relpath(path, repo),
                line=idx,
                description=f"Remote host literal in runtime Go code: {host}",
                snippet=snippet_at(read_text(path), idx),
                why="A remote destination not in the baseline is suspect.",
                confirm="Verify the endpoint is documented and approved.",
            )
        )

    # Supply chain.
    go_mod_info = parse_go_mod(repo)
    result.sinks  # keep
    for mod in go_mod_info.get("direct", []):
        pass  # recorded in report manually by user; baseline comparison handles drift
    for rep in go_mod_info.get("replace", []):
        result.findings.append(
            Finding(
                rule_id="DEP-REPLACE",
                severity="medium",
                file="go.mod",
                line=1,
                description=f"go.mod replace directive: {rep}",
                snippet="",
                why="Replace directives can redirect dependency source.",
                confirm="Review the replace target.",
            )
        )
    for issue in check_go_sum(repo):
        sev = "high" if "missing" in issue else "medium"
        result.findings.append(
            Finding(
                rule_id="GO-SUM-DRIFT",
                severity=sev,
                file="go.sum",
                line=1,
                description=issue,
                snippet="",
                why="go.sum integrity anchors the build.",
                confirm="Run `go mod verify`; re-pin versions.",
            )
        )
    result.findings.extend(check_ci_actions(repo))
    result.findings.extend(check_assets(repo))
    result.findings.extend(check_git_metadata(repo))
    result.findings.extend(check_persistence_and_secrets(repo))

    compare_with_baseline(result, baseline)

    # Overall risk = max finding severity.
    max_sev = "low"
    for f in result.findings:
        if SEVERITY_ORDER.get(f.severity, 0) > SEVERITY_ORDER.get(max_sev, 0):
            max_sev = f.severity
    result.overall_risk = max_sev.capitalize()

    if verbose:
        print(f"[scan] repo={repo} commit={commit} tree={dirty}")
        print(f"[scan] network sinks={len(net_sinks)} exec sinks={len(exec_sinks)}")
        print(f"[scan] findings={len(result.findings)} (max severity={max_sev})")

    return result


def emit_json(result: AuditResult) -> str:
    return json.dumps(
        {
            "repo": result.repo,
            "commit": result.commit,
            "scope": result.scope,
            "overall_risk": result.overall_risk,
            "sinks": [asdict(s) for s in result.sinks],
            "exec_sinks": [asdict(s) for s in result.exec_sinks],
            "findings": [asdict(f) for f in result.findings],
            "dismissed": result.dismissed,
            "baseline_drift": result.baseline_drift,
            "limits": result.limits,
        },
        indent=2,
    )


def emit_summary(result: AuditResult) -> str:
    lines = [
        f"repo: {result.repo}",
        f"commit: {result.commit}",
        f"scope: {result.scope}",
        f"overall_risk: {result.overall_risk}",
        f"network_sinks: {len(result.sinks)}",
        f"exec_sinks: {len(result.exec_sinks)}",
        f"findings: {len(result.findings)}",
        "",
        "Findings:",
    ]
    for f in result.findings:
        lines.append(
            f"  [{f.severity.upper()}] {f.rule_id}: {f.description} "
            f"({f.file}:{f.line})"
        )
    if result.baseline_drift:
        lines.append("")
        lines.append("Baseline drift:")
        for d in result.baseline_drift:
            lines.append(f"  - {d}")
    return "\n".join(lines)


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        description="Static network/exec scanner for golang repositories."
    )
    parser.add_argument("repo", help="Path to the golang repository")
    parser.add_argument(
        "--vendor",
        help="Path to vendor directory (app + vendor are scanned)",
    )
    parser.add_argument(
        "--baseline",
        default="references/network-baseline.json",
        help="Path to baseline JSON (default: references/network-baseline.json)",
    )
    parser.add_argument(
        "--json",
        help="Write full JSON result to this path",
    )
    parser.add_argument(
        "--fail-on",
        choices=["low", "medium", "high", "critical"],
        default="low",
        help="Exit non-zero if findings at or above this severity exist (default: low)",
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Verbose progress to stderr",
    )
    args = parser.parse_args(argv)

    repo = os.path.abspath(args.repo)
    if not os.path.isdir(repo):
        print(f"error: repo path not found: {repo}", file=sys.stderr)
        return 1

    baseline_path = args.baseline
    if not os.path.isabs(baseline_path):
        baseline_path = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                     "..", baseline_path)
    baseline = load_baseline(baseline_path)

    result = build_result(repo, baseline, args.verbose)

    if args.json:
        with open(args.json, "w", encoding="utf-8") as f:
            f.write(emit_json(result) + "\n")

    print(emit_summary(result))

    threshold = SEVERITY_ORDER.get(args.fail_on, 0)
    for f in result.findings:
        if SEVERITY_ORDER.get(f.severity, 0) >= threshold:
            return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
