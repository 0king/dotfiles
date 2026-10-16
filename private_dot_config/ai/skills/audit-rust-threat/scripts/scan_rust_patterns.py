#!/usr/bin/env python3
"""
scan_rust_patterns.py - Rust-focused heuristic scanner for hidden malware.

Complements the general repo-threat-audit scanner with checks specific to
Cargo/Rust supply chains, build scripts, proc macros, and networking patterns.

Usage:
    python3 scan_rust_patterns.py <repo-path> [--include-deps] [--json out.json]
"""

import argparse
import json
import os
import re
import sys

DEFAULT_SKIP_DIRS = {
    ".git", "node_modules", "vendor", "venv", ".venv", "target",
    "__pycache__", "dist", "build", ".tox",
}

RUST_EXTS = {".rs", ".toml"}
RUST_NAMES = {"Cargo.toml", "Cargo.lock", "build.rs", "rust-toolchain.toml"}

# Common typosquat / suspicious crate name shapes (heuristic, not exhaustive)
TYPOSQUAT_RE = re.compile(
    r"^\s*(?:[a-zA-Z0-9_-]+\s*=\s*\{[^}]*name\s*=\s*[\"']([^\"']+)[\"']|"
    r"([a-zA-Z0-9_-]+)\s*=\s*[\"'][^\"']+[\"'])",
    re.M,
)
SUSPICIOUS_CRATE_NAMES = {
    "reqeusts", "request", "rustls-native-certs-fake", "libcrypto",
    "openssl-sys-fake", "serde_jsonn", "tokioo", "hyperr",
}

LINE_RULES = [
    dict(id="RS-NET-001", severity="medium",
         desc="HTTP client crate usage (reqwest, ureq, hyper, isahc, surf). "
              "Legitimate for many apps; flag for triage when unexpected in "
              "a keyboard driver, CLI tool, or library with no stated network need.",
         exts={".rs", ".toml"},
         pattern=re.compile(r"\b(reqwest|ureq|isahc|surf|awc)\b|"
                             r"hyper::|hyper_util::")),
    dict(id="RS-NET-002", severity="medium",
         desc="Raw TCP/UDP socket API (TcpListener, TcpStream, UdpSocket). "
              "May be local IPC only — read bind/connect addresses and whether "
              "the listener starts by default.",
         exts={".rs"},
         pattern=re.compile(r"\b(TcpListener|TcpStream|UdpSocket)::"
                             r"(bind|connect|connect_timeout|send_to|recv_from)")),
    dict(id="RS-NET-003", severity="low",
         desc="DNS resolution or socket address parsing — often paired with "
              "outbound connections. Check what hostname is resolved.",
         exts={".rs"},
         pattern=re.compile(r"\b(to_socket_addrs|lookup_host|"
                             r"std::net::ToSocketAddrs)\b")),
    dict(id="RS-NET-004", severity="medium",
         desc="WebSocket or gRPC client/server crates — persistent network channel.",
         exts={".rs", ".toml"},
         pattern=re.compile(r"\b(tungstenite|tokio_tungstenite|tonic|"
                             r"grpcio|async_tungstenite)\b")),
    dict(id="RS-EXEC-001", severity="high",
         desc="Spawns an external process via std::process::Command. "
              "Legitimate for build tooling and opt-in features; suspicious "
              "when fed user/config input without validation or in build.rs.",
         exts={".rs"},
         pattern=re.compile(r"std::process::Command::new|Command::new\s*\(")),
    dict(id="RS-EXEC-002", severity="high",
         desc="Shell invocation (-c / /C /cmd / powershell). Runs through "
              "a shell interpreter — higher injection risk than direct exec.",
         exts={".rs"},
         pattern=re.compile(r"\.arg\s*\(\s*[\"']-c[\"']\)|"
                             r"\.args\s*\(\s*&?\[[^\]]*[\"']-c[\"']|"
                             r"\.arg\s*\(\s*[\"']/?(?:bin/)?(?:ba)?sh[\"']\)|"
                             r"\.arg\s*\(\s*[\"']cmd(?:\\.exe)?[\"']\)|"
                             r"\.arg\s*\(\s*[\"']powershell")),
    dict(id="RS-BUILD-001", severity="high",
         desc="build.rs shells out to an external command. Build scripts run "
              "automatically on every `cargo build` — network or download here "
              "is a supply-chain vector.",
         exts={".rs"},
         names={"build.rs"},
         pattern=re.compile(r"Command::new|std::process::Command")),
    dict(id="RS-BUILD-002", severity="medium",
         desc="build.rs sets compile-time env vars via cargo:rustc-env. "
              "Can embed secrets or C2 URLs into the binary at build time.",
         exts={".rs"},
         names={"build.rs"},
         pattern=re.compile(r'println!\(\s*"cargo:rustc-env=')),
    dict(id="RS-CARGO-001", severity="high",
         desc="Dependency pinned to a git URL instead of crates.io. Harder "
              "to audit and can change if the git ref is a branch.",
         exts={".toml"},
         names={"Cargo.toml"},
         pattern=re.compile(r"git\s*=\s*[\"']https?://")),
    dict(id="RS-CARGO-002", severity="medium",
         desc="Cargo [patch] section redirecting a crate to git or a local path. "
              "Can silently substitute upstream code — read the patch target.",
         exts={".toml"},
         names={"Cargo.toml"},
         pattern=re.compile(r"^\s*\[patch", re.M)),
    dict(id="RS-LOAD-001", severity="high",
         desc="Dynamic library loading (libloading, dlopen, LoadLibrary). "
              "Can load attacker-controlled code at runtime.",
         exts={".rs", ".toml"},
         pattern=re.compile(r"\b(libloading|Library::new|dlopen|"
                             r"LoadLibraryW?|GetProcAddress)\b")),
    dict(id="RS-OBF-001", severity="high",
         desc="Embedded binary payload via include_bytes!/include_str! — "
              "check whether the blob is decoded or executed afterward.",
         exts={".rs"},
         pattern=re.compile(r"\binclude_bytes!\s*\(|\binclude_str!\s*\(")),
    dict(id="RS-OBF-002", severity="medium",
         desc="Base64 decode in Rust source — benign for many formats; "
              "concerning if output is written to disk or passed to Command.",
         exts={".rs"},
         pattern=re.compile(r"base64::|BASE64|Engine::decode|"
                             r"general_purpose::STANDARD\.decode")),
    dict(id="RS-UNSAFE-001", severity="low",
         desc="unsafe block — not malicious by itself, but malware and "
              "rootkits often use unsafe for FFI and memory tricks. "
              "Read context when paired with network or dlopen.",
         exts={".rs"},
         pattern=re.compile(r"\bunsafe\s*\{|\bunsafe\s+fn\b|\bunsafe\s+extern\b")),
    dict(id="RS-ENV-001", severity="medium",
         desc="Reads environment variables — check if values are sent over "
              "the network or logged externally.",
         exts={".rs"},
         pattern=re.compile(r"std::env::var|env::var_os|std::env::vars\s*\(")),
    dict(id="RS-FILE-001", severity="high",
         desc="Writes to a path under home, /etc, or system config dirs — "
              "possible persistence or config tampering.",
         exts={".rs"},
         pattern=re.compile(r"\.write(?:_all)?\(|OpenOptions::new\(\)[^\n]{0,80}\.write|"
                             r"fs::write\s*\(")),
    dict(id="RS-PERSIST-001", severity="high",
         desc="References autostart, systemd user units, cron, shell rc, "
              "or LD_PRELOAD paths from Rust code.",
         exts={".rs"},
         pattern=re.compile(r"\.config/autostart|systemd/user|/etc/cron|"
                             r"\.bashrc|\.zshrc|LD_PRELOAD|ld\.so\.preload")),
    dict(id="RS-PROC-001", severity="medium",
         desc="Proc-macro crate attribute or macro export — macro crates can "
              "hide code from casual review. Read the macro expansion target.",
         exts={".rs"},
         pattern=re.compile(r"#\[proc_macro(_attribute|_derive)?\]|"
                             r"proc_macro::TokenStream")),
    dict(id="RS-WASM-001", severity="medium",
         desc="WASM web API fetch/XHR patterns — browser-side network from "
              "compiled Rust. Expected in wasm frontends; unexpected elsewhere.",
         exts={".rs"},
         pattern=re.compile(r"web_sys::.*[Ff]etch|wasm_bindgen_futures|"
                             r"XmlHttpRequest")),
    dict(id="RS-TELEM-001", severity="low",
         desc="Telemetry/analytics crate names (sentry, segment, mixpanel, "
              "posthog, amplitude). May phone home — verify what's sent.",
         exts={".rs", ".toml"},
         pattern=re.compile(r"\b(sentry|segment|mixpanel|posthog|amplitude|"
                             r"opentelemetry|tracing_opentelemetry)\b")),
    dict(id="SECRET-001", severity="high",
         desc="Hardcoded private key block.",
         exts={".rs", ".toml"},
         pattern=re.compile(r"-----BEGIN (RSA |OPENSSH |EC |DSA )?PRIVATE KEY-----")),
]

FILE_RULES = [
    dict(id="RS-FILE-002", severity="critical",
         desc="Same file reads credentials/SSH keys AND references outbound "
              "HTTP/network APIs — strong exfil candidate.",
         exts={".rs"},
         patterns=[
             re.compile(r"(\.ssh/id_|\.aws/credentials|\.git-credentials|"
                         r"\.npmrc|id_rsa|id_ed25519)"),
             re.compile(r"\b(reqwest|ureq|TcpStream::connect|"
                         r"hyper::|isahc|surf|awc)\b"),
         ],
         point_at=0),
    dict(id="RS-FILE-003", severity="critical",
         desc="build.rs both shells out AND references network/download URLs — "
              "classic supply-chain fetch-at-build-time pattern.",
         exts={".rs"},
         names={"build.rs"},
         patterns=[
             re.compile(r"Command::new|std::process::Command"),
             re.compile(r"https?://|reqwest|ureq|TcpStream|curl|wget"),
         ],
         point_at=0),
    dict(id="RS-FILE-004", severity="high",
         desc="Decodes embedded/base64 data and spawns a process in the same file.",
         exts={".rs"},
         patterns=[
             re.compile(r"base64::|Engine::decode|general_purpose::STANDARD"),
             re.compile(r"Command::new|std::process::Command"),
         ],
         point_at=0),
]


def iter_files(root, include_deps, max_bytes):
    for dirpath, dirnames, filenames in os.walk(root):
        if not include_deps:
            dirnames[:] = [d for d in dirnames if d not in DEFAULT_SKIP_DIRS]
        for name in filenames:
            ext = os.path.splitext(name)[1]
            if ext not in RUST_EXTS and name not in RUST_NAMES:
                continue
            path = os.path.join(dirpath, name)
            try:
                if os.path.getsize(path) > max_bytes:
                    continue
            except OSError:
                continue
            yield path, name, ext


def check_typosquat_cargo(path, text):
    findings = []
    if not path.endswith("Cargo.toml"):
        return findings
    for line in text.splitlines():
        m = re.match(r"^\s*([a-zA-Z0-9_-]+)\s*=", line)
        if not m:
            continue
        crate = m.group(1)
        if crate in SUSPICIOUS_CRATE_NAMES:
            findings.append({
                "rule_id": "RS-CARGO-003",
                "severity": "high",
                "description": "Dependency name matches a known typosquat/suspicious "
                                "crate name shape. Verify the crate on crates.io.",
                "file": path,
                "line": text[:text.find(line)].count("\n") + 1,
                "snippet": line.strip()[:200],
            })
    return findings


def scan_file(path, name, ext):
    findings = []
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            text = f.read()
    except OSError:
        return findings

    lines = text.splitlines()

    for rule in LINE_RULES:
        if ext not in rule["exts"]:
            continue
        if "names" in rule and name not in rule["names"]:
            continue
        for m in rule["pattern"].finditer(text):
            line_no = text.count("\n", 0, m.start()) + 1
            snippet = lines[line_no - 1].strip() if 0 < line_no <= len(lines) else ""
            findings.append({
                "rule_id": rule["id"],
                "severity": rule["severity"],
                "description": rule["desc"],
                "file": path,
                "line": line_no,
                "snippet": snippet[:200],
            })

    for rule in FILE_RULES:
        if ext not in rule["exts"]:
            continue
        if "names" in rule and name not in rule["names"]:
            continue
        if not all(p.search(text) for p in rule["patterns"]):
            continue
        m = rule["patterns"][rule["point_at"]].search(text)
        line_no = text.count("\n", 0, m.start()) + 1 if m else 1
        snippet = lines[line_no - 1].strip() if 0 < line_no <= len(lines) else ""
        findings.append({
            "rule_id": rule["id"],
            "severity": rule["severity"],
            "description": rule["desc"],
            "file": path,
            "line": line_no,
            "snippet": snippet[:200],
        })

    findings.extend(check_typosquat_cargo(path, text))
    return findings


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("path")
    ap.add_argument("--include-deps", action="store_true",
                    help="Also scan target/ and vendored trees (slow, noisy)")
    ap.add_argument("--max-file-mb", type=float, default=2.0)
    ap.add_argument("--json", default=None)
    args = ap.parse_args()

    max_bytes = int(args.max_file_mb * 1024 * 1024)
    all_findings = []
    files_scanned = 0

    for path, name, ext in iter_files(args.path, args.include_deps, max_bytes):
        files_scanned += 1
        all_findings.extend(scan_file(path, name, ext))

    order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    all_findings.sort(key=lambda f: (order.get(f["severity"], 9), f["file"], f["line"]))

    result = {
        "root": os.path.abspath(args.path),
        "files_scanned": files_scanned,
        "findings_count": len(all_findings),
        "findings": all_findings,
    }

    print(json.dumps(result, indent=2))
    if args.json:
        with open(args.json, "w") as f:
            json.dump(result, f, indent=2)


if __name__ == "__main__":
    main()
