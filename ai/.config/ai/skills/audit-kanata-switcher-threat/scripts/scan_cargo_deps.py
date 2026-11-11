#!/usr/bin/env python3
"""Offline supply-chain audit for the kanata-switcher Cargo dependency graph.

This script never executes the repository, never contacts the network, and
never writes into the checkout. It answers four questions:

  1. Is every locked package a crates.io package with a SHA-256 checksum?
  2. Do the manifest pins and registry configuration still match the baseline?
  3. Which locked crates run build scripts, export proc macros, or link native
     libraries (the places where a dependency can execute code at build time)?
  4. Which crates are network-capable, and are they expected in this project?

Crate *sources* are only inspected when they are already present in the local
Cargo registry cache. Missing sources are reported as "not scanned", not as
clean. Use `cargo fetch --locked` before the audit to make the deep pass
meaningful.

Exit codes: 0 = no findings at/above --fail-on, 1 = findings, 2 = usage error.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
import tomllib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

CRATES_IO_SOURCES = {
    "registry+https://github.com/rust-lang/crates.io-index",
    "sparse+https://index.crates.io/",
}

# Crates that can open sockets, speak HTTP/TLS/DNS, or tunnel traffic. This is
# intentionally broader than the direct dependency list: a transitive crate is
# still part of the runtime surface.
NETWORK_CRATES = {
    "reqwest", "hyper", "hyper-util", "h2", "http", "http-body", "http-body-util",
    "ureq", "surf", "isahc", "attohttpc", "curl", "curl-sys", "libcurl-sys",
    "openssl", "openssl-sys", "rustls", "rustls-native-certs", "webpki-roots",
    "native-tls", "schannel", "security-framework", "tokio-native-tls",
    "tokio-rustls", "tokio-tungstenite", "tungstenite", "async-tungstenite",
    "quinn", "quinn-proto", "quinn-udp", "tonic", "prost", "h3", "h3-quinn",
    "trust-dns-proto", "trust-dns-resolver", "hickory-proto", "hickory-resolver",
    "hickory-client", "hickory-server", "socket2", "mio", "async-io", "polling",
    "smol", "async-net", "async-std", "tokio", "tokio-util",
    "ssh2", "libssh2-sys", "russh", "russh-sftp", "thrussh",
    "redis", "mongodb", "sqlx", "tokio-postgres", "postgres", "mysql",
    "lapin", "amiquip", "rumqttc", "paho-mqtt", "zmq", "zeromq",
    "signal-hook", "nix", "libc", "socket2",
    # Local IPC / desktop transports: not IP, but still part of the network
    # surface and worth inventorying.
    "dbus", "libdbus-sys", "dbus-codegen", "ksni", "zbus",
    "wayland-client", "wayland-backend", "wayland-scanner",
    "x11rb", "x11rb-protocol",
}

# Build-script behaviors that can turn a build into network or code execution.
BUILD_NETWORK_PATTERNS = [
    (r"\bcurl\b|\bwget\b", "build script references curl/wget"),
    (r"reqwest|ureq|hyper::|attohttpc|isahc|surf::", "build script uses an HTTP client"),
    (r"TcpStream|UdpSocket|std::net|tokio::net", "build script opens a socket"),
    (r"Command::new\s*\(\s*\"(?:git|curl|wget|bash|sh|powershell|python)", "build script executes a downloader/shell"),
    (r"git clone|https?://", "build script contains a remote URL or clone"),
    (r"include_bytes!\s*\(\s*\"(?:/|\.\./)", "build script embeds a file from outside the crate"),
    (r"include_str!\s*\(\s*\"(?:/|\.\./)", "build script embeds a file from outside the crate"),
    (r"dlopen|libloading|std::process::Command", "build script can load or execute native code"),
]

NATIVE_LINK_HINTS = ("links =", "cc::Build", "pkg_config", "bindgen", "cmake", "nasm")

SEVERITY_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


@dataclass
class Finding:
    rule: str
    severity: str
    path: str
    detail: str

    def as_dict(self) -> dict[str, str]:
        return {
            "rule": self.rule,
            "severity": self.severity,
            "path": self.path,
            "detail": self.detail,
        }


@dataclass
class Report:
    repo: str
    lock_sha256: str = ""
    package_count: int = 0
    direct_crates: list[str] = field(default_factory=list)
    dev_crates: list[str] = field(default_factory=list)
    build_dependencies: list[str] = field(default_factory=list)
    source_classes: dict[str, int] = field(default_factory=dict)
    checksum_missing: list[str] = field(default_factory=list)
    checksum_mismatch: list[str] = field(default_factory=list)
    build_scripts: list[str] = field(default_factory=list)
    proc_macro_crates: list[str] = field(default_factory=list)
    native_crates: list[str] = field(default_factory=list)
    network_crates: list[str] = field(default_factory=list)
    scanned_sources: int = 0
    missing_sources: list[str] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)

    def add(self, rule: str, severity: str, path: str, detail: str) -> None:
        self.findings.append(Finding(rule, severity, path, detail))

    def as_dict(self) -> dict[str, Any]:
        data = {
            "repo": self.repo,
            "lock_sha256": self.lock_sha256,
            "package_count": self.package_count,
            "direct_crates": self.direct_crates,
            "dev_crates": self.dev_crates,
            "build_dependencies": self.build_dependencies,
            "source_classes": self.source_classes,
            "checksum_missing": self.checksum_missing,
            "checksum_mismatch": self.checksum_mismatch,
            "build_scripts": self.build_scripts,
            "proc_macro_crates": self.proc_macro_crates,
            "native_crates": self.native_crates,
            "network_crates": self.network_crates,
            "scanned_sources": self.scanned_sources,
            "missing_sources": self.missing_sources,
            "findings": [f.as_dict() for f in self.findings],
            "notes": self.notes,
        }
        return data


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def parse_manifest_deps(manifest: dict[str, Any]) -> tuple[list[str], list[str], list[str], list[str]]:
    """Return (direct, dev, build, unpinned) normalized name=version strings."""
    groups = [
        ("normal", manifest.get("dependencies", {})),
        ("dev", manifest.get("dev-dependencies", {})),
        ("build", manifest.get("build-dependencies", {})),
    ]
    for target in manifest.get("target", {}).values():
        groups.append(("normal", target.get("dependencies", {})))
        groups.append(("dev", target.get("dev-dependencies", {})))
        groups.append(("build", target.get("build-dependencies", {})))

    direct: list[str] = []
    dev: list[str] = []
    build: list[str] = []
    unpinned: list[str] = []
    for kind, deps in groups:
        for name, spec in deps.items():
            version = ""
            if isinstance(spec, str):
                version = spec
            elif isinstance(spec, dict):
                version = str(spec.get("version", ""))
                if any(k in spec for k in ("git", "path")):
                    unpinned.append(f"{name} ({'git' if 'git' in spec else 'path'})")
                    continue
                if spec.get("workspace"):
                    unpinned.append(f"{name} (workspace)")
                    continue
            entry = f"{name} {version}".strip()
            if version and not version.startswith("="):
                unpinned.append(entry)
            {"normal": direct, "dev": dev, "build": build}[kind].append(entry)
    return sorted(direct), sorted(dev), sorted(build), sorted(unpinned)


def lock_packages(lock: dict[str, Any]) -> list[dict[str, Any]]:
    return [p for p in lock.get("package", []) if isinstance(p, dict)]


def cargo_registry_roots() -> list[Path]:
    home = Path(os.environ.get("CARGO_HOME", Path.home() / ".cargo"))
    return [home / "registry" / "src", home / "registry" / "cache"]


def find_crate_source(name: str, version: str) -> Path | None:
    for root in cargo_registry_roots():
        if not root.is_dir():
            continue
        for registry in root.iterdir():
            candidate = registry / f"{name}-{version}"
            if candidate.is_dir():
                return candidate
    return None


def find_crate_archive(name: str, version: str) -> Path | None:
    home = Path(os.environ.get("CARGO_HOME", Path.home() / ".cargo"))
    cache = home / "registry" / "cache"
    if not cache.is_dir():
        return None
    for registry in cache.iterdir():
        candidate = registry / f"{name}-{version}.crate"
        if candidate.is_file():
            return candidate
    return None


def scan_crate_source(
    source: Path, name: str, version: str, report: Report
) -> None:
    report.scanned_sources += 1
    manifest_path = source / "Cargo.toml"
    manifest: dict[str, Any] = {}
    if manifest_path.is_file():
        try:
            manifest = tomllib.loads(manifest_path.read_text(encoding="utf-8"))
        except (OSError, tomllib.TOMLDecodeError) as exc:
            report.add("DEP-MANIFEST-UNREADABLE", "medium", str(manifest_path), str(exc))

    build_rel = manifest.get("package", {}).get("build", "build.rs")
    build_path: Path | None = None
    if isinstance(build_rel, str):
        build_path = source / build_rel
    elif build_rel is not False:
        build_path = source / "build.rs"
    if build_path is not None and build_path.is_file():
        report.build_scripts.append(f"{name} {version}")
        try:
            build_text = build_path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            build_text = ""
        for pattern, reason in BUILD_NETWORK_PATTERNS:
            if re.search(pattern, build_text):
                report.add(
                    "DEP-BUILD-SCRIPT-RISK",
                    "high" if "HTTP" in reason or "socket" in reason or "downloader" in reason or "remote URL" in reason else "medium",
                    str(build_path),
                    f"{name} {version}: {reason}",
                )
        if any(hint in build_text for hint in NATIVE_LINK_HINTS):
            entry = f"{name} {version} (native build)"
            if entry not in report.native_crates:
                report.native_crates.append(entry)

    if manifest.get("package", {}).get("links"):
        entry = f"{name} {version} (links={manifest['package']['links']})"
        if entry not in report.native_crates:
            report.native_crates.append(entry)

    lib_rs = source / "src" / "lib.rs"
    if lib_rs.is_file():
        try:
            lib_text = lib_rs.read_text(encoding="utf-8", errors="replace")
        except OSError:
            lib_text = ""
        if "proc_macro" in lib_text or manifest.get("lib", {}).get("proc-macro") is True:
            report.proc_macro_crates.append(f"{name} {version}")

def verify_cache_checksums(
    packages: list[dict[str, Any]], report: Report, include_cache: bool
) -> None:
    if not include_cache:
        return
    for package in packages:
        name, version = package.get("name"), package.get("version")
        checksum = package.get("checksum")
        if not name or not version or not checksum:
            continue
        archive = find_crate_archive(name, version)
        if archive is None:
            continue
        actual = sha256_file(archive)
        if actual != checksum:
            report.checksum_mismatch.append(f"{name} {version}: lock={checksum} cache={actual}")
            report.add(
                "DEP-CACHE-CHECKSUM-MISMATCH",
                "critical",
                str(archive),
                f"{name} {version} cached archive does not match Cargo.lock checksum",
            )


def audit_repo(repo: Path, report: Report, include_cache: bool) -> None:
    manifest_path = repo / "Cargo.toml"
    lock_path = repo / "Cargo.lock"
    if not manifest_path.is_file() or not lock_path.is_file():
        raise SystemExit(f"error: {repo} does not contain Cargo.toml and Cargo.lock")

    manifest = tomllib.loads(manifest_path.read_text(encoding="utf-8"))
    lock = tomllib.loads(lock_path.read_text(encoding="utf-8"))
    packages = lock_packages(lock)
    report.package_count = len(packages)
    report.lock_sha256 = sha256_file(lock_path)

    direct, dev, build, unpinned = parse_manifest_deps(manifest)
    report.direct_crates, report.dev_crates, report.build_dependencies = direct, dev, build
    for entry in unpinned:
        report.add("DEP-MANIFEST-UNPINNED", "medium", "Cargo.toml", f"not pinned with '=': {entry}")
    for section in ("patch", "replace"):
        if manifest.get(section):
            report.add("DEP-MANIFEST-OVERRIDE", "high", "Cargo.toml", f"[{section}] overrides a registry package")

    root_name = manifest.get("package", {}).get("name")
    root_version = manifest.get("package", {}).get("version")
    for package in packages:
        name, version = str(package.get("name", "")), str(package.get("version", ""))
        source = str(package.get("source", ""))
        if name == root_name and version == root_version and not source:
            report.source_classes["root"] = report.source_classes.get("root", 0) + 1
            continue
        if not source:
            report.add("DEP-LOCK-NO-SOURCE", "high", "Cargo.lock", f"{name} {version} has no source")
            report.source_classes["path"] = report.source_classes.get("path", 0) + 1
            continue
        if source in CRATES_IO_SOURCES:
            report.source_classes["crates.io"] = report.source_classes.get("crates.io", 0) + 1
        else:
            report.source_classes["other"] = report.source_classes.get("other", 0) + 1
            report.add("DEP-LOCK-NONREGISTRY", "high", "Cargo.lock", f"{name} {version} source={source}")
        checksum = package.get("checksum")
        if not checksum:
            report.checksum_missing.append(f"{name} {version}")
            report.add("DEP-LOCK-NO-CHECKSUM", "high", "Cargo.lock", f"{name} {version} has no checksum")
        elif not re.fullmatch(r"[0-9a-fA-F]{64}", str(checksum)):
            report.add("DEP-LOCK-BAD-CHECKSUM", "high", "Cargo.lock", f"{name} {version} checksum is malformed")

    verify_cache_checksums(packages, report, include_cache)

    # Network capability is a property of the crate name, so inventory it from
    # the lockfile even when the source is not cached. Build scripts, proc
    # macros, and native links still require the source tree.
    seen_network: set[str] = set()
    for package in packages:
        name = str(package.get("name", ""))
        version = str(package.get("version", ""))
        if name == root_name and version == root_version and not package.get("source"):
            continue
        entry = f"{name} {version}"
        if name in NETWORK_CRATES and entry not in seen_network:
            seen_network.add(entry)
            report.network_crates.append(entry)

    for package in packages:
        name, version = str(package.get("name", "")), str(package.get("version", ""))
        if name == root_name and version == root_version and not package.get("source"):
            continue
        source = find_crate_source(name, version)
        if source is None:
            report.missing_sources.append(f"{name} {version}")
            continue
        scan_crate_source(source, name, version, report)

    for config_name in (".cargo/config.toml", ".cargo/config"):
        config_path = repo / config_name
        if not config_path.is_file():
            continue
        try:
            config = tomllib.loads(config_path.read_text(encoding="utf-8"))
        except (OSError, tomllib.TOMLDecodeError) as exc:
            report.add("DEP-CARGO-CONFIG-UNREADABLE", "medium", str(config_path), str(exc))
            continue
        if config.get("source"):
            report.add("DEP-CARGO-SOURCE-REPLACEMENT", "high", str(config_path), "source replacement can redirect crate downloads")
        if config.get("patch"):
            report.add("DEP-CARGO-PATCH", "high", str(config_path), "patch section can replace a registry crate")
        net = config.get("net", {})
        if net.get("git-fetch-with-cli") or net.get("offline"):
            report.notes.append(f"{config_name}: net={net}")


def compare_baseline(report: Report, baseline: dict[str, Any]) -> None:
    expected = baseline.get("expected_dependencies", {})
    if not expected:
        report.notes.append("baseline has no expected_dependencies section; comparison skipped")
        return
    expected_lock = expected.get("lock_sha256")
    if expected_lock and expected_lock != report.lock_sha256:
        report.add(
            "DEP-LOCK-DRIFT",
            "high",
            "Cargo.lock",
            f"lockfile SHA-256 changed: expected {expected_lock}, got {report.lock_sha256}",
        )
    expected_direct = expected.get("direct_crates", [])
    if expected_direct and sorted(expected_direct) != report.direct_crates:
        report.add("DEP-DIRECT-DRIFT", "high", "Cargo.toml", "direct dependency set differs from baseline")
    expected_dev = expected.get("dev_crates", [])
    if expected_dev and sorted(expected_dev) != report.dev_crates:
        report.add("DEP-DEV-DRIFT", "medium", "Cargo.toml", "dev dependency set differs from baseline")
    expected_count = expected.get("package_count")
    if expected_count is not None and expected_count != report.package_count:
        report.add("DEP-COUNT-DRIFT", "high", "Cargo.lock", f"package count changed: expected {expected_count}, got {report.package_count}")
    allowed_network = set(expected.get("network_capable_crates", []))
    for crate in report.network_crates:
        if crate.split()[0] not in allowed_network:
            report.add("DEP-UNEXPECTED-NETWORK-CRATE", "high", "Cargo.lock", f"network-capable crate not in baseline: {crate}")
    allowed_build = set(expected.get("build_script_crates", []))
    for crate in report.build_scripts:
        if crate.split()[0] not in allowed_build:
            report.add("DEP-UNEXPECTED-BUILD-SCRIPT", "high", "Cargo.lock", f"build script not in baseline: {crate}")
    allowed_proc_macro = set(expected.get("proc_macro_crates", []))
    for crate in report.proc_macro_crates:
        if crate.split()[0] not in allowed_proc_macro:
            report.add("DEP-UNEXPECTED-PROC-MACRO", "medium", "Cargo.lock", f"proc-macro crate not in baseline: {crate}")
    allowed_native = set(expected.get("native_crates", []))
    for crate in report.native_crates:
        if crate.split()[0] not in allowed_native:
            report.add("DEP-UNEXPECTED-NATIVE", "medium", "Cargo.lock", f"native-linking crate not in baseline: {crate}")


def print_report(report: Report, verbose: bool) -> None:
    print(f"repo: {report.repo}")
    print(f"lock: {report.lock_sha256 or 'missing'}  packages: {report.package_count}")
    print(f"sources: {report.source_classes or '{}'}  scanned: {report.scanned_sources}  not-cached: {len(report.missing_sources)}")
    print(f"direct: {len(report.direct_crates)}  dev: {len(report.dev_crates)}  build: {len(report.build_dependencies)}")
    print(f"build scripts: {len(report.build_scripts)}  proc-macro: {len(report.proc_macro_crates)}  native: {len(report.native_crates)}  network-capable: {len(report.network_crates)}")
    if report.missing_sources:
        print("note: crate sources missing from the local registry; deep pass is incomplete (run cargo fetch --locked)")
    if verbose:
        for label, values in (
            ("direct crates", report.direct_crates),
            ("build scripts", report.build_scripts),
            ("proc-macro crates", report.proc_macro_crates),
            ("native crates", report.native_crates),
            ("network-capable crates", report.network_crates),
        ):
            if values:
                print(f"{label}:")
                for value in values:
                    print(f"  - {value}")
    counts = {severity: 0 for severity in SEVERITY_ORDER}
    for finding in report.findings:
        counts[finding.severity] = counts.get(finding.severity, 0) + 1
    print("findings: " + "  ".join(f"{k}={v}" for k, v in counts.items() if v))
    for finding in sorted(report.findings, key=lambda f: -SEVERITY_ORDER.get(f.severity, 0)):
        print(f"[{finding.severity.upper():8}] {finding.rule} {finding.path}: {finding.detail}")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("repo", nargs="?", default=".", help="repository root (default: .)")
    parser.add_argument("--baseline", type=Path, help="baseline JSON (default: ../references/network-baseline.json)")
    parser.add_argument("--json", type=Path, help="write the full report as JSON")
    parser.add_argument("--verbose", action="store_true", help="print crate inventories")
    parser.add_argument("--no-cache-check", action="store_true", help="skip SHA-256 verification of cached .crate archives")
    parser.add_argument("--fail-on", choices=list(SEVERITY_ORDER), default="high", help="exit 1 at/above this severity")
    args = parser.parse_args(argv)

    repo = Path(args.repo).resolve()
    baseline_path = args.baseline or Path(__file__).resolve().parent.parent / "references" / "network-baseline.json"
    report = Report(repo=str(repo))
    try:
        audit_repo(repo, report, include_cache=not args.no_cache_check)
    except (OSError, tomllib.TOMLDecodeError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    if baseline_path.is_file():
        try:
            baseline = json.loads(baseline_path.read_text(encoding="utf-8"))
            compare_baseline(report, baseline)
        except (OSError, json.JSONDecodeError) as exc:
            report.notes.append(f"baseline could not be loaded: {exc}")
    else:
        report.notes.append(f"baseline not found: {baseline_path}")

    print_report(report, args.verbose)
    if args.json:
        args.json.parent.mkdir(parents=True, exist_ok=True)
        args.json.write_text(json.dumps(report.as_dict(), indent=2) + "\n", encoding="utf-8")
        print(f"json: {args.json}")

    threshold = SEVERITY_ORDER[args.fail_on]
    return 1 if any(SEVERITY_ORDER.get(f.severity, 0) >= threshold for f in report.findings) else 0


if __name__ == "__main__":
    raise SystemExit(main())
