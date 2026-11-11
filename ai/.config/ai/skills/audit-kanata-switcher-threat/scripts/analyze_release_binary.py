#!/usr/bin/env python3
"""Static analysis of the kanata-switcher release ELF binary.

The binary is the artifact users actually run, so it is audited separately from
the source tree. This script reads the file only; it never executes it. It
parses the ELF header, program/section tables, dynamic dependencies, symbols,
and printable strings, then looks for:

  * writable+executable segments and text relocations;
  * appended data (overlays) and embedded ELF/PE/ZIP/gzip/script payloads;
  * high-entropy or packed sections;
  * unexpected shared-library dependencies and dangerous imported symbols;
  * remote URLs, IP addresses, domains, telemetry keywords, and shell commands;
  * build provenance (rustc version, build id, stripped/debug state).

A release binary is not reproducible byte-for-byte across machines, so the
baseline records invariants (NEEDED libraries, allowed URL patterns, maximum
size) rather than requiring one hash. Use --expect-sha256 only when you have a
trusted artifact to compare against.

Exit codes: 0 = no findings at/above --fail-on, 1 = findings, 2 = usage error.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import re
import struct
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

SEVERITY_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
ELF_MAGIC = b"\x7fELF"
PE_MAGIC = b"MZ"
ZIP_MAGIC = b"PK\x03\x04"
GZIP_MAGIC = b"\x1f\x8b"
SCRIPT_MAGIC = b"#!/"
MACHO_MAGICS = (b"\xfe\xed\xfa\xce", b"\xce\xfa\xed\xfe", b"\xfe\xed\xfa\xcf", b"\xcf\xfa\xed\xfe", b"\xca\xfe\xba\xbe")

URL_RE = re.compile(r"(?:https?|wss?|ftp|ssh)://[^\s\"'<>\\]+")
IPV4_RE = re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])")
DOMAIN_RE = re.compile(r"(?<![A-Za-z0-9_.-])(?:[A-Za-z0-9-]+\.)+[A-Za-z]{2,63}(?![A-Za-z0-9_.-])")
SUSPICIOUS_KEYWORDS = {
    "telemetry", "analytics", "sentry.io", "datadoghq", "mixpanel", "segment.io",
    "posthog", "amplitude", "discord.com/api/webhooks", "api.telegram.org",
    "pastebin.com", "transfer.sh", "ngrok", "bit.ly", "t.me/", "webhook",
    "aws_secret", "private_key", "mnemonic", "seed_phrase", "wallet",
}
DANGEROUS_SYMBOLS = {
    "system", "popen", "execve", "execv", "execvp", "execl", "execlp", "fork",
    "socket", "connect", "bind", "listen", "accept", "sendto", "recvfrom",
    "getaddrinfo", "gethostbyname", "dlopen", "dlsym", "ptrace", "memfd_create",
    "bpf", "init_module", "finit_module", "unshare", "setns", "keyctl",
}
KNOWN_NEEDED_PREFIXES = (
    "libc.so", "libm.so", "libgcc_s.so", "libpthread.so", "libdl.so", "librt.so",
    "ld-linux", "libdbus-1.so", "libwayland-client.so", "libwayland-cursor.so",
    "libwayland-egl.so", "libxkbcommon.so", "libX11.so", "libxcb.so",
)


@dataclass
class Finding:
    rule: str
    severity: str
    detail: str

    def as_dict(self) -> dict[str, str]:
        return {"rule": self.rule, "severity": self.severity, "detail": self.detail}


@dataclass
class Section:
    name: str
    type: int
    flags: int
    addr: int
    offset: int
    size: int
    entsize: int

    @property
    def end(self) -> int:
        return self.offset + self.size


@dataclass
class Segment:
    type: int
    flags: int
    offset: int
    vaddr: int
    filesz: int
    memsz: int

    @property
    def end(self) -> int:
        return self.offset + self.filesz

    @property
    def writable(self) -> bool:
        return bool(self.flags & 0x2)

    @property
    def executable(self) -> bool:
        return bool(self.flags & 0x1)


@dataclass
class Report:
    path: str
    sha256: str = ""
    size: int = 0
    elf_class: int = 0
    elf_type: int = 0
    machine: int = 0
    entry: int = 0
    phoff: int = 0
    phentsize: int = 0
    phnum: int = 0
    shoff: int = 0
    shentsize: int = 0
    shnum: int = 0
    build_id: str = ""
    comment: str = ""
    stripped: bool = False
    sections: list[Section] = field(default_factory=list)
    segments: list[Segment] = field(default_factory=list)
    needed: list[str] = field(default_factory=list)
    rpath: list[str] = field(default_factory=list)
    runpath: list[str] = field(default_factory=list)
    textrel: bool = False
    symbols: list[str] = field(default_factory=list)
    dangerous_symbols: list[str] = field(default_factory=list)
    urls: list[str] = field(default_factory=list)
    ips: list[str] = field(default_factory=list)
    domains: list[str] = field(default_factory=list)
    suspicious_strings: list[str] = field(default_factory=list)
    embedded: list[dict[str, Any]] = field(default_factory=list)
    overlay_size: int = 0
    overlay_magic: str = ""
    high_entropy_sections: list[str] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)

    def add(self, rule: str, severity: str, detail: str) -> None:
        self.findings.append(Finding(rule, severity, detail))

    def as_dict(self) -> dict[str, Any]:
        return {
            "path": self.path, "sha256": self.sha256, "size": self.size,
            "elf_class": self.elf_class, "elf_type": self.elf_type,
            "machine": self.machine, "entry": hex(self.entry),
            "build_id": self.build_id, "comment": self.comment,
            "stripped": self.stripped,
            "needed": self.needed, "rpath": self.rpath, "runpath": self.runpath,
            "textrel": self.textrel, "symbol_count": len(self.symbols),
            "dangerous_symbols": self.dangerous_symbols,
            "urls": self.urls, "ips": self.ips, "domains": self.domains,
            "suspicious_strings": self.suspicious_strings,
            "embedded": self.embedded, "overlay_size": self.overlay_size,
            "overlay_magic": self.overlay_magic,
            "high_entropy_sections": self.high_entropy_sections,
            "sections": [
                {"name": s.name, "type": s.type, "flags": s.flags,
                 "offset": s.offset, "size": s.size, "addr": s.addr}
                for s in self.sections
            ],
            "segments": [
                {"type": s.type, "flags": s.flags, "offset": s.offset,
                 "vaddr": s.vaddr, "filesz": s.filesz, "memsz": s.memsz}
                for s in self.segments
            ],
            "findings": [f.as_dict() for f in self.findings],
            "notes": self.notes,
        }


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = [0] * 256
    for byte in data:
        counts[byte] += 1
    length = len(data)
    return -sum((count / length) * math.log2(count / length) for count in counts if count)


def c_string(data: bytes, offset: int) -> str:
    end = data.find(b"\x00", offset)
    if end < 0:
        end = len(data)
    return data[offset:end].decode("utf-8", errors="replace")


def parse_elf(data: bytes, report: Report) -> None:
    if len(data) < 52 or data[:4] != ELF_MAGIC:
        raise ValueError("not an ELF file")
    elf_class = data[4]
    endian = "<" if data[5] == 1 else ">"
    if elf_class not in (1, 2):
        raise ValueError(f"unsupported ELF class {elf_class}")
    report.elf_class = elf_class

    if elf_class == 2:
        header = struct.unpack_from(endian + "HHIQQQIHHHHHH", data, 16)
        e_type, e_machine, _, e_entry, e_phoff, e_shoff, _, _, e_phentsize, e_phnum, e_shentsize, e_shnum, e_shstrndx = header
    else:
        header = struct.unpack_from(endian + "HHIIIIIHHHHHH", data, 16)
        e_type, e_machine, _, e_entry, e_phoff, e_shoff, _, _, e_phentsize, e_phnum, e_shentsize, e_shnum, e_shstrndx = header
    report.elf_type, report.machine, report.entry = e_type, e_machine, e_entry
    report.phoff, report.phentsize, report.phnum = e_phoff, e_phentsize, e_phnum
    report.shoff, report.shentsize, report.shnum = e_shoff, e_shentsize, e_shnum

    for index in range(e_phnum):
        offset = e_phoff + index * e_phentsize
        if offset + e_phentsize > len(data):
            break
        if elf_class == 2:
            p_type, p_flags, p_offset, p_vaddr, _, p_filesz, p_memsz, _ = struct.unpack_from(endian + "IIQQQQQQ", data, offset)
        else:
            p_type, p_offset, p_vaddr, _, p_filesz, p_memsz, p_flags, _ = struct.unpack_from(endian + "IIIIIIII", data, offset)
        report.segments.append(Segment(p_type, p_flags, p_offset, p_vaddr, p_filesz, p_memsz))

    raw_sections: list[tuple[int, int, int, int, int, int, int, int]] = []
    for index in range(e_shnum):
        offset = e_shoff + index * e_shentsize
        if offset + e_shentsize > len(data):
            break
        if elf_class == 2:
            values = struct.unpack_from(endian + "IIQQQQIIQQ", data, offset)
        else:
            values = struct.unpack_from(endian + "IIIIIIIIII", data, offset)
        raw_sections.append(values)

    shstrtab = b""
    if 0 <= e_shstrndx < len(raw_sections):
        values = raw_sections[e_shstrndx]
        shstrtab = data[values[4]:values[4] + values[5]]
    for values in raw_sections:
        name_off, sh_type, sh_flags, sh_addr, sh_offset, sh_size, _, _, _, sh_entsize = values
        name = c_string(shstrtab, name_off) if shstrtab else ""
        report.sections.append(Section(name, sh_type, sh_flags, sh_addr, sh_offset, sh_size, sh_entsize))

    section_by_name = {s.name: s for s in report.sections}
    if ".symtab" not in section_by_name:
        report.stripped = True

    dynstr = section_by_name.get(".dynstr")
    dynamic = section_by_name.get(".dynamic")
    if dynstr and dynamic:
        step = 16 if elf_class == 2 else 8
        for offset in range(dynamic.offset, min(dynamic.end, len(data)) - step + 1, step):
            if elf_class == 2:
                tag, value = struct.unpack_from(endian + "qQ", data, offset)
            else:
                tag, value = struct.unpack_from(endian + "iI", data, offset)
            if tag == 1:
                report.needed.append(c_string(data, dynstr.offset + value))
            elif tag == 15:
                report.rpath.append(c_string(data, dynstr.offset + value))
            elif tag == 29:
                report.runpath.append(c_string(data, dynstr.offset + value))
            elif tag == 22:
                report.textrel = True
            elif tag == 0:
                break

    for section_name, strtab_name in ((".dynsym", ".dynstr"), (".symtab", ".strtab")):
        symtab = section_by_name.get(section_name)
        strtab = section_by_name.get(strtab_name)
        if not symtab or not strtab or symtab.entsize == 0:
            continue
        for offset in range(symtab.offset, min(symtab.end, len(data)), symtab.entsize):
            if elf_class == 2 and offset + 24 > len(data):
                break
            if elf_class == 1 and offset + 16 > len(data):
                break
            name_off = struct.unpack_from(endian + "I", data, offset)[0]
            if name_off:
                name = c_string(data, strtab.offset + name_off)
                if name:
                    report.symbols.append(name)

    for section in report.sections:
        if section.name == ".note.gnu.build-id" and section.size > 16:
            note = data[section.offset:section.end]
            report.build_id = note[16:].hex()
        if section.name == ".comment":
            report.comment = data[section.offset:section.end].replace(b"\x00", b" ").decode("utf-8", errors="replace").strip()


def analyze_segments(data: bytes, report: Report) -> None:
    for segment in report.segments:
        if segment.type != 1:  # PT_LOAD
            continue
        if segment.writable and segment.executable:
            report.add("BIN-WX-SEGMENT", "high", f"PT_LOAD is writable+executable at offset {segment.offset:#x}")
    if report.textrel:
        report.add("BIN-TEXTREL", "high", "binary contains text relocations (DT_TEXTREL)")
    if report.rpath:
        report.add("BIN-RPATH", "medium", f"DT_RPATH present: {report.rpath}")
    if report.runpath:
        report.add("BIN-RUNPATH", "medium", f"DT_RUNPATH present: {report.runpath}")

    covered = 0
    for segment in report.segments:
        if segment.type == 1:
            covered = max(covered, segment.end)
    for section in report.sections:
        covered = max(covered, section.end)
    if report.phnum and report.phentsize:
        covered = max(covered, report.phoff + report.phnum * report.phentsize)
    if report.shnum and report.shentsize:
        covered = max(covered, report.shoff + report.shnum * report.shentsize)
    report.overlay_size = max(0, len(data) - covered)
    if report.overlay_size:
        overlay = data[covered:]
        for magic, label in (
            (ELF_MAGIC, "ELF"), (ZIP_MAGIC, "ZIP"), (GZIP_MAGIC, "gzip"),
            (SCRIPT_MAGIC, "script"), (MACHO_MAGICS[0], "Mach-O"), (MACHO_MAGICS[3], "Mach-O"),
        ):
            if overlay.startswith(magic):
                report.overlay_magic = label
                break
        severity = "high" if report.overlay_size >= 4096 or report.overlay_magic else "medium"
        report.add("BIN-OVERLAY", severity, f"{report.overlay_size} bytes after the last segment/section (magic={report.overlay_magic or 'none'})")

    for section in report.sections:
        if section.size < 4096 or not (section.flags & 0x2):  # SHF_ALLOC
            continue
        value = entropy(data[section.offset:section.end])
        if value >= 7.5:
            report.high_entropy_sections.append(f"{section.name}={value:.2f}")
            if section.name not in (".rodata", ".data.rel.ro", ".gnu_debugdata"):
                report.add("BIN-HIGH-ENTROPY", "medium", f"section {section.name} entropy {value:.2f}")


def valid_pe(data: bytes, offset: int) -> bool:
    if data[offset:offset + 2] != PE_MAGIC or offset + 0x40 > len(data):
        return False
    pe_offset = struct.unpack_from("<I", data, offset + 0x3C)[0]
    return data[offset + pe_offset:offset + pe_offset + 4] == b"PE\x00\x00"


def scan_embedded(data: bytes, report: Report) -> None:
    checks = [
        (ELF_MAGIC, "ELF", lambda d, o: len(d) > o + 20 and d[o + 4] in (1, 2) and d[o + 5] in (1, 2)),
        (PE_MAGIC, "PE", valid_pe),
        (ZIP_MAGIC, "ZIP", lambda d, o: o + 30 <= len(d)),
        (GZIP_MAGIC, "gzip", lambda d, o: o + 10 <= len(d)),
        (SCRIPT_MAGIC, "script", lambda d, o: o + 4 <= len(d)),
        (MACHO_MAGICS[0], "Mach-O", lambda d, o: o + 4 <= len(d)),
        (MACHO_MAGICS[3], "Mach-O", lambda d, o: o + 4 <= len(d)),
    ]
    section_ranges = [(s.offset, s.end, s.name) for s in report.sections if s.size]
    for magic, label, validator in checks:
        start = 0
        while True:
            offset = data.find(magic, start)
            if offset < 0:
                break
            start = offset + 1
            if offset == 0 or not validator(data, offset):
                continue
            containing = next((name for begin, end, name in section_ranges if begin <= offset < end), None)
            report.embedded.append({"offset": offset, "magic": label, "section": containing})
            if containing is None or label in ("PE", "ELF", "Mach-O"):
                report.add("BIN-EMBEDDED-PAYLOAD", "high", f"{label} magic at offset {offset:#x} (section={containing or 'none'})")
            else:
                report.add("BIN-EMBEDDED-MAGIC", "low", f"{label} magic inside section {containing} at offset {offset:#x}")


def extract_strings(data: bytes) -> list[str]:
    values: list[str] = []
    for match in re.finditer(rb"[\x20-\x7e]{4,}", data):
        values.append(match.group().decode("ascii", errors="replace"))
    for match in re.finditer(rb"(?:[\x20-\x7e]\x00){4,}", data):
        values.append(match.group().decode("utf-16le", errors="replace"))
    return values


def analyze_strings(data: bytes, report: Report, baseline: dict[str, Any]) -> None:
    expected = baseline.get("expected_binary", {})
    allowed_urls = expected.get("allowed_url_patterns", [])
    allowed_ips = set(expected.get("allowed_ip_literals", ["127.0.0.1"]))
    allowed_ips.update({"0.0.0.0", "255.255.255.255"})
    strings = extract_strings(data)
    seen: set[str] = set()
    for value in strings:
        if value in seen:
            continue
        seen.add(value)
        for url in URL_RE.findall(value):
            if url not in report.urls:
                report.urls.append(url)
            if not any(re.search(pattern, url) for pattern in allowed_urls):
                report.add("BIN-UNEXPECTED-URL", "high", f"remote URL string: {url}")
        for ip in IPV4_RE.findall(value):
            if ip not in report.ips:
                report.ips.append(ip)
            if ip not in allowed_ips and not ip.startswith("127."):
                report.add("BIN-UNEXPECTED-IP", "high", f"remote IP literal: {ip}")
        lowered = value.lower()
        for keyword in SUSPICIOUS_KEYWORDS:
            if keyword in lowered and value not in report.suspicious_strings:
                report.suspicious_strings.append(value[:300])
                report.add("BIN-SUSPICIOUS-STRING", "medium", f"keyword '{keyword}': {value[:200]}")
                break
        for domain in DOMAIN_RE.findall(value):
            if domain not in report.domains:
                report.domains.append(domain)

    for symbol in report.symbols:
        base = symbol.split("@", 1)[0]
        if base in DANGEROUS_SYMBOLS:
            report.dangerous_symbols.append(base)
    if report.dangerous_symbols:
        report.add("BIN-DANGEROUS-SYMBOLS", "low", f"imported symbols: {sorted(set(report.dangerous_symbols))}")

    if "rustc" not in report.comment and not any("rustc" in value for value in strings[:5000]):
        report.notes.append("no rustc marker found; binary provenance is not self-evident")
    if not report.build_id:
        report.notes.append("no GNU build-id; artifact provenance is weaker")


def compare_baseline(report: Report, baseline: dict[str, Any]) -> None:
    expected = baseline.get("expected_binary", {})
    if not expected:
        report.notes.append("baseline has no expected_binary section; comparison skipped")
        return
    max_size = expected.get("max_size_bytes")
    if max_size and report.size > max_size:
        report.add("BIN-SIZE-DRIFT", "high", f"binary is {report.size} bytes; baseline maximum is {max_size}")
    allowed_needed = expected.get("allowed_needed_prefixes", list(KNOWN_NEEDED_PREFIXES))
    for library in report.needed:
        if not any(library.startswith(prefix) for prefix in allowed_needed):
            report.add("BIN-UNEXPECTED-LIBRARY", "medium", f"NEEDED library not in baseline: {library}")
    required_needed = expected.get("required_needed_prefixes", [])
    for prefix in required_needed:
        if not any(library.startswith(prefix) for library in report.needed):
            report.add("BIN-MISSING-LIBRARY", "medium", f"baseline expects a NEEDED library starting with {prefix}")
    allowed_dangerous = set(expected.get("allowed_dangerous_symbols", []))
    for symbol in sorted(set(report.dangerous_symbols)):
        if symbol not in allowed_dangerous:
            report.add("BIN-UNEXPECTED-DANGEROUS-SYMBOL", "medium", f"symbol not in baseline: {symbol}")
    expected_sha = expected.get("sha256")
    if expected_sha and expected_sha != report.sha256:
        report.add("BIN-SHA256-DRIFT", "high", f"binary SHA-256 differs from baseline: {report.sha256}")
    overlay_max = expected.get("overlay_max_bytes", 0)
    if report.overlay_size > overlay_max:
        report.add("BIN-OVERLAY-DRIFT", "high", f"overlay is {report.overlay_size} bytes; baseline maximum is {overlay_max}")


def print_report(report: Report, verbose: bool) -> None:
    print(f"binary: {report.path}")
    print(f"sha256: {report.sha256}  size: {report.size}  class: ELF{report.elf_class * 32}  type: {report.elf_type}  machine: {report.machine}")
    print(f"build-id: {report.build_id or 'none'}  stripped: {report.stripped}  comment: {report.comment or 'none'}")
    print(f"needed: {', '.join(report.needed) or 'none'}")
    print(f"sections: {len(report.sections)}  segments: {len(report.segments)}  symbols: {len(report.symbols)}  overlay: {report.overlay_size}")
    print(f"urls: {len(report.urls)}  ips: {len(report.ips)}  domains: {len(report.domains)}  suspicious: {len(report.suspicious_strings)}")
    if verbose:
        for url in report.urls:
            print(f"  url: {url}")
        for ip in report.ips:
            print(f"  ip: {ip}")
        for value in report.suspicious_strings:
            print(f"  suspicious: {value}")
        for item in report.embedded:
            print(f"  embedded: {item}")
        if report.high_entropy_sections:
            print(f"  high-entropy: {', '.join(report.high_entropy_sections)}")
    counts = {severity: 0 for severity in SEVERITY_ORDER}
    for finding in report.findings:
        counts[finding.severity] = counts.get(finding.severity, 0) + 1
    print("findings: " + "  ".join(f"{k}={v}" for k, v in counts.items() if v))
    for finding in sorted(report.findings, key=lambda f: -SEVERITY_ORDER.get(f.severity, 0)):
        print(f"[{finding.severity.upper():8}] {finding.rule}: {finding.detail}")


def write_markdown(report: Report, path: Path) -> None:
    lines = [
        f"# Release Binary Audit: {Path(report.path).name}",
        "",
        f"- SHA-256: `{report.sha256}`",
        f"- Size: `{report.size}` bytes",
        f"- ELF: class {report.elf_class * 32}, type {report.elf_type}, machine {report.machine}",
        f"- Build ID: `{report.build_id or 'none'}`",
        f"- rustc comment: `{report.comment or 'none'}`",
        f"- Stripped: `{report.stripped}`",
        f"- NEEDED: {', '.join(f'`{x}`' for x in report.needed) or 'none'}",
        f"- Overlay: `{report.overlay_size}` bytes ({report.overlay_magic or 'no magic'})",
        "",
        "## Findings",
        "",
    ]
    if not report.findings:
        lines.append("No findings at the configured threshold.")
    for finding in sorted(report.findings, key=lambda f: -SEVERITY_ORDER.get(f.severity, 0)):
        lines.append(f"- **{finding.severity.upper()}** `{finding.rule}` — {finding.detail}")
    lines += ["", "## Network-like strings", ""]
    lines += [f"- `{url}`" for url in report.urls] or ["- none"]
    lines += ["", "## Notes", ""]
    lines += [f"- {note}" for note in report.notes] or ["- none"]
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("binary", type=Path, help="release ELF binary to inspect")
    parser.add_argument("--baseline", type=Path, help="baseline JSON (default: ../references/network-baseline.json)")
    parser.add_argument("--json", type=Path, help="write the full report as JSON")
    parser.add_argument("--markdown", type=Path, help="write a human-readable Markdown report")
    parser.add_argument("--verbose", action="store_true", help="print URLs, IPs, strings, and sections")
    parser.add_argument("--fail-on", choices=list(SEVERITY_ORDER), default="high", help="exit 1 at/above this severity")
    args = parser.parse_args(argv)

    binary = args.binary.resolve()
    if not binary.is_file():
        print(f"error: {binary} is not a file", file=sys.stderr)
        return 2
    data = binary.read_bytes()
    report = Report(path=str(binary), sha256=sha256_file(binary), size=len(data))
    try:
        parse_elf(data, report)
    except (ValueError, struct.error, IndexError) as exc:
        print(f"error: {exc}", file=sys.stderr)
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

    analyze_segments(data, report)
    scan_embedded(data, report)
    analyze_strings(data, report, baseline)
    compare_baseline(report, baseline)
    print_report(report, args.verbose)
    if args.json:
        args.json.parent.mkdir(parents=True, exist_ok=True)
        args.json.write_text(json.dumps(report.as_dict(), indent=2) + "\n", encoding="utf-8")
        print(f"json: {args.json}")
    if args.markdown:
        args.markdown.parent.mkdir(parents=True, exist_ok=True)
        write_markdown(report, args.markdown)
        print(f"markdown: {args.markdown}")

    threshold = SEVERITY_ORDER[args.fail_on]
    return 1 if any(SEVERITY_ORDER.get(f.severity, 0) >= threshold for f in report.findings) else 0


if __name__ == "__main__":
    raise SystemExit(main())
