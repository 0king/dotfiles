#!/usr/bin/env python3
"""Static audit of the kanata-switcher GNOME Shell extension.

The extension runs inside the compositor, so a compromised or careless change
has more authority than an ordinary app: it can read the focused window title,
inject keybindings, talk to every session-bus service, and spawn processes.
This scanner inventories exactly those capabilities without executing the
extension:

  * module imports and legacy `imports.*` access
  * process execution, eval/dynamic code, obfuscation helpers
  * network APIs, URLs, sockets, and proxy/resolver objects
  * file and clipboard access
  * keybinding registration
  * D-Bus destinations, interfaces, paths, and bus type
  * metadata.json / GSettings schema drift
  * per-file SHA-256 hashes

Findings are compared with the `gnome_extension` section of
`references/network-baseline.json`. Unknown imports or D-Bus destinations are
findings; known ones are notes.

Exit codes: 0 = no findings at/above --fail-on, 1 = findings, 2 = usage error.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable

SEVERITY_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}

EXPECTED_GI_MODULES = {
    "Gio", "GLib", "GObject", "St", "Clutter", "Gtk", "Adw", "Meta", "Shell",
    "Pango", "cairo", "Graphene", "Gdk", "GdkPixbuf", "Atk", "Atspi", "Gvc",
}

NETWORK_GI_MODULES = {"Soup", "GioUnix", "Gst", "GstNet"}

NETWORK_APIS = [
    (r"\bGio\.SocketClient\b", "Gio.SocketClient"),
    (r"\bGio\.Socket\b", "Gio.Socket"),
    (r"\bGio\.SocketConnection\b", "Gio.SocketConnection"),
    (r"\bGio\.NetworkAddress\b", "Gio.NetworkAddress"),
    (r"\bGio\.Resolver\b", "Gio.Resolver"),
    (r"\bGio\.ProxyResolver\b", "Gio.ProxyResolver"),
    (r"\bGio\.ProxyAddress\b", "Gio.ProxyAddress"),
    (r"\bGio\.TlsClientConnection\b", "Gio.TlsClientConnection"),
    (r"\bGio\.TlsCertificate\b", "Gio.TlsCertificate"),
    (r"\bGio\.DatagramClient\b", "Gio.DatagramClient"),
    (r"\bGio\.SubprocessLauncher\b", "Gio.SubprocessLauncher"),
    (r"\bSoup\.", "libsoup"),
    (r"\bfetch\s*\(", "fetch()"),
    (r"\bXMLHttpRequest\b", "XMLHttpRequest"),
    (r"\bWebSocket\b", "WebSocket"),
    (r"\bEventSource\b", "EventSource"),
    (r"\bnavigator\.sendBeacon\b", "sendBeacon"),
]

EXEC_APIS = [
    (r"\bGio\.Subprocess\b", "Gio.Subprocess"),
    (r"\bGLib\.spawn\w*\b", "GLib.spawn*"),
    (r"\bShell\.util_spawn\w*\b", "Shell.util_spawn*"),
    (r"\bUtil\.spawn\w*\b", "Util.spawn*"),
    (r"\bimports\.misc\.util\.spawn\w*\b", "imports.misc.util.spawn*"),
    (r"\bGLib\.shell_parse_argv\b", "GLib.shell_parse_argv"),
    (r"\bGio\.UnixFDList\b", "Gio.UnixFDList"),
]

DYNAMIC_CODE = [
    (r"(?<![\w.])eval\s*\(", "eval()"),
    (r"\bnew\s+Function\s*\(", "new Function()"),
    (r"(?<![\w.])Function\s*\(", "Function()"),
    (r"\bsetTimeout\s*\(\s*['\"]", "setTimeout(string)"),
    (r"\bsetInterval\s*\(\s*['\"]", "setInterval(string)"),
    (r"\brequire\s*\(", "require()"),
    (r"\bimports\.searchPath\b", "imports.searchPath"),
    (r"\bglobalThis\b", "globalThis"),
    (r"\bthis\.constructor\.constructor\b", "Function constructor escape"),
    (r"\bWebAssembly\b", "WebAssembly"),
]

OBFUSCATION = [
    (r"\batob\s*\(", "atob()"),
    (r"\bbtoa\s*\(", "btoa()"),
    (r"\bBuffer\.from\s*\(", "Buffer.from()"),
    (r"\bString\.fromCharCode\s*\(", "String.fromCharCode()"),
    (r"\bunescape\s*\(", "unescape()"),
    (r"\bdecodeURIComponent\s*\(\s*['\"]%", "encoded URI payload"),
]

FILE_APIS = [
    (r"\bGio\.File\b", "Gio.File"),
    (r"\bGio\.FileInfo\b", "Gio.FileInfo"),
    (r"\bGio\.FileEnumerator\b", "Gio.FileEnumerator"),
    (r"\bGLib\.file_get_contents\b", "GLib.file_get_contents"),
    (r"\bGLib\.file_set_contents\b", "GLib.file_set_contents"),
    (r"\bGLib\.mkdir_with_parents\b", "GLib.mkdir_with_parents"),
    (r"\bGLib\.unlink\b", "GLib.unlink"),
    (r"\bGLib\.rename\b", "GLib.rename"),
    (r"\b\.load_contents\b", "load_contents"),
    (r"\b\.replace_contents\b", "replace_contents"),
    (r"\b\.enumerate_children\b", "enumerate_children"),
    (r"\b\.read_async\b", "read_async"),
    (r"\b\.write_async\b", "write_async"),
    (r"\b\.open_readwrite\b", "open_readwrite"),
]

CLIPBOARD_APIS = [
    (r"\bSt\.Clipboard\b", "St.Clipboard"),
    (r"\bGtk\.Clipboard\b", "Gtk.Clipboard"),
    (r"\bget_content\b", "clipboard get_content"),
    (r"\bset_content\b", "clipboard set_content"),
]

KEYBINDING_APIS = [
    (r"\badd_keybinding\b", "add_keybinding"),
    (r"\bremove_keybinding\b", "remove_keybinding"),
    (r"\bMeta\.KeyBindingFlags\b", "Meta.KeyBindingFlags"),
    (r"\ballow_keybinding\b", "allow_keybinding"),
    (r"\bMain\.wm\.add_keybinding\b", "Main.wm.add_keybinding"),
]

DBUS_SYSTEM = [
    (r"\bGio\.DBus\.system\b", "Gio.DBus.system"),
    (r"\bGio\.BusType\.SYSTEM\b", "Gio.BusType.SYSTEM"),
    (r"\bGio\.DBus\.get_sync\s*\(\s*Gio\.BusType\.SYSTEM", "get_sync(SYSTEM)"),
]

URL_RE = re.compile(r"\b(?:https?|ftps?|sftp|ssh|ws|wss|telnet|gopher)://[^\s\"'<>]+", re.IGNORECASE)
IMPORT_RE = re.compile(r"""^\s*import\s+(?:[^'"]*?\s+from\s+)?['"]([^'"]+)['"]""", re.MULTILINE)
DYNAMIC_IMPORT_RE = re.compile(r"""\bimport\s*\(\s*['"]([^'"]+)['"]\s*\)""")
LEGACY_IMPORT_RE = re.compile(r"\bimports\.(gi|ui|misc|system)\.([A-Za-z_][A-Za-z0-9_]*)")
STRING_RE = re.compile(r'"((?:[^"\\]|\\.)*)"|\'((?:[^\'\\]|\\.)*)\'')
BUS_NAME_RE = re.compile(r"^(?:org|com|net|io|edu|de|fr|uk|us)\.[A-Za-z0-9_-]+(?:\.[A-Za-z0-9_-]+)+$")
IFACE_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)+$")
PATH_RE = re.compile(r"^/[A-Za-z0-9_/-]+$")

SETTINGS_GETTER_TYPES = {
    "get_boolean": "b",
    "get_string": "s",
    "get_int": "i",
    "get_uint": "u",
    "get_double": "d",
    "get_strv": "as",
    "get_value": "",
}
SETTINGS_KEY_RE = re.compile(
    r"\b(?:get_boolean|get_string|get_int|get_uint|get_double|get_strv|get_value|set_boolean|set_string|set_int|set_uint|set_double|set_strv)\s*\(\s*['\"]([^'\"]+)['\"]"
)
CHANGED_KEY_RE = re.compile(r"['\"]changed::([^'\"]+)['\"]")
BIND_KEY_RE = re.compile(r"\.bind\s*\(\s*['\"]([^'\"]+)['\"]")


@dataclass
class Finding:
    rule: str
    severity: str
    path: str
    line: int | None
    detail: str

    def as_dict(self) -> dict[str, Any]:
        return {
            "rule": self.rule,
            "severity": self.severity,
            "path": self.path,
            "line": self.line,
            "detail": self.detail,
        }


@dataclass
class Report:
    directory: str
    files: list[str] = field(default_factory=list)
    hashes: dict[str, str] = field(default_factory=dict)
    imports: dict[str, list[str]] = field(default_factory=dict)
    dbus_destinations: list[str] = field(default_factory=list)
    dbus_interfaces: list[str] = field(default_factory=list)
    dbus_paths: list[str] = field(default_factory=list)
    settings_keys: list[str] = field(default_factory=list)
    schema_keys: dict[str, str] = field(default_factory=dict)
    metadata: dict[str, Any] = field(default_factory=dict)
    findings: list[Finding] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)

    def add(self, rule: str, severity: str, path: str, line: int | None, detail: str) -> None:
        self.findings.append(Finding(rule, severity, path, line, detail))

    def as_dict(self) -> dict[str, Any]:
        return {
            "directory": self.directory,
            "files": self.files,
            "hashes": self.hashes,
            "imports": self.imports,
            "dbus_destinations": self.dbus_destinations,
            "dbus_interfaces": self.dbus_interfaces,
            "dbus_paths": self.dbus_paths,
            "settings_keys": self.settings_keys,
            "schema_keys": self.schema_keys,
            "metadata": self.metadata,
            "findings": [finding.as_dict() for finding in self.findings],
            "notes": self.notes,
        }


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def line_of(text: str, offset: int) -> int:
    return text.count("\n", 0, offset) + 1


def strip_comments(text: str) -> tuple[str, list[tuple[int, str]]]:
    """Blank out JS comments while preserving strings, newlines, and offsets."""
    out: list[str] = []
    comments: list[tuple[int, str]] = []
    state = "code"
    i = 0
    line = 1
    length = len(text)
    while i < length:
        char = text[i]
        if state == "code":
            if char == "/" and i + 1 < length and text[i + 1] == "/":
                start_line = line
                end = text.find("\n", i)
                if end == -1:
                    end = length
                comments.append((start_line, text[i:end]))
                out.append(" " * (end - i))
                i = end
                continue
            if char == "/" and i + 1 < length and text[i + 1] == "*":
                start_line = line
                end = text.find("*/", i + 2)
                if end == -1:
                    end = length - 2
                chunk = text[i:end + 2]
                comments.append((start_line, chunk))
                out.append("".join("\n" if c == "\n" else " " for c in chunk))
                line += chunk.count("\n")
                i = end + 2
                continue
            if char in "'\"`":
                state = {"'": "single", '"': "double", "`": "template"}[char]
            out.append(char)
            if char == "\n":
                line += 1
            i += 1
            continue

        out.append(char)
        if char == "\\" and i + 1 < length:
            out.append(text[i + 1])
            if text[i + 1] == "\n":
                line += 1
            i += 2
            continue
        if char == "\n":
            line += 1
        if (state == "single" and char == "'") or (state == "double" and char == '"') or (state == "template" and char == "`"):
            state = "code"
        i += 1
    return "".join(out), comments


def match_rules(text: str, rules: Iterable[tuple[str, str]], rule_id: str, severity: str,
                relative: str, report: Report) -> None:
    for pattern, label in rules:
        for match in re.finditer(pattern, text):
            report.add(rule_id, severity, relative, line_of(text, match.start()), f"{label} used")


def collect_strings(text: str) -> list[tuple[str, int]]:
    values: list[tuple[str, int]] = []
    for match in STRING_RE.finditer(text):
        value = match.group(1) if match.group(1) is not None else match.group(2)
        values.append((value, line_of(text, match.start())))
    return values


def scan_javascript(path: Path, relative: str, report: Report) -> None:
    raw = path.read_text(encoding="utf-8", errors="replace")
    code, comments = strip_comments(raw)
    constants = {
        match.group(1): match.group(2)
        for match in re.finditer(r"\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*['\"]([^'\"]+)['\"]", code)
    }

    for match in IMPORT_RE.finditer(code):
        module = match.group(1)
        report.imports.setdefault(module, []).append(f"{relative}:{line_of(code, match.start())}")
        if module.startswith("gi://"):
            name = module[len("gi://"):].split("?")[0]
            if name in NETWORK_GI_MODULES:
                report.add("GEXT-NETWORK-IMPORT", "critical", relative, line_of(code, match.start()), f"network-capable GObject import {module}")
            elif name not in EXPECTED_GI_MODULES:
                report.add("GEXT-UNEXPECTED-IMPORT", "medium", relative, line_of(code, match.start()), f"unexpected GObject import {module}")
        elif module.startswith("resource:///org/gnome/shell/") or module.startswith("resource:///org/gnome/Shell/"):
            report.notes.append(f"{relative}: shell resource import {module}")
        elif module.startswith(("./", "../")):
            continue
        else:
            report.add("GEXT-UNEXPECTED-IMPORT", "high", relative, line_of(code, match.start()), f"unexpected module import {module}")

    for match in DYNAMIC_IMPORT_RE.finditer(code):
        report.add("GEXT-DYNAMIC-IMPORT", "high", relative, line_of(code, match.start()), f"dynamic import of {match.group(1)}")

    for match in LEGACY_IMPORT_RE.finditer(code):
        namespace, name = match.group(1), match.group(2)
        report.add("GEXT-LEGACY-IMPORT", "medium", relative, line_of(code, match.start()), f"legacy imports.{namespace}.{name}")

    match_rules(code, NETWORK_APIS, "GEXT-NETWORK-API", "critical", relative, report)
    match_rules(code, EXEC_APIS, "GEXT-EXEC-API", "critical", relative, report)
    match_rules(code, DYNAMIC_CODE, "GEXT-DYNAMIC-CODE", "high", relative, report)
    match_rules(code, OBFUSCATION, "GEXT-OBFUSCATION", "medium", relative, report)
    match_rules(code, FILE_APIS, "GEXT-FILE-API", "high", relative, report)
    match_rules(code, CLIPBOARD_APIS, "GEXT-CLIPBOARD-API", "medium", relative, report)
    match_rules(code, KEYBINDING_APIS, "GEXT-KEYBINDING-API", "medium", relative, report)
    match_rules(code, DBUS_SYSTEM, "GEXT-DBUS-SYSTEM", "critical", relative, report)

    for match in URL_RE.finditer(code):
        report.add("GEXT-URL", "high", relative, line_of(code, match.start()), f"URL in extension code: {match.group(0)[:200]}")

    for line, comment in comments:
        if URL_RE.search(comment):
            report.notes.append(f"{relative}:{line}: URL in comment (not executable): {URL_RE.search(comment).group(0)[:160]}")

    for value, line in collect_strings(code):
        if BUS_NAME_RE.match(value) and not value.startswith("org.gnome.shell.extensions."):
            if value not in report.dbus_destinations:
                report.dbus_destinations.append(value)
        if PATH_RE.match(value) and value.count("/") >= 2:
            if value not in report.dbus_paths:
                report.dbus_paths.append(value)
        if len(value) >= 200 and re.fullmatch(r"[A-Za-z0-9+/=_-]+", value):
            report.add("GEXT-LONG-ENCODED-STRING", "medium", relative, line, f"{len(value)}-character encoded-looking string")

    for name, value in constants.items():
        if re.search(r"(?:INTERFACE|IFACE)$", name) and IFACE_RE.match(value):
            if value not in report.dbus_interfaces:
                report.dbus_interfaces.append(value)
        if re.search(r"PATH$", name) and PATH_RE.match(value):
            if value not in report.dbus_paths:
                report.dbus_paths.append(value)

    hex_escapes = len(re.findall(r"\\x[0-9a-fA-F]{2}", code))
    if hex_escapes >= 8:
        report.add("GEXT-HEX-ESCAPES", "medium", relative, None, f"{hex_escapes} hex escape sequences in code")

    def add_settings_key(value: str) -> None:
        resolved = constants.get(value, value)
        if resolved and resolved not in report.settings_keys:
            report.settings_keys.append(resolved)

    for match in SETTINGS_KEY_RE.finditer(code):
        add_settings_key(match.group(1))
    for match in re.finditer(r"\b(?:get|set)_(?:boolean|string|int|uint|double|strv|value)\s*\(\s*([A-Za-z_$][\w$]*)", code):
        add_settings_key(match.group(1))
    for match in re.finditer(r"changed::\$\{([A-Za-z_$][\w$]*)\}", code):
        add_settings_key(match.group(1))
    for match in CHANGED_KEY_RE.finditer(code):
        add_settings_key(match.group(1))
    for match in re.finditer(r"\.bind\s*\(\s*([A-Za-z_$][\w$]*)", code):
        add_settings_key(match.group(1))
    for match in BIND_KEY_RE.finditer(code):
        add_settings_key(match.group(1))


def scan_metadata(path: Path, relative: str, report: Report) -> None:
    try:
        metadata = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        report.add("GEXT-METADATA-INVALID", "critical", relative, None, f"metadata.json is not valid JSON: {exc}")
        return
    if not isinstance(metadata, dict):
        report.add("GEXT-METADATA-INVALID", "critical", relative, None, "metadata.json is not an object")
        return
    report.metadata = metadata

    uuid = metadata.get("uuid")
    if not isinstance(uuid, str) or "@" not in uuid:
        report.add("GEXT-METADATA-UUID", "high", relative, None, f"missing or malformed uuid: {uuid!r}")
    name = metadata.get("name")
    if not isinstance(name, str) or not name.strip():
        report.add("GEXT-METADATA-NAME", "medium", relative, None, "missing or empty name")
    versions = metadata.get("shell-version")
    if not isinstance(versions, list) or not versions or not all(isinstance(v, str) and v.isdigit() for v in versions):
        report.add("GEXT-METADATA-SHELL-VERSION", "high", relative, None, f"shell-version must be a non-empty list of numeric strings, got {versions!r}")
    if not isinstance(metadata.get("version"), int):
        report.add("GEXT-METADATA-VERSION", "medium", relative, None, "version must be an integer")
    schema = metadata.get("settings-schema")
    if not isinstance(schema, str) or not schema:
        report.add("GEXT-METADATA-SCHEMA", "high", relative, None, "settings-schema is missing")
    url = metadata.get("url")
    if url is not None:
        if not isinstance(url, str) or not url.startswith("https://"):
            report.add("GEXT-METADATA-URL", "medium", relative, None, f"metadata url is not https: {url!r}")
        else:
            report.notes.append(f"metadata url: {url}")
    unknown = set(metadata) - {
        "uuid", "name", "description", "shell-version", "settings-schema", "version",
        "url", "gettext-domain", "session-modes", "donations", "license",
    }
    for key in sorted(unknown):
        report.add("GEXT-METADATA-UNKNOWN-KEY", "low", relative, None, f"unknown metadata key {key!r}")


def scan_schema(path: Path, relative: str, report: Report) -> None:
    try:
        tree = ET.parse(path)
    except (OSError, ET.ParseError) as exc:
        report.add("GEXT-SCHEMA-INVALID", "critical", relative, None, f"schema XML is invalid: {exc}")
        return
    root = tree.getroot()
    for schema in root.iter("schema"):
        schema_id = schema.get("id", "")
        if not schema_id:
            report.add("GEXT-SCHEMA-ID", "high", relative, None, "schema without an id")
        report.notes.append(f"schema id: {schema_id}")
        for key in schema.iter("key"):
            key_name = key.get("name", "")
            key_type = key.get("type", "")
            if not key_name or not key_type:
                report.add("GEXT-SCHEMA-KEY", "high", relative, None, f"schema {schema_id} has a key without name/type")
                continue
            report.schema_keys[key_name] = key_type
            default_element = key.find("default")
            default = (default_element.text or "").strip() if default_element is not None else ""
            if key_type == "b":
                if default not in ("true", "false"):
                    report.add("GEXT-SCHEMA-DEFAULT", "medium", relative, None, f"{schema_id}:{key_name} boolean default is {default!r}")
            elif key_type == "s":
                if not (default.startswith("'") and default.endswith("'")):
                    report.add("GEXT-SCHEMA-DEFAULT", "medium", relative, None, f"{schema_id}:{key_name} string default is not quoted: {default!r}")


def scan_extension(directory: Path, report: Report) -> None:
    if not directory.is_dir():
        raise SystemExit(f"error: extension directory does not exist: {directory}")
    for path in sorted(directory.rglob("*")):
        if not path.is_file():
            continue
        relative = str(path.relative_to(directory))
        if any(part in (".git", "node_modules", "__pycache__") for part in path.parts):
            continue
        report.files.append(relative)
        report.hashes[relative] = sha256_file(path)
        if path.suffix == ".js":
            scan_javascript(path, relative, report)
        elif path.name == "metadata.json":
            scan_metadata(path, relative, report)
        elif path.suffix == ".xml":
            scan_schema(path, relative, report)
        elif path.suffix not in (".md", ".txt", ".css", ".ui", ".svg", ".png", ".po", ".pot"):
            report.add("GEXT-UNEXPECTED-FILE", "medium", relative, None, f"unexpected file type in extension: {path.suffix or '<none>'}")

    metadata = report.metadata
    if metadata:
        schema_id = metadata.get("settings-schema")
        schema_ids = [note.split(": ", 1)[1] for note in report.notes if note.startswith("schema id: ")]
        if schema_id and schema_id not in schema_ids:
            report.add("GEXT-SCHEMA-MISMATCH", "high", "metadata.json", None, f"settings-schema {schema_id!r} has no matching schema XML")
        uuid = metadata.get("uuid")
        if isinstance(uuid, str) and uuid and "@" in directory.name and directory.name != uuid:
            report.add("GEXT-UUID-DIRECTORY", "medium", "metadata.json", None, f"uuid {uuid!r} does not match directory name {directory.name!r}")

    for key in report.settings_keys:
        if key not in report.schema_keys:
            report.add("GEXT-SETTINGS-KEY-MISSING", "high", "schemas", None, f"JS uses settings key {key!r} that the schema does not define")


def compare_baseline(report: Report, baseline: dict[str, Any]) -> None:
    expected = baseline.get("gnome_extension", {})
    if not expected:
        report.notes.append("baseline has no gnome_extension section; skipping policy comparison")
        return
    allowed_imports = set(expected.get("allowed_imports", []))
    for module in report.imports:
        if allowed_imports and module not in allowed_imports and not module.startswith(("./", "../", "resource:///org/gnome/")):
            report.add("GEXT-IMPORT-DRIFT", "high", "imports", None, f"import not in baseline: {module}")
    allowed_destinations = set(expected.get("allowed_dbus_destinations", []))
    for destination in report.dbus_destinations:
        if allowed_destinations and destination not in allowed_destinations:
            report.add("GEXT-DBUS-DEST-DRIFT", "high", "dbus", None, f"D-Bus name not in baseline: {destination}")
    allowed_interfaces = set(expected.get("allowed_dbus_interfaces", []))
    for iface in report.dbus_interfaces:
        if allowed_interfaces and iface not in allowed_interfaces:
            report.add("GEXT-DBUS-IFACE-DRIFT", "medium", "dbus", None, f"D-Bus interface not in baseline: {iface}")
    expected_uuid = expected.get("uuid")
    if expected_uuid and report.metadata.get("uuid") != expected_uuid:
        report.add("GEXT-UUID-DRIFT", "high", "metadata.json", None, f"uuid changed: expected {expected_uuid!r}, got {report.metadata.get('uuid')!r}")
    expected_schema = expected.get("settings_schema")
    if expected_schema and report.metadata.get("settings-schema") != expected_schema:
        report.add("GEXT-SCHEMA-DRIFT", "high", "metadata.json", None, f"settings-schema changed: expected {expected_schema!r}, got {report.metadata.get('settings-schema')!r}")
    for key in expected.get("expected_settings_keys", []):
        if key not in report.settings_keys:
            report.add("GEXT-SETTINGS-KEY-UNUSED", "low", "settings", None, f"baseline settings key {key!r} is no longer used by the extension")
    expected_hashes = expected.get("file_hashes", {})
    if expected_hashes:
        for name, digest in expected_hashes.items():
            actual = report.hashes.get(name)
            if actual and actual != digest:
                report.add("GEXT-HASH-DRIFT", "info", name, None, "file hash differs from the recorded baseline")


def print_report(report: Report, verbose: bool) -> None:
    print(f"extension: {report.directory}")
    print(f"files: {len(report.files)}  imports: {len(report.imports)}  settings keys: {len(report.settings_keys)}  schema keys: {len(report.schema_keys)}")
    print(f"D-Bus destinations: {len(report.dbus_destinations)}  interfaces: {len(report.dbus_interfaces)}  paths: {len(report.dbus_paths)}")
    if verbose:
        for module, locations in sorted(report.imports.items()):
            print(f"  import {module}: {', '.join(locations)}")
        for destination in sorted(report.dbus_destinations):
            print(f"  dbus name {destination}")
        for iface in sorted(report.dbus_interfaces):
            print(f"  dbus interface {iface}")
        for key, key_type in sorted(report.schema_keys.items()):
            print(f"  schema key {key} ({key_type})")
    counts = {severity: 0 for severity in SEVERITY_ORDER}
    for finding in report.findings:
        counts[finding.severity] = counts.get(finding.severity, 0) + 1
    print("findings: " + "  ".join(f"{k}={v}" for k, v in counts.items() if v))
    for finding in sorted(report.findings, key=lambda f: -SEVERITY_ORDER.get(f.severity, 0)):
        location = f"{finding.path}:{finding.line}" if finding.line else finding.path
        print(f"[{finding.severity.upper():8}] {finding.rule} {location}: {finding.detail}")


def write_markdown(report: Report, path: Path) -> None:
    lines = [
        "# GNOME Extension Static Audit",
        "",
        f"- Extension: `{report.directory}`",
        f"- Files: {len(report.files)}",
        f"- Imports: {', '.join(sorted(report.imports)) or 'none'}",
        f"- D-Bus names: {', '.join(sorted(report.dbus_destinations)) or 'none'}",
        "",
        "## Findings",
        "",
    ]
    if not report.findings:
        lines.append("No findings at the configured threshold.")
    for finding in sorted(report.findings, key=lambda f: -SEVERITY_ORDER.get(f.severity, 0)):
        location = f"{finding.path}:{finding.line}" if finding.line else finding.path
        lines.append(f"- **{finding.severity.upper()}** `{finding.rule}` ({location}) — {finding.detail}")
    lines += ["", "## File hashes", ""]
    lines += [f"- `{name}` `{digest}`" for name, digest in sorted(report.hashes.items())] or ["- none"]
    lines += ["", "## Notes", ""]
    lines += [f"- {note}" for note in report.notes] or ["- none"]
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("directory", nargs="?", default=".", type=Path, help="extension directory (default: .)")
    parser.add_argument("--baseline", type=Path, help="baseline JSON (default: ../references/network-baseline.json)")
    parser.add_argument("--json", type=Path, help="write the full report as JSON")
    parser.add_argument("--markdown", type=Path, help="write a Markdown report")
    parser.add_argument("--verbose", action="store_true", help="print imports, D-Bus names, and schema keys")
    parser.add_argument("--fail-on", choices=list(SEVERITY_ORDER), default="high", help="exit 1 at/above this severity")
    args = parser.parse_args(argv)

    directory = args.directory.resolve()
    report = Report(directory=str(directory))
    try:
        scan_extension(directory, report)
    except (OSError, UnicodeDecodeError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    baseline_path = args.baseline or Path(__file__).resolve().parent.parent / "references" / "network-baseline.json"
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
    if args.markdown:
        args.markdown.parent.mkdir(parents=True, exist_ok=True)
        write_markdown(report, args.markdown)
        print(f"markdown: {args.markdown}")

    threshold = SEVERITY_ORDER[args.fail_on]
    return 1 if any(SEVERITY_ORDER.get(f.severity, 0) >= threshold for f in report.findings) else 0


if __name__ == "__main__":
    raise SystemExit(main())
