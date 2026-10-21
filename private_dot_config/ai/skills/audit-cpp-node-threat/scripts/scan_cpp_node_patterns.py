#!/usr/bin/env python3
"""
scan_cpp_node_patterns.py - C++ / Node / TypeScript heuristic scanner.

Complements the general repo-threat-audit scanner with checks specific to
native C/C++, CMake/Meson, npm lifecycle scripts, N-API addons, and JS/TS
runtime patterns.

Usage:
    python3 scan_cpp_node_patterns.py <repo-path> [--include-deps] [--json out.json]
"""

import argparse
import json
import os
import re
import sys

DEFAULT_SKIP_DIRS = {
    ".git", "node_modules", "vendor", "venv", ".venv", "target",
    "__pycache__", "dist", "build", "out", ".next", ".nuxt", ".tox",
    "CMakeFiles", ".cache", "coverage",
}

SOURCE_EXTS = {
    ".c", ".cc", ".cpp", ".cxx", ".h", ".hh", ".hpp", ".hxx", ".inl",
    ".mm", ".m",
    ".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".cts", ".mts",
    ".json", ".cmake", ".gyp", ".gypi", ".gn", ".ninja",
    ".yml", ".yaml", ".toml",
}

SOURCE_NAMES = {
    "CMakeLists.txt", "Makefile", "makefile", "GNUmakefile",
    "meson.build", "meson_options.txt",
    "binding.gyp", "binding.gypi",
    "package.json", "package-lock.json", "yarn.lock", "pnpm-lock.yaml",
    "tsconfig.json",
}

BIN_EXTS = {".node", ".so", ".dll", ".exe", ".dylib", ".wasm", ".a"}

# Heuristic typosquat / lookalike npm names (not exhaustive).
SUSPICIOUS_NPM_NAMES = {
    "lodahs", "loadsh", "crossenv", "cross-env.js",
    "electon", "event-stream-fix", "flatmap-stream",
    "babelcli", "mongose", "mongosee",
    "colour-name", "node-uuid-dev",
}

LINE_RULES = [
    # -- C++ networking ------------------------------------------------
    dict(id="CPP-NET-001", severity="medium",
         desc="libcurl / curl_easy usage — outbound HTTP from native code. "
              "Legitimate for many apps; unexpected in a library with no "
              "stated network need.",
         exts={".c", ".cc", ".cpp", ".cxx", ".h", ".hh", ".hpp", ".hxx", ".mm"},
         pattern=re.compile(r"\b(curl_easy_|curl_multi_|CURL \*|libcurl)\b")),
    dict(id="CPP-NET-002", severity="medium",
         desc="WinHTTP / WinInet client APIs.",
         exts={".c", ".cc", ".cpp", ".cxx", ".h", ".hh", ".hpp", ".hxx"},
         pattern=re.compile(r"\b(WinHttpOpen|WinHttpConnect|InternetOpen[AW]?|"
                             r"URLDownloadToFile[AW]?)\b")),
    dict(id="CPP-NET-003", severity="medium",
         desc="Raw TCP/UDP sockets (socket/connect/sendto/WSAStartup).",
         exts={".c", ".cc", ".cpp", ".cxx", ".h", ".hh", ".hpp", ".hxx", ".mm"},
         pattern=re.compile(r"\b(socket|connect|sendto|recvfrom|WSAStartup|"
                             r"getaddrinfo)\s*\(")),
    dict(id="CPP-NET-004", severity="low",
         desc="Hardcoded IPv4 literal — check if C2/exfil vs documented endpoint.",
         exts={".c", ".cc", ".cpp", ".cxx", ".h", ".hh", ".hpp", ".hxx",
               ".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs"},
         pattern=re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d?\d)\.){3}"
                             r"(?:25[0-5]|2[0-4]\d|[01]?\d?\d)\b")),

    # -- C++ execution / loading --------------------------------------
    dict(id="CPP-EXEC-001", severity="high",
         desc="system()/popen()/WinExec/CreateProcess — process spawn from native code.",
         exts={".c", ".cc", ".cpp", ".cxx", ".h", ".hh", ".hpp", ".hxx", ".mm"},
         pattern=re.compile(r"\b(system|popen|_popen|WinExec|CreateProcess[AW]?|"
                             r"ShellExecute[AW]?)\s*\(")),
    dict(id="CPP-EXEC-002", severity="high",
         desc="POSIX exec family (execl/execve/execvp) or fork+exec.",
         exts={".c", ".cc", ".cpp", ".cxx", ".h", ".hh", ".hpp", ".hxx"},
         pattern=re.compile(r"\b(execl|execle|execlp|execv|execve|execvp|execvpe)\s*\(")),
    dict(id="CPP-LOAD-001", severity="high",
         desc="dlopen / LoadLibrary / GetProcAddress — runtime code loading.",
         exts={".c", ".cc", ".cpp", ".cxx", ".h", ".hh", ".hpp", ".hxx"},
         pattern=re.compile(r"\b(dlopen|dlsym|LoadLibrary[AW]?|GetProcAddress|"
                             r"LoadLibraryEx[AW]?)\s*\(")),
    dict(id="CPP-CTOR-001", severity="high",
         desc="GCC/Clang constructor attribute — runs before main().",
         exts={".c", ".cc", ".cpp", ".cxx", ".h", ".hh", ".hpp", ".hxx"},
         pattern=re.compile(r"__attribute__\s*\(\s*\(\s*constructor\s*\)\s*\)|"
                             r"__attribute__\s*\(\s*\(\s*destructor\s*\)\s*\)")),
    dict(id="CPP-CTOR-002", severity="high",
         desc="DllMain — runs on every load/unload of a Windows DLL.",
         exts={".c", ".cc", ".cpp", ".cxx", ".h", ".hh", ".hpp", ".hxx"},
         pattern=re.compile(r"\bDllMain\s*\(")),

    # -- C++ persistence / rootkit-ish --------------------------------
    dict(id="CPP-PERSIST-001", severity="high",
         desc="References autostart, systemd user units, cron, shell rc, "
              "or Windows Run keys from native code.",
         exts={".c", ".cc", ".cpp", ".cxx", ".h", ".hh", ".hpp", ".hxx"},
         pattern=re.compile(r"\.config/autostart|systemd/user|/etc/cron|"
                             r"\.bashrc|\.zshrc|CurrentVersion\\\\Run|"
                             r"Software\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Run")),
    dict(id="CPP-ROOT-001", severity="critical",
         desc="LD_PRELOAD, ld.so.preload, ptrace, or /proc/self/mem — "
              "classic userland-rootkit primitives.",
         exts={".c", ".cc", ".cpp", ".cxx", ".h", ".hh", ".hpp", ".hxx"},
         pattern=re.compile(r"LD_PRELOAD|/etc/ld\.so\.preload|\bptrace\s*\(|"
                             r"/proc/self/mem")),
    dict(id="CPP-INJECT-001", severity="critical",
         desc="Process-injection APIs (VirtualAllocEx, WriteProcessMemory, "
              "CreateRemoteThread, NtCreateThreadEx).",
         exts={".c", ".cc", ".cpp", ".cxx", ".h", ".hh", ".hpp", ".hxx"},
         pattern=re.compile(r"\b(VirtualAllocEx|WriteProcessMemory|"
                             r"CreateRemoteThread|NtCreateThreadEx|"
                             r"QueueUserAPC)\s*\(")),

    # -- C++ obfuscation / droppers -----------------------------------
    dict(id="CPP-OBF-001", severity="medium",
         desc="XOR loop over a byte buffer — often payload decoding; also "
              "used for simple checksums. Read the buffer's destination.",
         exts={".c", ".cc", ".cpp", ".cxx", ".h", ".hh", ".hpp", ".hxx"},
         pattern=re.compile(r"\^\s*=\s*(0x[0-9A-Fa-f]+|\d+)\s*;|"
                             r"\[\s*\w+\s*\]\s*\^=\s*")),
    dict(id="CPP-OBF-002", severity="high",
         desc="VirtualAlloc / mmap RWX then function-pointer cast — "
              "in-memory execute of a blob.",
         exts={".c", ".cc", ".cpp", ".cxx", ".h", ".hh", ".hpp", ".hxx"},
         pattern=re.compile(r"\b(VirtualAlloc|VirtualProtect|mmap)\s*\(")),
    dict(id="CPP-ENV-001", severity="medium",
         desc="Reads environment variables from native code — check if sent "
              "over the network or used as an exec path.",
         exts={".c", ".cc", ".cpp", ".cxx", ".h", ".hh", ".hpp", ".hxx"},
         pattern=re.compile(r"\b(getenv|secure_getenv|GetEnvironmentVariable[AW]?)\s*\(")),

    # -- Build systems ------------------------------------------------
    dict(id="CPP-BUILD-001", severity="high",
         desc="CMake file(DOWNLOAD or FetchContent — downloads at configure time.",
         exts={".cmake", ".txt"},
         pattern=re.compile(r"\b(file\s*\(\s*DOWNLOAD|FetchContent_Declare|"
                             r"ExternalProject_Add)\b", re.I)),
    dict(id="CPP-BUILD-002", severity="high",
         desc="CMake execute_process — runs host commands during configure.",
         exts={".cmake", ".txt"},
         pattern=re.compile(r"\bexecute_process\s*\(", re.I)),
    dict(id="CPP-BUILD-003", severity="high",
         desc="CMake/Make/Meson invoking curl or wget.",
         exts={".cmake", ".txt", ".build", ""},
         names={"CMakeLists.txt", "Makefile", "makefile", "GNUmakefile",
                "meson.build"},
         pattern=re.compile(r"\b(curl|wget)\b")),
    dict(id="CPP-BUILD-004", severity="medium",
         desc="node-gyp / binding.gyp custom action — can run arbitrary commands "
              "when the native addon compiles.",
         exts={".gyp", ".gypi", ".json"},
         names={"binding.gyp", "binding.gypi"},
         pattern=re.compile(r'["\']actions["\']\s*:|"action"\s*:')),

    # -- JS/TS execution ----------------------------------------------
    dict(id="JS-EXEC-001", severity="high",
         desc="eval / new Function / vm.runIn* — dynamic JS execution.",
         exts={".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".cts", ".mts"},
         pattern=re.compile(r"\b(eval\s*\(|new\s+Function\s*\(|"
                             r"vm\.(runInThisContext|runInNewContext|runInContext|"
                             r"compileFunction)\s*\()")),
    dict(id="JS-EXEC-002", severity="high",
         desc="child_process exec/execSync/spawn with shell, or execFile of sh.",
         exts={".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".cts", ".mts"},
         pattern=re.compile(r"child_process\.(exec|execSync|execFile|spawn|fork)\s*\(|"
                             r"require\(\s*['\"]child_process['\"]\s*\)|"
                             r"from\s+['\"]node:child_process['\"]|"
                             r"from\s+['\"]child_process['\"]")),
    dict(id="JS-EXEC-003", severity="high",
         desc="Dynamic require/import of a non-literal path — can load attacker code.",
         exts={".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs"},
         pattern=re.compile(r"require\s*\(\s*[^'\"\s]|"
                             r"import\s*\(\s*[^'\"`\s]")),

    # -- JS/TS network ------------------------------------------------
    dict(id="JS-NET-001", severity="medium",
         desc="Node HTTP(S) / net / dgram client or server.",
         exts={".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".cts", ".mts"},
         pattern=re.compile(r"\b(https?|net|dgram|tls)\.(request|get|createServer|"
                             r"connect|createConnection)\s*\(|"
                             r"from\s+['\"]node:(https?|net|dgram|tls)['\"]")),
    dict(id="JS-NET-002", severity="medium",
         desc="axios / node-fetch / got / undici / WebSocket client.",
         exts={".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs"},
         pattern=re.compile(r"\b(axios|node-fetch|got|undici|node:fetch)\b|"
                             r"new\s+WebSocket\s*\(|from\s+['\"]ws['\"]")),
    dict(id="JS-NET-003", severity="low",
         desc="Telemetry / analytics package names.",
         exts={".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".json"},
         pattern=re.compile(r"\b(sentry|segment|mixpanel|posthog|amplitude|"
                             r"@sentry/node|applicationinsights)\b")),

    # -- npm supply chain ---------------------------------------------
    dict(id="JS-SUPPLY-001", severity="critical",
         desc="npm lifecycle script (pre/post/install/prepare) shells out to "
              "curl/wget or node -e. Runs automatically on npm install.",
         exts={".json"},
         names={"package.json"},
         pattern=re.compile(
             r'"(preinstall|postinstall|install|prepare|prepublish|prepublishOnly)"'
             r'\s*:\s*"[^"]*(curl|wget|node\s+-e|npx\s+--yes)')),
    dict(id="JS-SUPPLY-002", severity="high",
         desc="Any npm lifecycle script is present — read what it runs.",
         exts={".json"},
         names={"package.json"},
         pattern=re.compile(
             r'"(preinstall|postinstall|install|prepare|prepublish|prepublishOnly)"'
             r'\s*:')),
    dict(id="JS-SUPPLY-003", severity="high",
         desc="Dependency pinned to git URL instead of the npm registry.",
         exts={".json"},
         names={"package.json"},
         pattern=re.compile(r'"(git\+https?://|github:|gitlab:|bitbucket:|git://)')),
    dict(id="JS-SUPPLY-004", severity="medium",
         desc="package.json overrides/resolutions — can silently substitute a package.",
         exts={".json"},
         names={"package.json"},
         pattern=re.compile(r'"(overrides|resolutions)"\s*:')),

    # -- Native Node addons -------------------------------------------
    dict(id="JS-NATIVE-001", severity="medium",
         desc="N-API / node-addon-api / bindings — native addon load path.",
         exts={".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".json"},
         pattern=re.compile(r"\b(bindings|node-addon-api|node-gyp-build|"
                             r"napi-rs|prebuild-install)\b|"
                             r"require\s*\(\s*['\"][^'\"]+\.node['\"]")),
    dict(id="JS-ELECTRON-001", severity="high",
         desc="Electron nodeIntegration enabled or contextIsolation disabled.",
         exts={".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs"},
         pattern=re.compile(r"nodeIntegration\s*:\s*true|"
                             r"contextIsolation\s*:\s*false")),

    # -- JS obfuscation -----------------------------------------------
    dict(id="JS-OBF-001", severity="high",
         desc="base64/Buffer decode near eval/Function — classic payload smuggle.",
         exts={".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs"},
         pattern=re.compile(
             r"(atob\(|Buffer\.from\([^,]+,\s*['\"]base64['\"])"
             r"[^\n]{0,120}(eval\(|new\s+Function)"
             r"|(eval\(|new\s+Function)[^\n]{0,120}"
             r"(atob\(|Buffer\.from\([^,]+,\s*['\"]base64['\"])")),
    dict(id="JS-OBF-002", severity="medium",
         desc="fromCharCode chain used to hide a string.",
         exts={".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs"},
         pattern=re.compile(r"String\.fromCharCode\([^)]*,[^)]*,[^)]*,")),
    dict(id="JS-FS-001", severity="medium",
         desc="Writes files under home/config or chmod +x from JS.",
         exts={".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs"},
         pattern=re.compile(r"fs\.(writeFile|appendFile|chmod|copyFile)Sync?\s*\(|"
                             r"from\s+['\"]node:fs['\"]")),
    dict(id="SECRET-001", severity="high",
         desc="Hardcoded private key block.",
         exts="all",
         pattern=re.compile(r"-----BEGIN (RSA |OPENSSH |EC |DSA )?PRIVATE KEY-----")),
]

FILE_RULES = [
    dict(id="CPP-FILE-001", severity="critical",
         desc="Same native file reads credentials/SSH keys AND uses network APIs.",
         exts={".c", ".cc", ".cpp", ".cxx", ".h", ".hh", ".hpp", ".hxx"},
         patterns=[
             re.compile(r"(\.ssh/id_|\.aws/credentials|\.git-credentials|"
                         r"id_rsa|id_ed25519)"),
             re.compile(r"\b(curl_easy_|WinHttp|socket\s*\(|connect\s*\()\b"),
         ],
         point_at=0),
    dict(id="CPP-FILE-002", severity="critical",
         desc="Constructor/DllMain in the same file as network or process spawn.",
         exts={".c", ".cc", ".cpp", ".cxx", ".h", ".hh", ".hpp", ".hxx"},
         patterns=[
             re.compile(r"__attribute__\s*\(\s*\(\s*constructor\s*\)\s*\)|\bDllMain\s*\("),
             re.compile(r"\b(system|popen|curl_easy_|socket|connect|WinHttpOpen)\s*\("),
         ],
         point_at=0),
    dict(id="CPP-FILE-003", severity="critical",
         desc="CMake downloads AND executes a command — fetch-at-build-time.",
         names={"CMakeLists.txt"},
         exts={".txt", ".cmake"},
         patterns=[
             re.compile(r"\b(file\s*\(\s*DOWNLOAD|FetchContent_Declare|ExternalProject_Add)\b", re.I),
             re.compile(r"\b(execute_process|COMMAND)\b"),
         ],
         point_at=0),
    dict(id="JS-FILE-001", severity="critical",
         desc="Same JS/TS file reads credentials AND makes an outbound HTTP call.",
         exts={".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs"},
         patterns=[
             re.compile(r"(\.ssh/id_|\.aws/credentials|\.npmrc|"
                         r"\.git-credentials|id_rsa|id_ed25519)"),
             re.compile(r"\b(https?\.request|axios|fetch\s*\(|got\()"),
         ],
         point_at=0),
    dict(id="JS-FILE-002", severity="high",
         desc="Decodes base64/Buffer data and spawns a process in the same file.",
         exts={".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs"},
         patterns=[
             re.compile(r"atob\(|Buffer\.from\([^,]+,\s*['\"]base64['\"]"),
             re.compile(r"child_process\.(exec|execSync|spawn|fork)"),
         ],
         point_at=0),
]


def rule_applies(rule, name, ext):
    if rule["exts"] == "all":
        ext_ok = True
    else:
        ext_ok = ext in rule["exts"]
    if not ext_ok:
        return False
    if "names" in rule and name not in rule["names"]:
        return False
    return True


def iter_files(root, include_deps, max_bytes):
    for dirpath, dirnames, filenames in os.walk(root):
        if not include_deps:
            dirnames[:] = [d for d in dirnames if d not in DEFAULT_SKIP_DIRS]
        for name in filenames:
            ext = os.path.splitext(name)[1].lower()
            path = os.path.join(dirpath, name)
            if ext in BIN_EXTS:
                yield path, name, ext, "bin"
                continue
            if ext not in SOURCE_EXTS and name not in SOURCE_NAMES:
                continue
            try:
                if os.path.getsize(path) > max_bytes:
                    continue
            except OSError:
                continue
            yield path, name, ext, "text"


def check_typosquat_npm(path, text):
    findings = []
    if os.path.basename(path) != "package.json":
        return findings
    for crate in SUSPICIOUS_NPM_NAMES:
        if re.search(r'["\']' + re.escape(crate) + r'["\']', text):
            line_no = 1
            snippet = crate
            for i, line in enumerate(text.splitlines(), 1):
                if crate in line:
                    line_no = i
                    snippet = line.strip()[:200]
                    break
            findings.append({
                "rule_id": "JS-SUPPLY-005",
                "severity": "high",
                "description": "Dependency name matches a known typosquat/"
                                "malicious npm name shape. Verify on npmjs.com.",
                "file": path,
                "line": line_no,
                "snippet": snippet,
            })
    return findings


def scan_bin(path, name, ext):
    return [{
        "rule_id": "BIN-001",
        "severity": "high",
        "description": "Committed native/binary blob (%s). Confirm it has "
                       "matching source and expected `file` magic — unaudited "
                       ".node/.so/.dll/.exe/.wasm is a supply-chain vector." % ext,
        "file": path,
        "line": 1,
        "snippet": name,
    }]


def scan_file(path, name, ext):
    findings = []
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            text = f.read()
    except OSError:
        return findings

    lines = text.splitlines()

    for rule in LINE_RULES:
        if not rule_applies(rule, name, ext):
            continue
        if ext == ".txt" and name != "CMakeLists.txt" and rule["exts"] != "all":
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
        if not rule_applies(rule, name, ext):
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

    findings.extend(check_typosquat_npm(path, text))
    return findings


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("path")
    ap.add_argument("--include-deps", action="store_true",
                    help="Also scan node_modules/build/dist (slow, noisy)")
    ap.add_argument("--max-file-mb", type=float, default=2.0)
    ap.add_argument("--json", default=None)
    args = ap.parse_args()

    max_bytes = int(args.max_file_mb * 1024 * 1024)
    all_findings = []
    files_scanned = 0

    for path, name, ext, kind in iter_files(args.path, args.include_deps, max_bytes):
        files_scanned += 1
        if kind == "bin":
            all_findings.extend(scan_bin(path, name, ext))
        else:
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
