#!/usr/bin/env python3
"""
scan_patterns.py - Heuristic scanner for hidden malware in a repository.

Pure stdlib, no dependencies, no network access needed. Walks a directory tree
and applies a catalog of checks aimed at the ways malicious code actually hides
in a codebase: dynamic execution, remote fetch-and-run one-liners, obfuscation
tricks, decode-and-drop-to-disk payloads, exfiltration heuristics, persistence
(cron, shell rc files, systemd user units, GNOME autostart, LD_PRELOAD), risky
install-time hooks (npm postinstall, setup.py, git hooks), and a light pass for
hardcoded secrets/private keys. It also understands shell-script repos
specifically (plugin managers, dotfiles, frameworks): extensionless files with
a shell shebang, prompt/command hooks used for stealthy persistence, and
aliasing over sensitive commands.

This is a triage tool, not a verdict. It is deliberately biased toward finding
candidates (recall) over being quiet (precision) -- every hit needs a human (or
Claude) to read the surrounding code and decide if it's actually malicious or a
legitimate use of a risky-looking API. See references/threat-patterns.md for
the reasoning behind each rule and known false-positive shapes.

Usage:
    python3 scan_patterns.py <path> [--include-deps] [--max-file-mb N] [--json out.json]
"""

import argparse
import json
import os
import re
import sys

# Directories skipped by default -- vendored/dependency trees are huge, mostly
# third-party, and better audited via `--include-deps` or a dedicated
# dependency-vuln tool (npm audit, pip-audit) than a full recursive code scan.
DEFAULT_SKIP_DIRS = {
    ".git", "node_modules", "vendor", "venv", ".venv", "env",
    "__pycache__", "dist", "build", ".tox", "target", ".mypy_cache",
    ".pytest_cache", "site-packages",
}

SHELL_EXTS = {".sh", ".bash", ".zsh", ".zsh-theme", ".ksh"}

SOURCE_EXTS = SHELL_EXTS | {
    ".py", ".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".rb", ".php",
    ".ps1", ".psm1", ".pl", ".go", ".java",
    ".c", ".cpp", ".h", ".cs", ".rs", ".lua", ".yaml", ".yml", ".json",
    ".txt", ".cfg", ".ini", ".toml", ".xml", ".html", ".desktop", ".service",
}

MANIFEST_NAMES = {
    "package.json", "requirements.txt", "pyproject.toml", "setup.py",
    "Gemfile", "composer.json", "Cargo.toml", "Makefile",
}

SHEBANG_RE = re.compile(r"^#!.*\b(sh|bash|zsh|dash|ksh)\b")

# Executable-ish scripting languages, keyed by "rule ext" -- used for rules
# whose exts set is the literal string "shell" or "script".
SCRIPT_EXTS = SHELL_EXTS | {".py", ".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".ps1", ".psm1"}


def rule_applies(rule_exts, ext):
    if rule_exts == "all":
        return True
    if rule_exts == "shell":
        return ext in SHELL_EXTS
    if rule_exts == "script":
        return ext in SCRIPT_EXTS
    return ext in rule_exts


# Each rule: id, severity, description (the "why"), the exts it applies to
# ("all" / "shell" / "script" / an explicit set), and a compiled regex.
LINE_RULES = [
    # -- Dangerous dynamic execution -----------------------------------
    dict(id="EXEC-001", severity="high",
         desc="Dynamic evaluation of a string as code (eval/exec/Function). "
              "Legitimate uses exist (templating, JIT), but it's also the #1 "
              "way obfuscated payloads get run.",
         exts={".py", ".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs"},
         pattern=re.compile(r"\b(eval|exec)\s*\(|new\s+Function\s*\(")),
    dict(id="EXEC-002", severity="high",
         desc="Shell command execution with shell interpretation enabled "
              "(subprocess shell=True, os.system, os.popen, child_process.exec). "
              "Worth checking whether the command string includes any "
              "unsanitized input.",
         exts={".py", ".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs"},
         pattern=re.compile(r"os\.system\(|os\.popen\(|shell\s*=\s*True|"
                             r"child_process\.(exec|execSync)\(")),
    dict(id="EXEC-003", severity="high",
         desc="PowerShell dynamic execution (Invoke-Expression / iex / "
              "-EncodedCommand). Extremely common in Windows-targeted "
              "droppers and phishing payloads.",
         exts={".ps1", ".psm1", ".bat", ".cmd"},
         pattern=re.compile(r"Invoke-Expression|(?<![A-Za-z])iex\s|"
                             r"-[Ee]nc(odedCommand)?\b")),

    # -- Remote fetch-and-run --------------------------------------------
    dict(id="FETCH-001", severity="critical",
         desc="Downloads a remote script and pipes it directly into an "
              "interpreter without inspection. This is the single most "
              "common one-liner in supply-chain compromises.",
         exts="all",
         pattern=re.compile(r"(curl|wget)\s[^\n|]*\|\s*(sudo\s+)?(sh|bash|zsh|python[0-9.]*)\b")),
    dict(id="FETCH-002", severity="high",
         desc="Fetches remote content and evaluates it as code (fetch/urlopen "
              "chained into eval or exec).",
         exts={".py", ".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs"},
         pattern=re.compile(r"(fetch\(|urlopen\(|requests\.get\().{0,200}(eval\(|exec\()", re.S)),
    dict(id="SHELL-001", severity="critical",
         desc="Sources or eval's remote content directly into the current "
              "shell (source <(curl ...), . <(wget ...), eval \"$(curl ...)\"). "
              "In a shell framework/plugin-manager repo this is especially "
              "dangerous: it runs with the privileges of every interactive "
              "shell that loads it, silently, on every terminal open.",
         exts="shell",
         pattern=re.compile(r"(source|\.)\s+<\(\s*(curl|wget)\b|"
                             r"eval\s+[\"']\$\((curl|wget)\b")),

    # -- Obfuscation indicators -------------------------------------------
    dict(id="OBF-001", severity="high",
         desc="A long base64-looking string is decoded and passed into an "
              "executor, in either order (decode-then-exec, or exec wrapping "
              "a nested decode call like exec(base64.b64decode(x))). "
              "Classic payload-smuggling pattern.",
         exts={".py", ".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs"},
         pattern=re.compile(
             r"(atob\(|base64\.b64decode\(|Buffer\.from\([^,]+,\s*['\"]base64)"
             r"[^\n]{0,120}(eval\(|exec\(|Function\()"
             r"|(eval\(|exec\(|Function\()[^\n]{0,120}"
             r"(atob\(|base64\.b64decode\(|Buffer\.from\([^,]+,\s*['\"]base64)")),
    dict(id="OBF-002", severity="medium",
         desc="String built character-by-character via charCode/chr instead "
              "of a literal -- a common way to hide a suspicious string "
              "(URL, command name) from a quick visual read or naive grep.",
         exts={".py", ".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs"},
         pattern=re.compile(r"(String\.fromCharCode\([^)]*,[^)]*,[^)]*,|"
                             r"chr\(\d+\)\s*\+\s*chr\(\d+\)\s*\+\s*chr\(\d+\))")),
    dict(id="OBF-003", severity="critical",
         desc="Contains a zero-width character or the right-to-left "
              "override (U+202E). These are invisible or reorder how code "
              "*displays* without changing what it *does* -- used to hide "
              "malicious code from visual review.",
         exts="all",
         pattern=re.compile(r"[\u200b\u200c\u200d\ufeff\u202e]")),

    # -- Exfiltration heuristics -------------------------------------------
    dict(id="EXFIL-001", severity="high",
         desc="Reads an SSH key, cloud credentials file, or shell history, "
              "with a network call nearby in the same file. Check whether "
              "the file's actual purpose has any legitimate reason to touch "
              "credentials.",
         exts="script",
         pattern=re.compile(r"(\.ssh/id_rsa|\.ssh/id_ed25519|\.aws/credentials|\.npmrc|"
                             r"\.git-credentials|\.bash_history|\.zsh_history)")),
    dict(id="EXFIL-002", severity="medium",
         desc="Environment variables or process environment are serialized "
              "and referenced near an outbound HTTP call -- worth checking "
              "whether secrets are being phoned home.",
         exts={".py", ".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs"},
         pattern=re.compile(r"(process\.env|os\.environ)[^\n]{0,150}"
                             r"(requests\.(post|get)\(|fetch\(|axios\.)", re.S)),
    dict(id="EXFIL-003", severity="low",
         desc="References a webhook/paste-style endpoint (Discord webhook, "
              "raw pastebin/pastes, ngrok tunnel). These are legitimate for "
              "many apps but are also popular free exfil/C2 channels for "
              "malicious packages -- check the surrounding context.",
         exts="all",
         pattern=re.compile(r"(discord(app)?\.com/api/webhooks|pastebin\.com/raw|"
                             r"\.ngrok\.io|\.ngrok-free\.app)")),

    # -- Persistence ---------------------------------------------------------
    dict(id="PERSIST-001", severity="high",
         desc="Writes to a crontab or appends to a shell startup file "
              "(.bashrc/.zshrc/.zshenv/.zprofile/.profile) -- a way for code "
              "to keep running after the current process exits, or on every "
              "future shell session.",
         exts="all",
         pattern=re.compile(r"(crontab\s+-|/etc/cron|"
                             r">>\s*[\"']?~?/?\.?(bashrc|zshrc|zshenv|zprofile|profile)['\"]?)")),
    dict(id="PERSIST-002", severity="high",
         desc="Writes a GNOME autostart entry, systemd user unit, or dconf/"
              "gsettings key, or enables a systemd --user service. On a "
              "Linux desktop these all mean 'run automatically at login or "
              "on every session' -- legitimate for an installer, suspicious "
              "for anything else.",
         exts="all",
         pattern=re.compile(r"(\.config/autostart/|\.config/systemd/user/|"
                             r"systemctl\s+--user\s+enable|gsettings\s+set|dconf\s+write)")),
    dict(id="PERSIST-003", severity="critical",
         desc="Sets LD_PRELOAD or writes to /etc/ld.so.preload -- a classic "
              "Linux technique to inject a shared library into every "
              "subsequently launched process. Almost never legitimate "
              "outside of specialized debugging tools.",
         exts="all",
         pattern=re.compile(r"(LD_PRELOAD\s*=|/etc/ld\.so\.preload)")),
    dict(id="SHELL-002", severity="high",
         desc="Redefines a security-sensitive command (sudo, ssh, git, curl, "
              "wget, su, passwd) as an alias or function. The classic shell "
              "technique for intercepting credentials or silently changing "
              "what a trusted command does.",
         exts="shell",
         pattern=re.compile(r"\balias\s+(sudo|ssh|scp|curl|wget|git|su|passwd)\s*=|"
                             r"\bfunction\s+(sudo|ssh|scp|curl|wget|git|su|passwd)\b|"
                             r"^\s*(sudo|ssh|scp|curl|wget|git|su|passwd)\s*\(\)\s*\{",
                             re.M)),

    # -- Supply-chain / install-time hooks -----------------------------------
    dict(id="SUPPLY-001", severity="critical",
         desc="An npm pre/post-install lifecycle script exists and shells "
              "out to curl/wget or invokes node -e with inline code. "
              "Lifecycle scripts run automatically on `npm install` with no "
              "prompt, making them a favorite supply-chain vector.",
         exts={".json"},
         names={"package.json"},
         pattern=re.compile(r'"(pre|post)?install"\s*:\s*"[^"]*(curl|wget|node -e)')),
    dict(id="SUPPLY-002", severity="high",
         desc="setup.py runs network or shell activity at import/build time "
              "(outside of a normal install_requires/entry_points setup) -- "
              "pip runs setup.py automatically during install.",
         exts={".py"},
         names={"setup.py"},
         pattern=re.compile(r"(os\.system\(|subprocess\.|urllib\.request|requests\.)")),

    # -- Secrets (lightweight pass -- not a substitute for a dedicated
    #    secret-scanning tool, but cheap and catches the obvious cases) ------
    dict(id="SECRET-001", severity="high",
         desc="A hardcoded private key block. If this is a real key (not a "
              "test fixture), it's a credential leak at minimum, and a "
              "planted backdoor at worst.",
         exts="all",
         pattern=re.compile(r"-----BEGIN (RSA |OPENSSH |EC |DSA |PGP )?PRIVATE KEY-----")),
    dict(id="SECRET-002", severity="medium",
         desc="Matches the shape of a live cloud/service credential (AWS "
              "access key ID, GitHub personal access token). Could be a "
              "real leaked credential or a test fixture -- check context.",
         exts="all",
         pattern=re.compile(r"\bAKIA[0-9A-Z]{16}\b|\bghp_[A-Za-z0-9]{36}\b|"
                             r"\bgithub_pat_[A-Za-z0-9_]{22,}\b")),
]


# Whole-file heuristics: some patterns only make sense as "does this file
# contain BOTH of these things, anywhere" rather than a single line/window
# match. Each entry: id, severity, desc, exts, a list of regexes that must
# ALL match somewhere in the file, and which of those regexes to point the
# finding at (index into the list).
FILE_RULES = [
    dict(id="SHELL-003", severity="high",
         desc="Defines a prompt/command hook (precmd, preexec, chpwd, "
              "PROMPT_COMMAND) in the same file as a network call. These "
              "hooks fire on every prompt or every directory change -- "
              "combined with network activity, that's silent, repeated "
              "execution the user never explicitly triggered. Very much "
              "worth reading in full; plenty of legitimate prompt plugins "
              "(git status, version managers) do make network-adjacent "
              "calls, but they should be checking local state, not phoning "
              "out on every keystroke.",
         exts="shell",
         patterns=[
             re.compile(r"\b(precmd|preexec|chpwd)\s*\(\)|PROMPT_COMMAND\s*="),
             re.compile(r"\b(curl|wget|nc|ncat|/dev/tcp/)\b"),
         ],
         point_at=0),
    dict(id="DROP-001", severity="critical",
         desc="Decodes a blob to disk, marks it executable, and runs it "
              "(base64 -d > file; chmod +x file; ./file), or the "
              "equivalent. This 'decode, drop to disk, execute' sequence "
              "is a staple of shell-script-delivered malware because it "
              "avoids ever putting the real payload in a way that greps "
              "for eval/exec would catch.",
         exts="script",
         patterns=[
             re.compile(r"base64\s+(-d|--decode)\b|openssl\s+enc\s+-d\b"),
             re.compile(r"chmod\s+\+x\b"),
         ],
         point_at=0),
]


def iter_files(root, include_deps, max_bytes):
    for dirpath, dirnames, filenames in os.walk(root):
        if not include_deps:
            dirnames[:] = [d for d in dirnames if d not in DEFAULT_SKIP_DIRS]
        for name in filenames:
            ext = os.path.splitext(name)[1]
            path = os.path.join(dirpath, name)
            if ext in SOURCE_EXTS or name in MANIFEST_NAMES:
                yield path, name, ext
                continue
            # Extensionless (or unrecognized-extension) files are common in
            # shell frameworks/plugin managers -- peek the shebang before
            # skipping.
            try:
                if os.path.getsize(path) > max_bytes or os.path.getsize(path) == 0:
                    continue
                with open(path, "r", encoding="utf-8", errors="ignore") as f:
                    first_line = f.readline()
            except OSError:
                continue
            if SHEBANG_RE.match(first_line):
                yield path, name, ".sh"


def check_git_hooks(root):
    """.git is skipped by the main walk, but hooks are a real vector: a
    plugin manager or dotfiles repo that plants a non-sample, executable
    hook runs it automatically on the next git operation."""
    findings = []
    hooks_dir = os.path.join(root, ".git", "hooks")
    if not os.path.isdir(hooks_dir):
        return findings
    for name in os.listdir(hooks_dir):
        if name.endswith(".sample"):
            continue
        path = os.path.join(hooks_dir, name)
        if os.path.isfile(path) and os.access(path, os.X_OK):
            findings.append({
                "rule_id": "GIT-001",
                "severity": "medium",
                "description": "A non-sample, executable git hook is present. "
                                "Hooks run automatically on git operations "
                                "(commit, checkout, push) with no prompt. "
                                "Legitimate in projects that use hooks for "
                                "linting/formatting -- but worth reading in "
                                "full, since it's an easy place to hide "
                                "something that only fires locally and never "
                                "shows up in the diffed source tree.",
                "file": path,
                "line": 1,
                "snippet": name,
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
        if not rule_applies(rule["exts"], ext):
            continue
        if "names" in rule and name not in rule["names"]:
            continue
        for m in rule["pattern"].finditer(text):
            line_no = text.count("\n", 0, m.start()) + 1
            snippet = lines[line_no - 1].strip() if 0 < line_no <= len(lines) else ""
            findings.append({
                "rule_id": rule["id"], "severity": rule["severity"],
                "description": rule["desc"], "file": path, "line": line_no,
                "snippet": snippet[:200],
            })

    for rule in FILE_RULES:
        if not rule_applies(rule["exts"], ext):
            continue
        if not all(p.search(text) for p in rule["patterns"]):
            continue
        m = rule["patterns"][rule["point_at"]].search(text)
        line_no = text.count("\n", 0, m.start()) + 1 if m else 1
        snippet = lines[line_no - 1].strip() if 0 < line_no <= len(lines) else ""
        findings.append({
            "rule_id": rule["id"], "severity": rule["severity"],
            "description": rule["desc"], "file": path, "line": line_no,
            "snippet": snippet[:200],
        })

    return findings


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("path")
    ap.add_argument("--include-deps", action="store_true",
                     help="Also scan node_modules/vendor/venv/etc (slow, noisy)")
    ap.add_argument("--max-file-mb", type=float, default=2.0)
    ap.add_argument("--json", default=None, help="Write findings JSON to this path too")
    args = ap.parse_args()

    max_bytes = int(args.max_file_mb * 1024 * 1024)
    all_findings = []
    files_scanned = 0
    for path, name, ext in iter_files(args.path, args.include_deps, max_bytes):
        files_scanned += 1
        all_findings.extend(scan_file(path, name, ext))

    all_findings.extend(check_git_hooks(args.path))

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
