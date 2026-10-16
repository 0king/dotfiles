---
name: audit-cpp-node-threat
description: Audit C++, Node.js, and TypeScript repositories for hidden malware, supply-chain risks, native-addon backdoors, and suspicious network behavior. Runs the general repo-threat-audit scanner plus C++/Node/TS pattern scanners, then triages CMake/npm lifecycle scripts, native binaries, and N-API addons. Use when the user asks to audit, scan, or vet a C++, Node, TypeScript, or mixed native+JS repo for malware, backdoors, hidden threats, or suspicious dependencies — including "is this npm package safe", "check this before npm install", "does this C++ project phone home", or "/audit-cpp-node".
---

# C++ / Node / TypeScript Repo Threat Audit

Heuristic triage for hidden or malicious behavior in C++, Node.js, and TypeScript
codebases (including mixed native addons). Combines the general
[repo-threat-audit](../audit-threat/SKILL.md) pass with language-specific checks.
Pattern matching is recall-biased — triage every hit in context before reporting.

Not a CVE/`npm audit`/`cppcheck` substitute. Goal is *intentionally hidden*
behavior: install-time hooks, fetch-and-run, persistence, credential exfil,
obfuscated payloads, and unexpected network from native code.

## Workflow

### 1. Confirm the target

Get the repo path on disk (clone first if the user only gave a URL). Ask if unclear.

Note **target OS** and whether they care about **runtime network** vs static review.
If they will run `npm install` or build native code, say so in the report — install
and compile-time hooks fire before they ever start the app.

### 2. Run both scanners

Run from this skill directory (adjust if the skill lives elsewhere):

```bash
SKILL=~/.cursor/skills/audit-cpp-node-threat
GENERAL=~/.cursor/skills/audit-threat

python3 "$GENERAL/scripts/scan_patterns.py" <repo-path> --json /tmp/cpp-node-general-findings.json
python3 "$SKILL/scripts/scan_cpp_node_patterns.py" <repo-path> --json /tmp/cpp-node-findings.json
```

- Skip `node_modules/`, `build/`, `dist/`, `out/`, `.next/`, `vendor/` by default.
  Pass `--include-deps` only if the user wants those trees scanned — warn it's slower
  and noisier.
- Read both JSON outputs; merge and dedupe by file+line when reporting.

### 3. Language-specific manual pass

While triaging scanner hits, also check:

| Area | What to look for |
|------|------------------|
| **package.json** | `preinstall`/`install`/`postinstall`/`prepare`/`prepublish`; `node-gyp` rebuild; `git+` / `github:` deps; `overrides`/`resolutions`; typosquat names |
| **lockfiles** | `package-lock.json` / `yarn.lock` / `pnpm-lock.yaml` — resolved URL vs registry, integrity hashes, git SHAs that can move |
| **binding.gyp / node-gyp** | custom `actions` that download or run shell; unexpected include dirs |
| **CMakeLists / meson / Makefile** | `file(DOWNLOAD`, `FetchContent`, `ExternalProject`, `execute_process` with curl/wget, `add_custom_command` |
| **Native constructors** | `__attribute__((constructor))`, `DllMain`, static initializers that run network/exec before `main` |
| **Network inventory** | `curl`/`libcurl`, `WinHttp`, `socket`/`connect`, `https.request`, `axios`, `fetch`, `WebSocket`, `net.connect` — bind address and whether default-on |
| **N-API / `.node` addons** | committed `.node`/`.so`/`.dll` without matching source; `file` magic vs extension |
| **TypeScript** | `eval`/`Function` in `.ts` that compiles away types; `ts-node`/`tsx` running remote strings; `skipLibCheck` is not a threat by itself |
| **Electron** | `nodeIntegration: true` + `contextIsolation: false` with untrusted content |

For **network connections**, produce an explicit table:

| Component | Language | Direction | When active | Address / endpoint |
|-----------|----------|-----------|-------------|-------------------|
| (fill per finding) | C++ / JS / TS | inbound / outbound / none | default / opt-in / install-time | localhost vs remote |

### 4. Triage every finding

For each scanner hit:

1. Read surrounding code (function + call chain).
2. Check [references/cpp-node-threat-patterns.md](references/cpp-node-threat-patterns.md) for false-positive shapes.
3. Ask: does this match the project's stated purpose?
4. Downgrade or dismiss legitimate hits — but list dismissals in the report.

Escalate when: npm lifecycle fetch-and-run, CMake download-and-execute, constructor/`DllMain` network, credentials read near outbound HTTP, persistence writes, git deps from unknown hosts, or unexplained `.node` blobs.

### 5. Write the report

```markdown
# Threat Audit: <repo name>

**Scope:** <path>, scanners run, deps included Y/N, files scanned>
**Overall risk:** Critical / High / Medium / Low / Clean

## Summary
2-4 sentences: findings, severity, headline recommendation
(e.g. "do not run npm install", "build native code only after reviewing CMake FetchContent").

## Network connections
Table of all inbound/outbound behavior (or "none detected" with evidence).

## Findings

### Critical
**<rule id> — <one-line description>**
`path/to/file.cpp:42`
\`\`\`
<snippet>
\`\`\`
Why this matters here: <triage reasoning>.

(repeat for High / Medium / Low)

## Reviewed and dismissed
Scanner hits concluded benign, one line each with reason.

## Limits of this audit
Heuristic static analysis — not sandboxed runtime, not npm audit / OSV / CVE scanning.
Note if `--include-deps` was skipped. Runtime confirmation needs `strace`/Wireshark if requested.
```

### Severity rubric

- **Critical** — fetch-and-run in npm lifecycle or CMake; decode-drop-execute; constructor/`DllMain` that phones home; credential + network in the same module
- **High** — unexplained outbound HTTP on default startup; `child_process.exec` / `system()` of unsanitized input; committed native binary without source; git deps from unknown hosts
- **Medium** — optional TCP server; documented telemetry; `dlopen` in a stated plugin system
- **Low** — localhost IPC, test-only network, well-known build helpers (`pkg-config`, `node-gyp` with local sources)

Adjust based on context — see [references/cpp-node-threat-patterns.md](references/cpp-node-threat-patterns.md).

## Reference

- C++/Node/TS rule catalog: [references/cpp-node-threat-patterns.md](references/cpp-node-threat-patterns.md)
- General (non-language-specific) rules: `~/.cursor/skills/audit-threat/references/threat-patterns.md`
