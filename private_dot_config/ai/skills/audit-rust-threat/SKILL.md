---
name: audit-rust-threat
description: Audit Rust repositories and Cargo workspaces for hidden malware, supply-chain risks, and suspicious network behavior. Runs general and Rust-specific pattern scanners, triages build.rs/proc-macro/feature-flag risks, and maps inbound/outbound connections. Use when the user asks to audit, scan, or vet a Rust repo, Cargo crate, or workspace for malware, backdoors, hidden threats, suspicious dependencies, or network activity — including "does this make network connections", "is this crate safe", or "/audit-rust".
---

# Rust Repo Threat Audit

Heuristic triage for malicious or hidden behavior in Rust codebases. Combines the
general [repo-threat-audit](../audit-threat/SKILL.md) pass with Rust-specific
checks. Pattern matching is recall-biased — triage every hit in context before
reporting.

## Workflow

### 1. Confirm the target

Get the repo path on disk (clone first if the user only gave a URL). Ask if unclear.

Note the user's **target OS** and whether they care about **runtime network**
behavior vs static source review.

### 2. Run both scanners

Run from the audit-rust-threat skill directory (adjust paths if the skill lives elsewhere):

```bash
SKILL=~/.cursor/skills/audit-rust-threat
GENERAL=~/.cursor/skills/audit-threat

python3 "$GENERAL/scripts/scan_patterns.py" <repo-path> --json /tmp/rust-general-findings.json
python3 "$SKILL/scripts/scan_rust_patterns.py" <repo-path> --json /tmp/rust-findings.json
```

- Skip `target/` by default (third-party + build artifacts). Pass `--include-deps` only if the user wants vendored/lockfile trees scanned — warn it's slower and noisier.
- Read both JSON outputs; merge and dedupe by file+line when reporting.

### 3. Rust-specific manual pass

While triaging scanner hits, also check:

| Area | What to look for |
|------|------------------|
| **Cargo.toml / Cargo.lock** | `git = "..."` deps, `[patch]` redirects, workspace members, build-dependencies |
| **build.rs** | `Command::new`, downloads, `cargo:rustc-env=`, runs on every build |
| **Network inventory** | Grep `reqwest`, `ureq`, `TcpListener`, `TcpStream::connect`, `UdpSocket` — note bind address and whether enabled by default |
| **Feature flags** | Code behind `#[cfg(feature = "...")]` — especially off-by-default vs default features |
| **Proc macros** | `*-macros` crates, `#[proc_macro_derive]` — skim expansion logic |
| **Binaries** | Committed `.exe`/`.dll`/`.so`/`.wasm` without matching source — run `file` on suspicious blobs |
| **Examples vs main** | Network in `examples/` only is lower risk than in the default binary |

For **network connections**, produce an explicit table:

| Component | Direction | When active | Address / endpoint |
|-----------|-----------|-------------|-------------------|
| (fill per finding) | inbound / outbound / none | default / opt-in flag | localhost vs remote |

Default assumption for many Rust CLI tools: **no network unless `-p`, env var, or feature enables it** — verify in `main.rs` and clap args.

### 4. Triage every finding

For each scanner hit:

1. Read surrounding code (function + call chain).
2. Check [references/rust-threat-patterns.md](references/rust-threat-patterns.md) for false-positive shapes.
3. Ask: does this match the project's stated purpose?
4. Downgrade or dismiss legitimate hits — but list dismissals in the report.

Escalate when: build-time fetch-and-run, credentials read near outbound HTTP,
persistence writes, git deps from unknown hosts, or network on startup with no docs.

### 5. Write the report

```markdown
# Threat Audit: <repo name>

**Scope:** <path>, scanners run, deps included Y/N, files scanned>
**Overall risk:** Critical / High / Medium / Low / Clean

## Summary
2-4 sentences: findings, severity, headline recommendation.

## Network connections
Table of all inbound/outbound behavior (or "none detected" with evidence).

## Findings

### Critical
**<rule id> — <one-line description>**
`path/to/file.rs:42`
\`\`\`
<snippet>
\`\`\`
Why this matters here: <triage reasoning>.

(repeat for High / Medium / Low)

## Reviewed and dismissed
Scanner hits concluded benign, one line each with reason.

## Limits of this audit
Heuristic static analysis — not sandboxed runtime, not `cargo audit`/CVE scanning.
Note if `--include-deps` was skipped. Runtime confirmation needs `strace`/Wireshark if requested.
```

### Severity rubric

- **Critical** — fetch-and-run in build.rs, credential exfil pattern, decode-drop-execute, malicious git dep with network
- **High** — unexplained outbound HTTP on default startup, shell exec from config without opt-in, dynamic dlopen of untrusted paths
- **Medium** — optional TCP server, git deps in trusted forks, telemetry crates
- **Low** — localhost IPC, documented opt-in features, test-only network code

Adjust based on context — see [references/rust-threat-patterns.md](references/rust-threat-patterns.md).

## Reference

- Rust rule catalog: [references/rust-threat-patterns.md](references/rust-threat-patterns.md)
- General (non-Rust) rules: `~/.cursor/skills/audit-threat/references/threat-patterns.md`
