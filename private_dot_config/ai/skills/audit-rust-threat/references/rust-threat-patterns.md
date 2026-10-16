# Rust threat pattern catalog

Reasoning behind `scripts/scan_rust_patterns.py` rules and common false-positive
shapes. Read the section for a rule ID when triaging.

## RS-NET-* — Networking

Rust malware and supply-chain attacks often use `reqwest`/`ureq` for exfil or
C2, or raw `TcpStream` for simpler beacons. Many legitimate Rust apps need
networking — the tell is whether networking matches the project's stated purpose.

**False positives:**
- Optional local TCP control server bound to `127.0.0.1` (automation IPC)
- HTTP in a stated web service, sync client, or updater with documented behavior
- `TcpStream` in tests or examples only
- Comments/doc strings containing crate names

**Escalate when:**
- Network code has no documented purpose
- Listener binds `0.0.0.0` or connects to hardcoded external hosts on startup
- Network + credential reads in the same module

## RS-EXEC-* — Process execution

`std::process::Command` is normal for invoking `git`, `xset`, platform tools, or
opt-in `cmd` features. Shell `-c` invocation is higher risk.

**False positives:** build scripts running `cc`/compiler helpers; invoking
`powershell -c` in documented Windows setup; test fixtures.

**Escalate when:** command args come from config/env without validation; build.rs
downloads and executes; triggered on every keypress without user opt-in.

## RS-BUILD-* — build.rs

`build.rs` runs on every `cargo build` before compilation. Malicious build
scripts can download payloads, exfil env vars, or patch the build environment.

**False positives:** `build.rs` running `pkg-config`, embedding Windows
manifests, codegen from local files.

**Escalate when:** network fetch in build.rs; `cargo:rustc-env` embedding URLs or
secrets; shelling out to curl/wget/bash.

## RS-CARGO-* — Supply chain

- **RS-CARGO-001**: git dependencies — audit the exact commit; branches can move.
- **RS-CARGO-002**: `[patch]` — substitutes upstream crates; common in forks, rare in small libs.
- **RS-CARGO-003**: typosquat names — verify on crates.io; compare downloads and owner.

Also manually review `Cargo.lock` for `source = "git+..."` entries.

## RS-LOAD-001 — Dynamic loading

`libloading`, `dlopen`, `LoadLibraryW` load code at runtime. Legitimate for
plugin systems (e.g. Interception driver). Suspicious in a simple CLI with no
plugin story.

## RS-OBF-* — Embedded payloads

`include_bytes!` is normal for icons and embedded assets. Concerning when followed
by decode + write-to-disk + execute, or XOR loops.

## RS-PROC-001 — Proc macros

Macro crates (`*-macros`, `#[proc_macro_derive]`) expand at compile time and are
harder to review. Skim `macro`/`proc-macro` crate members in the workspace.

## RS-FILE-* — File rules

Combined-pattern rules (credentials + network, build.rs network + Command) are
stronger signals than single-line hits.

## RS-WASM-001 — WASM

Browser fetch from wasm is expected for web demos. The kanata wasm simulator is
local-only if it has no fetch calls.

## Manual checks the scanner misses

1. **Feature-flagged malware** — malicious code behind `#[cfg(feature = "...")]`
   disabled in default builds but enabled in release CI.
2. **Binary blobs** — `.wasm`, `.so`, `.dll`, `.exe` committed without source;
   check `file` magic vs extension.
3. **Proc-macro string obfuscation** — payloads hidden in macro-generated token streams.
4. **Workspace members** — audit every crate in `[workspace].members`, not just the root binary.
5. **Recently touched files** — `git log -1 --format=%ci -- path` on flagged files.
6. **Runtime behavior** — this scan is static; use `strace -e network` / `ss -tp`
   briefly if the user wants runtime confirmation on Linux.

## Severity adjustment

Downgrade RS-NET-* to Low when networking is opt-in, localhost-only, and
documented. Upgrade RS-EXEC-001 to Critical when build.rs fetches and runs remote code.
