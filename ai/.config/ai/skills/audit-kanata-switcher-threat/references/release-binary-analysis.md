# Release Binary Analysis

`scripts/analyze_release_binary.py` inspects the artifact users actually run.
It is an offline ELF reader: it never executes the binary and never contacts the
network. It complements the source scanner and the dependency audit because a
clean tree can still produce a tampered or unexpectedly linked artifact.

## Artifact provenance

Prefer a binary built from a clean `git archive` of the audited commit:

```bash
git -C <repo> archive --format=tar <commit> | tar -x -C /tmp/opencode/ks-src
CARGO_TARGET_DIR=/tmp/opencode/ks-target cargo build --release --locked \
  --manifest-path /tmp/opencode/ks-src/Cargo.toml
```

Record the commit, lockfile SHA-256, cargo/rustc versions, and binary SHA-256.
A supplied `--binary` artifact has unverified provenance; say so in the report.
A release binary is not byte-reproducible across machines, so a different
SHA-256 is not automatically malicious. Compare structural invariants instead.

## Command

```bash
python3 ~/.config/ai/skills/audit-kanata-switcher-threat/scripts/analyze_release_binary.py \
  /tmp/opencode/ks-target/release/kanata-switcher \
  --json /tmp/opencode/ks-binary.json \
  --markdown /tmp/opencode/ks-binary.md \
  --verbose
```

`--fail-on high` is the default. `--verbose` prints every URL, IP, suspicious
string, embedded candidate, and high-entropy section.

## ELF checks

| Check | Why it matters | Default severity |
|-------|----------------|------------------|
| Writable+executable `PT_LOAD` | W^X violation; code can be modified at runtime | high |
| `DT_TEXTREL` | text relocations; unusual for Rust and a hardening red flag | high |
| `RPATH`/`RUNPATH` | library search-path hijack surface | medium |
| Overlay after last segment/section | appended payload, packer stub, or tampered artifact | high if magic/large, medium otherwise |
| Embedded ELF/PE/Mach-O | second executable hidden in the file | high |
| Embedded ZIP/gzip/script magic | packed payload or dropper | low inside a known section, higher outside |
| High-entropy section | packing/encryption; can be legitimate for fonts/compressed data | medium outside known data sections |
| Remote IP literal | non-loopback IPv4 address embedded in strings | high |
| `NEEDED` libraries | unexpected dependency or injected library | medium/high |
| Dangerous imported symbols | `system`, `popen`, `ptrace`, `memfd_create`, `bpf`, module load, etc. | low/medium (baseline allowlist) |
| Build ID / `.comment` | provenance and toolchain evidence | info |

The parser supports ELF32/ELF64, little- and big-endian headers, program
headers, section headers, `.dynamic`, `.dynsym`, and `.symtab`. It does not
trust section names for control flow; malformed files fail closed.

## String checks

The analyzer extracts printable ASCII and UTF-16LE strings and looks for:

- `http://`, `https://`, `ws://`, `wss://`, `ftp://`, `ssh://` URLs;
- IPv4 literals and domain names;
- telemetry/analytics/webhook keywords (`sentry`, `datadog`, `mixpanel`,
  `segment.io`, `posthog`, `discord.com/api/webhooks`, `api.telegram.org`,
  `pastebin`, `ngrok`, `transfer.sh`, `bit.ly`, `t.me/`);
- wallet/key material markers (`mnemonic`, `private_key`, `seed_phrase`,
  `wallet`, `aws_secret`);
- shell/network tool commands.

Rust binaries contain many documentation and crate URLs. The baseline allows
known prefixes (`docs.rs`, `crates.io`, `github.com/rust-lang`,
`github.com/7mind/kanata-switcher`, `w3.org`, `freedesktop.org`). A URL outside
the reviewed prefixes is the finding, not the presence of docs links.

## Baseline invariants

`expected_binary` in `references/network-baseline.json` defines:

- `allowed_needed_prefixes`: reviewed shared libraries. `libc` is required;
  `libdbus-1`/`libwayland-client` are expected when dynamically linked.
- `allowed_url_patterns`: documentation prefixes allowed in strings.
- `allowed_dangerous_symbols`: expected libc networking/process imports.
- `max_size_bytes`: a generous upper bound; a large jump is a review event.
- `overlay_max_bytes`: 0 for a normal ELF.

Build ID, rustc comment, section offsets, and SHA-256 are reported but not
pinned. Do not add a machine-specific hash to the baseline as a trust anchor.

## Expected v1.2.0 shape

- ELF64, little-endian, `ET_DYN` PIE, x86-64 on the reference build.
- Dynamically linked against libc; desktop IPC libraries (`libdbus-1`,
  `libwayland-client`) may appear depending on features/toolchain.
- No writable+executable `PT_LOAD`, no overlay, no embedded ELF/PE.
- Rust `.comment`/build-id present unless stripped.
- Only documentation URLs, no telemetry/webhook/wallet strings.
- The only IP literal expected is `127.0.0.1` (default kanata host); a remote
  IP literal is a finding.

These are expectations, not a byte-for-byte fingerprint. Confirm against the
actual artifact and record differences.

## False positives

- `MZ` bytes inside compressed images/fonts are random. The analyzer only
  reports structural PE headers (`e_lfanew` points to `PE\0\0`).
- High entropy in `.rodata` can come from the embedded bitmap font; it is
  informational unless the section is unexpected or the file is packed.
- `libc` networking symbols (`socket`, `connect`, `bind`) are expected for the
  kanata client and D-Bus. Compare with `allowed_dangerous_symbols`.
- Docs/crates.io/GitHub URLs are compile-time metadata, not runtime fetches.
- A changed build-id or rustc comment after a rebuild is normal.
- `NEEDED` library order and exact versions vary by distro/toolchain.

## Limits

- Static ELF analysis cannot prove the absence of dynamically generated strings,
  encrypted payloads, or behavior in a loaded library.
- It does not execute the binary; pair it with the dynamic harness.
- It does not scan separate `.so` files, the GNOME extension, or the Nix store
  closure. Add those paths explicitly if the deployment uses them.
- It does not perform CVE lookup. Use `cargo audit`/distro tooling separately.
- A supplied artifact may have unverified provenance even if its structure is
  clean.

## Re-baselining

1. Build from the reviewed commit and run the analyzer with `--verbose`.
2. Review every URL, `NEEDED` library, dangerous symbol, overlay, and embedded
   candidate.
3. Update `expected_binary` only with reviewed values; keep the size/overlay
   limits tight enough to catch a payload.
4. Re-run the dynamic harness and `selftest_dynamic.sh`.
5. Record the toolchain and artifact hash in the report, but do not pin the hash
   unless the user explicitly wants reproducibility checking.