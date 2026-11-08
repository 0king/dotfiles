# Vicinae Security Audit Plan

## Overview
Comprehensive security audit of the Vicinae launcher codebase (C++23, Qt6, TypeScript/Node.js) targeting Ubuntu 26 with GNOME/Wayland. Focus on identifying hidden malware, supply chain attacks, and security vulnerabilities.

## Architecture Summary
- **Core**: C++23 Qt6 application (server, cli, data-control-server)
- **Extensions**: TypeScript/React via Node.js worker threads (extension-manager)
- **IPC**: Local Unix sockets + custom binary protocol (length-prefixed JSON)
- **Data**: SQLCipher-encrypted SQLite, Wayland data-control protocol
- **Network**: HTTP/HTTPS for updates, extension store, telemetry
- **Platform**: Linux (primary), macOS, Windows

---

## Audit Phases

### Phase 1: Supply Chain & Dependency Analysis
**Goal**: Verify all dependencies are legitimate, unmodified, and securely fetched.

#### 1.1 C++ Dependencies (CMake/FetchContent/Vendor)
- [ ] Audit `vendor/` directory for unexpected modifications:
  - `sqlcipher/` - SQLite encryption (verify against upstream)
  - `cmark-gfm/` - Markdown parser (verify against upstream)
  - `pugixml/` - XML parser
  - `zip/` - miniz
  - `fuzzy-trigram/` - FTS5 tokenizer
  - `spellfix/` - SQLite extension
  - `rang/` - Terminal colors
  - `tomlplusplus/` - TOML parser
  - `kirigami-wheelhandler/` - Qt component
- [ ] Verify `FetchContent` usage in CMake for:
  - `glaze` (JSON serialization) - check commit hash pinning
  - `KF6` (KDE syntax highlighting) - if not system
  - `QtKeychain` - if not system
  - `QtLayerShell` - if not system
- [ ] Check `CMakeLists.txt` for hardcoded URLs, unpinned versions
- [ ] Verify SHA256 checksums for all downloaded artifacts (Node.js runtime, etc.)

#### 1.2 Node.js/TypeScript Dependencies
- [ ] Audit `package.json` / `package-lock.json` in:
  - `src/typescript/api/`
  - `src/typescript/extension-manager/`
  - `src/typescript/raycast-api-compat/`
- [ ] Check for:
  - Unpinned versions (`^`, `~`, `latest`)
  - Suspicious packages (obfuscated, low-download, recently published)
  - Git dependencies without commit hashes
  - Post-install scripts that execute code
- [ ] Verify `npm audit` / `pnpm audit` output
- [ ] Check for dependency confusion (scoped packages)

#### 1.3 Build System Integrity
- [ ] Verify `flake.nix` / `flake.lock` for pinned Nixpkgs
- [ ] Check GitHub Actions / CI for:
  - Unpinned actions (`uses: owner/repo@main`)
  - Secrets in logs
  - Unverified artifact uploads

---

### Phase 2: Network Attack Surface
**Goal**: Identify all network connections, validate TLS, certificate pinning, and data exposure.

#### 2.1 Outbound Connections Inventory
| Service | Endpoint | Protocol | Auth | Purpose |
|---------|----------|----------|------|---------|
| Update Service | GitHub Releases API | HTTPS | None | Check for updates |
| Vicinae Store | `Environment::vicinaeApiBaseUrl()` | HTTPS | None | Fetch extensions |
| Raycast Store | Raycast API | HTTPS | None | Fetch Raycast extensions |
| Telemetry | `Environment::vicinaeApiBaseUrl()` | HTTPS | Anonymous UUID | System info |
| Node.js Runtime | `nodejs.org/dist/` | HTTPS | SHA256 verified | Download Node.js |

#### 2.2 Network Security Checks
- [ ] Verify all HTTPS endpoints use certificate validation (no `QSslSocket::IgnoreSslErrors`)
- [ ] Check for HTTP fallback or cleartext communication
- [ ] Validate `Environment::vicinaeApiBaseUrl()` - is it hardcoded or configurable?
- [ ] Verify User-Agent strings don't leak sensitive info
- [ ] Check telemetry payload for PII (userId is UUID, but correlateable)
- [ ] Verify extension download integrity (checksums, signatures)
- [ ] Check for DNS rebinding protection (localhost binding only?)

#### 2.3 Update Service Security
- [ ] `src/server/src/services/update/update-service.cpp`:
  - GitHub Releases API - verify asset name matching prevents substitution
  - No signature verification of downloaded artifacts (only GitHub TLS)
  - `m_installer->install(path, version)` - verify installer validates payload
  - macOS: `MacosUpdateInstaller` - check code signing validation
  - Linux: `NullUpdateInstaller` - updates disabled? Verify.

---

### Phase 3: IPC & Local Attack Surface
**Goal**: Analyze all inter-process communication for privilege escalation, injection, and data leakage.

#### 3.1 IPC Protocol Analysis
- **Main IPC**: `src/server/src/ipc-command-server.cpp` + `src/cli/src/ipc-client.hpp`
  - Unix domain socket at `Omnicast::commandSocketName()`
  - Length-prefixed binary protocol (glaze/beve serialization)
  - Commands: toggle, activate, config, etc.
- **Extension Manager IPC**: `src/server/src/extension/manager/extension-manager.cpp` ↔ `extension-manager.js`
  - Stdout/stdin + length-prefixed JSON
  - RPC via `manager.RpcTransport` / `extension.RpcTransport`
- **Data Control Server**: `src/data-control-server/src/main.cpp`
  - Wayland `ext-data-control-v1` protocol
  - Stdout pipe to main process (clipboard data)

#### 3.2 IPC Security Checks
- [ ] Socket permissions (abstract namespace vs filesystem, `QLocalServer` default)
- [ ] Input validation on all IPC commands (size limits, schema validation)
- [ ] No command injection via arguments (glaze deserialization safety)
- [ ] Extension manager worker isolation (Node.js `worker_threads` with `resourceLimits`)
- [ ] Clipboard data path: Wayland → data-control-server → stdout → main process → encrypted DB
- [ ] Browser native messaging: `vicinae-browser-link` helper - validate manifests

#### 3.3 Extension Sandbox
- [ ] Worker thread isolation: `maxOldGenerationSizeMb: 1000` (DoS limit only)
- [ ] No filesystem sandbox (extensions access `support_path`, `asset_path`, `cwd`)
- [ ] Capability system: `data.capabilities` checked at API boundary (`canAccess`)
- [ ] Raycast compat: `patchRequire` - verify it doesn't expose Node.js builtins
- [ ] Development mode: separate workers, hot reload - verify no prod leakage

---

### Phase 4: Data Handling & Storage
**Goal**: Verify encryption, access controls, and data minimization.

#### 4.1 Encryption
- [ ] SQLCipher usage: `src/server/src/services/clipboard/clipboard-db.cpp`
  - Key derivation: `src/lib/crypto/src/kdf.cpp` (PBKDF2? Argon2?)
  - Per-database keys (`keys.database`, `keys.clipboard`)
  - `config.encryptSensitiveData` toggle - default?
- [ ] Clipboard encryption: `clipboard-encrypter.cpp` - AES-GCM?
- [ ] Key storage: QtKeychain (libsecret on Linux) - verify

#### 4.2 Data Minimization & Retention
- [ ] Clipboard history: retention policy, max entries
- [ ] File indexer: what paths indexed, exclusion patterns
- [ ] Telemetry: opt-in/opt-out, data sent, retention server-side
- [ ] Extension store: what metadata collected
- [ ] Logs: `vicinae::log::installMessageHandler()` - sensitive data filtering?

#### 4.3 File Indexer Security
- [ ] `src/file-indexer/src/` - filesystem walker, scanner
- [ ] Symlink handling (follow/no-follow)
- [ ] Mount point traversal (bind mounts, network shares)
- [ ] Permission checks before indexing
- [ ] Exclusion of sensitive directories (`.ssh`, `.gnupg`, etc.)

---

### Phase 5: Code Execution & Injection Vectors
**Goal**: Identify all paths to arbitrary code execution.

#### 5.1 Script Commands
- [ ] `src/lib/script-command/` - Raycast-compatible script execution
- [ ] Shebang handling, argument parsing, environment isolation
- [ ] Timeout enforcement, resource limits
- [ ] Output capture size limits

#### 5.2 Snippet Expansion
- [ ] `src/server/src/services/snippet/` - text expansion
- [ ] `LinuxSnippetServer` via `LinuxInputServer` (uinput/uinput)
- [ ] Input injection validation (no command sequences)
- [ ] Wayland: virtual keyboard protocol?

#### 5.3 Browser Extension Bridge
- [ ] `src/browser-extension/` - Chrome/Firefox native messaging
- [ ] `vicinae-browser-link` helper binary
- [ ] Message validation, origin checking (`allowed_origins`)
- [ ] Tab data exposure (URLs, titles)

#### 5.4 Calculator Service
- [ ] `src/server/src/services/calculator-service/` - SoulverCore (macOS) / custom
- [ ] Expression evaluation sandbox

#### 5.5 AI Service (if enabled)
- [ ] `src/typescript/api/src/api/ai.ts` - check for prompt injection

---

### Phase 6: Platform-Specific (Ubuntu 26 / Wayland / GNOME)
**Goal**: Verify Linux/Wayland-specific security posture.

#### 6.1 Wayland Integration
- [ ] Layer Shell protocol (`WAYLAND_LAYER_SHELL=ON`) - `src/server/src/ui/` overlay
- [ ] Data Control protocol (`src/data-control-server/`) - clipboard sync
- [ ] Input methods: `LinuxInputServer` - uinput, virtual keyboard
- [ ] Global shortcuts: `GlobalShortcutBackendFactory` - what backend on GNOME?
- [ ] Screencast/screenshot portals (if used)

#### 6.2 System Integration
- [ ] systemd user service: `extra/vicinae.service` - permissions, sandboxing
- [ ] Desktop entry: `extra/vicinae.desktop` - `Exec=`, `TryExec=`
- [ ] Polkit / D-Bus policies (if any)
- [ ] AppArmor / SELinux profile (if shipped)

#### 6.3 Hardware Access
- [ ] Audio: `AudioControlService` - PulseAudio/PipeWire
- [ ] Wallpaper: `WallpaperManager` - GNOME DBus
- [ ] Power: `PowerManager` - UPower/DBus
- [ ] Bluetooth, NFC, etc. (check for unused permissions)

---

### Phase 7: Malware-Specific Heuristics
**Goal**: Detect signs of supply chain compromise, backdoors, or data exfiltration.

#### 7.1 Static Analysis Patterns
- [ ] Obfuscated strings (hex, base64, XOR) in C++ or TypeScript
- [ ] Dynamic code execution: `eval`, `Function` constructor, `dlopen`, `LoadLibrary`
- [ ] Hardcoded IPs, domains, public keys (C2 indicators)
- [ ] Unusual file operations: `/tmp`, `/dev/shm`, hidden directories
- [ ] Process injection: `ptrace`, `process_vm_writev`, `CreateRemoteThread`
- [ ] Persistence mechanisms beyond documented autostart
- [ ] Anti-debug/anti-VM checks
- [ ] Time-based logic bombs

#### 7.2 Binary Analysis (Post-Build)
- [ ] `strings` on all binaries for suspicious artifacts
- [ ] Check for stripped symbols vs debug info
- [ ] Verify RPATH/RUNPATH not pointing to attacker-controlled dirs
- [ ] Check for unexpected DT_NEEDED entries
- [ ] Analyze with `objdump`, `readelf`, `ldd`

#### 7.3 Runtime Behavior (Dynamic Analysis)
- [ ] `strace` / `ltrace` on startup and extension load
- [ ] Network captures (Wireshark) for all outbound connections
- [ ] File system monitoring (opens, writes, executes)
- [ ] IPC message fuzzing
- [ ] Extension worker memory analysis

---

### Phase 8: Configuration & Defaults
**Goal**: Verify secure defaults and configuration validation.

#### 8.1 Configuration Schema
- [ ] `src/server/src/config/config.hpp` - validate all options
- [ ] `encryptSensitiveData` default (should be `true`)
- [ ] `telemetry.systemInfo` default (should be `false` / opt-in)
- [ ] `autoInstallBrowserManifests` - user consent?
- [ ] `autoEnableAutostart` - user consent?
- [ ] Keybind validation (no dangerous defaults)

#### 8.2 Permission Model
- [ ] Extension capabilities: granular, user-approved?
- [ ] File search: directory allowlist/denylist
- [ ] Clipboard: history encryption, sync opt-in
- [ ] Browser tabs: origin restrictions

---

## Tooling & Automation

### Static Analysis
```bash
# C++
clang-tidy (already configured)
cppcheck --enable=all --std=c++23 src/
semgrep --config=auto src/
codeql database create /tmp/vicinae-cpp --language=cpp && codeql database analyze ...

# TypeScript
npm audit / pnpm audit
semgrep --config=auto src/typescript/
biome check (already configured)

# Dependencies
cyclonedx-bom (SBOM generation)
syft packages dir:. -o json
grype dir:. (vulnerability scan)
```

### Dynamic Analysis
```bash
# Build with sanitizers
cmake -DENABLE_SANITIZERS=ON -DCMAKE_BUILD_TYPE=Debug ..
make

# Runtime
strace -f -o trace.log ./bin/vicinae-server
ltrace -f ./bin/vicinae-server
# Network
sudo tcpdump -i any -w capture.pcap host <api-domain>
# Filesystem
fatrace -c vicinae-server
```

### Binary Analysis
```bash
# Check all binaries
for bin in bin/*; do
  strings "$bin" | grep -E "(http|ftp|ssh|key|password|token|secret)" 
  readelf -d "$bin" | grep NEEDED
  objdump -T "$bin" | grep -E "(dlopen|eval|system|exec)"
done
```

---

## Deliverables

1. **Findings Report**: Categorized by severity (Critical/High/Medium/Low/Info)
2. **SBOM**: Software Bill of Materials (CycloneDX JSON)
3. **Vulnerability Scan Results**: Grype/Trivy output
4. **Static Analysis Reports**: Clang-tidy, Semgrep, CodeQL SARIF
5. **Dynamic Analysis Logs**: Strace, network captures (sanitized)
6. **Remediation Plan**: Priority-ordered fixes with code references
7. **Hardening Recommendations**: Config, sandboxing, monitoring

---

## Scope Boundaries (Explicitly Out of Scope)
- Server-side API (`vicinae.com`, Raycast API) - separate audit
- Browser extension code (Chrome/Firefox Web Store review)
- NixOS module / Home Manager module (configuration only)
- Upstream Qt, Node.js, OpenSSL vulnerabilities (track via distro)
- Physical access / evil maid attacks

---

## Open Questions for User

1. **Threat Model**: What adversaries? (Malicious extension author? Compromised build server? Local user? Remote network?)
2. **Compliance**: Any regulatory requirements? (GDPR, SOC2, etc.)
3. **Extension Store**: Is the Vicinae Store self-hosted or third-party? Who reviews extensions?
4. **Telemetry**: Is opt-in implemented in UI? Default state?
5. **Signing**: Are releases signed (cosign, GPG)? Reproducible builds?
6. **Incident Response**: Existing process for security reports?
7. **Timeline**: When is the audit needed? Any blockers (CI access, build env)?