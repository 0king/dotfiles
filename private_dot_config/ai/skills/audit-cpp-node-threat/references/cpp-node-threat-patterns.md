# C++ / Node / TypeScript threat pattern catalog

Reasoning behind `scripts/scan_cpp_node_patterns.py` rules and common false-positive
shapes. Read the section for a rule ID when triaging.

## CPP-NET-* — Native networking

C++ malware often uses `libcurl`, WinHTTP, or raw `socket`/`connect` for C2 or
exfil. Many legitimate apps need networking — the tell is whether it matches the
stated purpose and whether it runs from constructors / install scripts.

**False positives:** documented HTTP clients; localhost IPC; test fixtures;
comments containing API names.

**Escalate when:** hardcoded external hosts on startup; constructor/`DllMain`
network; credentials read in the same translation unit.

## CPP-EXEC-* — Process execution

`system()`, `popen()`, `execve`, `CreateProcess`, `WinExec` spawn other programs.
Normal for build tools and documented CLI wrappers. Shelling out with concatenated
user/config input is higher risk.

**Escalate when:** command string is decoded or fetched; runs from a static
initializer; writes a dropped binary then executes it.

## CPP-LOAD-* — Dynamic loading

`dlopen`, `LoadLibrary`, `GetProcAddress` load code at runtime. Legitimate for
plugin systems. Suspicious in a simple CLI with no plugin story, or when the path
comes from the network / env without validation.

## CPP-CTOR-* — Hidden entry points

`__attribute__((constructor))`, `DllMain`, GCC `.init_array` — runs before or
instead of obvious `main()`. Malware uses these so a casual read of `main` looks
clean.

**False positives:** logging/crash-handler libraries; OpenSSL init.

**Escalate when:** constructor does network, `system()`, or writes to
`~/.config` / cron / autostart.

## CPP-BUILD-* — CMake / Meson / Make

`file(DOWNLOAD`, `FetchContent`, `ExternalProject_Add`, `execute_process` with
curl/wget run at *configure/build* time — equivalent to a malicious `build.rs`.

**False positives:** fetching well-known pinned tarball checksums (Boost, etc.).

**Escalate when:** URL is unpinned / attacker-controlled; downloaded file is
chmod + executed; no integrity hash.

## CPP-OBF-* — Payloads in native code

Large hex/base64 blobs, XOR loops over byte arrays, `VirtualAlloc` + `memcpy` +
function-pointer cast. Legitimate for shaders/fonts; concerning when followed by
execute or `WriteProcessMemory`.

## CPP-PERSIST-* / CPP-ROOT-*

Writes to cron, shell rc, autostart, systemd user units, `LD_PRELOAD`,
`/etc/ld.so.preload`, `ptrace`, `/proc/self/mem`. Almost never OK in a library.

## JS-EXEC-* — Dynamic JS/TS execution

`eval`, `new Function`, `vm.runInContext`, `child_process.exec`/`execSync` with
`shell: true`. Types in `.ts` do not prevent this — it still runs after compile.

**False positives:** template engines, documented CLIs wrapping `git`/`ffmpeg`
with fixed args.

**Escalate when:** argument is `atob`/Buffer-decoded or a `fetch` body.

## JS-NET-* — Node / browser network

`https.request`, `axios`, `fetch`, `net.connect`, `WebSocket`, `dgram`. Inventory
whether default-on vs flag, and localhost vs remote.

## JS-SUPPLY-* — npm / yarn / pnpm lifecycle

`preinstall` / `install` / `postinstall` / `prepare` run on `npm install` with no
prompt. Combined with `curl | sh`, `node -e`, or compiling a remote `.node`
binary, this is the dominant npm malware pattern.

Also check: `git+https://` deps (branch can move), `overrides`/`resolutions`
silently swapping packages, typosquat names (`lodahs`, `colour` vs `colors`).

## JS-NATIVE-* — Native addons

`bindings`, `node-addon-api`, `napi`, committed `.node`/`.so`/`.dll` without
source. A `.node` file is a shared library — treat like an unaudited binary.

**Escalate when:** addon is downloaded at install time rather than built from
in-tree C++; `file` says the blob is not what the extension claims.

## JS-ELECTRON-* — Electron

`nodeIntegration: true` with `contextIsolation: false` lets untrusted pages run
Node. Combined with `openExternal` of attacker URLs, that's RCE.

## JS-OBF-* — JS obfuscation

`Buffer.from(..., 'base64')` then `eval`; `String.fromCharCode` chains; unicode
RTLO. Legitimate for WASM/assets; not for executing the result.

## FILE-* combined rules

Credentials + network, decode + exec, CMake download + execute, constructor +
network are stronger than single-line hits.

## Manual checks the scanner misses

1. **Lockfile-only malware** — a clean `package.json` with a poisoned resolved
   URL in the lockfile.
2. **Workspace packages** — audit every `workspaces` member, not just the root.
3. **Binary blobs** — `.wasm`, `.so`, `.dll`, `.exe`, `.node`; run `file`.
4. **Recently touched files** — `git log -1 --format=%ci -- path`.
5. **Feature-flagged / `#ifdef DEBUG` inverted** — malicious code in the
   *release* `#else` branch.
6. **Runtime confirmation** — `strace -e network,execve` / `ss -tp` if requested.

## Severity adjustment

Downgrade JS-NET-* / CPP-NET-* to Low when networking is opt-in, localhost-only,
and documented. Upgrade JS-SUPPLY-* to Critical when lifecycle scripts fetch and
run remote code.
