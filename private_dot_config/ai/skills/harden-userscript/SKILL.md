---
name: harden-userscript
description: >-
  Audit, sandbox, and harden third-party browser userscripts (Tampermonkey, Violentmonkey, Greasemonkey). Use this skill when the user asks to review, audit, restrict permissions, block network access, or safely run an untrusted userscript for a specific purpose (e.g., outline, UI styling, data export) without security or privacy risks.
---

# Harden Userscript

A systematic procedure and automated toolkit to audit, sanitize, and sandbox third-party browser userscripts.

## Workflow

### 1. Audit the Target Userscript
Run the automated vulnerability scanner to identify broad scopes, dangerous grants, unpinned remote resources, and network vectors:

```bash
python3 ~/.config/ai/skills/harden-userscript/scripts/audit_userscript.py <path-to-script.user.js>
```

For JSON output:
```bash
python3 ~/.config/ai/skills/harden-userscript/scripts/audit_userscript.py <path-to-script.user.js> --json
```

Review findings against [userscript-threat-vectors.md](references/userscript-threat-vectors.md):
* **Universal Scope:** `@match http://*/*` or `https://*/*`
* **Privileged Grants:** `unsafeWindow`, `GM_cookie`, `GM_xmlhttpRequest`, `@connect *`
* **Remote Code & Overwrites:** `@updateURL`, `@downloadURL`, unpinned GitHub `@resource`/`@require`
* **DOM Script Injection:** `document.createElement('script')`
* **Multi-Protocol Channels:** `RTCPeerConnection`, `sendBeacon`, `WebSocket`, `EventSource`, `Worker`, DNS prefetching

---

### 2. Scope & Permission Minimization

Edit the metadata block (`// ==UserScript==`):

1. **Tighten Scope:** Replace wildcard `@match` with strictly the target origins required by the user.
2. **Strip Dangerous Grants:** Remove `GM_cookie`, `GM_xmlhttpRequest`, `unsafeWindow`, `window.focus`, `GM_notification`, and `@connect *`.
3. **Prevent Upstream Overwrites:** Remove `@downloadURL` and `@updateURL` so userscript managers do not replace the hardened code with upstream versions.
4. **Remove Unpinned Dependencies:** Remove or vendor any resources pointing to mutable branches (e.g. `@main`) lacking cryptographic hashes (`#sha256=...`).
5. **Retain Local UI Grants Only:** Keep only necessary local state grants (`GM_addStyle`, `GM_getValue`, `GM_setValue`, `GM_deleteValue`, `GM_getResourceText`, `GM_getResourceURL`).

---

### 3. Inject Zero-Trust Multi-Protocol Sandbox

Immediately after `// ==/UserScript==`, insert the production-grade guard from [zero-trust-guard-template.js](references/zero-trust-guard-template.js):

* **HTTP/HTTPS (`fetch`, `XMLHttpRequest`):** Intercepts and blocks all outbound network calls; permits local `blob:` and `data:` URLs so in-browser file exports and downloads function normally.
* **Sockets (`WebSocket`):** Throws immediately on construction.
* **WebRTC (`RTCPeerConnection`, `RTCDataChannel`):** Stubs peer connections to prevent UDP/TCP data channels and IP leakage.
* **Telemetry (`navigator.sendBeacon`):** Overridden to block and return `false`.
* **Streaming & WebTransport (`EventSource`, `WebTransport`):** Throws immediately on construction.
* **Background Threads (`Worker`, `SharedWorker`):** Throws immediately on construction.
* **Dynamic DOM Script & Frame Injection:** Blocks `document.createElement("script"|"iframe"|"embed"|"object")` and hooks `Node.prototype.appendChild` to block mounting `<script>` elements.
* **Side-Channel Prefetching:** Blocks `<link rel="dns-prefetch">`, `preconnect`, and anchor `ping` attributes.
* **Fallback Stub:** Provides a throwing fallback for `GM_xmlhttpRequest`.

---

### 4. Neuter In-Body Dangerous Code

If the userscript has specific in-body routines that dynamically inject scripts or trigger network sync:
1. Search for `injectScript` or `document.createElement("script")` and replace them with safe no-ops (`return Promise.resolve()`).
2. Neuter background sync managers (e.g., WebDAV sync loops, cloud patch registries).

---

### 5. Verification & Testing

#### A. Syntax Validation
Ensure the bundled script has no syntax errors:
```bash
node -c <path-to-script.user.js>
```

#### B. Re-run Audit Scanner
Confirm that all critical and high-severity issues are resolved and the sandbox is active:
```bash
python3 ~/.config/ai/skills/harden-userscript/scripts/audit_userscript.py <path-to-script.user.js>
```

#### C. Run Sandbox Unit Test Suite
Execute the 17-point automated trap verification suite against the hardened file:
```bash
node ~/.config/ai/skills/harden-userscript/scripts/test_userscript_sandbox.js <path-to-script.user.js>
```
All 17 exfiltration and network trap assertions must pass.
