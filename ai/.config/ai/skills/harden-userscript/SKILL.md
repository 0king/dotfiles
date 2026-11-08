---
name: harden-userscript
description: >-
  Audit, sandbox, and harden third-party browser userscripts (Tampermonkey, Violentmonkey, Greasemonkey). Use this skill when the user asks to review, audit, restrict permissions, block network access, or safely run an untrusted userscript for a specific purpose (e.g., outline, UI styling, data export) without security or privacy risks.
---

# Harden Userscript

Audit, sanitize, and harden third-party browser userscripts without breaking host web applications.

> [!WARNING]
> **Never Monkeypatch Host Page or DOM APIs**
> Do not override `window.fetch`, `XMLHttpRequest`, `WebSocket`, `Worker`, `document.createElement`, or `Node.prototype.appendChild`.
> Userscripts share the live DOM and global scope with the host application. Intercepting host APIs breaks application networking, dynamic imports, and component rendering.
>
> **Safe hardening boundary:**
> 1. Restrict `@match` to explicit target domains.
> 2. Revoke privileged extension grants (`GM_xmlhttpRequest`, `@connect *`, `unsafeWindow`, `GM_cookie`).
> 3. Neuter dangerous in-body functions directly.
> 4. Add non-invasive fallback stubs for ungranted extension APIs (`GM_xmlhttpRequest`).

---

## Workflow

### 1. Audit Script
Scan for vulnerabilities and breaking monkeypatches:
```bash
python3 ~/.config/ai/skills/harden-userscript/scripts/audit_userscript.py <path-to-script.user.js>
```
Flags to inspect:
- Universal `@match` (`*://*/*`)
- Privileged grants (`unsafeWindow`, `GM_cookie`, `GM_xmlhttpRequest`, `@connect *`)
- Native API overrides (`fetch`, `createElement`, `appendChild`)
- Unpinned dependencies (`@require`, `@resource` pointing to mutable branches)
- Dynamic code execution / DOM injection (`injectScript`)

### 2. Scope & Grant Minimization
In the `// ==UserScript==` metadata header:
1. **Scope:** Replace wildcard `@match` with explicit target origins.
2. **Revoke Grants:** Remove `GM_cookie`, `GM_xmlhttpRequest`, `unsafeWindow`, `window.focus`, `GM_notification`, `@connect *`.
3. **Disable Auto-Updates:** Remove `@downloadURL` and `@updateURL` to prevent upstream rewrites.
4. **Pin Dependencies:** Remove unneeded `@require` / `@resource` or pin to immutable commit hashes (`#sha256=...`).
5. **Retain UI Grants:** Keep local UI storage APIs (`GM_addStyle`, `GM_getValue`, `GM_setValue`, `GM_deleteValue`, `GM_getResourceText`, `GM_getResourceURL`).

### 3. Non-Invasive Stubs & Guards
1. **Stub `GM_xmlhttpRequest`:**
   Insert fallback immediately after `// ==/UserScript==` so internal userscript routines fail gracefully via callback instead of throwing unhandled `ReferenceError` crashes:
   ```javascript
   if (typeof GM_xmlhttpRequest === "undefined") {
     globalThis.GM_xmlhttpRequest = function(opts) {
       opts?.onerror?.(new Error("GM_xmlhttpRequest disabled by security policy."));
       return { abort: function() {} };
     };
   }
   ```
2. **Guard Tail Dependencies:**
   If an optional `@require` dependency was removed, guard the tail IIFE call against `ReferenceError`:
   ```javascript
   })(typeof __Dependency !== "undefined" ? __Dependency : {
     noop: () => ({ success: false, reason: "disabled" })
   });
   ```

### 4. Neuter In-Body Routines
Replace internal script injection and telemetry routines with safe no-ops:
```javascript
injectScript(e, t) {
  return Promise.resolve();
}
```
*Never intercept host DOM or network calls globally.*

### 5. Verification
```bash
# 1. Syntax check
node -c <path-to-script.user.js>

# 2. Automated audit scan
python3 ~/.config/ai/skills/harden-userscript/scripts/audit_userscript.py <path-to-script.user.js>

# 3. Unit test assertions (grants, host safety, stubs)
node ~/.config/ai/skills/harden-userscript/scripts/test_userscript_sandbox.js <path-to-script.user.js>
```
