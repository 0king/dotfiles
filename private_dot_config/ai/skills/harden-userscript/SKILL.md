---
name: harden-userscript
description: >-
  Audit, sandbox, and harden third-party browser userscripts (Tampermonkey, Violentmonkey, Greasemonkey). Use this skill when the user asks to review, audit, restrict permissions, block network access, or safely run an untrusted userscript for a specific purpose (e.g., outline, UI styling, data export) without security or privacy risks.
---

# Harden Userscript

A systematic procedure and automated toolkit to audit, sanitize, and safely harden third-party browser userscripts without breaking host web applications.

> [!WARNING]
> ### CRITICAL: Never Monkeypatch Native Page or DOM APIs
> **DO NOT globally override `window.fetch`, `window.XMLHttpRequest`, `document.createElement`, `Node.prototype.appendChild`, `window.WebSocket`, or `window.Worker`.**
>
> Userscripts share the live DOM tree (`document`, `Node.prototype`) and window context with host websites (e.g., ChatGPT, Claude, Gemini). Globally intercepting native APIs **destroys the host application itself**:
> - Overriding `window.fetch` breaks host completions, authentication polling, and sync (e.g. `ERR_BLOCKED_BY_CLIENT`, *"chatgpt hit a snag"*).
> - Overriding `document.createElement('img')` breaks user avatars, icons, and diagrams with unhandled exceptions in the host React tree.
> - Overriding `Node.prototype.appendChild` breaks lazy script chunk loading in Next.js and Vite.
>
> **Proper hardening is non-invasive:**
> 1. Restrict `@match` to explicit origins.
> 2. Revoke privileged extension grants (`GM_xmlhttpRequest`, `@connect *`, `unsafeWindow`, `GM_cookie`).
> 3. Neuter specific in-body dangerous functions (e.g. `injectScript() -> Promise.resolve()`).
> 4. Add non-invasive fallback stubs only for ungranted extension APIs (`GM_xmlhttpRequest`).

---

## Workflow

### 1. Audit the Target Userscript
Run the automated vulnerability and host-safety scanner:

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
* **Host API Monkeypatches:** Overriding `window.fetch`, `document.createElement`, `Node.prototype.appendChild`
* **Remote Code & Overwrites:** `@updateURL`, `@downloadURL`, unpinned GitHub `@resource`/`@require`
* **DOM Script Injection:** Dynamic `<script>` loaders

---

### 2. Scope & Permission Minimization

Edit the metadata block (`// ==UserScript==`):

1. **Tighten Scope:** Replace wildcard `@match` with strictly the target origins required by the user (e.g., `https://chatgpt.com/*`).
2. **Strip Dangerous Grants:** Remove `GM_cookie`, `GM_xmlhttpRequest`, `unsafeWindow`, `window.focus`, `GM_notification`, and `@connect *`.
3. **Prevent Upstream Overwrites:** Remove `@downloadURL` and `@updateURL` so userscript managers do not replace the hardened code with upstream versions.
4. **Remove Unpinned Dependencies:** Remove or vendor any resources pointing to mutable branches (e.g. `@main`) lacking cryptographic hashes (`#sha256=...`).
5. **Retain Local UI Grants Only:** Keep only necessary local state grants (`GM_addStyle`, `GM_getValue`, `GM_setValue`, `GM_deleteValue`, `GM_getResourceText`, `GM_getResourceURL`).

---

### 3. Install Non-Invasive Stubs & Dependency Guards

From [zero-trust-guard-template.js](references/zero-trust-guard-template.js):

1. **Stub `GM_xmlhttpRequest` Safely (Extension-Only API):**
   Immediately after `// ==/UserScript==`, insert a safe fallback so internal script features (like WebDAV or external registry checks) cleanly trigger their `onerror` callback instead of throwing unhandled `ReferenceError` crashes:
   ```javascript
   if (typeof GM_xmlhttpRequest === "undefined") {
     globalThis.GM_xmlhttpRequest = function(opts) {
       console.warn("[Userscript Hardening] GM_xmlhttpRequest is disabled.");
       opts?.onerror?.(new Error("GM_xmlhttpRequest is disabled by security policy."));
       return { abort: function() {} };
     };
   }
   ```
   *(Websites never use `GM_xmlhttpRequest`, so this never interferes with host applications.)*

2. **Guard Optional Dependency Invocations:**
   If an optional `@require` dependency was removed from the header, check the tail of the script for direct identifier invocations:
   ```javascript
   // Dangerous: throws ReferenceError if @require was removed
   })(__OptionalDependency);

   // Safe: guarded with typeof check and fallback stub
   })(typeof __OptionalDependency !== "undefined" ? __OptionalDependency : {
     noopMethod: () => ({ success: false, reason: "disabled" })
   });
   ```

---

### 4. Neuter In-Body Dangerous Code

If the userscript has specific in-body routines that dynamically inject scripts or trigger network sync:
1. Search for dynamic script loaders (e.g., `injectScript`) and replace the method body with a safe no-op:
   ```javascript
   injectScript(e, t) {
     return Promise.resolve();
   }
   ```
2. Neuter background sync managers (e.g., WebDAV sync loops, cloud patch registries).

---

### 5. Verification & Testing

#### A. Syntax Validation
Ensure the bundled script has no syntax errors:
```bash
node -c <path-to-script.user.js>
```

#### B. Re-run Audit Scanner
Confirm that all critical and high-severity issues are resolved and no breaking monkeypatches exist:
```bash
python3 ~/.config/ai/skills/harden-userscript/scripts/audit_userscript.py <path-to-script.user.js>
```

#### C. Run Hardening & Safety Unit Test Suite
Execute the automated verification suite against the hardened file:
```bash
node ~/.config/ai/skills/harden-userscript/scripts/test_userscript_sandbox.js <path-to-script.user.js>
```
All assertions (scope restrictions, revoked grants, host API non-interference, and safe dependency bindings) must pass.
