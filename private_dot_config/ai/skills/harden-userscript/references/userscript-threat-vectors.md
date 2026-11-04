# Userscript Threat Vectors & Attack Surfaces

This reference outlines the major security, privacy, and data exfiltration vectors specific to browser userscripts (Tampermonkey, Violentmonkey, Greasemonkey), along with critical guidance on avoiding host application breakage.

---

> [!WARNING]
> ## CRITICAL ARCHITECTURAL RULE: The Host-Page Sabotage Trap
> **NEVER globally monkey-patch host page or DOM APIs (`window.fetch`, `window.XMLHttpRequest`, `document.createElement`, `Node.prototype.appendChild`, `window.WebSocket`, `window.Worker`).**
>
> ### Why Global Monkey-Patching Breaks Websites
> Userscripts do not run in an isolated operating system container. In modern browsers:
> 1. **Shared DOM:** The userscript and the host web application (e.g. ChatGPT, Claude, Gemini) share the exact same live DOM tree (`document`, `Node.prototype`, `HTMLImageElement`).
> 2. **Shared Prototypes:** Mutating `document.createElement` or `Node.prototype.appendChild` mutates it for the **entire tab**.
> 3. **Shared Window:** Depending on the userscript manager's injection mode (`MAIN_WORLD`, page context, or scripts running with `@run-at document-start`), overriding `window.fetch` can replace the native `fetch` function for the host web app.
>
> ### Real-World Breakage Examples
> - **Blocking `document.createElement('img')`:** When ChatGPT tries to render the user's profile avatar (`<img src="https://cdn.auth0.com/avatars/user.png">`), the monkey-patch throws an unhandled error, crashing React's render tree.
> - **Blocking `window.fetch()`:** ChatGPT's background polling (`https://bzr.openai.com/v1/obi/sync`) and streaming completions (`/backend-api/conversation`) fail with `net::ERR_BLOCKED_BY_CLIENT`, throwing `"chatgpt hit a snag - something went wrong"`.
> - **Blocking `Node.prototype.appendChild(<script>)`:** Next.js and Vite chunk loaders fail to load lazy modules and code blocks, freezing the application.
>
> ### The Correct Mitigation Strategy
> - **Never intercept host APIs.**
> - **Revoke privileged extension grants** (`GM_xmlhttpRequest`, `@connect *`, `unsafeWindow`, `GM_cookie`) so the script cannot bypass CORS/CSP or read session cookies.
> - **Strictly scope `@match`** to specific target origins (e.g. `https://chatgpt.com/*`), preventing execution on banking or email portals.
> - **Audit and neuter in-body dangerous functions directly** (e.g., replace an internal `injectScript()` function with `return Promise.resolve()`).
> - **Provide non-invasive stubs** for extension APIs (`GM_xmlhttpRequest`) so internal userscript routines fail gracefully without ReferenceErrors.

---

## 1. Scope & Execution Context Risks

### `@match *` / `@include *` (Universal Injection)
* **Risk:** The userscript executes inside *every* origin the user visits.
* **Impact:** Active sessions for online banking, email (Gmail, Outlook), password manager web vaults (Bitwarden, 1Password), internal intranets, and cloud consoles (AWS, GCP) are exposed to the script's DOM manipulation and event listening.
* **Hardening:** Replace wildcard `@match *://*/*` with strict, explicit domain origins (e.g. `https://chatgpt.com/*`).

### `@grant unsafeWindow` (Sandbox Escape)
* **Risk:** Userscript managers execute scripts in an isolated extension world by default. `@grant unsafeWindow` pierces this boundary, granting direct access to the page's global JavaScript scope (`window`).
* **Impact:**
  - Can read/modify global JavaScript variables, tokens, and functions.
  - Can monkey-patch page-level prototypes (`EventTarget.prototype.addEventListener`, `Element.prototype.scrollTo`).
  - Exposes the script to attacks from malicious host page scripts.
* **Hardening:** Remove `@grant unsafeWindow`. Scripts will execute in the isolated userscript sandbox with DOM-only access.

---

## 2. Network & Communication Vectors

### Privileged Extension Proxying (`GM_xmlhttpRequest` & `@connect *`)
* **Risk:** Unlike native `fetch()` which is bound by the browser's Same-Origin Policy (SOP) and the host website's Content Security Policy (CSP), `GM_xmlhttpRequest` runs via the extension background process:
  - Bypasses Cross-Origin Resource Sharing (CORS).
  - Bypasses the page's Content Security Policy (`connect-src`).
  - When combined with `@connect *`, can send arbitrary requests to any external server or internal network IP.
* **Hardening:**
  1. Remove `@grant GM_xmlhttpRequest` and `@connect *` from the metadata header.
  2. Provide a non-invasive stub in the userscript scope (`globalThis.GM_xmlhttpRequest`) that invokes `opts?.onerror?.()` to ensure features like WebDAV fail gracefully instead of throwing fatal `ReferenceError` crashes.

### In-Body Network Routines
* **Risk:** A userscript might contain specific functions that call `fetch()`, `XMLHttpRequest`, or `WebSocket` to phone home or sync data to third-party cloud services.
* **Hardening:**
  - Audit the script body for outbound calls.
  - Neuter or remove specific exfiltration routines in the userscript's own code.
  - Do NOT attempt to globally override native browser networking on `window`.

---

## 3. DOM-Based Remote Code Execution & Injection

### Dynamic Script Injection within Userscript Routines
* **Pattern:**
  ```javascript
  injectScript(url) {
    const s = document.createElement("script");
    s.src = url;
    document.head.appendChild(s);
  }
  ```
* **Risk:** Internal routines that dynamically fetch and inject external unvetted scripts (e.g. unpinned Mermaid diagram runners from GitHub).
* **Hardening:** Directly edit the function definition in the script body to a no-op:
  ```javascript
  injectScript(url) {
    return Promise.resolve();
  }
  ```
  *(Do NOT intercept `document.createElement` or `Node.prototype.appendChild` globally, as host applications use them for dynamic chunk loading.)*

---

## 4. Supply Chain & Persistence Vectors

### Mutable Unpinned Branches
* **Directives:** `@require` or `@resource` pointing to GitHub `@main`, `@master`, or un-hashed URLs:
  ```javascript
  // @resource runner https://cdn.jsdelivr.net/gh/user/repo@main/script.js
  ```
* **Risk:** Anyone who pushes to the GitHub repository's `main` branch can modify the code running in the user's browser without warning or review.
* **Hardening:** Pin to an immutable commit hash and require subresource integrity (`#sha256=...`), or vendor the resource locally.

### Missing Dependency Parameter Guards
* **Pattern:**
  ```javascript
  })(DependencyName);
  ```
* **Risk:** If an unneeded `@require` dependency (e.g. watermark remover or math renderer) is removed from the userscript header to reduce bloat, invoking the script with an undeclared identifier throws a fatal `Uncaught ReferenceError: DependencyName is not defined` during script initialization.
* **Hardening:** Guard the parameter evaluation:
  ```javascript
  })(typeof DependencyName !== "undefined" ? DependencyName : {
    // safe fallback stub matching expected interface
  });
  ```

### Auto-Update Overwrites
* **Directives:** `@downloadURL` and `@updateURL` pointing to GreasyFork or GitHub:
  ```javascript
  // @updateURL https://update.greasyfork.org/...
  ```
* **Risk:** When a userscript is hardened locally, the userscript manager will automatically fetch upstream updates on a background schedule and overwrite the hardened script, restoring all dangerous permissions.
* **Hardening:** Remove both `@downloadURL` and `@updateURL` from the metadata header.
