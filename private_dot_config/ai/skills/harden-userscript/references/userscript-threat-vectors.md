# Userscript Threat Vectors & Mitigations

Security risks, exfiltration vectors, and non-breaking mitigations for browser userscripts.

> [!WARNING]
> **Host-Isolation Boundary**
> Userscripts share the live DOM tree (`document`, `Node.prototype`) and global execution context with host web applications.
>
> **Do not globally monkeypatch native APIs (`fetch`, `XMLHttpRequest`, `WebSocket`, `Worker`, `document.createElement`, `Node.prototype.appendChild`).**
> Global interception breaks host application network requests, chunk loading, and UI rendering. Hardening must be applied strictly through metadata restrictions, extension grant revocation, and targeted script-body edits.

---

## Threat Matrix & Mitigations

| Threat Vector | Mechanism / Directive | Risk | Correct Mitigation | Anti-Pattern |
| :--- | :--- | :--- | :--- | :--- |
| **Universal Execution** | `@match *://*/*` | Runs on all visited domains (banking, email, auth portals). Exposes DOM and events. | Restrict `@match` to explicit target domains. | None |
| **Sandbox Escape** | `@grant unsafeWindow` | Pierces userscript isolation; accesses host window context and credentials. | Remove `@grant unsafeWindow`. Run in isolated world. | Intercepting `window` properties |
| **Privileged Proxying** | `@grant GM_xmlhttpRequest`, `@connect *` | Bypasses CORS and host CSP; proxies arbitrary network requests via extension background. | Remove `@grant GM_xmlhttpRequest` and `@connect *`. Provide non-invasive stub. | Overriding `window.fetch` / `XMLHttpRequest` |
| **Cookie Theft** | `@grant GM_cookie` | Reads/writes session cookies across origins. | Remove `@grant GM_cookie`. | None |
| **Dynamic Script Injection** | Internal loader via `createElement("script")` | Loads unpinned, unvetted remote scripts into DOM. | Neuter loader method in script body to return `Promise.resolve()`. | Monkeypatching `document.createElement` |
| **Unpinned Dependencies** | `@require`, `@resource` pointing to mutable branch (e.g. `@main`) | Upstream repository commits execute automatically without review. | Pin to immutable commit hash with subresource integrity (`#sha256=...`), or vendor locally. | None |
| **Auto-Update Overwrites** | `@updateURL`, `@downloadURL` | Userscript manager pulls upstream versions, reverting hardening. | Remove `@updateURL` and `@downloadURL`. | None |
| **Missing Dependency Guard** | Tail invocation: `})(Dependency);` | Removing `@require` causes fatal `ReferenceError` during script initialization. | Guard invocation: `})(typeof Dependency !== "undefined" ? Dependency : stub);` | Global dummy variable pollution |

---

## Safe Non-Invasive Stubs

When extension-only APIs are revoked, internal userscript code may throw unhandled exceptions if called. Stub them strictly within userscript scope:

```javascript
// GM_xmlhttpRequest fallback stub (extension-only API, never called by host page)
if (typeof GM_xmlhttpRequest === "undefined") {
  globalThis.GM_xmlhttpRequest = function(opts) {
    opts?.onerror?.(new Error("GM_xmlhttpRequest disabled by security policy."));
    return { abort() {} };
  };
}
```
