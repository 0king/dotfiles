/* =========================================================================
 * SAFE USERSCRIPT STUB & EXTENSION ISOLATION TEMPLATE
 *
 * WARNING: NEVER MONKEYPATCH HOST PAGE OR DOM APIS!
 * -------------------------------------------------------------------------
 * Do NOT override window.fetch, window.XMLHttpRequest, window.WebSocket,
 * window.Worker, document.createElement, or Node.prototype.appendChild.
 *
 * Userscripts share the live DOM and execution context with host websites.
 * Overriding native APIs breaks application networking, chunk loading, and UI rendering.
 *
 * SAFE HARDENING PRINCIPLES:
 * 1. Scope restriction: Use explicit @match target origins, never wildcards.
 * 2. Grant revocation: Remove GM_xmlhttpRequest, @connect *, unsafeWindow, and GM_cookie.
 * 3. Neuter in-body routines: Replace dynamic script loaders (injectScript) with Promise.resolve().
 * 4. Safe extension stubs: Provide harmless fallbacks for extension-only APIs
 *    (GM_xmlhttpRequest) so internal features fail gracefully without ReferenceErrors.
 * 5. Safe parameter bindings: Guard tail arguments with typeof checks.
 * ========================================================================= */

// 1. Safe Non-Invasive Fallback Stub for GM_xmlhttpRequest
// Websites never use GM_xmlhttpRequest. This stub ensures internal userscript
// features (e.g., WebDAV sync, external registry checks) fail gracefully
// with an error callback instead of throwing an unhandled ReferenceError.
if (typeof GM_xmlhttpRequest === "undefined") {
  globalThis.GM_xmlhttpRequest = function(opts) {
    console.warn("[Userscript Hardening] GM_xmlhttpRequest is not granted and disabled.");
    if (typeof opts?.onerror === "function") {
      opts.onerror(new Error("GM_xmlhttpRequest is disabled by security policy."));
    }
    return { abort: function() {} };
  };
}

// 2. Safe Optional Dependency Binding Pattern
// If an optional @require dependency (e.g. a watermark remover or vendor library)
// was removed from the userscript header, guard the IIFE invocation at the bottom
// of the script so it does not throw:
// "Uncaught ReferenceError: <DependencyName> is not defined"
//
// Example pattern:
// })(typeof __OptionalDependency !== "undefined" ? __OptionalDependency : {
//   // Provide no-op stub matching the required interface:
//   noopMethod: () => ({ success: false, reason: "disabled" })
// });
