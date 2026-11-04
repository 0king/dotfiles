/* =========================================================================
 * MULTI-PROTOCOL ZERO-TRUST NETWORK GUARD (OUTLINE & EXPORT PRIVACY SANDBOX)
 * Proactively blocks all outbound communication vectors:
 * - HTTP/HTTPS (fetch, XMLHttpRequest, GM_xmlhttpRequest)
 * - WebSockets (WebSocket)
 * - WebRTC (RTCPeerConnection, RTCDataChannel)
 * - Telemetry & Side-Channels (sendBeacon, EventSource, WebTransport)
 * - Background Execution (Worker, SharedWorker)
 * - Dynamic Scripts & DOM Exfiltration (script, iframe, embed, object, img exfil, prefetch)
 * Permits ONLY in-memory local blob: and data: URLs required for file export.
 * ========================================================================= */
(function() {
  const _blocked = (api, target) => {
    console.warn(`[Ophel Security Sandbox] Blocked outbound ${api}${target ? `: ${target}` : ""}`);
    throw new Error(`[Ophel Security Sandbox] Network disabled for ${api}`);
  };

  // 1. Scoped Fetch Guard (Permits blob: and data: for local export file creation)
  const _nativeFetch = window.fetch.bind(window);
  window.fetch = async function(input, init) {
    const url = typeof input === "string" ? input : (input?.url || "");
    if (url.startsWith("blob:") || url.startsWith("data:")) {
      return _nativeFetch(input, init);
    }
    _blocked("fetch", url);
  };

  // 2. Scoped XMLHttpRequest Guard (Permits blob: and data:)
  const _NativeXHR = window.XMLHttpRequest;
  window.XMLHttpRequest = class extends _NativeXHR {
    open(method, url, ...args) {
      const urlStr = String(url);
      if (urlStr.startsWith("blob:") || urlStr.startsWith("data:")) {
        return super.open(method, url, ...args);
      }
      _blocked("XMLHttpRequest", urlStr);
    }
  };

  // 3. Scoped WebSocket Guard
  window.WebSocket = class {
    constructor(url) {
      _blocked("WebSocket", url);
    }
  };

  // 4. WebRTC Guard (Blocks peer connections & STUN/TURN traffic)
  window.RTCPeerConnection = class {
    constructor() { _blocked("RTCPeerConnection"); }
  };
  window.webkitRTCPeerConnection = window.RTCPeerConnection;
  if ("RTCDataChannel" in window) {
    window.RTCDataChannel = class {
      constructor() { _blocked("RTCDataChannel"); }
    };
  }

  // 5. Telemetry & Streaming Guards
  if (navigator.sendBeacon) {
    navigator.sendBeacon = function(url) {
      _blocked("navigator.sendBeacon", url);
      return false;
    };
  }
  if ("EventSource" in window) {
    window.EventSource = class {
      constructor(url) { _blocked("EventSource", url); }
    };
  }
  if ("WebTransport" in window) {
    window.WebTransport = class {
      constructor(url) { _blocked("WebTransport", url); }
    };
  }

  // 6. Background Worker Guard
  window.Worker = class {
    constructor() { _blocked("Worker"); }
  };
  window.SharedWorker = class {
    constructor() { _blocked("SharedWorker"); }
  };

  // 7. Dynamic Script & DOM Exfiltration Guard
  const _origCreateElement = document.createElement.bind(document);
  document.createElement = function(tagName, options) {
    const tag = String(tagName).toLowerCase();

    // HARD BLOCK: Dynamic script creation (prevents remote script loading)
    if (tag === "script") {
      _blocked("document.createElement('script')");
    }

    // HARD BLOCK: Frames and object embeds
    if (tag === "iframe" || tag === "object" || tag === "embed") {
      _blocked(`document.createElement('${tag}')`);
    }

    const el = _origCreateElement(tagName, options);

    // Block image/audio/video phone-home telemetry
    if (tag === "img" || tag === "audio" || tag === "video") {
      const origSetAttr = el.setAttribute.bind(el);
      el.setAttribute = function(name, val) {
        if (name === "src") {
          const str = String(val);
          if (!str.startsWith("blob:") && !str.startsWith("data:") && !str.startsWith("/")) {
            _blocked(`<${tag} src="${str}">`);
          }
        }
        return origSetAttr(name, val);
      };
    }

    // Block link prefetch & external resource requests
    if (tag === "link") {
      const origSetAttr = el.setAttribute.bind(el);
      el.setAttribute = function(name, val) {
        if (name === "rel" && /^(dns-prefetch|preconnect|prefetch|prerender)$/i.test(val)) {
          _blocked("DNS/Resource Prefetch", val);
        }
        return origSetAttr(name, val);
      };
    }

    if (tag === "a") {
      el.removeAttribute("ping");
    }

    return el;
  };

  // 8. Prevent appending any script elements to the DOM
  const _origAppendChild = Node.prototype.appendChild;
  Node.prototype.appendChild = function(child) {
    if (child instanceof HTMLScriptElement) {
      _blocked("Node.appendChild(<script>)");
    }
    return _origAppendChild.call(this, child);
  };

  // 9. Stub GM_xmlhttpRequest
  globalThis.GM_xmlhttpRequest = function(opts) {
    _blocked("GM_xmlhttpRequest", opts?.url || "");
    opts?.onerror?.(new Error("GM_xmlhttpRequest is disabled"));
    return { abort() {} };
  };
})();
