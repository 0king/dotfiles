#!/usr/bin/env node
/**
 * test_userscript_sandbox.js - Test and verify that a hardened userscript's
 * runtime sandbox guard traps all network and DOM exfiltration channels.
 */

const fs = require('fs');
const path = require('path');
const assert = require('assert');

const targetFile = process.argv[2];
if (!targetFile) {
  console.error("Usage: node test_userscript_sandbox.js <path-to-hardened-script.user.js>");
  process.exit(2);
}

const scriptContent = fs.readFileSync(path.resolve(targetFile), 'utf8');

const startMarker = '/* =========================================================================\n * MULTI-PROTOCOL ZERO-TRUST NETWORK GUARD';
const endMarker = '})();';
const startIdx = scriptContent.indexOf(startMarker);
const endIdx = scriptContent.indexOf(endMarker, startIdx) + endMarker.length;

if (startIdx === -1 || endIdx === -1) {
  console.error("FAIL: No Multi-Protocol Zero-Trust Network Guard detected in file!");
  process.exit(1);
}

const sandboxCode = scriptContent.slice(startIdx, endIdx);

// Setup a mock browser environment
const dom = {
  head: {
    appendChild: function(child) {
      return Node.prototype.appendChild.call(this, child);
    }
  },
  body: {
    appendChild: function(child) {
      return Node.prototype.appendChild.call(this, child);
    }
  },
  createElement: function(tag) {
    if (tag === 'a') return { removeAttribute: () => {} };
    if (tag === 'link') return { setAttribute: () => {} };
    if (tag === 'img' || tag === 'audio' || tag === 'video') return { setAttribute: () => {} };
    return {};
  }
};

class Node {
  appendChild(child) {
    return child;
  }
}
class HTMLScriptElement extends Node {}

const windowMock = {
  fetch: async function(url) {
    return { ok: true, url };
  },
  XMLHttpRequest: class {
    open(method, url) {
      this.method = method;
      this.url = url;
    }
  },
  WebSocket: class {},
  RTCPeerConnection: class {},
  EventSource: class {},
  WebTransport: class {},
  Worker: class {},
  SharedWorker: class {},
  document: dom,
  navigator: {
    sendBeacon: function(url) {
      return true;
    }
  }
};

const context = {
  window: windowMock,
  document: dom,
  navigator: windowMock.navigator,
  Node: Node,
  HTMLScriptElement: HTMLScriptElement,
  console: { warn: () => {}, log: () => {}, error: () => {} },
  globalThis: {}
};

// Execute sandbox guard in context
const fn = new Function('window', 'document', 'navigator', 'Node', 'HTMLScriptElement', 'console', 'globalThis', sandboxCode);
fn(context.window, context.document, context.navigator, context.Node, context.HTMLScriptElement, context.console, context.globalThis);

let passed = 0;
let total = 0;

async function runTests() {
  async function test(name, testFn) {
    total++;
    try {
      await testFn();
      console.log(`  ✓ [PASS] ${name}`);
      passed++;
    } catch (err) {
      console.error(`  ✗ [FAIL] ${name}:`, err.message);
    }
  }

  console.log(`Testing sandbox traps in ${path.basename(targetFile)}:`);

  // 1. Fetch
  await test('fetch outbound http blocked', async () => {
    await assert.rejects(async () => {
      await context.window.fetch('https://malicious.com/api');
    }, /Network disabled for fetch/);
  });

  await test('fetch local blob: allowed', async () => {
    const res = await context.window.fetch('blob:http://localhost/abc-123');
    assert(res.ok === true, 'Blob fetch should succeed');
  });

  await test('fetch local data: allowed', async () => {
    const res = await context.window.fetch('data:text/plain;base64,SGVsbG8=');
    assert(res.ok === true, 'Data fetch should succeed');
  });

  // 2. XMLHttpRequest
  await test('XHR outbound http blocked', () => {
    assert.throws(() => {
      const xhr = new context.window.XMLHttpRequest();
      xhr.open('GET', 'https://attacker.com/steal');
    }, /Network disabled for XMLHttpRequest/);
  });

  await test('XHR blob allowed', () => {
    const xhr = new context.window.XMLHttpRequest();
    xhr.open('GET', 'blob:test');
    assert(xhr.url === 'blob:test');
  });

  // 3. WebSocket
  await test('WebSocket blocked', () => {
    assert.throws(() => {
      new context.window.WebSocket('wss://attacker.com/ws');
    }, /Network disabled for WebSocket/);
  });

  // 4. WebRTC
  await test('RTCPeerConnection blocked', () => {
    assert.throws(() => {
      new context.window.RTCPeerConnection();
    }, /Network disabled for RTCPeerConnection/);
  });

  // 5. sendBeacon
  await test('navigator.sendBeacon blocked', () => {
    assert.throws(() => {
      context.navigator.sendBeacon('https://tracker.com/beacon');
    }, /Network disabled for navigator.sendBeacon/);
  });

  // 6. EventSource & WebTransport
  await test('EventSource blocked', () => {
    assert.throws(() => {
      new context.window.EventSource('https://stream.com/sse');
    }, /Network disabled for EventSource/);
  });

  await test('WebTransport blocked', () => {
    assert.throws(() => {
      new context.window.WebTransport('https://quic.com:443');
    }, /Network disabled for WebTransport/);
  });

  // 7. Workers
  await test('Worker blocked', () => {
    assert.throws(() => {
      new context.window.Worker('worker.js');
    }, /Network disabled for Worker/);
  });

  await test('SharedWorker blocked', () => {
    assert.throws(() => {
      new context.window.SharedWorker('shared.js');
    }, /Network disabled for SharedWorker/);
  });

  // 8. Dynamic script creation
  await test('document.createElement("script") blocked', () => {
    assert.throws(() => {
      context.document.createElement('script');
    }, /document.createElement\('script'\)/);
  });

  // 9. Dynamic iframe creation
  await test('document.createElement("iframe") blocked', () => {
    assert.throws(() => {
      context.document.createElement('iframe');
    }, /document.createElement\('iframe'\)/);
  });

  // 10. Node.prototype.appendChild for script element
  await test('Node.appendChild(<script>) blocked', () => {
    assert.throws(() => {
      const s = new HTMLScriptElement();
      context.document.head.appendChild(s);
    }, /Node.appendChild\(<script>\)/);
  });

  // 11. DNS Prefetch link
  await test('<link rel="dns-prefetch"> blocked', () => {
    assert.throws(() => {
      const link = context.document.createElement('link');
      link.setAttribute('rel', 'dns-prefetch');
    }, /DNS\/Resource Prefetch/);
  });

  // 12. GM_xmlhttpRequest stub
  await test('GM_xmlhttpRequest blocked', () => {
    assert.throws(() => {
      context.globalThis.GM_xmlhttpRequest({ url: 'https://evil.com' });
    }, /Network disabled for GM_xmlhttpRequest/);
  });

  console.log(`\nResult: ${passed}/${total} sandbox assertions passed.`);
  if (passed === total) {
    console.log('✓ All sandbox exfiltration traps verified successfully.');
    process.exit(0);
  } else {
    process.exit(1);
  }
}

runTests();
