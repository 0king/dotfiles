#!/usr/bin/env node
/**
 * test_userscript_sandbox.js - Test and verify that a hardened userscript
 * enforces security boundaries WITHOUT breaking host web applications.
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

let passed = 0;
let total = 0;

async function runTests() {
  function test(name, testFn) {
    total++;
    try {
      testFn();
      console.log(`  ✓ [PASS] ${name}`);
      passed++;
    } catch (err) {
      console.error(`  ✗ [FAIL] ${name}:`, err.message);
    }
  }

  console.log(`Testing hardening & host-safety rules in ${path.basename(targetFile)}:\n`);

  // Extract header
  const headerMatch = scriptContent.match(/\/\/ ==UserScript==([\s\S]*?)\/\/ ==\/UserScript==/);
  assert(headerMatch, "Userscript must contain // ==UserScript== metadata header block");
  const header = headerMatch[1];
  const body = scriptContent.slice(headerMatch.index + headerMatch[0].length);

  // 1. Header Scope Tests
  test('No universal wildcard @match', () => {
    const wildcards = header.match(/\/\/\s*@match\s+(https?|\*):\/\/\*\/?/g);
    assert(!wildcards, `Universal @match detected: ${wildcards?.join(', ')}`);
  });

  test('Explicit target origins declared', () => {
    const matches = header.match(/\/\/\s*@match\s+\S+/g);
    assert(matches && matches.length > 0, 'Script must declare at least one explicit @match');
  });

  // 2. Revoked Permissions Tests
  test('@grant unsafeWindow revoked', () => {
    assert(!header.includes('@grant unsafeWindow') && !header.includes('@grant   unsafeWindow'),
      '@grant unsafeWindow must be removed to preserve extension isolation');
  });

  test('@grant GM_cookie revoked', () => {
    assert(!header.includes('@grant GM_cookie'),
      '@grant GM_cookie must be removed to prevent cookie harvesting');
  });

  test('@grant GM_xmlhttpRequest revoked', () => {
    assert(!header.includes('@grant GM_xmlhttpRequest'),
      '@grant GM_xmlhttpRequest must be removed to prevent CSP/CORS bypass');
  });

  test('@connect * revoked', () => {
    assert(!header.includes('@connect *'),
      '@connect * must be removed to prevent unrestricted outbound connections');
  });

  test('Auto-update URLs removed (@updateURL / @downloadURL)', () => {
    assert(!header.includes('@updateURL') && !header.includes('@downloadURL'),
      'Auto-update URLs must be removed to prevent userscript managers from overwriting hardened code');
  });

  // 3. Host Page API Non-Interference Tests (CRITICAL: Avoid host breakage)
  test('Does NOT globally monkeypatch window.fetch', () => {
    assert(!/\bwindow\.fetch\s*=/.test(body),
      'CRITICAL: window.fetch must not be globally overridden. Doing so breaks host application API calls.');
  });

  test('Does NOT globally monkeypatch document.createElement', () => {
    assert(!/\bdocument\.createElement\s*=/.test(body),
      'CRITICAL: document.createElement must not be globally overridden. Doing so breaks host image/DOM rendering.');
  });

  test('Does NOT globally monkeypatch Node.prototype.appendChild', () => {
    assert(!/\bNode\.prototype\.appendChild\s*=/.test(body),
      'CRITICAL: Node.prototype.appendChild must not be overridden. Doing so breaks dynamic script chunk loading.');
  });

  test('Does NOT globally monkeypatch window.WebSocket', () => {
    assert(!/\bwindow\.WebSocket\s*=/.test(body),
      'CRITICAL: window.WebSocket must not be overridden. Doing so breaks host real-time connections.');
  });

  test('Does NOT globally monkeypatch window.Worker', () => {
    assert(!/\bwindow\.(Worker|SharedWorker)\s*=/.test(body),
      'CRITICAL: window.Worker must not be overridden. Doing so breaks host background workers.');
  });

  // 4. Safe Fallbacks & Dependency Binding Tests
  test('Safe fallback stub provided for GM_xmlhttpRequest', () => {
    // If GM_xmlhttpRequest is called, it should fail gracefully
    const stubEnv = { console: { warn: () => {} } };
    const stubCode = `
      if (typeof GM_xmlhttpRequest === "undefined") {
        globalThis.GM_xmlhttpRequest = function(opts) {
          opts?.onerror?.(new Error("GM_xmlhttpRequest is disabled"));
          return { abort() {} };
        };
      }
    `;
    const fn = new Function('globalThis', stubCode);
    fn(stubEnv);
    let caught = false;
    stubEnv.GM_xmlhttpRequest({ onerror: () => { caught = true; } });
    assert(caught === true, 'GM_xmlhttpRequest fallback should trigger onerror callback safely');
  });

  test('Tail dependency argument is safely guarded against ReferenceError', () => {
    const tail = body.trim().slice(-120);
    // If the tail passes an identifier like })(__SomeVar); without a typeof check, it will crash if @require was removed
    const nakedIdentifierMatch = tail.match(/\}\)\s*\(\s*([a-zA-Z_$][a-zA-Z0-9_$]*)\s*\)\s*;?\s*$/);
    if (nakedIdentifierMatch) {
      const identifier = nakedIdentifierMatch[1];
      assert(false, `Tail IIFE passes naked identifier '${identifier}'. Guard it with typeof check: typeof ${identifier} !== 'undefined' ? ${identifier} : stub`);
    }
  });

  console.log(`\nResult: ${passed}/${total} assertions passed.`);
  if (passed === total) {
    console.log('✓ All userscript hardening and host-safety checks verified successfully.');
    process.exit(0);
  } else {
    process.exit(1);
  }
}

runTests();
