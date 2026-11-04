#!/usr/bin/env python3
"""
audit_userscript.py - Audit userscripts for security risks, broad permissions,
unpinned remote code, hidden network vectors, and dangerous host-page monkeypatching.
"""

import sys
import re
import json
import argparse
from pathlib import Path

def parse_userscript(content):
    meta_start = content.find('// ==UserScript==')
    meta_end = content.find('// ==/UserScript==')
    if meta_start == -1 or meta_end == -1 or meta_end <= meta_start:
        return None, content
    
    header = content[meta_start:meta_end + len('// ==/UserScript==')]
    body = content[meta_end + len('// ==/UserScript=='):]
    return header, body

def audit_userscript(file_path):
    path = Path(file_path)
    if not path.is_file():
        raise FileNotFoundError(f"File not found: {file_path}")
    
    content = path.read_text(encoding='utf-8', errors='replace')
    header, body = parse_userscript(content)
    
    findings = []
    
    def add_finding(severity, category, title, description, snippet=None):
        findings.append({
            "severity": severity,
            "category": category,
            "title": title,
            "description": description,
            "snippet": snippet
        })
    
    if not header:
        add_finding("HIGH", "METADATA", "Missing Userscript Metadata Block",
                    "The file does not contain a standard // ==UserScript== header block.")
        header_text = ""
    else:
        header_text = header

    # 1. Scope / Match analysis
    match_directives = re.findall(r'//\s*@match\s+(.+)', header_text)
    include_directives = re.findall(r'//\s*@include\s+(.+)', header_text)
    all_scopes = match_directives + include_directives
    
    wildcard_scopes = [s.strip() for s in all_scopes if re.match(r'^(https?|\*):\/\/\*\/?', s.strip())]
    if wildcard_scopes:
        add_finding("CRITICAL", "SCOPE", "Universal Scope Execution (@match *)",
                    f"Script runs on all websites: {', '.join(wildcard_scopes)}. "
                    "It will execute inside banking, email, password manager vaults, and sensitive portals.",
                    snippet="; ".join(wildcard_scopes))
    elif not all_scopes:
        add_finding("HIGH", "SCOPE", "No Explicit Match Rules",
                    "No @match directives found; userscript managers may run on all pages by default.")

    # 2. Grant analysis
    grants = [g.strip() for g in re.findall(r'//\s*@grant\s+(.+)', header_text)]
    
    if "unsafeWindow" in grants:
        add_finding("CRITICAL", "PERMISSIONS", "@grant unsafeWindow (Sandbox Escape)",
                    "Grants direct access to the host page's JavaScript execution context, "
                    "bypassing userscript isolation and exposing native page variables, functions, and session tokens.")
        
    if "GM_cookie" in grants:
        add_finding("CRITICAL", "PERMISSIONS", "@grant GM_cookie (Cross-Origin Cookie Access)",
                    "Allows reading, querying, and modifying browser cookies across domains.")

    if "GM_xmlhttpRequest" in grants:
        add_finding("HIGH", "PERMISSIONS", "@grant GM_xmlhttpRequest (Background Network Proxy)",
                    "Allows making cross-origin background HTTP/HTTPS requests that bypass browser CORS and CSP.")

    connects = [c.strip() for c in re.findall(r'//\s*@connect\s+(.+)', header_text)]
    if "*" in connects:
        add_finding("CRITICAL", "NETWORK", "@connect * (Wildcard Cross-Origin Destination)",
                    "Grants unrestricted network connections to ANY arbitrary IP address or domain on the internet.")

    # 3. Supply Chain / Auto-Update analysis
    update_urls = re.findall(r'//\s*@(updateURL|downloadURL)\s+(.+)', header_text)
    if update_urls:
        urls_str = ", ".join([f"@{k} {v.strip()}" for k, v in update_urls])
        add_finding("MEDIUM", "SUPPLY_CHAIN", "Auto-Update Directives Present",
                    f"Found auto-update directives: {urls_str}. "
                    "If local security hardening is applied, userscript managers will overwrite local changes with upstream releases.",
                    snippet=urls_str)

    # 4. Dependency pinning (@require / @resource)
    external_refs = re.findall(r'//\s*@(require|resource)\s+([^\s]+)\s+(.+)', header_text)
    for ref_type, name_or_url, maybe_url in external_refs:
        url = maybe_url if ref_type == 'resource' else name_or_url
        url = url.strip()
        
        if re.search(r'@(main|master|latest)\b', url):
            add_finding("HIGH", "SUPPLY_CHAIN", f"Unpinned Mutable Branch in @{ref_type}",
                        f"Resource '{url}' tracks a mutable branch (main/master/latest). Code can change at any time without review.",
                        snippet=url)
        elif not re.search(r'#(sha256|sha384|sha512)=', url) and 'jsdelivr.net/gh/' in url:
            add_finding("MEDIUM", "SUPPLY_CHAIN", f"Missing Cryptographic Hash in @{ref_type}",
                        f"External script '{url}' does not pin a subresource integrity (SRI) hash.",
                        snippet=url)

    # 5. DANGEROUS HOST BREAKAGE: Global monkeypatching of browser APIs
    host_patches = [
        ("window.fetch Override", r'\bwindow\.fetch\s*=',
         "Overriding window.fetch breaks host web applications (e.g. ChatGPT chat completions, session synchronization)."),
        ("document.createElement Override", r'\bdocument\.createElement\s*=',
         "Overriding document.createElement breaks host element creation (e.g. user avatar images, icons, video/audio players)."),
        ("Node.prototype.appendChild Override", r'\bNode\.prototype\.appendChild\s*=',
         "Overriding Node.prototype.appendChild breaks host DOM mounting (e.g. Next.js/Vite script chunk loading)."),
        ("window.XMLHttpRequest Override", r'\bwindow\.XMLHttpRequest\s*=',
         "Overriding window.XMLHttpRequest breaks host XHR communication."),
        ("window.WebSocket Override", r'\bwindow\.WebSocket\s*=',
         "Overriding window.WebSocket breaks host real-time streaming sockets."),
        ("window.Worker Override", r'\bwindow\.(Worker|SharedWorker)\s*=',
         "Overriding window.Worker breaks host background workers (syntax highlighters, tokenizers).")
    ]
    for label, pattern, desc in host_patches:
        if re.search(pattern, body):
            add_finding("CRITICAL", "HOST_BREAKAGE", f"Dangerous Host API Monkeypatch: {label}",
                        f"CRITICAL BREAKAGE RISK: {desc} Userscripts share the DOM and window context. "
                        "Never globally intercept native browser APIs; neuter in-body userscript routines instead.")

    # 6. Body Analysis: Dynamic Script & Frame Injection
    script_creations = list(re.finditer(r'document\.createElement\s*\(\s*["\']script["\']\s*\)', body))
    if script_creations:
        add_finding("HIGH", "CODE_EXECUTION", "Dynamic <script> Injection in Body",
                    f"Found {len(script_creations)} occurrence(s) of document.createElement('script'). "
                    "If unneutered, this allows injecting external scripts into the page context. "
                    "Neuter the specific injection routine (e.g. injectScript() -> Promise.resolve()).",
                    snippet="document.createElement('script')")

    frame_creations = list(re.finditer(r'document\.createElement\s*\(\s*["\'](iframe|object|embed)["\']\s*\)', body))
    if frame_creations:
        add_finding("MEDIUM", "DOM_INJECTION", "Dynamic Frame/Embed Creation in Body",
                    f"Found {len(frame_creations)} occurrence(s) of creating iframe/object/embed elements.",
                    snippet="document.createElement('iframe/object/embed')")

    # 7. Body Analysis: Multi-Protocol Outbound Channels
    body_scans = [
        ("RTCPeerConnection", r'\b(RTCPeerConnection|webkitRTCPeerConnection)\b', "INFO", "WEBRTC",
         "WebRTC PeerConnection referenced in code body."),
        ("sendBeacon", r'\bnavigator\.sendBeacon\b', "INFO", "TELEMETRY",
         "navigator.sendBeacon referenced in code body."),
        ("WebSocket", r'\bnew\s+WebSocket\b', "INFO", "SOCKET",
         "WebSocket connection initiated in code body."),
        ("WebTransport", r'\bnew\s+WebTransport\b', "INFO", "SOCKET",
         "WebTransport connection initiated in code body."),
        ("EventSource", r'\bnew\s+EventSource\b', "INFO", "NETWORK",
         "Server-Sent Events (EventSource) connection initiated in code body."),
        ("Worker", r'\bnew\s+(Worker|SharedWorker)\b', "INFO", "WORKER",
         "Background Web Worker spawned in code body.")
    ]

    for label, pattern, sev, cat, desc in body_scans:
        matches = list(re.finditer(pattern, body))
        if matches:
            add_finding(sev, cat, f"{label} Detected ({len(matches)}x)",
                        desc, snippet=f"{len(matches)} match(es)")

    return {
        "file": str(path.resolve()),
        "header_found": bool(header),
        "total_findings": len(findings),
        "findings": findings
    }

def print_human_report(report):
    print("=" * 70)
    print(f"USERSCRIPT SECURITY AUDIT REPORT: {Path(report['file']).name}")
    print("=" * 70)
    
    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    for f in report["findings"]:
        counts[f["severity"]] = counts.get(f["severity"], 0) + 1
        
    print(f"Status: {len(report['findings'])} total finding(s)")
    print(f"  - CRITICAL: {counts.get('CRITICAL', 0)}")
    print(f"  - HIGH:     {counts.get('HIGH', 0)}")
    print(f"  - MEDIUM:   {counts.get('MEDIUM', 0)}")
    print(f"  - LOW:      {counts.get('LOW', 0)}")
    print(f"  - INFO:     {counts.get('INFO', 0)}")
    print("-" * 70)
    
    actionable = [f for f in report["findings"] if f["severity"] in ["CRITICAL", "HIGH", "MEDIUM"]]
    if not actionable:
        print("✓ CLEAN: No critical security risks or host-breakage monkeypatches detected.")
        return

    sev_order = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
    sorted_findings = sorted(report["findings"], key=lambda x: sev_order.index(x["severity"]) if x["severity"] in sev_order else 99)

    for item in sorted_findings:
        sev = item["severity"]
        cat = item["category"]
        title = item["title"]
        desc = item["description"]
        snippet = item.get("snippet")
        
        prefix = f"[{sev}]"
        print(f"{prefix:<11} [{cat}] {title}")
        print(f"            {desc}")
        if snippet:
            print(f"            Match: {snippet}")
        print()

def main():
    parser = argparse.ArgumentParser(description="Audit browser userscripts for security risks and host breakage.")
    parser.add_argument("script_path", help="Path to the .user.js file")
    parser.add_argument("--json", action="store_true", help="Output findings as JSON")
    args = parser.parse_args()

    try:
        report = audit_userscript(args.script_path)
        if args.json:
            print(json.dumps(report, indent=2))
        else:
            print_human_report(report)
            
        has_critical = any(f["severity"] in ["CRITICAL", "HIGH"] for f in report["findings"])
        sys.exit(1 if has_critical else 0)
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(2)

if __name__ == "__main__":
    main()
