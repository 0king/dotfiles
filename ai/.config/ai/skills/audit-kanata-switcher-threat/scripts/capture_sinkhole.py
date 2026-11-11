#!/usr/bin/env python3
"""DNS and TCP sinkholes for the privileged network audit.

The target runs in a network namespace whose only route is a veth pair to a
capture namespace. This process listens on the capture side and makes the
network look usable without ever forwarding a packet to the real network:

* DNS (UDP and TCP port 53) answers every A query with the capture address and
  every other query with NOERROR/NODATA. Every query is logged.
* TCP listeners on common service ports accept connections, read a bounded
  amount of data, log a preview, and close. Every connection and payload is
  logged.

All logs are JSONL so the analyzer can consume them without parsing prose.
"""

from __future__ import annotations

import argparse
import json
import os
import signal
import socket
import socketserver
import struct
import sys
import threading
from pathlib import Path
from typing import Any

LOG_LOCK = threading.Lock()


def log_jsonl(path: Path, record: dict[str, Any]) -> None:
    line = json.dumps(record, sort_keys=True, ensure_ascii=True)
    with LOG_LOCK:
        with path.open("a", encoding="utf-8") as handle:
            handle.write(line + "\n")


def parse_dns_question(data: bytes) -> tuple[str, int, int, bytes] | None:
    if len(data) < 12:
        return None
    qdcount = struct.unpack("!H", data[4:6])[0]
    if qdcount < 1:
        return None
    offset = 12
    labels: list[str] = []
    while offset < len(data):
        length = data[offset]
        offset += 1
        if length == 0:
            break
        if length & 0xC0:
            return None
        if offset + length > len(data):
            return None
        labels.append(data[offset:offset + length].decode("ascii", "replace"))
        offset += length
    if offset + 4 > len(data):
        return None
    qtype, qclass = struct.unpack("!HH", data[offset:offset + 4])
    return ".".join(labels), qtype, qclass, data[12:offset + 4]


def build_dns_response(query: bytes, question: bytes, qtype: int, answer_ip: str) -> bytes:
    txid = query[:2]
    flags = 0x8180  # QR=1, RD=1, RA=1, RCODE=NOERROR
    if qtype == 1:
        answer = b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 60, 4) + socket.inet_aton(answer_ip)
        ancount = 1
    else:
        answer = b""
        ancount = 0
    header = txid + struct.pack("!HHHHH", flags, 1, ancount, 0, 0)
    return header + question + answer


class DnsUdpHandler(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        data, sock = self.request
        parsed = parse_dns_question(data)
        if parsed is None:
            return
        qname, qtype, qclass, question = parsed
        log_jsonl(self.server.log_path, {
            "event": "dns_query", "transport": "udp",
            "client": f"{self.client_address[0]}:{self.client_address[1]}",
            "name": qname, "qtype": qtype, "qclass": qclass,
            "action": "answer" if qtype == 1 else "nodata",
        })
        sock.sendto(build_dns_response(data, question, qtype, self.server.answer_ip), self.client_address)


class DnsTcpHandler(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        self.request.settimeout(2.0)
        try:
            length_bytes = self._read_exact(2)
            if length_bytes is None:
                return
            length = struct.unpack("!H", length_bytes)[0]
            if length < 12 or length > 4096:
                return
            data = self._read_exact(length)
            if data is None:
                return
            parsed = parse_dns_question(data)
            if parsed is None:
                return
            qname, qtype, qclass, question = parsed
            log_jsonl(self.server.log_path, {
                "event": "dns_query", "transport": "tcp",
                "client": f"{self.client_address[0]}:{self.client_address[1]}",
                "name": qname, "qtype": qtype, "qclass": qclass,
                "action": "answer" if qtype == 1 else "nodata",
            })
            response = build_dns_response(data, question, qtype, self.server.answer_ip)
            self.request.sendall(struct.pack("!H", len(response)) + response)
        except (OSError, struct.error):
            return

    def _read_exact(self, count: int) -> bytes | None:
        chunks = bytearray()
        while len(chunks) < count:
            chunk = self.request.recv(count - len(chunks))
            if not chunk:
                return None
            chunks.extend(chunk)
        return bytes(chunks)


class TcpSinkholeHandler(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        peer = f"{self.client_address[0]}:{self.client_address[1]}"
        port = self.server.server_address[1]
        log_jsonl(self.server.log_path, {
            "event": "tcp_connect", "port": port, "peer": peer,
            "family": self.server.address_family.name,
        })
        self.request.settimeout(2.0)
        total = 0
        preview = bytearray()
        try:
            while total < 65536:
                chunk = self.request.recv(4096)
                if not chunk:
                    break
                total += len(chunk)
                if len(preview) < 512:
                    preview.extend(chunk[:512 - len(preview)])
        except (OSError, socket.timeout):
            pass
        if total:
            raw = bytes(preview)
            text = raw.decode("utf-8", "replace")
            log_jsonl(self.server.log_path, {
                "event": "tcp_data", "port": port, "peer": peer,
                "bytes": total, "preview_text": text,
                "preview_hex": raw[:128].hex(),
            })


class ThreadingUdpServer(socketserver.ThreadingMixIn, socketserver.UDPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, address, handler, log_path: Path, answer_ip: str, family: int):
        self.address_family = family
        self.log_path = log_path
        self.answer_ip = answer_ip
        super().__init__(address, handler)


class ThreadingTcpServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, address, handler, log_path: Path, family: int):
        self.address_family = family
        self.log_path = log_path
        super().__init__(address, handler)


def parse_ports(value: str) -> list[int]:
    ports: list[int] = []
    for part in value.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            start, end = part.split("-", 1)
            ports.extend(range(int(start), int(end) + 1))
        else:
            ports.append(int(part))
    return sorted({port for port in ports if 0 < port < 65536})


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--dns-address", default="10.213.0.1")
    parser.add_argument("--dns-address6", default="")
    parser.add_argument("--dns-port", type=int, default=53)
    parser.add_argument("--tcp-address", default="10.213.0.1")
    parser.add_argument("--tcp-address6", default="")
    parser.add_argument("--tcp-ports", default="21,22,25,80,110,143,443,465,587,993,995,1080,3128,5222,5228,8080,8443,8888,9418")
    parser.add_argument("--answer-ip", default="10.213.0.1")
    parser.add_argument("--dns-log", type=Path, required=True)
    parser.add_argument("--tcp-log", type=Path, required=True)
    parser.add_argument("--ready-file", type=Path, required=True)
    args = parser.parse_args(argv)

    args.dns_log.parent.mkdir(parents=True, exist_ok=True)
    args.tcp_log.parent.mkdir(parents=True, exist_ok=True)
    args.dns_log.write_text("", encoding="utf-8")
    args.tcp_log.write_text("", encoding="utf-8")

    servers: list[socketserver.BaseServer] = []
    threads: list[threading.Thread] = []

    def start(server: socketserver.BaseServer, label: str) -> None:
        thread = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.2}, daemon=True, name=label)
        thread.start()
        servers.append(server)
        threads.append(thread)

    try:
        start(ThreadingUdpServer((args.dns_address, args.dns_port), DnsUdpHandler, args.dns_log, args.answer_ip, socket.AF_INET), "dns-udp4")
        start(ThreadingTcpServer((args.dns_address, args.dns_port), DnsTcpHandler, args.dns_log, socket.AF_INET), "dns-tcp4")
        if args.dns_address6:
            start(ThreadingUdpServer((args.dns_address6, args.dns_port), DnsUdpHandler, args.dns_log, args.answer_ip, socket.AF_INET6), "dns-udp6")
            start(ThreadingTcpServer((args.dns_address6, args.dns_port), DnsTcpHandler, args.dns_log, socket.AF_INET6), "dns-tcp6")

        for port in parse_ports(args.tcp_ports):
            for address, family, suffix in (
                (args.tcp_address, socket.AF_INET, "4"),
                (args.tcp_address6, socket.AF_INET6, "6"),
            ):
                if not address:
                    continue
                try:
                    server = ThreadingTcpServer((address, port), TcpSinkholeHandler, args.tcp_log, family)
                except OSError as exc:
                    print(f"warning: cannot bind TCP {address}:{port}: {exc}", file=sys.stderr)
                    continue
                start(server, f"tcp-{port}-{suffix}")
    except OSError as exc:
        print(f"error: sinkhole bind failed: {exc}", file=sys.stderr)
        return 2

    args.ready_file.write_text("ready\n", encoding="utf-8")

    def stop(_signum, _frame):
        for server in servers:
            try:
                server.shutdown()
            except Exception:
                pass
        os._exit(0)

    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    for thread in threads:
        thread.join()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
