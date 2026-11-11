#!/usr/bin/env python3
"""Minimal mock kanata TCP server for the dynamic audit harness.

kanata-switcher speaks newline-delimited JSON over a plain TCP socket. The mock
implements the subset the daemon needs:

  * send {"LayerChange":{"new":"default"}} on connect;
  * answer RequestLayerNames with a fixed layer list;
  * answer RequestFakeKeyNames with a fixed virtual-key list;
  * log ChangeLayer / ActOnFakeKey commands.

It binds 127.0.0.1 only. The harness runs it inside an isolated network
namespace, so it is unreachable from outside the sandbox.
"""

from __future__ import annotations

import argparse
import json
import signal
import socketserver
import sys
import threading
import time
from pathlib import Path
from typing import Any

DEFAULT_LAYERS = ["default", "browser", "terminal", "vim"]
DEFAULT_KEYS = ["vk_browser", "vk_terminal", "vk_vim"]


class State:
    def __init__(self, log_path: Path) -> None:
        self.log_path = log_path
        self.lock = threading.Lock()
        self.stopping = threading.Event()

    def log(self, event: str, **fields: Any) -> None:
        record = {"ts": time.time(), "event": event, **fields}
        with self.lock:
            self.log_path.parent.mkdir(parents=True, exist_ok=True)
            with self.log_path.open("a", encoding="utf-8") as handle:
                handle.write(json.dumps(record, sort_keys=True) + "\n")


class Handler(socketserver.StreamRequestHandler):
    def handle(self) -> None:
        state: State = self.server.state  # type: ignore[attr-defined]
        peer = f"{self.client_address[0]}:{self.client_address[1]}"
        state.log("connect", peer=peer)
        self.wfile.write(b'{"LayerChange":{"new":"default"}}\n')
        self.wfile.flush()
        while not state.stopping.is_set():
            line = self.rfile.readline()
            if not line:
                break
            text = line.decode("utf-8", errors="replace").strip()
            if not text:
                continue
            try:
                message = json.loads(text)
            except json.JSONDecodeError:
                state.log("invalid_json", peer=peer, text=text[:500])
                continue
            state.log("message", peer=peer, message=message)
            if "RequestLayerNames" in message:
                self.wfile.write(json.dumps({"LayerNames": {"names": DEFAULT_LAYERS}}).encode() + b"\n")
                self.wfile.flush()
            elif "RequestFakeKeyNames" in message:
                if self.server.legacy:  # type: ignore[attr-defined]
                    self.wfile.write(b'{"status":"Error","msg":"unknown variant `RequestFakeKeyNames`"}\n')
                    self.wfile.flush()
                    break
                self.wfile.write(json.dumps({"FakeKeyNames": {"names": DEFAULT_KEYS}}).encode() + b"\n")
                self.wfile.flush()
        state.log("disconnect", peer=peer)


class Server(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=0)
    parser.add_argument("--port-file", type=Path, required=True)
    parser.add_argument("--log", type=Path, required=True)
    parser.add_argument("--legacy", action="store_true", help="simulate kanata without RequestFakeKeyNames")
    parser.add_argument("--duration", type=float, default=0, help="exit after N seconds (0 = run until signalled)")
    args = parser.parse_args(argv)

    state = State(args.log)
    server = Server((args.host, args.port), Handler)
    server.state = state  # type: ignore[attr-defined]
    server.legacy = args.legacy  # type: ignore[attr-defined]
    args.port_file.parent.mkdir(parents=True, exist_ok=True)
    args.port_file.write_text(str(server.server_address[1]), encoding="utf-8")
    state.log("listening", host=args.host, port=server.server_address[1], legacy=args.legacy)

    def stop(_signum: int, _frame: Any) -> None:
        state.stopping.set()
        threading.Thread(target=server.shutdown, daemon=True).start()

    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    if args.duration:
        threading.Timer(args.duration, stop, args=(signal.SIGTERM, None)).start()
    try:
        server.serve_forever(poll_interval=0.1)
    finally:
        state.stopping.set()
        server.server_close()
        state.log("stopped")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
