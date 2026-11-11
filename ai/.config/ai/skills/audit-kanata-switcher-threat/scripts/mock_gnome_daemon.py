#!/usr/bin/env python3
"""Mock kanata-switcher daemon for the GNOME extension audit.

Owns `com.github.kanata.Switcher.instances.audit` on the session bus and
implements the same interface as the real daemon. The extension discovers it,
calls `GetStatus`/`GetPaused`, and subscribes to `StatusChanged`/`PausedChanged`.
Every method call and emitted signal is written to a JSONL log so the audit can
prove which extension code paths actually ran.

This is audit scaffolding, not a reimplementation of the daemon.
"""

from __future__ import annotations

import argparse
import json
import os
import signal
import sys
import time
from pathlib import Path
from typing import Any

import dbus
import dbus.mainloop.glib
import dbus.service
from gi.repository import GLib

BUS_NAME = "com.github.kanata.Switcher.instances.audit"
OBJECT_PATH = "/com/github/kanata/Switcher"
INTERFACE = "com.github.kanata.Switcher"


def append_jsonl(path: Path, record: dict[str, Any]) -> None:
    record.setdefault("ts", time.time())
    with path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(record, sort_keys=True, ensure_ascii=True) + "\n")


class MockDaemon(dbus.service.Object):
    def __init__(self, bus: dbus.Bus, log_path: Path, status: tuple[str, list[str], str]) -> None:
        super().__init__(bus, OBJECT_PATH)
        self.log_path = log_path
        self.layer, self.virtual_keys, self.source = status
        self.paused = False
        self.calls = 0

    def _log(self, record: dict[str, Any]) -> None:
        append_jsonl(self.log_path, record)

    @dbus.service.method(INTERFACE, in_signature="", out_signature="(sass)")
    def GetStatus(self) -> dbus.Struct:
        self.calls += 1
        self._log({"event": "method", "name": "GetStatus"})
        return dbus.Struct(
            (
                dbus.String(self.layer),
                dbus.Array(self.virtual_keys, signature="s"),
                dbus.String(self.source),
            ),
            signature="(sass)",
        )

    @dbus.service.method(INTERFACE, in_signature="", out_signature="b")
    def GetPaused(self) -> bool:
        self.calls += 1
        self._log({"event": "method", "name": "GetPaused", "paused": self.paused})
        return dbus.Boolean(self.paused)

    @dbus.service.method(INTERFACE, in_signature="", out_signature="")
    def Restart(self) -> None:
        self.calls += 1
        self._log({"event": "method", "name": "Restart"})

    @dbus.service.method(INTERFACE, in_signature="", out_signature="")
    def Pause(self) -> None:
        self.calls += 1
        self._log({"event": "method", "name": "Pause"})
        self.paused = True
        self.PausedChanged(True)

    @dbus.service.method(INTERFACE, in_signature="", out_signature="")
    def Unpause(self) -> None:
        self.calls += 1
        self._log({"event": "method", "name": "Unpause"})
        self.paused = False
        self.PausedChanged(False)

    @dbus.service.method(INTERFACE, in_signature="ss", out_signature="")
    def WindowFocus(self, window_class: str, window_title: str) -> None:
        self.calls += 1
        self._log({"event": "method", "name": "WindowFocus", "class": str(window_class), "title": str(window_title)})

    @dbus.service.signal(INTERFACE, signature="sass")
    def StatusChanged(self, layer: str, virtual_keys: list[str], source: str) -> None:
        self._log({"event": "signal", "name": "StatusChanged", "layer": str(layer), "virtual_keys": [str(v) for v in virtual_keys], "source": str(source)})

    @dbus.service.signal(INTERFACE, signature="b")
    def PausedChanged(self, paused: bool) -> None:
        self._log({"event": "signal", "name": "PausedChanged", "paused": bool(paused)})

    def emit_status(self) -> bool:
        self.StatusChanged(self.layer, self.virtual_keys, self.source)
        return False

    def emit_paused(self) -> bool:
        self.PausedChanged(self.paused)
        return False


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--log", type=Path, required=True)
    parser.add_argument("--ready-file", type=Path, required=True)
    parser.add_argument("--layer", default="browser")
    parser.add_argument("--virtual-keys", default="")
    parser.add_argument("--source", default="focus")
    parser.add_argument("--emit-delay", type=float, default=2.0)
    parser.add_argument("--exit-after", type=float, default=0.0)
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    args.log.parent.mkdir(parents=True, exist_ok=True)
    args.log.write_text("", encoding="utf-8")
    if args.ready_file.exists():
        args.ready_file.unlink()

    dbus.mainloop.glib.DBusGMainLoop(set_as_default=True)
    bus = dbus.SessionBus()
    status = (args.layer, [v for v in args.virtual_keys.split(",") if v], args.source)
    daemon = MockDaemon(bus, args.log, status)
    name = dbus.service.BusName(BUS_NAME, bus=bus, do_not_queue=True)

    loop = GLib.MainLoop()

    def stop(_signum, _frame):
        loop.quit()

    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)

    def ready() -> bool:
        args.ready_file.write_text("ready\n", encoding="utf-8")
        append_jsonl(args.log, {"event": "ready", "bus_name": BUS_NAME, "pid": os.getpid()})
        return False

    GLib.idle_add(ready)
    GLib.timeout_add(int(args.emit_delay * 1000), daemon.emit_status)
    GLib.timeout_add(int(args.emit_delay * 1000) + 250, daemon.emit_paused)
    if args.exit_after > 0:
        GLib.timeout_add(int(args.exit_after * 1000), lambda: (loop.quit(), False)[1])

    try:
        loop.run()
    finally:
        append_jsonl(args.log, {"event": "exit", "calls": daemon.calls})
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
