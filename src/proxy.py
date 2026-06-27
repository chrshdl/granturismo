#!/usr/bin/env python3
"""Gran Turismo 7 telemetry -> NDJSON proxy.

Reads the encrypted UDP telemetry stream from a PlayStation via
:class:`granturismo.Feed`, decodes each packet, and re-emits it as one JSON
object per line ("NDJSON") to a UDP target.  Intended to run under systemd on
the instrument-cluster appliance.

Configuration comes from CLI flags or the matching environment variables:
    --ps-ip / GT_PS_IP                IP of the PlayStation (required)
    --jsonl-output / GT_JSONL_OUTPUT  udp://HOST:PORT sink (default localhost)
"""

from __future__ import annotations

import argparse
import dataclasses
import json
import os
import signal
import socket
import sys
import threading
import time
from typing import Any
from urllib.parse import urlparse

from granturismo import Feed

_DEFAULT_OUTPUT = "udp://127.0.0.1:5600"


def parse_udp_url(url: str) -> tuple[str, int]:
    """Parse ``udp://HOST:PORT`` (the ``udp://`` scheme is optional)."""
    if "://" not in url:
        url = "udp://" + url
    parsed = urlparse(url)
    if parsed.scheme.lower() != "udp" or not parsed.hostname or not parsed.port:
        raise ValueError(f"invalid UDP URL {url!r}; expected udp://HOST:PORT")
    return parsed.hostname, int(parsed.port)


def to_jsonable(obj: Any) -> Any:
    """Recursively convert a packet (nested dataclasses) to JSON-safe data."""
    if dataclasses.is_dataclass(obj) and not isinstance(obj, type):
        return {k: to_jsonable(v) for k, v in dataclasses.asdict(obj).items()}
    if isinstance(obj, (list, tuple)):
        return [to_jsonable(v) for v in obj]
    if isinstance(obj, dict):
        return {str(k): to_jsonable(v) for k, v in obj.items()}
    return obj


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="GT7 UDP -> NDJSON proxy")
    parser.add_argument("--ps-ip", default=os.environ.get("GT_PS_IP"),
                        help="PlayStation IP address (or GT_PS_IP)")
    parser.add_argument("--jsonl-output",
                        default=os.environ.get("GT_JSONL_OUTPUT", _DEFAULT_OUTPUT),
                        help="udp://HOST:PORT sink (or GT_JSONL_OUTPUT)")
    parser.add_argument("--get-latest-timeout", type=float, default=0.05,
                        help="seconds to wait for a fresh packet each loop")
    parser.add_argument("--include-paused", action="store_true",
                        help="forward packets even while the game is paused")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    if not args.ps_ip:
        sys.stderr.write("--ps-ip (or GT_PS_IP) is required\n")
        return 2

    host, port = parse_udp_url(args.jsonl_output)
    print(f"[proxy] {args.ps_ip} -> udp://{host}:{port}", flush=True)

    stop = threading.Event()
    signal.signal(signal.SIGINT, lambda *_: stop.set())
    signal.signal(signal.SIGTERM, lambda *_: stop.set())

    sink = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sent = 0
    with Feed(args.ps_ip) as feed:
        while not stop.is_set():
            packet = feed.get_latest(timeout=args.get_latest_timeout)
            if packet is None:
                continue
            if packet.flags.paused and not args.include_paused:
                continue

            payload = to_jsonable(packet)
            payload.setdefault("received_time", time.time())
            line = (json.dumps(payload, ensure_ascii=False) + "\n").encode("utf-8")
            sink.sendto(line, (host, port))

            sent += 1
            if sent == 1 or sent % 1000 == 0:
                print(f"[proxy] forwarded {sent} packets", flush=True)

    sink.close()
    print(f"[proxy] stopped after {sent} packets", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
