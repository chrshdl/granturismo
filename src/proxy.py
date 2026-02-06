#!/usr/bin/env python3
from __future__ import annotations

import argparse
import dataclasses
import json
import os
import socket
import sys
import time
from typing import Any, Mapping, Sequence
from urllib.parse import urlparse

from granturismo import Feed


def parse_udp_url(url: str) -> tuple[str, int]:
    if "://" not in url:
        url = "udp://" + url
    u = urlparse(url)
    if u.scheme.lower() != "udp" or not u.hostname or not u.port:
        raise ValueError(f"Invalid UDP URL: {url!r}. Expected udp://HOST:PORT")
    return u.hostname, int(u.port)


def to_jsonable(obj: Any) -> Any:
    if dataclasses.is_dataclass(obj):
        return {k: to_jsonable(v) for k, v in dataclasses.asdict(obj).items()}
    if isinstance(obj, (str, int, float, bool)) or obj is None:
        return obj
    if isinstance(obj, Mapping):
        return {str(k): to_jsonable(v) for k, v in obj.items()}
    if isinstance(obj, Sequence) and not isinstance(obj, (str, bytes, bytearray)):
        return [to_jsonable(v) for v in obj]
    if hasattr(obj, "__dict__"):
        return {
            k: to_jsonable(v) for k, v in vars(obj).items() if not k.startswith("_")
        }
    return str(obj)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="GT7 UDP -> JSONL proxy")
    ap.add_argument("--ps-ip", default=os.environ.get("GT_PS_IP"))
    ap.add_argument(
        "--jsonl-output",
        default=os.environ.get("GT_JSONL_OUTPUT", "udp://127.0.0.1:5600"),
    )
    ap.add_argument("--get-latest-timeout", type=float, default=0.02)
    ap.add_argument("--include-paused", action="store_true")
    args = ap.parse_args(argv)

    if not args.ps_ip:
        sys.stderr.write("--ps-ip (or GT_PS_IP) is required.\n")
        return 2

    host, port = parse_udp_url(args.jsonl_output)
    print(f"[Proxy] Starting, will send to {host}:{port}", flush=True)

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    feed = Feed(args.ps_ip)
    feed.start()
    send_count = 0
    try:
        while True:
            pkt = feed.get_latest(timeout=0.02)

            if pkt is None:
                continue

            payload = to_jsonable(pkt)
            if isinstance(payload, dict) and "received_time" not in payload:
                payload["received_time"] = time.time()

            line = (json.dumps(payload, ensure_ascii=False) + "\n").encode("utf-8")
            sock.sendto(line, (host, port))
            send_count += 1
            if send_count == 1:
                print(f"[Proxy] First packet sent to {host}:{port}", flush=True)
            elif send_count % 1000 == 0:
                print(f"[Proxy] Sent {send_count} packets", flush=True)

    except (KeyboardInterrupt, SystemExit):
        pass
    finally:
        try:
            feed.close()
        except Exception:
            pass
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
