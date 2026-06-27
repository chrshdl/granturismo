# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

A **pure standard-library** Python library (Python >= 3.12) that reads Gran Turismo 7's unofficial UDP telemetry stream. Given a PlayStation's IP, it sends heartbeats to the console, decrypts and decodes incoming packets into structured `Packet` objects. It has **no third-party runtime dependencies** and is MIT-licensed — it is an independent reimplementation of the publicly reverse-engineered GT7 wire format (the repo was forked from the unlicensed `lucaspettit/telempy`, then rewritten from scratch to clear the license).

## Commands

```bash
# The repo ships a uv-managed .venv that has NO pip. Install dev deps with uv:
VIRTUAL_ENV="$PWD/.venv" uv pip install -e '.[dev]'

# Run the suite / a single file / a single test
.venv/bin/python -m pytest
.venv/bin/python -m pytest tests/model/packet_test.py
.venv/bin/python -m pytest tests/intake/feed_test.py::test_latest_wins_keeps_only_freshest

# Run an example against a real PlayStation (PS IP + game running)
python3 examples/quickstart.py <PS_IP>

# Build the self-contained, architecture-independent bundle (version from `git describe`)
.venv/bin/python scripts/build_tarball.py --lib-root . --output dist/granturismo-selfcontained.tar.gz
```

## Architecture

Data path: **UDP socket → decrypt (Salsa20) → decode (byte offsets) → latest-wins mailbox → consumer**.

- **`granturismo.intake.feed.Feed`** (`src/granturismo/intake/feed.py`) — public entry point, re-exported as `granturismo.Feed`. A context manager owning two daemon threads: a heartbeat loop sending `b"A"` every 10s to port **33739** (the console only streams while it receives heartbeats), and a receiver loop on port **33740** that decrypts/parses and publishes to a **single-slot "latest wins" mailbox** (a `Condition` guarding one `Packet`). Three consumers: `get()` (blocks for the next packet), `get_latest(timeout)` (waits up to timeout, `None` on timeout), `get_nowait()` (non-blocking). All can return `None` once the feed is closed. **Always close the feed** or the console keeps streaming. Note: `Feed` installs **no signal handlers** — graceful shutdown is the application's job (see the proxy). This is deliberate; the old global SIGINT/SIGTERM handlers in `__init__` caused the recursion/shutdown bugs visible in git history.

- **`granturismo.security`** — `salsa20.py` is an independent pure-Python Salsa20/20 implementation (public-domain cipher); `decrypter.py` derives the 8-byte nonce per packet from the 32-bit seed at offset **0x40** of the encrypted buffer XOR'd with `0xDEADBEAF`, with a fixed 32-byte key, then XORs. There is **no external salsa20 dependency** anymore.

- **`granturismo.model`** — `Packet.from_bytes(buf, received_time)` checks the little-endian magic `b"0S7G"` ("G7S0") then reads fixed little-endian byte offsets (`struct.unpack_from("<...")`) into a plain frozen `@dataclass`. Value types (`Vector`, `Rotation`, `Wheel`, `Wheels`, `Bounds`, `Flags`) in `common.py` are also plain frozen dataclasses, so `dataclasses.asdict` serializes them for the proxy. The exhaustive field/offset/unit documentation lives in the README "Data" section — **consult it before touching offset math**. Wheel `rps`/`ground_speed` are derived from the raw rad/s field (`rps = rads / 2π`, `ground_speed = radius * rads`).

- **`src/proxy.py`** + **`src/proxy-wrapper.py`** — the GT7-UDP→NDJSON forwarder, **not** part of the importable package; staged into the bundle by `build_tarball.py`. `proxy.py` runs a `Feed`, serializes each packet to one JSON line, and re-emits over UDP to a `udp://HOST:PORT` sink (`--ps-ip`/`GT_PS_IP`, `--jsonl-output`/`GT_JSONL_OUTPUT`); it installs SIGINT/SIGTERM handlers for clean systemd shutdown. `proxy-wrapper.py` is the bundle root entry point: it puts the bundle (and an optional `vendor/`, currently unused) on `sys.path` and execs `granturismo/proxy.py` under the stock `python3`.

### Downstream contract (do not break)

This package is consumed by two sibling repos via the release tarball, so these are load-bearing:
- The release names the artifact `granturismo-selfcontained-<version>.tar.gz`; `instrument-cluster/.../installer.py` downloads `v<VERSION>` and expects `proxy-wrapper.py` at the tarball root + `granturismo/proxy.py`.
- `instrument-cluster-proxy.service` runs `python3 /opt/granturismo/proxy-wrapper.py --jsonl-output ${GT_JSONL_OUTPUT} --ps-ip ${GT_PS_IP}` — keep those flags and the env-var fallbacks.
- The emitted NDJSON keys are the `Packet`/`Flags`/`Wheel` dataclass field names (e.g. `flags.car_on_track`). Renaming a field changes the wire format the cluster parses.

## Tests

Plain `pytest` functions, **fully self-contained** — no fixture files, no PlayStation. `tests/helpers.py` builds synthetic packet buffers (`build_packet_buffer`) and encrypts them (`encrypt_packet`). `feed_test.py` exercises the real receive→decrypt→parse path over loopback UDP by sending crafted packets to port 33740. `test_salsa20.py` pins the cipher against the canonical all-zero ECRYPT known-answer vector.

## Conventions

- Source layout is `src/` (package under `src/granturismo`); always use absolute `granturismo.*` imports.
- New/rewritten code is **4-space** indented PEP 8. (The pre-rewrite history had 2-space files; the current `src/granturismo` tree is uniform 4-space.)
- `internal/` holds throwaway research/capture scripts. They are **stale** — they import the long-removed `Listener` and `granturismo.utils.settings`, are not shipped in the bundle, and are not tested. Don't rely on them.
