"""Small helpers for inspecting raw telemetry bytes during development."""

from __future__ import annotations

import struct


def to_bit_str(value) -> str:
    """Render ``value`` as space-separated 8-bit groups, MSB first.

    Accepts bytes/bytearray, an int, a float (packed as a 32-bit float), or a
    str (each character's code point).
    """
    if isinstance(value, float):
        value = struct.pack("f", value)
    if isinstance(value, str):
        value = value.encode("latin-1")
    if isinstance(value, (bytes, bytearray)):
        return " ".join(f"{byte:08b}" for byte in value)
    if isinstance(value, int):
        width = max(8, (value.bit_length() + 7) // 8 * 8)
        return format(value, f"0{width}b")
    raise TypeError(f"unsupported type: {type(value).__name__}")
