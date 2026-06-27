"""Helpers for building synthetic telemetry buffers in tests."""

from __future__ import annotations

import struct

from granturismo.security import salsa20
from granturismo.security.decrypter import _KEY, _NONCE_MASK, _SEED_OFFSET

PACKET_LEN = 0x128  # 296 bytes


def encrypt_packet(plaintext: bytes, seed: int = 0x0BADC0DE) -> bytes:
    """Encrypt ``plaintext`` the way the console does, decryptable by Decrypter.

    The decrypter reads its nonce seed from offset 0x40 of the *encrypted*
    bytes, so we stash the seed there.  Offset 0x40 falls in a region the
    packet parser ignores, leaving all decoded fields untouched.
    """
    nonce = (seed ^ _NONCE_MASK).to_bytes(4, "little") + seed.to_bytes(4, "little")
    keystream = salsa20.xor(bytes(len(plaintext)), nonce, _KEY)
    buf = bytearray(plaintext)
    buf[_SEED_OFFSET:_SEED_OFFSET + 4] = bytes(
        s ^ k for s, k in zip(seed.to_bytes(4, "little"),
                              keystream[_SEED_OFFSET:_SEED_OFFSET + 4])
    )
    cipher = salsa20.xor(bytes(buf), nonce, _KEY)
    assert cipher[_SEED_OFFSET:_SEED_OFFSET + 4] == seed.to_bytes(4, "little")
    return cipher


def build_packet_buffer() -> bytearray:
    """Return a 296-byte decrypted packet with known values at every offset.

    The values chosen here are mirrored by the assertions in
    ``tests/model/test_packet.py``; keep the two in sync.
    """
    b = bytearray(PACKET_LEN)
    b[0:4] = b"0S7G"  # "G7S0" little-endian magic

    def f32(off: float, val: float) -> None:
        struct.pack_into("<f", b, off, val)

    def u(off: int, size: int, val: int) -> None:
        b[off:off + size] = val.to_bytes(size, "little")

    # vectors / rotation / scalars
    f32(4, 1.0); f32(8, 2.0); f32(12, 3.0)        # position
    f32(16, 4.0); f32(20, 5.0); f32(24, 6.0)      # velocity
    f32(28, 0.1); f32(32, 0.2); f32(36, 0.3)      # rotation
    f32(40, 0.5)                                   # orientation
    f32(44, 7.0); f32(48, 8.0); f32(52, 9.0)      # angular_velocity
    f32(56, 0.25)                                  # body_height
    f32(60, 5000.0)                                # engine_rpm
    f32(68, 50.0); f32(72, 100.0)                  # gas level / capacity
    f32(76, 55.5)                                  # car_speed
    f32(80, 1.2)                                   # turbo_boost
    f32(84, 5.0)                                   # oil_pressure
    f32(88, 110.0); f32(92, 85.0)                  # water / oil temperature

    # wheel surface temperatures
    f32(96, 80.0); f32(100, 81.0); f32(104, 82.0); f32(108, 83.0)

    u(112, 4, 12345)        # packet_id
    u(116, 2, 2)            # lap_count
    u(118, 2, 10)           # laps_in_race
    u(120, 4, 90000)        # best_lap_time
    u(124, 4, 95000)        # last_lap_time
    u(128, 4, 3600000)      # time_of_day
    u(132, 4, 0x35)         # race_state -> start_position=3, cars_in_race=0x35
    u(136, 2, 7000)         # rpm_alert.min
    u(138, 2, 8000)         # rpm_alert.max
    u(140, 2, 300)          # car_max_speed
    u(142, 2, 0b0000000000011001)  # flags: car_on_track, in_gear, has_turbo
    u(144, 1, (4 << 4) | 3)  # gear byte: suggested=4, current=3
    u(145, 1, 200)          # throttle
    u(146, 1, 100)          # brake
    u(147, 1, 0)            # unused_0x93

    f32(148, 0.0); f32(152, 1.0); f32(156, 0.0)   # road_plane
    f32(160, 0.25)                                 # road_distance

    # wheel rotation speed (rad/s), radius, suspension per corner
    f32(164, 10.0); f32(168, 11.0); f32(172, 12.0); f32(176, 13.0)
    f32(180, 0.30); f32(184, 0.31); f32(188, 0.32); f32(192, 0.33)
    f32(196, 0.40); f32(200, 0.41); f32(204, 0.42); f32(208, 0.43)

    f32(244, 0.9)           # clutch
    f32(248, 0.8)           # clutch_engagement
    f32(252, 4500.0)        # clutch_gearbox_rpm
    f32(256, 2.5)           # transmission_max_speed

    # gear ratios: six real gears then zero terminator
    for i, ratio in enumerate((3.5, 2.5, 1.8, 1.3, 1.0, 0.8)):
        f32(260 + i * 4, ratio)

    u(292, 4, 42)           # car_id
    return b
