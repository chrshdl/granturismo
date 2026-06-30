"""The decoded GT7 telemetry :class:`Packet` and its binary parser.

The byte offsets below describe Gran Turismo 7's "Simulator Interface"
packet layout, which is a publicly documented result of community
reverse-engineering (credited in the project README).  Everything here is an
independent implementation of that wire format; values are read as
little-endian, the order the console sends them in.
"""

from __future__ import annotations

import math
import struct
from dataclasses import dataclass
from typing import List, Optional

from granturismo.model.common import Bounds, Flags, Rotation, Vector, Wheel, Wheels

# On the wire the 4-byte magic "G7S0" arrives little-endian, i.e. b"0S7G".
_MAGIC = b"0S7G"

# Sentinel values the game uses to mean "not applicable".
_U16_NONE = 0xFFFF
_U32_NONE = 0xFFFFFFFF
_NIBBLE_NONE = 0x0F

_TWO_PI = 2.0 * math.pi


def _f32(b: bytes, off: int) -> float:
    return struct.unpack_from("<f", b, off)[0]


def _u(b: bytes, off: int, size: int) -> int:
    return int.from_bytes(b[off:off + size], "little")


def _i32(b: bytes, off: int) -> int:
    return struct.unpack_from("<i", b, off)[0]


@dataclass(frozen=True)
class Packet:
    packet_id: int
    received_time: float
    car_id: int
    lap_count: Optional[int]
    laps_in_race: Optional[int]
    best_lap_time: Optional[int]
    last_lap_time: Optional[int]
    current_lap_time: Optional[int]  # ms; None when not in a timed lap (Packet C only)

    position: Vector
    velocity: Vector
    angular_velocity: Vector
    rotation: Rotation

    road_plane: Vector
    road_distance: float

    wheels: Wheels
    flags: Flags

    orientation: float
    body_height: float
    engine_rpm: float
    gas_level: float
    gas_capacity: float
    car_speed: float
    turbo_boost: float
    oil_pressure: float
    oil_temperature: float
    water_temperature: float
    time_of_day: int
    start_position: Optional[int]
    cars_in_race: Optional[int]
    rpm_alert: Bounds
    car_max_speed: int
    transmission_max_speed: float
    throttle: int
    brake: int
    clutch: float
    clutch_engagement: float
    clutch_gearbox_rpm: float
    current_gear: Optional[int]
    suggested_gear: Optional[int]
    gear_ratios: List[float]

    unused_0x93: int
    unused_0xD4: int

    @classmethod
    def from_bytes(cls, b: bytes, received_time: float) -> "Packet":
        """Decode a decrypted telemetry payload into a :class:`Packet`.

        :param b: the plaintext packet bytes (after decryption).
        :param received_time: wall-clock time the datagram arrived.
        """
        if bytes(b[:4]) != _MAGIC:
            raise ValueError(
                f"unexpected packet magic {bytes(b[:4])!r}; not a GT7 telemetry packet"
            )

        best_lap_time = _none_if(_u(b, 120, 4), _U32_NONE)
        last_lap_time = _none_if(_u(b, 124, 4), _U32_NONE)
        # Packet C (368 bytes): current lap timer in ms; -1 when no timed lap active.
        # surface_type (4 bytes) precedes it at offset 344.
        _clt = _i32(b, 348) if len(b) >= 352 else -1
        current_lap_time = None if _clt < 0 else _clt
        lap_count = _none_if(_u(b, 116, 2), _U16_NONE)
        laps_in_race = _none_if(_u(b, 118, 2), _U16_NONE)

        race_state = _u(b, 132, 4)
        start_position = race_state >> 4
        start_position = start_position if start_position < 4096 else None
        cars_in_race = _none_if(race_state & 0xFF, 0xFF)

        gear_byte = _u(b, 144, 1)
        current_gear = _none_if(gear_byte & 0x0F, _NIBBLE_NONE)
        suggested_gear = _none_if(gear_byte >> 4, _NIBBLE_NONE)

        return cls(
            packet_id=_u(b, 112, 4),
            received_time=received_time,
            car_id=_u(b, 292, 4),
            lap_count=lap_count,
            laps_in_race=laps_in_race,
            best_lap_time=best_lap_time,
            last_lap_time=last_lap_time,
            current_lap_time=current_lap_time,
            position=Vector(_f32(b, 4), _f32(b, 8), _f32(b, 12)),
            velocity=Vector(_f32(b, 16), _f32(b, 20), _f32(b, 24)),
            angular_velocity=Vector(_f32(b, 44), _f32(b, 48), _f32(b, 52)),
            rotation=Rotation(_f32(b, 28), _f32(b, 32), _f32(b, 36)),
            road_plane=Vector(_f32(b, 148), _f32(b, 152), _f32(b, 156)),
            road_distance=_f32(b, 160),
            wheels=cls._read_wheels(b),
            flags=cls._read_flags(b, 142),
            orientation=_f32(b, 40),
            body_height=_f32(b, 56),
            engine_rpm=_f32(b, 60),
            gas_level=_f32(b, 68),
            gas_capacity=_f32(b, 72),
            car_speed=_f32(b, 76),
            turbo_boost=_f32(b, 80),
            oil_pressure=_f32(b, 84),
            water_temperature=_f32(b, 88),
            oil_temperature=_f32(b, 92),
            time_of_day=_u(b, 128, 4),
            start_position=start_position,
            cars_in_race=cars_in_race,
            rpm_alert=Bounds(_u(b, 136, 2), _u(b, 138, 2)),
            car_max_speed=_u(b, 140, 2),
            transmission_max_speed=_f32(b, 256),
            throttle=_u(b, 145, 1),
            brake=_u(b, 146, 1),
            clutch=_f32(b, 244),
            clutch_engagement=_f32(b, 248),
            clutch_gearbox_rpm=_f32(b, 252),
            current_gear=current_gear,
            suggested_gear=suggested_gear,
            gear_ratios=cls._read_gear_ratios(b, 260),
            unused_0x93=_u(b, 147, 1),
            unused_0xD4=_u(b, 212, 32),
        )

    @staticmethod
    def _read_wheels(b: bytes) -> Wheels:
        # offsets per corner: (angular speed rad/s, radius m, suspension, temp)
        corners = (
            (164, 180, 196, 96),   # front-left
            (168, 184, 200, 100),  # front-right
            (172, 188, 204, 104),  # rear-left
            (176, 192, 208, 108),  # rear-right
        )
        wheels = []
        for rads_off, radius_off, susp_off, temp_off in corners:
            rads = _f32(b, rads_off)        # wheel rotation speed, radians/second
            radius = _f32(b, radius_off)
            wheels.append(Wheel(
                suspension_height=_f32(b, susp_off),
                radius=radius,
                rps=rads / _TWO_PI,
                ground_speed=radius * rads,  # 2*pi*r * (rads / 2*pi)
                temperature=_f32(b, temp_off),
            ))
        return Wheels(*wheels)

    @staticmethod
    def _read_flags(b: bytes, off: int) -> Flags:
        bits = _u(b, off, 2)
        flags = [bool(bits & (1 << i)) for i in range(16)]
        return Flags(*flags)

    @staticmethod
    def _read_gear_ratios(b: bytes, off: int) -> List[float]:
        ratios: List[float] = []
        for gear in range(8):
            ratio = _f32(b, off + gear * 4)
            if ratio == 0:
                break
            ratios.append(ratio)
        return ratios


def _none_if(value: int, sentinel: int) -> Optional[int]:
    return None if value == sentinel else value
