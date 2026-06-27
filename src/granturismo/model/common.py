"""Value types that make up a telemetry :class:`~granturismo.model.Packet`.

These are plain frozen dataclasses so they serialise cleanly with
:func:`dataclasses.asdict` and require no third-party runtime dependency.
"""

from __future__ import annotations

import enum
from dataclasses import dataclass


__all__ = [
    "CarType", "GameState", "Vector", "Rotation",
    "Wheel", "Wheels", "Bounds", "Flags",
]


class CarType(enum.Enum):
    UNKNOWN = 0
    GAS = 1
    ELECTRIC = 2
    KART = 3


class GameState(enum.Enum):
    UNKNOWN = 0
    MENU = 1
    PRE_RACE = 2
    RACE = 3
    POST_RACE = 4
    TIME_TRIAL = 5
    CIRCUIT_EXP_SECTOR = 6


@dataclass(frozen=True)
class Vector:
    x: float
    y: float
    z: float


@dataclass(frozen=True)
class Rotation:
    pitch: float
    yaw: float
    roll: float


@dataclass(frozen=True)
class Wheel:
    suspension_height: float  # 0 (extended) .. 1 (compressed)
    radius: float             # metres
    rps: float                # rotations per second
    ground_speed: float       # metres per second
    temperature: float        # celsius


@dataclass(frozen=True)
class Wheels:
    front_left: Wheel
    front_right: Wheel
    rear_left: Wheel
    rear_right: Wheel


@dataclass(frozen=True)
class Bounds:
    min: float
    max: float


@dataclass(frozen=True)
class Flags:
    car_on_track: bool
    paused: bool
    loading_or_processing: bool
    in_gear: bool
    has_turbo: bool
    rev_limiter_alert_active: bool
    hand_brake_active: bool
    lights_active: bool
    lights_high_beams_active: bool
    lights_low_beams_active: bool
    asm_active: bool
    tcs_active: bool
    unused1: bool
    unused2: bool
    unused3: bool
    unused4: bool
