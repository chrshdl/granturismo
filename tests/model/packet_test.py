import math

import pytest

from granturismo.model.packet import Packet
from tests.helpers import build_packet_buffer


def test_rejects_invalid_magic():
    buffer = build_packet_buffer()
    buffer[0:4] = b"XXXX"
    with pytest.raises(ValueError):
        Packet.from_bytes(buffer, received_time=0.0)


def test_parses_known_buffer():
    packet = Packet.from_bytes(build_packet_buffer(), received_time=123.5)

    assert packet.packet_id == 12345
    assert packet.received_time == 123.5
    assert packet.car_id == 42

    assert packet.position.x == 1.0 and packet.position.z == 3.0
    assert packet.velocity.y == 5.0
    assert packet.rotation.pitch == pytest.approx(0.1)
    assert packet.orientation == 0.5
    assert packet.angular_velocity.z == 9.0

    assert packet.lap_count == 2
    assert packet.laps_in_race == 10
    assert packet.best_lap_time == 90000
    assert packet.last_lap_time == 95000
    assert packet.time_of_day == 3600000

    assert packet.start_position == 3
    assert packet.cars_in_race == 0x35
    assert packet.rpm_alert.min == 7000
    assert packet.rpm_alert.max == 8000
    assert packet.car_max_speed == 300

    assert packet.current_gear == 3
    assert packet.suggested_gear == 4
    assert packet.throttle == 200
    assert packet.brake == 100

    assert packet.engine_rpm == 5000.0
    assert packet.car_speed == pytest.approx(55.5)
    assert packet.gear_ratios == pytest.approx([3.5, 2.5, 1.8, 1.3, 1.0, 0.8])


def test_flags_decode_to_correct_bits():
    flags = Packet.from_bytes(build_packet_buffer(), 0.0).flags
    assert flags.car_on_track is True
    assert flags.in_gear is True
    assert flags.has_turbo is True
    assert flags.paused is False
    assert flags.loading_or_processing is False
    assert flags.tcs_active is False


def test_wheel_physics_are_derived_from_rotation_speed():
    fl = Packet.from_bytes(build_packet_buffer(), 0.0).wheels.front_left
    # front-left: rotation speed 10 rad/s, radius 0.30 m, suspension 0.40
    assert fl.radius == pytest.approx(0.30)
    assert fl.suspension_height == pytest.approx(0.40)
    assert fl.temperature == 80.0
    assert fl.rps == pytest.approx(10.0 / (2 * math.pi))
    assert fl.ground_speed == pytest.approx(0.30 * 10.0)


def test_none_sentinels():
    buffer = build_packet_buffer()
    # 0xFFFFFFFF best/last lap, 0xFFFF lap counts, nibble 0xF gears
    buffer[120:124] = (0xFFFFFFFF).to_bytes(4, "little")
    buffer[116:118] = (0xFFFF).to_bytes(2, "little")
    buffer[144] = 0xFF  # both gear nibbles == 0xF
    packet = Packet.from_bytes(buffer, 0.0)
    assert packet.best_lap_time is None
    assert packet.lap_count is None
    assert packet.current_gear is None
    assert packet.suggested_gear is None
