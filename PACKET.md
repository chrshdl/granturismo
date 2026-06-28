# Packet reference

Fields are decoded from fixed little-endian byte offsets in the decrypted
payload. All values are what the console transmits; no scaling is applied except
where noted.

## Top-level fields

| Field | Type | Notes |
|---|---|---|
| `packet_id` | `int` | Monotonically increasing sequence number. |
| `received_time` | `float` | `time.time()` at datagram receipt, before decryption. |
| `car_id` | `int` | Overwritten by a gear ratio on cars with more than 8 gears. |
| `lap_count` | `int \| None` | `None` when not in a race. |
| `laps_in_race` | `int \| None` | `None` when not in a race. |
| `best_lap_time` | `int \| None` | Milliseconds. `None` before the first lap is completed. |
| `last_lap_time` | `int \| None` | Milliseconds. `None` before the first lap is completed. |
| `position` | `Vector` | World-space position (x, y, z) in metres. |
| `velocity` | `Vector` | World-space velocity (x, y, z) in m/s. |
| `angular_velocity` | `Vector` | Body angular velocity (x, y, z) in rad/s. |
| `rotation` | `Rotation` | Real part of the unit quaternion rotating the car body into the track frame (pitch, yaw, roll). |
| `road_plane` | `Vector` | Normal of the road surface beneath the car. |
| `road_distance` | `float` | Distance from body origin to road plane; matches `body_height` when grounded. |
| `wheels` | `Wheels` | Per-corner data — see below. |
| `flags` | `Flags` | Packed bitfield — see below. |
| `orientation` | `float` | Heading in radians. |
| `body_height` | `float` | Ride height in metres. |
| `engine_rpm` | `float` | Current engine speed. |
| `gas_level` | `float` | Fuel remaining (0–100). |
| `gas_capacity` | `float` | Tank capacity: 100 for petrol, 5 for karts, 0 for electric. |
| `car_speed` | `float` | Ground speed in m/s. |
| `turbo_boost` | `float` | Subtract 1 to get the value shown on the in-game boost gauge. |
| `oil_pressure` | `float` | Oil pressure in bar (approximate). |
| `oil_temperature` | `float` | Celsius. Appears fixed at 85.0 in normal conditions. |
| `water_temperature` | `float` | Celsius. Appears fixed at 110.0 in normal conditions. |
| `time_of_day` | `int` | Race-start time of day as a millisecond offset. Affected by the Variable Time Speed Ratio setting; not reliable for lap timing when that ratio ≠ 1. |
| `start_position` | `int \| None` | Grid position before race start; `None` once the race is underway. |
| `cars_in_race` | `int \| None` | Field size before race start; `None` once the race is underway. |
| `rpm_alert` | `Bounds` | RPM range for the shift indicator (min, max). |
| `car_max_speed` | `int` | Rated top speed in m/s. |
| `transmission_max_speed` | `float` | Top Speed setting of a custom gearbox, expressed as a gear ratio. |
| `throttle` | `int` | Throttle pedal position (0–255). |
| `brake` | `int` | Brake pedal position (0–255). |
| `clutch` | `float` | Clutch pedal position (0–1). |
| `clutch_engagement` | `float` | Actual clutch engagement (0–1). |
| `clutch_gearbox_rpm` | `float` | RPM at the gearbox input shaft. |
| `current_gear` | `int \| None` | Current gear. 0 = reverse, `None` = neutral. |
| `suggested_gear` | `int \| None` | Upshift suggestion from the game; `None` when none. |
| `gear_ratios` | `list[float]` | Ratios for gears 1–N (stops at the first zero entry). |
| `unused_0x93` | `int` | Always 0. |
| `unused_0xD4` | `int` | Always 0. |

## Wheel fields (`Wheels.front_left`, `.front_right`, `.rear_left`, `.rear_right`)

| Field | Type | Notes |
|---|---|---|
| `suspension_height` | `float` | 0 = fully extended, 1 = fully compressed. |
| `radius` | `float` | Tyre radius in metres. |
| `rps` | `float` | Rotations per second (derived from the raw rad/s value). |
| `ground_speed` | `float` | Tyre contact patch speed in m/s (`radius × rad/s`). |
| `temperature` | `float` | Tyre surface temperature in Celsius. |

## Flags (`Flags`)

| Field | Type | Notes |
|---|---|---|
| `car_on_track` | `bool` | Car is on a driveable surface. |
| `paused` | `bool` | Game is paused. |
| `loading_or_processing` | `bool` | Mid-load or post-race processing; telemetry values are unreliable. |
| `in_gear` | `bool` | `False` while shifting or when the car is in neutral/stationary. |
| `has_turbo` | `bool` | Car has a turbocharger fitted. |
| `rev_limiter_alert_active` | `bool` | Rev-limiter warning is active. |
| `hand_brake_active` | `bool` | Handbrake is applied. |
| `lights_active` | `bool` | Any exterior lights are on. |
| `lights_high_beams_active` | `bool` | High beams are on. |
| `lights_low_beams_active` | `bool` | Low beams are on. |
| `asm_active` | `bool` | Active Stability Management is intervening. |
| `tcs_active` | `bool` | Traction Control System is intervening. |
| `unused1`–`unused4` | `bool` | Always `False`. |
