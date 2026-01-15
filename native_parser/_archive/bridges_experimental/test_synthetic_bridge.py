#!/usr/bin/env python3
"""
Test the full native bridge with synthetic data matching Oura's exact format.
This verifies our byte serialization is correct.
"""

import subprocess
import struct
from pathlib import Path


def create_synthetic_sleep_data():
    """
    Create synthetic sleep data that matches Oura's exact format.
    Uses a 7-hour sleep session with realistic values.
    Uses AppEventSerializer for proper header formatting.
    """
    import sys
    sys.path.insert(0, '.')
    from oura.native.app_event import AppEventSerializer

    # Timestamps (milliseconds since epoch)
    # Typical night: 11 PM to 6 AM = 7 hours = 84 five-minute epochs
    bed_start_ms = 1700000000000  # Some arbitrary timestamp
    bed_end_ms = bed_start_ms + (7 * 60 * 60 * 1000)  # +7 hours
    tz_offset = 0  # UTC

    num_epochs = 84  # 7 hours of 5-min epochs
    phases = []
    for i in range(num_epochs):
        # Simple cycle: Deep(3) -> Light(2) -> REM(1) -> Awake(0)
        cycle_pos = (i // 20) % 4
        if cycle_pos == 0:
            phases.append(3)  # Deep
        elif cycle_pos == 1:
            phases.append(2)  # Light
        elif cycle_pos == 2:
            phases.append(1)  # REM
        else:
            phases.append(2)  # Light

    # Use AppEventSerializer which adds proper headers
    sleep_phases = AppEventSerializer.sleep_phases_v2(bed_start_ms, tz_offset, phases)
    print(f"sleep_phases: {len(sleep_phases)} bytes ({num_epochs} epochs)")
    print(f"  First 20 bytes: {sleep_phases[:20].hex()}")

    bedtime = AppEventSerializer.bedtime_period(bed_start_ms, tz_offset, bed_end_ms, tz_offset)
    print(f"bedtime: {len(bedtime)} bytes")

    # Sleep raw features
    raw_values = []
    for i in range(num_epochs):
        epoch_ts = bed_start_ms + (i * 5 * 60 * 1000)
        raw_values.append({
            'timestamp': epoch_ts,
            'tz_seconds': tz_offset,
            'avg_hr': 55.0 + (i % 20),
            'avg_breath': 14.0 + (i % 5) * 0.5,
            'std_breath': 1.0 + (i % 3) * 0.2,
            'sleep_state': phases[i],
        })
    raw_features = AppEventSerializer.sleep_raw_features(raw_values)
    print(f"raw_features: {len(raw_features)} bytes")

    # Motion
    motion_vals = [2 if phases[i] != 0 else 15 for i in range(num_epochs)]
    motion = AppEventSerializer.motion_seconds(bed_start_ms, tz_offset, motion_vals)
    print(f"motion: {len(motion)} bytes")

    # Temperatures
    temps_centideg = [3500 + (i % 20) * 5 for i in range(num_epochs)]
    temps = AppEventSerializer.skin_temperatures(bed_start_ms, tz_offset, temps_centideg)
    print(f"temps: {len(temps)} bytes")

    # HR/HRV
    hrv_vals = [(55 + (i % 20), 30 + (i % 15)) for i in range(num_epochs)]
    hrhrv = AppEventSerializer.hr_hrv_5min_averages(bed_start_ms, tz_offset, hrv_vals)
    print(f"hrhrv: {len(hrhrv)} bytes")

    # Low battery (with header)
    low_battery = AppEventSerializer.low_battery_alert(bed_start_ms)
    print(f"low_battery: {len(low_battery)} bytes")

    return {
        'sleep_phases': sleep_phases,
        'sleep_raw_features': raw_features,
        'motion_seconds': motion,
        'bedtime_period': bedtime,
        'low_battery': low_battery,
        'skin_temps': temps,
        'hr_hrv_5min': hrhrv,
    }


def run_bridge(arrays):
    """Run the bridge with the given byte arrays."""
    native_parser_dir = Path(__file__).parent
    android_root = native_parser_dir / "android_root"

    # Build binary input
    data = b''

    # Order matters - must match bridge expectations
    order = ['sleep_phases', 'sleep_raw_features', 'motion_seconds',
             'bedtime_period', 'low_battery', 'skin_temps', 'hr_hrv_5min']

    for key in order:
        arr = arrays[key]
        data += struct.pack('<I', len(arr))
        data += arr

    # User info (64 bytes)
    user_info = struct.pack('<iiii', 30, 70, 175, 0)  # age, weight, height, gender
    user_info += b'\x00' * (64 - len(user_info))
    data += user_info

    # Chronotype (32 bytes)
    # Field is idealSleepMidpointSec, NOT ideal_bedtime!
    # For 11PM-6AM sleep, midpoint is ~2:30 AM = 2.5 * 3600 = 9000 seconds
    chronotype = struct.pack('<ii', 2, 9000)  # type=MORNING, midpoint=2:30AM
    chronotype += b'\x00' * (32 - len(chronotype))
    data += chronotype

    # Day offset
    data += struct.pack('<i', 0)

    print(f"\nTotal input: {len(data)} bytes")

    # Run via QEMU with android_root for full bionic environment
    # The bridge binary needs to be compiled with NDK or use a different approach
    lib_path = f".:{android_root}/system/lib64"
    env = {
        "PATH": "/usr/bin:/bin",
        "LD_LIBRARY_PATH": lib_path,
        "QEMU_LD_PREFIX": str(android_root),
    }
    cmd = ["qemu-aarch64", str(native_parser_dir / "sleep_full_bridge")]

    result = subprocess.run(cmd, input=data, capture_output=True, env=env,
                           timeout=120, cwd=str(native_parser_dir))

    print("\n=== STDERR ===")
    print(result.stderr.decode()[:2000])

    print("\n=== STDOUT ===")
    stdout = result.stdout.decode()
    print(stdout[:500])

    # Parse output
    for line in stdout.split('\n'):
        if line.startswith('output_hex:'):
            hex_data = line.split(':')[1]
            output = bytes.fromhex(hex_data)

            print("\n=== Output Analysis ===")
            print("Non-zero bytes (first 256):")
            for i, b in enumerate(output[:256]):
                if b != 0:
                    print(f"  [{i}] = {b} (0x{b:02x})")

            print("\n4-byte ints at aligned offsets (signed):")
            for i in range(0, 256, 4):
                val = struct.unpack('<i', output[i:i+4])[0]
                if val != 0:
                    print(f"  [{i}] = {val}")

            print("\nLooking for score-like bytes (1-100):")
            for i, b in enumerate(output[:256]):
                if 1 <= b <= 100:
                    print(f"  [{i}] = {b}")

            print("\nSleepInfo structure interpretation:")
            # Native struct - try to match SleepInfo fields
            # Based on decompiled Java: SleepInfo has timestamps, then nested summaries

            def read_int(off):
                return struct.unpack('<i', output[off:off+4])[0]
            def read_long(off):
                return struct.unpack('<q', output[off:off+8])[0]

            # First try: timestamps at beginning
            print(f"\n  === Timestamps (longs) ===")
            for i in range(0, 80, 8):
                val = read_long(i)
                if val != 0:
                    print(f"  [{i}] = {val}")

            # Then look for int32 values
            print(f"\n  === Int32 values ===")
            for i in range(0, 256, 4):
                val = read_int(i)
                if val != 0 and -100000000 < val < 100000000:
                    # Filter reasonable values
                    print(f"  [{i}] = {val}")

            # SleepSummary2 interpretation (if embedded inline)
            # Fields: wakeTime, remTime, lightTime, deepTime, score, wakeUpCount, latency, totalSleep, efficiency
            print(f"\n  === Looking for SleepSummary2-like data (9 ints) ===")
            for start_offset in range(0, 200, 4):
                vals = [read_int(start_offset + i*4) for i in range(9)]
                # Check if this looks like sleep summary (reasonable values)
                if all(0 <= v <= 50000 for v in vals[:4]):  # Time values
                    if 0 < vals[4] <= 100:  # score
                        print(f"  Possible SleepSummary2 at offset {start_offset}:")
                        print(f"    wakeTime={vals[0]}s, remTime={vals[1]}s, lightTime={vals[2]}s, deepTime={vals[3]}s")
                        print(f"    score={vals[4]}, wakeUpCount={vals[5]}, latency={vals[6]}s")
                        print(f"    totalSleep={vals[7]}s, efficiency={vals[8]}")

            return output

    return None


def main():
    print("=== Synthetic Sleep Data Test ===\n")

    arrays = create_synthetic_sleep_data()
    output = run_bridge(arrays)

    if output and any(b != 0 for b in output[:256]):
        print("\n*** SUCCESS - Got non-zero output! ***")
    else:
        print("\n*** Still getting zeros - need to debug format ***")


if __name__ == '__main__':
    main()
