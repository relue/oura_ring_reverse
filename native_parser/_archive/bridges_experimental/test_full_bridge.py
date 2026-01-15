#!/usr/bin/env python3
"""
Test the full native sleep bridge with real protobuf data.
Uses AppEventSerializer to create 1:1 Oura byte arrays.
"""

import subprocess
import struct
import sys
sys.path.insert(0, '.')

from oura.data.reader import RingDataReader
from oura.native.app_event import AppEventSerializer, create_sleep_input_from_protobuf


def run_full_bridge(sleep_input):
    """
    Run sleep_full_bridge with serialized AppEvent data.

    Binary protocol:
        For each of 7 arrays: [4-byte length LE][bytes...]
        Then: [user_info struct][chronotype struct][day_offset int]
    """
    from pathlib import Path

    # Android root for QEMU (local to project)
    native_parser_dir = Path(__file__).parent
    android_root = native_parser_dir / "android_root"

    # Build binary input
    data = b''

    # 7 byte arrays (length-prefixed, little-endian)
    arrays = [
        sleep_input.sleep_phases,
        sleep_input.sleep_raw_features,
        sleep_input.motion_seconds,
        sleep_input.bedtime_period,
        sleep_input.low_battery,
        sleep_input.skin_temps,
        sleep_input.hr_hrv_5min,
    ]

    print("Input arrays:")
    for i, arr in enumerate(arrays):
        name = ['sleep_phases', 'sleep_raw_features', 'motion_seconds',
                'bedtime_period', 'low_battery', 'skin_temps', 'hr_hrv_5min'][i]
        print(f"  {name}: {len(arr)} bytes")
        data += struct.pack('<I', len(arr))
        data += arr

    # User info struct (64 bytes)
    user_info = struct.pack('<iiii',
        sleep_input.age,
        sleep_input.weight_kg,
        sleep_input.height_cm,
        sleep_input.gender)
    user_info += b'\x00' * (64 - len(user_info))  # Pad to 64 bytes
    data += user_info

    # Chronotype struct (32 bytes)
    chronotype = struct.pack('<ii',
        sleep_input.chronotype,
        sleep_input.ideal_bedtime_seconds)
    chronotype += b'\x00' * (32 - len(chronotype))  # Pad to 32 bytes
    data += chronotype

    # Day offset
    data += struct.pack('<i', sleep_input.day_offset)

    print(f"\nTotal input: {len(data)} bytes")

    # Run bridge via QEMU (same approach as parser.py)
    env = {
        "PATH": "/usr/bin:/bin",
        "QEMU_LD_PREFIX": str(android_root),
    }

    cmd = [
        "qemu-aarch64",
        str(native_parser_dir / "sleep_full_bridge"),
    ]

    result = subprocess.run(
        cmd,
        input=data,
        capture_output=True,
        env=env,
        timeout=120,
        cwd=str(native_parser_dir)
    )

    print("\n=== Bridge stderr ===")
    print(result.stderr.decode())

    print("\n=== Bridge stdout ===")
    stdout = result.stdout.decode()
    print(stdout[:500] if len(stdout) > 500 else stdout)

    # Parse output_hex line
    for line in stdout.split('\n'):
        if line.startswith('output_hex:'):
            hex_data = line.split(':')[1]
            output_bytes = bytes.fromhex(hex_data)
            return output_bytes

    return None


def analyze_output(output_bytes):
    """Analyze output buffer looking for score-like values."""
    if not output_bytes:
        print("No output to analyze")
        return

    print("\n=== Output Analysis ===")

    # Look for non-zero regions
    print("\nNon-zero bytes:")
    for i, b in enumerate(output_bytes[:256]):
        if b != 0:
            print(f"  [{i}] = {b} (0x{b:02x})")

    # Look for 4-byte integers
    print("\n4-byte integers (little-endian):")
    for i in range(0, min(256, len(output_bytes)), 4):
        val = struct.unpack('<i', output_bytes[i:i+4])[0]
        if val != 0 and -100000 < val < 100000:
            print(f"  offset {i}: {val}")

    # Look for floats
    print("\nPossible floats:")
    for i in range(0, min(256, len(output_bytes)), 4):
        try:
            val = struct.unpack('<f', output_bytes[i:i+4])[0]
            if val != 0 and 0.1 < abs(val) < 10000:
                print(f"  offset {i}: {val:.2f}")
        except:
            pass


def main():
    print("=== Full Sleep Bridge Test ===\n")

    # Load protobuf data
    reader = RingDataReader('input_data/ring_data.pb')
    print(f"Loaded protobuf with {len(list(reader.raw.bedtime_period.bedtime_start))} nights")

    # Create sleep input for last night
    print("\nCreating AppEvent data for last night...")
    sleep_input = create_sleep_input_from_protobuf(reader, night_index=-1)

    # Run bridge
    print("\n=== Running Full Bridge ===")
    output = run_full_bridge(sleep_input)

    # Analyze
    if output:
        analyze_output(output)
    else:
        print("Failed to get output from bridge")


if __name__ == '__main__':
    main()
