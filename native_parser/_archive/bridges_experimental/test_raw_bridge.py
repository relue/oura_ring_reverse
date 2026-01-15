#!/usr/bin/env python3
"""Test with raw data (no AppEvent headers) to see if that's what function expects."""

import subprocess
import struct
from pathlib import Path

def create_raw_sleep_data():
    """Create sleep data WITHOUT AppEvent headers."""
    bed_start_ms = 1700000000000
    bed_end_ms = bed_start_ms + (7 * 3600 * 1000)
    tz = 0
    num_epochs = 84

    # Phases: just the raw format [timestamp][tz][packed_phases]
    phases = [2] * num_epochs  # All light sleep
    sleep_phases = struct.pack('<qI', bed_start_ms, tz)
    for i in range(0, len(phases), 2):
        a, b = phases[i], phases[i+1] if i+1 < len(phases) else 0
        sleep_phases += struct.pack('B', (a & 0xF) | ((b & 0xF) << 4))
    
    # Bedtime: [start_ts][start_tz][end_ts][end_tz]
    bedtime = struct.pack('<qIqI', bed_start_ms, tz, bed_end_ms, tz)
    
    # Raw features: [ts][tz][hr][breath][std_breath][state] per epoch
    raw_features = b''
    for i in range(num_epochs):
        epoch_ts = bed_start_ms + (i * 5 * 60 * 1000)
        raw_features += struct.pack('<qIfffI', epoch_ts, tz, 60.0, 15.0, 1.0, 2)
    
    # Motion: [ts][tz][motion_bytes...]
    motion = struct.pack('<qI', bed_start_ms, tz) + bytes([5] * num_epochs)
    
    # Temps: [ts][tz][temp_centideg...]
    temps = struct.pack('<qI', bed_start_ms, tz)
    for i in range(num_epochs):
        temps += struct.pack('<i', 3550)
    
    # HRV: [ts][tz][[hr*8][rmssd*8]...]
    hrv = struct.pack('<qI', bed_start_ms, tz)
    for i in range(num_epochs):
        hrv += struct.pack('<HH', 60*8, 40*8)
    
    # Empty low battery
    low_battery = b''
    
    print(f"RAW (no headers): phases={len(sleep_phases)}B bedtime={len(bedtime)}B")
    
    return {
        'sleep_phases': sleep_phases,
        'sleep_raw_features': raw_features,
        'motion_seconds': motion,
        'bedtime_period': bedtime,
        'low_battery': low_battery,
        'skin_temps': temps,
        'hr_hrv_5min': hrv,
    }

def run_bridge(arrays):
    native_parser_dir = Path(__file__).parent
    android_root = native_parser_dir / "android_root"
    
    data = b''
    order = ['sleep_phases', 'sleep_raw_features', 'motion_seconds',
             'bedtime_period', 'low_battery', 'skin_temps', 'hr_hrv_5min']
    
    for key in order:
        arr = arrays[key]
        data += struct.pack('<I', len(arr))
        data += arr
    
    # User info
    user_info = struct.pack('<iiii', 30, 70, 175, 0)
    user_info += b'\x00' * (64 - len(user_info))
    data += user_info
    
    # Chronotype
    chronotype = struct.pack('<ii', 2, 9000)
    chronotype += b'\x00' * (32 - len(chronotype))
    data += chronotype
    
    data += struct.pack('<i', 0)
    
    lib_path = f".:{android_root}/system/lib64"
    env = {
        "PATH": "/usr/bin:/bin",
        "LD_LIBRARY_PATH": lib_path,
        "QEMU_LD_PREFIX": str(android_root),
    }
    result = subprocess.run(
        ["qemu-aarch64", str(native_parser_dir / "sleep_full_bridge")],
        input=data, capture_output=True, env=env, timeout=120, cwd=str(native_parser_dir)
    )
    
    print("STDERR:", result.stderr.decode()[-500:])
    
    for line in result.stdout.decode().split('\n'):
        if line.startswith('output_hex:'):
            output = bytes.fromhex(line.split(':')[1])
            print("\nNon-zero int32s:")
            for i in range(0, 256, 4):
                val = struct.unpack('<i', output[i:i+4])[0]
                if val != 0:
                    print(f"  [{i}] = {val}")

if __name__ == '__main__':
    arrays = create_raw_sleep_data()
    run_bridge(arrays)
