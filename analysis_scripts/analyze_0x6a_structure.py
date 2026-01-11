#!/usr/bin/env python3
"""
Analyze 0x6a (SLEEP_PERIOD_INFO_2) event structure
These appear to be individual samples, not protobuf messages
"""

import struct
from datetime import datetime

# Example events from your logs (bytes 2-15, the 14-byte payload after tag and length)
samples = [
    bytes.fromhex("95 05 02 00 87 0a 36 1e 92 22 00 01 00 00"),
    bytes.fromhex("2e 03 02 00 85 00 26 0d b8 09 00 01 00 00"),
    bytes.fromhex("d7 c9 00 00 85 f7 41 2c 8d 2c 00 01 00 00"),
    bytes.fromhex("c5 c8 00 00 85 f1 23 0e 84 2c 00 00 00 00"),
    bytes.fromhex("70 c7 00 00 8b 1f 30 1e 8d 2f 06 00 00 00"),
    bytes.fromhex("5f c6 00 00 8b 24 42 29 87 31 09 00 00 00"),
    bytes.fromhex("09 c5 00 00 8c 2c 75 61 56 4e 0d 00 00 00"),
    bytes.fromhex("ec c3 00 00 8f 43 75 61 67 49 0d 01 00 00"),
    bytes.fromhex("eb c2 00 00 86 00 2b 18 3e 1b 07 01 00 00"),
]

print("="*80)
print("0x6a (SLEEP_PERIOD_INFO_2) STRUCTURE ANALYSIS")
print("="*80)
print(f"\nAnalyzing {len(samples)} samples...")
print(f"Each sample is {len(samples[0])} bytes")

# Try different interpretations
print("\n" + "-"*80)
print("HYPOTHESIS 1: Little-endian 16-bit values (7 values per sample)")
print("-"*80)

for i, sample in enumerate(samples):
    print(f"\nSample {i+1}:")
    values = []
    for j in range(0, 14, 2):
        val = struct.unpack('<H', sample[j:j+2])[0]  # unsigned 16-bit LE
        values.append(val)
    print(f"  16-bit values: {values}")
    print(f"  Hex: {sample.hex(' ')}")

print("\n" + "-"*80)
print("HYPOTHESIS 2: Mixed format (trying to identify patterns)")
print("-"*80)

for i, sample in enumerate(samples):
    print(f"\nSample {i+1}:")
    print(f"  Raw hex: {sample.hex(' ')}")

    # Try various interpretations
    # Bytes 0-1: 16-bit value
    val_0_1 = struct.unpack('<H', sample[0:2])[0]
    print(f"  [0-1]  (u16 LE): {val_0_1:5d} (0x{val_0_1:04x})")

    # Bytes 2-3: 16-bit value
    val_2_3 = struct.unpack('<H', sample[2:4])[0]
    print(f"  [2-3]  (u16 LE): {val_2_3:5d} (0x{val_2_3:04x})")

    # Byte 4: single byte
    val_4 = sample[4]
    print(f"  [4]    (u8):     {val_4:5d} (0x{val_4:02x})")

    # Byte 5: single byte
    val_5 = sample[5]
    print(f"  [5]    (u8):     {val_5:5d} (0x{val_5:02x})")

    # Bytes 6-7: 16-bit value
    val_6_7 = struct.unpack('<H', sample[6:8])[0]
    print(f"  [6-7]  (u16 LE): {val_6_7:5d} (0x{val_6_7:04x})")

    # Bytes 8-9: 16-bit value
    val_8_9 = struct.unpack('<H', sample[8:10])[0]
    print(f"  [8-9]  (u16 LE): {val_8_9:5d} (0x{val_8_9:04x})")

    # Bytes 10-11: 16-bit value
    val_10_11 = struct.unpack('<H', sample[10:12])[0]
    print(f"  [10-11] (u16 LE): {val_10_11:5d} (0x{val_10_11:04x})")

    # Bytes 12-13: 16-bit value
    val_12_13 = struct.unpack('<H', sample[12:14])[0]
    print(f"  [12-13] (u16 LE): {val_12_13:5d} (0x{val_12_13:04x})")

print("\n" + "-"*80)
print("HYPOTHESIS 3: Looking for patterns in byte positions")
print("-"*80)

# Collect values by position
position_values = {i: [] for i in range(14)}
for sample in samples:
    for i, byte in enumerate(sample):
        position_values[i].append(byte)

for i in range(14):
    values = position_values[i]
    min_val = min(values)
    max_val = max(values)
    print(f"Byte {i:2d}: min={min_val:3d} (0x{min_val:02x})  max={max_val:3d} (0x{max_val:02x})  range={max_val-min_val:3d}  values: {[hex(v) for v in values]}")

print("\n" + "-"*80)
print("HYPOTHESIS 4: Could bytes 0-3 be a timestamp offset?")
print("-"*80)

for i, sample in enumerate(samples):
    # Try as 32-bit little-endian
    timestamp_offset = struct.unpack('<I', sample[0:4])[0]
    print(f"Sample {i+1}: offset={timestamp_offset:8d} (0x{timestamp_offset:08x})  remaining: {sample[4:].hex(' ')}")

print("\n" + "-"*80)
print("OBSERVATIONS:")
print("-"*80)
print("• Each 0x6a event is 14 bytes of binary data (not protobuf)")
print("• These appear to be individual minute samples")
print("• They need to be assembled together into arrays")
print("• Byte 4 often contains values like 0x85, 0x87, 0x8b, 0x8c, 0x8f (could be HR?)")
print("• Bytes 10-13 are often 0x00 or small values")
print("\nNext steps:")
print("1. Compare with decompiled Oura app to understand exact format")
print("2. Test different field interpretations")
print("3. Create assembler that collects all samples into arrays")
