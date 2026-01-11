#!/usr/bin/env python3
"""
Decode SLEEP_PERIOD_INFO_2 (0x6a) protobuf events from Oura Ring
"""

import sys
from datetime import datetime

def decode_varint(data, offset):
    """Decode a protobuf varint"""
    result = 0
    shift = 0
    while True:
        if offset >= len(data):
            return None, offset
        byte = data[offset]
        offset += 1
        result |= (byte & 0x7F) << shift
        if (byte & 0x80) == 0:
            break
        shift += 7
    return result, offset

def decode_fixed32(data, offset):
    """Decode a 32-bit fixed value (little-endian)"""
    if offset + 4 > len(data):
        return None, offset
    value = int.from_bytes(data[offset:offset+4], 'little')
    return value, offset + 4

def decode_fixed64(data, offset):
    """Decode a 64-bit fixed value (little-endian)"""
    if offset + 8 > len(data):
        return None, offset
    value = int.from_bytes(data[offset:offset+8], 'little')
    return value, offset + 8

def bytes_to_float(bytes_val):
    """Convert 4 bytes to float"""
    import struct
    return struct.unpack('<f', bytes_val)[0]

def decode_sleep_period_info(data):
    """Decode SleepPeriodInfo protobuf message"""
    result = {
        'timestamp': [],
        'average_hr': [],
        'hr_trend': [],
        'mzci': [],
        'dzci': [],
        'breath': [],
        'breath_v': [],
        'motion_count': [],
        'sleep_state': [],
        'cv': []
    }

    offset = 0
    while offset < len(data):
        # Read field header (field number + wire type)
        tag, offset = decode_varint(data, offset)
        if tag is None:
            break

        field_number = tag >> 3
        wire_type = tag & 0x07

        # Wire types: 0=varint, 1=64-bit, 2=length-delimited, 5=32-bit

        if field_number == 1:  # timestamp (repeated int64)
            if wire_type == 2:  # Packed repeated
                length, offset = decode_varint(data, offset)
                end = offset + length
                while offset < end:
                    value, offset = decode_fixed64(data, offset)
                    if value is not None:
                        result['timestamp'].append(value)
            elif wire_type == 1:  # 64-bit
                value, offset = decode_fixed64(data, offset)
                if value is not None:
                    result['timestamp'].append(value)

        elif field_number == 2:  # average_hr (repeated float)
            if wire_type == 2:  # Packed repeated
                length, offset = decode_varint(data, offset)
                end = offset + length
                while offset < end:
                    value, offset = decode_fixed32(data, offset)
                    if value is not None:
                        result['average_hr'].append(bytes_to_float(value.to_bytes(4, 'little')))
            elif wire_type == 5:  # 32-bit
                value, offset = decode_fixed32(data, offset)
                if value is not None:
                    result['average_hr'].append(bytes_to_float(value.to_bytes(4, 'little')))

        elif field_number == 3:  # hr_trend (repeated float)
            if wire_type == 2:
                length, offset = decode_varint(data, offset)
                end = offset + length
                while offset < end:
                    value, offset = decode_fixed32(data, offset)
                    if value is not None:
                        result['hr_trend'].append(bytes_to_float(value.to_bytes(4, 'little')))

        elif field_number == 4:  # mzci (repeated float)
            if wire_type == 2:
                length, offset = decode_varint(data, offset)
                end = offset + length
                while offset < end:
                    value, offset = decode_fixed32(data, offset)
                    if value is not None:
                        result['mzci'].append(bytes_to_float(value.to_bytes(4, 'little')))

        elif field_number == 5:  # dzci (repeated float)
            if wire_type == 2:
                length, offset = decode_varint(data, offset)
                end = offset + length
                while offset < end:
                    value, offset = decode_fixed32(data, offset)
                    if value is not None:
                        result['dzci'].append(bytes_to_float(value.to_bytes(4, 'little')))

        elif field_number == 6:  # breath (repeated float)
            if wire_type == 2:
                length, offset = decode_varint(data, offset)
                end = offset + length
                while offset < end:
                    value, offset = decode_fixed32(data, offset)
                    if value is not None:
                        result['breath'].append(bytes_to_float(value.to_bytes(4, 'little')))

        elif field_number == 7:  # breath_v (repeated float)
            if wire_type == 2:
                length, offset = decode_varint(data, offset)
                end = offset + length
                while offset < end:
                    value, offset = decode_fixed32(data, offset)
                    if value is not None:
                        result['breath_v'].append(bytes_to_float(value.to_bytes(4, 'little')))

        elif field_number == 8:  # motion_count (repeated int32)
            if wire_type == 2:
                length, offset = decode_varint(data, offset)
                end = offset + length
                while offset < end:
                    value, offset = decode_varint(data, offset)
                    if value is not None:
                        result['motion_count'].append(value)

        elif field_number == 9:  # sleep_state (repeated int32)
            if wire_type == 2:
                length, offset = decode_varint(data, offset)
                end = offset + length
                while offset < end:
                    value, offset = decode_varint(data, offset)
                    if value is not None:
                        result['sleep_state'].append(value)

        elif field_number == 10:  # cv (repeated float)
            if wire_type == 2:
                length, offset = decode_varint(data, offset)
                end = offset + length
                while offset < end:
                    value, offset = decode_fixed32(data, offset)
                    if value is not None:
                        result['cv'].append(bytes_to_float(value.to_bytes(4, 'little')))

        else:
            # Skip unknown field
            if wire_type == 0:  # Varint
                _, offset = decode_varint(data, offset)
            elif wire_type == 1:  # 64-bit
                offset += 8
            elif wire_type == 2:  # Length-delimited
                length, offset = decode_varint(data, offset)
                offset += length
            elif wire_type == 5:  # 32-bit
                offset += 4

    return result

def print_decoded_data(data_dict):
    """Pretty print decoded sleep period info"""
    num_samples = len(data_dict['timestamp'])

    print("\n" + "="*80)
    print("SLEEP_PERIOD_INFO_2 (0x6a) DECODED DATA")
    print("="*80)
    print(f"\nTotal samples: {num_samples}")
    print(f"Duration: ~{num_samples} minutes")

    if num_samples == 0:
        print("\nNo data found!")
        return

    # Print first timestamp
    if data_dict['timestamp']:
        first_ts = data_dict['timestamp'][0]
        last_ts = data_dict['timestamp'][-1]
        print(f"\nFirst sample: {datetime.fromtimestamp(first_ts/1000).strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"Last sample:  {datetime.fromtimestamp(last_ts/1000).strftime('%Y-%m-%d %H:%M:%S')}")

    # Print statistics for each metric
    print("\n" + "-"*80)
    print("METRIC SUMMARY")
    print("-"*80)

    for key, values in data_dict.items():
        if not values:
            continue

        if key == 'timestamp':
            continue

        avg = sum(values) / len(values)
        min_val = min(values)
        max_val = max(values)

        print(f"\n{key.upper().replace('_', ' ')}:")
        print(f"  Count: {len(values)}")
        print(f"  Range: {min_val:.2f} - {max_val:.2f}")
        print(f"  Average: {avg:.2f}")

    # Print first 5 samples in detail
    print("\n" + "-"*80)
    print("FIRST 5 SAMPLES (DETAILED)")
    print("-"*80)

    for i in range(min(5, num_samples)):
        print(f"\nSample {i+1}:")
        if i < len(data_dict['timestamp']):
            ts = data_dict['timestamp'][i]
            print(f"  Time: {datetime.fromtimestamp(ts/1000).strftime('%Y-%m-%d %H:%M:%S')}")
        if i < len(data_dict['average_hr']):
            print(f"  Heart Rate: {data_dict['average_hr'][i]:.1f} BPM")
        if i < len(data_dict['breath']):
            print(f"  Breathing Rate: {data_dict['breath'][i]:.1f} breaths/min")
        if i < len(data_dict['sleep_state']):
            state_names = {0: 'Awake', 1: 'Light', 2: 'Deep', 3: 'REM'}
            state = data_dict['sleep_state'][i]
            print(f"  Sleep State: {state} ({state_names.get(state, 'Unknown')})")
        if i < len(data_dict['motion_count']):
            print(f"  Motion Count: {data_dict['motion_count'][i]}")
        if i < len(data_dict['mzci']):
            print(f"  MZCI (HRV): {data_dict['mzci'][i]:.2f}")
        if i < len(data_dict['dzci']):
            print(f"  DZCI (HRV): {data_dict['dzci'][i]:.2f}")
        if i < len(data_dict['cv']):
            print(f"  PPG Quality (CV): {data_dict['cv'][i]:.4f}")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 decode_sleep_period_info.py <hex_string>")
        print("\nExample:")
        print("  python3 decode_sleep_period_info.py 0a0812f0d2a4e0e2...")
        sys.exit(1)

    hex_string = sys.argv[1].replace(" ", "").replace("0x", "")
    data = bytes.fromhex(hex_string)

    print(f"Input data: {len(data)} bytes")
    print(f"Hex: {data.hex()[:80]}{'...' if len(data) > 40 else ''}")

    decoded = decode_sleep_period_info(data)
    print_decoded_data(decoded)
