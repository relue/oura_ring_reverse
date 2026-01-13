#!/usr/bin/env python3
"""
Verify Oura Ring event parsing against documented formats.
"""
import struct
import sys

def parse_temp_event(data):
    """Parse 0x46 TEMP_EVENT (12 bytes total)"""
    if len(data) < 12:
        return None
    tag = data[0]
    length = data[1]
    timestamp = struct.unpack('<I', data[2:6])[0]  # deciseconds
    temp1_raw = struct.unpack('<H', data[6:8])[0]
    temp2_raw = struct.unpack('<H', data[8:10])[0]
    temp3_raw = struct.unpack('<H', data[10:12])[0]

    # Scale: divide by 100 to get °C
    temp1 = temp1_raw / 100.0
    temp2 = temp2_raw / 100.0
    temp3 = temp3_raw / 100.0

    return {
        'tag': tag,
        'timestamp_ds': timestamp,
        'temp1_C': temp1,
        'temp2_C': temp2,
        'temp3_C': temp3
    }

def parse_motion_event(data):
    """Parse 0x47 MOTION_EVENT"""
    if len(data) < 10:
        return None
    tag = data[0]
    length = data[1]
    timestamp = struct.unpack('<I', data[2:6])[0]  # deciseconds

    # Remaining bytes contain motion data
    return {
        'tag': tag,
        'length': length,
        'timestamp_ds': timestamp,
        'motion_data': data[6:].hex()
    }

def parse_activity_info(data):
    """Parse 0x50 ACTIVITY_INFO"""
    if len(data) < 8:
        return None
    tag = data[0]
    length = data[1]
    timestamp = struct.unpack('<I', data[2:6])[0]  # deciseconds
    step_count = data[6] if len(data) > 6 else 0

    return {
        'tag': tag,
        'length': length,
        'timestamp_ds': timestamp,
        'step_count': step_count,
        'remaining': data[7:].hex() if len(data) > 7 else ''
    }

def parse_wear_event(data):
    """Parse 0x53 WEAR_EVENT"""
    if len(data) < 8:
        return None
    tag = data[0]
    length = data[1]
    timestamp = struct.unpack('<I', data[2:6])[0]  # deciseconds
    state = data[6] if len(data) > 6 else 0

    return {
        'tag': tag,
        'length': length,
        'timestamp_ds': timestamp,
        'state': state,
        'text': data[7:].decode('utf-8', errors='ignore') if len(data) > 7 else ''
    }

def parse_state_change(data):
    """Parse 0x45 STATE_CHANGE_IND"""
    if len(data) < 7:
        return None
    tag = data[0]
    length = data[1]
    timestamp = struct.unpack('<I', data[2:6])[0]  # deciseconds
    state_type = data[6] if len(data) > 6 else 0
    text = data[7:].decode('utf-8', errors='ignore') if len(data) > 7 else ''

    return {
        'tag': tag,
        'length': length,
        'timestamp_ds': timestamp,
        'state_type': state_type,
        'text': text
    }

def parse_green_ibi_quality(data):
    """Parse 0x80 GREEN_IBI_QUALITY_EVENT"""
    if len(data) < 8:
        return None
    tag = data[0]
    length = data[1]
    timestamp = struct.unpack('<I', data[2:6])[0]

    # Remaining bytes are IBI quality pairs (HR, quality)
    ibi_data = []
    for i in range(6, len(data), 2):
        if i + 1 < len(data):
            hr = data[i]
            quality = data[i+1]
            ibi_data.append((hr, quality))

    return {
        'tag': tag,
        'length': length,
        'timestamp_ds': timestamp,
        'ibi_pairs': ibi_data,
        'avg_hr': sum(p[0] for p in ibi_data) / len(ibi_data) if ibi_data else 0
    }

def parse_meas_quality(data):
    """Parse 0x6d MEAS_QUALITY_EVENT"""
    if len(data) < 8:
        return None
    tag = data[0]
    length = data[1]
    timestamp = struct.unpack('<I', data[2:6])[0]
    quality_type = data[6] if len(data) > 6 else 0

    # Parse 4 quality values (signed 16-bit)
    quality_values = []
    for i in range(7, min(len(data), 7 + 8), 2):
        if i + 1 < len(data):
            val = struct.unpack('<h', data[i:i+2])[0]
            quality_values.append(val)

    return {
        'tag': tag,
        'timestamp_ds': timestamp,
        'quality_type': quality_type,
        'quality_values': quality_values
    }

def parse_ring_start(data):
    """Parse 0x41 RING_START_IND"""
    if len(data) < 6:
        return None
    tag = data[0]
    length = data[1]
    timestamp = struct.unpack('<I', data[2:6])[0]

    # Additional fields
    info = data[6:] if len(data) > 6 else b''

    return {
        'tag': tag,
        'timestamp_ds': timestamp,
        'info_hex': info.hex()
    }

def parse_ble_connection(data):
    """Parse 0x5b BLE_CONNECTION_IND"""
    if len(data) < 7:
        return None
    tag = data[0]
    length = data[1]
    timestamp = struct.unpack('<I', data[2:6])[0]
    conn_type = data[6] if len(data) > 6 else 0

    return {
        'tag': tag,
        'timestamp_ds': timestamp,
        'conn_type': conn_type,
        'data_hex': data[7:].hex() if len(data) > 7 else ''
    }

def parse_feature_session(data):
    """Parse 0x6c FEATURE_SESSION"""
    if len(data) < 8:
        return None
    tag = data[0]
    length = data[1]
    timestamp = struct.unpack('<I', data[2:6])[0]
    session_type = data[6] if len(data) > 6 else 0
    session_state = data[7] if len(data) > 7 else 0

    return {
        'tag': tag,
        'timestamp_ds': timestamp,
        'session_type': session_type,
        'session_state': session_state,
        'remaining': data[8:].hex() if len(data) > 8 else ''
    }

def parse_scan_start(data):
    """Parse 0x82 SCAN_START"""
    if len(data) < 6:
        return None
    tag = data[0]
    length = data[1]
    timestamp = struct.unpack('<I', data[2:6])[0]

    return {
        'tag': tag,
        'timestamp_ds': timestamp,
        'data_hex': data[6:].hex() if len(data) > 6 else ''
    }

def parse_scan_end(data):
    """Parse 0x83 SCAN_END"""
    if len(data) < 6:
        return None
    tag = data[0]
    length = data[1]
    timestamp = struct.unpack('<I', data[2:6])[0]

    return {
        'tag': tag,
        'timestamp_ds': timestamp,
        'data_hex': data[6:].hex() if len(data) > 6 else ''
    }

def parse_temp_period(data):
    """Parse 0x69 TEMP_PERIOD"""
    if len(data) < 8:
        return None
    tag = data[0]
    length = data[1]
    timestamp = struct.unpack('<I', data[2:6])[0]
    avg_temp = struct.unpack('<H', data[6:8])[0] / 100.0 if len(data) >= 8 else 0

    return {
        'tag': tag,
        'timestamp_ds': timestamp,
        'avg_temp_C': avg_temp
    }

def parse_sleep_period_info_2(data):
    """Parse 0x6a SLEEP_PERIOD_INFO_2 (16 bytes)"""
    if len(data) < 16:
        return None
    tag = data[0]
    length = data[1]
    timestamp = struct.unpack('<I', data[2:6])[0]

    avg_hr = data[6] * 0.5  # BPM
    hr_trend = data[7] * 0.0625
    mzci = data[8] * 0.0625
    dzci = data[9] * 0.0625
    motion_lo = data[10]
    motion_hi = data[11]
    motion_count = data[12]  # 0-120 seconds
    sleep_state = data[13]  # 0=awake, 1=light, 2=deep
    cv = struct.unpack('<H', data[14:16])[0] / 65536.0

    state_name = {0: 'awake', 1: 'light', 2: 'deep'}.get(sleep_state, f'unknown({sleep_state})')

    return {
        'tag': tag,
        'timestamp_ds': timestamp,
        'avg_hr': avg_hr,
        'hr_trend': hr_trend,
        'mzci': mzci,
        'dzci': dzci,
        'motion_count': motion_count,
        'sleep_state': sleep_state,
        'sleep_state_name': state_name,
        'cv': cv
    }

def parse_sleep_acm_period(data):
    """Parse 0x72 SLEEP_ACM_PERIOD (18 bytes)"""
    if len(data) < 18:
        return None
    tag = data[0]
    length = data[1]
    timestamp = struct.unpack('<I', data[2:6])[0]

    # Activity metrics
    metrics = []
    for i in range(6, min(len(data), 18), 2):
        if i + 1 < len(data):
            val = struct.unpack('<H', data[i:i+2])[0]
            metrics.append(val)

    return {
        'tag': tag,
        'timestamp_ds': timestamp,
        'metrics': metrics
    }

def parse_sleep_temp_event(data):
    """Parse 0x75 SLEEP_TEMP_EVENT (20 bytes, 7 sensors)"""
    if len(data) < 20:
        return None
    tag = data[0]
    length = data[1]
    timestamp = struct.unpack('<I', data[2:6])[0]

    # 7 temperature sensors
    temps = []
    for i in range(6, min(len(data), 20), 2):
        if i + 1 < len(data):
            temp_raw = struct.unpack('<H', data[i:i+2])[0]
            temps.append(temp_raw / 100.0)

    return {
        'tag': tag,
        'timestamp_ds': timestamp,
        'temps': temps,
        'avg_temp': sum(temps) / len(temps) if temps else 0
    }

def parse_hrv_event(data):
    """Parse 0x5d HRV_EVENT (18 bytes)"""
    if len(data) < 18:
        return None
    tag = data[0]
    length = data[1]
    timestamp = struct.unpack('<I', data[2:6])[0]

    # HRV metrics
    metrics = []
    for i in range(6, min(len(data), 18), 2):
        if i + 1 < len(data):
            val = struct.unpack('<H', data[i:i+2])[0]
            metrics.append(val)

    return {
        'tag': tag,
        'timestamp_ds': timestamp,
        'metrics': metrics
    }

def main():
    # Use latest export file
    import os
    import glob
    events_files = glob.glob('/home/witcher/projects/oura_ring_reverse/analysis_scripts/ring_events_*.txt')
    events_file = max(events_files, key=os.path.getmtime) if events_files else '/home/witcher/projects/oura_ring_reverse/analysis_scripts/ring_events_20260111_235116.txt'
    print(f"Analyzing: {events_file}")

    print("=" * 70)
    print("OURA RING EVENT VERIFICATION")
    print("=" * 70)

    with open(events_file, 'r') as f:
        lines = [l.strip() for l in f if l.strip() and not l.startswith('#')]

    event_counts = {}
    verified = {}

    for line in lines:
        parts = line.split('|')
        if len(parts) < 4:
            continue

        idx = int(parts[0])
        tag_hex = parts[1]
        tag_name = parts[2]
        hex_data = parts[3]

        data = bytes.fromhex(hex_data)
        tag = data[0]

        event_counts[tag_name] = event_counts.get(tag_name, 0) + 1

        # Parse specific event types
        if tag == 0x46:  # TEMP_EVENT
            parsed = parse_temp_event(data)
            if parsed and tag_name not in verified:
                verified[tag_name] = parsed
                print(f"\n[0x46] TEMP_EVENT (idx={idx}):")
                print(f"  Timestamp: {parsed['timestamp_ds']} deciseconds")
                print(f"  Temp1: {parsed['temp1_C']:.2f}°C")
                print(f"  Temp2: {parsed['temp2_C']:.2f}°C")
                print(f"  Temp3: {parsed['temp3_C']:.2f}°C")

        elif tag == 0x47:  # MOTION_EVENT
            parsed = parse_motion_event(data)
            if parsed and tag_name not in verified:
                verified[tag_name] = parsed
                print(f"\n[0x47] MOTION_EVENT (idx={idx}):")
                print(f"  Timestamp: {parsed['timestamp_ds']} deciseconds")
                print(f"  Motion data: {parsed['motion_data']}")

        elif tag == 0x50:  # ACTIVITY_INFO
            parsed = parse_activity_info(data)
            if parsed and tag_name not in verified:
                verified[tag_name] = parsed
                print(f"\n[0x50] ACTIVITY_INFO (idx={idx}):")
                print(f"  Timestamp: {parsed['timestamp_ds']} deciseconds")
                print(f"  Steps: {parsed['step_count']}")
                print(f"  Remaining: {parsed['remaining']}")

        elif tag == 0x53:  # WEAR_EVENT
            parsed = parse_wear_event(data)
            if parsed and tag_name not in verified:
                verified[tag_name] = parsed
                print(f"\n[0x53] WEAR_EVENT (idx={idx}):")
                print(f"  Timestamp: {parsed['timestamp_ds']} deciseconds")
                print(f"  State: {parsed['state']}")
                print(f"  Text: '{parsed['text']}'")

        elif tag == 0x45:  # STATE_CHANGE_IND
            parsed = parse_state_change(data)
            if parsed and tag_name not in verified:
                verified[tag_name] = parsed
                print(f"\n[0x45] STATE_CHANGE_IND (idx={idx}):")
                print(f"  Timestamp: {parsed['timestamp_ds']} deciseconds")
                print(f"  State type: {parsed['state_type']}")
                print(f"  Text: '{parsed['text']}'")

        elif tag == 0x80:  # GREEN_IBI_QUALITY_EVENT
            parsed = parse_green_ibi_quality(data)
            if parsed and tag_name not in verified:
                verified[tag_name] = parsed
                print(f"\n[0x80] GREEN_IBI_QUALITY_EVENT (idx={idx}):")
                print(f"  Timestamp: {parsed['timestamp_ds']} deciseconds")
                print(f"  IBI pairs (HR, quality): {parsed['ibi_pairs'][:3]}...")
                print(f"  Avg HR estimate: {parsed['avg_hr']:.1f} BPM")

        elif tag == 0x6d:  # MEAS_QUALITY_EVENT
            parsed = parse_meas_quality(data)
            if parsed and tag_name not in verified:
                verified[tag_name] = parsed
                print(f"\n[0x6d] MEAS_QUALITY_EVENT (idx={idx}):")
                print(f"  Timestamp: {parsed['timestamp_ds']} deciseconds")
                print(f"  Quality type: {parsed['quality_type']}")
                print(f"  Quality values: {parsed['quality_values']}")

        elif tag == 0x41:  # RING_START_IND
            parsed = parse_ring_start(data)
            if parsed and tag_name not in verified:
                verified[tag_name] = parsed
                print(f"\n[0x41] RING_START_IND (idx={idx}):")
                print(f"  Timestamp: {parsed['timestamp_ds']} deciseconds")
                print(f"  Info: {parsed['info_hex']}")

        elif tag == 0x5b:  # BLE_CONNECTION_IND
            parsed = parse_ble_connection(data)
            if parsed and tag_name not in verified:
                verified[tag_name] = parsed
                print(f"\n[0x5b] BLE_CONNECTION_IND (idx={idx}):")
                print(f"  Timestamp: {parsed['timestamp_ds']} deciseconds")
                print(f"  Connection type: {parsed['conn_type']}")
                print(f"  Data: {parsed['data_hex']}")

        elif tag == 0x6c:  # FEATURE_SESSION
            parsed = parse_feature_session(data)
            if parsed and tag_name not in verified:
                verified[tag_name] = parsed
                print(f"\n[0x6c] FEATURE_SESSION (idx={idx}):")
                print(f"  Timestamp: {parsed['timestamp_ds']} deciseconds")
                print(f"  Session type: {parsed['session_type']}")
                print(f"  Session state: {parsed['session_state']}")

        elif tag == 0x82:  # SCAN_START
            parsed = parse_scan_start(data)
            if parsed and tag_name not in verified:
                verified[tag_name] = parsed
                print(f"\n[0x82] SCAN_START (idx={idx}):")
                print(f"  Timestamp: {parsed['timestamp_ds']} deciseconds")
                print(f"  Data: {parsed['data_hex']}")

        elif tag == 0x83:  # SCAN_END
            parsed = parse_scan_end(data)
            if parsed and tag_name not in verified:
                verified[tag_name] = parsed
                print(f"\n[0x83] SCAN_END (idx={idx}):")
                print(f"  Timestamp: {parsed['timestamp_ds']} deciseconds")
                print(f"  Data: {parsed['data_hex']}")

        elif tag == 0x69:  # TEMP_PERIOD
            parsed = parse_temp_period(data)
            if parsed and tag_name not in verified:
                verified[tag_name] = parsed
                print(f"\n[0x69] TEMP_PERIOD (idx={idx}):")
                print(f"  Timestamp: {parsed['timestamp_ds']} deciseconds")
                print(f"  Avg temp: {parsed['avg_temp_C']:.2f}°C")

        elif tag == 0x6a:  # SLEEP_PERIOD_INFO_2
            parsed = parse_sleep_period_info_2(data)
            if parsed and tag_name not in verified:
                verified[tag_name] = parsed
                print(f"\n[0x6a] SLEEP_PERIOD_INFO_2 (idx={idx}):")
                print(f"  Timestamp: {parsed['timestamp_ds']} deciseconds")
                print(f"  Avg HR: {parsed['avg_hr']:.1f} BPM")
                print(f"  Sleep State: {parsed['sleep_state']} ({parsed['sleep_state_name']})")
                print(f"  Motion: {parsed['motion_count']} sec")

        elif tag == 0x72:  # SLEEP_ACM_PERIOD
            parsed = parse_sleep_acm_period(data)
            if parsed and tag_name not in verified:
                verified[tag_name] = parsed
                print(f"\n[0x72] SLEEP_ACM_PERIOD (idx={idx}):")
                print(f"  Timestamp: {parsed['timestamp_ds']} deciseconds")
                print(f"  Metrics: {parsed['metrics'][:4]}...")

        elif tag == 0x75:  # SLEEP_TEMP_EVENT
            parsed = parse_sleep_temp_event(data)
            if parsed and tag_name not in verified:
                verified[tag_name] = parsed
                print(f"\n[0x75] SLEEP_TEMP_EVENT (idx={idx}):")
                print(f"  Timestamp: {parsed['timestamp_ds']} deciseconds")
                print(f"  Temps: {[f'{t:.2f}°C' for t in parsed['temps'][:3]]}...")
                print(f"  Avg: {parsed['avg_temp']:.2f}°C")

        elif tag == 0x5d:  # HRV_EVENT
            parsed = parse_hrv_event(data)
            if parsed and tag_name not in verified:
                verified[tag_name] = parsed
                print(f"\n[0x5d] HRV_EVENT (idx={idx}):")
                print(f"  Timestamp: {parsed['timestamp_ds']} deciseconds")
                print(f"  Metrics: {parsed['metrics']}")

    print("\n" + "=" * 70)
    print("EVENT SUMMARY")
    print("=" * 70)
    for name, count in sorted(event_counts.items()):
        status = "✓ VERIFIED" if name in verified else "  (not parsed)"
        print(f"  {name}: {count} events {status}")

    print("\n" + "=" * 70)
    print(f"Total event types: {len(event_counts)}")
    print(f"Verified: {len(verified)}")
    print("=" * 70)

if __name__ == '__main__':
    main()
