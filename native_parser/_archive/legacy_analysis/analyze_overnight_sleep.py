#!/usr/bin/env python3
"""
Analyze overnight sleep data from Oura Ring export.
Parses 0x6a SLEEP_PERIOD_INFO_2 events and other related events.
"""
import struct
import sys
from collections import defaultdict
from datetime import datetime, timedelta

def parse_sleep_period_info_2(data):
    """Parse 0x6a SLEEP_PERIOD_INFO_2 (16 bytes)

    Format based on SleepPeriodInfoParser.kt:
    [0]: tag = 0x6A
    [1]: length = 0x0E (14)
    [2-5]: timestamp (deciseconds, LE uint32)
    [6]: avgHr raw (* 0.5 = BPM)
    [7]: hrTrend raw (* 0.0625)
    [8]: MZCI (upper nibble) + DZCI (lower nibble)?
    [9]: breath raw (* 0.5)
    [10-11]: motion data
    [12]: sleepState (0=awake, 1=light, 2=deep, 3=REM)
    [13]: CV (coefficient of variation)?
    [14-15]: reserved
    """
    if len(data) < 16:
        return None

    tag = data[0]
    length = data[1]
    timestamp_ds = struct.unpack('<I', data[2:6])[0]

    avg_hr_raw = data[6]
    hr_trend_raw = data[7] if len(data) > 7 else 0
    byte8 = data[8] if len(data) > 8 else 0
    breath_raw = data[9] if len(data) > 9 else 0
    motion_lo = data[10] if len(data) > 10 else 0
    motion_hi = data[11] if len(data) > 11 else 0
    sleep_state = data[12] if len(data) > 12 else 0
    cv_raw = data[13] if len(data) > 13 else 0

    # Apply scaling factors from SleepPeriodInfoParser.kt
    avg_hr_bpm = avg_hr_raw * 0.5
    hr_trend = (hr_trend_raw - 128) * 0.0625 if hr_trend_raw else 0
    breath_rpm = breath_raw * 0.5
    motion = (motion_hi << 8) | motion_lo

    # Sleep state interpretation
    sleep_state_name = {
        0: "awake",
        1: "light",
        2: "deep",
        3: "REM"
    }.get(sleep_state, f"unknown({sleep_state})")

    return {
        'tag': tag,
        'length': length,
        'timestamp_ds': timestamp_ds,
        'avg_hr_bpm': avg_hr_bpm,
        'hr_trend': hr_trend,
        'byte8': byte8,
        'breath_rpm': breath_rpm,
        'motion': motion,
        'sleep_state': sleep_state,
        'sleep_state_name': sleep_state_name,
        'cv': cv_raw
    }

def deciseconds_to_time(ds, base_time=None):
    """Convert deciseconds to human-readable time."""
    seconds = ds / 10.0
    if base_time:
        return base_time + timedelta(seconds=seconds)
    return timedelta(seconds=seconds)

def analyze_events_file(filepath):
    """Parse and analyze exported events file."""
    print("=" * 70)
    print("OVERNIGHT SLEEP DATA ANALYSIS")
    print("=" * 70)

    event_counts = defaultdict(int)
    sleep_events = []
    temp_events = []
    hr_events = []
    motion_events = []

    with open(filepath, 'r') as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith('#'):
                continue

            parts = line.split('|')
            if len(parts) < 4:
                continue

            idx = int(parts[0])
            tag_hex = parts[1]
            tag_name = parts[2]
            hex_data = parts[3]

            data = bytes.fromhex(hex_data)
            tag = data[0] if data else 0

            event_counts[tag_name] += 1

            # Parse specific events
            if tag == 0x6a:  # SLEEP_PERIOD_INFO_2
                parsed = parse_sleep_period_info_2(data)
                if parsed:
                    sleep_events.append((idx, parsed))
            elif tag == 0x46:  # TEMP_EVENT
                if len(data) >= 12:
                    ts = struct.unpack('<I', data[2:6])[0]
                    t1 = struct.unpack('<H', data[6:8])[0] / 100.0
                    t2 = struct.unpack('<H', data[8:10])[0] / 100.0
                    t3 = struct.unpack('<H', data[10:12])[0] / 100.0
                    temp_events.append((idx, ts, t1, t2, t3))
            elif tag == 0x47:  # MOTION_EVENT
                if len(data) >= 10:
                    ts = struct.unpack('<I', data[2:6])[0]
                    motion_events.append((idx, ts, data[6:].hex()))

    # Event type summary
    print("\nEVENT TYPE SUMMARY")
    print("-" * 50)
    for name, count in sorted(event_counts.items(), key=lambda x: -x[1]):
        print(f"  {name}: {count}")
    print(f"\nTotal events: {sum(event_counts.values())}")

    # Sleep analysis
    if sleep_events:
        print("\n" + "=" * 70)
        print("SLEEP ANALYSIS (0x6a SLEEP_PERIOD_INFO_2)")
        print("=" * 70)
        print(f"\nTotal sleep samples: {len(sleep_events)}")

        # Remove duplicates based on timestamp
        unique_sleep = {}
        for idx, evt in sleep_events:
            ts = evt['timestamp_ds']
            if ts not in unique_sleep:
                unique_sleep[ts] = (idx, evt)

        sleep_events = sorted(unique_sleep.values(), key=lambda x: x[1]['timestamp_ds'])
        print(f"Unique samples: {len(sleep_events)}")

        # Time range
        first_ts = sleep_events[0][1]['timestamp_ds']
        last_ts = sleep_events[-1][1]['timestamp_ds']
        duration_sec = (last_ts - first_ts) / 10.0
        duration_hr = duration_sec / 3600.0
        print(f"\nDuration: {duration_hr:.2f} hours ({duration_sec/60:.1f} minutes)")

        # Heart rate statistics
        hr_values = [e[1]['avg_hr_bpm'] for e in sleep_events if e[1]['avg_hr_bpm'] > 0]
        if hr_values:
            print(f"\nHeart Rate:")
            print(f"  Min: {min(hr_values):.1f} BPM")
            print(f"  Max: {max(hr_values):.1f} BPM")
            print(f"  Avg: {sum(hr_values)/len(hr_values):.1f} BPM")

        # Breathing rate statistics
        breath_values = [e[1]['breath_rpm'] for e in sleep_events if e[1]['breath_rpm'] > 0]
        if breath_values:
            print(f"\nBreathing Rate:")
            print(f"  Min: {min(breath_values):.1f} RPM")
            print(f"  Max: {max(breath_values):.1f} RPM")
            print(f"  Avg: {sum(breath_values)/len(breath_values):.1f} RPM")

        # Sleep state distribution
        state_counts = defaultdict(int)
        state_samples = defaultdict(list)
        for idx, evt in sleep_events:
            state = evt['sleep_state_name']
            state_counts[state] += 1
            state_samples[state].append(evt)

        print(f"\nSleep State Distribution:")
        total = sum(state_counts.values())
        for state in ['awake', 'light', 'deep', 'REM']:
            if state in state_counts:
                count = state_counts[state]
                pct = 100.0 * count / total
                # Each sample is ~5 min, estimate duration
                duration_min = count * 5
                print(f"  {state.upper():8s}: {count:4d} samples ({pct:5.1f}%) ~{duration_min} min")

        # Sample some actual data points
        print(f"\nSample Sleep Records (first 10):")
        print("-" * 70)
        print(f"{'Idx':>5} {'TS(ds)':>10} {'HR':>6} {'Breath':>6} {'Motion':>6} {'State':>8}")
        print("-" * 70)
        for idx, evt in sleep_events[:10]:
            print(f"{idx:>5} {evt['timestamp_ds']:>10} {evt['avg_hr_bpm']:>6.1f} "
                  f"{evt['breath_rpm']:>6.1f} {evt['motion']:>6} {evt['sleep_state_name']:>8}")

        # Show sleep transitions
        print(f"\nSleep State Timeline (transitions):")
        print("-" * 50)
        prev_state = None
        transitions = []
        for idx, evt in sleep_events:
            state = evt['sleep_state_name']
            if state != prev_state:
                transitions.append((evt['timestamp_ds'], state, evt['avg_hr_bpm']))
                prev_state = state

        # Show first 20 transitions
        for i, (ts, state, hr) in enumerate(transitions[:20]):
            relative_min = (ts - first_ts) / 10.0 / 60.0
            print(f"  +{relative_min:6.1f} min: {state.upper():8s} (HR: {hr:.1f})")

        if len(transitions) > 20:
            print(f"  ... ({len(transitions) - 20} more transitions)")

    # Temperature analysis
    if temp_events:
        print("\n" + "=" * 70)
        print("TEMPERATURE ANALYSIS (0x46)")
        print("=" * 70)

        # Remove duplicates
        unique_temp = {}
        for idx, ts, t1, t2, t3 in temp_events:
            if ts not in unique_temp:
                unique_temp[ts] = (idx, ts, t1, t2, t3)

        temp_events = sorted(unique_temp.values(), key=lambda x: x[1])
        print(f"\nUnique temperature samples: {len(temp_events)}")

        # Statistics for each sensor
        t1_vals = [t[2] for t in temp_events]
        t2_vals = [t[3] for t in temp_events]
        t3_vals = [t[4] for t in temp_events]

        print(f"\nSensor 1 (body):    Min {min(t1_vals):.2f}°C, Max {max(t1_vals):.2f}°C, Avg {sum(t1_vals)/len(t1_vals):.2f}°C")
        print(f"Sensor 2 (ref):     Min {min(t2_vals):.2f}°C, Max {max(t2_vals):.2f}°C, Avg {sum(t2_vals)/len(t2_vals):.2f}°C")
        print(f"Sensor 3 (ambient): Min {min(t3_vals):.2f}°C, Max {max(t3_vals):.2f}°C, Avg {sum(t3_vals)/len(t3_vals):.2f}°C")

    print("\n" + "=" * 70)
    print("ANALYSIS COMPLETE")
    print("=" * 70)

def main():
    filepath = '/home/witcher/projects/oura_ring_reverse/analysis_scripts/ring_events_20260112_092318.txt'
    if len(sys.argv) > 1:
        filepath = sys.argv[1]

    analyze_events_file(filepath)

if __name__ == '__main__':
    main()
