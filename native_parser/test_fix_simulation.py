#!/usr/bin/env python3
"""
Simulate what the fixed GetEvent protocol would do.

This script simulates the ring's behavior based on our understanding:
- Ring has ~50K events in a circular buffer
- GetEvent(timestamp) returns events with ts >= timestamp
- Each GetEvent call returns max ~50K events

Shows: current broken approach vs fixed approach.
"""

import struct
from pathlib import Path
from collections import defaultdict

def extract_event_timestamp(event_hex: str) -> int | None:
    """Extract timestamp from event hex data."""
    try:
        event = bytes.fromhex(event_hex)
        if len(event) >= 6:
            return struct.unpack('<I', event[2:6])[0]
    except:
        pass
    return None

def load_unique_events(filepath: Path) -> list:
    """Load unique events (deduped) from file."""
    seen = set()
    events = []

    with open(filepath, 'r') as f:
        for line in f:
            if line.startswith('#') or not line.strip():
                continue

            parts = line.strip().split('|')
            if len(parts) < 4:
                continue

            hex_data = parts[3]
            if hex_data in seen:
                continue

            seen.add(hex_data)
            ts = extract_event_timestamp(hex_data)
            if ts:
                events.append((ts, hex_data))

    # Sort by timestamp
    events.sort(key=lambda x: x[0])
    return events

def simulate_ring_buffer(events: list, buffer_size: int = 50000):
    """Simulate ring's circular buffer behavior."""
    # Ring only keeps the latest buffer_size events
    if len(events) > buffer_size:
        return events[-buffer_size:]
    return events

def simulate_getevent(buffer: list, timestamp: int, max_return: int = 50000) -> list:
    """Simulate GetEvent(timestamp) behavior."""
    # Return events with ts >= timestamp, up to max_return
    matching = [(ts, hex) for ts, hex in buffer if ts >= timestamp]
    return matching[:max_return]

def simulate_broken_approach(buffer: list):
    """Simulate our current broken approach."""
    print("=== BROKEN APPROACH (increment seq by batch size) ===\n")

    all_received = []
    seq = 0
    batch_num = 0

    while batch_num < 5:  # Simulate 5 batches
        batch_num += 1
        events = simulate_getevent(buffer, seq)

        if not events:
            print(f"Batch {batch_num}: GetEvent({seq}) -> 0 events, done")
            break

        min_ts = min(e[0] for e in events)
        max_ts = max(e[0] for e in events)

        new_events = [e for e in events if e[1] not in {x[1] for x in all_received}]
        all_received.extend(new_events)

        print(f"Batch {batch_num}: GetEvent({seq})")
        print(f"  Received: {len(events)} events (ts {min_ts:,} to {max_ts:,})")
        print(f"  NEW events: {len(new_events)}")
        print(f"  Total unique so far: {len(all_received)}")
        print()

        # BROKEN: increment by batch size
        seq += len(events)

    print(f"TOTAL: {len(all_received)} unique events after {batch_num} batches")
    return all_received

def simulate_fixed_approach(buffer: list):
    """Simulate the fixed approach using timestamps."""
    print("\n=== FIXED APPROACH (use max_ts from events) ===\n")

    all_received = []
    timestamp = 0
    batch_num = 0

    while batch_num < 5:  # Simulate 5 batches
        batch_num += 1
        events = simulate_getevent(buffer, timestamp)

        if not events:
            print(f"Batch {batch_num}: GetEvent({timestamp}) -> 0 events, done")
            break

        min_ts = min(e[0] for e in events)
        max_ts = max(e[0] for e in events)

        new_events = [e for e in events if e[1] not in {x[1] for x in all_received}]
        all_received.extend(new_events)

        print(f"Batch {batch_num}: GetEvent({timestamp})")
        print(f"  Received: {len(events)} events (ts {min_ts:,} to {max_ts:,})")
        print(f"  NEW events: {len(new_events)}")
        print(f"  Total unique so far: {len(all_received)}")
        print()

        # FIXED: use max timestamp from received events
        timestamp = max_ts + 1

    print(f"TOTAL: {len(all_received)} unique events after {batch_num} batches")
    return all_received

def main():
    data_dir = Path(__file__).parent / "input_data"
    events_file = data_dir / "ring_events.txt"

    print("Loading unique events from file...")
    all_events = load_unique_events(events_file)
    print(f"Loaded {len(all_events)} unique events")
    print(f"Timestamp range: {all_events[0][0]:,} to {all_events[-1][0]:,}")
    print()

    # Simulate ring's buffer (latest 50K events)
    buffer = simulate_ring_buffer(all_events)
    print(f"Ring buffer: {len(buffer)} events")
    print(f"Buffer timestamp range: {buffer[0][0]:,} to {buffer[-1][0]:,}")
    print()

    # Test both approaches
    broken_result = simulate_broken_approach(buffer)
    fixed_result = simulate_fixed_approach(buffer)

    print("\n" + "="*60)
    print("COMPARISON")
    print("="*60)
    print(f"Broken approach: {len(broken_result)} unique events, ~5 batches")
    print(f"Fixed approach:  {len(fixed_result)} unique events, ~{1 if len(fixed_result) <= 50000 else 2} batch(es)")
    print()

    if len(fixed_result) >= len(broken_result):
        print("FIXED approach gets same or more unique events with FEWER batches!")
        print("This would eliminate the 16x duplication problem.")
    else:
        print("Results differ - investigate further")

if __name__ == "__main__":
    main()
