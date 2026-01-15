#!/usr/bin/env python3
"""
Test script to analyze GetEvent behavior and verify the timestamp hypothesis.

Theory: The GetEvent parameter at bytes 2-5 is a TIMESTAMP (ring_time), not a sequence number.
We're sending 0, 50000, 100000... which are all tiny timestamps, so the ring returns
its entire buffer each time.

This script will:
1. Analyze existing event data to find timestamp patterns
2. Show what timestamps we SHOULD be using for pagination
3. Test the theory by comparing timestamp ranges between batches
"""

import struct
from pathlib import Path
from collections import defaultdict

def extract_event_timestamp(event_hex: str) -> int | None:
    """Extract timestamp from event hex data (bytes 2-5, little-endian)."""
    try:
        event = bytes.fromhex(event_hex)
        if len(event) >= 6:
            return struct.unpack('<I', event[2:6])[0]
    except:
        pass
    return None

def analyze_events_file(filepath: Path, sample_size: int = 100000):
    """Analyze event file to find timestamp patterns."""
    print(f"\n=== Analyzing: {filepath} ===\n")

    if not filepath.exists():
        print(f"File not found: {filepath}")
        return

    timestamps = []
    event_types = defaultdict(int)

    with open(filepath, 'r') as f:
        for i, line in enumerate(f):
            if line.startswith('#') or not line.strip():
                continue

            parts = line.strip().split('|')
            if len(parts) < 4:
                continue

            hex_data = parts[3]
            tag = int(parts[1], 16) if parts[1].startswith('0x') else int(parts[1])
            event_types[tag] += 1

            ts = extract_event_timestamp(hex_data)
            if ts is not None and ts > 0:
                timestamps.append((i, ts, tag))

            if i >= sample_size:
                break

    if not timestamps:
        print("No valid timestamps found!")
        return

    print(f"Analyzed {len(timestamps)} events with valid timestamps")
    print()

    # Find min/max timestamps
    min_ts = min(t[1] for t in timestamps)
    max_ts = max(t[1] for t in timestamps)

    print(f"Timestamp range:")
    print(f"  Min: {min_ts:,} ({min_ts / 36000:.2f} hours)")
    print(f"  Max: {max_ts:,} ({max_ts / 36000:.2f} hours)")
    print(f"  Span: {max_ts - min_ts:,} deciseconds ({(max_ts - min_ts) / 36000:.2f} hours)")
    print()

    # Check if we're sending the right values
    print("=== What we SHOULD send for GetEvent ===")
    print()
    print("If GetEvent param is timestamp:")
    print(f"  First call: GetEvent(0) -> get all from beginning")
    print(f"  After batch 1: GetEvent({max_ts}) -> get events after last received")
    print()
    print("But we're sending:")
    print(f"  Batch 1: GetEvent(0)")
    print(f"  Batch 2: GetEvent(50000)  <- This is timestamp ~1.4 hours!")
    print(f"  Batch 3: GetEvent(100000) <- This is timestamp ~2.8 hours!")
    print()
    print("Our actual event timestamps start at:", min_ts)
    print("So GetEvent(50000) would still include ALL events since 50000 < min_ts!")
    print()

    # Analyze timestamp distribution by batch
    batch_size = 50000
    print("=== Timestamp distribution by 50K event batches ===")
    print()

    for batch_num in range(min(5, (len(timestamps) // batch_size) + 1)):
        start_idx = batch_num * batch_size
        end_idx = min((batch_num + 1) * batch_size, len(timestamps))
        batch = timestamps[start_idx:end_idx]

        if not batch:
            break

        batch_min = min(t[1] for t in batch)
        batch_max = max(t[1] for t in batch)

        print(f"Batch {batch_num + 1} (events {start_idx}-{end_idx}):")
        print(f"  Timestamps: {batch_min:,} to {batch_max:,}")
        print(f"  Would need GetEvent({batch_max}) for next batch")
        print()

    # Check for duplicate timestamps
    ts_counts = defaultdict(int)
    for _, ts, _ in timestamps:
        ts_counts[ts] += 1

    duplicates = [(ts, count) for ts, count in ts_counts.items() if count > 1]
    duplicates.sort(key=lambda x: -x[1])

    print(f"=== Duplicate timestamps ===")
    print(f"Unique timestamps: {len(ts_counts)}")
    print(f"Timestamps with duplicates: {len(duplicates)}")

    if duplicates:
        print(f"\nTop 10 most repeated timestamps:")
        for ts, count in duplicates[:10]:
            print(f"  {ts}: {count} events")

    return timestamps

def analyze_response_format():
    """Analyze what the 0x11 response actually contains."""
    print("\n=== Response Format Analysis ===\n")

    print("From OURA_RING_COMMANDS.md:")
    print("  Response: [0x11, length, eventsReceived, sleepProgress, bytesLeft(4 bytes LE)]")
    print()
    print("From sync.md:")
    print("  [17] [length] [eventCount] [???] [nextTimestamp: 4 bytes uint32 LE]")
    print()
    print("These CONFLICT! One says 'bytesLeft', other says 'nextTimestamp'")
    print()
    print("Our observation:")
    print("  - Values like 920964, 873071, etc. that DECREASE over time")
    print("  - If it were 'nextTimestamp', it would INCREASE (timestamps go up)")
    print("  - Therefore it's probably 'bytesLeft', not 'nextTimestamp'")
    print()
    print("CONCLUSION: The 0x11 response gives us 'bytes_left', not 'nextTimestamp'")
    print("We must extract the timestamp from the events themselves!")

def propose_fix():
    """Propose the fix based on analysis."""
    print("\n=== PROPOSED FIX ===\n")

    print("Current (BROKEN) flow:")
    print("  1. GetEvent(seq=0) -> get 50K events")
    print("  2. current_seq += 50000 (our counter)")
    print("  3. GetEvent(seq=50000) -> get 50K events (same data!)")
    print("  4. Repeat...")
    print()
    print("Fixed flow (using timestamp from events):")
    print("  1. GetEvent(timestamp=0) -> get events, extract max_ts from them")
    print("  2. GetEvent(timestamp=max_ts+1) -> get next batch")
    print("  3. Repeat until no more events")
    print()
    print("OR, even simpler:")
    print("  - After each batch, check if bytes_left == 0")
    print("  - If bytes_left > 0, send GetEvent(0) again")
    print("  - Ring will return remaining events (if events are consumed)")
    print()
    print("BUT: If 'Events consumed when read' is true, bytes_left should decrease")
    print("faster than we observe. So either:")
    print("  a) Events are NOT consumed when read (bug in docs)")
    print("  b) We need to use the TIMESTAMP to paginate properly")

def main():
    data_dir = Path(__file__).parent / "input_data"

    # Analyze our event files
    events_file = data_dir / "ring_events.txt"
    timestamps = analyze_events_file(events_file)

    analyze_response_format()
    propose_fix()

    print("\n" + "="*60)
    print("NEXT STEP: Create a BLE test that sends GetEvent with proper timestamps")
    print("="*60)

if __name__ == "__main__":
    main()
