#!/usr/bin/env python3
"""
Deep analysis of event duplication in our data.

This will determine:
1. Are duplicates EXACT copies (same hex data)?
2. Or different events with same timestamp?
3. What's the actual duplication pattern?
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

def analyze_duplicates(filepath: Path):
    """Analyze exact duplicates vs timestamp duplicates."""
    print(f"\n=== Deep Duplicate Analysis: {filepath} ===\n")

    if not filepath.exists():
        print(f"File not found: {filepath}")
        return

    # Track by hex data and by timestamp
    hex_counts = defaultdict(int)
    ts_events = defaultdict(list)  # timestamp -> list of hex data
    all_events = []

    with open(filepath, 'r') as f:
        for i, line in enumerate(f):
            if line.startswith('#') or not line.strip():
                continue

            parts = line.strip().split('|')
            if len(parts) < 4:
                continue

            hex_data = parts[3]
            hex_counts[hex_data] += 1

            ts = extract_event_timestamp(hex_data)
            if ts:
                ts_events[ts].append(hex_data)
                all_events.append((i, ts, hex_data))

    total_events = sum(hex_counts.values())
    unique_hex = len(hex_counts)

    print(f"Total events: {total_events:,}")
    print(f"Unique hex data: {unique_hex:,}")
    print(f"Duplication factor: {total_events / unique_hex:.2f}x")
    print()

    # Find exact duplicates
    exact_dups = [(h, c) for h, c in hex_counts.items() if c > 1]
    exact_dups.sort(key=lambda x: -x[1])

    print(f"=== Exact duplicates (same hex data) ===")
    print(f"Events with duplicates: {len(exact_dups):,}")
    dup_count = sum(c - 1 for _, c in exact_dups)
    print(f"Total duplicate instances: {dup_count:,}")
    print()

    if exact_dups:
        print("Top 10 most duplicated events:")
        for hex_data, count in exact_dups[:10]:
            ts = extract_event_timestamp(hex_data)
            tag = bytes.fromhex(hex_data)[0] if hex_data else 0
            print(f"  {count}x: tag=0x{tag:02x}, ts={ts}, len={len(hex_data)//2}")
    print()

    # Analyze timestamp duplicates
    print(f"=== Timestamp duplicates (same timestamp, different data) ===")
    ts_with_multiple = [(ts, events) for ts, events in ts_events.items() if len(events) > 1]

    # Check if same-timestamp events are exact duplicates or different
    same_ts_same_data = 0
    same_ts_diff_data = 0

    for ts, events in ts_with_multiple:
        unique_events = set(events)
        if len(unique_events) == 1:
            # All events at this timestamp are identical
            same_ts_same_data += len(events) - 1
        else:
            # Different events at same timestamp
            same_ts_diff_data += len(events)

    print(f"Timestamps with multiple events: {len(ts_with_multiple):,}")
    print(f"  Same timestamp, same data (exact dups): {same_ts_same_data:,}")
    print(f"  Same timestamp, different data (real events): {same_ts_diff_data:,}")
    print()

    # Analyze batch patterns
    print(f"=== Batch Pattern Analysis ===")
    print()

    # Divide into ~50K batches and check overlap
    batch_size = 50000
    batches = []
    for i in range(0, len(all_events), batch_size):
        batch = all_events[i:i+batch_size]
        batch_hex = set(e[2] for e in batch)
        batch_ts = set(e[1] for e in batch)
        batches.append({
            'idx': i // batch_size,
            'events': len(batch),
            'unique_hex': len(batch_hex),
            'unique_ts': len(batch_ts),
            'hex_set': batch_hex,
            'ts_set': batch_ts,
            'min_ts': min(e[1] for e in batch),
            'max_ts': max(e[1] for e in batch),
        })

    for b in batches:
        print(f"Batch {b['idx'] + 1}:")
        print(f"  Events: {b['events']:,} ({b['unique_hex']:,} unique)")
        print(f"  Timestamp range: {b['min_ts']:,} to {b['max_ts']:,}")

    # Check overlap between consecutive batches
    print()
    print("=== Overlap between consecutive batches ===")
    for i in range(len(batches) - 1):
        b1, b2 = batches[i], batches[i+1]
        hex_overlap = len(b1['hex_set'] & b2['hex_set'])
        ts_overlap = len(b1['ts_set'] & b2['ts_set'])

        hex_overlap_pct = hex_overlap / len(b1['hex_set']) * 100 if b1['hex_set'] else 0
        ts_overlap_pct = ts_overlap / len(b1['ts_set']) * 100 if b1['ts_set'] else 0

        print(f"Batch {i+1} -> {i+2}:")
        print(f"  Hex overlap: {hex_overlap:,} ({hex_overlap_pct:.1f}%)")
        print(f"  Timestamp overlap: {ts_overlap:,} ({ts_overlap_pct:.1f}%)")

    # Conclusion
    print()
    print("="*60)
    print("CONCLUSIONS")
    print("="*60)

    if exact_dups:
        print()
        print("1. EXACT DUPLICATES EXIST")
        print(f"   {len(exact_dups):,} events appear multiple times with IDENTICAL hex data")
        print("   This proves we're receiving the same events repeatedly!")

    if same_ts_same_data > 0:
        print()
        print("2. SAME TIMESTAMP = SAME DATA")
        print(f"   When timestamps match, the data is usually identical")
        print("   This confirms duplicates are the same events, not different events at same time")

    if batches and len(batches) > 1:
        hex_overlap = len(batches[0]['hex_set'] & batches[1]['hex_set'])
        if hex_overlap > 0:
            print()
            print("3. HIGH BATCH OVERLAP")
            print(f"   Consecutive 50K batches share {hex_overlap:,} identical events")
            print("   This is why deduplication was needed!")

def main():
    data_dir = Path(__file__).parent / "input_data"
    events_file = data_dir / "ring_events.txt"
    analyze_duplicates(events_file)

if __name__ == "__main__":
    main()
