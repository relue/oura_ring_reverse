"""
Preprocess ring events file before parsing to protobuf.

Deduplicates events while preserving recording order.
Writes to transformed_ring_events.txt, keeping original intact.
"""

from pathlib import Path
from typing import Tuple


def preprocess_events(input_path: str, output_path: str = None) -> Tuple[int, int, int]:
    """Deduplicate events file (preserves recording order).

    Args:
        input_path: Path to raw ring_events.txt
        output_path: Path for cleaned output (default: transformed_ring_events.txt)

    Returns:
        Tuple of (total_events, unique_events, duplicates_removed)
    """
    if output_path is None:
        # Write to intermediate file, preserve original
        input_p = Path(input_path)
        output_path = str(input_p.parent / "transformed_ring_events.txt")

    events = []  # (timestamp, tag_byte, line)
    seen = set()
    total = 0
    duplicates = 0

    with open(input_path) as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith('#'):
                continue

            parts = line.split('|')
            if len(parts) < 4:
                continue

            tag = parts[1]
            hex_data = parts[3]

            if len(hex_data) < 12:
                continue

            total += 1

            # Extract timestamp (bytes 2-5, little-endian)
            try:
                ts = int.from_bytes(bytes.fromhex(hex_data[4:12]), 'little')
                tag_byte = int(tag, 16)
            except ValueError:
                continue

            # Dedup key
            key = (tag_byte, ts)
            if key in seen:
                duplicates += 1
                continue
            seen.add(key)

            events.append((ts, line))

    # NOTE: Don't sort - native parser expects events in recording order
    # events.sort(key=lambda x: x[0])

    # Write output
    unique = len(events)
    Path(output_path).parent.mkdir(parents=True, exist_ok=True)

    with open(output_path, 'w') as f:
        f.write('# Oura Ring Events (deduplicated, recording order preserved)\n')
        f.write(f'# Total: {total}, Unique: {unique}, Duplicates removed: {duplicates}\n')
        f.write('#\n')
        f.write('# Format: index|tag_hex|event_name|hex_data\n')
        f.write('#\n')
        for _, line in events:
            f.write(line + '\n')

    return total, unique, duplicates


def main():
    import sys

    if len(sys.argv) < 2:
        print("Usage: python -m oura.data.preprocess <events.txt> [output.txt]")
        sys.exit(1)

    input_path = sys.argv[1]
    output_path = sys.argv[2] if len(sys.argv) > 2 else None

    total, unique, dups = preprocess_events(input_path, output_path)

    print(f"Total events: {total}")
    print(f"Unique events: {unique}")
    print(f"Duplicates removed: {dups} ({100*dups/total:.1f}%)")
    print(f"Output: {output_path or input_path}")


if __name__ == "__main__":
    main()
