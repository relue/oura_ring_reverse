"""
Preprocess ring events file before parsing to protobuf.

Sorts events by REVERSE date order (newest first).
This makes the native parser detect all sleep nights correctly.
Writes to transformed_ring_events.txt, keeping original intact.
"""

from pathlib import Path
from typing import Tuple


def preprocess_events(input_path: str, output_path: str = None, reverse_order: bool = False) -> Tuple[int, int, int]:
    """Sort events by timestamp for native parser.

    Events should be in chronological order (oldest first) for SleepNet ML model.
    Reverse order was previously used to workaround RING_START_IND session clearing,
    but this breaks SleepNet preprocessing which expects chronological data.

    Args:
        input_path: Path to raw ring_events.txt
        output_path: Path for cleaned output (default: transformed_ring_events.txt)
        reverse_order: If True, sort events by timestamp DESC (deprecated)

    Returns:
        Tuple of (total_events, output_events, 0)
    """
    if output_path is None:
        input_p = Path(input_path)
        output_path = str(input_p.parent / "transformed_ring_events.txt")

    events = []  # (timestamp, line)
    total = 0

    with open(input_path) as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith('#'):
                continue

            parts = line.split('|')
            if len(parts) < 4:
                continue

            hex_data = parts[3]
            if len(hex_data) < 12:
                continue

            total += 1

            # Extract timestamp (bytes 2-5, little-endian)
            try:
                ts = int.from_bytes(bytes.fromhex(hex_data[4:12]), 'little')
            except ValueError:
                continue

            events.append((ts, line))

    # Sort by timestamp - chronological order (oldest first) for SleepNet ML
    events.sort(key=lambda x: x[0], reverse=reverse_order)

    # Write output
    Path(output_path).parent.mkdir(parents=True, exist_ok=True)
    order_str = "reverse date order (newest first)" if reverse_order else "chronological order (oldest first)"

    with open(output_path, 'w') as f:
        f.write(f'# Oura Ring Events ({order_str})\n')
        f.write(f'# Events: {len(events)}\n')
        f.write('#\n')
        for _, line in events:
            f.write(line + '\n')

    return total, len(events), 0


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
