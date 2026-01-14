#!/usr/bin/env python3
"""Decode Oura Ring protobuf data with full type information.

Uses the unified oura_ring_data library for type-safe parsing and analysis.

Usage:
    python decode_ringdata.py [ring_data.pb] [--json]
"""

import sys
import argparse
from pathlib import Path

from oura.data.reader import RingDataReader


def main():
    parser = argparse.ArgumentParser(
        description='Decode Oura Ring protobuf data',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
    python decode_ringdata.py ring_data.pb
    python decode_ringdata.py ring_data.pb --json
"""
    )
    parser.add_argument('pb_file', nargs='?', default='ring_data.pb',
                        help='Path to protobuf file (default: ring_data.pb)')
    parser.add_argument('--json', action='store_true',
                        help='Output as JSON')

    args = parser.parse_args()

    pb_path = args.pb_file
    if not Path(pb_path).exists():
        print(f"Error: File not found: {pb_path}", file=sys.stderr)
        sys.exit(1)

    # Load data
    print(f"Loading {pb_path}...", file=sys.stderr)
    data = Path(pb_path).read_bytes()
    print(f"Binary size: {len(data):,} bytes", file=sys.stderr)

    print("Parsing protobuf...", file=sys.stderr)
    reader = RingDataReader(pb_path)

    # Output format
    if args.json:
        print(reader.to_json())
    else:
        print(reader.summary())

        # Also show raw protobuf access example
        print("\n" + "=" * 60)
        print("RAW PROTOBUF ACCESS:")
        print("=" * 60)
        print(f"Fields: {', '.join(reader.fields_present[:10])}{'...' if len(reader.fields_present) > 10 else ''}")


if __name__ == '__main__':
    main()
