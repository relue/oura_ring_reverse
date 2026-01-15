#!/usr/bin/env python3
"""
Test the fixed GetEvent timestamp-based pagination.

This test will:
1. Connect to the ring
2. Do a limited sync using the FIXED approach
3. Verify we get minimal/no duplicates between batches
4. Compare to what the OLD approach would have done
"""

import asyncio
import struct
from pathlib import Path
from collections import defaultdict

import sys
sys.path.insert(0, str(Path(__file__).parent))

from oura.ble.client import OuraClient

async def test_fixed_sync():
    """Test the fixed sync approach."""
    print("="*60)
    print("TEST: Fixed GetEvent Timestamp-Based Pagination")
    print("="*60)

    client = OuraClient()

    # Connect and auth
    print("\n1. Connecting...")
    if not await client.connect():
        print("Failed to connect!")
        return

    print("\n2. Authenticating...")
    if not await client.authenticate():
        print("Failed to authenticate!")
        await client.disconnect()
        return

    try:
        print("\n3. Syncing time...")
        await client.sync_time()
        await asyncio.sleep(1)

        print("\n4. Testing fixed sync (limited to 2000 events)...")

        # Save original event_data so we can analyze batches
        batch_data = []

        # Override logging to capture batch info
        original_log = client._log
        def capture_log(level, msg):
            original_log(level, msg)
            if "Max timestamp in batch" in msg:
                print(f"  >> {msg}")

        client._log = capture_log

        # Fetch limited data
        events = await client.get_data(
            start_seq=0,  # Start from timestamp 0
            stop_after_count=2000,  # Stop after 2000 events
            save_between_batches=False
        )

        client._log = original_log

        print(f"\n5. Analyzing results...")
        print(f"   Total events received: {len(events)}")

        if events:
            # Extract timestamps
            timestamps = []
            hex_data = []
            for e in events:
                if len(e) >= 6:
                    ts = struct.unpack('<I', e[2:6])[0]
                    timestamps.append(ts)
                    hex_data.append(e.hex())

            if timestamps:
                print(f"   Timestamp range: {min(timestamps):,} to {max(timestamps):,}")
                print(f"   Unique timestamps: {len(set(timestamps)):,}")
                print(f"   Unique events (by hex): {len(set(hex_data)):,}")

                dup_count = len(hex_data) - len(set(hex_data))
                dup_pct = dup_count / len(hex_data) * 100 if hex_data else 0
                print(f"   Duplicates: {dup_count} ({dup_pct:.1f}%)")

                if dup_pct > 10:
                    print("\n   WARNING: High duplicate rate!")
                    print("   The fix may not be working correctly.")
                else:
                    print("\n   SUCCESS: Low duplicate rate!")
                    print("   The timestamp-based pagination is working!")

    finally:
        await client.disconnect()
        print("\nTest complete!")

if __name__ == "__main__":
    asyncio.run(test_fixed_sync())
