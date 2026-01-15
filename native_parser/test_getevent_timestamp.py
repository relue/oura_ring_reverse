#!/usr/bin/env python3
"""
BLE test script to verify GetEvent timestamp theory.

This script will:
1. Connect to the ring
2. Send GetEvent(timestamp=0) and capture events
3. Extract max timestamp from received events
4. Send GetEvent(timestamp=max_ts+1) and see if we get different/fewer events
5. Compare results to prove the timestamp theory

Run with: python3 test_getevent_timestamp.py
"""

import asyncio
import struct
import time
from pathlib import Path
from collections import defaultdict

# Add parent to path for imports
import sys
sys.path.insert(0, str(Path(__file__).parent))

from oura.ble.client import OuraClient
from oura.ble.protocol import build_get_event_cmd

class GetEventTester:
    """Test GetEvent with different timestamp values."""

    def __init__(self):
        self.client = None
        self.events_by_batch = {}
        self.current_batch = 0
        self.current_events = []

    def extract_timestamp(self, event: bytes) -> int | None:
        """Extract timestamp from event (bytes 2-5, little-endian)."""
        if len(event) >= 6:
            return struct.unpack('<I', event[2:6])[0]
        return None

    async def test_with_timestamp(self, timestamp: int, max_events: int = 1000) -> dict:
        """Send GetEvent with specific timestamp and collect results."""
        print(f"\n=== Testing GetEvent(timestamp={timestamp}) ===")

        # Reset collection
        self.current_events = []
        self.client.event_data.clear()
        self.client.bytes_left = -1
        self.client.fetch_complete = False

        # Build and send command
        cmd = build_get_event_cmd(timestamp, max_events=0)  # 0 = streaming
        print(f"Command: {cmd.hex()}")
        print(f"  Timestamp param: {timestamp} ({timestamp/36000:.2f} hours)")

        await self.client.send_command(cmd, f"GetEvent(ts={timestamp})")

        # Wait for events (with timeout)
        start_time = time.time()
        last_count = 0
        stall_count = 0

        while time.time() - start_time < 30:  # 30 second timeout
            await asyncio.sleep(0.5)
            current = len(self.client.event_data)

            if self.client.bytes_left == 0:
                print(f"bytes_left=0, done")
                break

            if current > 0 and current >= max_events:
                print(f"Reached max_events={max_events}")
                break

            if current == last_count:
                stall_count += 1
                if stall_count >= 6:  # 3 seconds of no new events
                    print(f"Stalled at {current} events")
                    break
            else:
                stall_count = 0
                print(f"  Received {current} events, bytes_left={self.client.bytes_left}")

            last_count = current

        events = self.client.event_data.copy()

        # Analyze results
        result = {
            'timestamp_param': timestamp,
            'events_received': len(events),
            'bytes_left': self.client.bytes_left,
        }

        if events:
            timestamps = [self.extract_timestamp(e) for e in events]
            timestamps = [t for t in timestamps if t is not None]

            if timestamps:
                result['min_ts'] = min(timestamps)
                result['max_ts'] = max(timestamps)
                result['ts_range'] = max(timestamps) - min(timestamps)

                print(f"\nResults:")
                print(f"  Events: {len(events)}")
                print(f"  Timestamp range: {min(timestamps):,} to {max(timestamps):,}")
                print(f"  bytes_left: {self.client.bytes_left}")

                # Check if all events have ts >= our requested timestamp
                events_below = sum(1 for t in timestamps if t < timestamp)
                if events_below > 0:
                    print(f"  WARNING: {events_below} events have timestamp < {timestamp}")
                else:
                    print(f"  SUCCESS: All events have timestamp >= {timestamp}")

        return result

    async def run_test(self):
        """Run the complete test sequence."""
        print("="*60)
        print("GetEvent Timestamp Theory Test")
        print("="*60)

        # Connect
        self.client = OuraClient()

        print("\n1. Connecting to ring...")
        if not await self.client.connect():
            print("Failed to connect!")
            return

        print("\n2. Authenticating...")
        if not await self.client.authenticate():
            print("Failed to authenticate!")
            await self.client.disconnect()
            return

        try:
            # Test 1: GetEvent(0) - should get everything
            result1 = await self.test_with_timestamp(0, max_events=1000)

            if not result1.get('events_received'):
                print("No events received!")
                return

            max_ts_batch1 = result1.get('max_ts', 0)

            # Test 2: GetEvent(max_ts) - should get fewer/different events
            print(f"\n\nNow testing with timestamp = {max_ts_batch1}")
            print("If the theory is correct, we should get FEWER events")
            print("(only events with timestamp >= max_ts_batch1)")

            await asyncio.sleep(2)  # Brief pause between tests
            result2 = await self.test_with_timestamp(max_ts_batch1, max_events=1000)

            # Test 3: GetEvent(max_ts + 10000) - should get even fewer
            higher_ts = max_ts_batch1 + 10000
            print(f"\n\nTesting with even higher timestamp = {higher_ts}")
            await asyncio.sleep(2)
            result3 = await self.test_with_timestamp(higher_ts, max_events=1000)

            # Compare results
            print("\n" + "="*60)
            print("COMPARISON OF RESULTS")
            print("="*60)

            print(f"\nGetEvent(0):         {result1.get('events_received', 0)} events")
            print(f"  Timestamp range:   {result1.get('min_ts', 0):,} to {result1.get('max_ts', 0):,}")

            print(f"\nGetEvent({max_ts_batch1}): {result2.get('events_received', 0)} events")
            if result2.get('min_ts'):
                print(f"  Timestamp range:   {result2.get('min_ts', 0):,} to {result2.get('max_ts', 0):,}")

            print(f"\nGetEvent({higher_ts}): {result3.get('events_received', 0)} events")
            if result3.get('min_ts'):
                print(f"  Timestamp range:   {result3.get('min_ts', 0):,} to {result3.get('max_ts', 0):,}")

            # Verdict
            print("\n" + "="*60)
            if result1['events_received'] > result2.get('events_received', 0):
                print("THEORY CONFIRMED: Higher timestamp = fewer events")
                print("The GetEvent parameter IS a timestamp, not a sequence number!")
            elif result1['events_received'] == result2.get('events_received', 0):
                print("THEORY UNCERTAIN: Same number of events")
                print("Ring may ignore timestamp OR we hit the buffer limit")
            else:
                print("THEORY DISPROVED: More events with higher timestamp?!")

        finally:
            await self.client.disconnect()
            print("\nTest complete!")

async def main():
    tester = GetEventTester()
    await tester.run_test()

if __name__ == "__main__":
    asyncio.run(main())
