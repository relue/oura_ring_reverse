#!/usr/bin/env python3
"""
Oura Ring BLE Client - Uses RPA Tracker for reliable connections

This client works with the RPA Tracker daemon to always connect using
the freshest RPA address. The ring is always connectable - we just need
the right address from the most recent advertisement.

Usage:
    # First, start the RPA tracker daemon (run once after bonding)
    python rpa_tracker.py --start

    # Then use this client
    python oura_client.py --heartbeat
    python oura_client.py --get-data --output data.txt
    python oura_client.py --interactive
"""

import asyncio
import argparse
import json
import sys
import struct
import time
from datetime import datetime
from pathlib import Path
from typing import Optional, List, Callable

from bleak import BleakClient, BleakScanner
from bleak.backends.device import BLEDevice

try:
    from Crypto.Cipher import AES
except ImportError:
    print("ERROR: pycryptodome required. Run: pip install pycryptodome")
    sys.exit(1)

# ============================================================================
# CONFIGURATION
# ============================================================================

ADAPTER = "hci1"  # TP-Link UB500
TRACKER_STATE_FILE = Path("/tmp/oura_rpa_tracker.json")
AUTH_KEY_FILE = Path("stored_auth_key.bin")

# BLE UUIDs
SERVICE_UUID = "98ed0001-a541-11e4-b6a0-0002a5d5c51b"
WRITE_CHAR_UUID = "98ed0002-a541-11e4-b6a0-0002a5d5c51b"
NOTIFY_CHAR_UUID = "98ed0003-a541-11e4-b6a0-0002a5d5c51b"

# Commands
CMD_GET_AUTH_NONCE = bytes([0x2f, 0x01, 0x2b])
CMD_INIT_1 = bytes([0x2f, 0x02, 0x20, 0x02])
CMD_INIT_2 = bytes([0x2f, 0x03, 0x22, 0x02, 0x03])
CMD_START_STREAM = bytes([0x2f, 0x03, 0x26, 0x02, 0x02])
CMD_STOP = bytes([0x2f, 0x03, 0x22, 0x02, 0x01])
CMD_TIME_SYNC = bytes([0x12, 0x00])
CMD_FACTORY_RESET = bytes([0x1a, 0x00])

# Default auth key
DEFAULT_AUTH_KEY = bytes.fromhex("00426ed816dcece48dd9968c1f36c0b5")

# Event type names
EVENT_TYPES = {
    0x11: "GET_EVENT_SUMMARY",
    0x13: "TIME_SYNC_RESPONSE",
    0x2f: "CMD_RESPONSE",
    0x41: "RING_START_IND",
    0x43: "DEBUG_EVENT",
    0x44: "PPG_SAMPLE",
    0x45: "ACCEL_SAMPLE",
    0x46: "GYRO_TEMP",
    0x47: "TEMP_SAMPLE",
    0x48: "SLEEP_PERIOD_INFO",
    0x49: "SLEEP_SUMMARY_1",
    0x4B: "SLEEP_PHASE_INFO",
    0x4C: "SLEEP_SUMMARY_2",
    0x4E: "SLEEP_PHASE_DETAILS",
    0x51: "SLEEP_PERIOD_INFO_OLD",
    0x55: "SLEEP_HR",
    0x5A: "HEARTBEAT",
    0x60: "HR_REST",
    0x61: "ACTIVITY_EVENT",
    0x6A: "SLEEP_PERIOD_INFO_2",
    0x72: "SLEEP_ACM_PERIOD",
    0x75: "SLEEP_TEMP_EVENT",
    0x76: "BEDTIME_PERIOD",
    0x80: "SPO2_EVENT",
}


def get_event_name(tag: int) -> str:
    return EVENT_TYPES.get(tag, f"UNKNOWN_0x{tag:02x}")


# ============================================================================
# RPA TRACKER INTEGRATION
# ============================================================================

def get_current_rpa(identity: str = None) -> Optional[str]:
    """
    Get the current RPA address from the tracker daemon.

    The tracker continuously monitors advertisements and keeps
    the freshest RPA address for each bonded device.

    Args:
        identity: Optional identity address to look up (default: first Oura device)

    Returns:
        Current RPA address string, or None if not available
    """
    if not TRACKER_STATE_FILE.exists():
        return None

    try:
        data = json.loads(TRACKER_STATE_FILE.read_text())
        devices = data.get('devices', {})

        if identity:
            if identity in devices:
                return devices[identity].get('current_rpa')
        else:
            # Return first device (usually Oura)
            for dev_identity, info in devices.items():
                rpa = info.get('current_rpa')
                if rpa:
                    return rpa

        return None
    except Exception as e:
        print(f"Error reading tracker state: {e}")
        return None


def get_device_info() -> Optional[dict]:
    """Get full device info from tracker."""
    if not TRACKER_STATE_FILE.exists():
        return None

    try:
        data = json.loads(TRACKER_STATE_FILE.read_text())
        devices = data.get('devices', {})

        # Return first device
        for identity, info in devices.items():
            info['identity'] = identity
            return info

        return None
    except:
        return None


# ============================================================================
# OURA CLIENT
# ============================================================================

class OuraClient:
    """Oura Ring BLE Client with RPA tracker integration."""

    def __init__(self, auth_key: Optional[bytes] = None, adapter: str = ADAPTER):
        self.auth_key = auth_key or self._load_auth_key() or DEFAULT_AUTH_KEY
        self.adapter = adapter
        self.client: Optional[BleakClient] = None
        self.is_connected = False
        self.is_authenticated = False

        # Response handling
        self.response_event = asyncio.Event()
        self.last_response: bytes = b""

        # Event storage
        self.event_data: List[bytes] = []
        self.current_seq_num = 0
        self.fetch_complete = False

        # Callbacks
        self.on_event: Optional[Callable] = None
        self.on_heartbeat: Optional[Callable] = None

    def _load_auth_key(self) -> Optional[bytes]:
        """Load auth key from file."""
        try:
            if AUTH_KEY_FILE.exists():
                key = AUTH_KEY_FILE.read_bytes()
                if len(key) == 16:
                    return key
        except:
            pass
        return None

    def save_auth_key(self, key: bytes):
        """Save auth key to file."""
        AUTH_KEY_FILE.write_bytes(key)
        self.auth_key = key
        print(f"Auth key saved: {key.hex()}")

    def _notification_handler(self, sender, data: bytes):
        """Handle incoming BLE notifications."""
        if not data:
            return

        tag = data[0]

        # Command response
        if tag == 0x2f:
            self.last_response = data
            self.response_event.set()

            # Check for auth nonce response
            if len(data) >= 18 and data[2] == 0x2c:
                # Will be handled in authenticate()
                pass
            # Check for auth result
            elif len(data) >= 4 and data[2] == 0x2e:
                status = data[3]
                if status == 0:
                    self.is_authenticated = True
                    print("Authentication successful!")
                else:
                    print(f"Authentication failed: status={status}")

        # Heartbeat
        elif tag == 0x2f and len(data) >= 10 and data[1] == 0x0f and data[2] == 0x28:
            ibi_low = data[8] & 0xFF
            ibi_high = data[9] & 0x0F
            ibi_ms = (ibi_high << 8) | ibi_low
            bpm = 60000.0 / ibi_ms if ibi_ms > 0 else 0

            print(f"Heartbeat: {bpm:.1f} BPM (IBI: {ibi_ms}ms)")
            if self.on_heartbeat:
                self.on_heartbeat(bpm, ibi_ms)

        # Real heartbeat packet (0x5a)
        elif tag == 0x5A and len(data) >= 4:
            bpm = data[2]
            quality = data[3] if len(data) > 3 else 0
            print(f"Heartbeat: {bpm} BPM (quality: {quality})")
            if self.on_heartbeat:
                self.on_heartbeat(bpm, 0)

        # Time sync response
        elif tag == 0x13 and len(data) >= 6:
            ring_time = struct.unpack('<I', data[2:6])[0]
            print(f"Time sync response: ring_time={ring_time} deciseconds")

        # GetEvent summary (0x11)
        elif tag == 0x11 and len(data) >= 8:
            events_received = data[2]
            bytes_left = struct.unpack('<I', data[4:8])[0]

            print(f"GetEvent summary: {events_received} events, {bytes_left} bytes left")

            if bytes_left == 0:
                self.fetch_complete = True
            else:
                # Continue fetching
                self.current_seq_num += events_received

        # Event data (tags >= 0x41)
        elif tag >= 0x41:
            self.event_data.append(data)
            if self.on_event:
                self.on_event(tag, get_event_name(tag), data)

    async def connect(self, address: str = None, timeout: float = 30.0) -> bool:
        """
        Connect to Oura Ring.

        If no address is provided, gets the current RPA from the tracker daemon.
        The tracker keeps addresses fresh by continuously monitoring advertisements.

        Args:
            address: BLE address to connect to (default: from tracker)
            timeout: Connection timeout in seconds

        Returns:
            True if connected successfully
        """
        # Get address from tracker if not provided
        if not address:
            device_info = get_device_info()
            if device_info:
                address = device_info.get('current_rpa')
                identity = device_info.get('identity', 'unknown')
                last_seen = device_info.get('last_seen', 'unknown')
                print(f"Using RPA from tracker: {address}")
                print(f"  Identity: {identity}")
                print(f"  Last seen: {last_seen}")
            else:
                print("ERROR: No address available from tracker")
                print("Make sure rpa_tracker.py daemon is running:")
                print("  python rpa_tracker.py --start")
                return False

        print(f"\nConnecting to {address}...")

        try:
            self.client = BleakClient(address, adapter=self.adapter, timeout=timeout)
            await self.client.connect()

            if not self.client.is_connected:
                print("ERROR: Connection failed")
                return False

            print(f"Connected to {address}")
            self.is_connected = True

            # Subscribe to notifications
            print("Subscribing to notifications...")
            await self.client.start_notify(NOTIFY_CHAR_UUID, self._notification_handler)
            print("Ready!")

            return True

        except Exception as e:
            print(f"Connection error: {e}")
            return False

    async def disconnect(self):
        """Disconnect from ring."""
        if self.client and self.client.is_connected:
            try:
                await self.client.disconnect()
            except:
                pass
        self.is_connected = False
        self.is_authenticated = False
        print("Disconnected")

    async def send_command(self, cmd: bytes, name: str = "", wait_response: bool = True) -> Optional[bytes]:
        """Send a command to the ring."""
        if not self.client or not self.client.is_connected:
            print("ERROR: Not connected")
            return None

        if name:
            print(f"TX: {cmd.hex()} ({name})")
        else:
            print(f"TX: {cmd.hex()}")

        self.response_event.clear()
        await self.client.write_gatt_char(WRITE_CHAR_UUID, cmd)

        if wait_response:
            try:
                await asyncio.wait_for(self.response_event.wait(), timeout=5.0)
                return self.last_response
            except asyncio.TimeoutError:
                print("Response timeout")
                return None

        return b""

    async def authenticate(self) -> bool:
        """Authenticate with the ring using AES-ECB encrypted nonce."""
        print("\n=== AUTHENTICATING ===")

        # Get nonce
        response = await self.send_command(CMD_GET_AUTH_NONCE, "GetAuthNonce")
        if not response or len(response) < 18:
            print("ERROR: Failed to get nonce")
            return False

        if response[2] != 0x2c:
            print(f"ERROR: Unexpected response: {response.hex()}")
            return False

        nonce = response[3:18]  # 15-byte nonce
        print(f"Nonce: {nonce.hex()}")

        # Encrypt nonce with auth key
        cipher = AES.new(self.auth_key, AES.MODE_ECB)
        # Pad nonce to 16 bytes
        padded_nonce = nonce + bytes([0])  # Add one zero byte
        encrypted = cipher.encrypt(padded_nonce)
        print(f"Encrypted: {encrypted.hex()}")

        # Send auth command: 2f 11 2d <16-byte encrypted nonce>
        auth_cmd = bytes([0x2f, 0x11, 0x2d]) + encrypted[:16]
        response = await self.send_command(auth_cmd, "Authenticate")

        if response and len(response) >= 4 and response[3] == 0x00:
            self.is_authenticated = True
            print("Authentication successful!")
            return True
        else:
            print("Authentication failed")
            return False

    async def start_heartbeat(self, duration: int = 60):
        """Start heartbeat monitoring."""
        if not self.is_authenticated:
            if not await self.authenticate():
                return

        print(f"\n=== STARTING HEARTBEAT ({duration}s) ===")

        await self.send_command(CMD_INIT_1, "INIT_1")
        await asyncio.sleep(0.2)
        await self.send_command(CMD_INIT_2, "INIT_2")
        await asyncio.sleep(0.2)
        await self.send_command(CMD_START_STREAM, "START_STREAM")

        print("Monitoring heartbeat... (press Ctrl+C to stop)")
        try:
            await asyncio.sleep(duration)
        except asyncio.CancelledError:
            pass

        await self.send_command(CMD_STOP, "STOP")
        print("Heartbeat monitoring stopped")

    async def sync_time(self):
        """Send time sync command to ring."""
        if not self.is_authenticated:
            if not await self.authenticate():
                return

        print("\n=== SYNCING TIME ===")
        await self.send_command(CMD_TIME_SYNC, "TIME_SYNC")
        await asyncio.sleep(1)  # Wait for response

    async def get_data(self, start_seq: int = 0, max_events: int = 0) -> List[bytes]:
        """
        Get event data from ring.

        Args:
            start_seq: Starting sequence number
            max_events: Max events per batch (0 = all)

        Returns:
            List of raw event data bytes
        """
        if not self.is_authenticated:
            if not await self.authenticate():
                return []

        print(f"\n=== GETTING DATA (start_seq={start_seq}) ===")

        self.event_data.clear()
        self.current_seq_num = start_seq
        self.fetch_complete = False

        batch_count = 0
        while not self.fetch_complete:
            # Build GetEvent command
            cmd = bytes([0x10, 0x07]) + struct.pack('<I', self.current_seq_num) + bytes([max_events])
            await self.send_command(cmd, f"GetEvent(seq={self.current_seq_num})", wait_response=False)
            await asyncio.sleep(0.5)

            batch_count += 1
            if batch_count > 1000:
                print("Max batches reached")
                break

        print(f"Received {len(self.event_data)} events")
        return self.event_data

    def export_data(self, filename: str):
        """Export event data to file."""
        with open(filename, 'w') as f:
            for i, event in enumerate(self.event_data):
                tag = event[0] if event else 0
                name = get_event_name(tag)
                f.write(f"{i}|0x{tag:02x}|{name}|{event.hex()}\n")
        print(f"Exported {len(self.event_data)} events to {filename}")


# ============================================================================
# INTERACTIVE MODE
# ============================================================================

async def interactive_mode(client: OuraClient):
    """Interactive menu for Oura Ring operations."""
    print("\n=== OURA RING INTERACTIVE MODE ===\n")

    while True:
        print("\nOptions:")
        print("  1. Connect")
        print("  2. Authenticate")
        print("  3. Start Heartbeat")
        print("  4. Get Data")
        print("  5. Sync Time")
        print("  6. Disconnect")
        print("  7. Show Tracker Status")
        print("  0. Exit")

        try:
            choice = input("\nChoice: ").strip()
        except EOFError:
            break

        if choice == '1':
            await client.connect()
        elif choice == '2':
            await client.authenticate()
        elif choice == '3':
            duration = input("Duration (seconds) [60]: ").strip() or "60"
            await client.start_heartbeat(int(duration))
        elif choice == '4':
            await client.get_data()
            if client.event_data:
                save = input("Save to file? (filename or Enter to skip): ").strip()
                if save:
                    client.export_data(save)
        elif choice == '5':
            await client.sync_time()
        elif choice == '6':
            await client.disconnect()
        elif choice == '7':
            info = get_device_info()
            if info:
                print(f"\nTracker Status:")
                print(f"  Identity: {info.get('identity')}")
                print(f"  Current RPA: {info.get('current_rpa')}")
                print(f"  Last seen: {info.get('last_seen')}")
                print(f"  RSSI: {info.get('rssi')}")
            else:
                print("No tracker data available")
        elif choice == '0':
            break

    await client.disconnect()


# ============================================================================
# MAIN
# ============================================================================

async def main():
    parser = argparse.ArgumentParser(description="Oura Ring BLE Client")
    parser.add_argument('--address', '-a', help='BLE address (default: from tracker)')
    parser.add_argument('--adapter', default=ADAPTER, help=f'Bluetooth adapter (default: {ADAPTER})')
    parser.add_argument('--auth-key', help='Auth key (32 hex chars)')
    parser.add_argument('--heartbeat', action='store_true', help='Monitor heartbeat')
    parser.add_argument('--duration', type=int, default=60, help='Heartbeat duration (seconds)')
    parser.add_argument('--get-data', action='store_true', help='Get event data')
    parser.add_argument('--output', '-o', help='Output file for data')
    parser.add_argument('--sync-time', action='store_true', help='Sync time with ring')
    parser.add_argument('--interactive', '-i', action='store_true', help='Interactive mode')
    parser.add_argument('--status', action='store_true', help='Show tracker status')
    args = parser.parse_args()

    # Just show status
    if args.status:
        info = get_device_info()
        if info:
            print("RPA Tracker Status:")
            print(f"  Identity: {info.get('identity')}")
            print(f"  Current RPA: {info.get('current_rpa')}")
            print(f"  Last seen: {info.get('last_seen')}")
            print(f"  RSSI: {info.get('rssi')}")
        else:
            print("No tracker data. Start the daemon:")
            print("  python rpa_tracker.py --start")
        return 0

    # Parse auth key
    auth_key = None
    if args.auth_key:
        auth_key = bytes.fromhex(args.auth_key)

    # Create client
    client = OuraClient(auth_key=auth_key, adapter=args.adapter)

    try:
        # Interactive mode
        if args.interactive:
            await interactive_mode(client)
            return 0

        # Connect
        if not await client.connect(args.address):
            return 1

        # Perform requested operation
        if args.heartbeat:
            await client.start_heartbeat(args.duration)
        elif args.get_data:
            await client.get_data()
            if args.output:
                client.export_data(args.output)
        elif args.sync_time:
            await client.sync_time()
        else:
            # Default: just connect and show status
            print("\nConnected! Use Ctrl+C to disconnect")
            await asyncio.sleep(10)

    except KeyboardInterrupt:
        print("\nInterrupted")
    finally:
        await client.disconnect()

    return 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
