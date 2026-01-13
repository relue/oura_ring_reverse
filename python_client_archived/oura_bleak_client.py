#!/usr/bin/env python3
"""
Oura Ring BLE Client using Bleak (BlueZ D-Bus)
Works with existing BlueZ bonds - no manual key management needed.

Usage:
    python oura_bleak_client.py --heartbeat
    python oura_bleak_client.py --get-data
"""

import asyncio
import argparse
import sys
import struct
from datetime import datetime
from pathlib import Path
from typing import Optional, Callable

from bleak import BleakClient, BleakScanner
from bleak.backends.device import BLEDevice
from bleak.backends.scanner import AdvertisementData

try:
    from Crypto.Cipher import AES
except ImportError:
    print("Warning: pycryptodome not installed. Run: pip install pycryptodome")
    AES = None

# ============================================================================
# CONSTANTS
# ============================================================================

SERVICE_UUID = "98ed0001-a541-11e4-b6a0-0002a5d5c51b"
WRITE_CHAR_UUID = "98ed0002-a541-11e4-b6a0-0002a5d5c51b"
NOTIFY_CHAR_UUID = "98ed0003-a541-11e4-b6a0-0002a5d5c51b"

# TP-Link UB500 adapter
ADAPTER = "hci1"  # or "0C:EF:15:5E:0D:F1"

# Auth key from bonding
DEFAULT_AUTH_KEY = bytes.fromhex("00426ed816dcece48dd9968c1f36c0b5")

# Commands
CMD_GET_AUTH_NONCE = bytes([0x2f, 0x01, 0x2b])
CMD_INIT_1 = bytes([0x2f, 0x02, 0x20, 0x02])
CMD_INIT_2 = bytes([0x2f, 0x03, 0x22, 0x02, 0x03])
CMD_START_STREAM = bytes([0x2f, 0x03, 0x26, 0x02, 0x02])
CMD_STOP = bytes([0x2f, 0x03, 0x22, 0x02, 0x01])

# Event types
EVENT_TYPES = {
    0x2f: "CMD_RESPONSE",
    0x41: "RING_START_IND",
    0x44: "PPG_SAMPLE",
    0x45: "ACCEL_SAMPLE",
    0x46: "GYRO_SAMPLE",
    0x47: "TEMP_SAMPLE",
    0x51: "SLEEP_PERIOD_INFO",
    0x52: "SLEEP_ANALYSIS_INFO",
    0x5a: "HEARTBEAT",
}


def oura_filter(device: BLEDevice, adv: AdvertisementData) -> bool:
    """Filter for Oura Ring devices"""
    if device.name and "Oura" in device.name:
        return True
    # Also check for Oura service UUID in advertisement
    if SERVICE_UUID.lower() in [str(u).lower() for u in adv.service_uuids]:
        return True
    return False


class OuraBleakClient:
    def __init__(self, auth_key: Optional[bytes] = None, adapter: str = ADAPTER):
        self.auth_key = auth_key or self._load_auth_key() or DEFAULT_AUTH_KEY
        self.adapter = adapter
        self.client: Optional[BleakClient] = None
        self.device: Optional[BLEDevice] = None
        self.response_event = asyncio.Event()
        self.last_response: bytes = b""
        self.event_callback: Optional[Callable] = None
        self.is_authenticated = False

    def _load_auth_key(self) -> Optional[bytes]:
        try:
            path = Path("stored_auth_key.bin")
            if path.exists():
                return path.read_bytes()
        except:
            pass
        return None

    def _notification_handler(self, sender, data: bytes):
        """Handle incoming notifications"""
        if len(data) == 0:
            return

        event_type = data[0]
        event_name = EVENT_TYPES.get(event_type, f"UNKNOWN_{hex(event_type)}")

        if event_type == 0x2f:  # Command response
            self.last_response = data
            self.response_event.set()
        elif event_type == 0x5a:  # Heartbeat
            if len(data) >= 4:
                bpm = data[2]
                quality = data[3] if len(data) > 3 else 0
                print(f"Heartbeat: {bpm} BPM (quality: {quality})")
        else:
            if self.event_callback:
                self.event_callback(data)
            else:
                print(f"Event: {event_name} - {data.hex()}")

    async def connect(self, timeout: float = 60.0) -> bool:
        """Connect to Oura Ring using Bleak (BlueZ handles bonding/encryption)"""

        print(f"Scanning for Oura Ring (adapter: {self.adapter})...")

        try:
            # Scan for Oura Ring by name/service UUID
            self.device = await BleakScanner.find_device_by_filter(
                oura_filter,
                timeout=timeout,
                adapter=self.adapter
            )

            if not self.device:
                print("ERROR: Oura Ring not found. Try moving the ring to trigger advertising.")
                return False

            print(f"Found: {self.device.address} - {self.device.name}")

            # Connect with pair=True (uses existing bond or pairs if needed)
            print("Connecting...")
            self.client = BleakClient(
                self.device,
                adapter=self.adapter,
                timeout=30.0
            )

            await self.client.connect()
            print(f"Connected! (paired: {self.client.is_connected})")

            # BlueZ should handle encryption automatically for bonded devices

            # Subscribe to notifications
            print("Subscribing to notifications...")
            await self.client.start_notify(NOTIFY_CHAR_UUID, self._notification_handler)
            print("Subscribed!")

            return True

        except Exception as e:
            print(f"Connection error: {e}")
            import traceback
            traceback.print_exc()
            return False

    async def send_command(self, cmd: bytes, wait_response: bool = True) -> Optional[bytes]:
        """Send command and optionally wait for response"""
        if not self.client or not self.client.is_connected:
            return None

        self.response_event.clear()
        await self.client.write_gatt_char(WRITE_CHAR_UUID, cmd)

        if wait_response:
            try:
                await asyncio.wait_for(self.response_event.wait(), timeout=5.0)
                return self.last_response
            except asyncio.TimeoutError:
                return None
        return b""

    async def authenticate(self) -> bool:
        """Authenticate with the ring"""
        if not AES:
            print("ERROR: pycryptodome required for authentication")
            return False

        print("Authenticating...")

        # Get nonce
        response = await self.send_command(CMD_GET_AUTH_NONCE)
        if not response or len(response) < 19:
            print("ERROR: Failed to get auth nonce")
            return False

        nonce = response[3:19]
        print(f"  Nonce: {nonce.hex()}")

        # Encrypt nonce with auth key
        cipher = AES.new(self.auth_key, AES.MODE_ECB)
        encrypted = cipher.encrypt(nonce)
        print(f"  Encrypted: {encrypted.hex()}")

        # Send auth response
        auth_cmd = bytes([0x2f, 0x11, 0x2c]) + encrypted
        response = await self.send_command(auth_cmd)

        if response and len(response) >= 4 and response[3] == 0x01:
            print("Authentication successful!")
            self.is_authenticated = True
            return True
        else:
            print("Authentication failed")
            return False

    async def start_heartbeat(self, duration: int = 60):
        """Start heartbeat monitoring"""
        if not self.is_authenticated:
            if not await self.authenticate():
                return

        print(f"\nStarting heartbeat monitoring ({duration}s)...")
        await self.send_command(CMD_INIT_1)
        await self.send_command(CMD_INIT_2)
        await self.send_command(CMD_START_STREAM)

        print("Waiting for heartbeat data...\n")
        await asyncio.sleep(duration)

        await self.send_command(CMD_STOP)
        print("\nStopped heartbeat monitoring")

    async def disconnect(self):
        """Disconnect from ring"""
        if self.client and self.client.is_connected:
            try:
                await self.client.disconnect()
            except:
                pass
        print("Disconnected")


async def main():
    parser = argparse.ArgumentParser(description="Oura Ring BLE Client (Bleak)")
    parser.add_argument("--heartbeat", action="store_true", help="Monitor heartbeat")
    parser.add_argument("--duration", type=int, default=60, help="Duration in seconds")
    parser.add_argument("--auth-key", help="Auth key (32 hex chars)")
    parser.add_argument("--adapter", default=ADAPTER, help=f"Bluetooth adapter (default: {ADAPTER})")
    parser.add_argument("--scan-timeout", type=int, default=60, help="Scan timeout in seconds")
    args = parser.parse_args()

    auth_key = bytes.fromhex(args.auth_key) if args.auth_key else None
    client = OuraBleakClient(auth_key=auth_key, adapter=args.adapter)

    try:
        if not await client.connect(timeout=args.scan_timeout):
            return 1

        if args.heartbeat:
            await client.start_heartbeat(args.duration)
        else:
            # Just connect and show we're connected
            print("\nConnected! Press Ctrl+C to disconnect")
            await asyncio.sleep(10)

    except KeyboardInterrupt:
        print("\nInterrupted")
    finally:
        await client.disconnect()

    return 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
