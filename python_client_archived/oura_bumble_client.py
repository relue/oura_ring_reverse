#!/usr/bin/env python3
"""
Oura Ring BLE Client using Google Bumble
Works when ring is on finger (after bonding)

Usage:
    # First time: stop BlueZ
    sudo systemctl stop bluetooth

    # Run client (no sudo needed after udev rule)
    python oura_bumble_client.py --heartbeat
    python oura_bumble_client.py --get-data
"""

import asyncio
import argparse
import sys
import struct
import time
import json
from datetime import datetime
from pathlib import Path
from typing import Optional, Callable

from bumble.device import Device, Connection, Peer
from bumble.host import Host
from bumble.transport import open_transport
from bumble.keys import PairingKeys, JsonKeyStore
from bumble.hci import Address, OwnAddressType
import os
import glob

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

# USB transport for TP-Link BT5 adapter
USB_TRANSPORT = "usb:2357:0604"

# Keys from BlueZ bond
IRK = bytes.fromhex("6D83ADB6605E138D2ECDCE758866C6D8")
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


class OuraBumbleClient:
    def __init__(self, auth_key: Optional[bytes] = None):
        self.auth_key = auth_key or self._load_auth_key() or DEFAULT_AUTH_KEY
        self.device: Optional[Device] = None
        self.connection: Optional[Connection] = None
        self.peer: Optional[Peer] = None
        self.write_char = None
        self.notify_char = None
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

    def _load_bluez_keys(self) -> Optional[dict]:
        """Load bonding keys from BlueZ for the Oura Ring"""
        try:
            # Find BlueZ bond files
            pattern = "/var/lib/bluetooth/*/A0:38:F8:43:4E:CB/info"
            files = glob.glob(pattern)
            if not files:
                print("No BlueZ bond found for Oura Ring")
                return None

            # Parse the info file
            keys = {}
            with open(files[0], 'r') as f:
                section = None
                for line in f:
                    line = line.strip()
                    if line.startswith('[') and line.endswith(']'):
                        section = line[1:-1]
                    elif '=' in line and section:
                        key, value = line.split('=', 1)
                        if section == 'IdentityResolvingKey' and key == 'Key':
                            keys['irk'] = bytes.fromhex(value)
                        elif section == 'PeripheralLongTermKey' and key == 'Key':
                            keys['ltk'] = bytes.fromhex(value)

            if 'irk' in keys and 'ltk' in keys:
                print(f"Loaded BlueZ keys:")
                print(f"  IRK: {keys['irk'].hex()}")
                print(f"  LTK: {keys['ltk'].hex()}")
                return keys
        except Exception as e:
            print(f"Error loading BlueZ keys: {e}")
        return None

    async def connect(self, timeout: float = 30.0) -> bool:
        """Connect to Oura Ring using Bumble"""

        # Load BlueZ bond keys first
        self.bluez_keys = self._load_bluez_keys()

        print("Opening USB transport...")

        try:
            transport = await open_transport(USB_TRANSPORT)
            hci_source, hci_sink = transport

            # Use the same address as the BlueZ bond for proper reconnection
            adapter_addr = Address("0C:EF:15:5E:0D:F1", Address.PUBLIC_DEVICE_ADDRESS)
            self.device = Device(name="OuraBumble", address=adapter_addr, host=Host(hci_source, hci_sink))
            self.device.irk = IRK
            # Create keystore explicitly
            self.device.keystore = JsonKeyStore(namespace="oura_bumble")
            print(f"Using adapter address: {adapter_addr}")

            await self.device.power_on()
            print("Bluetooth powered on")

            # Configure keystore with BlueZ keys
            if self.bluez_keys:
                ring_addr = "A0:38:F8:43:4E:CB"
                pairing_keys = PairingKeys()
                pairing_keys.ltk = PairingKeys.Key(value=self.bluez_keys['ltk'])
                pairing_keys.irk = PairingKeys.Key(value=self.bluez_keys['irk'])

                # Store keys in device keystore
                await self.device.keystore.update(ring_addr, pairing_keys)
                print(f"Configured keystore with BlueZ keys for {ring_addr}")

            # Set up address resolver with ring's IRK
            from bumble.smp import AddressResolver
            ring_identity = Address("A0:38:F8:43:4E:CB", Address.PUBLIC_DEVICE_ADDRESS)
            resolver = AddressResolver([(self.bluez_keys['irk'], ring_identity)]) if self.bluez_keys else None

            # Scan for ring
            print("Scanning for Oura Ring...")
            oura_addr = None
            ad_count = 0

            seen_addresses = set()

            def on_ad(ad):
                nonlocal oura_addr, ad_count
                ad_count += 1
                addr_str = str(ad.address)

                # Log unique addresses with names (first 15)
                if addr_str not in seen_addresses and len(seen_addresses) < 15:
                    seen_addresses.add(addr_str)
                    # Get name and address type
                    name = None
                    try:
                        n = ad.data.get(0x09) or ad.data.get(0x08)
                        if n:
                            name = n if isinstance(n, str) else n.decode()
                    except:
                        pass
                    addr_type = ad.address.address_type if hasattr(ad.address, 'address_type') else 'unknown'
                    print(f"  #{len(seen_addresses)}: {addr_str} type={addr_type} name={name}")

                try:
                    # First try IRK resolution (only for random addresses)
                    if resolver and not oura_addr:
                        resolved = resolver.resolve(ad.address)
                        if resolved:
                            oura_addr = ad.address
                            print(f"  Found by IRK: {ad.address} -> {resolved}")
                            return

                    # Fallback to name matching
                    n = ad.data.get(0x09) or ad.data.get(0x08)
                    if n:
                        name = n if isinstance(n, str) else n.decode()
                        if "Oura" in name and not oura_addr:
                            oura_addr = ad.address
                            print(f"  Found by name: {ad.address} - {name}")
                except Exception as e:
                    if ad_count < 5:
                        print(f"  Error processing ad: {e}")

            self.device.on('advertisement', on_ad)
            await self.device.start_scanning()

            start = time.time()
            while not oura_addr and (time.time() - start) < timeout:
                await asyncio.sleep(0.5)
                # Print progress every 5 seconds
                elapsed = time.time() - start
                if int(elapsed) % 5 == 0 and int(elapsed) > 0:
                    print(f"  ...scanning ({int(elapsed)}s, {ad_count} ads received)")

            await self.device.stop_scanning()
            print(f"  Scan complete. Received {ad_count} advertisements.")

            if not oura_addr:
                print("ERROR: Oura Ring not found (try moving the ring to wake it up)")
                return False

            # Store keys under RPA address BEFORE connecting (so encrypt can find them)
            if self.bluez_keys:
                rpa_addr = str(oura_addr)
                pairing_keys = PairingKeys()
                pairing_keys.ltk = PairingKeys.Key(value=self.bluez_keys['ltk'])
                pairing_keys.irk = PairingKeys.Key(value=self.bluez_keys['irk'])
                await self.device.keystore.update(rpa_addr, pairing_keys)
                print(f"Pre-stored keys for RPA: {rpa_addr}")

            # Connect using PUBLIC address (must match BlueZ bond)
            print(f"Connecting to {oura_addr}...")
            self.connection = await asyncio.wait_for(
                self.device.connect(oura_addr, own_address_type=OwnAddressType.PUBLIC),
                timeout=30.0
            )
            print(f"Connected! Handle: {self.connection.handle}")

            # Encrypt immediately (keys already stored before connection)
            print("Encrypting connection...")
            try:
                await self.connection.encrypt()
                print("  Encryption enabled!")
            except Exception as e:
                print(f"  Encryption error: {e}")
                return False

            # Discover services
            print("Discovering services...")
            self.peer = Peer(self.connection)
            await self.peer.discover_services()
            print(f"Found {len(self.peer.services)} services")

            # Find Oura service
            for service in self.peer.services:
                print(f"  Service: {service.uuid}")
                if str(service.uuid).lower() == SERVICE_UUID.lower():
                    print(f"Found Oura service! Discovering characteristics...")
                    # Discover characteristics for this service
                    await self.peer.discover_characteristics(service)
                    print(f"  Found {len(service.characteristics)} characteristics")
                    for char in service.characteristics:
                        uuid = str(char.uuid).lower()
                        print(f"    Char: {char.uuid}")
                        if uuid == WRITE_CHAR_UUID.lower():
                            self.write_char = char
                            print(f"    -> Write char!")
                        elif uuid == NOTIFY_CHAR_UUID.lower():
                            self.notify_char = char
                            print(f"    -> Notify char!")

            if not self.write_char or not self.notify_char:
                print("ERROR: Required characteristics not found")
                return False

            # Subscribe to notifications
            print("Subscribing to notifications...")
            await self.peer.subscribe(self.notify_char, self._on_notification)
            print("Subscribed!")

            return True

        except Exception as e:
            print(f"Connection error: {e}")
            import traceback
            traceback.print_exc()
            return False

    def _on_notification(self, data: bytes):
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
                print(f"💓 Heartbeat: {bpm} BPM (quality: {quality})")
        else:
            if self.event_callback:
                self.event_callback(data)
            else:
                print(f"Event: {event_name} - {data.hex()}")

    async def send_command(self, cmd: bytes, wait_response: bool = True) -> Optional[bytes]:
        """Send command and optionally wait for response"""
        if not self.write_char or not self.peer:
            return None

        self.response_event.clear()
        await self.peer.write(self.write_char, cmd)

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
            print("✓ Authentication successful!")
            self.is_authenticated = True
            return True
        else:
            print("✗ Authentication failed")
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

        print("💓 Waiting for heartbeat data...\n")
        await asyncio.sleep(duration)

        await self.send_command(CMD_STOP)
        print("\nStopped heartbeat monitoring")

    async def disconnect(self):
        """Disconnect from ring"""
        if self.connection:
            try:
                await self.connection.disconnect()
            except:
                pass
        print("Disconnected")


async def main():
    parser = argparse.ArgumentParser(description="Oura Ring BLE Client (Bumble)")
    parser.add_argument("--heartbeat", action="store_true", help="Monitor heartbeat")
    parser.add_argument("--duration", type=int, default=60, help="Duration in seconds")
    parser.add_argument("--auth-key", help="Auth key (32 hex chars)")
    args = parser.parse_args()

    auth_key = bytes.fromhex(args.auth_key) if args.auth_key else None
    client = OuraBumbleClient(auth_key=auth_key)

    try:
        if not await client.connect():
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
    # Check if BlueZ is running
    import subprocess
    result = subprocess.run(["systemctl", "is-active", "bluetooth"], capture_output=True)
    if result.stdout.strip() == b"active":
        print("WARNING: BlueZ is running. Stop it first:")
        print("  sudo systemctl stop bluetooth")
        print()

    sys.exit(asyncio.run(main()))
