#!/usr/bin/env python3
"""
Oura Ring Gen 3 BLE Heartbeat Monitor
Uses Bleak library to communicate with Oura Ring and display live BPM data

Protocol verified from reverse engineering with Frida instrumentation
"""

import asyncio
import sys
from bleak import BleakClient, BleakScanner
from bleak.exc import BleakError

# Oura Ring BLE UUIDs
SERVICE_UUID = "98ed0001-a541-11e4-b6a0-0002a5d5c51b"
WRITE_CHAR_UUID = "98ed0002-a541-11e4-b6a0-0002a5d5c51b"
NOTIFY_CHAR_UUID = "98ed0003-a541-11e4-b6a0-0002a5d5c51b"

# Known Oura Ring MAC address
OURA_MAC = "4B:DD:91:1C:33:61"

# Initialization commands (verified from protocol analysis)
CMD_INIT_1 = bytes([0x2f, 0x02, 0x20, 0x02])
CMD_INIT_2 = bytes([0x2f, 0x03, 0x22, 0x02, 0x03])
CMD_START_STREAM = bytes([0x2f, 0x03, 0x26, 0x02, 0x02])
CMD_STOP = bytes([0x2f, 0x03, 0x22, 0x02, 0x01])


def parse_heartbeat(data):
    """
    Parse heartbeat packet and extract BPM

    Packet format (17 bytes):
    Offset:  0   1   2   3   4   5   6   7   8      9      10  11  12  13  14  15  16
    Data:   2f  0f  28  02  XX  02  00  00 [IBI_L] [IBI_H] 00  00  00  00  YY  ZZ  7f

    IBI (Inter-Beat Interval) is in milliseconds, stored as 12-bit little-endian
    BPM = 60000 / IBI

    Args:
        data: Byte array from BLE notification

    Returns:
        tuple: (ibi_ms, bpm, flag_byte) or None if not a heartbeat packet
    """
    if len(data) < 10:
        return None

    # Check if this is a heartbeat packet (starts with 2f 0f 28)
    if data[0] != 0x2f or data[1] != 0x0f or data[2] != 0x28:
        return None

    # Extract IBI from bytes 8-9 (12-bit little-endian)
    ibi_low = data[8] & 0xFF
    ibi_high = data[9] & 0x0F  # Only lower 4 bits
    ibi_ms = (ibi_high << 8) | ibi_low

    # Calculate BPM
    if ibi_ms == 0:
        return None
    bpm = 60000.0 / ibi_ms

    # Extract flag byte (changes between packets)
    flag = data[4] if len(data) > 4 else 0

    return (ibi_ms, bpm, flag)


def format_hex(data):
    """Format byte array as hex string"""
    return ' '.join(f'{b:02x}' for b in data)


class OuraHeartbeatMonitor:
    """Oura Ring BLE Heartbeat Monitor"""

    def __init__(self, mac_address=OURA_MAC):
        self.mac_address = mac_address
        self.client = None
        self.heartbeat_count = 0

    async def find_device(self):
        """Scan for Oura Ring"""
        print(f"🔍 Scanning for Oura Ring ({self.mac_address})...")

        devices = await BleakScanner.discover(timeout=10.0)

        for device in devices:
            if device.address.upper() == self.mac_address.upper():
                print(f"✓ Found Oura Ring: {device.name} ({device.address})")
                return device

        return None

    async def notification_handler(self, sender, data):
        """Handle BLE notifications from the ring"""
        result = parse_heartbeat(data)

        if result:
            ibi_ms, bpm, flag = result
            self.heartbeat_count += 1

            # Display heartbeat
            print(f"\n┌{'─' * 58}┐")
            print(f"│  💓 HEARTBEAT #{self.heartbeat_count:<44}│")
            print(f"├{'─' * 58}┤")
            print(f"│  BPM: {bpm:>6.1f} BPM{' ' * 42}│")
            print(f"│  IBI: {ibi_ms:>6} ms{' ' * 43}│")
            print(f"│  Flag: 0x{flag:02x}{' ' * 49}│")
            print(f"└{'─' * 58}┘")
        else:
            # Non-heartbeat packet (ACK, status, etc.)
            print(f"[INFO] Received: {format_hex(data)}")

    async def send_command(self, command, description):
        """Send command and wait briefly for response"""
        print(f"📤 Sending {description}: {format_hex(command)}")
        await self.client.write_gatt_char(WRITE_CHAR_UUID, command)
        await asyncio.sleep(0.5)  # Wait for ACK

    async def start_monitoring(self):
        """Connect to ring and start heartbeat monitoring"""
        try:
            # Find the device
            device = await self.find_device()
            if not device:
                print(f"❌ Oura Ring not found. Make sure it's powered on and nearby.")
                return False

            # Connect
            print(f"\n🔗 Connecting to {device.address}...")
            async with BleakClient(device.address) as client:
                self.client = client
                print(f"✓ Connected!")

                # Subscribe to notifications
                print(f"\n🔔 Subscribing to notifications...")
                await client.start_notify(NOTIFY_CHAR_UUID, self.notification_handler)
                print(f"✓ Subscribed!")

                # Send initialization sequence
                print(f"\n🚀 Starting heartbeat monitoring...")
                await self.send_command(CMD_INIT_1, "Init command 1")
                await self.send_command(CMD_INIT_2, "Init command 2")
                await self.send_command(CMD_START_STREAM, "Start streaming")

                print(f"\n✓ Heartbeat monitoring active! Press Ctrl+C to stop.\n")
                print(f"{'=' * 60}")

                # Keep running until interrupted
                try:
                    while True:
                        await asyncio.sleep(1)
                except KeyboardInterrupt:
                    print(f"\n\n🛑 Stopping monitoring...")

                # Send stop command
                await self.send_command(CMD_STOP, "Stop command")
                await client.stop_notify(NOTIFY_CHAR_UUID)

                print(f"\n✓ Disconnected. Total heartbeats received: {self.heartbeat_count}")
                return True

        except BleakError as e:
            print(f"❌ Bluetooth error: {e}")
            return False
        except Exception as e:
            print(f"❌ Error: {e}")
            import traceback
            traceback.print_exc()
            return False


async def main():
    """Main entry point"""
    print("╔════════════════════════════════════════════════════════════╗")
    print("║           OURA RING GEN 3 HEARTBEAT MONITOR              ║")
    print("╚════════════════════════════════════════════════════════════╝")
    print()

    monitor = OuraHeartbeatMonitor(OURA_MAC)
    success = await monitor.start_monitoring()

    return 0 if success else 1


if __name__ == "__main__":
    try:
        exit_code = asyncio.run(main())
        sys.exit(exit_code)
    except KeyboardInterrupt:
        print("\n\n👋 Goodbye!")
        sys.exit(0)
