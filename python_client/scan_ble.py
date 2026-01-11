#!/usr/bin/env python3
"""
BLE Scanner - Find all Bluetooth LE devices
Useful for checking if Oura Ring is advertising
"""

import sys

# FIX for Python 3.14 + WinRT threading issue
# Must be set BEFORE importing anything that uses pythoncom/WinRT
if sys.platform == 'win32':
    sys.coinit_flags = 0  # Force Multi-Threaded Apartment (MTA)

import asyncio
from bleak import BleakScanner

async def scan():
    print("Scanning for BLE devices...")
    print("This will take 10 seconds...\n")

    devices = await BleakScanner.discover(timeout=10.0)

    print(f"Found {len(devices)} BLE devices:\n")
    print(f"{'Address':<20} {'Name':<30} {'RSSI':<6}")
    print("-" * 60)

    oura_found = False
    for device in devices:
        name = device.name if device.name else "(Unknown)"
        rssi = device.rssi if hasattr(device, 'rssi') else "N/A"

        # Highlight Oura Ring if found
        if "oura" in name.lower() or device.address.upper() == "4B:DD:91:1C:33:61":
            print(f">>> {device.address:<20} {name:<30} {rssi} <<<")
            oura_found = True
        else:
            print(f"    {device.address:<20} {name:<30} {rssi}")

    print("-" * 60)

    if oura_found:
        print("\n[OK] Oura Ring found! You can proceed with pairing.")
    else:
        print("\n[NOT FOUND] Oura Ring (4B:DD:91:1C:33:61) NOT found.")
        print("\nTroubleshooting:")
        print("1. Disconnect ring from phone (Oura app or Android Bluetooth)")
        print("2. Make sure ring is charged")
        print("3. Keep ring close to computer")
        print("4. Ring might need to be on your finger or off charger")

if __name__ == "__main__":
    asyncio.run(scan())
