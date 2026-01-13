#!/usr/bin/env python3
"""Test if Bluetooth is accessible"""

import sys

print("Testing Bluetooth access...\n")

# Test 1: Import Bleak
try:
    import bleak
    print("[OK] Bleak imported successfully")
except Exception as e:
    print(f"[FAIL] Cannot import Bleak: {e}")
    sys.exit(1)

# Test 2: Check WinRT
try:
    from bleak.backends.winrt import scanner
    print("[OK] WinRT backend available")
except Exception as e:
    print(f"[FAIL] WinRT backend not available: {e}")
    sys.exit(1)

# Test 3: Try to create scanner
try:
    import asyncio
    async def test():
        from bleak import BleakScanner
        scanner = BleakScanner()
        print("[OK] Scanner object created")
        print("[INFO] Attempting to start scan (this tests Bluetooth access)...")
        try:
            await scanner.start()
            print("[OK] Scanner started successfully - Bluetooth IS working!")
            await scanner.stop()
            return True
        except Exception as e:
            print(f"[FAIL] Cannot start scanner: {e}")
            print("\nPossible issues:")
            print("1. No Bluetooth adapter detected by Windows")
            print("2. Bluetooth adapter disabled")
            print("3. Bluetooth drivers not installed")
            print("4. USB Bluetooth dongle not recognized")
            return False

    result = asyncio.run(test())
    sys.exit(0 if result else 1)

except Exception as e:
    print(f"[FAIL] Error during test: {e}")
    import traceback
    traceback.print_exc()
    sys.exit(1)
