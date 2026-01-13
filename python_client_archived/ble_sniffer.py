#!/usr/bin/env python3
"""
BLE Sniffer - Captures ALL advertisements
Run: python ble_sniffer.py > /tmp/ble_sniffer.log 2>&1 &
"""

import asyncio
from bleak import BleakScanner
from datetime import datetime
import sys

ADAPTER = "hci1"  # TP-Link

seen_devices = {}
oura_found = False

def callback(device, adv):
    global oura_found
    addr = device.address
    now = datetime.now().strftime('%H:%M:%S.%f')[:-3]

    # Track devices
    if addr not in seen_devices:
        seen_devices[addr] = {'count': 0, 'name': device.name}
    seen_devices[addr]['count'] += 1

    name = device.name or ''
    rssi = adv.rssi if hasattr(adv, 'rssi') else 0
    mfr_keys = list(adv.manufacturer_data.keys()) if adv.manufacturer_data else []

    # Highlight Oura Ring
    if 'Oura' in name or (690 in mfr_keys):  # 690 = 0x02b2 = Oura manufacturer ID
        marker = ' *** OURA ***'
        oura_found = True
    else:
        marker = ''

    # Print advertisement
    line = f'{now} | {addr} | {rssi:4}dBm | {name[:25]:25} | mfr:{mfr_keys}{marker}'
    print(line, flush=True)

async def main():
    print(f'=== BLE SNIFFER - Adapter: {ADAPTER} ===', flush=True)
    print(f'Started: {datetime.now()}', flush=True)
    print('Watching for ALL advertisements... (Oura will be highlighted)', flush=True)
    print('=' * 90, flush=True)

    scanner = BleakScanner(callback, adapter=ADAPTER)

    try:
        await scanner.start()
        # Run indefinitely
        while True:
            await asyncio.sleep(60)
            # Periodic summary
            print(f'\n--- {datetime.now().strftime("%H:%M:%S")} | {len(seen_devices)} unique devices | Oura found: {oura_found} ---\n', flush=True)
    except KeyboardInterrupt:
        pass
    finally:
        await scanner.stop()
        print(f'\n=== FINAL: {len(seen_devices)} devices seen ===', flush=True)

if __name__ == '__main__':
    asyncio.run(main())
