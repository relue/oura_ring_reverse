#!/usr/bin/env python3
"""
Long-running scan to catch infrequent Oura Ring advertisements
"""

import asyncio
import sys
from datetime import datetime

from bumble.device import Device
from bumble.host import Host
from bumble.transport import open_transport
from bumble.hci import Address

RING_ADDRESS = "A0:38:F8:43:4E:CB"
IRK = bytes.fromhex("6D83ADB6605E138D2ECDCE758866C6D8")


async def main():
    print("="*60)
    print("Long Scan for Oura Ring (2 minutes)")
    print("Ring should be on finger - looking for slow advertisements")
    print("="*60)

    try:
        async with await open_transport("usb:2357:0604") as (hci_source, hci_sink):
            host = Host(hci_source, hci_sink)
            device = Device(name="Bumble", host=host)
            device.irk = IRK

            await device.power_on()
            print(f"Scanning... (started {datetime.now().strftime('%H:%M:%S')})\n")

            oura_seen = []

            def on_advertisement(advertisement):
                addr = str(advertisement.address)
                name = "?"
                try:
                    n = advertisement.data.get(0x09) or advertisement.data.get(0x08)
                    if n:
                        name = n if isinstance(n, str) else n.decode()
                except:
                    pass

                # Check for Oura or try to resolve RPA
                is_oura = "Oura" in name
                resolved = False

                if advertisement.address.is_resolvable:
                    try:
                        if advertisement.address.resolve(IRK):
                            resolved = True
                            is_oura = True
                    except:
                        pass

                if is_oura:
                    ts = datetime.now().strftime('%H:%M:%S')
                    oura_seen.append((ts, addr, name, resolved))
                    status = "RESOLVED via IRK!" if resolved else f"name={name}"
                    print(f"[{ts}] OURA FOUND: {addr} ({status})")

            device.on('advertisement', on_advertisement)
            await device.start_scanning(active=True)

            # Scan for 2 minutes, printing status every 30 seconds
            for i in range(4):
                await asyncio.sleep(30)
                print(f"... {(i+1)*30}s elapsed, Oura advertisements seen: {len(oura_seen)}")

            await device.stop_scanning()

            print("\n" + "="*60)
            if oura_seen:
                print(f"SUCCESS! Oura Ring advertised {len(oura_seen)} times:")
                for ts, addr, name, resolved in oura_seen:
                    print(f"  [{ts}] {addr}")
            else:
                print("NO Oura Ring advertisements detected in 2 minutes")
                print("Ring may use directed advertising only visible to bonded phone")
            print("="*60)

            return 0 if oura_seen else 1

    except Exception as e:
        print(f"Error: {e}")
        return 1


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
