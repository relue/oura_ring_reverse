#!/usr/bin/env python3
"""
Motion test - detect when Oura Ring advertises
Keep hand STILL for first 60 seconds, then MOVE
"""

import asyncio
from datetime import datetime
from bumble.device import Device
from bumble.host import Host
from bumble.transport import open_transport

IRK = bytes.fromhex("6D83ADB6605E138D2ECDCE758866C6D8")
LTK = bytes.fromhex("564F303F87ADB6E73E4A474EC9C27EE5")
RING_ADDR = "A0:38:F8:43:4E:CB"

async def main():
    print("="*60)
    print("MOTION TEST - Oura Ring Advertisement Detection")
    print("="*60)
    print("\nINSTRUCTIONS:")
    print("  0-60 sec:  Keep hand COMPLETELY STILL")
    print("  60-120 sec: MOVE your hand / wave it around")
    print("="*60)

    async with await open_transport("usb:2357:0604") as (hci_source, hci_sink):
        device = Device(name="Bumble", host=Host(hci_source, hci_sink))
        device.irk = IRK
        await device.power_on()

        start_time = datetime.now()
        oura_events = []

        def on_ad(ad):
            name = ""
            try:
                n = ad.data.get(0x09) or ad.data.get(0x08)
                if n:
                    name = n if isinstance(n, str) else n.decode()
            except:
                pass

            # Check for Oura or resolve RPA
            is_oura = "Oura" in name
            if ad.address.is_resolvable:
                try:
                    if ad.address.resolve(IRK):
                        is_oura = True
                except:
                    pass

            if is_oura:
                elapsed = (datetime.now() - start_time).total_seconds()
                phase = "STILL" if elapsed < 60 else "MOVING"
                ts = datetime.now().strftime('%H:%M:%S')
                print(f"[{ts}] ({elapsed:5.1f}s) [{phase}] OURA DETECTED: {ad.address}")
                oura_events.append((elapsed, phase))

        device.on('advertisement', on_ad)
        await device.start_scanning()

        print(f"\nStarted at {datetime.now().strftime('%H:%M:%S')}")
        print("Scanning... (ring on finger, hand STILL)\n")

        # Phase 1: Still (60 sec)
        await asyncio.sleep(60)
        print("\n" + "="*60)
        print(">>> NOW MOVE YOUR HAND! Wave it, shake it! <<<")
        print("="*60 + "\n")

        # Phase 2: Moving (60 sec)
        await asyncio.sleep(60)

        await device.stop_scanning()

        # Results
        print("\n" + "="*60)
        print("RESULTS:")
        still_count = sum(1 for e in oura_events if e[1] == "STILL")
        move_count = sum(1 for e in oura_events if e[1] == "MOVING")
        print(f"  STILL phase (0-60s):   {still_count} advertisements")
        print(f"  MOVING phase (60-120s): {move_count} advertisements")
        print("="*60)

        if move_count > still_count:
            print("✓ THEORY CONFIRMED: Motion triggers ring advertising!")
        elif still_count == 0 and move_count == 0:
            print("✗ No advertisements detected in either phase")
        else:
            print("? Results inconclusive")

if __name__ == "__main__":
    asyncio.run(main())
