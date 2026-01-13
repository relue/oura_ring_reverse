#!/usr/bin/env python3
"""
Bond with Oura Ring using Bumble - capture and save all keys
"""

import asyncio
import json
from datetime import datetime
from bumble.device import Device
from bumble.host import Host
from bumble.transport import open_transport
from bumble.pairing import PairingConfig, PairingDelegate

KEYS_FILE = "oura_bond_keys.json"

class SimplePairingDelegate(PairingDelegate):
    def __init__(self):
        super().__init__()

    async def confirm(self, auto=False):
        print("  -> Auto-confirming pairing")
        return True

async def main():
    print("="*60)
    print("Bumble Bonding - Oura Ring")
    print("="*60)
    print("\nPut ring in PAIRING MODE (on charger, hold button)")
    print("="*60)

    async with await open_transport("usb:2357:0604") as (hci_source, hci_sink):
        device = Device(name="BumbleOura", host=Host(hci_source, hci_sink))

        # Configure pairing
        device.pairing_config_factory = lambda conn: PairingConfig(
            bonding=True,
            mitm=False,
            sc=True,
            delegate=SimplePairingDelegate()
        )

        await device.power_on()
        print("Scanning for Oura Ring...")

        oura_addr = None

        def on_ad(ad):
            nonlocal oura_addr
            try:
                n = ad.data.get(0x09) or ad.data.get(0x08)
                if n:
                    name = n if isinstance(n, str) else n.decode()
                    if "Oura" in name and not oura_addr:
                        oura_addr = ad.address
                        print(f"Found: {ad.address} - {name}")
            except:
                pass

        device.on('advertisement', on_ad)
        await device.start_scanning()

        for i in range(20):
            if oura_addr:
                break
            await asyncio.sleep(1)

        await device.stop_scanning()

        if not oura_addr:
            print("ERROR: Oura Ring not found")
            return 1

        print(f"\nConnecting to {oura_addr}...")

        # Set up pairing event handlers
        keys_data = {"address": str(oura_addr), "timestamp": datetime.now().isoformat(), "keys": {}}
        pairing_done = asyncio.Event()

        def on_pairing(keys):
            print(f"\n*** PAIRING COMPLETE ***")
            if keys:
                print(f"Keys: {keys}")
                if hasattr(keys, 'ltk') and keys.ltk:
                    keys_data["keys"]["ltk"] = keys.ltk.value.hex().upper()
                    print(f"  LTK: {keys_data['keys']['ltk']}")
                if hasattr(keys, 'irk') and keys.irk:
                    keys_data["keys"]["irk"] = keys.irk.value.hex().upper()
                    print(f"  IRK: {keys_data['keys']['irk']}")
                if hasattr(keys, 'ltk_peer') and keys.ltk_peer:
                    keys_data["keys"]["ltk_peer"] = keys.ltk_peer.value.hex().upper()
                    print(f"  LTK_PEER: {keys_data['keys']['ltk_peer']}")
                if hasattr(keys, 'irk_peer') and keys.irk_peer:
                    keys_data["keys"]["irk_peer"] = keys.irk_peer.value.hex().upper()
                    print(f"  IRK_PEER: {keys_data['keys']['irk_peer']}")
            pairing_done.set()

        def on_pairing_failure(reason):
            print(f"\n*** PAIRING FAILED: {reason} ***")
            pairing_done.set()

        device.on('pairing', on_pairing)
        device.on('pairing_failure', on_pairing_failure)

        try:
            connection = await asyncio.wait_for(
                device.connect(oura_addr),
                timeout=30.0
            )
            print(f"Connected! Handle: {connection.handle}")

            # Also listen on connection level
            connection.on('pairing', on_pairing)
            connection.on('pairing_failure', on_pairing_failure)

            # Immediately initiate pairing
            print("\nInitiating pairing immediately...")
            try:
                await connection.pair()
                print("Pair call returned")
            except Exception as e:
                print(f"Pair exception: {e}")

            # Wait for pairing event
            try:
                await asyncio.wait_for(pairing_done.wait(), timeout=10.0)
            except asyncio.TimeoutError:
                print("No pairing event received")

            # Check keystore
            print("\nChecking keystore...")
            if device.keystore:
                try:
                    all_keys = await device.keystore.get_all()
                    print(f"All stored keys: {all_keys}")
                    for addr, keys in all_keys.items():
                        print(f"  {addr}: {keys}")
                        if hasattr(keys, 'ltk') and keys.ltk:
                            keys_data["keys"]["ltk"] = keys.ltk.value.hex().upper()
                        if hasattr(keys, 'irk') and keys.irk:
                            keys_data["keys"]["irk"] = keys.irk.value.hex().upper()
                except Exception as e:
                    print(f"Keystore error: {e}")

            # Save what we have
            with open(KEYS_FILE, 'w') as f:
                json.dump(keys_data, f, indent=2)
            print(f"\nSaved to {KEYS_FILE}")

            await asyncio.sleep(2)

            try:
                await connection.disconnect()
            except:
                pass

            return 0 if keys_data["keys"] else 1

        except Exception as e:
            print(f"Error: {e}")
            import traceback
            traceback.print_exc()
            return 1

if __name__ == "__main__":
    asyncio.run(main())
