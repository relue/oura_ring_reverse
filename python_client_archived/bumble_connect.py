#!/usr/bin/env python3
"""
Connect to Oura Ring using Google Bumble with Controller Resolving List
"""

import asyncio
import sys

from bumble.device import Device
from bumble.host import Host
from bumble.transport import open_transport
from bumble.hci import Address, HCI_Command, HCI_LE_Add_Device_To_Resolving_List_Command

# Ring identity address (from BlueZ bond)
RING_ADDRESS = "A0:38:F8:43:4E:CB"

# IRK for RPA resolution (from BlueZ bond)
IRK = bytes.fromhex("6D83ADB6605E138D2ECDCE758866C6D8")

# Our local IRK (can be random for now)
LOCAL_IRK = bytes(16)  # All zeros - we don't use RPA ourselves


async def main():
    print("="*60)
    print("Bumble - Resolving List Connection Test")
    print("="*60)

    transport_name = "usb:2357:0604"

    try:
        async with await open_transport(transport_name) as (hci_source, hci_sink):
            print("Transport opened")

            host = Host(hci_source, hci_sink)
            device = Device(name="Bumble", host=host)

            await device.power_on()
            print("Device powered on")

            # Step 1: Clear resolving list
            print("\n--- Setting up Resolving List ---")
            try:
                await host.send_command(HCI_Command(0x2029))  # LE_Clear_Resolving_List
                print("Cleared resolving list")
            except Exception as e:
                print(f"Clear resolving list: {e}")

            # Step 2: Add ring to resolving list with its IRK
            print(f"Adding ring {RING_ADDRESS} with IRK to resolving list...")
            try:
                # HCI_LE_Add_Device_To_Resolving_List command
                # Peer address type: 0x00 = Public
                # Peer identity address: 6 bytes (little endian)
                # Peer IRK: 16 bytes
                # Local IRK: 16 bytes
                addr_bytes = bytes.fromhex(RING_ADDRESS.replace(":", ""))[::-1]  # Little endian

                cmd = HCI_LE_Add_Device_To_Resolving_List_Command(
                    peer_identity_address_type=0,  # Public
                    peer_identity_address=Address(RING_ADDRESS),
                    peer_irk=IRK,
                    local_irk=LOCAL_IRK
                )
                await host.send_command(cmd)
                print("Added to resolving list!")
            except Exception as e:
                print(f"Add to resolving list error: {e}")

            # Step 3: Enable address resolution
            print("Enabling address resolution...")
            try:
                await host.send_command(HCI_Command(0x202D, bytes([0x01])))  # LE_Set_Address_Resolution_Enable
                print("Address resolution enabled")
            except Exception as e:
                print(f"Enable resolution: {e}")

            # Step 4: Scan for devices (controller will auto-resolve RPAs)
            print("\n--- Scanning for 15 seconds ---")
            found_devices = {}
            oura_address = None

            def on_advertisement(advertisement):
                nonlocal oura_address
                addr = str(advertisement.address)
                if addr not in found_devices:
                    name_str = "?"
                    try:
                        name = advertisement.data.get(0x09) or advertisement.data.get(0x08)
                        if name:
                            name_str = name if isinstance(name, str) else name.decode()
                    except:
                        pass

                    found_devices[addr] = name_str
                    resolved = "(resolved)" if addr == RING_ADDRESS else ""
                    print(f"  {addr} - {name_str} {resolved}")

                    if "Oura" in name_str or addr == RING_ADDRESS:
                        oura_address = advertisement.address

            device.on('advertisement', on_advertisement)
            await device.start_scanning()
            await asyncio.sleep(15)
            await device.stop_scanning()
            print(f"Found {len(found_devices)} devices")

            await asyncio.sleep(1)

            # Step 5: Try to connect
            print("\n--- Connection Attempt ---")
            target = oura_address if oura_address else Address(RING_ADDRESS, Address.PUBLIC_DEVICE_ADDRESS)
            print(f"Target: {target}")

            try:
                connection = await asyncio.wait_for(
                    device.connect(target),
                    timeout=30.0
                )
                print(f"CONNECTED! Handle: {connection.handle}")
                return 0
            except asyncio.TimeoutError:
                print("Connection timeout")
            except Exception as e:
                print(f"Connection error: {e}")

            return 1

    except Exception as e:
        print(f"Error: {e}")
        import traceback
        traceback.print_exc()
        return 1


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
