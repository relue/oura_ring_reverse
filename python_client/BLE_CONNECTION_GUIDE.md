# Oura Ring BLE Connection Guide

## Overview

This document describes the reliable approach for connecting to Oura Ring Gen 3/4 via BLE on Linux using BlueZ and Bleak.

## Hardware Tested

- **Adapter**: TP-Link UB500 (Realtek RTL8761B) on `hci0`
- **Controller Address**: `0C:EF:15:5E:0D:F1`
- **Ring**: Oura Ring 4
- **Identity Address**: `A0:38:F8:43:4E:CB` (LE Public)

## The Problem

When connecting to a bonded BLE device using Bleak on Linux, connecting via a scanned `BLEDevice` object can cause BlueZ to attempt a BR/EDR (classic Bluetooth) connection path, resulting in:

- `br-connection-canceled` errors
- Connection timeouts (30+ seconds)
- `CancelledError` from D-Bus calls

This happens because BlueZ Device1 objects can have both LE and BR/EDR bearers present, and BlueZ may try the wrong path.

## The Solution

**Connect via identity address string, not the scanned BLEDevice object.**

This approach:
1. Scans to populate Bleak's device cache (required for Bleak to know about the device)
2. Connects using the identity address string directly
3. Avoids BR/EDR interference by not using the BLEDevice object

## Connection Steps (10 Steps)

### 1. Setup Logging
```python
logging.getLogger("bleak").setLevel(logging.WARNING)
logging.getLogger("dbus_fast").setLevel(logging.WARNING)
```

### 2. Get Controller Address
Query BlueZ D-Bus for the adapter's address:
```python
def bluez_get_controller_address(adapter: str) -> str:
    objs = bluez_get_managed_objects()
    apath = f"/org/bluez/{adapter}"
    props = objs[apath]["org.bluez.Adapter1"]
    return str(props.get("Address", ""))
```

### 3. Find Bonded Device
Search BlueZ D-Bus for paired device matching "Oura":
```python
def bluez_find_paired_identity(adapter: str, name_substr: str = "Oura"):
    # Returns (address, address_type, dbus_path)
    # Prefer Alias over Name (BlueZ recommendation)
```

### 4. Extract Identity Info
- Identity address: `A0:38:F8:43:4E:CB`
- Address type: `public` (LE Public)
- D-Bus path: `/org/bluez/hci0/dev_A0_38_F8_43_4E_CB`

### 5. Check If Already Connected
```python
def bluez_is_connected(adapter: str, identity_addr: str) -> bool:
    # Query BlueZ Device1.Connected property
```

### 6. Quick BLE Scan
Scan to find the advertising device and populate Bleak's cache:
```python
async def bleak_find_device(adapter, name_substr, service_uuid, timeout=15.0):
    scanner = BleakScanner(detection_callback=cb, adapter=adapter)
    await scanner.start()
    # Wait for device with matching name
    await scanner.stop()
    return found_device
```

### 7. Connect Via Identity Address (CRITICAL)
```python
# DO THIS - Connect via identity address string
client = BleakClient(identity_addr, adapter=adapter)
await client.connect(timeout=30.0)

# DON'T DO THIS - Causes BR/EDR interference on bonded devices
# client = BleakClient(scanned_ble_device)
# await client.connect()
```

### 8. Service Discovery
Bleak 2.x discovers services automatically during `connect()`:
```python
if client.is_connected:
    _ = client.services  # Services already discovered
```

### 9. Access GATT Services
```python
for service in client.services:
    print(f"Service: {service.uuid}")
    for char in service.characteristics:
        print(f"  Characteristic: {char.uuid}")
```

### 10. Subscribe to Notifications
```python
await client.start_notify(char_uuid, handler_callback)
# ... do work ...
await client.stop_notify(char_uuid)
await client.disconnect()
```

## Oura Ring Services

| UUID | Description |
|------|-------------|
| `00001800-0000-1000-8000-00805f9b34fb` | Generic Access |
| `00001801-0000-1000-8000-00805f9b34fb` | Generic Attribute |
| `00060000-f8ce-11e4-abf4-0002a5d5c51b` | Vendor Specific (Nordic DFU?) |
| `98ed0001-a541-11e4-b6a0-0002a5d5c51b` | Oura Main Service |

### Oura Main Service Characteristics

| UUID | Properties | Description |
|------|------------|-------------|
| `98ed0002-...` | write | Command TX (write commands here) |
| `98ed0003-...` | notify | Response RX (notifications) |

## Timing

With this approach, typical connection times are:
- Scan: ~1-5 seconds (depends on ring advertising)
- Connect: ~3 seconds
- **Total: ~4-8 seconds**

## Troubleshooting

### Ring Not Found During Scan
- Put ring on charger briefly to wake it up
- Ring goes to sleep when worn and not syncing

### Connection Timeout
- Ensure using identity address string, not BLEDevice object
- Check ring is paired/bonded: `bluetoothctl info <addr>`
- Try restarting bluetoothd: `sudo systemctl restart bluetooth`

### BR/EDR Errors
- This is the main issue this guide solves
- Always connect via identity address string after scanning

## Optional: Kernel Auto-Connect

For more robust connections, you can arm kernel auto-connect:
```bash
sudo btmgmt --index 0 add-device -t 1 -a 2 A0:38:F8:43:4E:CB
# -t 1 = LE Public address
# -a 2 = Auto-connect when seen
```

This makes the kernel connect automatically when it sees the device advertising, but is not required for the scan+identity connect approach.

## Code Reference

See `oura_connect_test.py` for the full implementation.

## Version Info

- BlueZ: 5.85
- Bleak: 0.22.x (2.x API)
- Python: 3.11
- Linux Kernel: 6.17.x
