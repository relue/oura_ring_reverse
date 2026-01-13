#!/usr/bin/env python3
"""
Oura Ring BLE Connection Test Script

Uses the robust pattern:
1. btmgmt add-device -a 2 for kernel auto-connect
2. Bleak scanner for device discovery
3. Connect via BLEDevice from scanner (preferred on Linux)
4. Prefer Alias over Name for identity lookup
"""

import argparse
import asyncio
import logging
import re
import subprocess
import sys
import time
import traceback
from datetime import datetime
from typing import Optional, Tuple

from bleak import BleakClient, BleakScanner


# Configure logging
LOG_FILE = "oura_connect.log"

def setup_logging(verbose: bool = False):
    """Setup logging to both file and console."""
    # Create formatter - shorter for console
    fmt = "%(asctime)s [%(levelname)s] %(message)s"
    datefmt = "%H:%M:%S"
    formatter = logging.Formatter(fmt, datefmt)

    # File handler - DEBUG for our code, but filter dbus spam
    fh = logging.FileHandler(LOG_FILE, mode='w')
    fh.setLevel(logging.DEBUG)
    fh.setFormatter(formatter)

    # Console handler
    ch = logging.StreamHandler()
    ch.setLevel(logging.DEBUG if verbose else logging.INFO)
    ch.setFormatter(formatter)

    # Root logger - set to INFO to suppress dbus_fast/bleak debug spam
    root = logging.getLogger()
    root.setLevel(logging.WARNING)  # Suppress most library debug
    root.addHandler(fh)
    root.addHandler(ch)

    # Our logger - full debug access
    logger = logging.getLogger(__name__)
    logger.setLevel(logging.DEBUG)

    # Suppress chatty libraries
    logging.getLogger("bleak").setLevel(logging.WARNING)
    logging.getLogger("dbus_fast").setLevel(logging.WARNING)

    return logger

log = logging.getLogger(__name__)


OURA_DEFAULT_SERVICE = "98ed0001-a541-11e4-b6a0-0002a5d5c51b"


def run(cmd, input_text: Optional[str] = None, timeout: int = 30) -> subprocess.CompletedProcess:
    log.debug(f"Running command: {' '.join(cmd)}")
    result = subprocess.run(
        cmd,
        input=input_text,
        text=True,
        capture_output=True,
        timeout=timeout,
        check=False,
    )
    log.debug(f"Command exit code: {result.returncode}")
    if result.stdout:
        log.debug(f"stdout: {result.stdout[:500]}")
    if result.stderr:
        log.debug(f"stderr: {result.stderr[:500]}")
    return result


def hci_index(adapter: str) -> int:
    m = re.fullmatch(r"hci(\d+)", adapter)
    if not m:
        raise ValueError(f"adapter must look like hci0/hci1, got {adapter}")
    return int(m.group(1))


def mgmt_addr_type_from_bluez(addr_type: str) -> int:
    """Convert BlueZ AddressType to btmgmt -t value. public=1, random=2."""
    t = (addr_type or "").strip().lower()
    if t == "public":
        return 1
    if t == "random":
        return 2
    # Hard fail - guessing breaks btmgmt -a 2
    raise RuntimeError(f"Missing/unknown AddressType '{addr_type}', cannot choose btmgmt -t")


def bluetoothctl_prep_and_pair(controller_addr: str, device_addr: str, timeout: int) -> Tuple[int, str, str]:
    """Pair with device using bluetoothctl in a single session, wait for completion."""
    # Single session with quit - agent state doesn't carry between invocations
    script = "\n".join([
        f"select {controller_addr}",
        "power on",
        "agent NoInputNoOutput",
        "default-agent",
        f"pair {device_addr}",
        f"trust {device_addr}",
        "quit",
    ])
    log.info(f"Pairing with {device_addr} (single bluetoothctl session)...")
    p = run(["bluetoothctl"], input_text=script, timeout=timeout)

    # Poll BlueZ to confirm pairing completed - match exact device path
    target_suffix = "dev_" + device_addr.replace(":", "_")
    log.info(f"Waiting for pairing to complete (target: {target_suffix})...")
    for i in range(timeout):
        time.sleep(1)
        try:
            objs = bluez_get_managed_objects()
            for path, ifaces in objs.items():
                if "org.bluez.Device1" not in ifaces:
                    continue
                # Match the exact device we paired, not just "any Oura"
                if target_suffix in str(path) and bool(ifaces["org.bluez.Device1"].get("Paired", False)):
                    addr = str(ifaces["org.bluez.Device1"].get("Address", ""))
                    log.info(f"Pairing confirmed for {addr} at {path}")
                    return 0, "Paired", ""
        except Exception as e:
            log.debug(f"Checking pair status: {e}")
        log.debug(f"Waiting for pair... ({i+1}/{timeout}s)")

    log.warning("Pairing may not have completed")
    return p.returncode, p.stdout, p.stderr


def bluez_get_managed_objects():
    import dbus

    bus = dbus.SystemBus()
    obj = bus.get_object("org.bluez", "/")
    manager = dbus.Interface(obj, "org.freedesktop.DBus.ObjectManager")
    return manager.GetManagedObjects()


def bluez_get_controller_address(adapter: str) -> Optional[str]:
    objs = bluez_get_managed_objects()
    apath = f"/org/bluez/{adapter}"
    if apath not in objs:
        return None
    if "org.bluez.Adapter1" not in objs[apath]:
        return None
    props = objs[apath]["org.bluez.Adapter1"]
    return str(props.get("Address", "")) or None


def bluez_find_paired_identity(adapter: str, name_substr: str = "Oura") -> Optional[Tuple[str, str, str]]:
    """Find paired device by name/alias. Returns (address, address_type, dbus_path) or None."""
    log.debug(f"Looking for paired device with name containing '{name_substr}'")
    objs = bluez_get_managed_objects()
    aprefix = f"/org/bluez/{adapter}/"
    for path, ifaces in objs.items():
        if not str(path).startswith(aprefix):
            continue
        if "org.bluez.Device1" not in ifaces:
            continue
        props = ifaces["org.bluez.Device1"]
        paired = bool(props.get("Paired", False))
        connected = bool(props.get("Connected", False))
        trusted = bool(props.get("Trusted", False))
        addr = str(props.get("Address", ""))
        if not addr:
            continue
        # Log all devices for debugging
        log.debug(f"  Device {path}: addr={addr}, paired={paired}, connected={connected}, trusted={trusted}")
        if not paired:
            continue
        # Prefer Alias over Name (Name can be empty/stale, BlueZ recommends Alias)
        alias = str(props.get("Alias", "") or "")
        name = str(props.get("Name", "") or "")
        atype = str(props.get("AddressType", "") or "")
        log.debug(f"    name={name}, alias={alias}, type={atype}")
        s = f"{alias} {name}".lower()
        if name_substr.lower() in s:
            log.debug(f"  -> MATCHED by alias/name")
            return addr, atype, str(path)
    # No fallback - don't silently pick the wrong paired device
    return None


def bluez_is_connected(adapter: str, identity_addr: str) -> bool:
    objs = bluez_get_managed_objects()
    aprefix = f"/org/bluez/{adapter}/"
    for path, ifaces in objs.items():
        if not str(path).startswith(aprefix):
            continue
        if "org.bluez.Device1" not in ifaces:
            continue
        props = ifaces["org.bluez.Device1"]
        addr = str(props.get("Address", ""))
        if addr.upper() != identity_addr.upper():
            continue
        return bool(props.get("Connected", False))
    return False


def btmgmt_add_autoconnect(adapter: str, identity_addr: str, addr_type: str) -> Tuple[int, str, str]:
    """Add device to kernel auto-connect list (Action=2 = connect when found)."""
    idx = str(hci_index(adapter))
    t = str(mgmt_addr_type_from_bluez(addr_type))
    log.info(f"btmgmt add-device --index {idx} -t {t} -a 2 {identity_addr}")
    try:
        p = run(["sudo", "btmgmt", "--index", idx, "add-device", "-t", t, "-a", "2", identity_addr], timeout=15)
        return p.returncode, p.stdout, p.stderr
    except subprocess.TimeoutExpired:
        log.warning("btmgmt command timed out (continuing anyway)")
        return -1, "", "timeout"


async def bleak_find_device(adapter: str, name_substr: str, service_uuid: str, timeout: float):
    """Scan for device by name or service UUID."""
    found = None

    def cb(device, adv):
        nonlocal found
        if found is not None:
            return
        name = (adv.local_name or device.name or "").lower()
        log.debug(f"Scan saw: {device.address} - {name}")
        # Log manufacturer/service data for debugging RPA devices
        md = adv.manufacturer_data or {}
        sd = adv.service_data or {}
        if md or sd:
            log.debug(f"  adv md={md} sd={list(sd.keys())}")
        if name_substr.lower() in name:
            log.info(f"Found by name: {device.address} - {name}")
            found = device
            return
        # Check service UUID (often empty for RPA devices, name is primary)
        su = [s.lower() for s in (adv.service_uuids or [])]
        if service_uuid and service_uuid.lower() in su:
            log.info(f"Found by UUID: {device.address}")
            found = device

    log.info(f"Scanning on {adapter} for {timeout}s...")
    scanner = BleakScanner(detection_callback=cb, adapter=adapter)
    await scanner.start()
    try:
        start = time.time()
        while time.time() - start < timeout:
            if found is not None:
                break
            await asyncio.sleep(0.2)
    finally:
        await scanner.stop()
    if found:
        log.debug(f"Scanner found device details: {found.details}")
    else:
        log.warning("Scanner did not find device")
    return found


async def connect_gatt(adapter: str, identity_addr: str, name_substr: str, service_uuid: str, connect_timeout: float, already_connected: bool = False, dbus_path: str = "", force_disconnect: bool = False):
    """Connect via identity address with quick scan to populate Bleak's device cache."""
    log.info(f"connect_gatt: adapter={adapter}, identity={identity_addr}, already_connected={already_connected}")

    # If already connected and force_disconnect requested, disconnect first
    if already_connected and force_disconnect:
        log.info("Force disconnect requested - disconnecting existing connection...")
        run(["bluetoothctl", "disconnect", identity_addr], timeout=5)
        await asyncio.sleep(1.0)
    elif already_connected:
        log.info("Device already connected by kernel - will try to use existing connection")

    # Quick scan to populate Bleak's device cache (needed before connecting via address)
    log.info("Scanning to find device (ring must be awake)...")
    d = await bleak_find_device(adapter, name_substr, service_uuid, timeout=15.0)

    if d is not None:
        log.info(f"Found device: {d.address}")
        # Connect via identity address (not scanned BLEDevice to avoid BR/EDR interference)
        log.info(f"Connecting to identity address {identity_addr}...")
        client = BleakClient(identity_addr, adapter=adapter)
        try:
            await client.connect(timeout=connect_timeout)
            if client.is_connected:
                log.info("Connected! Services discovered.")
                _ = client.services  # Bleak 2.x: services discovered during connect()
                return client
        except Exception as e:
            log.error(f"Connect failed: {e}")
            log.debug(traceback.format_exc())
            raise
    else:
        raise RuntimeError("Device not found during scan - put ring on charger to wake it")


async def main():
    ap = argparse.ArgumentParser(description="Oura Ring BLE Connection Test")
    ap.add_argument("--adapter", default="hci0", help="Bluetooth adapter (default: hci0)")
    ap.add_argument("--name", default="Oura", help="Device name substring to match")
    ap.add_argument("--service-uuid", default=OURA_DEFAULT_SERVICE)
    ap.add_argument("--identity", default="", help="Override identity address")
    ap.add_argument("--bond", action="store_true", help="Scan and pair first")
    ap.add_argument("--fresh-bond", action="store_true", help="Remove existing bond first, then re-pair")
    ap.add_argument("--arm-autoconnect", action="store_true", default=False,
                    help="Manually arm kernel auto-connect (btmgmt add-device -a 2)")
    ap.add_argument("--force-disconnect", action="store_true", default=False,
                    help="Disconnect existing connection before scan+connect (may lose ring)")
    ap.add_argument("--wait-secs", type=float, default=60.0,
                    help="Max seconds to wait for auto-connect")
    ap.add_argument("--scan-secs", type=float, default=15.0,
                    help="Scan timeout for bonding")
    ap.add_argument("--connect-timeout", type=float, default=30.0)
    ap.add_argument("--notify-uuid", default="98ed0003-a541-11e4-b6a0-0002a5d5c51b",
                    help="UUID to subscribe for notifications")
    ap.add_argument("--run-secs", type=float, default=10.0,
                    help="How long to listen for notifications")
    ap.add_argument("-v", "--verbose", action="store_true", help="Verbose logging to console")
    args = ap.parse_args()

    # Setup logging
    setup_logging(args.verbose)
    log.info(f"=== Oura Ring BLE Connection Test ===")
    log.info(f"Adapter: {args.adapter}")
    log.info(f"Log file: {LOG_FILE}")

    # Track if we armed Action=2 anywhere (bonding or manual)
    autoconnect_armed = False

    # Get controller address
    try:
        controller_addr = bluez_get_controller_address(args.adapter)
    except Exception as e:
        log.error(f"BlueZ D-Bus not available: {e}")
        controller_addr = None

    if not controller_addr:
        log.error(f"Could not resolve controller address for {args.adapter}")
        sys.exit(2)

    log.info(f"Controller: {controller_addr}")

    # Check if already bonded
    existing_bond = bluez_find_paired_identity(args.adapter, args.name)
    if existing_bond:
        log.info(f"Existing bond found: {existing_bond[0]} (type={existing_bond[1]})")
        log.debug(f"D-Bus path: {existing_bond[2]}")

    # Fresh bond: remove existing first
    if args.fresh_bond and existing_bond:
        log.info(f"Removing existing bond for {existing_bond[0]}...")
        p = run(["bluetoothctl", "remove", existing_bond[0]], timeout=10)
        log.debug(f"Remove result: rc={p.returncode}")
        await asyncio.sleep(1.0)
        existing_bond = None  # Force re-bond

    # Bond if requested
    if args.bond or args.fresh_bond:
        if existing_bond:
            log.info("Device already bonded, skipping pair. Use --fresh-bond to re-bond.")
        else:
            log.info("Scanning for ring to pair...")
            dev = await bleak_find_device(args.adapter, args.name, args.service_uuid, timeout=args.scan_secs)
            if dev is None:
                log.error("Scan did not find ring. Put it on charger / wake it and retry.")
                sys.exit(3)
            log.info(f"Pairing with {dev.address}...")
            rc, out, err = bluetoothctl_prep_and_pair(controller_addr, dev.address, timeout=60)
            if rc != 0:
                log.warning(f"Pair output: {out}")
                log.warning(f"Pair stderr: {err}")
            log.info("Pairing complete")

            # After bonding, get identity and arm auto-connect immediately
            await asyncio.sleep(1.0)  # Give BlueZ time to resolve identity
            try:
                r = bluez_find_paired_identity(args.adapter, args.name)
                if r is not None:
                    bond_identity, bond_addr_type, _ = r
                    log.info(f"Identity resolved: {bond_identity} (type={bond_addr_type})")
                    log.info("Arming kernel auto-connect after fresh bond...")
                    btmgmt_add_autoconnect(args.adapter, bond_identity, bond_addr_type)
                    autoconnect_armed = True
            except Exception as e:
                log.warning(f"Could not arm auto-connect: {e}")

    # Get identity address
    identity = args.identity.strip()
    addr_type = ""
    dbus_path = ""
    if not identity:
        try:
            r = bluez_find_paired_identity(args.adapter, args.name)
            if r is None:
                log.error("No paired device found in BlueZ. Run with --bond first.")
                sys.exit(4)
            identity, addr_type, dbus_path = r
            log.info(f"Identity: {identity} (type={addr_type})")
            log.debug(f"D-Bus path: {dbus_path}")
        except Exception as e:
            log.error(f"Failed to query BlueZ paired devices: {e}")
            log.debug(traceback.format_exc())
            sys.exit(5)
    else:
        log.info(f"Using provided identity: {identity}")
        try:
            r = bluez_find_paired_identity(args.adapter, args.name)
            if r is not None and r[0].upper() == identity.upper():
                addr_type = r[1]
                dbus_path = r[2]
        except Exception:
            pass

    # Check if already connected (e.g. from recent bond)
    kernel_connected = False
    try:
        kernel_connected = bluez_is_connected(args.adapter, identity)
        if kernel_connected:
            log.info("Device already connected!")
    except Exception:
        pass

    # Optionally arm kernel auto-connect (usually not needed - scan+identity connect works)
    if args.arm_autoconnect and not kernel_connected and addr_type:
        log.info(f"Arming kernel auto-connect for {identity} (type={addr_type})...")
        rc, out, err = btmgmt_add_autoconnect(args.adapter, identity, addr_type)
        if rc != 0:
            log.warning(f"btmgmt warning: {out} {err}")
        else:
            log.info(f"Armed auto-connect for {identity}")
            autoconnect_armed = True

        # Wait for kernel to connect when it sees the device advertising
        log.info(f"Waiting up to {args.wait_secs}s for kernel auto-connect...")
        log.info("(Wake the ring by putting it on charger briefly)")
        deadline = time.time() + args.wait_secs
        while time.time() < deadline:
            try:
                if bluez_is_connected(args.adapter, identity):
                    log.info("Device connected by kernel!")
                    kernel_connected = True
                    break
            except Exception:
                pass
            await asyncio.sleep(0.5)
        if not kernel_connected:
            log.info("Kernel auto-connect timed out, will try direct connect")

    # Connect GATT
    log.info("Connecting GATT...")
    try:
        client = await connect_gatt(args.adapter, identity, args.name, args.service_uuid,
                                    connect_timeout=args.connect_timeout, already_connected=kernel_connected,
                                    dbus_path=dbus_path, force_disconnect=args.force_disconnect)
    except Exception as e:
        log.error(f"GATT connection failed: {e}")
        log.debug(traceback.format_exc())
        sys.exit(6)

    try:
        log.info(f"Connected to {identity}")
        services_list = list(client.services)
        log.info(f"Services: {len(services_list)}")
        for s in client.services:
            log.info(f"  S {s.uuid}")
            for c in s.characteristics:
                props = ",".join(sorted(list(c.properties))) if c.properties else ""
                log.debug(f"    C {c.uuid} [{props}]")

        # Subscribe to notifications
        if args.notify_uuid:
            log.info(f"Subscribing to {args.notify_uuid}...")
            q = asyncio.Queue()

            def handler(_, data: bytearray):
                q.put_nowait(bytes(data))

            await client.start_notify(args.notify_uuid, handler)
            log.info(f"Listening for {args.run_secs}s...")
            end = time.time() + args.run_secs
            count = 0
            while time.time() < end:
                try:
                    b = await asyncio.wait_for(q.get(), timeout=1.0)
                    count += 1
                    log.info(f"  [{count}] {b.hex()}")
                except asyncio.TimeoutError:
                    pass
            await client.stop_notify(args.notify_uuid)
            log.info(f"Received {count} notifications")
        else:
            await asyncio.sleep(args.run_secs)

        log.info("SUCCESS!")

    finally:
        await client.disconnect()
        log.info("Disconnected")


if __name__ == "__main__":
    asyncio.run(main())
