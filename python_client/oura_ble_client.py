#!/usr/bin/env python3
"""
Oura Ring Gen 3/4 BLE Client - Full Featured

Features:
- Bonding with kernel auto-connect (replicates Android behavior)
- Authentication (GetAuthNonce, AES-ECB encryption)
- SetAuthKey (write new auth key to ring)
- Heartbeat monitoring (live BPM)
- Data retrieval (get all events from ring)
- Sleep data retrieval (filtered sleep events)
- Time sync
- Event capture to file

Usage:
    # Interactive mode with full menu
    python oura_ble_client.py

    # Bond with ring (must be in pairing mode!)
    python oura_ble_client.py --bond

    # Live heartbeat monitoring (requires auth)
    python oura_ble_client.py --heartbeat

    # Get stored data from ring
    python oura_ble_client.py --get-data

    # Get sleep events only
    python oura_ble_client.py --get-data --filter-sleep --output sleep.txt

    # Set auth key (16 bytes hex)
    python oura_ble_client.py --set-auth-key 00426ed816dcece48dd9968c1f36c0b5
"""

import asyncio
import argparse
import sys
import struct
import time
import json
import subprocess
from datetime import datetime
from pathlib import Path
from typing import Optional, List, Callable

try:
    from bleak import BleakClient, BleakScanner
    from bleak.exc import BleakError
except ImportError:
    print("Error: bleak not installed. Run: pip install bleak")
    sys.exit(1)

try:
    from Crypto.Cipher import AES
except ImportError:
    print("Warning: pycryptodome not installed. Authentication will not work.")
    print("Run: pip install pycryptodome")
    AES = None

# ============================================================================
# CONSTANTS
# ============================================================================

# Oura Ring BLE UUIDs
SERVICE_UUID = "98ed0001-a541-11e4-b6a0-0002a5d5c51b"
WRITE_CHAR_UUID = "98ed0002-a541-11e4-b6a0-0002a5d5c51b"
NOTIFY_CHAR_UUID = "98ed0003-a541-11e4-b6a0-0002a5d5c51b"

# BLE Adapter (hci0 = TP-Link UB500, hci1 = Intel AX211)
BLE_ADAPTER = "hci0"

# Default auth key (from protocol documentation)
DEFAULT_AUTH_KEY = bytes.fromhex("00426ed816dcece48dd9968c1f36c0b5")

# Auth key storage file
AUTH_KEY_FILE = "stored_auth_key.bin"

# Bonded device address storage
BONDED_ADDRESS_FILE = "bonded_device.txt"

# ============================================================================
# COMMANDS (from Android app reverse engineering)
# ============================================================================

# Authentication
CMD_GET_AUTH_NONCE = bytes([0x2f, 0x01, 0x2b])

# Initialization / Heartbeat
CMD_INIT_1 = bytes([0x2f, 0x02, 0x20, 0x02])
CMD_INIT_2 = bytes([0x2f, 0x03, 0x22, 0x02, 0x03])
CMD_START_STREAM = bytes([0x2f, 0x03, 0x26, 0x02, 0x02])
CMD_STOP = bytes([0x2f, 0x03, 0x22, 0x02, 0x01])

# Factory reset (DANGEROUS - clears all data including auth key)
CMD_FACTORY_RESET = bytes([0x1a, 0x00])

# ============================================================================
# EVENT TYPES
# ============================================================================

EVENT_TYPES = {
    0x2f: "CMD_RESPONSE",
    0x41: "API_RING_START_IND",
    0x42: "API_TIME_SYNC_IND",
    0x43: "API_DEBUG_EVENT",
    0x44: "API_SLEEP_PERIOD_INFO",
    0x45: "API_STATE_CHANGE_IND",
    0x46: "API_TEMP_EVENT",
    0x47: "API_MOTION_EVENT",
    0x48: "API_BEDTIME_PERIOD",
    0x49: "API_SLEEP_TEMP_EVENT",
    0x4a: "API_HRV_EVENT",
    0x4b: "API_ALERT_EVENT",
    0x4c: "API_BATTERY_LEVEL",
    0x4d: "API_STATE_CHANGE",
    0x4e: "API_REAL_STEPS_FEATURES",
    0x4f: "API_FEATURE_SESSION",
    0x50: "API_RAW_PPG_DATA",
    0x51: "API_WEAR_EVENT",
    0x52: "API_ACTIVITY_INFO",
    0x53: "API_EHR_TRACE_EVENT",
    0x54: "API_EHR_ACM_INTENSITY",
    0x55: "API_SLEEP_SUMMARY_1",
    0x56: "API_TEMP_PERIOD",
    0x57: "API_BLE_USAGE_STATS",
    0x58: "API_BLE_MODE_SWITCH",
    0x59: "API_HR_SETTINGS_DATA",
    0x5a: "API_SLEEP_STATISTICS",
    0x5b: "API_BLE_CONNECTION_IND",
    0x5c: "API_FLASH_USAGE_STATS",
    0x5d: "API_HRV_EVENT",
    0x5e: "API_SCAN_END",
    0x5f: "API_MOTION_PERIOD",
    0x60: "API_IBI_AND_AMPLITUDE_EVENT",
    0x61: "API_MEAS_QUALITY_EVENT",
    0x62: "API_GREEN_IBI_QUALITY",
    0x63: "API_SPO2_EVENT",
    0x64: "API_SPO2_IBI_AMPLITUDE",
    0x65: "API_SPO2_DC_EVENT",
    0x66: "API_REP_DEBUG_DATA",
    0x67: "API_EXCEPTION_LOG",
    0x68: "API_SLEEP_PHASE_INFO",
    0x69: "API_SLEEP_SUMMARY_2",
    0x6a: "API_SLEEP_PERIOD_INFO_2",
    0x6b: "API_RING_SLEEP_FEATURE",
    0x6c: "API_SLEEP_PHASE_DETAILS",
    0x6d: "API_MEAS_QUALITY_EVENT",
    0x6e: "API_SLEEP_HR",
    0x6f: "API_RING_SLEEP_FEATURE_2",
    0x70: "API_SLEEP_SUMMARY_4",
    0x71: "API_SLEEP_PHASE_DATA",
    0x72: "API_SLEEP_ACM_PERIOD",
    0x75: "API_SLEEP_TEMP_EVENT",
    0x80: "API_GREEN_IBI_QUALITY_EVENT",
}

# Sleep-related events for filtering
SLEEP_EVENT_TYPES = {0x48, 0x49, 0x4B, 0x4C, 0x4D, 0x4E, 0x4F, 0x55, 0x57, 0x58, 0x5A, 0x6a, 0x72, 0x75, 0x76}

# ============================================================================
# HELPER FUNCTIONS
# ============================================================================

def format_hex(data: bytes) -> str:
    """Format bytes as hex string."""
    return ' '.join(f'{b:02x}' for b in data)


def get_event_name(tag: int) -> str:
    """Get event type name from tag byte."""
    return EVENT_TYPES.get(tag, f"UNKNOWN_{tag:02x}")


def parse_heartbeat(data: bytes) -> Optional[tuple]:
    """Parse heartbeat packet and return (ibi_ms, bpm, flag)."""
    if len(data) < 10:
        return None
    if data[0] != 0x2f or data[1] != 0x0f or data[2] != 0x28:
        return None

    # IBI from bytes 8-9 (12-bit little-endian)
    ibi_low = data[8] & 0xFF
    ibi_high = data[9] & 0x0F
    ibi_ms = (ibi_high << 8) | ibi_low

    if ibi_ms == 0 or ibi_ms > 2000:
        return None

    bpm = 60000.0 / ibi_ms
    flag = data[4] if len(data) > 4 else 0
    return (ibi_ms, bpm, flag)


def encrypt_nonce(nonce: bytes, auth_key: bytes) -> bytes:
    """Encrypt 15-byte nonce using AES-128-ECB with PKCS5 padding."""
    if AES is None:
        raise RuntimeError("pycryptodome not installed")
    if len(nonce) != 15:
        raise ValueError(f"Nonce must be 15 bytes, got {len(nonce)}")
    if len(auth_key) != 16:
        raise ValueError(f"Auth key must be 16 bytes, got {len(auth_key)}")

    # PKCS5 padding: 15 bytes + 1 padding byte (0x01)
    padded = nonce + bytes([1])
    cipher = AES.new(auth_key, AES.MODE_ECB)
    return cipher.encrypt(padded)


def build_get_event_cmd(seq_num: int, max_events: int = 0) -> bytes:
    """Build GetEvent command (0x10)."""
    # Format: 10 09 <event_seq_num:4-bytes LE> <max_events:1-byte> <flags:4-bytes LE>
    cmd = bytearray(11)
    cmd[0] = 0x10  # REQUEST_TAG
    cmd[1] = 0x09  # length

    # Event sequence number (4 bytes, little endian)
    cmd[2] = seq_num & 0xFF
    cmd[3] = (seq_num >> 8) & 0xFF
    cmd[4] = (seq_num >> 16) & 0xFF
    cmd[5] = (seq_num >> 24) & 0xFF

    # Max events (0 = fetch all)
    cmd[6] = max_events & 0xFF

    # Flags (4 bytes, all zeros)
    cmd[7] = 0x00
    cmd[8] = 0x00
    cmd[9] = 0x00
    cmd[10] = 0x00

    return bytes(cmd)


def build_time_sync_cmd() -> bytes:
    """Build TimeSync command (0x12)."""
    # Format: 12 09 <utc_time_sec:8-bytes LE> <tz_30min_units:1-byte>
    current_time_sec = int(time.time())

    # Get timezone offset in 30-minute units
    import time as t
    tz_offset_sec = -t.timezone if t.daylight == 0 else -t.altzone
    tz_30min_units = tz_offset_sec // 1800

    cmd = bytearray(11)
    cmd[0] = 0x12  # TIME_SYNC REQUEST_TAG
    cmd[1] = 0x09  # length

    # UTC time in seconds (8 bytes, little endian)
    for i in range(8):
        cmd[2 + i] = (current_time_sec >> (i * 8)) & 0xFF

    # Timezone offset in 30-minute units (1 byte, signed)
    cmd[10] = tz_30min_units & 0xFF

    return bytes(cmd)


def build_set_auth_key_cmd(new_key: bytes) -> bytes:
    """Build SetAuthKey command (0x24 0x10)."""
    if len(new_key) != 16:
        raise ValueError(f"Auth key must be 16 bytes, got {len(new_key)}")

    # Format: 24 10 <16-byte-key>
    cmd = bytearray(18)
    cmd[0] = 0x24  # SET_AUTH_KEY_TAG
    cmd[1] = 0x10  # length (16)
    cmd[2:18] = new_key

    return bytes(cmd)


# ============================================================================
# BONDING FUNCTIONS
# ============================================================================

def run_cmd(cmd: List[str], timeout: int = 30) -> tuple:
    """Run a shell command and return (success, stdout, stderr)."""
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return (result.returncode == 0, result.stdout.strip(), result.stderr.strip())
    except subprocess.TimeoutExpired:
        return (False, "", "Command timed out")
    except Exception as e:
        return (False, "", str(e))


def get_adapter_index(adapter: str = "hci1") -> int:
    """Get numeric index from adapter name (e.g., 'hci1' -> 1)."""
    if adapter.startswith("hci"):
        try:
            return int(adapter[3:])
        except ValueError:
            pass
    return 1  # Default to hci1


def get_adapter_address(adapter: str = "hci1") -> Optional[str]:
    """Get the MAC address of the Bluetooth adapter."""
    # First try sysfs - most reliable and respects adapter parameter
    try:
        with open(f"/sys/class/bluetooth/{adapter}/address", "r") as f:
            return f.read().strip().upper()
    except:
        pass

    # Fallback to bluetoothctl list - look for [default] marker
    success, stdout, _ = run_cmd(["bluetoothctl", "list"])
    if success:
        # Format: "Controller XX:XX:XX:XX:XX:XX name [default]"
        for line in stdout.strip().splitlines():
            parts = line.split()
            if len(parts) >= 2:
                addr = parts[1]
                if "[default]" in line:
                    return addr
        # Fallback: return first controller
        for line in stdout.strip().splitlines():
            parts = line.split()
            if len(parts) >= 2:
                return parts[1]

    return None


async def bond_ring(adapter: str = BLE_ADAPTER, scan_timeout: float = 15.0) -> Optional[str]:
    """
    Bond with Oura Ring and enable kernel auto-connect.

    This replicates the Android bonding behavior:
    1. Scan for Oura Ring (must be in pairing mode!)
    2. Pair/bond with it
    3. Enable kernel auto-connect (btmgmt add-device -a 2)
    4. Trust the device

    Args:
        adapter: Bluetooth adapter (default: hci1)
        scan_timeout: How long to scan for the ring

    Returns:
        Identity address if successful, None otherwise
    """
    print("=" * 60)
    print("  OURA RING BONDING + AUTO-CONNECT SETUP")
    print("=" * 60)
    print()
    print("Make sure the ring is in PAIRING MODE!")
    print("(Place on charger, wait for white light, then remove)")
    print()

    adapter_index = get_adapter_index(adapter)
    adapter_addr = get_adapter_address(adapter)

    if not adapter_addr:
        print(f"ERROR: Could not get address for adapter {adapter}")
        return None

    print(f"Using adapter: {adapter} ({adapter_addr})")
    print()

    # Step 1: Scan for Oura Ring
    print("[1/5] Scanning for Oura Ring...")

    # Start scanning with bluetoothctl
    scan_proc = subprocess.Popen(
        ["bluetoothctl", "scan", "on"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE
    )

    await asyncio.sleep(scan_timeout)

    # Stop scan
    scan_proc.terminate()
    run_cmd(["bluetoothctl", "scan", "off"])

    # Find Oura device
    success, stdout, _ = run_cmd(["bluetoothctl", "devices"])
    oura_rpa = None
    for line in stdout.splitlines():
        if "Oura" in line:
            parts = line.split()
            if len(parts) >= 2:
                oura_rpa = parts[1]
                break

    if not oura_rpa:
        print("ERROR: Oura Ring not found!")
        print("Make sure it's in pairing mode (white light on charger, then remove)")
        return None

    print(f"Found Oura Ring at: {oura_rpa}")
    print()

    # Step 2: Pair with the ring
    print(f"[2/5] Pairing with {oura_rpa}...")
    success, stdout, stderr = run_cmd(["bluetoothctl", "pair", oura_rpa], timeout=30)
    if not success and "Already Paired" not in stderr:
        print(f"Pairing output: {stdout} {stderr}")

    # Wait for pairing to complete and identity to resolve
    await asyncio.sleep(2)

    # Get identity address (BlueZ resolves RPA to identity after pairing)
    success, stdout, _ = run_cmd(["bluetoothctl", "devices", "Paired"])
    identity_addr = None
    for line in stdout.splitlines():
        if "Oura" in line:
            parts = line.split()
            if len(parts) >= 2:
                identity_addr = parts[1]
                break

    if not identity_addr:
        # Fall back to the address we paired with
        identity_addr = oura_rpa

    print(f"Identity address: {identity_addr}")
    print()

    # Step 3: Trust the device
    print("[3/5] Trusting device...")
    success, stdout, stderr = run_cmd(["bluetoothctl", "trust", identity_addr])
    if success:
        print("  Trusted!")
    else:
        print(f"  Trust output: {stdout} {stderr}")
    print()

    # Step 4: Enable kernel auto-connect
    print("[4/5] Enabling kernel auto-connect (btmgmt add-device -a 2)...")
    success, stdout, stderr = run_cmd([
        "sudo", "btmgmt", "--index", str(adapter_index),
        "add-device", "-a", "2", "-t", "1", identity_addr
    ])
    print(f"  {stdout}")
    if stderr:
        print(f"  {stderr}")
    print()

    # Step 5: Verify bond
    print("[5/5] Verifying bond...")
    bond_file = Path(f"/var/lib/bluetooth/{adapter_addr}/{identity_addr}/info")
    if bond_file.exists():
        print(f"  Bond file exists: {bond_file}")
        # Try to read IRK
        try:
            content = bond_file.read_text()
            for i, line in enumerate(content.splitlines()):
                if "[IdentityResolvingKey]" in line:
                    # Next line should have Key=
                    lines = content.splitlines()
                    if i + 1 < len(lines) and "Key=" in lines[i + 1]:
                        irk = lines[i + 1].split("=")[1]
                        print(f"  IRK: {irk}")
                    break
        except:
            pass
    else:
        print(f"  WARNING: Bond file not found at {bond_file}")
    print()

    # Done!
    print("=" * 60)
    print("  BONDING COMPLETE!")
    print("=" * 60)
    print()
    print(f"Identity Address: {identity_addr}")
    print("Kernel Action: Auto-connect (0x02)")
    print()
    print("The kernel will now automatically connect when")
    print("the ring advertises (with any RPA).")
    print()
    print("To test: python oura_ble_client.py --get-data")
    print()

    # Save the bonded address
    try:
        with open(BONDED_ADDRESS_FILE, 'w') as f:
            f.write(identity_addr)
        print(f"Saved identity address to {BONDED_ADDRESS_FILE}")
    except Exception as e:
        print(f"Warning: Could not save address: {e}")

    return identity_addr


# ============================================================================
# OURA CLIENT CLASS
# ============================================================================

class OuraClient:
    """Full-featured Oura Ring BLE Client."""

    def __init__(self, adapter: str = BLE_ADAPTER, auth_key: Optional[bytes] = None):
        self.adapter = adapter

        # Load stored auth key if no key provided
        if auth_key:
            self.auth_key = auth_key
        else:
            self.auth_key = self._load_auth_key() or DEFAULT_AUTH_KEY

        self.client: Optional[BleakClient] = None
        self.device = None

        # State
        self.is_connected = False
        self.is_authenticated = False
        self.pending_nonce: Optional[bytes] = None

        # Data collection
        self.received_data: List[bytes] = []
        self.event_data: List[bytes] = []
        self.heartbeat_count = 0

        # Callbacks
        self.on_heartbeat: Optional[Callable] = None
        self.on_event: Optional[Callable] = None
        self.on_auth_response: Optional[Callable] = None

        # Data retrieval state
        self.current_seq_num = 0
        self.bytes_left = -1
        self.fetch_complete = False

        # Filtering state
        self.current_filter: Optional['EventFilter'] = None
        self.stop_after_count: Optional[int] = None
        self.stop_after_type: Optional[int] = None
        self.event_type_count: int = 0

        # Time sync state
        self.time_sync_points: List[dict] = []

    async def scan(self, timeout: float = 15.0) -> Optional[object]:
        """
        Scan for Oura Ring using multiple detection methods.

        Note: Don't rely solely on service UUID - BlueZ caching can cause
        UUIDs to not populate from advertising data. Use multiple indicators:
        - Local name containing "Oura"
        - Service UUID (when available)
        - Known OUI prefix (A0:38:F8 for Oura Ring 4)
        """
        print(f"Scanning for Oura Ring on {self.adapter}...")

        found = None
        def callback(device, adv_data):
            nonlocal found
            if found:
                return

            # Method 1: Check local name (most reliable)
            name = adv_data.local_name or device.name or ""
            if "Oura" in name:
                print(f"Found (by name): {device.address} - {name}")
                found = device
                return

            # Method 2: Check service UUIDs (may be unreliable due to BlueZ caching)
            services = adv_data.service_uuids or []
            if SERVICE_UUID.lower() in [s.lower() for s in services]:
                print(f"Found (by UUID): {device.address} - {name or 'Oura Ring'}")
                found = device
                return

            # Method 3: Check known OUI prefix (Oura Ring 4 uses A0:38:F8)
            if device.address.upper().startswith("A0:38:F8"):
                print(f"Found (by OUI): {device.address} - {name or 'Oura Ring'}")
                found = device
                return

        scanner = BleakScanner(detection_callback=callback, adapter=self.adapter)
        await scanner.start()

        for _ in range(int(timeout * 2)):
            if found:
                break
            await asyncio.sleep(0.5)

        await scanner.stop()
        return found

    def _dbus_connect(self, address: str, timeout: float = 30.0) -> bool:
        """
        Connect to bonded device using D-Bus directly (like bluetoothctl connect).
        This works for bonded devices even when not advertising.
        """
        try:
            import dbus
            bus = dbus.SystemBus()

            # Find the device path - could be identity address or RPA
            adapter_path = f"/org/bluez/{self.adapter}"
            device_path = None

            # First try direct identity address path
            addr_path = address.replace(':', '_').upper()
            direct_path = f"{adapter_path}/dev_{addr_path}"

            # Check if direct path exists
            try:
                test_obj = bus.get_object("org.bluez", direct_path)
                dbus.Interface(test_obj, "org.freedesktop.DBus.Properties").Get("org.bluez.Device1", "Address")
                device_path = direct_path
                print(f"  Found device at identity path: {device_path}")
            except:
                # Search all devices under this adapter for matching Address
                print(f"  Searching for device with address {address}...")
                manager = dbus.Interface(
                    bus.get_object("org.bluez", "/"),
                    "org.freedesktop.DBus.ObjectManager"
                )
                objects = manager.GetManagedObjects()

                for path, interfaces in objects.items():
                    if not path.startswith(adapter_path + "/dev_"):
                        continue
                    if "org.bluez.Device1" not in interfaces:
                        continue
                    props = interfaces["org.bluez.Device1"]
                    dev_addr = str(props.get("Address", ""))
                    # Match by address OR by name containing Oura
                    if dev_addr.upper() == address.upper():
                        device_path = path
                        print(f"  Found device at: {device_path}")
                        break
                    name = str(props.get("Name", ""))
                    if "Oura" in name:
                        device_path = path
                        print(f"  Found Oura device at: {device_path} ({dev_addr})")
                        break

            if not device_path:
                print(f"  Device {address} not found in D-Bus")
                return False

            device_obj = bus.get_object("org.bluez", device_path)
            device_iface = dbus.Interface(device_obj, "org.bluez.Device1")
            props_iface = dbus.Interface(device_obj, "org.freedesktop.DBus.Properties")

            # Check if already connected
            connected = props_iface.Get("org.bluez.Device1", "Connected")
            if connected:
                print("  Already connected via D-Bus!")
                return True

            # Call Connect() - this triggers kernel to connect (uses IRK for RPA resolution)
            print("  Calling Device1.Connect()...")
            device_iface.Connect()

            # Wait for connection
            import time
            start = time.time()
            while time.time() - start < timeout:
                connected = props_iface.Get("org.bluez.Device1", "Connected")
                if connected:
                    print("  D-Bus connection successful!")
                    return True
                time.sleep(0.5)

            print("  D-Bus connection timeout")
            return False

        except ImportError:
            print("  D-Bus not available (install dbus-python)")
            return False
        except Exception as e:
            print(f"  D-Bus connect error: {e}")
            return False

    async def connect(self, address: Optional[str] = None, timeout: float = 30.0, retries: int = 3) -> bool:
        """
        Connect to Oura Ring using scan + identity address approach.

        This approach avoids BR/EDR interference:
        1. Scan to find device and populate Bleak's cache
        2. Connect via identity address string (NOT the BLEDevice object)

        Args:
            address: Optional identity address. If None, tries bonded address.
            timeout: Connection timeout in seconds (default 30s)
            retries: Number of connection attempts (default 3)
        """
        # Try bonded address if no address provided
        if not address:
            address = self._load_bonded_address()

        # Step 1: Scan to find device (populates Bleak's cache)
        print("Scanning for Oura Ring (must be awake - put on charger briefly)...")
        self.device = await self.scan(timeout=15.0)

        if not self.device:
            print("Oura Ring not found during scan!")
            print("Tip: Put ring on charger to wake it up, then try again.")
            return False

        # Use scanned address if no bonded address
        if not address:
            address = self.device.address
            print(f"Using scanned address: {address}")

        # Step 2: Connect via identity address string (avoids BR/EDR interference)
        print(f"Connecting to identity address {address}...")

        for attempt in range(retries):
            print(f"  Attempt {attempt + 1}/{retries}...")
            try:
                # CRITICAL: Use address string, NOT the BLEDevice object
                self.client = BleakClient(address, adapter=self.adapter)
                await self.client.connect(timeout=timeout)
                if self.client.is_connected:
                    print("  Connected!")
                    break
            except Exception as e:
                print(f"  Connection failed: {e}")
                if attempt < retries - 1:
                    print("  Retrying...")
                    await asyncio.sleep(2)

        if not self.client or not self.client.is_connected:
            print("Connection failed after all retries!")
            return False

        print("Connected!")
        self.is_connected = True

        # Check if already paired
        needs_pairing = False
        if self.device:
            try:
                props = self.device.details.get('props', {})
                is_paired = props.get('Paired', False) or props.get('Bonded', False)
                needs_pairing = not is_paired
            except:
                needs_pairing = True

        if needs_pairing:
            print("Attempting to pair...")
            try:
                await self.client.pair(protection_level=2)
                print("Paired successfully!")
            except Exception as e:
                print(f"Pair attempt: {e}")
                # Check if ring might already be paired from its side
                # Try to continue - authentication might still work
                print("Pairing failed - will try to continue (ring may already be paired)")
                # Don't abort - let authentication attempt proceed

        # After successful connection/pairing, get identity address from BlueZ
        # This ensures we save the stable identity address, not a temporary RPA
        identity_addr = self._get_identity_address_from_bluez()
        if identity_addr:
            self._save_bonded_address(identity_addr)
        elif not needs_pairing:
            # Already paired, save the address we used
            self._save_bonded_address(connected_address)

        # Enable notifications
        print("Enabling notifications...")
        await self.client.start_notify(NOTIFY_CHAR_UUID, self._notification_handler)
        print("Notifications enabled!")

        return True

    async def disconnect(self):
        """Disconnect from ring."""
        if self.client and self.client.is_connected:
            try:
                await self.client.stop_notify(NOTIFY_CHAR_UUID)
            except:
                pass
            await self.client.disconnect()
        self.is_connected = False
        self.is_authenticated = False
        print("Disconnected")

    async def _notification_handler(self, sender, data: bytes):
        """Handle BLE notifications."""
        self.received_data.append(data)

        tag = data[0] if data else 0

        # Command response (0x2f)
        if tag == 0x2f and len(data) >= 3:
            ext_tag = data[2]

            # Auth nonce response: 2f <subcmd> 2c <15-byte-nonce>
            if ext_tag == 0x2c and len(data) >= 18:
                self.pending_nonce = data[3:18]
                print(f"Received auth nonce: {format_hex(self.pending_nonce)}")
                if self.on_auth_response:
                    self.on_auth_response('nonce', self.pending_nonce)

            # Auth result: 2f <subcmd> 2e <status>
            elif ext_tag == 0x2e and len(data) >= 4:
                status = data[3]
                if status == 0x00:
                    print("Authentication SUCCESS!")
                    self.is_authenticated = True
                else:
                    print(f"Authentication FAILED (status={status})")
                    self.is_authenticated = False
                if self.on_auth_response:
                    self.on_auth_response('result', status)

            # Heartbeat packet: 2f 0f 28 ...
            elif ext_tag == 0x28:
                result = parse_heartbeat(data)
                if result:
                    ibi_ms, bpm, flag = result
                    self.heartbeat_count += 1
                    if self.on_heartbeat:
                        self.on_heartbeat(self.heartbeat_count, ibi_ms, bpm, flag)
                    else:
                        print(f"Heartbeat #{self.heartbeat_count}: {bpm:.1f} BPM (IBI: {ibi_ms}ms)")

        # TIME_SYNC response (0x13)
        elif tag == 0x13 and len(data) >= 6:
            # Format: 13 05 <ring_time:4LE>
            ring_time_deciseconds = struct.unpack('<I', data[2:6])[0]
            utc_millis = int(time.time() * 1000)

            sync_point = {
                'ring_time': ring_time_deciseconds,
                'utc_millis': utc_millis,
                'timestamp': datetime.now().isoformat()
            }
            self.time_sync_points.append(sync_point)

            print(f"✓ Time sync: ring_time={ring_time_deciseconds} deciseconds")
            print(f"  (Ring timestamp at {datetime.now().strftime('%H:%M:%S')})")

        # Event data (0x11 response) - this is the metadata/status packet, not actual events
        elif tag == 0x11 and len(data) >= 8:
            # Parse event response header (matching Android format)
            # Format: 11 <len> <events_received:1> <sleep_progress:1> <bytes_left:4LE>
            events_received = data[2] & 0xFF  # 1 byte - events in THIS batch
            sleep_progress = data[3] & 0xFF if len(data) > 3 else 0  # 1 byte
            self.bytes_left = struct.unpack('<I', data[4:8])[0] if len(data) >= 8 else 0  # 4 bytes LE

            # Update sequence number for next batch request
            # Each batch starts from current_seq_num, so increment by events received
            self.current_seq_num += events_received

            print(f"  Batch: {events_received} events, bytes_left={self.bytes_left}, next_seq={self.current_seq_num}")

            # Note: Don't store 0x11 packets - they're metadata, not events
            # Actual events come as separate packets with tag >= 0x41

            if self.bytes_left == 0:
                self.fetch_complete = True

        # Other events
        elif tag >= 0x41:
            # Apply filter if provided
            if self.current_filter is None or self.current_filter.should_include(tag):
                self.event_data.append(data)

                # Check stop conditions
                if self.stop_after_count and len(self.event_data) >= self.stop_after_count:
                    self.fetch_complete = True
                elif self.stop_after_type and tag == self.stop_after_type:
                    self.event_type_count += 1
                    if self.event_type_count >= self.stop_after_count:
                        self.fetch_complete = True

            if self.on_event:
                self.on_event(tag, get_event_name(tag), data)

    async def send_command(self, cmd: bytes, description: str = "") -> bool:
        """Send command to ring."""
        if not self.client or not self.client.is_connected:
            print("Not connected!")
            return False

        if description:
            print(f"Sending: {description} ({format_hex(cmd)})")

        try:
            await self.client.write_gatt_char(WRITE_CHAR_UUID, cmd)
            await asyncio.sleep(0.3)
            return True
        except Exception as e:
            print(f"Send error: {e}")
            return False

    async def authenticate(self, auth_key: Optional[bytes] = None) -> bool:
        """Perform authentication with ring."""
        key = auth_key or self.auth_key
        if not key:
            print("No auth key provided!")
            return False

        if AES is None:
            print("pycryptodome not installed - cannot authenticate")
            return False

        print("\n=== AUTHENTICATION ===")

        # Step 1: Get nonce
        print("Step 1: Getting auth nonce...")
        self.pending_nonce = None
        self.received_data.clear()
        await self.send_command(CMD_GET_AUTH_NONCE, "GetAuthNonce")

        # Wait for nonce
        for _ in range(20):
            if self.pending_nonce:
                break
            await asyncio.sleep(0.1)

        if not self.pending_nonce:
            print("No nonce received!")
            return False

        # Step 2: Encrypt nonce
        print("Step 2: Encrypting nonce...")
        try:
            encrypted = encrypt_nonce(self.pending_nonce, key)
            print(f"Encrypted: {format_hex(encrypted)}")
        except Exception as e:
            print(f"Encryption error: {e}")
            return False

        # Step 3: Send authenticate command
        print("Step 3: Sending authenticate command...")
        auth_cmd = bytes([0x2f, 0x11, 0x2d]) + encrypted[:16]
        self.received_data.clear()
        await self.send_command(auth_cmd, "Authenticate")

        # Wait for result
        for _ in range(20):
            if self.is_authenticated:
                # Save the successful auth key for future sessions
                self.auth_key = key
                self._save_auth_key(key)
                return True
            await asyncio.sleep(0.1)

        print("Authentication timeout!")
        return False

    async def set_auth_key(self, new_key: bytes) -> bool:
        """Write new auth key to ring."""
        if len(new_key) != 16:
            print(f"Auth key must be 16 bytes, got {len(new_key)}")
            return False

        print(f"Setting new auth key: {format_hex(new_key)}")
        cmd = build_set_auth_key_cmd(new_key)
        await self.send_command(cmd, "SetAuthKey")

        # Update local key and save for future sessions
        self.auth_key = new_key
        self._save_auth_key(new_key)
        return True

    async def sync_time(self) -> bool:
        """Sync time with ring."""
        if not self.is_authenticated:
            print("Must be authenticated first!")
            return False

        print("\n=== TIME SYNC ===")
        cmd = build_time_sync_cmd()
        await self.send_command(cmd, "TimeSync")
        await asyncio.sleep(1)
        return True

    async def start_heartbeat(self, duration: Optional[int] = None):
        """Start heartbeat monitoring."""
        if not self.is_authenticated:
            print("Must be authenticated first!")
            return

        print("\n=== STARTING HEARTBEAT MONITORING ===")

        # Send init sequence
        await self.send_command(CMD_INIT_1, "Init 1")
        await self.send_command(CMD_INIT_2, "Init 2")
        await self.send_command(CMD_START_STREAM, "Start Stream")

        print("\nMonitoring active! Press Ctrl+C to stop.\n")

        try:
            if duration:
                await asyncio.sleep(duration)
            else:
                while True:
                    await asyncio.sleep(1)
        except KeyboardInterrupt:
            print("\nStopping...")

        await self.send_command(CMD_STOP, "Stop")
        print(f"\nTotal heartbeats: {self.heartbeat_count}")

    async def get_data(self, start_seq: int = 0, max_events: int = 0,
                       event_filter: Optional['EventFilter'] = None,
                       stop_after_count: Optional[int] = None,
                       stop_after_type: Optional[int] = None) -> List[bytes]:
        """
        Get stored event data from ring with optional filtering.

        Args:
            start_seq: Starting sequence number
            max_events: Max events per batch (0 = unlimited)
            event_filter: Optional EventFilter to include/exclude event types
            stop_after_count: Stop after receiving this many events total
            stop_after_type: Stop after N events of this specific type (use with stop_after_count)

        Returns:
            List of raw event bytes
        """
        if not self.is_authenticated:
            print("Must be authenticated first!")
            return []

        print(f"\n=== GETTING DATA (starting from seq {start_seq}) ===")
        if event_filter:
            print(f"Filter: whitelist={event_filter.whitelist}, blacklist={event_filter.blacklist}")
        if stop_after_count:
            print(f"Stop after {stop_after_count} events" +
                  (f" of type 0x{stop_after_type:02x}" if stop_after_type else ""))

        self.event_data.clear()
        self.current_seq_num = start_seq
        self.fetch_complete = False

        # Set filtering state
        self.current_filter = event_filter
        self.stop_after_count = stop_after_count
        self.stop_after_type = stop_after_type
        self.event_type_count = 0

        batch_count = 0
        while not self.fetch_complete:
            cmd = build_get_event_cmd(self.current_seq_num, max_events)
            await self.send_command(cmd, f"GetEvent (seq={self.current_seq_num})")

            # Wait for response
            await asyncio.sleep(0.5)

            batch_count += 1
            if batch_count > 1000:  # Safety limit
                print("Max batches reached")
                break

        # Clear filter state
        self.current_filter = None
        self.stop_after_count = None
        self.stop_after_type = None

        print(f"Received {len(self.event_data)} events")
        return self.event_data

    async def factory_reset(self) -> bool:
        """
        DANGEROUS: Factory reset ring (erases ALL data and auth key).
        Ring will reboot and require re-pairing.
        """
        print("\n" + "="*60)
        print("⚠️  WARNING: FACTORY RESET ⚠️")
        print("="*60)
        print("This will:")
        print("  - Erase ALL stored data on the ring")
        print("  - Reset the auth key to default")
        print("  - Require re-pairing the ring")
        print("  - Cannot be undone")
        print("="*60)

        confirm = input("Type 'FACTORY RESET' to confirm: ").strip()
        if confirm != "FACTORY RESET":
            print("Cancelled.")
            return False

        print("\nSending factory reset command...")
        await self.send_command(CMD_FACTORY_RESET, "Factory Reset")
        print("✓ Factory reset command sent. Ring will reboot.")
        print("  You will need to re-pair and authenticate with default key.")

        return True

    def save_sync_points(self, filename: str = 'time_sync_points.json'):
        """Save time sync points to file."""
        with open(filename, 'w') as f:
            json.dump(self.time_sync_points, f, indent=2)
        print(f"Saved {len(self.time_sync_points)} sync points to {filename}")

    def load_sync_points(self, filename: str = 'time_sync_points.json'):
        """Load time sync points from file."""
        if Path(filename).exists():
            with open(filename, 'r') as f:
                self.time_sync_points = json.load(f)
            print(f"Loaded {len(self.time_sync_points)} sync points from {filename}")
        else:
            print(f"Sync file {filename} not found")

    def _load_auth_key(self) -> Optional[bytes]:
        """Load stored auth key from file."""
        if Path(AUTH_KEY_FILE).exists():
            try:
                with open(AUTH_KEY_FILE, 'rb') as f:
                    key = f.read()
                if len(key) == 16:
                    print(f"Loaded stored auth key: {format_hex(key)}")
                    return key
            except Exception as e:
                print(f"Warning: Could not load auth key: {e}")
        return None

    def _save_auth_key(self, key: bytes):
        """Save auth key to file for future sessions."""
        try:
            with open(AUTH_KEY_FILE, 'wb') as f:
                f.write(key)
            print(f"Saved auth key to {AUTH_KEY_FILE}")
        except Exception as e:
            print(f"Warning: Could not save auth key: {e}")

    def _load_bonded_address(self) -> Optional[str]:
        """
        Load bonded device address.

        Priority:
        1. BlueZ identity address (stable, handles RPA)
        2. Our stored file (only if BlueZ confirms bond exists)

        If BlueZ has no bond, the stored file is stale and ignored.
        """
        # First try BlueZ - this gives us the identity address which is stable
        identity_addr = self._get_identity_address_from_bluez()
        if identity_addr:
            print(f"Found bonded device (BlueZ): {identity_addr}")
            return identity_addr

        # No bond in BlueZ - check if we have a stale file
        if Path(BONDED_ADDRESS_FILE).exists():
            # BlueZ has no bond, so our stored address is stale (likely an RPA)
            print("No bond in BlueZ - stored address may be stale RPA, ignoring")
            try:
                Path(BONDED_ADDRESS_FILE).unlink()
                print(f"Removed stale {BONDED_ADDRESS_FILE}")
            except:
                pass

        return None

    def _save_bonded_address(self, address: str):
        """Save bonded device address for future sessions."""
        try:
            with open(BONDED_ADDRESS_FILE, 'w') as f:
                f.write(address)
            print(f"Saved bonded device address to {BONDED_ADDRESS_FILE}")
        except Exception as e:
            print(f"Warning: Could not save bonded address: {e}")

    def _get_identity_address_from_bluez(self) -> Optional[str]:
        """
        Get the identity address from BlueZ for bonded Oura Ring via D-Bus.

        This finds the actual identity address stored by BlueZ, which is stable
        even if the device uses Resolvable Private Addresses (RPA).

        Note: Don't rely on Name for sleeping/privacy devices - it can be empty.
        Use Paired status and match against adapter path.
        """
        try:
            import dbus

            bus = dbus.SystemBus()

            # Correct D-Bus ObjectManager call
            obj = bus.get_object("org.bluez", "/")
            manager = dbus.Interface(obj, "org.freedesktop.DBus.ObjectManager")
            objects = manager.GetManagedObjects()

            # Build adapter path for filtering
            adapter_path = f"/org/bluez/{self.adapter}/"

            for path, interfaces in objects.items():
                # Only look at devices under our adapter
                if not str(path).startswith(adapter_path):
                    continue

                if "org.bluez.Device1" not in interfaces:
                    continue

                props = interfaces["org.bluez.Device1"]
                paired = bool(props.get("Paired", False))
                address = str(props.get("Address", ""))

                if not paired or not address:
                    continue

                # Check multiple indicators (Name may be empty for sleeping device)
                name = str(props.get("Name", ""))
                alias = str(props.get("Alias", ""))

                # Match by name/alias if available
                if "Oura" in name or "Oura" in alias:
                    return address

                # Also check if this is a known Oura identity address pattern
                # (Oura Ring 4 uses A0:38:F8 OUI prefix)
                if address.upper().startswith("A0:38:F8"):
                    return address

        except ImportError:
            pass  # dbus not available
        except Exception as e:
            print(f"  D-Bus lookup error: {e}")

        # Fallback to bluetoothctl (works even without dbus-python)
        try:
            result = subprocess.run(
                ["bluetoothctl", "devices", "Paired"],
                capture_output=True, text=True, timeout=5
            )
            for line in result.stdout.splitlines():
                # Format: "Device XX:XX:XX:XX:XX:XX Oura Ring 4"
                # or just "Device XX:XX:XX:XX:XX:XX" if name not cached
                parts = line.split()
                if len(parts) >= 2:
                    addr = parts[1]
                    # Check by name if present
                    if "Oura" in line:
                        return addr
                    # Check by known OUI prefix
                    if addr.upper().startswith("A0:38:F8"):
                        return addr
        except:
            pass

        return None


# ============================================================================
# INTERACTIVE MODE
# ============================================================================

async def interactive_mode(auth_key: Optional[bytes] = None):
    """Run interactive menu."""
    client = OuraClient(auth_key=auth_key or DEFAULT_AUTH_KEY)

    print("\n" + "=" * 60)
    print("OURA RING BLE CLIENT - INTERACTIVE MODE")
    print("=" * 60)

    while True:
        print("\n--- Menu ---")
        print("0. Bond Ring (pairing mode required)")
        print("1. Scan and Connect")
        print("2. Authenticate")
        print("3. Start Heartbeat Monitoring")
        print("4. Get Data")
        print("5. Get Data (with filters)")
        print("6. Sync Time and Save")
        print("7. Set Auth Key")
        print("8. ⚠️  Factory Reset (DANGEROUS)")
        print("9. Disconnect")
        print("10. Exit")

        try:
            choice = input("\nChoice: ").strip()
        except (KeyboardInterrupt, EOFError):
            break

        if choice == '0':
            identity = await bond_ring(adapter=client.adapter)
            if identity:
                print(f"\nBonding successful! You can now use option 1 to connect.")
        elif choice == '1':
            await client.connect()
        elif choice == '2':
            if not client.is_connected:
                print("Connect first!")
            else:
                key_hex = input("Auth key (hex, 32 chars) or Enter for stored: ").strip()
                if key_hex:
                    try:
                        key = bytes.fromhex(key_hex.replace(' ', ''))
                        await client.authenticate(key)
                    except ValueError:
                        print("Invalid hex!")
                else:
                    await client.authenticate()
        elif choice == '3':
            await client.start_heartbeat()
        elif choice == '4':
            data = await client.get_data()
            print(f"Got {len(data)} events")
        elif choice == '5':
            print("\nFilter options:")
            print("1. Sleep events only")
            print("2. Custom whitelist")
            print("3. Custom blacklist")
            filter_choice = input("Choice (or Enter to skip): ").strip()

            event_filter = None
            if filter_choice == '1':
                from event_filter import EventFilter, SLEEP_EVENTS
                event_filter = EventFilter()
                event_filter.whitelist = SLEEP_EVENTS
                print(f"Using sleep filter: {len(SLEEP_EVENTS)} event types")
            elif filter_choice == '2':
                from event_filter import EventFilter
                event_filter = EventFilter()
                types = input("Whitelist (space-separated hex, e.g. 0x6a 0x46): ").strip().split()
                for t in types:
                    try:
                        event_filter.add_whitelist(int(t, 16))
                    except ValueError:
                        print(f"Invalid hex: {t}")
                print(f"Whitelist: {event_filter.whitelist}")
            elif filter_choice == '3':
                from event_filter import EventFilter
                event_filter = EventFilter()
                types = input("Blacklist (space-separated hex, e.g. 0x43): ").strip().split()
                for t in types:
                    try:
                        event_filter.add_blacklist(int(t, 16))
                    except ValueError:
                        print(f"Invalid hex: {t}")
                print(f"Blacklist: {event_filter.blacklist}")

            data = await client.get_data(event_filter=event_filter)
            print(f"Got {len(data)} events")
        elif choice == '6':
            await client.sync_time()
            await asyncio.sleep(1)  # Wait for response
            client.save_sync_points()
        elif choice == '7':
            key_hex = input("New auth key (hex, 32 chars): ").strip()
            try:
                key = bytes.fromhex(key_hex.replace(' ', ''))
                await client.set_auth_key(key)
            except ValueError:
                print("Invalid hex!")
        elif choice == '8':
            await client.factory_reset()
        elif choice == '9':
            await client.disconnect()
        elif choice == '10':
            break

    await client.disconnect()
    print("\nGoodbye!")


# ============================================================================
# MAIN
# ============================================================================

async def main():
    parser = argparse.ArgumentParser(
        description='Oura Ring BLE Client - Full Featured',
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument('--heartbeat', action='store_true', help='Start heartbeat monitoring')
    parser.add_argument('--capture', action='store_true', help='Capture events to file')
    parser.add_argument('--get-data', action='store_true', help='Get stored data from ring')
    parser.add_argument('--output', '-o', default='ring_events.txt', help='Output file')
    parser.add_argument('--duration', '-d', type=int, help='Duration in seconds')
    parser.add_argument('--auth-key', '-k', help='Auth key (32 hex chars)')
    parser.add_argument('--set-auth-key', help='Set new auth key on ring')
    parser.add_argument('--adapter', default=BLE_ADAPTER, help=f'BLE adapter (default: {BLE_ADAPTER})')

    # Filtering options
    parser.add_argument('--filter-whitelist', nargs='+',
                       help='Only include these event types (hex, e.g., 0x6a 0x46)')
    parser.add_argument('--filter-blacklist', nargs='+',
                       help='Exclude these event types (hex, e.g., 0x43 0x61)')
    parser.add_argument('--filter-sleep', action='store_true',
                       help='Shortcut: only get sleep-related events')
    parser.add_argument('--stop-after', type=int,
                       help='Stop after receiving N events')
    parser.add_argument('--stop-after-type',
                       help='Stop after N events of this type (hex, e.g., 0x6a)')

    # Time sync options
    parser.add_argument('--sync-time', action='store_true',
                       help='Sync time with ring and save sync point')
    parser.add_argument('--save-sync', default='time_sync_points.json',
                       help='File to save time sync points (default: time_sync_points.json)')

    # Factory reset (DANGEROUS)
    parser.add_argument('--factory-reset', action='store_true',
                       help='⚠️ DANGEROUS: Factory reset the ring (erases all data)')

    # Bonding
    parser.add_argument('--bond', action='store_true',
                       help='Bond with ring and enable kernel auto-connect (ring must be in pairing mode)')
    parser.add_argument('--scan-timeout', type=float, default=15.0,
                       help='Scan timeout for bonding (default: 15 seconds)')

    args = parser.parse_args()

    # Parse auth key if provided
    auth_key = None
    if args.auth_key:
        try:
            auth_key = bytes.fromhex(args.auth_key.replace(' ', ''))
        except ValueError:
            print("Invalid auth key hex!")
            return 1

    # Run interactive mode if no specific action requested
    if not (args.heartbeat or args.capture or args.get_data or args.set_auth_key
            or args.sync_time or args.factory_reset or args.bond):
        await interactive_mode(auth_key)
        return 0

    # Handle bonding separately (doesn't need existing connection)
    if args.bond:
        identity = await bond_ring(adapter=args.adapter, scan_timeout=args.scan_timeout)
        return 0 if identity else 1

    # Otherwise run specific mode
    client = OuraClient(adapter=args.adapter, auth_key=auth_key)

    if not await client.connect():
        return 1

    try:
        # Factory reset (no auth needed, but dangerous)
        if args.factory_reset:
            await client.factory_reset()
            return 0

        # Set auth key if requested
        if args.set_auth_key:
            new_key = bytes.fromhex(args.set_auth_key.replace(' ', ''))
            await client.set_auth_key(new_key)
            return 0

        # Authenticate first (uses default key if none provided)
        if args.heartbeat or args.get_data or args.sync_time:
            if not await client.authenticate():
                print("Authentication failed!")
                return 1

        # Time sync
        if args.sync_time:
            await client.sync_time()
            await asyncio.sleep(1)  # Wait for response
            client.save_sync_points(args.save_sync)
            return 0

        if args.heartbeat:
            await client.start_heartbeat(args.duration)
        elif args.capture:
            # TODO: Implement capture mode
            print("Capture mode not yet implemented in new client")
        elif args.get_data:
            # Build filter if specified
            event_filter = None
            if args.filter_whitelist or args.filter_blacklist or args.filter_sleep:
                from event_filter import EventFilter, SLEEP_EVENTS
                event_filter = EventFilter()

                if args.filter_sleep:
                    event_filter.whitelist = SLEEP_EVENTS
                if args.filter_whitelist:
                    for t in args.filter_whitelist:
                        event_filter.add_whitelist(int(t, 16))
                if args.filter_blacklist:
                    for t in args.filter_blacklist:
                        event_filter.add_blacklist(int(t, 16))

            # Parse stop conditions
            stop_after_count = args.stop_after
            stop_after_type = None
            if args.stop_after_type:
                stop_after_type = int(args.stop_after_type, 16)

            # Fetch data
            data = await client.get_data(
                event_filter=event_filter,
                stop_after_count=stop_after_count,
                stop_after_type=stop_after_type
            )

            # Save to file with header (matching analysis_scripts format)
            if args.output:
                with open(args.output, 'w') as f:
                    # Write header
                    f.write("# Oura Ring Event Export\n")
                    f.write(f"# Timestamp: {datetime.now().strftime('%a %b %d %H:%M:%S %Z %Y')}\n")
                    f.write(f"# Events: {len(data)}\n")
                    f.write("#\n")
                    f.write("# Format: index|tag_hex|event_name|hex_data\n")
                    f.write("#\n")
                    # Write events
                    for i, event in enumerate(data):
                        tag = event[0] if event else 0
                        f.write(f"{i}|0x{tag:02x}|{get_event_name(tag)}|{event.hex()}\n")
                print(f"Saved {len(data)} events to {args.output}")

    finally:
        await client.disconnect()

    return 0


if __name__ == "__main__":
    try:
        sys.exit(asyncio.run(main()))
    except KeyboardInterrupt:
        print("\nInterrupted!")
        sys.exit(0)
