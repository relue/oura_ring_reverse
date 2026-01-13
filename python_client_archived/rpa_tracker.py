#!/usr/bin/env python3
"""
RPA Tracker Daemon - Continuously monitors BLE advertisements and resolves RPAs

This daemon runs in the background after bonding and:
1. Sniffs ALL BLE advertisements
2. Resolves each RPA using the stored IRK
3. Tracks the current/newest RPA address for bonded devices
4. Writes current address to a file for the main client to use

The main client can then always connect to the freshest RPA address.

Usage:
    # Start daemon (runs in background)
    python rpa_tracker.py --start

    # Check current address
    python rpa_tracker.py --status

    # Stop daemon
    python rpa_tracker.py --stop
"""

import asyncio
import argparse
import json
import os
import sys
import signal
import struct
from datetime import datetime
from pathlib import Path
from typing import Optional, Dict, Set
import time

from bleak import BleakScanner
from bleak.backends.device import BLEDevice
from bleak.backends.scanner import AdvertisementData

try:
    from Crypto.Cipher import AES
except ImportError:
    print("ERROR: pycryptodome required. Run: pip install pycryptodome")
    sys.exit(1)

# ============================================================================
# CONFIGURATION
# ============================================================================

ADAPTER = "hci1"  # TP-Link UB500
BLUEZ_BOND_PATH = "/var/lib/bluetooth"
TRACKER_STATE_FILE = Path("/tmp/oura_rpa_tracker.json")
PID_FILE = Path("/tmp/oura_rpa_tracker.pid")
LOG_FILE = Path("/tmp/oura_rpa_tracker.log")

# Known Oura identifiers
OURA_SERVICE_UUID = "98ed0001-a541-11e4-b6a0-0002a5d5c51b"
OURA_MANUFACTURER_ID = 690  # 0x02B2

# ============================================================================
# RPA RESOLUTION
# ============================================================================

def resolve_rpa(rpa_address: str, irk: bytes) -> bool:
    """
    Check if an RPA (Resolvable Private Address) resolves to the given IRK.

    BLE RPA format: XX:XX:XX:YY:YY:YY
    - Lower 3 bytes (XX:XX:XX) = hash (localHash)
    - Upper 3 bytes (YY:YY:YY) = prand (random part)

    Resolution: hash = AES-128(IRK, prand_padded)[0:3]
    If computed hash matches localHash, the RPA belongs to this IRK.

    Args:
        rpa_address: BLE address string like "4D:1A:DE:B4:C3:C9"
        irk: 16-byte Identity Resolving Key

    Returns:
        True if RPA resolves to this IRK
    """
    try:
        # Parse address bytes (reverse order - BLE is little-endian)
        addr_bytes = bytes.fromhex(rpa_address.replace(":", ""))

        # Check if this is an RPA (top 2 bits of first byte should be 01)
        # RPA has format 01xxxxxx in the most significant byte
        if (addr_bytes[0] >> 6) != 0b01:
            return False  # Not an RPA

        # Extract prand (bytes 3-5, big-endian in address) and localHash (bytes 0-2)
        # Address format: localHash[2]:localHash[1]:localHash[0]:prand[2]:prand[1]:prand[0]
        prand = addr_bytes[3:6]  # Upper 3 bytes
        local_hash = addr_bytes[0:3]  # Lower 3 bytes

        # Pad prand to 16 bytes for AES (prand in bytes 13-15, rest zeros)
        # Actually BLE spec says: plaintext = prand || 0^13 (prand followed by 13 zero bytes)
        plaintext = bytes(13) + prand  # 13 zeros + 3 bytes prand = 16 bytes

        # Encrypt with AES-128-ECB
        cipher = AES.new(irk, AES.MODE_ECB)
        encrypted = cipher.encrypt(plaintext)

        # Compare lowest 3 bytes of encrypted result with localHash
        computed_hash = encrypted[0:3]

        return computed_hash == local_hash

    except Exception as e:
        return False


def load_bonds_from_bluez(adapter_address: str) -> Dict[str, dict]:
    """
    Load all bonds from BlueZ storage for the given adapter.

    Returns:
        Dict mapping identity address to bond info (irk, ltk, name)
    """
    bonds = {}
    adapter_path = Path(BLUEZ_BOND_PATH) / adapter_address.upper()

    if not adapter_path.exists():
        return bonds

    for device_dir in adapter_path.iterdir():
        if not device_dir.is_dir():
            continue

        # Skip non-device directories
        if device_dir.name in ['cache', 'settings']:
            continue

        info_file = device_dir / "info"
        if not info_file.exists():
            continue

        try:
            content = info_file.read_text()
            bond_info = {'identity': device_dir.name}

            # Parse IRK
            if '[IdentityResolvingKey]' in content:
                for line in content.split('\n'):
                    if line.startswith('Key=') and 'IdentityResolvingKey' in content.split(line)[0].split('[')[-1]:
                        pass  # Need better parsing

                # Simple parsing
                in_irk_section = False
                in_general_section = False
                for line in content.split('\n'):
                    line = line.strip()
                    if line == '[IdentityResolvingKey]':
                        in_irk_section = True
                        in_general_section = False
                    elif line == '[General]':
                        in_general_section = True
                        in_irk_section = False
                    elif line.startswith('['):
                        in_irk_section = False
                        in_general_section = False
                    elif in_irk_section and line.startswith('Key='):
                        bond_info['irk'] = bytes.fromhex(line.split('=')[1])
                    elif in_general_section and line.startswith('Name='):
                        bond_info['name'] = line.split('=')[1]

            if 'irk' in bond_info:
                bonds[device_dir.name] = bond_info

        except Exception as e:
            pass

    return bonds


# ============================================================================
# RPA TRACKER STATE
# ============================================================================

class RPATrackerState:
    """Tracks current RPA addresses for bonded devices."""

    def __init__(self):
        self.devices: Dict[str, dict] = {}  # identity -> {current_rpa, last_seen, rssi, name}
        self.irk_map: Dict[str, bytes] = {}  # identity -> IRK
        self.load()

    def load(self):
        """Load state from file."""
        if TRACKER_STATE_FILE.exists():
            try:
                data = json.loads(TRACKER_STATE_FILE.read_text())
                self.devices = data.get('devices', {})
            except:
                pass

    def save(self):
        """Save state to file."""
        try:
            data = {
                'devices': self.devices,
                'updated': datetime.now().isoformat()
            }
            TRACKER_STATE_FILE.write_text(json.dumps(data, indent=2))
        except Exception as e:
            pass

    def add_irk(self, identity: str, irk: bytes, name: str = ""):
        """Add an IRK to track."""
        self.irk_map[identity] = irk
        if identity not in self.devices:
            self.devices[identity] = {
                'current_rpa': None,
                'last_seen': None,
                'rssi': None,
                'name': name,
                'identity': identity
            }

    def update_rpa(self, identity: str, rpa: str, rssi: int, name: str = ""):
        """Update the current RPA for a device."""
        now = datetime.now().isoformat()

        if identity not in self.devices:
            self.devices[identity] = {}

        old_rpa = self.devices[identity].get('current_rpa')

        self.devices[identity].update({
            'current_rpa': rpa,
            'last_seen': now,
            'rssi': rssi,
            'name': name or self.devices[identity].get('name', ''),
            'identity': identity
        })

        # Log RPA changes
        if old_rpa != rpa:
            log(f"RPA UPDATE: {identity[:17]} -> {rpa} (was {old_rpa}) RSSI:{rssi}")

        self.save()

    def get_current_rpa(self, identity: str) -> Optional[str]:
        """Get the most recent RPA for an identity."""
        if identity in self.devices:
            return self.devices[identity].get('current_rpa')
        return None

    def get_all_devices(self) -> Dict[str, dict]:
        """Get all tracked devices."""
        return self.devices


# ============================================================================
# LOGGING
# ============================================================================

def log(message: str):
    """Log message to file and stdout."""
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]
    line = f"[{timestamp}] {message}"
    print(line, flush=True)
    try:
        with open(LOG_FILE, 'a') as f:
            f.write(line + '\n')
    except:
        pass


# ============================================================================
# SCANNER DAEMON
# ============================================================================

class RPATrackerDaemon:
    """Background daemon that tracks RPAs for bonded devices.

    Can operate in two modes:
    1. Track mode (default): Just tracks RPAs and stores them for later connection
    2. Auto-connect mode: Immediately connects when a matching RPA is seen
    """

    def __init__(self, adapter: str = ADAPTER, auto_connect: bool = False):
        self.adapter = adapter
        self.state = RPATrackerState()
        self.running = False
        self.auto_connect = auto_connect
        self.connected_client = None
        self.connection_lock = asyncio.Lock()
        self.last_connect_attempt = 0
        self.min_connect_interval = 5  # Minimum seconds between connect attempts
        self.stats = {
            'advertisements_seen': 0,
            'rpas_resolved': 0,
            'connections_made': 0,
            'start_time': None
        }

    def load_bonds(self, adapter_address: str):
        """Load bonds from BlueZ and add their IRKs to tracking."""
        bonds = load_bonds_from_bluez(adapter_address)

        for identity, bond_info in bonds.items():
            if 'irk' in bond_info:
                name = bond_info.get('name', '')
                self.state.add_irk(identity, bond_info['irk'], name)
                log(f"Tracking: {identity} ({name}) IRK:{bond_info['irk'].hex()[:16]}...")

        log(f"Loaded {len(bonds)} bonded devices to track")

    def add_device(self, identity: str, irk: bytes, name: str = ""):
        """Manually add a device to track."""
        self.state.add_irk(identity, irk, name)
        log(f"Added device: {identity} ({name})")

    def _advertisement_callback(self, device: BLEDevice, adv: AdvertisementData):
        """Process each advertisement."""
        self.stats['advertisements_seen'] += 1

        addr = device.address
        rssi = adv.rssi if hasattr(adv, 'rssi') else -100
        name = device.name or ""

        # Check if this is an Oura device by name or manufacturer ID
        is_oura = False
        if name and "Oura" in name:
            is_oura = True
        if adv.manufacturer_data and OURA_MANUFACTURER_ID in adv.manufacturer_data:
            is_oura = True

        # Try to resolve RPA against all tracked IRKs
        for identity, irk in self.state.irk_map.items():
            if resolve_rpa(addr, irk):
                self.stats['rpas_resolved'] += 1
                self.state.update_rpa(identity, addr, rssi, name)

                # AUTO-CONNECT: Immediately connect when we see our device
                if self.auto_connect and not self.connected_client:
                    now = time.time()
                    if now - self.last_connect_attempt >= self.min_connect_interval:
                        self.last_connect_attempt = now
                        # Schedule connection (can't await in callback)
                        asyncio.create_task(self._auto_connect(addr, identity, device))
                return

        # If it's an Oura device but doesn't resolve to any known IRK, log it
        if is_oura:
            log(f"UNKNOWN OURA: {addr} RSSI:{rssi} name:{name} (not bonded)")

    async def _auto_connect(self, rpa: str, identity: str, device: BLEDevice):
        """Auto-connect to device when RPA is detected."""
        async with self.connection_lock:
            if self.connected_client:
                return  # Already connected

            log(f"AUTO-CONNECT: Connecting to {rpa} (identity: {identity})")

            try:
                from bleak import BleakClient

                # Connect using the BLEDevice object (has freshest info)
                client = BleakClient(device, adapter=self.adapter, timeout=15.0)
                await client.connect()

                if client.is_connected:
                    self.connected_client = client
                    self.stats['connections_made'] += 1
                    log(f"AUTO-CONNECT: SUCCESS! Connected to {rpa}")

                    # Write connection status to file for other processes
                    self._write_connection_status(rpa, identity, True)

                    # Keep connection alive - wait for disconnect
                    while client.is_connected and self.running:
                        await asyncio.sleep(1)

                    log(f"AUTO-CONNECT: Disconnected from {rpa}")
                    self.connected_client = None
                    self._write_connection_status(rpa, identity, False)
                else:
                    log(f"AUTO-CONNECT: Failed to connect to {rpa}")

            except Exception as e:
                log(f"AUTO-CONNECT: Error connecting to {rpa}: {e}")
                self.connected_client = None

    def _write_connection_status(self, rpa: str, identity: str, connected: bool):
        """Write connection status to state file."""
        try:
            if identity in self.state.devices:
                self.state.devices[identity]['connected'] = connected
                self.state.devices[identity]['connection_time'] = datetime.now().isoformat() if connected else None
                self.state.save()
        except:
            pass

    async def run(self):
        """Main scanner loop."""
        self.running = True
        self.stats['start_time'] = datetime.now().isoformat()

        mode = "AUTO-CONNECT" if self.auto_connect else "TRACK-ONLY"
        log(f"=== RPA TRACKER DAEMON STARTED ({mode}) ===")
        log(f"Adapter: {self.adapter}")
        log(f"Mode: {mode}")
        log(f"Tracking {len(self.state.irk_map)} devices")
        log(f"State file: {TRACKER_STATE_FILE}")
        if self.auto_connect:
            log(f"Will auto-connect when bonded device advertises!")

        scanner = BleakScanner(
            detection_callback=self._advertisement_callback,
            adapter=self.adapter
        )

        try:
            await scanner.start()
            log("Scanner started - monitoring all advertisements...")

            # Run forever, printing stats periodically
            while self.running:
                await asyncio.sleep(60)

                # Print stats
                elapsed = (datetime.now() - datetime.fromisoformat(self.stats['start_time'])).total_seconds()
                rate = self.stats['advertisements_seen'] / elapsed if elapsed > 0 else 0

                connected_str = "YES" if self.connected_client else "no"
                log(f"--- STATS: {self.stats['advertisements_seen']} adverts, "
                    f"{self.stats['rpas_resolved']} resolved, "
                    f"{self.stats['connections_made']} connects, "
                    f"connected={connected_str}, {rate:.1f}/sec ---")

                # Print current RPA for each tracked device
                for identity, info in self.state.devices.items():
                    rpa = info.get('current_rpa', 'none')
                    last_seen = info.get('last_seen', 'never')
                    name = info.get('name', '')
                    log(f"  {name or identity[:17]}: RPA={rpa} last={last_seen}")

        except asyncio.CancelledError:
            log("Scanner cancelled")
        except Exception as e:
            log(f"Scanner error: {e}")
        finally:
            await scanner.stop()
            log("Scanner stopped")

    def stop(self):
        """Stop the daemon."""
        self.running = False


# ============================================================================
# MAIN
# ============================================================================

def get_adapter_address() -> str:
    """Get the adapter's MAC address."""
    # Try to read from sys
    try:
        for adapter_dir in Path('/sys/class/bluetooth').iterdir():
            if adapter_dir.name.startswith('hci'):
                addr_file = adapter_dir / 'address'
                if addr_file.exists():
                    addr = addr_file.read_text().strip().upper()
                    # Check if this is our adapter
                    if ADAPTER in adapter_dir.name or ADAPTER == adapter_dir.name:
                        return addr
        # Default to first adapter
        addr_file = Path(f'/sys/class/bluetooth/{ADAPTER}/address')
        if addr_file.exists():
            return addr_file.read_text().strip().upper()
    except:
        pass

    # Fallback - TP-Link UB500
    return "0C:EF:15:5E:0D:F1"


def start_daemon(auto_connect: bool = False):
    """Start the RPA tracker daemon."""
    # Check if already running
    if PID_FILE.exists():
        try:
            pid = int(PID_FILE.read_text().strip())
            os.kill(pid, 0)  # Check if process exists
            print(f"Daemon already running (PID {pid})")
            return
        except (OSError, ValueError):
            PID_FILE.unlink(missing_ok=True)

    mode = "auto-connect" if auto_connect else "track-only"
    print(f"Starting daemon in {mode} mode...")

    # Fork to background
    if os.fork() > 0:
        print("Daemon starting in background...")
        print(f"Log: {LOG_FILE}")
        print(f"State: {TRACKER_STATE_FILE}")
        return

    # Detach from terminal
    os.setsid()

    # Second fork
    if os.fork() > 0:
        sys.exit(0)

    # Write PID file
    PID_FILE.write_text(str(os.getpid()))

    # Setup signal handlers
    def handle_signal(signum, frame):
        PID_FILE.unlink(missing_ok=True)
        sys.exit(0)

    signal.signal(signal.SIGTERM, handle_signal)
    signal.signal(signal.SIGINT, handle_signal)

    # Redirect stdout/stderr to log file
    sys.stdout = open(LOG_FILE, 'a')
    sys.stderr = sys.stdout

    # Run daemon
    daemon = RPATrackerDaemon(ADAPTER, auto_connect=auto_connect)
    adapter_addr = get_adapter_address()
    daemon.load_bonds(adapter_addr)

    try:
        asyncio.run(daemon.run())
    finally:
        PID_FILE.unlink(missing_ok=True)


def stop_daemon():
    """Stop the RPA tracker daemon."""
    if not PID_FILE.exists():
        print("Daemon not running")
        return

    try:
        pid = int(PID_FILE.read_text().strip())
        os.kill(pid, signal.SIGTERM)
        print(f"Stopped daemon (PID {pid})")
        PID_FILE.unlink(missing_ok=True)
    except (OSError, ValueError) as e:
        print(f"Error stopping daemon: {e}")
        PID_FILE.unlink(missing_ok=True)


def show_status():
    """Show current tracker status."""
    print("=== RPA TRACKER STATUS ===\n")

    # Check if daemon is running
    running = False
    if PID_FILE.exists():
        try:
            pid = int(PID_FILE.read_text().strip())
            os.kill(pid, 0)
            running = True
            print(f"Daemon: RUNNING (PID {pid})")
        except:
            print("Daemon: NOT RUNNING (stale PID file)")
    else:
        print("Daemon: NOT RUNNING")

    print()

    # Load and display state
    if TRACKER_STATE_FILE.exists():
        try:
            data = json.loads(TRACKER_STATE_FILE.read_text())
            print(f"State file: {TRACKER_STATE_FILE}")
            print(f"Last updated: {data.get('updated', 'unknown')}")
            print()

            devices = data.get('devices', {})
            if devices:
                print("Tracked devices:")
                for identity, info in devices.items():
                    print(f"\n  Identity: {identity}")
                    print(f"  Name: {info.get('name', 'unknown')}")
                    print(f"  Current RPA: {info.get('current_rpa', 'none')}")
                    print(f"  Last seen: {info.get('last_seen', 'never')}")
                    print(f"  RSSI: {info.get('rssi', 'unknown')}")
            else:
                print("No devices tracked")
        except Exception as e:
            print(f"Error reading state: {e}")
    else:
        print("No state file (daemon hasn't run yet)")

    print()

    # Show recent log entries
    if LOG_FILE.exists():
        print("Recent log entries:")
        try:
            lines = LOG_FILE.read_text().split('\n')[-10:]
            for line in lines:
                if line.strip():
                    print(f"  {line}")
        except:
            pass


def run_foreground(auto_connect: bool = False):
    """Run tracker in foreground (for debugging)."""
    daemon = RPATrackerDaemon(ADAPTER, auto_connect=auto_connect)
    adapter_addr = get_adapter_address()
    daemon.load_bonds(adapter_addr)

    try:
        asyncio.run(daemon.run())
    except KeyboardInterrupt:
        print("\nStopped")


def main():
    parser = argparse.ArgumentParser(description="RPA Tracker Daemon")
    parser.add_argument('--start', action='store_true', help='Start daemon in background')
    parser.add_argument('--stop', action='store_true', help='Stop daemon')
    parser.add_argument('--status', action='store_true', help='Show status')
    parser.add_argument('--foreground', '-f', action='store_true', help='Run in foreground')
    parser.add_argument('--auto-connect', '-c', action='store_true',
                       help='Auto-connect when bonded device advertises (replicates Android behavior)')
    parser.add_argument('--adapter', default=ADAPTER, help=f'Bluetooth adapter (default: {ADAPTER})')
    args = parser.parse_args()

    global ADAPTER
    ADAPTER = args.adapter

    if args.start:
        start_daemon(auto_connect=args.auto_connect)
    elif args.stop:
        stop_daemon()
    elif args.status:
        show_status()
    elif args.foreground:
        run_foreground(auto_connect=args.auto_connect)
    else:
        # Default: show status
        show_status()


if __name__ == "__main__":
    main()
