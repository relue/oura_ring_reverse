"""
Oura Ring BLE Client

Full-featured async BLE client for Oura Ring Gen 3/4.
Supports bonding, authentication, heartbeat monitoring, data retrieval, and time sync.

Refactored for callback-based output to support both CLI and web integration.
"""

import asyncio
import json
import struct
import time
from datetime import datetime
from pathlib import Path
from typing import Optional, List, Callable, Any

try:
    from bleak import BleakClient, BleakScanner
    from bleak.exc import BleakError
except ImportError:
    raise ImportError("bleak not installed. Run: pip install bleak")

from oura.ble.protocol import (
    SERVICE_UUID, WRITE_CHAR_UUID, NOTIFY_CHAR_UUID,
    DEFAULT_ADAPTER, DEFAULT_AUTH_KEY, DEFAULT_DATA_DIR,
    AUTH_KEY_FILE, BONDED_ADDRESS_FILE, SYNC_POINT_FILE,
    CMD_GET_AUTH_NONCE, CMD_INIT_1, CMD_INIT_2, CMD_START_STREAM, CMD_STOP,
    CMD_FACTORY_RESET,
    EVENT_TYPES, get_event_name, format_hex, parse_heartbeat,
    build_get_event_cmd, build_time_sync_cmd, build_set_auth_key_cmd,
    build_auth_cmd, encrypt_nonce,
    EventFilter,
)


class OuraClient:
    """Full-featured Oura Ring BLE Client with callback-based output."""

    def __init__(
        self,
        adapter: str = DEFAULT_ADAPTER,
        auth_key: Optional[bytes] = None,
        data_dir: Optional[Path] = None
    ):
        """Initialize Oura BLE client.

        Args:
            adapter: Bluetooth adapter (e.g., 'hci0', 'hci1')
            auth_key: 16-byte auth key. If None, loads from file or uses default.
            data_dir: Directory for storing auth key, sync points, etc.
        """
        self.adapter = adapter
        self.data_dir = Path(data_dir) if data_dir else DEFAULT_DATA_DIR

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

        # Existing callbacks (for events)
        self.on_heartbeat: Optional[Callable[[int, int, float, int], None]] = None
        self.on_event: Optional[Callable[[int, str, bytes], None]] = None
        self.on_auth_response: Optional[Callable[[str, Any], None]] = None

        # NEW callbacks for web integration
        self.on_log: Optional[Callable[[str, str], None]] = None
        self.on_status_change: Optional[Callable[[dict], None]] = None
        self.on_progress: Optional[Callable[[str, int, int, str], None]] = None
        self.on_sync_point: Optional[Callable[[dict], None]] = None

        # Data retrieval state
        self.current_seq_num = 0
        self.bytes_left = -1
        self.fetch_complete = False
        self.probe_events_received = 0

        # Filtering state
        self.current_filter: Optional[EventFilter] = None
        self.stop_after_count: Optional[int] = None
        self.stop_after_type: Optional[int] = None
        self.event_type_count: int = 0

        # Time sync state
        self.time_sync_points: List[dict] = []

        # Heartbeat control
        self._heartbeat_running = False

    # ========================================================================
    # Logging (callback-based)
    # ========================================================================

    def _log(self, level: str, message: str):
        """Internal logging - routes to callback or print."""
        if self.on_log:
            self.on_log(level, message)
        else:
            prefix = {'info': '>', 'success': '✓', 'error': '✗', 'warn': '!'}.get(level, '>')
            print(f"[{prefix}] {message}")

    def _emit_status(self):
        """Emit current status via callback."""
        if self.on_status_change:
            self.on_status_change({
                'connected': self.is_connected,
                'authenticated': self.is_authenticated,
                'adapter': self.adapter,
            })

    def _emit_progress(self, action: str, current: int, total: int, label: str):
        """Emit progress via callback."""
        if self.on_progress:
            self.on_progress(action, current, total, label)

    # ========================================================================
    # Scanning
    # ========================================================================

    async def scan(self, timeout: float = 15.0) -> Optional[object]:
        """Scan for Oura Ring using multiple detection methods.

        Returns:
            BLEDevice if found, None otherwise.
        """
        self._log('info', f"Scanning for Oura Ring on {self.adapter}...")

        found = None

        def callback(device, adv_data):
            nonlocal found
            if found:
                return

            # Method 1: Check local name (most reliable)
            name = adv_data.local_name or device.name or ""
            if "Oura" in name:
                self._log('success', f"Found (by name): {device.address} - {name}")
                found = device
                return

            # Method 2: Check service UUIDs
            services = adv_data.service_uuids or []
            if SERVICE_UUID.lower() in [s.lower() for s in services]:
                self._log('success', f"Found (by UUID): {device.address} - {name or 'Oura Ring'}")
                found = device
                return

            # Method 3: Check known OUI prefix (Oura Ring 4 uses A0:38:F8)
            if device.address.upper().startswith("A0:38:F8"):
                self._log('success', f"Found (by OUI): {device.address} - {name or 'Oura Ring'}")
                found = device
                return

        scanner = BleakScanner(detection_callback=callback, adapter=self.adapter)
        await scanner.start()

        for i in range(int(timeout * 2)):
            if found:
                break
            await asyncio.sleep(0.5)
            if i % 4 == 0:  # Progress every 2 seconds
                self._emit_progress('scan', i, int(timeout * 2), f"Scanning... {i//2}s")

        await scanner.stop()

        if not found:
            self._log('warn', "Oura Ring not found during scan")
            self._log('info', "Tip: Put ring on charger to wake it up, then try again")

        return found

    # ========================================================================
    # Connection
    # ========================================================================

    async def connect(self, address: Optional[str] = None, timeout: float = 30.0, retries: int = 3) -> bool:
        """Connect to Oura Ring.

        Args:
            address: Optional identity address. If None, tries bonded address or scans.
            timeout: Connection timeout in seconds.
            retries: Number of connection attempts.

        Returns:
            True if connected successfully.
        """
        # Try bonded address if no address provided
        if not address:
            address = self._load_bonded_address()

        # Step 1: Scan to find device
        self._log('info', "Scanning for Oura Ring (must be awake - put on charger briefly)...")
        self.device = await self.scan(timeout=15.0)

        if not self.device:
            self._log('error', "Oura Ring not found during scan!")
            return False

        # Use scanned address if no bonded address
        if not address:
            address = self.device.address
            self._log('info', f"Using scanned address: {address}")

        # Step 2: Connect via identity address string
        self._log('info', f"Connecting to identity address {address}...")

        for attempt in range(retries):
            self._log('info', f"Attempt {attempt + 1}/{retries}...")
            self._emit_progress('connect', attempt + 1, retries, f"Connection attempt {attempt + 1}")

            try:
                self.client = BleakClient(address, adapter=self.adapter)
                await self.client.connect(timeout=timeout)
                if self.client.is_connected:
                    self._log('success', "Connected!")
                    break
            except Exception as e:
                self._log('error', f"Connection failed: {e}")
                if attempt < retries - 1:
                    self._log('info', "Retrying...")
                    await asyncio.sleep(2)

        if not self.client or not self.client.is_connected:
            self._log('error', "Connection failed after all retries!")
            return False

        self.is_connected = True
        self._emit_status()

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
            self._log('info', "Attempting to pair...")
            try:
                await self.client.pair(protection_level=2)
                self._log('success', "Paired successfully!")
            except Exception as e:
                self._log('warn', f"Pair attempt: {e}")
                self._log('info', "Pairing failed - will try to continue (ring may already be paired)")

        # Save bonded address
        identity_addr = self._get_identity_address_from_bluez()
        if identity_addr:
            self._save_bonded_address(identity_addr)
        elif not needs_pairing:
            self._save_bonded_address(address)

        # Enable notifications
        self._log('info', "Enabling notifications...")
        await self.client.start_notify(NOTIFY_CHAR_UUID, self._notification_handler)
        self._log('success', "Notifications enabled!")

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
        self._emit_status()
        self._log('info', "Disconnected")

    # ========================================================================
    # Notification Handler
    # ========================================================================

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
                self._log('info', f"Received auth nonce: {format_hex(self.pending_nonce)}")
                if self.on_auth_response:
                    self.on_auth_response('nonce', self.pending_nonce)

            # Auth result: 2f <subcmd> 2e <status>
            elif ext_tag == 0x2e and len(data) >= 4:
                status = data[3]
                if status == 0x00:
                    self._log('success', "Authentication SUCCESS!")
                    self.is_authenticated = True
                else:
                    self._log('error', f"Authentication FAILED (status={status})")
                    self.is_authenticated = False
                self._emit_status()
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
                        self._log('info', f"Heartbeat #{self.heartbeat_count}: {bpm:.1f} BPM (IBI: {ibi_ms}ms)")

        # TIME_SYNC response (0x13)
        elif tag == 0x13 and len(data) >= 6:
            ring_time_deciseconds = struct.unpack('<I', data[2:6])[0]
            utc_millis = int(time.time() * 1000)

            sync_point = {
                'ring_time': ring_time_deciseconds,
                'utc_millis': utc_millis,
                'timestamp': datetime.now().isoformat()
            }
            self.time_sync_points.append(sync_point)

            self._log('success', f"Time sync: ring_time={ring_time_deciseconds} deciseconds")
            self._log('info', f"Ring timestamp at {datetime.now().strftime('%H:%M:%S')}")

            if self.on_sync_point:
                self.on_sync_point(sync_point)

        # Event data (0x11 response)
        elif tag == 0x11 and len(data) >= 8:
            events_received = data[2] & 0xFF
            self.bytes_left = struct.unpack('<I', data[4:8])[0] if len(data) >= 8 else 0
            self.probe_events_received = events_received
            self.current_seq_num += events_received

            self._log('info', f"Batch: {events_received} events, bytes_left={self.bytes_left}, next_seq={self.current_seq_num}")

            if self.bytes_left == 0:
                self.fetch_complete = True

        # Other events
        elif tag >= 0x41:
            if self.current_filter is None or self.current_filter.should_include(tag):
                self.event_data.append(data)

                if self.stop_after_count and len(self.event_data) >= self.stop_after_count:
                    self.fetch_complete = True
                elif self.stop_after_type and tag == self.stop_after_type:
                    self.event_type_count += 1
                    if self.event_type_count >= (self.stop_after_count or 1):
                        self.fetch_complete = True

            if self.on_event:
                self.on_event(tag, get_event_name(tag), data)

    # ========================================================================
    # Commands
    # ========================================================================

    async def send_command(self, cmd: bytes, description: str = "") -> bool:
        """Send command to ring."""
        if not self.client or not self.client.is_connected:
            self._log('error', "Not connected!")
            return False

        if description:
            self._log('info', f"Sending: {description}")

        try:
            await self.client.write_gatt_char(WRITE_CHAR_UUID, cmd)
            await asyncio.sleep(0.3)
            return True
        except Exception as e:
            self._log('error', f"Send error: {e}")
            return False

    # ========================================================================
    # Authentication
    # ========================================================================

    async def authenticate(self, auth_key: Optional[bytes] = None) -> bool:
        """Perform authentication with ring."""
        key = auth_key or self.auth_key
        if not key:
            self._log('error', "No auth key provided!")
            return False

        self._log('info', "=== AUTHENTICATION ===")

        # Step 1: Get nonce
        self._log('info', "Step 1: Getting auth nonce...")
        self.pending_nonce = None
        self.received_data.clear()
        await self.send_command(CMD_GET_AUTH_NONCE, "GetAuthNonce")

        for _ in range(20):
            if self.pending_nonce:
                break
            await asyncio.sleep(0.1)

        if not self.pending_nonce:
            self._log('error', "No nonce received!")
            return False

        # Step 2: Encrypt nonce
        self._log('info', "Step 2: Encrypting nonce...")
        try:
            encrypted = encrypt_nonce(self.pending_nonce, key)
            self._log('info', f"Encrypted: {format_hex(encrypted)}")
        except Exception as e:
            self._log('error', f"Encryption error: {e}")
            return False

        # Step 3: Send authenticate command
        self._log('info', "Step 3: Sending authenticate command...")
        auth_cmd = build_auth_cmd(encrypted)
        self.received_data.clear()
        await self.send_command(auth_cmd, "Authenticate")

        for _ in range(20):
            if self.is_authenticated:
                self.auth_key = key
                self._save_auth_key(key)
                return True
            await asyncio.sleep(0.1)

        self._log('error', "Authentication timeout!")
        return False

    # ========================================================================
    # Time Sync
    # ========================================================================

    async def sync_time(self) -> bool:
        """Sync time with ring."""
        if not self.is_authenticated:
            self._log('error', "Must be authenticated first!")
            return False

        self._log('info', "=== TIME SYNC ===")
        cmd = build_time_sync_cmd()
        await self.send_command(cmd, "TimeSync")
        await asyncio.sleep(1)
        return True

    # ========================================================================
    # Heartbeat Monitoring
    # ========================================================================

    async def start_heartbeat(self, duration: Optional[int] = None):
        """Start heartbeat monitoring."""
        if not self.is_authenticated:
            self._log('error', "Must be authenticated first!")
            return

        self._log('info', "=== STARTING HEARTBEAT MONITORING ===")
        self._heartbeat_running = True

        await self.send_command(CMD_INIT_1, "Init 1")
        await self.send_command(CMD_INIT_2, "Init 2")
        await self.send_command(CMD_START_STREAM, "Start Stream")

        self._log('success', "Monitoring active!")

        try:
            if duration:
                await asyncio.sleep(duration)
            else:
                while self._heartbeat_running:
                    await asyncio.sleep(1)
        except asyncio.CancelledError:
            pass

        await self.stop_heartbeat()

    async def stop_heartbeat(self):
        """Stop heartbeat monitoring."""
        self._heartbeat_running = False
        await self.send_command(CMD_STOP, "Stop")
        self._log('info', f"Total heartbeats: {self.heartbeat_count}")

    # ========================================================================
    # Data Retrieval
    # ========================================================================

    async def find_last_event_seq(self) -> tuple:
        """Binary search to find the last valid event sequence number."""
        self._log('info', "=== BINARY SEARCH: Finding last event sequence ===")

        self.event_data.clear()
        probe_low = 0
        probe_high = 50_000_000
        last_valid_seq = -1
        first_valid_seq = -1
        self.probe_events_received = 0

        iterations = 0
        max_iterations = 30

        while probe_high - probe_low > 1 and iterations < max_iterations:
            mid = (probe_low + probe_high) // 2
            self._log('info', f"Probing seq {mid} (range: [{probe_low}, {probe_high}])...")
            self._emit_progress('binary_search', iterations, max_iterations, f"Probing seq {mid}")

            self.current_seq_num = mid
            self.bytes_left = -1
            self.probe_events_received = 0
            self.fetch_complete = False

            cmd = build_get_event_cmd(mid, max_events=1)
            await self.send_command(cmd, None)
            await asyncio.sleep(0.3)

            if self.probe_events_received > 0:
                last_valid_seq = mid
                if first_valid_seq < 0:
                    first_valid_seq = mid
                probe_low = mid
                self._log('success', f"Found events! last_valid={last_valid_seq}")
            else:
                probe_high = mid
                self._log('info', "No events, searching lower...")

            iterations += 1

        self.event_data.clear()

        if last_valid_seq >= 0:
            self._log('success', f"Binary search complete!")
            self._log('info', f"Last valid sequence: {last_valid_seq}")
            self._log('info', f"First found sequence: {first_valid_seq}")
            self._log('info', f"Estimated total events: ~{last_valid_seq + 1}")
        else:
            self._log('warn', "Ring appears to be empty (no events found)")

        return (last_valid_seq, first_valid_seq)

    async def get_data(
        self,
        start_seq: int = -1,
        max_events: int = 0,
        event_filter: Optional[EventFilter] = None,
        stop_after_count: Optional[int] = None,
        stop_after_type: Optional[int] = None,
        fetch_all: bool = False
    ) -> List[bytes]:
        """Get stored event data from ring with optional filtering."""
        if not self.is_authenticated:
            self._log('error', "Must be authenticated first!")
            return []

        if start_seq < 0:
            last_valid_seq, first_valid_seq = await self.find_last_event_seq()
            if last_valid_seq < 0:
                self._log('warn', "No events found on ring!")
                return []

            if fetch_all:
                start_seq = first_valid_seq
                self._log('info', f"FETCH ALL: Will fetch from seq {first_valid_seq} to {last_valid_seq}")
            else:
                start_seq = first_valid_seq
                self._log('info', f"Will fetch from seq {start_seq} to {last_valid_seq}")

        self._log('info', f"=== GETTING DATA (starting from seq {start_seq}) ===")

        self.event_data.clear()
        self.current_seq_num = start_seq
        self.fetch_complete = False
        self.current_filter = event_filter
        self.stop_after_count = stop_after_count
        self.stop_after_type = stop_after_type
        self.event_type_count = 0

        batch_count = 0
        while not self.fetch_complete:
            cmd = build_get_event_cmd(self.current_seq_num, max_events)
            await self.send_command(cmd, f"GetEvent (seq={self.current_seq_num})")
            await asyncio.sleep(0.5)

            batch_count += 1
            self._emit_progress('get_data', len(self.event_data), 0, f"Received {len(self.event_data)} events")

            if batch_count > 1000:
                self._log('warn', "Max batches reached")
                break

        self.current_filter = None
        self.stop_after_count = None
        self.stop_after_type = None

        self._log('success', f"Received {len(self.event_data)} events")
        return self.event_data

    # ========================================================================
    # Auth Key Management
    # ========================================================================

    async def set_auth_key(self, new_key: bytes) -> bool:
        """Write new auth key to ring."""
        if len(new_key) != 16:
            self._log('error', f"Auth key must be 16 bytes, got {len(new_key)}")
            return False

        self._log('info', f"Setting new auth key: {format_hex(new_key)}")
        cmd = build_set_auth_key_cmd(new_key)
        await self.send_command(cmd, "SetAuthKey")

        self.auth_key = new_key
        self._save_auth_key(new_key)
        return True

    # ========================================================================
    # Factory Reset
    # ========================================================================

    async def factory_reset(self, confirmed: bool = False) -> bool:
        """DANGEROUS: Factory reset ring (erases ALL data and auth key)."""
        if not confirmed:
            self._log('error', "Factory reset requires explicit confirmation!")
            return False

        self._log('warn', "="*60)
        self._log('warn', "FACTORY RESET - ERASING ALL DATA")
        self._log('warn', "="*60)

        await self.send_command(CMD_FACTORY_RESET, "Factory Reset")

        self._log('success', "Factory reset command sent. Ring will reboot.")
        self._log('info', "You will need to re-pair and authenticate with default key.")

        return True

    # ========================================================================
    # Sync Point Management
    # ========================================================================

    def save_sync_point(self, filename: Optional[str] = None, description: str = None) -> bool:
        """Save the latest sync point to file."""
        if not self.time_sync_points:
            self._log('error', "No sync points captured - run sync_time() first")
            return False

        latest = self.time_sync_points[-1]
        sync_point = {
            'ring_time': latest['ring_time'],
            'utc_millis': latest['utc_millis'],
            'timestamp': latest['timestamp'],
            'description': description or 'Time sync captured via oura.ble'
        }

        filepath = self.data_dir / (filename or SYNC_POINT_FILE)
        filepath.parent.mkdir(parents=True, exist_ok=True)

        with open(filepath, 'w') as f:
            json.dump(sync_point, f, indent=2)

        self._log('success', f"Saved sync point to {filepath}")
        return True

    # ========================================================================
    # File Storage Helpers
    # ========================================================================

    def _load_auth_key(self) -> Optional[bytes]:
        """Load stored auth key from file."""
        key_path = self.data_dir / AUTH_KEY_FILE
        if key_path.exists():
            try:
                with open(key_path, 'rb') as f:
                    key = f.read()
                if len(key) == 16:
                    self._log('info', f"Loaded stored auth key")
                    return key
            except Exception as e:
                self._log('warn', f"Could not load auth key: {e}")
        return None

    def _save_auth_key(self, key: bytes):
        """Save auth key to file."""
        try:
            key_path = self.data_dir / AUTH_KEY_FILE
            key_path.parent.mkdir(parents=True, exist_ok=True)
            with open(key_path, 'wb') as f:
                f.write(key)
            self._log('info', f"Saved auth key")
        except Exception as e:
            self._log('warn', f"Could not save auth key: {e}")

    def _load_bonded_address(self) -> Optional[str]:
        """Load bonded device address."""
        # First try BlueZ
        identity_addr = self._get_identity_address_from_bluez()
        if identity_addr:
            self._log('info', f"Found bonded device (BlueZ): {identity_addr}")
            return identity_addr

        # Check stored file
        addr_path = self.data_dir / BONDED_ADDRESS_FILE
        if addr_path.exists():
            # BlueZ has no bond, stored address may be stale
            self._log('info', "No bond in BlueZ - stored address may be stale, ignoring")
            try:
                addr_path.unlink()
            except:
                pass

        return None

    def _save_bonded_address(self, address: str):
        """Save bonded device address."""
        try:
            addr_path = self.data_dir / BONDED_ADDRESS_FILE
            addr_path.parent.mkdir(parents=True, exist_ok=True)
            with open(addr_path, 'w') as f:
                f.write(address)
            self._log('info', f"Saved bonded device address")
        except Exception as e:
            self._log('warn', f"Could not save bonded address: {e}")

    def _get_identity_address_from_bluez(self) -> Optional[str]:
        """Get the identity address from BlueZ for bonded Oura Ring via D-Bus."""
        try:
            import dbus

            bus = dbus.SystemBus()
            obj = bus.get_object("org.bluez", "/")
            manager = dbus.Interface(obj, "org.freedesktop.DBus.ObjectManager")
            objects = manager.GetManagedObjects()

            adapter_path = f"/org/bluez/{self.adapter}/"

            for path, interfaces in objects.items():
                if not str(path).startswith(adapter_path):
                    continue
                if "org.bluez.Device1" not in interfaces:
                    continue

                props = interfaces["org.bluez.Device1"]
                paired = bool(props.get("Paired", False))
                address = str(props.get("Address", ""))

                if not paired or not address:
                    continue

                name = str(props.get("Name", ""))
                alias = str(props.get("Alias", ""))

                if "Oura" in name or "Oura" in alias:
                    return address

                if address.upper().startswith("A0:38:F8"):
                    return address

        except ImportError:
            pass
        except Exception:
            pass

        # Fallback to bluetoothctl
        try:
            import subprocess
            result = subprocess.run(
                ["bluetoothctl", "devices", "Paired"],
                capture_output=True, text=True, timeout=5
            )
            for line in result.stdout.splitlines():
                parts = line.split()
                if len(parts) >= 2:
                    addr = parts[1]
                    if "Oura" in line or addr.upper().startswith("A0:38:F8"):
                        return addr
        except:
            pass

        return None

    # ========================================================================
    # Event File Export
    # ========================================================================

    def save_events_to_file(self, filename: Optional[str] = None) -> bool:
        """Save collected events to file in standard format."""
        if not self.event_data:
            self._log('error', "No events to save")
            return False

        filepath = self.data_dir / (filename or "ring_events.txt")
        filepath.parent.mkdir(parents=True, exist_ok=True)

        with open(filepath, 'w') as f:
            f.write("# Oura Ring Event Export\n")
            f.write(f"# Timestamp: {datetime.now().strftime('%a %b %d %H:%M:%S %Z %Y')}\n")
            f.write(f"# Events: {len(self.event_data)}\n")
            f.write("#\n")
            f.write("# Format: index|tag_hex|event_name|hex_data\n")
            f.write("#\n")
            for i, event in enumerate(self.event_data):
                tag = event[0] if event else 0
                f.write(f"{i}|0x{tag:02x}|{get_event_name(tag)}|{event.hex()}\n")

        self._log('success', f"Saved {len(self.event_data)} events to {filepath}")
        return True
