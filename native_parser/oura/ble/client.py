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

        # Callbacks for events
        self.on_heartbeat: Optional[Callable[[int, int, float, int], None]] = None
        self.on_event: Optional[Callable[[int, str, bytes], None]] = None
        self.on_auth_response: Optional[Callable[[str, Any], None]] = None

        # Callbacks for web integration (must be initialized before _load_auth_key)
        self.on_log: Optional[Callable[[str, str], None]] = None
        self.on_status_change: Optional[Callable[[dict], None]] = None
        self.on_progress: Optional[Callable[[str, int, int, str], None]] = None
        self.on_sync_point: Optional[Callable[[dict], None]] = None

        # Load stored auth key if no key provided (after callbacks init)
        if auth_key:
            self.auth_key = auth_key
        else:
            self.auth_key = self._load_auth_key() or DEFAULT_AUTH_KEY

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
        """Connect to Oura Ring using scan + identity address approach.

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

        # Check if device is already connected via BlueZ - disconnect first so Bleak can connect
        if address:
            await self._disconnect_if_bluez_connected(address)

        # Step 1: Scan to find device (populates Bleak's cache)
        self._log('info', "Scanning for Oura Ring (must be awake - put on charger briefly)...")
        self.device = await self.scan(timeout=15.0)

        if not self.device:
            self._log('error', "Oura Ring not found during scan!")
            self._log('info', "Tip: Put ring on charger to wake it up, then try again.")
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

        # Note: Pairing is now handled separately via the Pair button
        # Connect just establishes the BLE connection

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

            # Convert ring time to human-readable format
            ring_hours = ring_time_deciseconds / 36000  # deciseconds to hours
            self._log('success', f"Time sync captured: ring uptime {ring_hours:.1f}h")

            # Always save to file immediately so get_data() can load it
            self.save_sync_point()

            if self.on_sync_point:
                self.on_sync_point(sync_point)

        # Event data (0x11 response)
        elif tag == 0x11 and len(data) >= 8:
            events_received = data[2] & 0xFF
            self.bytes_left = struct.unpack('<I', data[4:8])[0] if len(data) >= 8 else 0
            self.probe_events_received = events_received
            self.current_seq_num += events_received

            self._log('info', f"Batch: {events_received} events, bytes_left={self.bytes_left}, next_seq={self.current_seq_num}")

            # NOTE: Don't set fetch_complete here - let the get_data loop handle it
            # after events have had time to stream in

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
        fetch_all: bool = False,
        target_seq: int = -1,
        save_between_batches: bool = True,
        output_file: Optional[str] = None,
        append_mode: bool = False
    ) -> List[bytes]:
        """Get stored event data from ring with optional filtering.

        When fetch_all=True, handles the ring's ~50K event limit per streaming
        session by automatically fetching in batches until all data is retrieved.

        Args:
            target_seq: If specified, keep batching until we reach this sequence.
                       If -1 and fetch_all=True, will auto-detect via binary search.
            save_between_batches: If True, save to file after each batch (prevents data loss)
            output_file: Output filename for incremental saves (default: ring_events.txt)
        """
        if not self.is_authenticated:
            self._log('error', "Must be authenticated first!")
            return []

        # Load sync point for timestamp-based end detection
        sync_point = self._load_sync_point()
        sync_ring_time = sync_point.get('ring_time')
        sync_utc_millis = sync_point.get('utc_millis')

        if sync_ring_time and sync_utc_millis:
            self._log('info', f"Sync point loaded: ring_time={sync_ring_time}")
        else:
            self._log('warn', "No sync point - timestamp detection disabled")

        # Determine starting point for fetch
        # With timestamp-based approach, we don't need binary search if start_seq is provided
        # End detection is handled by "caught up to real-time" check (timestamp near now)
        if start_seq >= 0:
            # We know where to start - no binary search needed
            self._log('info', f"Starting from timestamp {start_seq} (binary search skipped)")
        elif fetch_all and target_seq < 0:
            # No start point and fetch_all - use binary search to find range
            last_valid_seq, first_valid_seq = await self.find_last_event_seq()
            if last_valid_seq < 0:
                self._log('warn', "No events found on ring!")
                return []
            target_seq = last_valid_seq
            start_seq = 0  # Start from beginning for complete fetch
            self._log('info', f"FETCH ALL: seq {start_seq} to {target_seq} (batched, ~50K per batch)")
        elif start_seq < 0:
            # No start point - use binary search
            last_valid_seq, first_valid_seq = await self.find_last_event_seq()
            if last_valid_seq < 0:
                self._log('warn', "No events found on ring!")
                return []
            start_seq = first_valid_seq
            self._log('info', f"Will fetch from seq {start_seq} to {last_valid_seq}")

        self._log('info', f"=== GETTING DATA (starting from seq {start_seq}) ===")

        self.current_filter = event_filter
        self.stop_after_count = stop_after_count
        self.stop_after_type = stop_after_type
        self.event_type_count = 0

        import time
        overall_start_time = time.time()
        all_events: List[bytes] = []
        batch_num = 0
        # NOTE: GetEvent parameter is a TIMESTAMP (ring_time), not a sequence number!
        # We use the max timestamp from each batch to paginate, not event count.
        current_timestamp = start_seq  # start_seq is actually a starting timestamp

        # Batch fetching loop - ring limits streaming to ~50K events per session
        while True:
            batch_num += 1
            self._log('info', f"=== BATCH {batch_num}: Fetching from timestamp {current_timestamp} ===")

            # Reset state for this batch
            self.event_data.clear()
            self.current_seq_num = current_timestamp  # Track for notification handler
            self.fetch_complete = False
            self.bytes_left = -1

            batch_start_time = time.time()

            # Send GetEvent command with timestamp (not sequence number!)
            # Ring returns events with ring_time >= current_timestamp
            cmd = build_get_event_cmd(current_timestamp, max_events)
            await self.send_command(cmd, f"GetEvent (timestamp={current_timestamp}, stream)")

            # Wait for batch to complete
            last_count = 0
            stall_count = 0

            while not self.fetch_complete:
                await asyncio.sleep(1.0)
                current = len(self.event_data)
                batch_elapsed = time.time() - batch_start_time
                total_elapsed = time.time() - overall_start_time
                total_events = len(all_events) + current

                # Progress update
                rate = total_events / total_elapsed if total_elapsed > 0 else 0
                self._log('info', f"Batch {batch_num} [{batch_elapsed:.0f}s]: {current} events, "
                         f"total={total_events} ({rate:.0f}/sec), bytes_left={self.bytes_left}")
                self._emit_progress('get_data', total_events, 0, f"Batch {batch_num}: {total_events} events")

                # Check completion
                if self.bytes_left == 0:
                    self.fetch_complete = True
                elif current == last_count:
                    stall_count += 1
                    if stall_count >= 3:  # Stalled - end of batch (50K limit)
                        self._log('info', f"Batch {batch_num} stalled at {current} events")
                        self.fetch_complete = True
                else:
                    stall_count = 0

                last_count = current

                # Per-batch timeout (2 minutes)
                if batch_elapsed > 120:
                    self._log('warn', f"Batch {batch_num} timeout!")
                    break

            # Accumulate events from this batch
            batch_events = len(self.event_data)
            all_events.extend(self.event_data)
            self._log('success', f"Batch {batch_num} complete: {batch_events} events")

            # Update current timestamp for next batch
            # FIX: Use MAX timestamp from received events, not event count!
            # This prevents getting the same events repeatedly.
            if batch_events > 0 and self.event_data:
                # Extract max timestamp from received events (bytes 2-5, little-endian)
                timestamps = []
                for e in self.event_data:
                    if len(e) >= 6:
                        ts = int.from_bytes(e[2:6], 'little')
                        if ts > 0:
                            timestamps.append(ts)
                if timestamps:
                    max_ts = max(timestamps)
                    current_timestamp = max_ts + 1  # Next batch starts AFTER this timestamp
                    self._log('info', f"Max timestamp in batch: {max_ts}, next request from {current_timestamp}")

            # Save to file between batches (prevents data loss if interrupted)
            if save_between_batches and len(all_events) > 0:
                filepath = self.data_dir / (output_file or "ring_events.txt")
                filepath.parent.mkdir(parents=True, exist_ok=True)

                if append_mode:
                    # Append new events only (for incremental sync)
                    # Index is based on total events, not timestamp
                    start_idx = len(all_events) - batch_events
                    with open(filepath, 'a') as f:
                        for idx, event in enumerate(self.event_data):
                            tag = event[0] if event else 0
                            f.write(f"{start_idx + idx}|0x{tag:02x}|{get_event_name(tag)}|{event.hex()}\n")
                    self._log('info', f"Appended {batch_events} events to {filepath}")
                else:
                    # Overwrite with all events (for full fetch)
                    with open(filepath, 'w') as f:
                        f.write("# Oura Ring Event Export (in progress)\n")
                        f.write(f"# Events so far: {len(all_events)}\n")
                        f.write("#\n")
                        f.write("# Format: index|tag_hex|event_name|hex_data\n")
                        f.write("#\n")
                        for i, event in enumerate(all_events):
                            tag = event[0] if event else 0
                            f.write(f"{i}|0x{tag:02x}|{get_event_name(tag)}|{event.hex()}\n")
                    self._log('info', f"Saved {len(all_events)} events to {filepath}")

            # fetch_all mode: check if caught up to real-time via timestamp
            if fetch_all:
                if batch_events == 0:
                    self._log('success', "All data fetched (0 events in batch)")
                    break

                # Timestamp-based end detection: stop when latest event is near "now"
                if sync_ring_time and sync_utc_millis and self.event_data:
                    # Get latest event's timestamp (bytes 2-5, little-endian, in deciseconds)
                    latest_event = self.event_data[-1]
                    if len(latest_event) >= 6:
                        latest_ts = int.from_bytes(latest_event[2:6], 'little')
                        # Calculate current ring time (ring_time is in deciseconds!)
                        current_utc_ms = int(time.time() * 1000)
                        ring_time_now = sync_ring_time + (current_utc_ms - sync_utc_millis) / 100  # ms to deciseconds
                        time_diff_ds = ring_time_now - latest_ts  # in deciseconds
                        time_diff_sec = time_diff_ds / 10  # convert to seconds for display

                        if 0 <= time_diff_sec < 30:  # Within 30 seconds of "now" (and not negative)
                            self._log('success', f"Caught up to real-time! (latest_ts={latest_ts}, now={ring_time_now:.0f}, diff={time_diff_sec:.1f}s)")
                            break
                        elif batch_num % 10 == 0:  # Log progress every 10 batches
                            self._log('info', f"Time remaining: {time_diff_sec:.0f}s behind real-time")

                # Ring's bytes_left=0 just means "session limit reached", not "no more data"
                self._log('info', f"Continuing to next batch from timestamp {current_timestamp}...")
                await asyncio.sleep(0.5)
                continue

            # Single batch mode
            if self.bytes_left == 0:
                self._log('success', "All data fetched (bytes_left=0)")
                break

            if self.bytes_left > 0:
                self._log('info', f"More data available ({self.bytes_left} bytes). "
                         "Use --get-all-data to fetch everything.")
            break

        self.current_filter = None
        self.stop_after_count = None
        self.stop_after_type = None

        elapsed = time.time() - overall_start_time
        self._log('success', f"=== FETCH COMPLETE: {len(all_events)} events in {elapsed:.1f}s ({batch_num} batches) ===")

        # Final save with "complete" header (only for full fetch, not append mode)
        if save_between_batches and all_events and not append_mode:
            filepath = self.data_dir / (output_file or "ring_events.txt")
            with open(filepath, 'w') as f:
                f.write("# Oura Ring Event Export\n")
                f.write(f"# Timestamp: {datetime.now().strftime('%a %b %d %H:%M:%S %Z %Y')}\n")
                f.write(f"# Events: {len(all_events)}\n")
                f.write("#\n")
                f.write("# Format: index|tag_hex|event_name|hex_data\n")
                f.write("#\n")
                for i, event in enumerate(all_events):
                    tag = event[0] if event else 0
                    f.write(f"{i}|0x{tag:02x}|{get_event_name(tag)}|{event.hex()}\n")
            self._log('success', f"Final save: {len(all_events)} events to {filepath}")

        # Store in event_data for save_events_to_file()
        self.event_data = all_events
        return all_events

    async def get_data_incremental(
        self,
        event_filter: Optional[EventFilter] = None,
        sync_point_file: Optional[str] = None
    ) -> List[bytes]:
        """Get only NEW events since last sync using timestamp-based pagination.

        This method tracks `last_synced_ring_time` in the sync_point.json file and only
        fetches events with timestamps greater than the last sync.

        How it works (timestamp-based approach):
        1. Load `last_synced_ring_time` from sync_point.json (default: 0)
        2. Fetch events with ring_time > last_synced_ring_time
        3. After successful fetch, extract max ring_time and update sync_point.json

        Args:
            event_filter: Optional event type filter
            sync_point_file: Optional sync point filename

        Returns:
            List of raw event bytes (only NEW events since last sync)
        """
        if not self.is_authenticated:
            self._log('error', "Must be authenticated first!")
            return []

        # Scan events file to find max timestamp - this is our starting point
        events_file = self.data_dir / "ring_events.txt"
        last_ring_time = 0
        if events_file.exists():
            last_ring_time = self._find_max_timestamp_in_file(events_file)
            self._log('info', f"Events file max ring_time: {last_ring_time}")

        self._log('info', "="*60)
        self._log('info', "INCREMENTAL SYNC (timestamp-based)")
        self._log('info', "="*60)

        # Fetch from last_ring_time + 1 to avoid duplicates
        start_timestamp = last_ring_time + 1 if last_ring_time > 0 else 0
        self._log('info', f"Fetching events with ring_time >= {start_timestamp}...")

        events = await self.get_data(
            start_seq=start_timestamp,  # This is actually a timestamp!
            event_filter=event_filter,
            fetch_all=True,  # Fetch all new events in batches
            append_mode=True  # Append to existing file, don't overwrite
        )

        if events:
            # Find max ring_time for logging
            max_ring_time = max(
                int.from_bytes(e[2:6], 'little') for e in events if len(e) >= 6
            )
            self._log('success', f"Fetched {len(events)} new events (ring_time {start_timestamp} -> {max_ring_time})")
        else:
            self._log('info', "No new events (already up to date)")

        return events

    def _update_sync_point_ring_time(self, ring_time: int, filename: Optional[str] = None):
        """Update sync_point.json with new last_synced_ring_time."""
        filepath = self.data_dir / (filename or SYNC_POINT_FILE)

        # Load existing or create new
        sync_point = {}
        if filepath.exists():
            try:
                with open(filepath) as f:
                    sync_point = json.load(f)
            except Exception:
                pass

        # Update with new ring_time
        sync_point['last_synced_ring_time'] = ring_time

        # Write back
        with open(filepath, 'w') as f:
            json.dump(sync_point, f, indent=2)

        self._log('info', f"Updated last_synced_ring_time: {ring_time}")

    def _find_max_timestamp_in_file(self, filepath: Path) -> int:
        """Scan events file to find maximum ring_time timestamp."""
        max_ts = 0
        try:
            with open(filepath) as f:
                for line in f:
                    if line.startswith('#') or not line.strip():
                        continue
                    parts = line.strip().split('|')
                    if len(parts) >= 4:
                        hex_data = parts[3]
                        if len(hex_data) >= 12:
                            ts = int.from_bytes(bytes.fromhex(hex_data[4:12]), 'little')
                            if ts > max_ts:
                                max_ts = ts
        except Exception:
            pass
        return max_ts

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

    def _load_sync_point(self, filename: Optional[str] = None) -> dict:
        """Load sync point from file.

        Returns:
            Dict with sync point data, or empty dict if not found.
            Keys: ring_time, utc_millis, timestamp, description, last_synced_seq
        """
        filepath = self.data_dir / (filename or SYNC_POINT_FILE)
        if not filepath.exists():
            return {}

        try:
            with open(filepath, 'r') as f:
                return json.load(f)
        except Exception as e:
            self._log('warn', f"Could not load sync point: {e}")
            return {}

    def load_sync_point(self, filename: Optional[str] = None) -> bool:
        """Load sync point from file and populate time_sync_points for time conversion.

        Use this instead of sync_time() when you want to use existing sync data
        without communicating with the ring.

        Returns:
            True if sync point loaded successfully, False otherwise.
        """
        sync_point = self._load_sync_point(filename)
        if not sync_point or 'ring_time' not in sync_point or 'utc_millis' not in sync_point:
            self._log('error', "No valid sync point found - run sync_time() first")
            return False

        # Populate time_sync_points from loaded data
        self.time_sync_points = [sync_point]
        self._log('info', f"Loaded sync point: ring_time={sync_point['ring_time']}, "
                         f"timestamp={sync_point.get('timestamp', 'N/A')}")
        return True

    def save_sync_point(
        self,
        filename: Optional[str] = None,
        description: str = None,
        last_synced_seq: Optional[int] = None
    ) -> bool:
        """Save the latest sync point to file.

        Args:
            filename: Optional filename (uses default if not specified)
            description: Optional description string
            last_synced_seq: Optional last synced sequence number for incremental sync
        """
        if not self.time_sync_points:
            self._log('error', "No sync points captured - run sync_time() first")
            return False

        latest = self.time_sync_points[-1]

        # Load existing sync point to preserve last_synced_seq if not provided
        filepath = self.data_dir / (filename or SYNC_POINT_FILE)
        existing = {}
        if filepath.exists():
            try:
                with open(filepath, 'r') as f:
                    existing = json.load(f)
            except:
                pass

        sync_point = {
            'ring_time': latest['ring_time'],
            'utc_millis': latest['utc_millis'],
            'timestamp': latest['timestamp'],
            'description': description or 'Time sync captured via oura.ble'
        }

        # Preserve or update last_synced_seq (legacy)
        if last_synced_seq is not None:
            sync_point['last_synced_seq'] = last_synced_seq
        elif 'last_synced_seq' in existing:
            sync_point['last_synced_seq'] = existing['last_synced_seq']

        # Preserve last_synced_ring_time (new timestamp-based approach)
        if 'last_synced_ring_time' in existing:
            sync_point['last_synced_ring_time'] = existing['last_synced_ring_time']

        filepath.parent.mkdir(parents=True, exist_ok=True)

        with open(filepath, 'w') as f:
            json.dump(sync_point, f, indent=2)

        self._log('success', f"Saved sync point to {filepath}")
        if 'last_synced_ring_time' in sync_point:
            self._log('info', f"  last_synced_ring_time: {sync_point['last_synced_ring_time']}")
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

    async def _connect_via_dbus(self, address: str, timeout: float = 15.0) -> bool:
        """Connect to bonded device via D-Bus (works without scanning).

        Args:
            address: Device address (identity address)
            timeout: Connection timeout in seconds

        Returns:
            True if connected successfully
        """
        try:
            import dbus

            bus = dbus.SystemBus()
            device_path = f"/org/bluez/{self.adapter}/dev_{address.replace(':', '_')}"

            try:
                device_obj = bus.get_object("org.bluez", device_path)
                device = dbus.Interface(device_obj, "org.bluez.Device1")
                props = dbus.Interface(device_obj, "org.freedesktop.DBus.Properties")
            except dbus.exceptions.DBusException as e:
                self._log('warn', f"Device not found in BlueZ: {e}")
                return False

            # Check if already connected
            connected = props.Get("org.bluez.Device1", "Connected")
            if connected:
                self._log('info', "Device already connected via BlueZ")
            else:
                # Initiate connection via D-Bus
                self._log('info', "Connecting via D-Bus...")
                device.Connect()

                # Wait for connection
                for _ in range(int(timeout * 2)):
                    await asyncio.sleep(0.5)
                    connected = props.Get("org.bluez.Device1", "Connected")
                    if connected:
                        break

                if not connected:
                    self._log('warn', "D-Bus connection timed out")
                    return False

            # Now create BleakClient from connected device
            self._log('info', "Creating BleakClient from connected device...")
            self.client = BleakClient(address, adapter=self.adapter)
            await self.client.connect(timeout=5.0)

            if self.client.is_connected:
                return True
            else:
                self._log('warn', "BleakClient failed to connect after D-Bus connect")
                return False

        except ImportError:
            self._log('warn', "dbus module not available")
            return False
        except Exception as e:
            self._log('warn', f"D-Bus connect failed: {e}")
            return False

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

    async def _disconnect_if_bluez_connected(self, address: str):
        """Disconnect device if already connected via BlueZ (blocking Bleak)."""
        try:
            import dbus
            bus = dbus.SystemBus()
            addr_path = address.replace(':', '_').upper()
            device_path = f"/org/bluez/{self.adapter}/dev_{addr_path}"
            device_obj = bus.get_object("org.bluez", device_path)
            props = dbus.Interface(device_obj, "org.freedesktop.DBus.Properties")
            is_connected = bool(props.Get("org.bluez.Device1", "Connected"))
            if is_connected:
                self._log('info', "Ring already connected via BlueZ, disconnecting first...")
                device_iface = dbus.Interface(device_obj, "org.bluez.Device1")
                device_iface.Disconnect()
                await asyncio.sleep(0.5)
        except ImportError:
            pass  # dbus not available
        except Exception:
            pass  # Device not in BlueZ or other error

    # ========================================================================
    # Event File Export
    # ========================================================================

    def save_events_to_file(self, filename: Optional[str] = None, append: bool = False) -> bool:
        """Save collected events to file in standard format.

        Args:
            filename: Output filename (default: ring_events.txt)
            append: If True, append to existing file instead of overwriting.
                   Used for incremental sync to accumulate events.

        Returns:
            True if saved successfully.
        """
        if not self.event_data:
            self._log('error', "No events to save")
            return False

        filepath = self.data_dir / (filename or "ring_events.txt")
        filepath.parent.mkdir(parents=True, exist_ok=True)

        # Determine starting index for event numbering
        start_index = 0
        if append and filepath.exists():
            # Count existing events to continue numbering
            with open(filepath, 'r') as f:
                for line in f:
                    if line and not line.startswith('#'):
                        start_index += 1

        mode = 'a' if append and filepath.exists() else 'w'
        with open(filepath, mode) as f:
            if mode == 'w':
                # Write header only for new files
                f.write("# Oura Ring Event Export\n")
                f.write(f"# Timestamp: {datetime.now().strftime('%a %b %d %H:%M:%S %Z %Y')}\n")
                f.write(f"# Events: {len(self.event_data)}\n")
                f.write("#\n")
                f.write("# Format: index|tag_hex|event_name|hex_data\n")
                f.write("#\n")

            for i, event in enumerate(self.event_data):
                tag = event[0] if event else 0
                f.write(f"{start_index + i}|0x{tag:02x}|{get_event_name(tag)}|{event.hex()}\n")

        action = "Appended" if append else "Saved"
        self._log('success', f"{action} {len(self.event_data)} events to {filepath}")
        return True
