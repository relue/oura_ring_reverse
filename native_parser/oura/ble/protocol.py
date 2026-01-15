"""
Oura Ring BLE Protocol Constants and Command Builders

Contains UUIDs, command constants, event types, and command builder functions
for the Oura Ring BLE protocol.
"""

import struct
import time
from pathlib import Path

# ============================================================================
# BLE UUIDs
# ============================================================================

SERVICE_UUID = "98ed0001-a541-11e4-b6a0-0002a5d5c51b"
WRITE_CHAR_UUID = "98ed0002-a541-11e4-b6a0-0002a5d5c51b"
NOTIFY_CHAR_UUID = "98ed0003-a541-11e4-b6a0-0002a5d5c51b"

# ============================================================================
# Default Configuration
# ============================================================================

# Default BLE adapter
DEFAULT_ADAPTER = "hci0"

# Default auth key (from protocol documentation)
DEFAULT_AUTH_KEY = bytes.fromhex("00426ed816dcece48dd9968c1f36c0b5")

# Default data directory
DEFAULT_DATA_DIR = Path(__file__).parent.parent.parent / "input_data"

# Storage files
AUTH_KEY_FILE = "auth_key.bin"
BONDED_ADDRESS_FILE = "bonded_device.txt"
SYNC_POINT_FILE = "sync_point.json"

# ============================================================================
# Commands
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
# Event Types
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
SLEEP_EVENT_TYPES = {
    0x48, 0x49, 0x4B, 0x4C, 0x4D, 0x4E, 0x4F, 0x55, 0x57, 0x58,
    0x5A, 0x6a, 0x72, 0x75, 0x76
}

# Heart rate related events
HEART_RATE_EVENT_TYPES = {0x60, 0x5d, 0x4a, 0x6e}

# Temperature events
TEMP_EVENT_TYPES = {0x46, 0x49, 0x56, 0x75}

# Motion/Activity events
MOTION_EVENT_TYPES = {0x47, 0x4e, 0x52, 0x5f}

# SpO2 events
SPO2_EVENT_TYPES = {0x63, 0x64, 0x65}

# ============================================================================
# Helper Functions
# ============================================================================

def get_event_name(tag: int) -> str:
    """Get event type name from tag byte."""
    return EVENT_TYPES.get(tag, f"UNKNOWN_{tag:02x}")


def format_hex(data: bytes) -> str:
    """Format bytes as hex string."""
    return ' '.join(f'{b:02x}' for b in data)


def parse_heartbeat(data: bytes) -> tuple | None:
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


# ============================================================================
# Command Builders
# ============================================================================

def build_get_event_cmd(timestamp: int, max_events: int = 0) -> bytes:
    """Build GetEvent command (0x10).

    Args:
        timestamp: Ring timestamp (ring_time in deciseconds). Events with
                   ring_time >= timestamp will be returned. Use 0 to get all events.
                   NOTE: This is NOT a sequence number - it's a timestamp!
        max_events: Maximum events per request (0 = streaming mode, up to ~50K)

    Returns:
        11-byte command: [0x10] [0x09] [timestamp:4B LE] [max:1B] [flags:4B]
    """
    # Format: 10 09 <timestamp:4-bytes LE> <max_events:1-byte> <flags:4-bytes LE>
    cmd = bytearray(11)
    cmd[0] = 0x10  # REQUEST_TAG
    cmd[1] = 0x09  # length

    # Timestamp (ring_time in deciseconds, 4 bytes, little endian)
    cmd[2] = timestamp & 0xFF
    cmd[3] = (timestamp >> 8) & 0xFF
    cmd[4] = (timestamp >> 16) & 0xFF
    cmd[5] = (timestamp >> 24) & 0xFF

    # Max events (0 = streaming mode)
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


def build_auth_cmd(encrypted_nonce: bytes) -> bytes:
    """Build authentication command with encrypted nonce."""
    return bytes([0x2f, 0x11, 0x2d]) + encrypted_nonce[:16]


def encrypt_nonce(nonce: bytes, auth_key: bytes) -> bytes:
    """Encrypt 15-byte nonce using AES-128-ECB with PKCS5 padding."""
    try:
        from Crypto.Cipher import AES
    except ImportError:
        raise RuntimeError("pycryptodome not installed - run: pip install pycryptodome")

    if len(nonce) != 15:
        raise ValueError(f"Nonce must be 15 bytes, got {len(nonce)}")
    if len(auth_key) != 16:
        raise ValueError(f"Auth key must be 16 bytes, got {len(auth_key)}")

    # PKCS5 padding: 15 bytes + 1 padding byte (0x01)
    padded = nonce + bytes([1])
    cipher = AES.new(auth_key, AES.MODE_ECB)
    return cipher.encrypt(padded)


# ============================================================================
# Event Filter Presets
# ============================================================================

FILTER_PRESETS = {
    'all': None,  # No filtering
    'sleep': SLEEP_EVENT_TYPES,
    'heart_rate': HEART_RATE_EVENT_TYPES,
    'temperature': TEMP_EVENT_TYPES,
    'motion': MOTION_EVENT_TYPES,
    'spo2': SPO2_EVENT_TYPES,
}


class EventFilter:
    """Filter for selecting specific event types."""

    def __init__(self):
        self.whitelist: set = set()
        self.blacklist: set = set()

    def add_whitelist(self, event_type: int):
        """Add event type to whitelist."""
        self.whitelist.add(event_type)

    def add_blacklist(self, event_type: int):
        """Add event type to blacklist."""
        self.blacklist.add(event_type)

    def should_include(self, tag: int) -> bool:
        """Check if event should be included based on filters."""
        if self.blacklist and tag in self.blacklist:
            return False
        if self.whitelist and tag not in self.whitelist:
            return False
        return True

    @classmethod
    def from_preset(cls, preset: str) -> 'EventFilter':
        """Create filter from preset name."""
        filter_obj = cls()
        event_types = FILTER_PRESETS.get(preset)
        if event_types:
            filter_obj.whitelist = event_types.copy()
        return filter_obj
