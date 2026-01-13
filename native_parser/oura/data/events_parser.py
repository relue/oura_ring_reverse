"""
Ring Events Parser

Parses ring_events.txt to extract real timestamps for each event type.
These can be used with a SyncPoint to get UTC timestamps.
"""

from __future__ import annotations

from pathlib import Path
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Tuple
from datetime import datetime

from oura.data.timesync import SyncPoint, load_sync_point


@dataclass
class ParsedEvents:
    """Parsed events with real ring timestamps."""

    # Sleep events (0x6a - API_SLEEP_PERIOD_INFO_2)
    sleep_timestamps: List[int] = field(default_factory=list)
    sleep_data: List[bytes] = field(default_factory=list)

    # IBI events (0x60 - API_IBI_AND_AMPLITUDE_EVENT)
    ibi_timestamps: List[int] = field(default_factory=list)
    ibi_data: List[bytes] = field(default_factory=list)

    # Temperature events (0x46 - API_TEMP_EVENT)
    temp_timestamps: List[int] = field(default_factory=list)
    temp_data: List[bytes] = field(default_factory=list)

    # HRV events (0x5d - API_HRV_EVENT)
    hrv_timestamps: List[int] = field(default_factory=list)
    hrv_data: List[bytes] = field(default_factory=list)

    # Motion events (0x47 - API_MOTION_EVENT)
    motion_timestamps: List[int] = field(default_factory=list)
    motion_data: List[bytes] = field(default_factory=list)

    def apply_sync(self, sync_point: SyncPoint) -> 'ParsedEvents':
        """Convert all timestamps to UTC milliseconds using sync point."""
        return ParsedEvents(
            sleep_timestamps=[sync_point.ring_to_utc_ms(ts) for ts in self.sleep_timestamps],
            sleep_data=self.sleep_data,
            ibi_timestamps=[sync_point.ring_to_utc_ms(ts) for ts in self.ibi_timestamps],
            ibi_data=self.ibi_data,
            temp_timestamps=[sync_point.ring_to_utc_ms(ts) for ts in self.temp_timestamps],
            temp_data=self.temp_data,
            hrv_timestamps=[sync_point.ring_to_utc_ms(ts) for ts in self.hrv_timestamps],
            hrv_data=self.hrv_data,
            motion_timestamps=[sync_point.ring_to_utc_ms(ts) for ts in self.motion_timestamps],
            motion_data=self.motion_data,
        )


def parse_events_file(path: str) -> ParsedEvents:
    """Parse ring_events.txt and extract timestamps for each event type.

    Args:
        path: Path to ring_events.txt file

    Returns:
        ParsedEvents with ring timestamps (deciseconds)
    """
    result = ParsedEvents()

    # Event tag to handler mapping
    handlers = {
        '0x6a': (result.sleep_timestamps, result.sleep_data),    # Sleep
        '0x60': (result.ibi_timestamps, result.ibi_data),        # IBI
        '0x46': (result.temp_timestamps, result.temp_data),      # Temp
        '0x5d': (result.hrv_timestamps, result.hrv_data),        # HRV
        '0x47': (result.motion_timestamps, result.motion_data),  # Motion
    }

    with open(path) as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith('#'):
                continue

            parts = line.split('|')
            if len(parts) < 4:
                continue

            tag = parts[1]
            hex_data = parts[3]

            if tag not in handlers:
                continue

            ts_list, data_list = handlers[tag]

            # Extract timestamp from hex data (bytes 2-5, little-endian)
            try:
                if len(hex_data) >= 12:
                    ts_hex = hex_data[4:12]  # After tag (2) and length (2)
                    ts_bytes = bytes.fromhex(ts_hex)
                    ring_ts = int.from_bytes(ts_bytes, 'little')

                    ts_list.append(ring_ts)
                    data_list.append(bytes.fromhex(hex_data))
            except (ValueError, IndexError):
                continue

    return result


def get_sleep_times(
    events_path: str,
    sync_point: Optional[SyncPoint] = None
) -> Tuple[datetime, datetime, int]:
    """Get sleep session start/end times from events file.

    Args:
        events_path: Path to ring_events.txt
        sync_point: Optional sync point for UTC conversion

    Returns:
        Tuple of (start_time, end_time, epoch_count)
    """
    if sync_point is None:
        sync_point = load_sync_point()

    if sync_point is None:
        raise ValueError("No sync point available")

    events = parse_events_file(events_path)

    if not events.sleep_timestamps:
        raise ValueError("No sleep events found")

    # Convert to UTC
    utc_events = events.apply_sync(sync_point)

    start_ms = utc_events.sleep_timestamps[0]
    end_ms = utc_events.sleep_timestamps[-1]

    return (
        datetime.fromtimestamp(start_ms / 1000),
        datetime.fromtimestamp(end_ms / 1000),
        len(utc_events.sleep_timestamps)
    )


def get_ibi_times(
    events_path: str,
    sync_point: Optional[SyncPoint] = None
) -> Tuple[datetime, datetime, int]:
    """Get IBI session start/end times from events file.

    Args:
        events_path: Path to ring_events.txt
        sync_point: Optional sync point for UTC conversion

    Returns:
        Tuple of (start_time, end_time, sample_count)
    """
    if sync_point is None:
        sync_point = load_sync_point()

    if sync_point is None:
        raise ValueError("No sync point available")

    events = parse_events_file(events_path)

    if not events.ibi_timestamps:
        raise ValueError("No IBI events found")

    # Convert to UTC
    utc_events = events.apply_sync(sync_point)

    start_ms = utc_events.ibi_timestamps[0]
    end_ms = utc_events.ibi_timestamps[-1]

    return (
        datetime.fromtimestamp(start_ms / 1000),
        datetime.fromtimestamp(end_ms / 1000),
        len(utc_events.ibi_timestamps)
    )
