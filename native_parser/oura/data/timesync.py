"""
Time Sync Utility

Converts ring timestamps (deciseconds) to UTC milliseconds using a sync point.
"""

from __future__ import annotations

import json
from pathlib import Path
from dataclasses import dataclass
from typing import Optional, List, Union
from datetime import datetime


@dataclass
class SyncPoint:
    """Time sync point mapping ring time to UTC.

    Ring time is in deciseconds (0.1 second units).
    UTC time is in milliseconds.
    """
    ring_time: int      # Ring's internal clock (deciseconds)
    utc_millis: int     # UTC timestamp (milliseconds)
    timestamp: str      # Human-readable timestamp

    def ring_to_utc_ms(self, ring_decisec: int) -> int:
        """Convert ring deciseconds to UTC milliseconds."""
        offset_decisec = ring_decisec - self.ring_time
        offset_ms = offset_decisec * 100
        return self.utc_millis + offset_ms

    def ring_to_utc_sec(self, ring_decisec: int) -> float:
        """Convert ring deciseconds to UTC seconds (float)."""
        return self.ring_to_utc_ms(ring_decisec) / 1000.0

    def utc_to_ring(self, utc_ms: int) -> int:
        """Convert UTC milliseconds to ring deciseconds."""
        offset_ms = utc_ms - self.utc_millis
        offset_decisec = offset_ms // 100
        return self.ring_time + offset_decisec

    def format_utc(self, ring_decisec: int) -> str:
        """Convert ring time to formatted UTC string."""
        utc_ms = self.ring_to_utc_ms(ring_decisec)
        return datetime.fromtimestamp(utc_ms / 1000).strftime('%Y-%m-%d %H:%M:%S')

    @classmethod
    def from_dict(cls, data: dict) -> 'SyncPoint':
        """Create SyncPoint from dictionary."""
        return cls(
            ring_time=data['ring_time'],
            utc_millis=data['utc_millis'],
            timestamp=data.get('timestamp', ''),
        )

    @classmethod
    def from_json_file(cls, path: Union[str, Path]) -> 'SyncPoint':
        """Load SyncPoint from JSON file."""
        path = Path(path)
        data = json.loads(path.read_text())
        return cls.from_dict(data)

    def to_dict(self) -> dict:
        """Convert to dictionary."""
        return {
            'ring_time': self.ring_time,
            'utc_millis': self.utc_millis,
            'timestamp': self.timestamp,
        }

    def to_json(self, indent: int = 2) -> str:
        """Convert to JSON string."""
        return json.dumps(self.to_dict(), indent=indent)


def load_sync_point(path: Optional[Union[str, Path]] = None) -> Optional[SyncPoint]:
    """Load sync point from file.

    Args:
        path: Path to sync_point.json. If None, searches default locations.

    Returns:
        SyncPoint if found, None otherwise.
    """
    if path is not None:
        path = Path(path)
        if path.exists():
            return SyncPoint.from_json_file(path)
        return None

    # Search default locations
    search_paths = [
        Path(__file__).parent.parent.parent / 'input_data' / 'sync_point.json',  # native_parser/input_data/
        Path.cwd() / 'input_data' / 'sync_point.json',
        Path.cwd() / 'sync_point.json',
        Path.home() / '.oura' / 'sync_point.json',
    ]

    for p in search_paths:
        if p.exists():
            return SyncPoint.from_json_file(p)

    return None


def convert_timestamps(
    timestamps: List[int],
    sync_point: SyncPoint,
    from_ring: bool = True
) -> List[int]:
    """Convert a list of timestamps using sync point.

    Args:
        timestamps: List of timestamps to convert
        sync_point: SyncPoint for conversion
        from_ring: If True, convert ring->UTC. If False, UTC->ring.

    Returns:
        List of converted timestamps (UTC ms if from_ring, ring decisec otherwise)
    """
    if from_ring:
        return [sync_point.ring_to_utc_ms(ts) for ts in timestamps]
    else:
        return [sync_point.utc_to_ring(ts) for ts in timestamps]
