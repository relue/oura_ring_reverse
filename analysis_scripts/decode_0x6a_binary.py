#!/usr/bin/env python3
"""
Decode 0x6a (SLEEP_PERIOD_INFO_2) binary events from Oura Ring

Based on decompiled Oura app:
- SleepPeriodInfoValue has 10 fields
- Each 0x6a event is 14 bytes of custom binary format
- Events are sent individually and assembled into protobuf arrays
"""

import struct
import sys
from datetime import datetime
from typing import List, Dict

class SleepPeriodInfoSample:
    """
    Represents one minute of sleep data from a 0x6a event.

    Field mapping (14 bytes total):
    Based on observed data and SleepPeriodInfoValue class structure
    """

    def __init__(self, raw_bytes: bytes):
        if len(raw_bytes) != 14:
            raise ValueError(f"Expected 14 bytes, got {len(raw_bytes)}")

        self.raw = raw_bytes

        # Parse based on observed patterns and data structure
        # Bytes 0-3: Timestamp offset (32-bit LE unsigned int)
        self.timestamp_offset = struct.unpack('<I', raw_bytes[0:4])[0]

        # Byte 4: Heart rate (unsigned 8-bit) - observed range 133-143 (0x85-0x8f)
        self.avg_hr = raw_bytes[4]

        # Byte 5: Could be HR trend or quality indicator
        self.hr_trend_or_quality = raw_bytes[5]

        # Bytes 6-7: 16-bit value (could be IBI-related)
        self.value_6_7 = struct.unpack('<H', raw_bytes[6:8])[0]

        # Bytes 8-9: 16-bit value (could be breathing or motion)
        self.value_8_9 = struct.unpack('<H', raw_bytes[8:10])[0]

        # Bytes 10-11: 16-bit value (often 0x00 or small values)
        self.value_10_11 = struct.unpack('<H', raw_bytes[10:12])[0]

        # Bytes 12-13: 16-bit value (often 0x00 or small values)
        self.value_12_13 = struct.unpack('<H', raw_bytes[12:14])[0]

    def to_dict(self) -> Dict:
        """Convert to dictionary for analysis"""
        return {
            'raw_hex': self.raw.hex(' '),
            'timestamp_offset': self.timestamp_offset,
            'avg_hr': self.avg_hr,
            'hr_trend_or_quality': self.hr_trend_or_quality,
            'value_6_7': self.value_6_7,
            'value_8_9': self.value_8_9,
            'value_10_11': self.value_10_11,
            'value_12_13': self.value_12_13,
        }

    def __str__(self) -> str:
        """Human-readable representation"""
        lines = [
            f"  Raw: {self.raw.hex(' ')}",
            f"  Timestamp offset: {self.timestamp_offset} (0x{self.timestamp_offset:08x})",
            f"  Heart Rate: {self.avg_hr} BPM",
            f"  HR Trend/Quality: {self.hr_trend_or_quality} (0x{self.hr_trend_or_quality:02x})",
            f"  Value[6-7]: {self.value_6_7} (0x{self.value_6_7:04x})",
            f"  Value[8-9]: {self.value_8_9} (0x{self.value_8_9:04x})",
            f"  Value[10-11]: {self.value_10_11} (0x{self.value_10_11:04x})",
            f"  Value[12-13]: {self.value_12_13} (0x{self.value_12_13:04x})",
        ]
        return '\n'.join(lines)


def parse_0x6a_event(event_bytes: bytes) -> SleepPeriodInfoSample:
    """
    Parse a complete 0x6a event (tag + length + payload).

    Args:
        event_bytes: Complete event including tag (0x6a) and length (0x0e)

    Returns:
        SleepPeriodInfoSample object
    """
    if len(event_bytes) < 2:
        raise ValueError("Event too short")

    tag = event_bytes[0]
    length = event_bytes[1]

    if tag != 0x6a:
        raise ValueError(f"Expected tag 0x6a, got 0x{tag:02x}")

    if length != 14:
        raise ValueError(f"Expected length 14 (0x0e), got {length}")

    if len(event_bytes) < 2 + length:
        raise ValueError(f"Event truncated: expected {2 + length} bytes, got {len(event_bytes)}")

    # Extract payload (skip tag and length bytes)
    payload = event_bytes[2:2+length]

    return SleepPeriodInfoSample(payload)


def assemble_sleep_period(samples: List[SleepPeriodInfoSample], base_timestamp: int = None) -> Dict:
    """
    Assemble multiple 0x6a samples into a SleepPeriodInfo structure.

    This mimics how the Oura app collects individual events and builds
    the protobuf arrays for storage.

    Args:
        samples: List of SleepPeriodInfoSample objects
        base_timestamp: Optional base timestamp (milliseconds). If None, uses first sample's offset.

    Returns:
        Dictionary with arrays matching SleepPeriodInfo protobuf structure
    """
    if not samples:
        return {
            'timestamps': [],
            'average_hr': [],
            'hr_trend': [],
            'avg_ibi': [],
            'std_ibi': [],
            'breath': [],
            'breath_v': [],
            'motion_count': [],
            'sleep_state': [],
            'cv': []
        }

    # Sort samples by timestamp offset (ascending = chronological order)
    sorted_samples = sorted(samples, key=lambda s: s.timestamp_offset)

    # Build arrays
    result = {
        'timestamps': [],
        'average_hr': [],
        'hr_trend': [],
        'avg_ibi': [],
        'std_ibi': [],
        'breath': [],
        'breath_v': [],
        'motion_count': [],
        'sleep_state': [],
        'cv': []
    }

    for sample in sorted_samples:
        # Timestamp: offset in seconds from base, convert to milliseconds
        if base_timestamp:
            result['timestamps'].append(base_timestamp + (sample.timestamp_offset * 1000))
        else:
            result['timestamps'].append(sample.timestamp_offset * 1000)

        # Heart rate (BPM)
        result['average_hr'].append(float(sample.avg_hr))

        # Other fields - placeholder values until we decode the exact format
        result['hr_trend'].append(float(sample.hr_trend_or_quality))
        result['avg_ibi'].append(0.0)  # Need to decode from value_6_7
        result['std_ibi'].append(0.0)  # Need to decode
        result['breath'].append(0.0)   # Need to decode from value_8_9
        result['breath_v'].append(0.0) # Need to decode
        result['motion_count'].append(sample.value_10_11)  # Guess
        result['sleep_state'].append(sample.value_12_13 & 0xFF)  # Guess (lower byte)
        result['cv'].append(0.0)       # Need to decode

    return result


def print_sample_analysis(samples: List[SleepPeriodInfoSample]):
    """Print detailed analysis of multiple samples"""
    print("\n" + "="*80)
    print("0x6a (SLEEP_PERIOD_INFO_2) DECODED SAMPLES")
    print("="*80)
    print(f"\nTotal samples: {len(samples)}")

    if not samples:
        print("No samples to analyze")
        return

    # Analyze timestamp ordering
    offsets = [s.timestamp_offset for s in samples]
    print(f"\nTimestamp offsets:")
    print(f"  First: {offsets[0]} (0x{offsets[0]:08x})")
    print(f"  Last:  {offsets[-1]} (0x{offsets[-1]:08x})")
    print(f"  Order: {'Ascending (chronological)' if offsets[0] < offsets[-1] else 'Descending (reverse chronological)'}")

    # Analyze heart rate
    hrs = [s.avg_hr for s in samples]
    print(f"\nHeart Rate (BPM):")
    print(f"  Min: {min(hrs)}, Max: {max(hrs)}, Avg: {sum(hrs)/len(hrs):.1f}")

    # Print first 5 samples in detail
    print("\n" + "-"*80)
    print("FIRST 5 SAMPLES (DETAILED)")
    print("-"*80)
    for i, sample in enumerate(samples[:5]):
        print(f"\nSample {i+1}:")
        print(sample)

    # Print assembled structure
    print("\n" + "-"*80)
    print("ASSEMBLED SLEEP PERIOD INFO")
    print("-"*80)
    assembled = assemble_sleep_period(samples)
    print(f"Total entries: {len(assembled['timestamps'])}")
    print(f"Duration: ~{len(assembled['timestamps'])} minutes")
    print(f"\nFirst 3 entries:")
    for i in range(min(3, len(assembled['timestamps']))):
        print(f"  [{i}] ts={assembled['timestamps'][i]}, hr={assembled['average_hr'][i]:.0f} BPM")


if __name__ == "__main__":
    # Test with example events from your logs
    print("Testing 0x6a decoder with example events from logs...")

    test_events = [
        # Format: 6a 0e [14-byte payload]
        bytes.fromhex("6a 0e 95 05 02 00 87 0a 36 1e 92 22 00 01 00 00"),
        bytes.fromhex("6a 0e 2e 03 02 00 85 00 26 0d b8 09 00 01 00 00"),
        bytes.fromhex("6a 0e d7 c9 00 00 85 f7 41 2c 8d 2c 00 01 00 00"),
        bytes.fromhex("6a 0e c5 c8 00 00 85 f1 23 0e 84 2c 00 00 00 00"),
        bytes.fromhex("6a 0e 70 c7 00 00 8b 1f 30 1e 8d 2f 06 00 00 00"),
        bytes.fromhex("6a 0e 5f c6 00 00 8b 24 42 29 87 31 09 00 00 00"),
        bytes.fromhex("6a 0e 09 c5 00 00 8c 2c 75 61 56 4e 0d 00 00 00"),
        bytes.fromhex("6a 0e ec c3 00 00 8f 43 75 61 67 49 0d 01 00 00"),
        bytes.fromhex("6a 0e eb c2 00 00 86 00 2b 18 3e 1b 07 01 00 00"),
    ]

    samples = []
    for event in test_events:
        try:
            sample = parse_0x6a_event(event)
            samples.append(sample)
        except Exception as e:
            print(f"Error parsing event {event.hex()}: {e}")

    print_sample_analysis(samples)

    # If command line arguments provided, parse those too
    if len(sys.argv) > 1:
        print("\n\n" + "="*80)
        print("PARSING COMMAND LINE EVENTS")
        print("="*80)

        cli_samples = []
        for hex_str in sys.argv[1:]:
            try:
                event_bytes = bytes.fromhex(hex_str.replace(" ", "").replace("0x", ""))
                sample = parse_0x6a_event(event_bytes)
                cli_samples.append(sample)
            except Exception as e:
                print(f"Error parsing {hex_str}: {e}")

        if cli_samples:
            print_sample_analysis(cli_samples)
