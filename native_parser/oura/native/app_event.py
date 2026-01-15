"""
AppEvent Serialization for Oura Native Library

Serializes data into the exact byte format Oura uses for nativeCalculateSleepScore.
Based on decompiled AppEvent.java classes.

Byte order: Little-endian (ByteBuffer.order(ByteOrder.LITTLE_ENDIAN) in Oura)
"""

import struct
from typing import List, Tuple, Optional
from dataclasses import dataclass


class AppEventSerializer:
    """Serialize data to Oura AppEvent byte format (1:1 with Oura app)."""

    # AppEvent tag values (from decompiled AppEvent.java - VERIFIED)
    TAG_BEDTIME_PERIOD = 54       # Line 33
    TAG_HR_HRV_5MIN = 60          # Line 221
    TAG_LOW_BATTERY = 55          # Line 360
    TAG_MOTION_SECONDS = 53       # Line 489
    TAG_SKIN_TEMPERATURES = 59    # Line 634
    TAG_SLEEP_PHASES_V2 = 51      # Line 709
    TAG_SLEEP_RAW_FEATURES = 52   # Line 944

    @staticmethod
    def _wrap_with_header(event_data: bytes, tag: int, event_timestamp_ms: int) -> bytes:
        """
        Wrap event data with the 12-byte AppEvent header.

        Header format:
            - byte magic: 0xFE (-2 signed)
            - byte tag: Event type tag
            - short length: len(event_data) + 8 (includes timestamp)
            - long timestamp: Event timestamp in milliseconds

        Args:
            event_data: The encoded event content
            tag: Event type tag
            event_timestamp_ms: Event timestamp in milliseconds

        Returns:
            Complete AppEvent bytes with header
        """
        import time

        # Use current time if not provided
        if event_timestamp_ms == 0:
            event_timestamp_ms = int(time.time() * 1000)

        # Length includes the 8-byte timestamp but not the first 4 bytes (magic/tag/length)
        length = len(event_data) + 8

        # Header: magic(1) + tag(1) + length(2) + timestamp(8) = 12 bytes
        # Note: ByteBuffer in Java with LITTLE_ENDIAN
        header = struct.pack('<bbHq', -2, tag, length, event_timestamp_ms)

        return header + event_data

    @classmethod
    def sleep_phases_v2(cls, first_ts_ms: int, tz_seconds: int, phases: List[int]) -> bytes:
        """
        Serialize SleepPhasesV2 AppEvent with header.

        Format from decompiled code:
            - [12-byte AppEvent header]
            - long firstPhaseTimestamp (8 bytes, little-endian)
            - int firstPhaseTimeZoneSeconds (4 bytes, little-endian)
            - packed phases: 2 phases per byte (low nibble = first, high nibble = second)

        Phase values: 0=Awake, 1=REM, 2=Light, 3=Deep, 4=Unknown

        Args:
            first_ts_ms: First phase timestamp in milliseconds (UTC)
            tz_seconds: Timezone offset in seconds
            phases: List of phase values (0-4)

        Returns:
            Serialized byte array with header
        """
        # Event data: timestamp (8 bytes) + timezone (4 bytes) + packed phases
        event_data = struct.pack('<qI', first_ts_ms, tz_seconds)

        # Pack phases: 2 per byte (nibbles)
        # From twoValuesToByte: (a & 0xF) | ((b & 0xF) << 4)
        for i in range(0, len(phases), 2):
            a = phases[i] if i < len(phases) else 0
            b = phases[i + 1] if i + 1 < len(phases) else 0
            # Clamp to 0-4 range
            a = max(0, min(4, a))
            b = max(0, min(4, b))
            event_data += struct.pack('B', (a & 0xF) | ((b & 0xF) << 4))

        return cls._wrap_with_header(event_data, cls.TAG_SLEEP_PHASES_V2, first_ts_ms)

    @classmethod
    def bedtime_period(cls, start_ts_ms: int, start_tz: int, end_ts_ms: int, end_tz: int) -> bytes:
        """
        Serialize BedtimePeriod AppEvent with header.

        Format:
            - [12-byte AppEvent header]
            - long startTimestamp (8 bytes)
            - int startTimeZoneSeconds (4 bytes)
            - long endTimestamp (8 bytes)
            - int endTimeZoneSeconds (4 bytes)

        Args:
            start_ts_ms: Bedtime start in milliseconds (UTC)
            start_tz: Start timezone offset in seconds
            end_ts_ms: Bedtime end in milliseconds (UTC)
            end_tz: End timezone offset in seconds

        Returns:
            Serialized byte array with header (36 bytes total)
        """
        event_data = struct.pack('<qIqI', start_ts_ms, start_tz, end_ts_ms, end_tz)
        return cls._wrap_with_header(event_data, cls.TAG_BEDTIME_PERIOD, start_ts_ms)

    @classmethod
    def skin_temperatures(cls, first_ts_ms: int, tz_seconds: int, temps_centideg: List[int]) -> bytes:
        """
        Serialize SkinTemperatures AppEvent with header.

        Format:
            - [12-byte AppEvent header]
            - long firstTimestamp (8 bytes)
            - int timeZoneSeconds (4 bytes)
            - for each temp: int tempCentidegrees (4 bytes)

        Args:
            first_ts_ms: First temperature timestamp in milliseconds
            tz_seconds: Timezone offset in seconds
            temps_centideg: List of temperatures in centidegrees (e.g., 3550 = 35.50C)

        Returns:
            Serialized byte array with header
        """
        event_data = struct.pack('<qI', first_ts_ms, tz_seconds)
        for temp in temps_centideg:
            event_data += struct.pack('<i', temp)
        return cls._wrap_with_header(event_data, cls.TAG_SKIN_TEMPERATURES, first_ts_ms)

    @classmethod
    def motion_seconds(cls, first_ts_ms: int, tz_seconds: int, motion_values: List[int]) -> bytes:
        """
        Serialize MotionSeconds AppEvent with header.

        Format:
            - [12-byte AppEvent header]
            - long firstTimestamp (8 bytes)
            - int timeZoneSeconds (4 bytes)
            - for each value: byte motionSeconds (1 byte each)

        Args:
            first_ts_ms: First motion timestamp in milliseconds
            tz_seconds: Timezone offset in seconds
            motion_values: List of motion values (0-255)

        Returns:
            Serialized byte array with header
        """
        event_data = struct.pack('<qI', first_ts_ms, tz_seconds)
        for m in motion_values:
            event_data += struct.pack('B', min(255, max(0, m)))
        return cls._wrap_with_header(event_data, cls.TAG_MOTION_SECONDS, first_ts_ms)

    @classmethod
    def hr_hrv_5min_averages(cls, first_ts_ms: int, tz_seconds: int,
                             values: List[Tuple[int, int]]) -> bytes:
        """
        Serialize HrHrv5MinAverages AppEvent with header.

        Format:
            - [12-byte AppEvent header]
            - long firstTimestamp (8 bytes)
            - int timeZoneSeconds (4 bytes)
            - for each 5-min period:
                - short hr_times_8 (2 bytes) - HR * 8
                - short rmssd_times_8 (2 bytes) - RMSSD * 8

        Args:
            first_ts_ms: First HRV timestamp in milliseconds
            tz_seconds: Timezone offset in seconds
            values: List of (hr, rmssd) tuples

        Returns:
            Serialized byte array with header
        """
        event_data = struct.pack('<qI', first_ts_ms, tz_seconds)
        for hr, rmssd in values:
            # Values stored as x8 to preserve decimal precision
            event_data += struct.pack('<HH', hr * 8, rmssd * 8)
        return cls._wrap_with_header(event_data, cls.TAG_HR_HRV_5MIN, first_ts_ms)

    @classmethod
    def sleep_raw_features(cls, values: List[dict]) -> bytes:
        """
        Serialize SleepRawFeatures AppEvent with header.

        Format:
            - [12-byte AppEvent header]
            - For each Value:
                - long timestamp (8 bytes)
                - int timeZoneSeconds (4 bytes)
                - float avgHr (4 bytes)
                - float avgBreathingRate (4 bytes)
                - float stdBreathingRate (4 bytes)
                - int sleepState (4 bytes)

        Total: 28 bytes per value (plus 12-byte header)

        Args:
            values: List of dicts with keys:
                - timestamp: int (milliseconds)
                - tz_seconds: int
                - avg_hr: float
                - avg_breath: float
                - std_breath: float
                - sleep_state: int (0-4)

        Returns:
            Serialized byte array with header
        """
        event_data = b''
        first_ts = values[0]['timestamp'] if values else 0
        for v in values:
            event_data += struct.pack('<qIfffI',
                v['timestamp'],
                v['tz_seconds'],
                v['avg_hr'],
                v['avg_breath'],
                v['std_breath'],
                v['sleep_state'])
        return cls._wrap_with_header(event_data, cls.TAG_SLEEP_RAW_FEATURES, first_ts)

    @classmethod
    def low_battery_alert(cls, timestamp_ms: int = 0) -> bytes:
        """
        Serialize LowBatteryAlert AppEvent with header.

        Args:
            timestamp_ms: Event timestamp (uses current time if 0)

        Returns:
            Serialized byte array with header (12-byte header + empty event data)
        """
        return cls._wrap_with_header(b'', cls.TAG_LOW_BATTERY, timestamp_ms)


@dataclass
class SleepCalculationInput:
    """All inputs needed for native sleep score calculation."""
    sleep_phases: bytes
    sleep_raw_features: bytes
    motion_seconds: bytes
    bedtime_period: bytes
    low_battery: bytes
    skin_temps: bytes
    hr_hrv_5min: bytes

    # User info
    age: int = 30
    weight_kg: int = 70
    height_cm: int = 175
    gender: int = 0  # 0=male, 1=female

    # Chronotype
    chronotype: int = 2  # 0-4 scale, 2=neutral
    ideal_bedtime_seconds: int = 23 * 3600  # 11 PM

    day_offset: int = 0


def downsample_to_5min_epochs(timestamps: list, values: list, bed_start: int, bed_end: int) -> tuple:
    """
    Downsample high-resolution data to 5-minute epochs.

    Args:
        timestamps: List of timestamps in ms
        values: List of values corresponding to timestamps
        bed_start: Start of bedtime period in ms
        bed_end: End of bedtime period in ms

    Returns:
        Tuple of (epoch_timestamps, epoch_values)
    """
    EPOCH_MS = 5 * 60 * 1000  # 5 minutes in milliseconds

    # Create bins for each 5-minute epoch
    epoch_start = bed_start
    epochs = []
    epoch_vals = []

    while epoch_start < bed_end:
        epoch_end = epoch_start + EPOCH_MS

        # Collect values in this epoch
        epoch_values = []
        for ts, val in zip(timestamps, values):
            if epoch_start <= ts < epoch_end:
                epoch_values.append(val)

        if epoch_values:
            # Use mode (most common) for categorical, mean for numeric
            if all(isinstance(v, int) and 0 <= v <= 4 for v in epoch_values):
                # Categorical (phases) - use mode
                from collections import Counter
                mode_val = Counter(epoch_values).most_common(1)[0][0]
                epochs.append(epoch_start)
                epoch_vals.append(mode_val)
            else:
                # Numeric - use mean
                epochs.append(epoch_start)
                epoch_vals.append(sum(epoch_values) / len(epoch_values))
        else:
            # No data for this epoch - use previous value or default
            if epoch_vals:
                epochs.append(epoch_start)
                epoch_vals.append(epoch_vals[-1])

        epoch_start = epoch_end

    return epochs, epoch_vals


def create_sleep_input_from_protobuf(reader, night_index: int = -1) -> SleepCalculationInput:
    """
    Create SleepCalculationInput from RingDataReader protobuf data.

    Downsamples high-resolution data to 5-minute epochs as expected by Oura.

    Args:
        reader: RingDataReader instance
        night_index: Which night to process (-1 = last)

    Returns:
        SleepCalculationInput with all serialized AppEvent data
    """
    rd = reader.raw

    # Get bedtime period for this night
    bp = rd.bedtime_period
    starts = list(bp.bedtime_start)
    ends = list(bp.bedtime_end)
    idx = night_index if night_index >= 0 else len(starts) + night_index
    bed_start = starts[idx]
    bed_end = ends[idx]
    tz_offset = 0  # TODO: Get from protobuf if available

    # Serialize bedtime period
    bedtime_bytes = AppEventSerializer.bedtime_period(
        bed_start, tz_offset, bed_end, tz_offset
    )

    # Get sleep phases and downsample to 5-min epochs
    spi = rd.sleep_period_info
    spi_ts = list(spi.timestamp)
    spi_states = list(spi.sleep_state)

    # Filter to bedtime period
    filtered_ts = [ts for ts in spi_ts if bed_start <= ts <= bed_end]
    filtered_states = [spi_states[i] for i, ts in enumerate(spi_ts)
                       if bed_start <= ts <= bed_end and i < len(spi_states)]

    # Downsample to 5-min epochs
    epoch_ts, epoch_phases = downsample_to_5min_epochs(
        filtered_ts, filtered_states, bed_start, bed_end
    )

    if epoch_ts:
        phases_bytes = AppEventSerializer.sleep_phases_v2(
            epoch_ts[0], tz_offset, epoch_phases
        )
    else:
        phases_bytes = b''

    # Serialize motion data (also downsample)
    me = rd.motion_event
    motion_ts = list(me.timestamp)
    motion_secs = list(me.motion_seconds)

    filtered_motion_ts = [ts for ts in motion_ts if bed_start <= ts <= bed_end]
    filtered_motion = [motion_secs[i] for i, ts in enumerate(motion_ts)
                       if bed_start <= ts <= bed_end and i < len(motion_secs)]

    if filtered_motion_ts:
        motion_bytes = AppEventSerializer.motion_seconds(
            filtered_motion_ts[0], tz_offset, filtered_motion
        )
    else:
        motion_bytes = b''

    # Serialize temperature data (downsample to 5-min)
    ste = rd.sleep_temp_event
    temp_ts = list(ste.timestamp)
    temps_raw = list(ste.temp)

    filtered_temp_ts = [ts for ts in temp_ts if bed_start <= ts <= bed_end]
    filtered_temps = [temps_raw[i] for i, ts in enumerate(temp_ts)
                      if bed_start <= ts <= bed_end and i < len(temps_raw)]

    # Downsample temps
    epoch_temp_ts, epoch_temps = downsample_to_5min_epochs(
        filtered_temp_ts, filtered_temps, bed_start, bed_end
    )

    if epoch_temp_ts:
        # Convert to centidegrees
        temps_centideg = [int(t * 100) for t in epoch_temps]
        temp_bytes = AppEventSerializer.skin_temperatures(
            epoch_temp_ts[0], tz_offset, temps_centideg
        )
    else:
        temp_bytes = b''

    # Serialize HRV data (already 5-min)
    hrv = rd.hrv_event
    hrv_ts = list(hrv.timestamp)
    hr_5min = list(hrv.average_hr_5min) if hasattr(hrv, 'average_hr_5min') else []
    rmssd_5min = list(hrv.average_rmssd_5min) if hasattr(hrv, 'average_rmssd_5min') else []

    hrv_vals = []
    hrv_first_ts = None
    for i, ts in enumerate(hrv_ts):
        if bed_start <= ts <= bed_end:
            if hrv_first_ts is None:
                hrv_first_ts = ts
            hr = hr_5min[i] if i < len(hr_5min) else 60
            rmssd = rmssd_5min[i] if i < len(rmssd_5min) else 30
            hrv_vals.append((int(hr), int(rmssd)))

    if hrv_vals:
        hrv_bytes = AppEventSerializer.hr_hrv_5min_averages(
            hrv_first_ts, tz_offset, hrv_vals
        )
    else:
        hrv_bytes = b''

    # Build sleep raw features (downsample to 5-min epochs)
    spi_hr = list(spi.average_hr) if hasattr(spi, 'average_hr') else []
    spi_breath = list(spi.breath) if hasattr(spi, 'breath') else []
    spi_breath_v = list(spi.breath_v) if hasattr(spi, 'breath_v') else []

    raw_features = []
    for i, ts in enumerate(epoch_ts):
        raw_features.append({
            'timestamp': ts,
            'tz_seconds': tz_offset,
            'avg_hr': float(epoch_phases[i]) if i < len(epoch_phases) else 60.0,  # Placeholder
            'avg_breath': 15.0,  # Default
            'std_breath': 1.0,
            'sleep_state': epoch_phases[i] if i < len(epoch_phases) else 0,
        })

    raw_bytes = AppEventSerializer.sleep_raw_features(raw_features)

    return SleepCalculationInput(
        sleep_phases=phases_bytes,
        sleep_raw_features=raw_bytes,
        motion_seconds=motion_bytes,
        bedtime_period=bedtime_bytes,
        low_battery=AppEventSerializer.low_battery_alert(bed_start),
        skin_temps=temp_bytes,
        hr_hrv_5min=hrv_bytes,
    )
