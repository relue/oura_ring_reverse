"""
Oura Ring Data Reader

High-level interface for parsing Oura Ring protobuf data.
Supports time sync for converting ring timestamps to UTC.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Optional, Any, Dict, List, Union

# Import protobuf
try:
    import ringeventparser_pb2 as proto
except ImportError:
    import sys
    sys.path.insert(0, str(Path(__file__).parent.parent.parent))
    import ringeventparser_pb2 as proto

from oura.data.models import (
    HeartRateData,
    SleepData,
    TemperatureData,
    HRVData,
    ActivityData,
    SpO2Data,
    MotionData,
    RingInfo,
    NativeSleepStages,
)
from oura.data.timesync import SyncPoint, load_sync_point
from oura.data.events_parser import parse_events_file, ParsedEvents


class RingDataReader:
    """High-level interface to Oura Ring protobuf data.

    This is the main entry point for accessing parsed ring data.
    It provides convenient properties for accessing different data types.

    Example:
        reader = RingDataReader("ring_data.pb")
        print(f"HR: {reader.heart_rate.average_bpm:.1f} BPM")
        print(f"Temp: {reader.temperature.average_celsius:.2f}C")
        print(reader.summary())
    """

    def __init__(self, pb_path: str, sync_point: Optional[Union[SyncPoint, str, Path]] = 'auto'):
        """Load and parse protobuf file.

        Args:
            pb_path: Path to the ring_data.pb file
            sync_point: Time sync for converting ring timestamps to UTC.
                       - 'auto': Auto-detect sync_point.json (default)
                       - SyncPoint instance: Use directly
                       - str/Path: Load from file
                       - None: Don't convert timestamps
        """
        self._path = Path(pb_path)
        self._rd = proto.RingData()
        self._rd.ParseFromString(self._path.read_bytes())

        # Load sync point
        if sync_point == 'auto':
            self._sync_point = load_sync_point()
        elif isinstance(sync_point, SyncPoint):
            self._sync_point = sync_point
        elif isinstance(sync_point, (str, Path)):
            self._sync_point = load_sync_point(sync_point)
        else:
            self._sync_point = None

        # Cache wrapper objects
        self._heart_rate: Optional[HeartRateData] = None
        self._sleep: Optional[SleepData] = None
        self._temperature: Optional[TemperatureData] = None
        self._hrv: Optional[HRVData] = None
        self._activity: Optional[ActivityData] = None
        self._spo2: Optional[SpO2Data] = None
        self._motion: Optional[MotionData] = None
        self._ring_info: Optional[RingInfo] = None

        # Parsed events with real timestamps (from ring_events.txt)
        self._parsed_events: Optional[ParsedEvents] = None

    @property
    def sync_point(self) -> Optional[SyncPoint]:
        """Time sync point for timestamp conversion."""
        return self._sync_point

    @property
    def has_sync(self) -> bool:
        """Whether time sync is available for UTC conversion."""
        return self._sync_point is not None

    @property
    def has_events(self) -> bool:
        """Whether parsed events with real timestamps are available."""
        return self._parsed_events is not None

    def _convert_timestamps(self, timestamps: List[int]) -> List[int]:
        """Convert ring timestamps to UTC milliseconds if sync available."""
        if self._sync_point is None:
            return timestamps
        return [self._sync_point.ring_to_utc_ms(ts) for ts in timestamps]

    def load_events_file(self, events_path: str) -> None:
        """Load real timestamps from ring_events.txt file.

        This extracts actual ring timestamps from the events file and
        uses them to replace the relative timestamps in the protobuf.

        Args:
            events_path: Path to ring_events.txt
        """
        self._parsed_events = parse_events_file(events_path)

        # Apply sync point to get UTC timestamps
        if self._sync_point is not None:
            self._parsed_events = self._parsed_events.apply_sync(self._sync_point)

        # Clear cached data to force reload with new timestamps
        self._heart_rate = None
        self._sleep = None
        self._temperature = None
        self._hrv = None
        self._motion = None

    @classmethod
    def from_events(
        cls,
        pb_path: str,
        events_path: str,
        sync_point: Optional[Union[SyncPoint, str, Path]] = 'auto'
    ) -> 'RingDataReader':
        """Create reader with real timestamps from events file.

        This is the recommended way to load data when you have both
        the protobuf and the original events file.

        Args:
            pb_path: Path to ring_data.pb
            events_path: Path to ring_events.txt
            sync_point: Time sync configuration

        Returns:
            RingDataReader with real UTC timestamps
        """
        reader = cls(pb_path, sync_point=sync_point)
        reader.load_events_file(events_path)
        return reader

    @property
    def raw(self) -> proto.RingData:
        """Access the raw protobuf RingData object."""
        return self._rd

    @property
    def heart_rate(self) -> HeartRateData:
        """Heart rate / IBI data with UTC timestamps if sync available."""
        if self._heart_rate is None:
            self._heart_rate = HeartRateData()
            if self._rd.HasField('ibi_and_amplitude_event'):
                ev = self._rd.ibi_and_amplitude_event
                raw_timestamps = list(ev.timestamp)
                self._heart_rate = HeartRateData(
                    timestamps=self._convert_timestamps(raw_timestamps),
                    ibi_ms=list(ev.ibi),
                    amplitudes=list(ev.amp),
                )
        return self._heart_rate

    @property
    def sleep(self) -> SleepData:
        """Sleep period data with UTC timestamps if sync available."""
        if self._sleep is None:
            self._sleep = SleepData()
            if self._rd.HasField('sleep_period_info'):
                ev = self._rd.sleep_period_info

                # Get HRV data if available
                rmssd_values = []
                if self._rd.HasField('hrv_event'):
                    rmssd_values = list(self._rd.hrv_event.average_rmssd_5min)

                # Use parsed event timestamps if available (real UTC)
                if self._parsed_events and self._parsed_events.sleep_timestamps:
                    timestamps = self._parsed_events.sleep_timestamps
                else:
                    raw_timestamps = list(ev.timestamp)
                    timestamps = self._convert_timestamps(raw_timestamps)

                self._sleep = SleepData(
                    timestamps=timestamps,
                    average_hr=list(ev.average_hr),
                    hr_trend=list(ev.hr_trend),
                    breath_rate=list(ev.breath),
                    breath_v=list(ev.breath_v),
                    motion_count=list(ev.motion_count),
                    sleep_state=list(ev.sleep_state),
                    mzci=list(ev.mzci),
                    dzci=list(ev.dzci),
                    cv=list(ev.cv),
                    rmssd_5min=rmssd_values,
                )
        return self._sleep

    @property
    def temperature(self) -> TemperatureData:
        """Temperature data with UTC timestamps if sync available."""
        if self._temperature is None:
            self._temperature = TemperatureData()
            if self._rd.HasField('sleep_temp_event'):
                ev = self._rd.sleep_temp_event

                # Use parsed event timestamps if available
                if self._parsed_events and self._parsed_events.temp_timestamps:
                    timestamps = self._parsed_events.temp_timestamps
                else:
                    raw_timestamps = list(ev.timestamp)
                    timestamps = self._convert_timestamps(raw_timestamps)

                self._temperature = TemperatureData(
                    timestamps=timestamps,
                    temp_celsius=list(ev.temp),
                )
        return self._temperature

    @property
    def hrv(self) -> HRVData:
        """Heart rate variability data with UTC timestamps if sync available."""
        if self._hrv is None:
            self._hrv = HRVData()
            if self._rd.HasField('hrv_event'):
                ev = self._rd.hrv_event
                raw_timestamps = list(ev.timestamp)
                self._hrv = HRVData(
                    timestamps=self._convert_timestamps(raw_timestamps),
                    average_hr_5min=list(ev.average_hr_5min),
                    average_rmssd_5min=list(ev.average_rmssd_5min),
                )
        return self._hrv

    @property
    def activity(self) -> ActivityData:
        """Activity and step count data with UTC timestamps if sync available."""
        if self._activity is None:
            self._activity = ActivityData()
            if self._rd.HasField('activity_info_event'):
                ev = self._rd.activity_info_event
                met_levels = {}
                for i in range(1, 14):
                    attr = f'met_level{i}'
                    if hasattr(ev, attr):
                        values = list(getattr(ev, attr))
                        if values:
                            met_levels[attr] = values
                raw_timestamps = list(ev.timestamp)
                self._activity = ActivityData(
                    timestamps=self._convert_timestamps(raw_timestamps),
                    step_count=list(ev.step_count),
                    met_levels=met_levels,
                )
        return self._activity

    @property
    def spo2(self) -> SpO2Data:
        """Blood oxygen saturation data with UTC timestamps if sync available."""
        if self._spo2 is None:
            self._spo2 = SpO2Data()
            if self._rd.HasField('spo2_event'):
                ev = self._rd.spo2_event
                raw_timestamps = list(ev.timestamp)
                self._spo2 = SpO2Data(
                    timestamps=self._convert_timestamps(raw_timestamps),
                    spo2_values=list(ev.spo2),
                    beat_indices=list(ev.beat_index),
                )
        return self._spo2

    @property
    def motion(self) -> MotionData:
        """Motion/accelerometer data with UTC timestamps if sync available."""
        if self._motion is None:
            self._motion = MotionData()
            if self._rd.HasField('motion_event'):
                ev = self._rd.motion_event

                # Use parsed event timestamps if available
                if self._parsed_events and self._parsed_events.motion_timestamps:
                    timestamps = self._parsed_events.motion_timestamps
                else:
                    raw_timestamps = list(ev.timestamp)
                    timestamps = self._convert_timestamps(raw_timestamps)

                self._motion = MotionData(
                    timestamps=timestamps,
                    orientation=list(ev.orientation),
                    motion_seconds=list(ev.motion_seconds),
                    average_x=list(ev.average_x),
                    average_y=list(ev.average_y),
                    average_z=list(ev.average_z),
                )
        return self._motion

    @property
    def ring_info(self) -> RingInfo:
        """Ring hardware/firmware information."""
        if self._ring_info is None:
            self._ring_info = RingInfo()
            try:
                if self._rd.HasField('startup_event'):
                    ev = self._rd.startup_event
                    self._ring_info = RingInfo(
                        ring_type=ev.ring_type if hasattr(ev, 'ring_type') else 0,
                        firmware_version=ev.fw_version if hasattr(ev, 'fw_version') else "",
                        hardware_version=ev.hw_version if hasattr(ev, 'hw_version') else "",
                        serial_number=ev.serial if hasattr(ev, 'serial') else "",
                        bootloader_version=ev.bl_version if hasattr(ev, 'bl_version') else "",
                    )
            except ValueError:
                # Field doesn't exist in this protobuf schema
                pass
        return self._ring_info

    def get_native_sleep_stages(self) -> NativeSleepStages:
        """Get pre-classified sleep stages from ring data.

        The ring stores sleep stages classified by the Oura app:
            0 = DEEP_SLEEP
            1 = LIGHT_SLEEP
            2 = REM_SLEEP
            3 = AWAKE

        Returns:
            NativeSleepStages with duration metrics
        """
        return NativeSleepStages(
            timestamps=self.sleep.timestamps,
            stages=self.sleep.sleep_state
        )

    @property
    def fields_present(self) -> List[str]:
        """List of data fields present in the protobuf."""
        fields = []
        field_checks = [
            ('ibi_and_amplitude_event', 'heart_rate'),
            ('sleep_period_info', 'sleep'),
            ('sleep_temp_event', 'temperature'),
            ('hrv_event', 'hrv'),
            ('activity_info_event', 'activity'),
            ('spo2_event', 'spo2'),
            ('motion_event', 'motion'),
            ('startup_event', 'ring_info'),
        ]
        for proto_field, name in field_checks:
            try:
                if self._rd.HasField(proto_field):
                    fields.append(name)
            except ValueError:
                # Field doesn't exist in this protobuf schema
                pass
        return fields

    def summary(self) -> str:
        """Generate a human-readable summary of the data."""
        from datetime import datetime

        lines = [
            "=" * 50,
            "Oura Ring Data Summary",
            "=" * 50,
            f"File: {self._path.name}",
            f"Fields: {', '.join(self.fields_present)}",
            f"Time Sync: {'Active (UTC timestamps)' if self.has_sync else 'Not available (relative timestamps)'}",
        ]

        # Show bedtime if sync available and sleep data exists
        if self.has_sync and self.sleep.total_samples > 0:
            sleep_ts = self.sleep.timestamps
            if sleep_ts and sleep_ts[0] > 1000000000:  # Valid UTC ms
                start = datetime.fromtimestamp(sleep_ts[0] / 1000)
                end = datetime.fromtimestamp(sleep_ts[-1] / 1000)
                lines.extend([
                    "",
                    "[Bedtime]",
                    f"  Start: {start.strftime('%Y-%m-%d %H:%M')}",
                    f"  End:   {end.strftime('%Y-%m-%d %H:%M')}",
                ])

        # Heart Rate
        if self.heart_rate.sample_count > 0:
            lines.extend([
                "",
                "[Heart Rate]",
                f"  Samples: {self.heart_rate.sample_count}",
                f"  Average: {self.heart_rate.average_bpm:.1f} BPM",
                f"  Range: {self.heart_rate.min_bpm:.0f} - {self.heart_rate.max_bpm:.0f} BPM",
            ])

        # HRV
        if self.hrv.sample_count > 0:
            lines.extend([
                "",
                "[HRV]",
                f"  Samples: {self.hrv.sample_count}",
                f"  Average RMSSD: {self.hrv.average_rmssd:.1f} ms",
                f"  Range: {self.hrv.min_rmssd:.1f} - {self.hrv.max_rmssd:.1f} ms",
            ])

        # Sleep
        if self.sleep.total_samples > 0:
            lines.extend([
                "",
                "[Sleep]",
                f"  Samples: {self.sleep.total_samples}",
                f"  Duration: ~{self.sleep.duration_hours:.1f} hours",
                f"  Avg HR: {self.sleep.average_heart_rate:.1f} BPM",
                f"  Avg Breath: {self.sleep.average_breath_rate:.1f} rpm",
            ])

        # Temperature
        if self.temperature.sample_count > 0:
            lines.extend([
                "",
                "[Temperature]",
                f"  Samples: {self.temperature.sample_count}",
                f"  Average: {self.temperature.average_celsius:.2f} C",
            ])

        # Activity
        if self.activity.sample_count > 0:
            lines.extend([
                "",
                "[Activity]",
                f"  Samples: {self.activity.sample_count}",
                f"  Total Steps: {self.activity.total_steps}",
            ])

        # SpO2
        if self.spo2.sample_count > 0:
            lines.extend([
                "",
                "[SpO2]",
                f"  Samples: {self.spo2.sample_count}",
                f"  Average: {self.spo2.average_spo2:.1f}%",
            ])

        lines.append("=" * 50)
        return "\n".join(lines)

    def to_dict(self) -> Dict[str, Any]:
        """Convert all data to dictionary for JSON serialization."""
        return {
            "file": str(self._path),
            "fields_present": self.fields_present,
            "heart_rate": self.heart_rate.to_dict() if self.heart_rate.sample_count > 0 else None,
            "hrv": self.hrv.to_dict() if self.hrv.sample_count > 0 else None,
            "sleep": self.sleep.to_dict() if self.sleep.total_samples > 0 else None,
            "temperature": self.temperature.to_dict() if self.temperature.sample_count > 0 else None,
            "activity": self.activity.to_dict() if self.activity.sample_count > 0 else None,
            "spo2": self.spo2.to_dict() if self.spo2.sample_count > 0 else None,
            "motion": self.motion.to_dict() if self.motion.sample_count > 0 else None,
            "ring_info": self.ring_info.to_dict(),
        }

    def to_json(self, indent: int = 2) -> str:
        """Convert all data to JSON string."""
        return json.dumps(self.to_dict(), indent=indent)
