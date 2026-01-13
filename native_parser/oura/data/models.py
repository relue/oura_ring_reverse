"""
Oura Ring Data Models

Data classes for representing ring sensor data.
These are immutable containers with computed properties.
"""

from __future__ import annotations

from dataclasses import dataclass, field, asdict
from datetime import datetime
from typing import List, Dict, Any, Optional


def _format_timestamp(ms: int) -> str:
    """Format millisecond timestamp as ISO string."""
    if ms > 0:
        try:
            dt = datetime.fromtimestamp(ms / 1000)
            return dt.isoformat()
        except (ValueError, OSError):
            return f"{ms}ms"
    return "N/A"


@dataclass
class HeartRateData:
    """Heart rate / Inter-Beat Interval (IBI) data from the ring."""
    timestamps: List[int] = field(default_factory=list)
    ibi_ms: List[int] = field(default_factory=list)
    amplitudes: List[int] = field(default_factory=list)

    @property
    def sample_count(self) -> int:
        """Number of IBI samples."""
        return len(self.ibi_ms)

    @property
    def average_ibi(self) -> float:
        """Average IBI in milliseconds."""
        if not self.ibi_ms:
            return 0.0
        return sum(self.ibi_ms) / len(self.ibi_ms)

    @property
    def average_bpm(self) -> float:
        """Average heart rate in BPM."""
        avg_ibi = self.average_ibi
        return 60000 / avg_ibi if avg_ibi > 0 else 0.0

    @property
    def min_bpm(self) -> float:
        """Minimum heart rate in BPM (from max IBI)."""
        if not self.ibi_ms:
            return 0.0
        max_ibi = max(self.ibi_ms)
        return 60000 / max_ibi if max_ibi > 0 else 0.0

    @property
    def max_bpm(self) -> float:
        """Maximum heart rate in BPM (from min IBI)."""
        if not self.ibi_ms:
            return 0.0
        min_ibi = min(self.ibi_ms)
        return 60000 / min_ibi if min_ibi > 0 else 0.0

    @property
    def time_range(self) -> tuple:
        """First and last timestamp as (start, end) ISO strings."""
        if not self.timestamps:
            return ("N/A", "N/A")
        return (_format_timestamp(self.timestamps[0]),
                _format_timestamp(self.timestamps[-1]))

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return {
            "sample_count": self.sample_count,
            "average_bpm": round(self.average_bpm, 1),
            "min_bpm": round(self.min_bpm, 1),
            "max_bpm": round(self.max_bpm, 1),
            "average_ibi_ms": round(self.average_ibi, 0),
            "time_range": self.time_range,
        }


@dataclass
class SleepData:
    """Sleep period information from the ring."""
    timestamps: List[int] = field(default_factory=list)
    average_hr: List[float] = field(default_factory=list)
    hr_trend: List[float] = field(default_factory=list)
    breath_rate: List[float] = field(default_factory=list)
    breath_v: List[float] = field(default_factory=list)
    motion_count: List[int] = field(default_factory=list)
    sleep_state: List[int] = field(default_factory=list)
    mzci: List[float] = field(default_factory=list)
    dzci: List[float] = field(default_factory=list)
    cv: List[float] = field(default_factory=list)
    rmssd_5min: List[float] = field(default_factory=list)

    @property
    def total_samples(self) -> int:
        """Number of sleep samples (typically 5-minute intervals)."""
        return len(self.timestamps)

    @property
    def duration_hours(self) -> float:
        """Estimated sleep duration in hours (samples * 5 min / 60)."""
        return (self.total_samples * 5) / 60

    @property
    def average_heart_rate(self) -> float:
        """Average heart rate during sleep."""
        valid_hr = [h for h in self.average_hr if h > 0]
        return sum(valid_hr) / len(valid_hr) if valid_hr else 0.0

    @property
    def average_breath_rate(self) -> float:
        """Average breathing rate per minute during sleep."""
        valid_br = [b for b in self.breath_rate if b > 0]
        return sum(valid_br) / len(valid_br) if valid_br else 0.0

    @property
    def time_range(self) -> tuple:
        """First and last timestamp as (start, end) ISO strings."""
        if not self.timestamps:
            return ("N/A", "N/A")
        return (_format_timestamp(self.timestamps[0]),
                _format_timestamp(self.timestamps[-1]))

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return {
            "total_samples": self.total_samples,
            "duration_hours": round(self.duration_hours, 1),
            "average_heart_rate": round(self.average_heart_rate, 1),
            "average_breath_rate": round(self.average_breath_rate, 1),
            "time_range": self.time_range,
        }


@dataclass
class TemperatureData:
    """Temperature readings from the ring."""
    timestamps: List[int] = field(default_factory=list)
    temp_celsius: List[float] = field(default_factory=list)

    @property
    def sample_count(self) -> int:
        """Number of temperature samples."""
        return len(self.temp_celsius)

    @property
    def average_celsius(self) -> float:
        """Average temperature in Celsius."""
        if not self.temp_celsius:
            return 0.0
        return sum(self.temp_celsius) / len(self.temp_celsius)

    @property
    def min_celsius(self) -> float:
        """Minimum temperature in Celsius."""
        return min(self.temp_celsius) if self.temp_celsius else 0.0

    @property
    def max_celsius(self) -> float:
        """Maximum temperature in Celsius."""
        return max(self.temp_celsius) if self.temp_celsius else 0.0

    @property
    def time_range(self) -> tuple:
        """First and last timestamp as (start, end) ISO strings."""
        if not self.timestamps:
            return ("N/A", "N/A")
        return (_format_timestamp(self.timestamps[0]),
                _format_timestamp(self.timestamps[-1]))

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return {
            "sample_count": self.sample_count,
            "average_celsius": round(self.average_celsius, 2),
            "min_celsius": round(self.min_celsius, 2),
            "max_celsius": round(self.max_celsius, 2),
            "time_range": self.time_range,
        }


@dataclass
class HRVData:
    """Heart Rate Variability (HRV) data from the ring."""
    timestamps: List[int] = field(default_factory=list)
    average_hr_5min: List[int] = field(default_factory=list)
    average_rmssd_5min: List[int] = field(default_factory=list)

    @property
    def sample_count(self) -> int:
        """Number of HRV samples (typically 5-minute intervals)."""
        return len(self.average_rmssd_5min)

    @property
    def average_rmssd(self) -> float:
        """Average RMSSD (root mean square of successive differences) in ms."""
        if not self.average_rmssd_5min:
            return 0.0
        return sum(self.average_rmssd_5min) / len(self.average_rmssd_5min)

    @property
    def min_rmssd(self) -> float:
        """Minimum RMSSD in ms."""
        return min(self.average_rmssd_5min) if self.average_rmssd_5min else 0.0

    @property
    def max_rmssd(self) -> float:
        """Maximum RMSSD in ms."""
        return max(self.average_rmssd_5min) if self.average_rmssd_5min else 0.0

    @property
    def average_hr(self) -> float:
        """Average heart rate from HRV measurements."""
        if not self.average_hr_5min:
            return 0.0
        return sum(self.average_hr_5min) / len(self.average_hr_5min)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return {
            "sample_count": self.sample_count,
            "average_rmssd_ms": round(self.average_rmssd, 1),
            "min_rmssd_ms": round(self.min_rmssd, 1),
            "max_rmssd_ms": round(self.max_rmssd, 1),
            "average_hr_bpm": round(self.average_hr, 1),
        }


@dataclass
class ActivityData:
    """Activity and step count data from the ring."""
    timestamps: List[int] = field(default_factory=list)
    step_count: List[int] = field(default_factory=list)
    met_levels: Dict[str, List[float]] = field(default_factory=dict)

    @property
    def sample_count(self) -> int:
        """Number of activity samples."""
        return len(self.timestamps)

    @property
    def total_steps(self) -> int:
        """Total step count across all samples."""
        return sum(self.step_count)

    @property
    def time_range(self) -> tuple:
        """First and last timestamp as (start, end) ISO strings."""
        if not self.timestamps:
            return ("N/A", "N/A")
        return (_format_timestamp(self.timestamps[0]),
                _format_timestamp(self.timestamps[-1]))

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return {
            "sample_count": self.sample_count,
            "total_steps": self.total_steps,
            "time_range": self.time_range,
        }


@dataclass
class SpO2Data:
    """Blood oxygen saturation (SpO2) data from the ring."""
    timestamps: List[int] = field(default_factory=list)
    spo2_values: List[int] = field(default_factory=list)
    beat_indices: List[int] = field(default_factory=list)

    @property
    def sample_count(self) -> int:
        """Number of SpO2 samples."""
        return len(self.spo2_values)

    @property
    def average_spo2(self) -> float:
        """Average SpO2 percentage."""
        if not self.spo2_values:
            return 0.0
        return sum(self.spo2_values) / len(self.spo2_values)

    @property
    def min_spo2(self) -> float:
        """Minimum SpO2 percentage."""
        return min(self.spo2_values) if self.spo2_values else 0.0

    @property
    def max_spo2(self) -> float:
        """Maximum SpO2 percentage."""
        return max(self.spo2_values) if self.spo2_values else 0.0

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return {
            "sample_count": self.sample_count,
            "average_spo2": round(self.average_spo2, 1),
            "min_spo2": round(self.min_spo2, 1),
            "max_spo2": round(self.max_spo2, 1),
        }


@dataclass
class MotionData:
    """Motion/accelerometer data from the ring."""
    timestamps: List[int] = field(default_factory=list)
    orientation: List[int] = field(default_factory=list)
    motion_seconds: List[int] = field(default_factory=list)
    average_x: List[float] = field(default_factory=list)
    average_y: List[float] = field(default_factory=list)
    average_z: List[float] = field(default_factory=list)

    @property
    def sample_count(self) -> int:
        """Number of motion samples."""
        return len(self.timestamps)

    @property
    def total_motion_seconds(self) -> int:
        """Total detected motion in seconds."""
        return sum(self.motion_seconds)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return {
            "sample_count": self.sample_count,
            "total_motion_seconds": self.total_motion_seconds,
        }


@dataclass
class RingInfo:
    """Basic ring information from startup event."""
    ring_type: int = 0
    firmware_version: str = ""
    hardware_version: str = ""
    serial_number: str = ""
    bootloader_version: str = ""

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return asdict(self)


@dataclass
class NativeSleepStages:
    """Sleep stages from native ring data (pre-classified by Oura).

    Stage encoding:
        0 = DEEP_SLEEP
        1 = LIGHT_SLEEP
        2 = REM_SLEEP
        3 = AWAKE
    """
    timestamps: List[int] = field(default_factory=list)
    stages: List[int] = field(default_factory=list)
    epoch_seconds: int = 30  # 30-second epochs

    @property
    def total_epochs(self) -> int:
        return len(self.stages)

    @property
    def deep_epochs(self) -> int:
        return sum(1 for s in self.stages if s == 0)

    @property
    def light_epochs(self) -> int:
        return sum(1 for s in self.stages if s == 1)

    @property
    def rem_epochs(self) -> int:
        return sum(1 for s in self.stages if s == 2)

    @property
    def awake_epochs(self) -> int:
        return sum(1 for s in self.stages if s == 3)

    @property
    def epoch_minutes(self) -> float:
        """Epoch duration in minutes."""
        return self.epoch_seconds / 60.0

    @property
    def deep_minutes(self) -> float:
        return self.deep_epochs * self.epoch_minutes

    @property
    def light_minutes(self) -> float:
        return self.light_epochs * self.epoch_minutes

    @property
    def rem_minutes(self) -> float:
        return self.rem_epochs * self.epoch_minutes

    @property
    def awake_minutes(self) -> float:
        return self.awake_epochs * self.epoch_minutes

    @property
    def total_sleep_minutes(self) -> float:
        return self.deep_minutes + self.light_minutes + self.rem_minutes

    @property
    def sleep_efficiency(self) -> float:
        total = self.total_epochs * self.epoch_minutes
        return (self.total_sleep_minutes / total * 100) if total > 0 else 0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "deep_minutes": round(self.deep_minutes, 1),
            "light_minutes": round(self.light_minutes, 1),
            "rem_minutes": round(self.rem_minutes, 1),
            "awake_minutes": round(self.awake_minutes, 1),
            "total_sleep_minutes": round(self.total_sleep_minutes, 1),
            "sleep_efficiency": round(self.sleep_efficiency, 1),
        }
