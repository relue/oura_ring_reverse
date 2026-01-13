"""
Dashboard API

High-level aggregation layer providing Oura-app-like dashboard data.
"""

from __future__ import annotations

from dataclasses import dataclass, asdict
from typing import Dict, Any, Optional, TYPE_CHECKING
import json

from oura.analysis.scores import SleepScore, StageDurations

if TYPE_CHECKING:
    from oura.data.reader import RingDataReader
    from oura.analysis.sleep import SleepAnalyzer
    from oura.analysis.hrv import HRVAnalyzer


@dataclass
class Dashboard:
    """Oura-app-like dashboard data aggregation.

    Provides a single object with all the key metrics displayed
    on the Oura app's home screen.

    Example:
        analyzer = OuraAnalyzer("ring_data.pb")
        dashboard = analyzer.dashboard

        print(f"Sleep Score: {dashboard.sleep_score}")
        print(f"HRV: {dashboard.hrv_average} ms")
        print(f"Deep Sleep: {dashboard.deep_sleep_minutes} min")
    """

    # Sleep metrics
    sleep_score: int = 0
    total_sleep_hours: float = 0.0
    deep_sleep_minutes: float = 0.0
    rem_sleep_minutes: float = 0.0
    light_sleep_minutes: float = 0.0
    awake_minutes: float = 0.0
    sleep_efficiency: float = 0.0

    # HRV metrics
    hrv_average: float = 0.0
    hrv_min: float = 0.0
    hrv_max: float = 0.0
    hrv_balance: Optional[float] = None  # % deviation from baseline

    # Heart rate metrics
    avg_heart_rate: float = 0.0
    lowest_heart_rate: float = 0.0
    resting_heart_rate: float = 0.0

    # Breathing
    breathing_rate: float = 0.0

    # Temperature
    body_temperature: float = 0.0
    temperature_deviation: Optional[float] = None

    # SpO2
    spo2_average: float = 0.0

    # Activity
    steps: int = 0
    calories: int = 0

    # Readiness (placeholder - needs historical data)
    readiness_score: Optional[int] = None

    # Activity score (placeholder)
    activity_score: Optional[int] = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return asdict(self)

    def to_json(self, indent: int = 2) -> str:
        """Convert to JSON string."""
        return json.dumps(self.to_dict(), indent=indent)

    @classmethod
    def from_reader(cls, reader: 'RingDataReader') -> 'Dashboard':
        """Create Dashboard from RingDataReader.

        Args:
            reader: RingDataReader with loaded data

        Returns:
            Dashboard instance with populated metrics
        """
        from oura.analysis.sleep import SleepAnalyzer
        from oura.analysis.hrv import HRVAnalyzer

        # Create analyzers
        sleep_analyzer = SleepAnalyzer(reader)
        hrv_analyzer = HRVAnalyzer(reader)

        # Get sleep metrics
        stage_durations = sleep_analyzer.stage_durations
        sleep_score = sleep_analyzer.score

        # Get HRV metrics
        hrv_by_stage = hrv_analyzer.by_sleep_stage()

        return cls(
            # Sleep
            sleep_score=sleep_score.score,
            total_sleep_hours=stage_durations.total_sleep / 60.0,
            deep_sleep_minutes=stage_durations.deep,
            rem_sleep_minutes=stage_durations.rem,
            light_sleep_minutes=stage_durations.light,
            awake_minutes=stage_durations.awake,
            sleep_efficiency=stage_durations.efficiency,

            # HRV
            hrv_average=hrv_analyzer.average_rmssd,
            hrv_min=hrv_analyzer.min_rmssd,
            hrv_max=hrv_analyzer.max_rmssd,

            # Heart rate
            avg_heart_rate=reader.sleep.average_heart_rate,
            lowest_heart_rate=reader.heart_rate.min_bpm if reader.heart_rate.sample_count > 0 else 0.0,
            resting_heart_rate=reader.heart_rate.min_bpm if reader.heart_rate.sample_count > 0 else 0.0,

            # Breathing
            breathing_rate=reader.sleep.average_breath_rate,

            # Temperature
            body_temperature=reader.temperature.average_celsius,

            # SpO2
            spo2_average=reader.spo2.average_spo2,

            # Activity
            steps=reader.activity.total_steps,
        )

    def summary(self) -> str:
        """Generate a human-readable dashboard summary."""
        lines = [
            "=" * 50,
            "Oura Dashboard",
            "=" * 50,
            "",
            "[Sleep]",
            f"  Score: {self.sleep_score}",
            f"  Total: {self.total_sleep_hours:.1f} hours",
            f"  Deep: {self.deep_sleep_minutes:.0f} min",
            f"  REM: {self.rem_sleep_minutes:.0f} min",
            f"  Light: {self.light_sleep_minutes:.0f} min",
            f"  Awake: {self.awake_minutes:.0f} min",
            f"  Efficiency: {self.sleep_efficiency:.1f}%",
            "",
            "[HRV]",
            f"  Average: {self.hrv_average:.1f} ms",
            f"  Range: {self.hrv_min:.0f} - {self.hrv_max:.0f} ms",
        ]

        if self.hrv_balance is not None:
            lines.append(f"  Balance: {self.hrv_balance:+.1f}%")

        lines.extend([
            "",
            "[Vitals]",
            f"  Avg HR: {self.avg_heart_rate:.0f} BPM",
            f"  Lowest HR: {self.lowest_heart_rate:.0f} BPM",
            f"  Breathing: {self.breathing_rate:.1f} rpm",
        ])

        if self.body_temperature > 0:
            lines.append(f"  Temperature: {self.body_temperature:.1f}°C")

        if self.spo2_average > 0:
            lines.append(f"  SpO2: {self.spo2_average:.0f}%")

        if self.steps > 0:
            lines.extend([
                "",
                "[Activity]",
                f"  Steps: {self.steps:,}",
            ])

        lines.append("=" * 50)
        return "\n".join(lines)
