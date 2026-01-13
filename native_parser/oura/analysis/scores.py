"""
Oura Score Data Classes

Data classes for sleep, readiness, and activity scores with contributors.
"""

from __future__ import annotations

from dataclasses import dataclass, asdict
from typing import Dict, Any
import json


@dataclass
class SleepScore:
    """Sleep score with 7 contributors (0-100 scale).

    Contributors:
        total_sleep: Total sleep duration contribution
        efficiency: Sleep efficiency (time asleep / time in bed)
        restfulness: Sleep disturbances/restlessness
        rem_sleep: REM sleep percentage contribution
        deep_sleep: Deep sleep percentage contribution
        latency: Time to fall asleep contribution
        timing: Circadian alignment contribution
    """
    score: int = 0
    total_sleep: int = 0
    efficiency: int = 0
    restfulness: int = 0
    rem_sleep: int = 0
    deep_sleep: int = 0
    latency: int = 0
    timing: int = 0

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(self.to_dict())

    @property
    def contributors(self) -> Dict[str, int]:
        """Return just the contributor values."""
        return {
            "total_sleep": self.total_sleep,
            "efficiency": self.efficiency,
            "restfulness": self.restfulness,
            "rem_sleep": self.rem_sleep,
            "deep_sleep": self.deep_sleep,
            "latency": self.latency,
            "timing": self.timing,
        }


@dataclass
class ReadinessScore:
    """Readiness score with 9 contributors (0-100 scale).

    Contributors:
        previous_night: Last night's sleep quality
        sleep_balance: 2-week sleep debt balance
        previous_day_activity: Yesterday's activity level
        activity_balance: Training load balance
        body_temperature: Temperature deviation from baseline
        resting_heart_rate: RHR vs baseline
        hrv_balance: HRV vs baseline
        recovery_index: Overall recovery status
        sleep_regularity: Sleep schedule consistency
    """
    score: int = 0
    previous_night: int = 0
    sleep_balance: int = 0
    previous_day_activity: int = 0
    activity_balance: int = 0
    body_temperature: int = 0
    resting_heart_rate: int = 0
    hrv_balance: int = 0
    recovery_index: int = 0
    sleep_regularity: int = 0

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(self.to_dict())

    @property
    def contributors(self) -> Dict[str, int]:
        """Return just the contributor values."""
        return {
            "previous_night": self.previous_night,
            "sleep_balance": self.sleep_balance,
            "previous_day_activity": self.previous_day_activity,
            "activity_balance": self.activity_balance,
            "body_temperature": self.body_temperature,
            "resting_heart_rate": self.resting_heart_rate,
            "hrv_balance": self.hrv_balance,
            "recovery_index": self.recovery_index,
            "sleep_regularity": self.sleep_regularity,
        }


@dataclass
class ActivityScore:
    """Activity score with 6 contributors (0-100 scale).

    Contributors:
        stay_active: Overall activity level
        move_every_hour: Hourly movement consistency
        meet_daily_targets: Goal achievement
        training_frequency: Training session count
        training_volume: Total training time
        recovery_time: Low activity recovery balance
    """
    score: int = 0
    stay_active: int = 0
    move_every_hour: int = 0
    meet_daily_targets: int = 0
    training_frequency: int = 0
    training_volume: int = 0
    recovery_time: int = 0

    # Additional metrics
    steps: int = 0
    calories: int = 0
    distance_meters: int = 0

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(self.to_dict())

    @property
    def contributors(self) -> Dict[str, int]:
        """Return just the contributor values."""
        return {
            "stay_active": self.stay_active,
            "move_every_hour": self.move_every_hour,
            "meet_daily_targets": self.meet_daily_targets,
            "training_frequency": self.training_frequency,
            "training_volume": self.training_volume,
            "recovery_time": self.recovery_time,
        }


@dataclass
class StageDurations:
    """Sleep stage durations in minutes."""
    deep: float = 0.0
    light: float = 0.0
    rem: float = 0.0
    awake: float = 0.0

    @property
    def total_sleep(self) -> float:
        """Total sleep time (excluding awake)."""
        return self.deep + self.light + self.rem

    @property
    def total_time(self) -> float:
        """Total time in bed."""
        return self.deep + self.light + self.rem + self.awake

    @property
    def efficiency(self) -> float:
        """Sleep efficiency percentage."""
        return (self.total_sleep / self.total_time * 100) if self.total_time > 0 else 0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "deep_minutes": round(self.deep, 1),
            "light_minutes": round(self.light, 1),
            "rem_minutes": round(self.rem, 1),
            "awake_minutes": round(self.awake, 1),
            "total_sleep_minutes": round(self.total_sleep, 1),
            "efficiency_percent": round(self.efficiency, 1),
        }
