"""
Sleep Analyzer

High-level sleep analysis with stages, scores, and metrics.
Uses SleepNet ML model when available for proper REM classification.
"""

from __future__ import annotations

from typing import List, Dict, Any, Optional, Tuple, TYPE_CHECKING
from datetime import datetime
import numpy as np

from oura.data.models import SleepData, NativeSleepStages
from oura.analysis.scores import SleepScore, StageDurations

if TYPE_CHECKING:
    from oura.data.reader import RingDataReader

# Try to import SleepNet for ML-based classification
_SLEEPNET_AVAILABLE = False
_sleepnet_model = None

def _get_sleepnet():
    """Get or create the SleepNet model (singleton)."""
    global _SLEEPNET_AVAILABLE, _sleepnet_model
    if _sleepnet_model is not None:
        return _sleepnet_model
    if not _SLEEPNET_AVAILABLE:
        try:
            from ml_inference.sleepnet import SleepNetModel
            _sleepnet_model = SleepNetModel()
            _SLEEPNET_AVAILABLE = True
            print("[SleepAnalyzer] SleepNet ML model loaded")
        except Exception as e:
            _SLEEPNET_AVAILABLE = False
            print(f"[SleepAnalyzer] SleepNet not available: {e}")
    return _sleepnet_model


class SleepAnalyzer:
    """Sleep-specific analysis.

    Provides access to sleep stages, durations, scores, and hypnogram data.
    Uses SleepNet ML model when available for proper REM classification.

    Example:
        analyzer = OuraAnalyzer("ring_data.pb")
        sleep = analyzer.sleep

        print(sleep.stages)              # [0, 1, 2, 3, ...] with ML classification
        print(sleep.stage_durations)     # StageDurations with REM
        print(sleep.score)               # SleepScore
        print(sleep.efficiency)          # 92.5

    Stage encoding (standard):
        0 = AWAKE
        1 = LIGHT
        2 = DEEP
        3 = REM
    """

    def __init__(self, reader: 'RingDataReader', use_ml: bool = True):
        """Initialize with a RingDataReader.

        Args:
            reader: RingDataReader instance with loaded data
            use_ml: Whether to use SleepNet ML model for classification (default True)
        """
        self._reader = reader
        self._use_ml = use_ml
        self._native_stages: Optional[NativeSleepStages] = None
        self._ml_result = None  # Cached SleepNet result
        self._score: Optional[SleepScore] = None
        self._ml_attempted = False

    def _get_ml_result(self):
        """Get SleepNet ML classification result (cached)."""
        if self._ml_result is not None:
            return self._ml_result
        if self._ml_attempted:
            return None
        self._ml_attempted = True

        if not self._use_ml:
            return None

        sleepnet = _get_sleepnet()
        if sleepnet is None:
            return None

        try:
            self._ml_result = sleepnet.predict_from_reader(self._reader)
            return self._ml_result
        except Exception as e:
            print(f"[SleepAnalyzer] ML prediction failed: {e}")
            return None

    @property
    def uses_ml(self) -> bool:
        """Whether ML-based classification is being used."""
        return self._get_ml_result() is not None

    @property
    def stages(self) -> np.ndarray:
        """Sleep stages as numpy array (30-second epochs).

        Stage encoding (standard):
            0 = AWAKE
            1 = LIGHT
            2 = DEEP
            3 = REM

        Uses SleepNet ML model when available, otherwise falls back to raw protobuf.

        Returns:
            numpy array of stage values
        """
        ml_result = self._get_ml_result()
        if ml_result is not None:
            return ml_result.stages

        # Fallback to raw protobuf (no REM)
        # Raw protobuf uses: 0=Deep, 1=Light - convert to standard encoding
        native = self._get_native_stages()
        raw_stages = np.array(native.stages)
        # Map: raw 0 (Deep) -> 2, raw 1 (Light) -> 1
        stage_map = {0: 2, 1: 1, 2: 3, 3: 0}
        return np.array([stage_map.get(int(s), int(s)) for s in raw_stages])

    @property
    def stage_durations(self) -> StageDurations:
        """Duration in each sleep stage (minutes).

        Uses SleepNet ML model when available for accurate REM detection.
        """
        ml_result = self._get_ml_result()
        if ml_result is not None:
            return StageDurations(
                deep=ml_result.deep_seconds / 60,
                light=ml_result.light_seconds / 60,
                rem=ml_result.rem_seconds / 60,
                awake=ml_result.awake_seconds / 60,
            )

        # Fallback to raw protobuf
        native = self._get_native_stages()
        return StageDurations(
            deep=native.deep_minutes,
            light=native.light_minutes,
            rem=native.rem_minutes,
            awake=native.awake_minutes,
        )

    @property
    def timestamps(self) -> np.ndarray:
        """Unix timestamps (seconds) for each sleep epoch.

        Uses SleepNet derived timestamps when available (from IBI duration).
        Falls back to synthetic timestamps otherwise.

        Returns:
            numpy array of Unix timestamps
        """
        ml_result = self._get_ml_result()
        if ml_result is not None:
            return ml_result.timestamps

        # Fallback: generate synthetic timestamps (assume current time as end)
        import time
        n_epochs = len(self._get_native_stages().stages)
        end_time = time.time()
        start_time = end_time - (n_epochs * 30)  # 30 sec per epoch
        return np.linspace(start_time, end_time, n_epochs)

    @property
    def bedtime_start(self) -> float:
        """Bedtime start as Unix timestamp (seconds)."""
        ts = self.timestamps
        return float(ts[0]) if len(ts) > 0 else 0.0

    @property
    def bedtime_end(self) -> float:
        """Bedtime end as Unix timestamp (seconds)."""
        ts = self.timestamps
        return float(ts[-1]) if len(ts) > 0 else 0.0

    @property
    def total_sleep_minutes(self) -> float:
        """Total sleep time in minutes (excluding awake)."""
        return self.stage_durations.total_sleep

    @property
    def efficiency(self) -> float:
        """Sleep efficiency percentage (time asleep / time in bed)."""
        return self.stage_durations.efficiency

    @property
    def score(self) -> SleepScore:
        """Calculate sleep score with contributors.

        Uses ML-aware stage_durations for accurate REM data.
        Falls back to basic calculation if native library unavailable.
        """
        if self._score is not None:
            return self._score

        # Use ML-aware stage durations (not raw protobuf)
        durations = self.stage_durations

        # Try native score calculation via QEMU bridge
        try:
            from oura_ecore import EcoreWrapper
            ecore = EcoreWrapper()

            result = ecore.calculate_sleep_score(
                total_sleep_min=int(durations.total_sleep),
                deep_sleep_min=int(durations.deep),
                rem_sleep_min=int(durations.rem),  # Now uses ML REM!
                efficiency=int(durations.efficiency),
                latency_min=10,  # Default estimate
                wakeup_count=self._estimate_wakeup_count(),
                awake_sec=int(durations.awake * 60),
                restless_periods=5,  # Default estimate
                temp_deviation=0,
            )

            # Calculate REM contributor (20-25% optimal)
            rem_pct = (durations.rem / durations.total_sleep * 100) if durations.total_sleep > 0 else 0
            if rem_pct >= 20:
                rem_contrib = 100
            elif rem_pct >= 15:
                rem_contrib = 80
            elif rem_pct >= 10:
                rem_contrib = 60
            else:
                rem_contrib = 40

            self._score = SleepScore(
                score=result.score,
                total_sleep=result.total_contrib,
                efficiency=result.efficiency_contrib,
                restfulness=result.restfulness_contrib,
                rem_sleep=rem_contrib,
                deep_sleep=result.deep_contrib,
                latency=result.latency_contrib,
                timing=result.timing_contrib,
            )
        except Exception:
            # Fallback to basic score calculation
            self._score = self._calculate_basic_score()

        return self._score

    @property
    def hypnogram(self) -> List[Tuple[int, int]]:
        """Timestamped stages for plotting.

        Returns:
            List of (timestamp_ms, stage) tuples
        """
        native = self._get_native_stages()
        result = []
        for i, stage in enumerate(native.stages):
            if i < len(native.timestamps):
                result.append((native.timestamps[i], stage))
        return result

    @property
    def average_heart_rate(self) -> float:
        """Average heart rate during sleep."""
        return self._reader.sleep.average_heart_rate

    @property
    def average_breath_rate(self) -> float:
        """Average breathing rate during sleep."""
        return self._reader.sleep.average_breath_rate

    def _get_native_stages(self) -> NativeSleepStages:
        """Get native sleep stages (cached)."""
        if self._native_stages is None:
            self._native_stages = self._reader.get_native_sleep_stages()
        return self._native_stages

    def _estimate_wakeup_count(self) -> int:
        """Estimate number of wake periods during sleep."""
        stages = self.stages
        if len(stages) == 0:
            return 0

        wakeup_count = 0
        in_sleep = False

        for stage in stages:
            if stage != 3:  # Not awake
                in_sleep = True
            elif in_sleep and stage == 3:  # Transition to awake
                wakeup_count += 1
                in_sleep = False

        return wakeup_count

    def _calculate_basic_score(self) -> SleepScore:
        """Calculate basic sleep score without native library.

        Uses ML-aware stage_durations for accurate REM data.
        """
        # Use ML-aware durations (not raw protobuf)
        durations = self.stage_durations

        # Simple scoring based on duration and efficiency
        total_sleep_hours = durations.total_sleep / 60

        # Duration score: 7-9 hours optimal
        if total_sleep_hours >= 7 and total_sleep_hours <= 9:
            duration_score = 100
        elif total_sleep_hours >= 6:
            duration_score = 80
        elif total_sleep_hours >= 5:
            duration_score = 60
        else:
            duration_score = 40

        # Efficiency score
        eff = durations.efficiency
        if eff >= 85:
            efficiency_score = 100
        elif eff >= 75:
            efficiency_score = 80
        elif eff >= 65:
            efficiency_score = 60
        else:
            efficiency_score = 40

        # Deep sleep score: 15-20% optimal
        deep_pct = (durations.deep / durations.total_sleep * 100) if durations.total_sleep > 0 else 0
        if deep_pct >= 15:
            deep_score = 100
        elif deep_pct >= 10:
            deep_score = 80
        else:
            deep_score = 60

        # REM score: 20-25% optimal (now with real ML REM data!)
        rem_pct = (durations.rem / durations.total_sleep * 100) if durations.total_sleep > 0 else 0
        if rem_pct >= 20:
            rem_score = 100
        elif rem_pct >= 15:
            rem_score = 80
        elif rem_pct >= 10:
            rem_score = 60
        else:
            rem_score = 40

        # Overall score (weighted average)
        overall = int(
            duration_score * 0.35 +
            efficiency_score * 0.25 +
            deep_score * 0.20 +
            rem_score * 0.20
        )

        return SleepScore(
            score=overall,
            total_sleep=int(duration_score),
            efficiency=int(efficiency_score),
            restfulness=70,  # Default
            rem_sleep=int(rem_score),
            deep_sleep=int(deep_score),
            latency=80,  # Default
            timing=80,  # Default
        )

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return {
            "stage_durations": self.stage_durations.to_dict(),
            "total_sleep_minutes": round(self.total_sleep_minutes, 1),
            "efficiency": round(self.efficiency, 1),
            "score": self.score.to_dict(),
            "average_heart_rate": round(self.average_heart_rate, 1),
            "average_breath_rate": round(self.average_breath_rate, 1),
        }
