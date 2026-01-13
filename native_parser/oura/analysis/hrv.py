"""
HRV Analyzer

Heart Rate Variability analysis with RMSSD metrics and sleep stage breakdown.
"""

from __future__ import annotations

from typing import Dict, Any, List, Optional, TYPE_CHECKING
import numpy as np

from oura.data.models import HRVData

if TYPE_CHECKING:
    from oura.data.reader import RingDataReader


class HRVAnalyzer:
    """HRV-specific analysis.

    Provides RMSSD metrics, per-stage analysis, and balance calculations.

    Example:
        analyzer = OuraAnalyzer("ring_data.pb")
        hrv = analyzer.hrv

        print(hrv.average_rmssd)         # 21.2
        print(hrv.samples_5min)          # [17, 19, 23, ...]
        print(hrv.by_sleep_stage())      # {'deep': 25.3, 'light': 19.1, ...}
        print(hrv.balance(baseline=25))  # -15.2%
    """

    def __init__(self, reader: 'RingDataReader'):
        """Initialize with a RingDataReader.

        Args:
            reader: RingDataReader instance with loaded data
        """
        self._reader = reader

    @property
    def average_rmssd(self) -> float:
        """Average RMSSD in milliseconds."""
        return self._reader.hrv.average_rmssd

    @property
    def min_rmssd(self) -> float:
        """Minimum RMSSD in milliseconds."""
        return self._reader.hrv.min_rmssd

    @property
    def max_rmssd(self) -> float:
        """Maximum RMSSD in milliseconds."""
        return self._reader.hrv.max_rmssd

    @property
    def samples_5min(self) -> List[int]:
        """5-minute RMSSD samples from ring."""
        return self._reader.hrv.average_rmssd_5min

    @property
    def sample_count(self) -> int:
        """Number of HRV samples."""
        return self._reader.hrv.sample_count

    @property
    def timestamps(self) -> List[int]:
        """Timestamps for each 5-minute sample."""
        return self._reader.hrv.timestamps

    def by_sleep_stage(self) -> Dict[str, float]:
        """Calculate average HRV per sleep stage.

        Uses ML-classified sleep stages from SleepAnalyzer for proper REM detection.
        HRV samples are at 5-minute intervals, sleep stages at 30-second epochs.
        We downsample stages to 5-min windows (most common stage per window).

        Returns:
            Dict with keys 'deep', 'light', 'rem', 'awake' and average RMSSD values
        """
        from oura.analysis.sleep import SleepAnalyzer

        hrv_samples = self.samples_5min
        if not hrv_samples:
            return {'deep': 0.0, 'light': 0.0, 'rem': 0.0, 'awake': 0.0}

        # Get ML-classified stages (30-sec epochs)
        # Standard encoding: 0=Awake, 1=Light, 2=Deep, 3=REM
        sleep_analyzer = SleepAnalyzer(self._reader)
        stages_30sec = sleep_analyzer.stages

        if len(stages_30sec) == 0:
            return {'deep': 0.0, 'light': 0.0, 'rem': 0.0, 'awake': 0.0}

        # Downsample 30-sec epochs to 5-min windows (10 epochs per window)
        # Take most common stage in each 5-min window
        epochs_per_5min = 10  # 5 min / 30 sec = 10
        stages_5min = []

        for i in range(0, len(stages_30sec), epochs_per_5min):
            window = stages_30sec[i:i + epochs_per_5min]
            if len(window) > 0:
                # Most common stage in window
                counts = np.bincount(window.astype(int), minlength=4)
                most_common = int(np.argmax(counts))
                stages_5min.append(most_common)

        # Collect HRV samples by stage
        # Standard encoding: 0=Awake, 1=Light, 2=Deep, 3=REM
        stage_hrvs = {0: [], 1: [], 2: [], 3: []}

        n = min(len(hrv_samples), len(stages_5min))
        for i in range(n):
            stage = stages_5min[i]
            if stage in stage_hrvs:
                stage_hrvs[stage].append(hrv_samples[i])

        # Calculate averages with correct stage names
        # Standard: 0=Awake, 1=Light, 2=Deep, 3=REM
        return {
            'awake': float(np.mean(stage_hrvs[0])) if stage_hrvs[0] else 0.0,
            'light': float(np.mean(stage_hrvs[1])) if stage_hrvs[1] else 0.0,
            'deep': float(np.mean(stage_hrvs[2])) if stage_hrvs[2] else 0.0,
            'rem': float(np.mean(stage_hrvs[3])) if stage_hrvs[3] else 0.0,
        }

    def balance(self, baseline: float) -> float:
        """Calculate HRV balance relative to baseline.

        Args:
            baseline: Personal baseline RMSSD in ms (e.g., 28-day average)

        Returns:
            Percentage deviation from baseline (positive = above, negative = below)
        """
        if baseline <= 0:
            return 0.0
        return ((self.average_rmssd - baseline) / baseline) * 100

    def trend(self) -> List[Dict[str, Any]]:
        """Get HRV trend over time.

        Returns:
            List of {timestamp, rmssd, hr} dictionaries
        """
        result = []
        hrv_data = self._reader.hrv

        for i in range(hrv_data.sample_count):
            entry = {
                'rmssd': hrv_data.average_rmssd_5min[i] if i < len(hrv_data.average_rmssd_5min) else 0,
                'hr': hrv_data.average_hr_5min[i] if i < len(hrv_data.average_hr_5min) else 0,
            }
            if i < len(hrv_data.timestamps):
                entry['timestamp'] = hrv_data.timestamps[i]
            result.append(entry)

        return result

    def variability_index(self) -> float:
        """Calculate HRV variability index (coefficient of variation).

        Higher values indicate more variable HRV throughout the night.

        Returns:
            CV as percentage (std / mean * 100)
        """
        samples = self.samples_5min
        if len(samples) < 2:
            return 0.0

        arr = np.array(samples)
        mean = np.mean(arr)
        if mean <= 0:
            return 0.0

        return (np.std(arr) / mean) * 100

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        by_stage = self.by_sleep_stage()
        return {
            "average_rmssd": round(self.average_rmssd, 1),
            "min_rmssd": round(self.min_rmssd, 1),
            "max_rmssd": round(self.max_rmssd, 1),
            "sample_count": self.sample_count,
            "variability_index": round(self.variability_index(), 1),
            "by_sleep_stage": {k: round(v, 1) for k, v in by_stage.items()},
        }
