#!/usr/bin/env python3
"""Sleep Stage Classification for Oura Ring Data.

This module provides sleep stage classification using the raw sensor data
captured from the Oura Ring. It implements both rule-based heuristics
and provides an interface for ML-based classification.

Sleep Stages (matching Oura's schema):
    0 = DEEP_SLEEP   - Slow-wave sleep, lowest HR, minimal motion
    1 = LIGHT_SLEEP  - Transitional, moderate HR, some motion
    2 = REM_SLEEP    - Dreaming, variable HR, eye movements, low muscle tone
    3 = AWAKE        - Conscious, higher HR, motion

Based on analysis of Oura app's NssaPyTorchModel which uses:
    - acmValues (activity/motion counts)
    - ibiValues (inter-beat intervals from PPG)
    - temperatureValues (skin temperature)
    - demographics (age, sex)
    - bedtime (sleep period boundaries)

Research references:
    - Beattie et al. (2017) - Estimation of sleep stages using cardiac signals
    - Fonseca et al. (2015) - Sleep stage classification with ECG and accelerometer
    - de Zambotti et al. (2019) - Wearable sleep technology in clinical research
"""

from dataclasses import dataclass
from enum import IntEnum
from typing import List, Optional, Tuple, Iterator
import numpy as np
from collections import deque


class SleepStage(IntEnum):
    """Sleep stage classification matching Oura's SleepPhase_OSSAv1 enum."""
    DEEP_SLEEP = 0
    LIGHT_SLEEP = 1
    REM_SLEEP = 2
    AWAKE = 3
    UNKNOWN = -1


@dataclass
class SleepEpoch:
    """A single sleep epoch (typically 30 seconds)."""
    timestamp: int          # Unix timestamp or ringtime
    stage: SleepStage       # Classified sleep stage
    confidence: float       # Classification confidence (0-1)
    hr_bpm: float           # Heart rate in BPM
    hrv_ms: float           # HRV (RMSSD) in milliseconds
    motion: float           # Motion/activity level (0-1 normalized)
    temperature: float      # Skin temperature deviation from baseline


@dataclass
class SleepStageResult:
    """Complete sleep staging result for a sleep period."""
    epochs: List[SleepEpoch]
    deep_minutes: float
    light_minutes: float
    rem_minutes: float
    awake_minutes: float
    sleep_efficiency: float  # (total sleep / time in bed) * 100

    @property
    def total_sleep_minutes(self) -> float:
        return self.deep_minutes + self.light_minutes + self.rem_minutes

    @property
    def stages_30sec(self) -> List[int]:
        """Return stages as list of integers (Oura format)."""
        return [e.stage.value for e in self.epochs]

    def summary(self) -> str:
        """Human-readable summary."""
        lines = [
            "Sleep Stage Summary",
            "=" * 40,
            f"Deep Sleep:    {self.deep_minutes:5.1f} min ({self.deep_minutes/60:.1f} hrs)",
            f"Light Sleep:   {self.light_minutes:5.1f} min ({self.light_minutes/60:.1f} hrs)",
            f"REM Sleep:     {self.rem_minutes:5.1f} min ({self.rem_minutes/60:.1f} hrs)",
            f"Awake:         {self.awake_minutes:5.1f} min",
            "-" * 40,
            f"Total Sleep:   {self.total_sleep_minutes:5.1f} min ({self.total_sleep_minutes/60:.1f} hrs)",
            f"Efficiency:    {self.sleep_efficiency:.1f}%",
        ]
        return "\n".join(lines)


class SleepStageClassifier:
    """Base class for sleep stage classifiers."""

    def classify(self,
                 hr_values: List[float],
                 hrv_values: List[float],
                 motion_values: List[float],
                 temperature_values: Optional[List[float]] = None,
                 timestamps: Optional[List[int]] = None,
                 epoch_seconds: int = 30) -> SleepStageResult:
        """
        Classify sleep stages from sensor data.

        Args:
            hr_values: Heart rate in BPM for each epoch
            hrv_values: HRV (RMSSD) in ms for each epoch
            motion_values: Motion/activity level for each epoch
            temperature_values: Optional temperature data
            timestamps: Optional timestamps for each epoch
            epoch_seconds: Duration of each epoch (default 30s)

        Returns:
            SleepStageResult with classified epochs and statistics
        """
        raise NotImplementedError


class RuleBasedClassifier(SleepStageClassifier):
    """
    Rule-based sleep stage classifier using physiological heuristics.

    Based on established sleep research showing:
    - Deep sleep: lowest HR, lowest HRV, minimal motion
    - Light sleep: moderate HR, moderate HRV, some motion
    - REM sleep: variable HR (higher HRV), low motion, temp drops
    - Awake: highest HR, motion present

    Thresholds are adaptive based on the individual's baseline.
    """

    def __init__(self,
                 motion_awake_threshold: float = 0.3,
                 hr_deep_percentile: float = 20,
                 hr_rem_variability: float = 0.15):
        """
        Initialize classifier with tunable parameters.

        Args:
            motion_awake_threshold: Motion level above which = awake (0-1)
            hr_deep_percentile: HR percentile below which = deep sleep candidate
            hr_rem_variability: HR variability threshold for REM detection
        """
        self.motion_awake_threshold = motion_awake_threshold
        self.hr_deep_percentile = hr_deep_percentile
        self.hr_rem_variability = hr_rem_variability

    def classify(self,
                 hr_values: List[float],
                 hrv_values: List[float],
                 motion_values: List[float],
                 temperature_values: Optional[List[float]] = None,
                 timestamps: Optional[List[int]] = None,
                 epoch_seconds: int = 30) -> SleepStageResult:

        n_epochs = len(hr_values)
        if n_epochs == 0:
            return SleepStageResult([], 0, 0, 0, 0, 0)

        # Ensure all arrays same length
        hrv_values = self._pad_or_trim(hrv_values, n_epochs, default=0)
        motion_values = self._pad_or_trim(motion_values, n_epochs, default=0)

        if temperature_values:
            temperature_values = self._pad_or_trim(temperature_values, n_epochs, default=0)
        else:
            temperature_values = [0.0] * n_epochs

        if timestamps is None:
            timestamps = list(range(n_epochs))

        # Convert to numpy for easier computation
        hr = np.array(hr_values, dtype=float)
        hrv = np.array(hrv_values, dtype=float)
        motion = np.array(motion_values, dtype=float)
        temp = np.array(temperature_values, dtype=float)

        # Normalize motion to 0-1
        if motion.max() > 1:
            motion = motion / motion.max() if motion.max() > 0 else motion

        # Calculate adaptive thresholds from this person's data
        hr_baseline = np.median(hr[hr > 0]) if np.any(hr > 0) else 60
        hr_deep_threshold = np.percentile(hr[hr > 0], self.hr_deep_percentile) if np.any(hr > 0) else hr_baseline * 0.85

        # Calculate HR variability (rolling std)
        hr_variability = self._rolling_std(hr, window=5)

        # Classify each epoch
        epochs = []
        for i in range(n_epochs):
            stage, confidence = self._classify_epoch(
                hr[i], hrv[i], motion[i], temp[i],
                hr_baseline, hr_deep_threshold, hr_variability[i]
            )

            epochs.append(SleepEpoch(
                timestamp=timestamps[i],
                stage=stage,
                confidence=confidence,
                hr_bpm=hr[i],
                hrv_ms=hrv[i],
                motion=motion[i],
                temperature=temp[i]
            ))

        # Apply temporal smoothing (sleep stages don't flip every 30s)
        epochs = self._smooth_stages(epochs)

        # Calculate statistics
        epoch_minutes = epoch_seconds / 60
        stage_counts = {s: 0 for s in SleepStage}
        for e in epochs:
            stage_counts[e.stage] += 1

        total_epochs = len(epochs)
        sleep_epochs = total_epochs - stage_counts[SleepStage.AWAKE]
        efficiency = (sleep_epochs / total_epochs * 100) if total_epochs > 0 else 0

        return SleepStageResult(
            epochs=epochs,
            deep_minutes=stage_counts[SleepStage.DEEP_SLEEP] * epoch_minutes,
            light_minutes=stage_counts[SleepStage.LIGHT_SLEEP] * epoch_minutes,
            rem_minutes=stage_counts[SleepStage.REM_SLEEP] * epoch_minutes,
            awake_minutes=stage_counts[SleepStage.AWAKE] * epoch_minutes,
            sleep_efficiency=efficiency
        )

    def _classify_epoch(self, hr: float, hrv: float, motion: float, temp: float,
                        hr_baseline: float, hr_deep_threshold: float,
                        hr_var: float) -> Tuple[SleepStage, float]:
        """Classify a single epoch."""

        # Invalid data
        if hr <= 0:
            return SleepStage.UNKNOWN, 0.0

        # High motion = awake
        if motion > self.motion_awake_threshold:
            confidence = min(1.0, motion / self.motion_awake_threshold * 0.7 + 0.3)
            return SleepStage.AWAKE, confidence

        # Very low motion with low HR = likely deep sleep
        if motion < 0.05 and hr < hr_deep_threshold:
            confidence = 0.7 + (1 - hr/hr_baseline) * 0.3
            return SleepStage.DEEP_SLEEP, min(1.0, confidence)

        # Low motion but variable HR = likely REM
        # REM characterized by irregular heart rate
        if motion < 0.1 and hr_var > self.hr_rem_variability * hr_baseline:
            confidence = 0.6 + min(0.4, hr_var / hr_baseline)
            return SleepStage.REM_SLEEP, confidence

        # Default to light sleep
        # This catches transitional periods
        confidence = 0.5 + (1 - motion) * 0.3
        return SleepStage.LIGHT_SLEEP, confidence

    def _smooth_stages(self, epochs: List[SleepEpoch],
                       min_duration: int = 3) -> List[SleepEpoch]:
        """
        Smooth stage transitions - real sleep stages last multiple epochs.

        Args:
            epochs: List of classified epochs
            min_duration: Minimum epochs for a stage to be valid
        """
        if len(epochs) < min_duration:
            return epochs

        # Use median filter to smooth short transitions
        stages = [e.stage for e in epochs]
        smoothed = []

        for i in range(len(stages)):
            # Get window around this epoch
            start = max(0, i - min_duration // 2)
            end = min(len(stages), i + min_duration // 2 + 1)
            window = stages[start:end]

            # Find most common stage in window
            from collections import Counter
            most_common = Counter(window).most_common(1)[0][0]
            smoothed.append(most_common)

        # Update epochs with smoothed stages
        for i, epoch in enumerate(epochs):
            if smoothed[i] != epoch.stage:
                # Reduce confidence when smoothing changed the stage
                epoch.stage = smoothed[i]
                epoch.confidence *= 0.8

        return epochs

    def _rolling_std(self, values: np.ndarray, window: int = 5) -> np.ndarray:
        """Calculate rolling standard deviation."""
        result = np.zeros_like(values)
        for i in range(len(values)):
            start = max(0, i - window // 2)
            end = min(len(values), i + window // 2 + 1)
            result[i] = np.std(values[start:end])
        return result

    def _pad_or_trim(self, values: List, target_len: int, default=0) -> List:
        """Ensure list is exactly target_len."""
        if len(values) >= target_len:
            return values[:target_len]
        return values + [default] * (target_len - len(values))


class SleepDataAdapter:
    """
    Adapts raw Oura ring data to the format expected by sleep classifiers.

    Maps from our protobuf fields to classifier inputs:
    - sleep_period_info.average_hr -> hr_values
    - sleep_period_info.rmssd_5min -> hrv_values
    - sleep_period_info.motion_count -> motion_values
    - sleep_temp_event -> temperature_values
    """

    @staticmethod
    def from_sleep_period_info(sleep_samples: List[dict]) -> dict:
        """
        Convert sleep_period_info samples to classifier input format.

        Args:
            sleep_samples: List of dicts with keys like:
                - average_hr, rmssd_5min, motion_count, etc.

        Returns:
            Dict with hr_values, hrv_values, motion_values, timestamps
        """
        hr_values = []
        hrv_values = []
        motion_values = []
        timestamps = []

        for sample in sleep_samples:
            # Extract HR (convert from 0.1 BPM units if needed)
            hr = sample.get('average_hr', 0)
            if hr > 200:  # Likely in 0.1 BPM units
                hr = hr / 10.0
            hr_values.append(hr)

            # Extract HRV (RMSSD in ms)
            hrv = sample.get('rmssd_5min', 0)
            hrv_values.append(hrv)

            # Extract motion
            motion = sample.get('motion_count', 0)
            # Normalize - typical range is 0-1000
            motion = min(1.0, motion / 100.0) if motion > 1 else motion
            motion_values.append(motion)

            # Timestamp
            ts = sample.get('timestamp', sample.get('ringtime', 0))
            timestamps.append(ts)

        return {
            'hr_values': hr_values,
            'hrv_values': hrv_values,
            'motion_values': motion_values,
            'timestamps': timestamps
        }

    @staticmethod
    def from_ring_data_reader(reader) -> dict:
        """
        Extract sleep data from RingDataReader object.

        Args:
            reader: RingDataReader instance from oura_ring_data.py
        """
        # Get sleep period info events
        hr_values = []
        hrv_values = []
        motion_values = []
        timestamps = []

        for event in reader.events:
            if event.event_type == 'sleep_period_info':
                data = event.data
                # These field names match our protobuf schema
                hr = getattr(data, 'average_hr', 0) or 0
                if hr > 200:
                    hr = hr / 10.0
                hr_values.append(hr)

                hrv = getattr(data, 'rmssd_5min', 0) or 0
                hrv_values.append(hrv)

                motion = getattr(data, 'motion_count', 0) or 0
                motion = min(1.0, motion / 100.0) if motion > 1 else motion
                motion_values.append(motion)

                ts = getattr(data, 'timestamp', 0) or event.ringtime or 0
                timestamps.append(ts)

        return {
            'hr_values': hr_values,
            'hrv_values': hrv_values,
            'motion_values': motion_values,
            'timestamps': timestamps
        }


def classify_sleep(hr_values: List[float],
                   hrv_values: List[float],
                   motion_values: List[float],
                   temperature_values: Optional[List[float]] = None,
                   timestamps: Optional[List[int]] = None,
                   epoch_seconds: int = 30,
                   classifier: Optional[SleepStageClassifier] = None) -> SleepStageResult:
    """
    Convenience function to classify sleep stages.

    Args:
        hr_values: Heart rate in BPM for each epoch
        hrv_values: HRV (RMSSD) in ms for each epoch
        motion_values: Motion/activity level for each epoch
        temperature_values: Optional temperature deviation data
        timestamps: Optional timestamps for each epoch
        epoch_seconds: Duration of each epoch (default 30s)
        classifier: Optional custom classifier (default: RuleBasedClassifier)

    Returns:
        SleepStageResult with classified stages and statistics
    """
    if classifier is None:
        classifier = RuleBasedClassifier()

    return classifier.classify(
        hr_values=hr_values,
        hrv_values=hrv_values,
        motion_values=motion_values,
        temperature_values=temperature_values,
        timestamps=timestamps,
        epoch_seconds=epoch_seconds
    )


# Example usage and testing
if __name__ == '__main__':
    # Generate sample data (simulating a night of sleep)
    import random
    random.seed(42)

    # 8 hours = 960 30-second epochs
    n_epochs = 960

    # Simulate sleep architecture:
    # First hour: falling asleep (light)
    # Hours 2-3: deep sleep
    # Hour 4: REM
    # Hours 5-6: light/deep cycle
    # Hour 7: REM
    # Hour 8: light, waking

    hr_values = []
    motion_values = []

    for i in range(n_epochs):
        hour = i / 120  # 120 epochs per hour

        if hour < 0.5:  # Falling asleep
            hr = 70 + random.gauss(0, 3)
            motion = 0.2 + random.random() * 0.3
        elif hour < 2.5:  # Deep sleep
            hr = 52 + random.gauss(0, 2)
            motion = random.random() * 0.05
        elif hour < 3.5:  # REM
            hr = 60 + random.gauss(0, 5)  # Variable HR
            motion = random.random() * 0.08
        elif hour < 5.5:  # Light/deep mix
            hr = 55 + random.gauss(0, 3)
            motion = random.random() * 0.1
        elif hour < 6.5:  # REM
            hr = 62 + random.gauss(0, 6)
            motion = random.random() * 0.08
        else:  # Waking up
            hr = 68 + random.gauss(0, 4)
            motion = 0.1 + random.random() * 0.2

        hr_values.append(max(40, hr))
        motion_values.append(min(1, max(0, motion)))

    # HRV inversely correlates with HR
    hrv_values = [max(10, 80 - hr + random.gauss(0, 5)) for hr in hr_values]

    # Classify
    classifier = RuleBasedClassifier()
    result = classifier.classify(
        hr_values=hr_values,
        hrv_values=hrv_values,
        motion_values=motion_values
    )

    print(result.summary())
    print()

    # Show stage distribution over time
    print("Sleep Architecture (hourly):")
    print("-" * 40)
    for hour in range(8):
        start = hour * 120
        end = min(start + 120, len(result.epochs))
        hour_epochs = result.epochs[start:end]

        counts = {s: 0 for s in SleepStage}
        for e in hour_epochs:
            counts[e.stage] += 1

        bar = ""
        for stage in [SleepStage.DEEP_SLEEP, SleepStage.LIGHT_SLEEP,
                      SleepStage.REM_SLEEP, SleepStage.AWAKE]:
            char = {SleepStage.DEEP_SLEEP: 'D', SleepStage.LIGHT_SLEEP: 'L',
                    SleepStage.REM_SLEEP: 'R', SleepStage.AWAKE: 'W'}[stage]
            bar += char * (counts[stage] // 6)  # Scale for display

        print(f"Hour {hour+1}: {bar}")
