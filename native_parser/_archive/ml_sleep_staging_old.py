"""
Sleep Staging Model Wrapper

Provides a high-level interface for sleep stage classification using
Oura's sleepstaging model.

Usage:
    from ml_inference.sleep_staging import SleepStagingModel
    from oura_ring_data import RingDataReader

    reader = RingDataReader("ring_data.pb")
    model = SleepStagingModel()
    result = model.predict(reader)

    print(f"Sleep stages: {result.stages}")
    print(f"Deep sleep: {result.deep_sleep_percent:.1f}%")
"""

from dataclasses import dataclass
from typing import List, Optional, Tuple, Dict, Any
from enum import IntEnum
from pathlib import Path

import torch
import numpy as np

from .model_loader import ModelLoader, DEFAULT_MODELS_DIR


class SleepStage(IntEnum):
    """Sleep stage classification values."""
    AWAKE = 0
    LIGHT = 1
    DEEP = 2
    REM = 3
    UNKNOWN = 4


@dataclass
class SleepStagingResult:
    """Result from sleep staging model."""
    # Timestamps for each stage (milliseconds)
    timestamps_ms: List[int]

    # Sleep stage for each epoch (0=awake, 1=light, 2=deep, 3=REM)
    stages: List[int]

    # Combined features from the model
    features: Optional[np.ndarray] = None

    # Debug metrics from the model
    debug_values: Optional[np.ndarray] = None

    @property
    def stage_names(self) -> List[str]:
        """Get stage names for each epoch."""
        names = {0: "Awake", 1: "Light", 2: "Deep", 3: "REM", 4: "Unknown"}
        return [names.get(s, "Unknown") for s in self.stages]

    @property
    def total_epochs(self) -> int:
        """Total number of epochs."""
        return len(self.stages)

    @property
    def awake_epochs(self) -> int:
        """Number of awake epochs."""
        return sum(1 for s in self.stages if s == SleepStage.AWAKE)

    @property
    def light_epochs(self) -> int:
        """Number of light sleep epochs."""
        return sum(1 for s in self.stages if s == SleepStage.LIGHT)

    @property
    def deep_epochs(self) -> int:
        """Number of deep sleep epochs."""
        return sum(1 for s in self.stages if s == SleepStage.DEEP)

    @property
    def rem_epochs(self) -> int:
        """Number of REM sleep epochs."""
        return sum(1 for s in self.stages if s == SleepStage.REM)

    @property
    def sleep_epochs(self) -> int:
        """Number of sleep epochs (non-awake)."""
        return self.total_epochs - self.awake_epochs

    @property
    def awake_percent(self) -> float:
        """Percentage of time awake."""
        return 100 * self.awake_epochs / self.total_epochs if self.total_epochs > 0 else 0

    @property
    def light_sleep_percent(self) -> float:
        """Percentage of sleep time in light sleep."""
        sleep = self.sleep_epochs
        return 100 * self.light_epochs / sleep if sleep > 0 else 0

    @property
    def deep_sleep_percent(self) -> float:
        """Percentage of sleep time in deep sleep."""
        sleep = self.sleep_epochs
        return 100 * self.deep_epochs / sleep if sleep > 0 else 0

    @property
    def rem_sleep_percent(self) -> float:
        """Percentage of sleep time in REM."""
        sleep = self.sleep_epochs
        return 100 * self.rem_epochs / sleep if sleep > 0 else 0

    @property
    def total_sleep_minutes(self) -> float:
        """Total sleep time in minutes (assuming 5-min epochs)."""
        return self.sleep_epochs * 5

    @property
    def deep_sleep_minutes(self) -> float:
        """Deep sleep time in minutes."""
        return self.deep_epochs * 5

    @property
    def rem_sleep_minutes(self) -> float:
        """REM sleep time in minutes."""
        return self.rem_epochs * 5

    def to_hypnogram(self) -> List[Tuple[int, str]]:
        """
        Get hypnogram data for charting.

        Returns list of (timestamp_ms, stage_name) tuples.
        """
        return list(zip(self.timestamps_ms, self.stage_names))

    def summary(self) -> str:
        """Get a text summary of sleep stages."""
        lines = [
            f"Sleep Staging Results ({self.total_epochs} epochs, ~{self.total_epochs * 5} min)",
            f"  Total Sleep: {self.total_sleep_minutes:.0f} min ({100 - self.awake_percent:.0f}%)",
            f"  - Light: {self.light_epochs * 5:.0f} min ({self.light_sleep_percent:.1f}%)",
            f"  - Deep:  {self.deep_sleep_minutes:.0f} min ({self.deep_sleep_percent:.1f}%)",
            f"  - REM:   {self.rem_sleep_minutes:.0f} min ({self.rem_sleep_percent:.1f}%)",
            f"  Awake: {self.awake_epochs * 5:.0f} min ({self.awake_percent:.1f}%)",
        ]
        return "\n".join(lines)


class SleepStagingModel:
    """
    High-level wrapper for sleep staging inference.

    Usage:
        model = SleepStagingModel()

        # From RingDataReader
        result = model.predict(reader)

        # Or with raw data
        result = model.predict_raw(
            acm_values, acm_timestamps,
            ibi_values, ibi_timestamps,
            temp_values, temp_timestamps,
            demographics, bedtime
        )
    """

    # Default demographics if not provided
    DEFAULT_AGE = 35
    DEFAULT_WEIGHT_KG = 70
    DEFAULT_HEIGHT_CM = 170

    def __init__(
        self,
        model_name: str = "sleepstaging_2_6_0",
        models_dir: Optional[Path] = None,
        device: str = "cpu"
    ):
        """
        Initialize the sleep staging model.

        Args:
            model_name: Name of the model to load
            models_dir: Directory containing model files
            device: PyTorch device ("cpu" or "cuda")
        """
        self.device = device
        self.loader = ModelLoader(models_dir=models_dir, device=device)
        self.model = self.loader.load(model_name)
        self.model.eval()

    def predict(
        self,
        reader: Any,
        demographics: Optional[Dict[str, float]] = None
    ) -> SleepStagingResult:
        """
        Predict sleep stages from RingDataReader.

        Args:
            reader: RingDataReader instance with parsed ring data
            demographics: Optional dict with 'age', 'weight_kg', 'height_cm'

        Returns:
            SleepStagingResult with stages and metrics
        """
        # Extract data from reader
        hr = reader.heart_rate
        sleep = reader.sleep
        temp = reader.temperature
        motion = reader.motion

        # The ring data has relative timestamps - we need to convert to absolute epoch ms
        # Use a reference time (current time or a simulated bedtime)
        import time
        # Use a reference time of "last night at 11pm" for realistic sleep data
        now_ms = int(time.time() * 1000)
        # Set reference to approximately 8 hours ago (middle of sleep)
        reference_ms = now_ms - (8 * 60 * 60 * 1000)

        def to_absolute(relative_ts_list: List[int]) -> List[int]:
            """Convert relative timestamps to absolute epoch ms."""
            return [reference_ms + ts for ts in relative_ts_list]

        def generate_timestamps(n_samples: int, interval_sec: int = 30) -> List[int]:
            """Generate evenly spaced timestamps when originals are missing."""
            interval_ms = interval_sec * 1000
            return [reference_ms + (i * interval_ms) for i in range(n_samples)]

        # Check if sleep timestamps are valid (not all zeros)
        sleep_timestamps_valid = sleep.timestamps and len(set(sleep.timestamps)) > 1

        # Get IBI data - convert timestamps to absolute
        ibi_timestamps = to_absolute(hr.timestamps) if hr.timestamps else []
        ibi_values = hr.ibi_ms if hr.ibi_ms else []

        # Get temperature data - convert timestamps to absolute
        temp_timestamps = to_absolute(temp.timestamps) if temp.timestamps else []
        temp_values = temp.temp_celsius if temp.temp_celsius else []

        # Get motion data (ACM) - use motion timestamps and any available values
        # Model expects 6 columns: [x, y, z, magnitude, orientation, motion_seconds]
        # Check if motion timestamps are valid
        motion_timestamps_valid = motion.timestamps and len(set(motion.timestamps)) > 1

        if motion_timestamps_valid:
            acm_timestamps = to_absolute(motion.timestamps)
            n_samples = len(motion.timestamps)

            # Get xyz data or use defaults
            x = motion.average_x if motion.average_x else [0.0] * n_samples
            y = motion.average_y if motion.average_y else [0.0] * n_samples
            z = motion.average_z if motion.average_z else [1.0] * n_samples

            # Calculate magnitude
            magnitudes = [np.sqrt(xi**2 + yi**2 + zi**2) for xi, yi, zi in zip(x, y, z)]

            # Get orientation and motion_seconds or use defaults
            orientations = motion.orientation if motion.orientation else [0] * n_samples
            motion_secs = motion.motion_seconds if motion.motion_seconds else [0] * n_samples

            # Build 6-column array
            acm_values = [
                [xi, yi, zi, mag, orient, mot_sec]
                for xi, yi, zi, mag, orient, mot_sec
                in zip(x, y, z, magnitudes, orientations, motion_secs)
            ]
        elif motion.sample_count > 0:
            # Motion data exists but timestamps are all zeros - generate timestamps
            n_samples = motion.sample_count
            acm_timestamps = generate_timestamps(n_samples, interval_sec=30)

            # Get xyz data or use defaults
            x = motion.average_x if motion.average_x else [0.0] * n_samples
            y = motion.average_y if motion.average_y else [0.0] * n_samples
            z = motion.average_z if motion.average_z else [1.0] * n_samples

            magnitudes = [np.sqrt(xi**2 + yi**2 + zi**2) for xi, yi, zi in zip(x, y, z)]
            orientations = motion.orientation if motion.orientation else [0] * n_samples
            motion_secs = motion.motion_seconds if motion.motion_seconds else [0] * n_samples

            acm_values = [
                [xi, yi, zi, mag, orient, mot_sec]
                for xi, yi, zi, mag, orient, mot_sec
                in zip(x, y, z, magnitudes, orientations, motion_secs)
            ]
        elif sleep.total_samples > 0:
            # Fallback: generate timestamps based on sleep samples
            n_samples = sleep.total_samples
            acm_timestamps = generate_timestamps(n_samples, interval_sec=30)
            # [x, y, z, magnitude, orientation, motion_seconds]
            acm_values = [[0.0, 0.0, 1.0, 1.0, 0, 0] for _ in range(n_samples)]
        else:
            raise ValueError("No motion or sleep data available")

        # Get bedtime from sleep data
        if sleep_timestamps_valid:
            abs_sleep_ts = to_absolute(sleep.timestamps)
            bedtime_start = min(abs_sleep_ts)
            bedtime_end = max(abs_sleep_ts)
        elif sleep.total_samples > 0:
            # Generate bedtime based on number of sleep samples (assume 30-sec epochs)
            n_sleep_samples = sleep.total_samples
            duration_ms = n_sleep_samples * 30 * 1000  # 30 sec per epoch
            bedtime_start = reference_ms
            bedtime_end = reference_ms + duration_ms
        else:
            # Estimate from other data (already absolute)
            all_ts = ibi_timestamps + temp_timestamps + acm_timestamps
            bedtime_start = min(all_ts) if all_ts else reference_ms
            bedtime_end = max(all_ts) if all_ts else reference_ms

        # Demographics
        if demographics is None:
            demographics = {}
        age = demographics.get('age', self.DEFAULT_AGE)
        weight = demographics.get('weight_kg', self.DEFAULT_WEIGHT_KG)
        height = demographics.get('height_cm', self.DEFAULT_HEIGHT_CM)

        return self.predict_raw(
            acm_values=acm_values,
            acm_timestamps=acm_timestamps,
            ibi_values=ibi_values,
            ibi_timestamps=ibi_timestamps,
            temp_values=temp_values,
            temp_timestamps=temp_timestamps,
            age=age,
            weight_kg=weight,
            height_cm=height,
            bedtime_start_ms=bedtime_start,
            bedtime_end_ms=bedtime_end
        )

    def predict_raw(
        self,
        acm_values: List,
        acm_timestamps: List[int],
        ibi_values: List[int],
        ibi_timestamps: List[int],
        temp_values: List[float],
        temp_timestamps: List[int],
        age: float = 35,
        weight_kg: float = 70,
        height_cm: float = 170,
        bedtime_start_ms: int = 0,
        bedtime_end_ms: int = 0,
        rerun_if_long_wake: bool = True,
        check_for_false_nap: bool = True
    ) -> SleepStagingResult:
        """
        Predict sleep stages from raw sensor data.

        Args:
            acm_values: Accelerometer values, list of [x, y, z] or magnitudes
            acm_timestamps: Accelerometer timestamps in ms
            ibi_values: Inter-beat intervals in ms
            ibi_timestamps: IBI timestamps in ms
            temp_values: Temperature values
            temp_timestamps: Temperature timestamps in ms
            age: User age in years
            weight_kg: User weight in kg
            height_cm: User height in cm
            bedtime_start_ms: Sleep start timestamp in ms
            bedtime_end_ms: Sleep end timestamp in ms
            rerun_if_long_wake: Re-analyze if long wake detected
            check_for_false_nap: Filter out false nap detections

        Returns:
            SleepStagingResult with stages and metrics
        """
        # Prepare tensors
        # ACM values must have 6 columns: [x, y, z, magnitude, orientation, motion_seconds]
        acm_arr = np.array(acm_values, dtype=np.float32)
        if acm_arr.ndim == 1:
            acm_arr = acm_arr.reshape(-1, 1)

        # Ensure we have 6 columns
        if acm_arr.shape[1] == 3:
            # We have [x, y, z] - compute magnitude and add placeholders
            magnitude = np.sqrt(np.sum(acm_arr**2, axis=1, keepdims=True))
            # Add orientation (0) and motion_seconds (0) as placeholders
            acm_arr = np.hstack([
                acm_arr,  # x, y, z
                magnitude,  # magnitude
                np.zeros((acm_arr.shape[0], 1), dtype=np.float32),  # orientation
                np.zeros((acm_arr.shape[0], 1), dtype=np.float32),  # motion_seconds
            ])
        elif acm_arr.shape[1] < 6:
            # Pad with zeros to get 6 columns
            padding = np.zeros((acm_arr.shape[0], 6 - acm_arr.shape[1]), dtype=np.float32)
            acm_arr = np.hstack([acm_arr, padding])

        acm_tensor = torch.tensor(acm_arr, dtype=torch.float32)

        # ACM timestamps - must be int64
        acm_ts_tensor = torch.tensor(acm_timestamps, dtype=torch.int64)

        # IBI values - include validity flag
        # Format: [ibi_ms, amplitude, validity]
        ibi_arr = np.array(ibi_values, dtype=np.float32).reshape(-1, 1)
        # Add dummy amplitude and validity columns
        ibi_with_meta = np.hstack([
            ibi_arr,
            np.ones_like(ibi_arr) * 100,  # amplitude
            np.ones_like(ibi_arr)  # validity
        ])
        ibi_tensor = torch.tensor(ibi_with_meta, dtype=torch.float32)

        # IBI timestamps - must be int64
        ibi_ts_tensor = torch.tensor(ibi_timestamps, dtype=torch.int64)

        # Temperature - values float32, timestamps int64
        temp_tensor = torch.tensor(temp_values, dtype=torch.float32)
        temp_ts_tensor = torch.tensor(temp_timestamps, dtype=torch.int64)

        # Demographics [age, weight, height] or similar
        scalars_tensor = torch.tensor([age, weight_kg, height_cm], dtype=torch.float32)

        # Bedtime [start_ms, end_ms] - must be int64
        bedtime_tensor = torch.tensor([bedtime_start_ms, bedtime_end_ms], dtype=torch.int64)

        # Run model
        with torch.no_grad():
            try:
                outputs = self.model(
                    acm_tensor,
                    acm_ts_tensor,
                    ibi_tensor,
                    ibi_ts_tensor,
                    temp_tensor,
                    temp_ts_tensor,
                    scalars_tensor,
                    bedtime_tensor,
                    rerun_if_long_wake,
                    check_for_false_nap
                )

                # Parse outputs: (timestamp_ms, stages, features, debug_values)
                timestamps_ms = outputs[0].numpy().flatten().astype(int).tolist()
                stages = outputs[1].numpy().flatten().astype(int).tolist()
                features = outputs[2].numpy() if len(outputs) > 2 else None
                debug_values = outputs[3].numpy() if len(outputs) > 3 else None

                return SleepStagingResult(
                    timestamps_ms=timestamps_ms,
                    stages=stages,
                    features=features,
                    debug_values=debug_values
                )

            except Exception as e:
                # If model fails, return empty result
                print(f"Sleep staging model error: {e}")
                return SleepStagingResult(
                    timestamps_ms=[],
                    stages=[],
                    features=None,
                    debug_values=None
                )

    @staticmethod
    def aggregate_to_5min(stages_30sec: List[int]) -> List[int]:
        """
        Aggregate 30-second epochs to 5-minute epochs.

        Uses majority voting within each 5-minute window.

        Args:
            stages_30sec: Sleep stages at 30-second resolution

        Returns:
            Sleep stages at 5-minute resolution
        """
        epochs_per_5min = 10  # 10 x 30sec = 5min
        result = []

        for i in range(0, len(stages_30sec), epochs_per_5min):
            window = stages_30sec[i:i + epochs_per_5min]
            if window:
                # Majority vote
                from collections import Counter
                most_common = Counter(window).most_common(1)[0][0]
                result.append(most_common)

        return result
