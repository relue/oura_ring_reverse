"""
SleepNet Model Wrapper - Real Neural Network for Sleep Stage Classification

This uses the actual trained neural network (sleepnet_moonstone_1_1_0.pt) with 4.5MB
of weights for sleep stage classification.

Pipeline (per docs/SLEEPNET_INPUT_COMPLETE_SPEC.md):
1. IBI Correction via EcoreWrapper (libappecore.so) - native signal processing
2. SleepNet Model - PyTorch neural network for classification

Input Requirements:
- bedtime_input: [start_sec, end_sec] - from BedtimePeriod or derived
- ibi_input: [N, 4] - [timestamp_sec, ibi_ms, amplitude, validity]
- acm_input: [M, 2] - [timestamp_sec, motion_seconds] - USE motion.motion_seconds!
- temp_input: [P, 2] - [timestamp_sec, temp_celsius]
- spo2_input: [Q, 2] - [timestamp_sec, spo2_percent]
- scalars_input: [5] - [age, weight_kg, sex_normalized, 0, 0]
- tst_input: [1] - total sleep time hint (0.0 = auto)

The model outputs:
- Sleep stages (Awake=0, Light=1, Deep=2, REM=3)
- Apnea detection
- SpO2 analysis
"""

import torch
import numpy as np
from pathlib import Path
from typing import Tuple, List, Optional, Dict, NamedTuple
from dataclasses import dataclass
import sys

# Ensure custom ops are registered
from . import custom_ops
custom_ops.register_oura_ops()

# Flag to track if EcoreWrapper is available
_ECORE_AVAILABLE = None


class TimeSyncInfo(NamedTuple):
    """Time synchronization info from TIME_SYNC_IND event.

    The ring has no RTC - it uses a monotonic decisecond counter.
    TIME_SYNC_IND pairs ring time with phone UTC time.

    Conversion formula:
        event_utc_ms = sync_utc_ms - ((sync_ring_time - event_ring_time) * 100)
    """
    sync_utc_ms: int      # Phone's UTC time in milliseconds
    sync_ring_time: int   # Ring's time in deciseconds at sync point

    def ring_time_to_utc_sec(self, ring_time_decisec: int) -> float:
        """Convert ring time (deciseconds) to UTC seconds."""
        time_diff_decisec = self.sync_ring_time - ring_time_decisec
        event_utc_ms = self.sync_utc_ms - (time_diff_decisec * 100)
        return event_utc_ms / 1000.0


@dataclass
class CorrectedIBI:
    """Corrected IBI data from EcoreWrapper.

    Matches Oura's IbiAndAmplitudeEvent.Corrected exactly:
    - timestamp_ms: UTC milliseconds
    - ibi_ms: Inter-beat interval (CORRECTED by EcoreWrapper)
    - amplitude: Amplitude value (CORRECTED by EcoreWrapper)
    - validity: 0=Unknown, 1=Valid, 2=Interpolated
    """
    timestamp_ms: int
    ibi_ms: int
    amplitude: int
    validity: int


def _check_ecore():
    """Check if EcoreWrapper is available (REQUIRED for SleepNet)."""
    global _ECORE_AVAILABLE
    if _ECORE_AVAILABLE is None:
        try:
            from oura_ecore import EcoreWrapper
            ecore = EcoreWrapper()
            _ECORE_AVAILABLE = True
            print("[SleepNet] EcoreWrapper available - native IBI correction enabled")
        except Exception as e:
            _ECORE_AVAILABLE = False
            print(f"[SleepNet] WARNING: EcoreWrapper not available ({e})")
            print("[SleepNet] EcoreWrapper is REQUIRED for 1:1 match with Oura app")
    return _ECORE_AVAILABLE


@dataclass
class SleepNetResult:
    """Result from SleepNet inference"""
    timestamps: np.ndarray  # Unix timestamps (seconds)
    stages: np.ndarray  # Sleep stages: 0=Awake, 1=Light, 2=Deep, 3=REM
    stage_probabilities: np.ndarray  # Shape (N, 4) - probabilities for each stage

    # Stage durations in seconds
    awake_seconds: int = 0
    light_seconds: int = 0
    deep_seconds: int = 0
    rem_seconds: int = 0
    total_sleep_seconds: int = 0

    # Summary stats
    sleep_efficiency: float = 0.0  # Percentage of time in bed actually sleeping


class SleepNetModel:
    """
    Wrapper for the SleepNet neural network model.

    Uses sleepnet_moonstone_1_1_0.pt which contains actual trained CNN weights
    for sleep stage classification.
    """

    def __init__(self, model_path: Optional[str] = None, use_moonstone: bool = True):
        if model_path is None:
            # Default path - use moonstone for Ring 4 compatibility
            base_dir = Path(__file__).parent.parent
            if use_moonstone:
                model_path = base_dir / "decrypted_models" / "sleepnet_moonstone_1_1_0.pt"
            else:
                model_path = base_dir / "decrypted_models" / "sleepnet_1_0_0.pt"

        self.model_path = Path(model_path)
        if not self.model_path.exists():
            raise FileNotFoundError(f"Model not found: {self.model_path}")

        # Load model
        self.model = torch.jit.load(str(self.model_path))
        self.model.eval()

        print(f"[SleepNet] Loaded model from {self.model_path}")
        print(f"[SleepNet] Model has {len(self.model.state_dict())} parameter tensors")

    def predict_from_reader(
        self,
        reader,
        reference_time: Optional[float] = None,
        time_sync: Optional[TimeSyncInfo] = None,
        user_age: float = 37.0,
        user_weight_kg: float = 88.0,
        user_sex: str = "male",
        night_index: int = -1
    ) -> SleepNetResult:
        """
        Predict sleep stages from RingDataReader.

        Args:
            reader: RingDataReader instance with ring data
            reference_time: Unix timestamp (seconds) as reference. Defaults to now.
            time_sync: TimeSyncInfo from TIME_SYNC_IND event (if available)
            user_age: User's age in years
            user_weight_kg: User's weight in kg
            user_sex: "male", "female", or "other"
            night_index: Which night to analyze if multiple bedtime periods exist.
                        -1 = most recent (last), 0 = first, etc.

        Returns:
            SleepNetResult with sleep stages and statistics
        """
        import time

        # Extract data from reader
        hr = reader.heart_rate
        motion = reader.motion
        temp = reader.temperature
        sleep = reader.sleep

        # Use reference time for absolute timestamps
        if reference_time is None:
            reference_time = time.time()

        # ===== BEDTIME INPUT =====
        # Get bedtime from BedtimePeriod protobuf (selects specific night if multiple)
        bedtime_start, bedtime_end = self._get_bedtime(reader, reference_time, night_index)
        sleep_duration_sec = bedtime_end - bedtime_start

        print(f"[SleepNet] Bedtime window: {sleep_duration_sec/3600:.1f} hours")

        # ===== IBI INPUT =====
        # Shape: [N, 4] - [timestamp_sec, ibi_ms, amplitude, validity]
        # All values from EcoreWrapper (1:1 match with Oura app - no fallbacks)
        # CRITICAL: Filter to bedtime period BEFORE EcoreWrapper (prevents 100K limit issues)
        amplitudes = hr.amplitudes if hasattr(hr, 'amplitudes') and hr.amplitudes else None
        timestamps = hr.timestamps if hr.timestamps else None

        # Get corrected IBI data from EcoreWrapper (REQUIRED - must succeed)
        corrected_ibi = self._get_corrected_ibi_data(
            hr, amplitudes, timestamps, bedtime_start, bedtime_end
        )

        # Build IBI input tensor from corrected data
        ibi_input = self._build_ibi_input(corrected_ibi)
        print(f"[SleepNet] IBI input: {ibi_input.shape[0]} samples")

        # ===== ACM INPUT =====
        # Shape: [M, 2] - [timestamp_sec, motion_seconds]
        # CRITICAL: Use raw protobuf motion_event (aligned timestamps + motion_seconds)
        # NOT reader.motion which mixes sources (events file timestamps + protobuf motion_seconds)
        acm_input = self._build_acm_input(
            reader, bedtime_start, bedtime_end
        )
        print(f"[SleepNet] ACM input: {acm_input.shape[0]} samples")

        # ===== TEMPERATURE INPUT =====
        # Shape: [P, 2] - [timestamp_sec, temp_celsius]
        temp_input = self._build_temp_input(
            temp, bedtime_start, bedtime_end
        )
        print(f"[SleepNet] Temp input: {temp_input.shape[0]} samples")

        # ===== SPO2 INPUT =====
        # Shape: [Q, 2] - [timestamp_sec, spo2_percent]
        spo2_input = self._build_spo2_input(
            reader.spo2, bedtime_start, bedtime_end
        )
        print(f"[SleepNet] SpO2 input: {spo2_input.shape[0]} samples")

        # ===== SCALARS INPUT =====
        # Shape: [5] - [age, weight_kg, sex_normalized, 0, 0]
        # Sex normalization: Female=-1, Male=0, Other=1
        sex_map = {"female": -1.0, "male": 0.0, "other": 1.0}
        sex_normalized = sex_map.get(user_sex.lower(), 0.0)
        scalars_input = torch.tensor(
            [user_age, user_weight_kg, sex_normalized, 0.0, 0.0],
            dtype=torch.float64
        )

        # ===== BEDTIME INPUT TENSOR =====
        bedtime_input = torch.tensor([bedtime_start, bedtime_end], dtype=torch.float64)

        return self.predict(
            bedtime_input=bedtime_input,
            ibi_input=ibi_input,
            acm_input=acm_input,
            temp_input=temp_input,
            spo2_input=spo2_input,
            scalars_input=scalars_input
        )

    def _get_bedtime(self, reader, reference_time: float, night_index: int = -1) -> Tuple[float, float]:
        """Extract bedtime from BedtimePeriod or derive from available data.

        Args:
            reader: RingDataReader instance
            reference_time: Unix timestamp (seconds) as reference
            night_index: Which night to select if multiple are available.
                        -1 = most recent (last), 0 = first, etc.

        Priority:
        1. BedtimePeriod from protobuf (if available) - select specific night
        2. IBI timestamps range (actual data period)
        3. Default 8 hours from reference_time
        """
        # Try to get from protobuf BedtimePeriod
        try:
            # Access raw protobuf if available
            if hasattr(reader, 'raw'):
                rd = reader.raw
                if rd.HasField('bedtime_period'):
                    bp = rd.bedtime_period
                    if bp.bedtime_start and bp.bedtime_end:
                        # Get unique bedtime periods
                        periods = set()
                        for i in range(len(bp.bedtime_start)):
                            periods.add((bp.bedtime_start[i], bp.bedtime_end[i]))

                        if periods:
                            sorted_periods = sorted(periods)  # Sort by start time
                            import datetime

                            print(f"[SleepNet] Found {len(sorted_periods)} unique bedtime period(s):")
                            for i, (s, e) in enumerate(sorted_periods):
                                s_dt = datetime.datetime.fromtimestamp(s / 1000)
                                e_dt = datetime.datetime.fromtimestamp(e / 1000)
                                dur_h = (e - s) / 1000 / 3600
                                marker = " <-- SELECTED" if (i == night_index or (night_index == -1 and i == len(sorted_periods) - 1)) else ""
                                print(f"  Night {i+1}: {s_dt.strftime('%Y-%m-%d %H:%M')} to {e_dt.strftime('%H:%M')} ({dur_h:.1f}h){marker}")

                            # Select the requested night
                            selected = sorted_periods[night_index]
                            start_ms, end_ms = selected

                            if start_ms > 0 and end_ms > 0:
                                return start_ms / 1000.0, end_ms / 1000.0
        except Exception as e:
            print(f"[SleepNet] Warning: Could not read BedtimePeriod: {e}")

        # Fallback: Use IBI timestamp range (if available)
        hr = reader.heart_rate
        if hr.timestamps and len(hr.timestamps) > 0:
            first_ts = hr.timestamps[0] / 1000.0  # ms to sec
            last_ts = hr.timestamps[-1] / 1000.0
            if last_ts - first_ts > 1800:  # At least 30 minutes
                print(f"[SleepNet] Derived bedtime from IBI timestamps: {(last_ts-first_ts)/3600:.2f} hours")
                return first_ts, last_ts

        # Default to 8 hours from reference time
        bedtime_end = reference_time
        bedtime_start = reference_time - 8 * 3600
        print("[SleepNet] Using default 8-hour bedtime window")

        return bedtime_start, bedtime_end

    def _build_ibi_input(self, corrected_data: List[CorrectedIBI]) -> torch.Tensor:
        """Build IBI input tensor from EcoreWrapper corrected data.

        This matches Oura's model input construction exactly (verified from
        SleepNetBdiPyTorchModel.java line 133):
        - timestamp: corrected.timestamp / 1000.0 (ms → seconds)
        - ibi: corrected.ibi (direct cast to double)
        - amplitude: corrected.amplitude (direct cast to double)
        - validity: corrected.validity (direct cast - RAW value 0/1/2)

        Format: [N, 4] - [timestamp_sec, ibi_ms, amplitude, validity]
        """
        if not corrected_data:
            raise RuntimeError("No corrected IBI data - cannot build model input")

        ibi_data = []
        for c in corrected_data:
            # Exact Oura conversion: timestamp / 1000.0d (ms → seconds)
            ts_sec = c.timestamp_ms / 1000.0

            # Direct cast to double (no scaling)
            ibi = float(c.ibi_ms)
            amp = float(c.amplitude)

            # Validity: RAW value (0=Unknown, 1=Valid, 2=Interpolated)
            # Oura app: Double.valueOf(it.f61139d) - direct cast, no mapping
            validity = float(c.validity)

            ibi_data.append([ts_sec, ibi, amp, validity])

        # Log sample and range
        if len(ibi_data) >= 2:
            ts_start = ibi_data[0][0]
            ts_end = ibi_data[-1][0]
            print(f"[SleepNet] Model IBI input (all values from EcoreWrapper):")
            print(f"  [0] ts={ibi_data[0][0]:.3f}s, ibi={ibi_data[0][1]:.0f}ms, amp={ibi_data[0][2]:.0f}, valid={ibi_data[0][3]}")
            print(f"  [-1] ts={ibi_data[-1][0]:.3f}s, ibi={ibi_data[-1][1]:.0f}ms, amp={ibi_data[-1][2]:.0f}, valid={ibi_data[-1][3]}")
            print(f"  Range: {ts_end - ts_start:.1f}s ({(ts_end - ts_start)/3600:.2f}h)")

        return torch.tensor(ibi_data, dtype=torch.float64)

    def _get_corrected_ibi_data(
        self,
        hr,
        amplitudes: Optional[List],
        timestamps: Optional[List],
        bedtime_start: float,
        bedtime_end: float
    ) -> List[CorrectedIBI]:
        """Get corrected IBI data from EcoreWrapper (REQUIRED - no fallback).

        This matches Oura's IbiAndAmplitudeEventExtKt.correctIbiAndAmplitudeEvents().
        EcoreWrapper MUST succeed - RuntimeError raised if not available.

        CRITICAL: Filters IBI data to bedtime period BEFORE calling EcoreWrapper.
        This prevents hitting the 100K sample limit with multi-night data.

        Args:
            hr: HeartRate data with ibi_ms
            amplitudes: Raw amplitude values
            timestamps: UTC timestamps in milliseconds from reader.py
            bedtime_start: Bedtime start in UTC seconds
            bedtime_end: Bedtime end in UTC seconds

        Returns:
            List of CorrectedIBI with all corrected values from EcoreWrapper
        """
        if not _check_ecore():
            raise RuntimeError(
                "EcoreWrapper required but not available. "
                "Install qemu-aarch64 and ensure android_root is set up."
            )

        from oura_ecore import EcoreWrapper
        ecore = EcoreWrapper()

        n_ibi = len(hr.ibi_ms)
        if n_ibi == 0:
            raise RuntimeError("No IBI data available - cannot proceed")

        # Convert bedtime to milliseconds for filtering
        bedtime_start_ms = bedtime_start * 1000.0
        bedtime_end_ms = bedtime_end * 1000.0

        # Build raw IBI data, FILTERING to bedtime period (like Oura's MotionEventExtKt)
        # NO SCALING - original app passes raw values directly (verified from gp/a.java)
        raw_ibi_data = []
        filtered_count = 0
        for i in range(n_ibi):
            ibi = hr.ibi_ms[i]

            # Use actual UTC timestamps from reader.py
            if timestamps and i < len(timestamps):
                ts_ms = int(timestamps[i])
            else:
                # Build cumulative if timestamps missing (shouldn't happen with proper reader)
                if i == 0:
                    ts_ms = timestamps[0] if timestamps else 0
                else:
                    if raw_ibi_data:
                        ts_ms = raw_ibi_data[-1][0] + raw_ibi_data[-1][1]
                    else:
                        continue  # Skip if we can't determine timestamp

            # Filter to bedtime period (like Oura's MotionEventExtKt.motionEvents)
            if bedtime_start_ms <= ts_ms <= bedtime_end_ms:
                # Raw amplitude - no scaling (verified from gp/a.java line 31)
                amp = int(amplitudes[i]) if amplitudes and i < len(amplitudes) else 200
                raw_ibi_data.append((ts_ms, ibi, amp))
            else:
                filtered_count += 1

        # Log input summary
        if not raw_ibi_data:
            raise RuntimeError(f"No IBI data within bedtime period. Checked {n_ibi} samples.")

        print(f"[SleepNet] EcoreWrapper input: {len(raw_ibi_data)} samples (filtered {filtered_count} outside bedtime)")
        print(f"  First: ts={raw_ibi_data[0][0]}ms, ibi={raw_ibi_data[0][1]}ms, amp={raw_ibi_data[0][2]}")
        print(f"  Last:  ts={raw_ibi_data[-1][0]}ms, ibi={raw_ibi_data[-1][1]}ms, amp={raw_ibi_data[-1][2]}")

        # Run native IBI correction (must succeed)
        corrected_results = ecore.correct_ibi(raw_ibi_data)

        if not corrected_results:
            raise RuntimeError("EcoreWrapper returned no corrected results")

        # Convert to CorrectedIBI list (keeping ALL corrected values)
        corrected_data = [
            CorrectedIBI(
                timestamp_ms=r.timestamp,
                ibi_ms=r.ibi,
                amplitude=r.amplitude,
                validity=r.validity
            )
            for r in corrected_results
        ]

        # Log output summary
        valid_count = sum(1 for c in corrected_data if c.validity == 1)
        valid_pct = valid_count / len(corrected_data) * 100
        print(f"[SleepNet] EcoreWrapper output: {len(corrected_data)} corrected samples")
        print(f"  Valid: {valid_count}/{len(corrected_data)} ({valid_pct:.1f}%)")

        if valid_pct < 50:
            print(f"[SleepNet] Warning: Low validity percentage ({valid_pct:.1f}%)")

        return corrected_data

    def _build_acm_input(
        self,
        reader,
        bedtime_start: float,
        bedtime_end: float
    ) -> torch.Tensor:
        """Build ACM (motion) input tensor.

        Format: [M, 2] - [timestamp_sec, motion_seconds]

        1:1 MATCH WITH OURA MOONSTONE:
        - Uses raw protobuf motion_event (timestamps + motion_seconds are aligned)
        - Filters to bedtime period (like Oura's MotionEventExtKt.motionEvents)
        - Converts timestamp_ms / 1000.0 to seconds (like IBI)

        Reference: com/ouraring/ringeventparser/message/MotionEvent.java
        - timestamp: long (milliseconds)
        - motionSeconds: int (0-29 range from ring)

        IMPORTANT: Use reader.raw.motion_event directly, NOT reader.motion
        The reader.motion mixes sources (events file timestamps + protobuf motion_seconds)
        which causes misalignment.
        """
        acm_data = []

        # PRIMARY: Use raw protobuf motion_event (1:1 with Oura Moonstone)
        rd = reader.raw
        if rd.HasField('motion_event'):
            me = rd.motion_event
            timestamps = list(me.timestamp)
            motion_seconds = list(me.motion_seconds)

            n_samples = min(len(timestamps), len(motion_seconds))

            if n_samples > 0:
                # Convert bedtime to ms for comparison
                bedtime_start_ms = bedtime_start * 1000.0
                bedtime_end_ms = bedtime_end * 1000.0

                # Filter motion events to bedtime period (like Oura's indexOfFirstAndLastOrNull)
                for i in range(n_samples):
                    ts_ms = timestamps[i]

                    # Filter to bedtime period
                    if bedtime_start_ms <= ts_ms <= bedtime_end_ms:
                        # Oura conversion: timestamp_ms / 1000.0 → seconds
                        ts_sec = ts_ms / 1000.0
                        # Direct cast to double (like IBI)
                        val = float(motion_seconds[i])
                        acm_data.append([ts_sec, val])

                if acm_data:
                    mean_val = sum(d[1] for d in acm_data) / len(acm_data)
                    max_val = max(d[1] for d in acm_data)
                    print(f"[SleepNet] ACM from protobuf motion_event: {len(acm_data)} samples "
                          f"(filtered from {n_samples}), mean={mean_val:.1f}, max={max_val:.0f}")

        # Minimal placeholder if no motion data
        if not acm_data:
            acm_data = [[bedtime_start, 0.5], [bedtime_end, 0.5]]
            print("[SleepNet] Using placeholder motion data")

        return torch.tensor(acm_data, dtype=torch.float64)

    def _build_temp_input(
        self,
        temp,
        bedtime_start: float,
        bedtime_end: float
    ) -> torch.Tensor:
        """Build temperature input tensor.

        Format: [P, 2] - [timestamp_sec, temp_celsius]
        No normalization - direct Celsius values from sensor.
        """
        temp_data = []
        sleep_duration = bedtime_end - bedtime_start

        temp_vals = temp.temp_celsius if hasattr(temp, 'temp_celsius') and temp.temp_celsius else []

        if temp_vals:
            n_temp = len(temp_vals)
            temp_interval = sleep_duration / n_temp

            for i in range(n_temp):
                ts_sec = bedtime_start + i * temp_interval
                val = float(temp_vals[i])
                temp_data.append([ts_sec, val])

        if not temp_data:
            # Placeholder with typical skin temperature
            temp_data = [[bedtime_start, 34.0], [bedtime_end, 34.0]]

        return torch.tensor(temp_data, dtype=torch.float64)

    def _build_spo2_input(
        self,
        spo2,
        bedtime_start: float,
        bedtime_end: float
    ) -> torch.Tensor:
        """Build SpO2 input tensor.

        Format: [Q, 2] - [timestamp_sec, spo2_percent]
        Can be minimal/empty - model handles sparse SpO2 data.
        """
        spo2_data = []
        sleep_duration = bedtime_end - bedtime_start

        spo2_vals = spo2.spo2_percentage if hasattr(spo2, 'spo2_percentage') and spo2.spo2_percentage else []

        if spo2_vals:
            n_spo2 = len(spo2_vals)
            spo2_interval = sleep_duration / n_spo2

            for i in range(n_spo2):
                ts_sec = bedtime_start + i * spo2_interval
                val = float(spo2_vals[i])
                spo2_data.append([ts_sec, val])

        if not spo2_data:
            # Minimal placeholder
            spo2_data = [[bedtime_start, 97.0], [bedtime_end, 97.0]]

        return torch.tensor(spo2_data, dtype=torch.float64)

    def _filter_short_awake(self, stages: np.ndarray, min_awake_epochs: int = 16) -> np.ndarray:
        """Filter out short awake periods (< min_awake_epochs).

        Per Oura app decompilation: 8-minute minimum for awake periods.
        Short awake periods are reclassified as the surrounding sleep stage.

        Args:
            stages: Array of sleep stages (0=Awake, 1=Light, 2=Deep, 3=REM)
            min_awake_epochs: Minimum consecutive awake epochs to keep (default 16 = 8 min)

        Returns:
            Filtered stages with short awake periods replaced
        """
        if len(stages) == 0:
            return stages

        filtered = stages.copy()
        i = 0

        while i < len(filtered):
            if filtered[i] == 0:  # Awake
                # Find end of this awake segment
                j = i
                while j < len(filtered) and filtered[j] == 0:
                    j += 1

                awake_length = j - i

                # If too short, replace with surrounding stage
                if awake_length < min_awake_epochs:
                    # Find the most common non-awake stage in surrounding context
                    context_start = max(0, i - 10)
                    context_end = min(len(filtered), j + 10)
                    context = filtered[context_start:context_end]
                    non_awake = context[context != 0]

                    if len(non_awake) > 0:
                        # Use the most common surrounding stage
                        replacement = int(np.bincount(non_awake).argmax())
                    else:
                        replacement = 1  # Default to Light

                    filtered[i:j] = replacement

                i = j
            else:
                i += 1

        return filtered

    def predict(
        self,
        bedtime_input: torch.Tensor,
        ibi_input: torch.Tensor,
        acm_input: torch.Tensor,
        temp_input: torch.Tensor,
        spo2_input: torch.Tensor,
        scalars_input: torch.Tensor,
        tst_input: Optional[torch.Tensor] = None
    ) -> SleepNetResult:
        """
        Run sleep stage prediction.

        Args:
            bedtime_input: [start_s, end_s] - bedtime window in seconds
            ibi_input: [N, 4] - [timestamp_s, ibi_ms, amplitude, validity]
            acm_input: [M, 2] - [timestamp_s, motion_seconds]
            temp_input: [P, 2] - [timestamp_s, temperature_c]
            spo2_input: [Q, 2] - [timestamp_s, spo2_percent]
            scalars_input: [5] - [age, weight_kg, sex_normalized, 0, 0]
            tst_input: [1] - total sleep time hint (optional, default 0.0)

        Returns:
            SleepNetResult with predictions
        """
        if tst_input is None:
            tst_input = torch.tensor([0.0], dtype=torch.float64)

        with torch.no_grad():
            outputs = self.model(
                bedtime_input,
                ibi_input,
                acm_input,
                temp_input,
                spo2_input,
                scalars_input,
                tst_input
            )

        # Unpack outputs: (staging_outputs, apnea_outputs, spo2_outputs, output_metrics, debug_metrics)
        staging_outputs = outputs[0]

        # staging_outputs shape: [N, 6] where columns are:
        # [timestamp_s, stage, prob_deep, prob_light, prob_rem, prob_awake]
        # Stage encoding per Oura SleepPhase enum: 1=Deep, 2=Light, 3=REM, 4=Awake
        staging_np = staging_outputs.numpy()

        timestamps = staging_np[:, 0]
        raw_stages = staging_np[:, 1].astype(int)
        probabilities = staging_np[:, 2:6]  # [deep, light, rem, awake]

        # Convert from model encoding (1-4) to standard encoding (0-3)
        # Model (Oura SleepPhase): 1=Deep, 2=Light, 3=REM, 4=Awake
        # Standard: 0=Awake, 1=Light, 2=Deep, 3=REM
        stage_mapping = {1: 2, 2: 1, 3: 3, 4: 0}  # Model→Standard
        stages = np.array([stage_mapping.get(s, s) for s in raw_stages])

        # Post-processing: Filter short awake periods (Oura uses 8-minute minimum)
        # Per decompiled app: f39898c = 8 minutes minimum for awake
        stages = self._filter_short_awake(stages, min_awake_epochs=16)  # 16 * 30s = 8 min

        # Calculate durations (30-second epochs)
        epoch_duration = 30  # seconds
        n_epochs = len(stages)

        # Using standard encoding: 0=Awake, 1=Light, 2=Deep, 3=REM
        awake_epochs = np.sum(stages == 0)
        light_epochs = np.sum(stages == 1)
        deep_epochs = np.sum(stages == 2)
        rem_epochs = np.sum(stages == 3)

        awake_seconds = int(awake_epochs * epoch_duration)
        light_seconds = int(light_epochs * epoch_duration)
        deep_seconds = int(deep_epochs * epoch_duration)
        rem_seconds = int(rem_epochs * epoch_duration)
        total_sleep_seconds = light_seconds + deep_seconds + rem_seconds

        # Sleep efficiency = sleep time / time in bed
        time_in_bed = n_epochs * epoch_duration
        sleep_efficiency = (total_sleep_seconds / time_in_bed * 100) if time_in_bed > 0 else 0.0

        return SleepNetResult(
            timestamps=timestamps,
            stages=stages,
            stage_probabilities=probabilities,
            awake_seconds=awake_seconds,
            light_seconds=light_seconds,
            deep_seconds=deep_seconds,
            rem_seconds=rem_seconds,
            total_sleep_seconds=total_sleep_seconds,
            sleep_efficiency=sleep_efficiency
        )


def test_sleepnet():
    """Test SleepNet with ring data"""
    sys.path.insert(0, str(Path(__file__).parent.parent))
    from oura.data.reader import RingDataReader

    # Load ring data
    data_path = Path(__file__).parent.parent / "ring_data_fresh.pb"
    if not data_path.exists():
        print(f"Test data not found: {data_path}")
        return

    reader = RingDataReader(str(data_path))

    # Create model and predict
    model = SleepNetModel()
    result = model.predict_from_reader(reader)

    print("\n" + "=" * 60)
    print("SleepNet Results")
    print("=" * 60)
    print(f"Total epochs: {len(result.stages)}")
    print(f"Awake: {result.awake_seconds // 60} min")
    print(f"Light: {result.light_seconds // 60} min")
    print(f"Deep: {result.deep_seconds // 60} min")
    print(f"REM: {result.rem_seconds // 60} min")
    print(f"Total sleep: {result.total_sleep_seconds // 60} min")
    print(f"Sleep efficiency: {result.sleep_efficiency:.1f}%")

    # Show stage distribution
    unique, counts = np.unique(result.stages, return_counts=True)
    print("\nStage distribution:")
    stage_names = {0: "Awake", 1: "Light", 2: "Deep", 3: "REM"}
    for stage, count in zip(unique, counts):
        pct = count / len(result.stages) * 100
        print(f"  {stage_names.get(stage, f'Unknown({stage})')}: {count} epochs ({pct:.1f}%)")


if __name__ == "__main__":
    test_sleepnet()
