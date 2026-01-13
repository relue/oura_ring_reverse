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


def _check_ecore():
    """Check if EcoreWrapper is available."""
    global _ECORE_AVAILABLE
    if _ECORE_AVAILABLE is None:
        try:
            from oura_ecore import EcoreWrapper
            ecore = EcoreWrapper()
            _ECORE_AVAILABLE = True
            print("[SleepNet] EcoreWrapper available - using native IBI correction")
        except Exception as e:
            _ECORE_AVAILABLE = False
            print(f"[SleepNet] EcoreWrapper not available ({e}) - using simple validity check")
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
        user_sex: str = "male"
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
        # Try to get from BedtimePeriod protobuf first, otherwise derive from epochs
        bedtime_start, bedtime_end = self._get_bedtime(reader, reference_time)
        sleep_duration_sec = bedtime_end - bedtime_start

        print(f"[SleepNet] Bedtime window: {sleep_duration_sec/3600:.1f} hours")

        # ===== IBI INPUT =====
        # Shape: [N, 4] - [timestamp_sec, ibi_ms, amplitude, validity]
        ibi_input = self._build_ibi_input(
            hr, bedtime_start, bedtime_end, time_sync
        )
        print(f"[SleepNet] IBI input: {ibi_input.shape[0]} samples")

        # ===== ACM INPUT =====
        # Shape: [M, 2] - [timestamp_sec, motion_seconds]
        # CRITICAL: Use motion.motion_seconds (0-30 range), NOT sleep.motion_count
        acm_input = self._build_acm_input(
            motion, sleep, bedtime_start, bedtime_end
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

    def _get_bedtime(self, reader, reference_time: float) -> Tuple[float, float]:
        """Extract bedtime from BedtimePeriod or derive from available data.

        Priority:
        1. BedtimePeriod from protobuf (if available)
        2. IBI total duration (most accurate representation of sleep period)
        3. Sleep epoch count * 30 seconds
        4. Default 8 hours
        """
        # Try to get from protobuf BedtimePeriod
        try:
            import ringeventparser_pb2 as pb
            # Access raw protobuf if available
            if hasattr(reader, '_raw_data'):
                rd = reader._raw_data
                if rd.HasField('bedtime_period'):
                    bp = rd.bedtime_period
                    if bp.bedtime_start and bp.bedtime_end:
                        # Convert from milliseconds to seconds
                        start_ms = bp.bedtime_start[0]
                        end_ms = bp.bedtime_end[0]
                        if start_ms > 0 and end_ms > 0:
                            print("[SleepNet] Using BedtimePeriod from protobuf")
                            return start_ms / 1000.0, end_ms / 1000.0
        except Exception as e:
            pass  # Fall through to derivation

        # Try IBI total duration (ring only sends sleep-period IBI data)
        hr = reader.heart_rate
        if hr.ibi_ms and len(hr.ibi_ms) > 0:
            total_ibi_ms = sum(hr.ibi_ms)
            ibi_duration_sec = total_ibi_ms / 1000.0
            if ibi_duration_sec > 1800:  # At least 30 minutes
                bedtime_end = reference_time
                bedtime_start = reference_time - ibi_duration_sec
                print(f"[SleepNet] Derived bedtime from IBI total: {ibi_duration_sec/3600:.2f} hours")
                return bedtime_start, bedtime_end

        # Derive from sleep epoch count (30 seconds per epoch)
        sleep = reader.sleep
        n_epochs = len(sleep.sleep_state) if hasattr(sleep, 'sleep_state') and sleep.sleep_state else 0

        if n_epochs > 0:
            sleep_duration_sec = n_epochs * 30  # 30 seconds per epoch
            bedtime_end = reference_time
            bedtime_start = reference_time - sleep_duration_sec
            print(f"[SleepNet] Derived bedtime from {n_epochs} sleep epochs: {sleep_duration_sec/3600:.2f} hours")
        else:
            # Default to 8 hours
            bedtime_end = reference_time
            bedtime_start = reference_time - 8 * 3600
            print("[SleepNet] Using default 8-hour bedtime window")

        return bedtime_start, bedtime_end

    def _build_ibi_input(
        self,
        hr,
        bedtime_start: float,
        bedtime_end: float,
        time_sync: Optional[TimeSyncInfo]
    ) -> torch.Tensor:
        """Build IBI input tensor.

        Format: [N, 4] - [timestamp_sec, ibi_ms, amplitude, validity]
        """
        ibi_data = []
        n_ibi = len(hr.ibi_ms) if hr.ibi_ms else 0
        amplitudes = hr.amplitudes if hasattr(hr, 'amplitudes') and hr.amplitudes else None
        raw_timestamps = hr.timestamps if hr.timestamps else None

        if n_ibi == 0:
            # Minimal placeholder
            return torch.tensor([
                [bedtime_start, 800.0, 10000.0, 1.0],
                [bedtime_end, 800.0, 10000.0, 1.0]
            ], dtype=torch.float64)

        # Compute validity using EcoreWrapper or fallback
        validity_map = self._compute_ibi_validity(hr, amplitudes, raw_timestamps)

        # Build timestamps
        if time_sync and raw_timestamps:
            # Use TIME_SYNC_IND conversion (proper method)
            print("[SleepNet] Using TIME_SYNC_IND for IBI timestamps")
            for i in range(n_ibi):
                ring_time = raw_timestamps[i]
                ts_sec = time_sync.ring_time_to_utc_sec(ring_time)
                ibi = float(hr.ibi_ms[i])
                amp = float(amplitudes[i]) if amplitudes and i < len(amplitudes) else 10000.0
                validity = validity_map.get(i, 1.0 if 300 <= ibi <= 2000 else 0.0)
                ibi_data.append([ts_sec, ibi, amp, validity])
        else:
            # Build continuous timestamps from IBI values
            # Ring data is organized in 6-sample chunks with discontinuous timestamps
            # We ignore the ring timestamps and build our own from cumulative IBI
            print("[SleepNet] Building timestamps from IBI values (continuous)")

            # Calculate total IBI duration
            total_ibi_ms = sum(hr.ibi_ms)
            total_ibi_sec = total_ibi_ms / 1000.0

            # Scale factor to fit IBI data within bedtime window
            sleep_duration = bedtime_end - bedtime_start
            if total_ibi_sec > 0 and sleep_duration > 0:
                scale = sleep_duration / total_ibi_sec
            else:
                scale = 1.0

            print(f"[SleepNet] IBI duration: {total_ibi_sec/3600:.2f}h, "
                  f"Bedtime: {sleep_duration/3600:.2f}h, scale: {scale:.3f}")

            # Build continuous timestamps - each IBI advances by its duration
            ts_sec = bedtime_start
            for i in range(n_ibi):
                ibi = float(hr.ibi_ms[i])
                amp = float(amplitudes[i]) if amplitudes and i < len(amplitudes) else 10000.0
                validity = validity_map.get(i, 1.0 if 300 <= ibi <= 2000 else 0.0)
                ibi_data.append([ts_sec, ibi, amp, validity])
                # Advance by scaled IBI duration
                ts_sec += (ibi / 1000.0) * scale

        return torch.tensor(ibi_data, dtype=torch.float64)

    def _compute_ibi_validity(
        self,
        hr,
        amplitudes: Optional[List],
        timestamps: Optional[List]
    ) -> Dict[int, float]:
        """Compute IBI validity using EcoreWrapper or fallback."""
        validity_map = {}
        n_ibi = len(hr.ibi_ms)

        # Try native EcoreWrapper
        if _check_ecore():
            try:
                from oura_ecore import EcoreWrapper
                ecore = EcoreWrapper()

                # Prepare data - use millisecond timestamps for native lib
                raw_ibi_data = []
                for i in range(n_ibi):
                    # EcoreWrapper expects (timestamp_ms, ibi_ms, amplitude)
                    ts_ms = timestamps[i] * 100 if timestamps and i < len(timestamps) else i * 1000
                    ibi = hr.ibi_ms[i]
                    amp = amplitudes[i] if amplitudes and i < len(amplitudes) else 10000
                    raw_ibi_data.append((ts_ms, ibi, amp))

                # Run native IBI correction
                corrected = ecore.correct_ibi(raw_ibi_data)

                # Map validity: native 0=Valid→1.0, native 1/2=Invalid→0.0
                valid_count = 0
                for i, result in enumerate(corrected):
                    validity_map[i] = 1.0 if result.validity == 0 else 0.0
                    if result.validity == 0:
                        valid_count += 1

                valid_pct = valid_count / len(corrected) * 100 if corrected else 0
                print(f"[SleepNet] EcoreWrapper: {valid_count}/{len(corrected)} valid ({valid_pct:.1f}%)")

                # If too few valid, fall back to simple check
                if valid_pct < 20:
                    print("[SleepNet] Warning: EcoreWrapper marked <20% valid, using fallback")
                    validity_map = {}  # Clear and use fallback

            except Exception as e:
                print(f"[SleepNet] EcoreWrapper failed: {e}, using fallback")

        # Fallback: simple physiological range check
        if not validity_map:
            for i in range(n_ibi):
                ibi = hr.ibi_ms[i]
                # Valid range: 300-2000ms = 30-200 BPM
                validity_map[i] = 1.0 if 300 <= ibi <= 2000 else 0.0

            valid_count = sum(1 for v in validity_map.values() if v == 1.0)
            print(f"[SleepNet] Fallback validity: {valid_count}/{n_ibi} valid")

        return validity_map

    def _build_acm_input(
        self,
        motion,
        sleep,
        bedtime_start: float,
        bedtime_end: float
    ) -> torch.Tensor:
        """Build ACM (motion) input tensor.

        Format: [M, 2] - [timestamp_sec, motion_seconds]

        IMPORTANT: Use motion.motion_seconds (0-30 range) as primary source.
        This matches the Oura app which uses MotionEvent.motion_seconds.
        """
        acm_data = []
        sleep_duration = bedtime_end - bedtime_start

        # PRIMARY: Use motion.motion_seconds (correct per decompiled app)
        if hasattr(motion, 'motion_seconds') and motion.motion_seconds and len(motion.motion_seconds) > 0:
            n_motion = len(motion.motion_seconds)
            motion_interval = sleep_duration / n_motion

            for i in range(n_motion):
                ts_sec = bedtime_start + i * motion_interval
                # motion_seconds is in range 0-30 (seconds of motion per epoch)
                val = min(float(motion.motion_seconds[i]), 30.0)
                acm_data.append([ts_sec, val])

            mean_val = sum(motion.motion_seconds) / n_motion
            print(f"[SleepNet] Using motion.motion_seconds: mean={mean_val:.1f}")

        # FALLBACK: Use sleep.motion_count if motion_seconds not available
        elif hasattr(sleep, 'motion_count') and sleep.motion_count and len(sleep.motion_count) > 0:
            n_motion = len(sleep.motion_count)
            motion_interval = sleep_duration / n_motion

            for i in range(n_motion):
                ts_sec = bedtime_start + i * motion_interval
                # motion_count may need scaling to 0-30 range
                val = min(float(sleep.motion_count[i]), 30.0)
                acm_data.append([ts_sec, val])

            mean_val = sum(sleep.motion_count) / n_motion
            print(f"[SleepNet] Using sleep.motion_count (fallback): mean={mean_val:.1f}")

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
