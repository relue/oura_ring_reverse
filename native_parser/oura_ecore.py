#!/usr/bin/env python3
"""
oura_ecore.py - Python wrapper for libappecore.so via QEMU bridges

This module provides a Python API for Oura ring native library functions
by running ARM64 bridge binaries through QEMU user-mode emulation.

Usage:
    from oura_ecore import EcoreWrapper

    ecore = EcoreWrapper()

    # IBI Correction (WORKING)
    corrected = ecore.correct_ibi([
        (1000000, 857, 12450),
        (1001000, 892, 11230),
        # ... more (timestamp_ms, ibi_ms, amplitude)
    ])
    for r in corrected:
        print(f"ts={r.timestamp} ibi={r.ibi} validity={r.validity}")

    # Daytime HR (Basic - uses IBI->HR conversion)
    hr_results = ecore.process_daytime_hr(ibi_data)
"""

import os
import subprocess
import csv
from io import StringIO
from dataclasses import dataclass
from typing import List, Tuple, Optional
from pathlib import Path


@dataclass
class IbiResult:
    """Result from IBI correction"""
    timestamp: int  # ms
    ibi: int  # ms
    amplitude: int
    validity: int  # 0=Valid, 1=Invalid, 2=Interpolated


@dataclass
class HrResult:
    """Result from HR processing"""
    timestamp: int  # ms
    ibi: int  # ms
    hr_bpm: int
    quality: int


@dataclass
class SleepScoreResult:
    """Sleep score result with contributor scores (from native ecore_sleep_score_calculate_minutes).

    Note: The native function returns 6 contributors. Circadian alignment is factored
    into the final score via init_limits, not returned as a separate contributor.
    """
    score: int  # Overall sleep score (0-100)
    total_sleep_contrib: int  # Total sleep time contributor
    deep_sleep_contrib: int  # Deep sleep contributor
    rem_sleep_contrib: int  # REM sleep contributor
    efficiency_contrib: int  # Efficiency contributor
    latency_contrib: int  # Latency contributor (byte 5, combines latency + awake time)
    disturbances_contrib: int  # Disturbances/restfulness contributor (byte 6, restless periods)
    quality_flag: int = 1  # Quality indicator: 1=good, higher values indicate deficits in deep/REM


@dataclass
class ReadinessScore:
    """Readiness score with contributors"""
    score: int  # 0-100
    activity_balance: int
    last_day_activity: int
    last_night_sleep: int
    resting_hr: int
    sleep_balance: int
    temperature: int
    hrv_balance: Optional[int]
    sleep_regularity: Optional[int]


@dataclass
class ActivityScore:
    """Activity score with metrics"""
    score: int  # 0-100
    steps: int
    active_calories: int
    total_calories: int
    equivalent_distance_meters: int


class EcoreWrapper:
    """
    Python wrapper for libappecore.so via QEMU ARM64 emulation.

    Provides access to Oura ring native algorithms:
    - IBI correction (working)
    - Daytime HR processing (basic)
    - Score calculations (TODO)
    """

    def __init__(self, native_parser_dir: Optional[str] = None):
        """
        Initialize the EcoreWrapper.

        Args:
            native_parser_dir: Path to native_parser directory.
                              Defaults to directory containing this file.
        """
        if native_parser_dir is None:
            native_parser_dir = str(Path(__file__).parent)

        self.native_parser_dir = Path(native_parser_dir)
        self.android_root = self.native_parser_dir / "android_root"

        # Check prerequisites
        self._check_prerequisites()

    def _check_prerequisites(self):
        """Verify QEMU and required files exist."""
        # Check QEMU
        try:
            subprocess.run(
                ["qemu-aarch64", "--version"],
                capture_output=True,
                check=True
            )
        except (FileNotFoundError, subprocess.CalledProcessError):
            raise RuntimeError(
                "qemu-aarch64 not found. Install QEMU user-mode:\n"
                "  Arch: sudo pacman -S qemu-user\n"
                "  Debian/Ubuntu: sudo apt install qemu-user qemu-user-binfmt"
            )

        # Check android_root
        if not self.android_root.exists():
            raise RuntimeError(
                f"Android root not found: {self.android_root}\n"
                f"Run: {self.native_parser_dir}/setup_android_root.sh --help"
            )

        # Check libappecore.so
        libappecore = self.android_root / "system/lib64/libappecore.so"
        if not libappecore.exists():
            raise RuntimeError(
                f"libappecore.so not found: {libappecore}\n"
                "Extract from Oura APK: lib/arm64-v8a/libappecore.so"
            )

    def _run_bridge(self, bridge_name: str, input_data: str,
                    timeout: int = 60, use_args: bool = False) -> Tuple[str, str]:
        """
        Run a bridge binary via QEMU.

        Args:
            bridge_name: Name of bridge binary (e.g., 'ibi_correction_bridge_v9')
            input_data: CSV data to send to stdin OR command line argument
            timeout: Timeout in seconds
            use_args: If True, pass input_data as command line argument instead of stdin.
                      Required for some bridges due to QEMU stdin pipe issues.

        Returns:
            Tuple of (stdout, stderr)
        """
        bridge_path = self.native_parser_dir / bridge_name
        if not bridge_path.exists():
            raise FileNotFoundError(f"Bridge not found: {bridge_path}")

        env = {
            "LD_LIBRARY_PATH": str(self.android_root / "system/lib64"),
            "QEMU_LD_PREFIX": str(self.android_root),
        }

        cmd = [
            "qemu-aarch64",
            "-L", str(self.android_root),
            str(bridge_path)
        ]

        if use_args:
            # Pass data as command line argument (avoids QEMU stdin pipe bug)
            cmd.append(input_data.strip())
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                env=env,
                timeout=timeout
            )
        else:
            # Standard stdin piping
            result = subprocess.run(
                cmd,
                input=input_data,
                capture_output=True,
                text=True,
                env=env,
                timeout=timeout
            )

        return result.stdout, result.stderr

    def correct_ibi(self, ibi_data: List[Tuple[int, int, int]]) -> List[IbiResult]:
        """
        Run IBI correction on raw IBI data.

        This uses Oura's native IBI correction algorithm which:
        - Filters outliers
        - Interpolates missing beats
        - Marks validity of each sample

        Args:
            ibi_data: List of (timestamp_ms, ibi_ms, amplitude) tuples

        Returns:
            List of IbiResult with corrected values and validity flags

        Example:
            >>> ecore = EcoreWrapper()
            >>> results = ecore.correct_ibi([
            ...     (1000000, 857, 12450),
            ...     (1001000, 892, 11230),
            ... ])
            >>> for r in results:
            ...     print(f"{r.timestamp},{r.ibi},{r.validity}")
        """
        # Convert to CSV
        csv_lines = []
        for ts, ibi, amp in ibi_data:
            csv_lines.append(f"{ts},{ibi},{amp}")
        input_csv = "\n".join(csv_lines) + "\n"

        # Run bridge
        stdout, stderr = self._run_bridge("ibi_correction_bridge_v9", input_csv)

        # Parse output
        results = []
        reader = csv.DictReader(StringIO(stdout))
        for row in reader:
            results.append(IbiResult(
                timestamp=int(row["timestamp"]),
                ibi=int(row["ibi"]),
                amplitude=int(row["amplitude"]),
                validity=int(row["validity"])
            ))

        return results

    def process_daytime_hr(self, ibi_data: List[Tuple[int, int, int]]) -> List[HrResult]:
        """
        Process daytime HR events.

        Currently uses basic IBI->HR conversion (60000/ibi_ms).
        Native callback integration pending.

        Args:
            ibi_data: List of (timestamp_ms, ibi_ms, amplitude) tuples

        Returns:
            List of HrResult with HR values
        """
        # Convert to CSV
        csv_lines = []
        for ts, ibi, amp in ibi_data:
            csv_lines.append(f"{ts},{ibi},{amp}")
        input_csv = "\n".join(csv_lines) + "\n"

        # Try native bridge
        try:
            stdout, stderr = self._run_bridge("daytime_hr_bridge", input_csv)
        except FileNotFoundError:
            # Fallback to simple calculation
            results = []
            for ts, ibi, amp in ibi_data:
                hr_bpm = 60000 // ibi if ibi > 0 else 0
                results.append(HrResult(
                    timestamp=ts,
                    ibi=ibi,
                    hr_bpm=hr_bpm,
                    quality=0
                ))
            return results

        # Parse output
        results = []
        reader = csv.DictReader(StringIO(stdout))
        for row in reader:
            results.append(HrResult(
                timestamp=int(row["timestamp"]),
                ibi=int(row["ibi"]),
                hr_bpm=int(row["hr_bpm"]),
                quality=int(row["quality"])
            ))

        return results

    def calculate_hr_from_ibi(self, ibi_ms: int) -> int:
        """
        Calculate heart rate from inter-beat interval.

        Args:
            ibi_ms: Inter-beat interval in milliseconds

        Returns:
            Heart rate in BPM
        """
        if ibi_ms <= 0:
            return 0
        return 60000 // ibi_ms

    # ==================== Score Calculations ====================

    def calculate_sleep_score(
        self,
        total_sleep_min: int,
        deep_sleep_min: int,
        rem_sleep_min: int,
        light_sleep_min: int = None,
        efficiency: int = 85,
        latency_min: int = 10,
        wakeup_count: int = 2,
        awake_sec: int = 300,
        restless_periods: int = 4,
        temp_deviation: int = 0,
        got_up_count: int = 0,
        sleep_midpoint_sec: int = 10800,  # 3 AM default
    ) -> SleepScoreResult:
        """
        Calculate sleep score using native Oura library (STATELESS).

        This calls ecore_sleep_score_calculate_minutes directly via the
        sleep_score_minutes_ndk binary. This is a stateless function that
        doesn't require library initialization.

        Args:
            total_sleep_min: Total sleep time in minutes (e.g., 420 for 7h)
            deep_sleep_min: Deep sleep time in minutes
            rem_sleep_min: REM sleep time in minutes
            light_sleep_min: Light sleep time (calculated from total if None)
            efficiency: Sleep efficiency percentage (0-100, default: 85)
            latency_min: Time to fall asleep in minutes (default: 10)
            wakeup_count: Number of times woken up (default: 2)
            awake_sec: Time awake during sleep in seconds (default: 300)
            restless_periods: Number of restless periods (default: 4)
            temp_deviation: Temperature deviation in centidegrees (default: 0)
            got_up_count: Number of times got out of bed (default: 0)
            sleep_midpoint_sec: Sleep midpoint in seconds from midnight (default: 10800 = 3AM)

        Returns:
            SleepScoreResult with overall score and 7 contributor scores

        Example:
            >>> ecore = EcoreWrapper()
            >>> result = ecore.calculate_sleep_score(
            ...     total_sleep_min=420,  # 7h
            ...     deep_sleep_min=84,    # ~20%
            ...     rem_sleep_min=105,    # ~25%
            ...     efficiency=88,
            ... )
            >>> print(f"Sleep score: {result.score}")
            Sleep score: 68
        """
        # Calculate light sleep if not provided
        if light_sleep_min is None:
            light_sleep_min = max(0, total_sleep_min - deep_sleep_min - rem_sleep_min)

        # Format input as comma-separated values (12 parameters)
        # total,deep,rem,light,eff,latency,wakeups,awake_sec,restless,temp_dev,got_up,midpoint
        input_args = (
            f"{total_sleep_min},{deep_sleep_min},{rem_sleep_min},{light_sleep_min},"
            f"{efficiency},{latency_min},{wakeup_count},{awake_sec},{restless_periods},"
            f"{temp_deviation},{got_up_count},{sleep_midpoint_sec}"
        )

        # Run bridge with command line args (use_args=True avoids QEMU stdin pipe bug)
        stdout, stderr = self._run_bridge("sleep_score_minutes_ndk", input_args, use_args=True)

        # Parse output - format is:
        # sleepScore
        # <score>
        # contributors
        # <total>,<deep>,<rem>,<eff>,<latency>,<disturb>
        # qualityFlag
        # <flag>
        lines = stdout.strip().split('\n')
        score = 0
        contribs = [0, 0, 0, 0, 0, 0]
        quality_flag = 1

        for i, line in enumerate(lines):
            if line == 'sleepScore' and i + 1 < len(lines):
                score = int(lines[i + 1])
            elif line == 'contributors' and i + 1 < len(lines):
                contribs = [int(x) for x in lines[i + 1].split(',')]
            elif line == 'qualityFlag' and i + 1 < len(lines):
                quality_flag = int(lines[i + 1])

        return SleepScoreResult(
            score=score,
            total_sleep_contrib=contribs[0] if len(contribs) > 0 else 0,
            deep_sleep_contrib=contribs[1] if len(contribs) > 1 else 0,
            rem_sleep_contrib=contribs[2] if len(contribs) > 2 else 0,
            efficiency_contrib=contribs[3] if len(contribs) > 3 else 0,
            latency_contrib=contribs[4] if len(contribs) > 4 else 0,
            disturbances_contrib=contribs[5] if len(contribs) > 5 else 0,
            quality_flag=quality_flag,
        )

    def calculate_readiness_score(self, readiness_data: dict) -> Optional[ReadinessScore]:
        """
        Calculate readiness score (TODO - requires bridge implementation).

        Input based on ReadinessScoreSleepInput.java:
        {
            'sleep_date_utc_seconds': int,
            'day_number': int,
            'sleep_score': int,
            'time_in_bed_seconds': int,
            'total_sleep_seconds': int,
            'rem_sleep_seconds': int,
            'deep_sleep_seconds': int,
            'latency_seconds': int,
            'wake_up_count': int,
            'highest_temp_centidegrees': int,
            'lowest_hr': int,
            'lowest_hr_time_seconds': int,
            'rmssd': int,
        }
        """
        raise NotImplementedError(
            "Readiness score bridge not yet implemented. "
            "See ReadinessScoreSleepInput.java for input format."
        )

    def calculate_activity_score(self, activity_data: dict) -> Optional[ActivityScore]:
        """
        Calculate activity score (TODO - requires bridge implementation).

        Input based on ActivityInput.java - complex structure with:
        - MET values, steps, sit alerts
        - Activity history
        - Sleep periods
        - Rest mode state
        """
        raise NotImplementedError(
            "Activity score bridge not yet implemented. "
            "See ActivityInput.java for input format."
        )


# ==================== Utility Functions ====================

def ibi_to_hr(ibi_ms: int) -> int:
    """Convert IBI (ms) to heart rate (BPM)."""
    return 60000 // ibi_ms if ibi_ms > 0 else 0


def hr_to_ibi(hr_bpm: int) -> int:
    """Convert heart rate (BPM) to IBI (ms)."""
    return 60000 // hr_bpm if hr_bpm > 0 else 0


# ==================== Main (for testing) ====================

if __name__ == "__main__":
    import sys

    print("EcoreWrapper Test")
    print("=" * 50)

    try:
        ecore = EcoreWrapper()
        print("Initialized EcoreWrapper successfully")

        # Test IBI correction with sample data
        test_data = [
            (1000000, 857, 12450),
            (1001000, 892, 11230),
            (1002000, 901, 11890),
            (1003000, 876, 12100),
            (1004000, 923, 11450),
        ]

        print(f"\nTesting IBI correction with {len(test_data)} samples...")
        results = ecore.correct_ibi(test_data)

        print(f"Received {len(results)} corrected samples:")
        print("timestamp,ibi,amplitude,validity")
        for r in results:
            print(f"{r.timestamp},{r.ibi},{r.amplitude},{r.validity}")

        # Test HR processing
        print(f"\nTesting HR processing...")
        hr_results = ecore.process_daytime_hr(test_data)

        print(f"Received {len(hr_results)} HR samples:")
        print("timestamp,ibi,hr_bpm,quality")
        for r in hr_results:
            print(f"{r.timestamp},{r.ibi},{r.hr_bpm},{r.quality}")

        # Test sleep score calculation
        print(f"\nTesting sleep score calculation...")
        sleep_result = ecore.calculate_sleep_score(
            total_sleep_min=420,  # 7 hours
            deep_sleep_min=84,    # ~20%
            rem_sleep_min=105,    # ~25%
            efficiency=88,
            latency_min=10,
            wakeup_count=2,
        )
        print(f"Sleep score: {sleep_result.score}")
        print(f"  Total sleep contributor: {sleep_result.total_sleep_contrib}")
        print(f"  Deep sleep contributor: {sleep_result.deep_sleep_contrib}")
        print(f"  REM sleep contributor: {sleep_result.rem_sleep_contrib}")
        print(f"  Efficiency contributor: {sleep_result.efficiency_contrib}")
        print(f"  Latency contributor: {sleep_result.latency_contrib}")
        print(f"  Disturbances contributor: {sleep_result.disturbances_contrib}")
        print(f"  Quality flag: {sleep_result.quality_flag}")

    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)
