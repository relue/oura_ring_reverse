#!/usr/bin/env python3
"""
test_high_level_api.py - Comprehensive test of all high-level oura API functions

Tests:
1. OuraAnalyzer - main entry point
2. SleepAnalyzer - stages, stage_durations, score, bedtime, to_dict()
3. HRVAnalyzer - rmssd stats, samples_5min, by_sleep_stage(), to_dict()
4. Dashboard - aggregated metrics, to_dict(), summary()
5. RingDataReader - raw data access
"""

import sys
import traceback
from typing import Callable, Any

# Test results tracking
results = []

def test(name: str, func: Callable[[], Any], expected_type=None, check=None):
    """Run a test and record result."""
    try:
        result = func()

        # Type check
        if expected_type and not isinstance(result, expected_type):
            results.append((name, "FAIL", f"Expected {expected_type.__name__}, got {type(result).__name__}"))
            return None

        # Custom validation
        if check and not check(result):
            results.append((name, "FAIL", f"Validation failed: {result}"))
            return None

        results.append((name, "PASS", result))
        return result
    except Exception as e:
        results.append((name, "ERROR", f"{type(e).__name__}: {e}"))
        traceback.print_exc()
        return None


def main():
    print("=" * 70)
    print("HIGH-LEVEL API TEST SUITE")
    print("=" * 70)

    # ========================================================================
    # SECTION 1: OuraAnalyzer (main entry point)
    # ========================================================================
    print("\n" + "-" * 70)
    print("1. OuraAnalyzer - Main Entry Point")
    print("-" * 70)

    from oura import OuraAnalyzer

    analyzer = test(
        "OuraAnalyzer.__init__",
        lambda: OuraAnalyzer('ring_data_fresh.pb'),
        check=lambda x: x is not None
    )

    if not analyzer:
        print("FATAL: Cannot create OuraAnalyzer, aborting tests")
        return 1

    test("OuraAnalyzer.sleep", lambda: analyzer.sleep, check=lambda x: x is not None)
    test("OuraAnalyzer.hrv", lambda: analyzer.hrv, check=lambda x: x is not None)
    test("OuraAnalyzer.dashboard", lambda: analyzer.dashboard, check=lambda x: x is not None)
    test("OuraAnalyzer.raw", lambda: analyzer.raw, check=lambda x: x is not None)

    # ========================================================================
    # SECTION 2: SleepAnalyzer
    # ========================================================================
    print("\n" + "-" * 70)
    print("2. SleepAnalyzer - Sleep Stage Analysis")
    print("-" * 70)

    sleep = analyzer.sleep

    # Core properties
    test("SleepAnalyzer.stages", lambda: sleep.stages,
         check=lambda x: len(x) > 0)

    test("SleepAnalyzer.stages unique values",
         lambda: sorted(set(sleep.stages.tolist())),
         check=lambda x: all(v in [0, 1, 2, 3] for v in x))

    test("SleepAnalyzer.timestamps", lambda: sleep.timestamps,
         check=lambda x: len(x) > 0)

    test("SleepAnalyzer.uses_ml", lambda: sleep.uses_ml, expected_type=bool)

    # Bedtime
    test("SleepAnalyzer.bedtime_start", lambda: sleep.bedtime_start,
         check=lambda x: x > 0)

    test("SleepAnalyzer.bedtime_end", lambda: sleep.bedtime_end,
         check=lambda x: x > sleep.bedtime_start)

    # Stage durations
    durations = test("SleepAnalyzer.stage_durations", lambda: sleep.stage_durations,
                     check=lambda x: x is not None)

    if durations:
        test("stage_durations.deep", lambda: durations.deep, expected_type=float,
             check=lambda x: x >= 0)
        test("stage_durations.light", lambda: durations.light, expected_type=float,
             check=lambda x: x >= 0)
        test("stage_durations.rem", lambda: durations.rem, expected_type=float,
             check=lambda x: x >= 0)
        test("stage_durations.awake", lambda: durations.awake, expected_type=float,
             check=lambda x: x >= 0)
        test("stage_durations.total_sleep", lambda: durations.total_sleep, expected_type=float,
             check=lambda x: x > 0)
        test("stage_durations.efficiency", lambda: durations.efficiency, expected_type=float,
             check=lambda x: 0 <= x <= 100)

        # Verify REM is present (ML should detect REM, raw protobuf doesn't)
        if sleep.uses_ml:
            test("ML detects REM sleep", lambda: durations.rem,
                 check=lambda x: x > 0)

    # Sleep score (correct attribute names: total_sleep, efficiency, rem_sleep, deep_sleep, etc.)
    score = test("SleepAnalyzer.score", lambda: sleep.score,
                 check=lambda x: x is not None)

    if score:
        test("score.score", lambda: score.score, expected_type=int,
             check=lambda x: 0 <= x <= 100)
        test("score.total_sleep", lambda: score.total_sleep, expected_type=int)
        test("score.efficiency", lambda: score.efficiency, expected_type=int)
        test("score.deep_sleep", lambda: score.deep_sleep, expected_type=int)
        test("score.rem_sleep", lambda: score.rem_sleep, expected_type=int)
        test("score.restfulness", lambda: score.restfulness, expected_type=int)
        test("score.latency", lambda: score.latency, expected_type=int)
        test("score.timing", lambda: score.timing, expected_type=int)

        # Verify REM contributor is calculated (should be > 0 if we have REM sleep)
        if durations and durations.rem > 0:
            test("score.rem_sleep calculated", lambda: score.rem_sleep,
                 check=lambda x: x > 0)

    # to_dict()
    sleep_dict = test("SleepAnalyzer.to_dict()", lambda: sleep.to_dict(), expected_type=dict,
                      check=lambda x: 'stage_durations' in x)

    # ========================================================================
    # SECTION 3: HRVAnalyzer
    # ========================================================================
    print("\n" + "-" * 70)
    print("3. HRVAnalyzer - Heart Rate Variability")
    print("-" * 70)

    hrv = analyzer.hrv

    # Core stats
    test("HRVAnalyzer.average_rmssd", lambda: hrv.average_rmssd, expected_type=float,
         check=lambda x: x > 0)

    test("HRVAnalyzer.min_rmssd", lambda: hrv.min_rmssd,
         check=lambda x: x > 0)

    test("HRVAnalyzer.max_rmssd", lambda: hrv.max_rmssd,
         check=lambda x: x >= hrv.min_rmssd)

    test("HRVAnalyzer.sample_count", lambda: hrv.sample_count, expected_type=int,
         check=lambda x: x > 0)

    # 5-min samples (returns List[int], not List[Dict])
    samples = test("HRVAnalyzer.samples_5min", lambda: hrv.samples_5min, expected_type=list,
                   check=lambda x: len(x) > 0)

    if samples and len(samples) > 0:
        test("samples_5min[0] is int", lambda: samples[0], expected_type=int,
             check=lambda x: x > 0)

    # HRV by sleep stage (critical test - should use ML stages)
    by_stage = test("HRVAnalyzer.by_sleep_stage()", lambda: hrv.by_sleep_stage(), expected_type=dict)

    if by_stage:
        test("by_sleep_stage has 'deep'", lambda: 'deep' in by_stage,
             check=lambda x: x == True)
        test("by_sleep_stage has 'light'", lambda: 'light' in by_stage,
             check=lambda x: x == True)
        test("by_sleep_stage has 'rem'", lambda: 'rem' in by_stage,
             check=lambda x: x == True)
        test("by_sleep_stage has 'awake'", lambda: 'awake' in by_stage,
             check=lambda x: x == True)

        # Verify REM HRV is calculated (critical test after our fix)
        if sleep.uses_ml and durations and durations.rem > 0:
            test("by_sleep_stage REM HRV calculated", lambda: by_stage.get('rem', 0),
                 check=lambda x: x > 0)

    # Balance (requires baseline argument)
    test("HRVAnalyzer.balance(baseline=25.0)", lambda: hrv.balance(baseline=25.0), expected_type=float)

    # Variability index
    test("HRVAnalyzer.variability_index()", lambda: hrv.variability_index(), expected_type=float)

    # to_dict()
    test("HRVAnalyzer.to_dict()", lambda: hrv.to_dict(), expected_type=dict,
         check=lambda x: 'average_rmssd' in x)

    # ========================================================================
    # SECTION 4: Dashboard
    # ========================================================================
    print("\n" + "-" * 70)
    print("4. Dashboard - Aggregated Metrics")
    print("-" * 70)

    dashboard = analyzer.dashboard

    # Sleep metrics
    test("Dashboard.sleep_score", lambda: dashboard.sleep_score, expected_type=int,
         check=lambda x: 0 <= x <= 100)

    test("Dashboard.sleep_efficiency", lambda: dashboard.sleep_efficiency, expected_type=float,
         check=lambda x: 0 <= x <= 100)

    test("Dashboard.total_sleep_hours", lambda: dashboard.total_sleep_hours, expected_type=float,
         check=lambda x: x > 0)

    test("Dashboard.deep_sleep_minutes", lambda: dashboard.deep_sleep_minutes, expected_type=float,
         check=lambda x: x >= 0)

    test("Dashboard.rem_sleep_minutes", lambda: dashboard.rem_sleep_minutes, expected_type=float,
         check=lambda x: x >= 0)

    test("Dashboard.light_sleep_minutes", lambda: dashboard.light_sleep_minutes, expected_type=float,
         check=lambda x: x >= 0)

    # HRV metrics (correct name: hrv_average, not average_hrv)
    test("Dashboard.hrv_average", lambda: dashboard.hrv_average, expected_type=float,
         check=lambda x: x > 0)

    test("Dashboard.hrv_min", lambda: dashboard.hrv_min,
         check=lambda x: x > 0)

    test("Dashboard.hrv_max", lambda: dashboard.hrv_max,
         check=lambda x: x >= dashboard.hrv_min)

    # Activity metrics
    test("Dashboard.steps", lambda: dashboard.steps, expected_type=int,
         check=lambda x: x >= 0)

    # Vitals
    test("Dashboard.avg_heart_rate", lambda: dashboard.avg_heart_rate, expected_type=float)
    test("Dashboard.breathing_rate", lambda: dashboard.breathing_rate, expected_type=float)
    test("Dashboard.body_temperature", lambda: dashboard.body_temperature, expected_type=float)

    # to_dict() and summary()
    test("Dashboard.to_dict()", lambda: dashboard.to_dict(), expected_type=dict,
         check=lambda x: 'sleep_score' in x)

    test("Dashboard.summary()", lambda: dashboard.summary(), expected_type=str,
         check=lambda x: len(x) > 0)

    # ========================================================================
    # SECTION 5: RingDataReader (raw access)
    # ========================================================================
    print("\n" + "-" * 70)
    print("5. RingDataReader - Raw Data Access")
    print("-" * 70)

    from oura.data.reader import RingDataReader

    reader = test("RingDataReader.__init__", lambda: RingDataReader('ring_data_fresh.pb'),
                  check=lambda x: x is not None)

    if reader:
        test("RingDataReader.heart_rate", lambda: reader.heart_rate,
             check=lambda x: x is not None)
        test("RingDataReader.heart_rate.sample_count", lambda: reader.heart_rate.sample_count,
             expected_type=int, check=lambda x: x > 0)

        test("RingDataReader.sleep", lambda: reader.sleep,
             check=lambda x: x is not None)
        test("RingDataReader.sleep.total_samples", lambda: reader.sleep.total_samples,
             expected_type=int, check=lambda x: x > 0)

        test("RingDataReader.temperature", lambda: reader.temperature,
             check=lambda x: x is not None)

        test("RingDataReader.motion", lambda: reader.motion,
             check=lambda x: x is not None)

        test("RingDataReader.to_json()", lambda: reader.to_json(), expected_type=str,
             check=lambda x: len(x) > 0)

        test("RingDataReader.summary()", lambda: reader.summary(), expected_type=str,
             check=lambda x: len(x) > 0)

    # ========================================================================
    # SECTION 6: Cross-validation
    # ========================================================================
    print("\n" + "-" * 70)
    print("6. Cross-validation - Consistency Checks")
    print("-" * 70)

    # Note: Dashboard creates its own SleepAnalyzer with fresh ML inference,
    # so small variations are expected due to model non-determinism

    # Sleep score should be close (allow 5 points variance)
    test("Sleep score consistency (SleepAnalyzer ~ Dashboard)",
         lambda: (sleep.score.score, dashboard.sleep_score),
         check=lambda x: abs(x[0] - x[1]) <= 5)

    # HRV average should match (HRV data doesn't use ML)
    test("HRV average consistency (HRVAnalyzer == Dashboard)",
         lambda: (hrv.average_rmssd, dashboard.hrv_average),
         check=lambda x: abs(x[0] - x[1]) < 0.1)

    # Stage durations should be close (allow 5 min variance for ML variability)
    test("Deep sleep consistency (SleepAnalyzer ~ Dashboard)",
         lambda: (durations.deep, dashboard.deep_sleep_minutes),
         check=lambda x: abs(x[0] - x[1]) < 5.0)

    test("REM sleep consistency (SleepAnalyzer ~ Dashboard)",
         lambda: (durations.rem, dashboard.rem_sleep_minutes),
         check=lambda x: abs(x[0] - x[1]) < 5.0)

    # ========================================================================
    # RESULTS SUMMARY
    # ========================================================================
    print("\n" + "=" * 70)
    print("TEST RESULTS SUMMARY")
    print("=" * 70)

    passed = [r for r in results if r[1] == "PASS"]
    failed = [r for r in results if r[1] == "FAIL"]
    errors = [r for r in results if r[1] == "ERROR"]

    print(f"\nTotal:  {len(results)}")
    print(f"Passed: {len(passed)}")
    print(f"Failed: {len(failed)}")
    print(f"Errors: {len(errors)}")

    if failed:
        print("\n" + "-" * 70)
        print("FAILURES:")
        for name, status, msg in failed:
            print(f"  {name}: {msg}")

    if errors:
        print("\n" + "-" * 70)
        print("ERRORS:")
        for name, status, msg in errors:
            print(f"  {name}: {msg}")

    # Key metrics display
    print("\n" + "-" * 70)
    print("KEY METRICS:")
    print("-" * 70)

    if durations:
        print(f"  Sleep Duration: {durations.total_sleep:.1f} min ({durations.total_sleep/60:.1f} hrs)")
        print(f"  Deep:  {durations.deep:.1f} min ({durations.deep/durations.total_sleep*100:.1f}%)")
        print(f"  Light: {durations.light:.1f} min ({durations.light/durations.total_sleep*100:.1f}%)")
        print(f"  REM:   {durations.rem:.1f} min ({durations.rem/durations.total_sleep*100:.1f}%)")
        print(f"  Awake: {durations.awake:.1f} min")
        print(f"  Efficiency: {durations.efficiency:.1f}%")

    if score:
        print(f"\n  Sleep Score: {score.score}/100")
        print(f"    Total Sleep:  {score.total_sleep}")
        print(f"    Efficiency:   {score.efficiency}")
        print(f"    Deep Sleep:   {score.deep_sleep}")
        print(f"    REM Sleep:    {score.rem_sleep}")
        print(f"    Restfulness:  {score.restfulness}")
        print(f"    Latency:      {score.latency}")
        print(f"    Timing:       {score.timing}")

    if by_stage:
        print(f"\n  HRV by Stage:")
        print(f"    Deep:  {by_stage.get('deep', 0):.1f} ms")
        print(f"    Light: {by_stage.get('light', 0):.1f} ms")
        print(f"    REM:   {by_stage.get('rem', 0):.1f} ms")
        print(f"    Awake: {by_stage.get('awake', 0):.1f} ms")

    print("\n" + "=" * 70)

    # Return code
    if errors or failed:
        print("RESULT: SOME TESTS FAILED")
        return 1
    else:
        print("RESULT: ALL TESTS PASSED")
        return 0


if __name__ == '__main__':
    sys.exit(main())
