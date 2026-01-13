#!/usr/bin/env python3
"""
test_full_pipeline.py - Test complete Oura data processing pipeline

This tests all available approaches for sleep staging:
1. Native ring data (sleep_state from Oura app)
2. SleepNet ML model (sleepnet_moonstone_1_1_0.pt)
3. Native IBI correction (via libappecore.so)
"""

import sys
from oura.data.reader import RingDataReader
from oura_ecore import EcoreWrapper
from ml_inference.sleepnet import SleepNetModel
from collections import Counter


def test_native_sleep_data(reader):
    """Test 1: Native sleep staging from ring data."""
    print("\n" + "=" * 70)
    print("TEST 1: Native Sleep Staging (from Oura app on ring)")
    print("=" * 70)

    sleep = reader.sleep
    native_result = reader.get_native_sleep_stages()

    print(f"\nNative Sleep Stages:")
    print(f"  Total epochs: {native_result.total_epochs}")
    print(f"  Deep:  {native_result.deep_minutes:.0f} min")
    print(f"  Light: {native_result.light_minutes:.0f} min")
    print(f"  REM:   {native_result.rem_minutes:.0f} min")
    print(f"  Awake: {native_result.awake_minutes:.0f} min")
    print(f"  Total Sleep: {native_result.total_sleep_minutes:.0f} min")
    print(f"  Efficiency: {native_result.sleep_efficiency:.1f}%")

    # Show stage distribution
    stage_names = {0: 'DEEP', 1: 'LIGHT', 2: 'REM', 3: 'AWAKE'}
    print("\nStage distribution:")
    counts = Counter(native_result.stages)
    for stage, count in sorted(counts.items()):
        name = stage_names.get(stage, f'UNKNOWN({stage})')
        pct = count / native_result.total_epochs * 100
        print(f"  {name}: {count} epochs ({pct:.1f}%)")

    return native_result


def test_sleepnet_model(reader):
    """Test 2: SleepNet ML model."""
    print("\n" + "=" * 70)
    print("TEST 2: SleepNet ML Model (sleepnet_moonstone_1_1_0.pt)")
    print("=" * 70)

    model = SleepNetModel(use_moonstone=True)
    result = model.predict_from_reader(reader)

    stage_names = {0: 'AWAKE', 1: 'LIGHT', 2: 'DEEP', 3: 'REM'}

    print(f"\nSleepNet Results:")
    print(f"  Total epochs: {len(result.stages)}")
    print(f"  Unique stages: {sorted(set(result.stages.tolist()))}")

    print(f"\nDurations:")
    print(f"  Awake: {result.awake_seconds / 60:.1f} min")
    print(f"  Light: {result.light_seconds / 60:.1f} min")
    print(f"  Deep:  {result.deep_seconds / 60:.1f} min")
    print(f"  REM:   {result.rem_seconds / 60:.1f} min")
    print(f"  Total Sleep: {result.total_sleep_seconds / 60:.1f} min")
    print(f"  Efficiency: {result.sleep_efficiency:.1f}%")

    # Show stage distribution
    print("\nStage distribution:")
    counts = Counter(result.stages.tolist())
    total = len(result.stages)
    for stage, count in sorted(counts.items()):
        name = stage_names.get(stage, f'UNKNOWN({stage})')
        pct = count / total * 100
        print(f"  {name}: {count} epochs ({pct:.1f}%)")

    return result


def test_native_ibi_correction(reader):
    """Test 3: Native IBI correction via libappecore.so."""
    print("\n" + "=" * 70)
    print("TEST 3: Native IBI Correction (via libappecore.so)")
    print("=" * 70)

    hr = reader.heart_rate
    print(f"\nRaw IBI data: {hr.sample_count} samples")
    print(f"  Average IBI: {hr.average_ibi:.0f} ms ({hr.average_bpm:.1f} BPM)")
    print(f"  IBI range: {min(hr.ibi_ms)} - {max(hr.ibi_ms)} ms")

    # Test with sample of IBI data
    ecore = EcoreWrapper()

    # Prepare sample (using relative timestamps as-is)
    sample_size = min(500, hr.sample_count)
    ibi_data = []
    for i in range(sample_size):
        ts = hr.timestamps[i] if hr.timestamps else i * 1000
        ibi = hr.ibi_ms[i]
        amp = hr.amplitudes[i] if hr.amplitudes else 10000
        ibi_data.append((ts, ibi, amp))

    print(f"\nRunning native IBI correction on {sample_size} samples...")
    corrected = ecore.correct_ibi(ibi_data)

    # Count validity
    valid = sum(1 for r in corrected if r.validity == 0)
    invalid = sum(1 for r in corrected if r.validity == 1)
    interp = sum(1 for r in corrected if r.validity == 2)

    print(f"\nValidity distribution:")
    print(f"  Valid: {valid} ({valid/len(corrected)*100:.1f}%)")
    print(f"  Invalid: {invalid} ({invalid/len(corrected)*100:.1f}%)")
    print(f"  Interpolated: {interp} ({interp/len(corrected)*100:.1f}%)")

    return corrected


def test_sleep_score(reader):
    """Test 4: Sleep score calculation."""
    print("\n" + "=" * 70)
    print("TEST 4: Sleep Score Calculation (via libappecore.so)")
    print("=" * 70)

    ecore = EcoreWrapper()

    # Use data derived from native sleep staging
    native = reader.get_native_sleep_stages()

    result = ecore.calculate_sleep_score(
        total_sleep_min=int(native.total_sleep_minutes),
        deep_sleep_min=int(native.deep_minutes),
        rem_sleep_min=int(native.rem_minutes),
        efficiency=int(native.sleep_efficiency),
        latency_min=10,  # Assumed
        wakeup_count=2,  # Assumed
        awake_sec=int(native.awake_minutes * 60),
        restless_periods=5,  # Assumed
        temp_deviation=0
    )

    print(f"\nSleep Score: {result.score}/100")
    print(f"\nContributors:")
    print(f"  Total Sleep: {result.total_contrib}/100")
    print(f"  Efficiency:  {result.efficiency_contrib}/100")
    print(f"  Restfulness: {result.restfulness_contrib}/100")
    print(f"  Deep Sleep:  {result.deep_contrib}/100")
    print(f"  Latency:     {result.latency_contrib}/100")
    print(f"  Timing:      {result.timing_contrib}/100")

    return result


def main():
    print("=" * 70)
    print("Full Pipeline Test - Oura Ring Data Processing")
    print("=" * 70)

    # Load ring data
    print("\nLoading ring_data_fresh.pb...")
    reader = RingDataReader('ring_data_fresh.pb')
    print(f"  IBI samples: {reader.heart_rate.sample_count}")
    print(f"  Sleep samples: {reader.sleep.total_samples}")
    print(f"  Temperature samples: {reader.temperature.sample_count if hasattr(reader.temperature, 'sample_count') else len(reader.temperature.temp_celsius)}")

    # Run all tests
    results = {}

    try:
        results['native'] = test_native_sleep_data(reader)
    except Exception as e:
        print(f"  ERROR: {e}")

    try:
        results['sleepnet'] = test_sleepnet_model(reader)
    except Exception as e:
        print(f"  ERROR: {e}")

    try:
        results['ibi_correction'] = test_native_ibi_correction(reader)
    except Exception as e:
        print(f"  ERROR: {e}")

    try:
        results['sleep_score'] = test_sleep_score(reader)
    except Exception as e:
        print(f"  ERROR: {e}")

    # Summary
    print("\n" + "=" * 70)
    print("SUMMARY")
    print("=" * 70)

    status = {
        'Native Sleep Stages': 'native' in results,
        'SleepNet ML Model': 'sleepnet' in results,
        'Native IBI Correction': 'ibi_correction' in results,
        'Sleep Score Calculation': 'sleep_score' in results,
    }

    for name, working in status.items():
        icon = "OK" if working else "FAIL"
        print(f"  [{icon}] {name}")

    # Compare results if both available
    if 'native' in results and 'sleepnet' in results:
        print("\n" + "-" * 70)
        print("Comparison: Native vs SleepNet")
        print("-" * 70)

        native = results['native']
        sleepnet = results['sleepnet']

        print(f"\n{'Metric':<20} {'Native':<15} {'SleepNet':<15}")
        print("-" * 50)
        print(f"{'Deep (min)':<20} {native.deep_minutes:<15.0f} {sleepnet.deep_seconds/60:<15.1f}")
        print(f"{'Light (min)':<20} {native.light_minutes:<15.0f} {sleepnet.light_seconds/60:<15.1f}")
        print(f"{'REM (min)':<20} {native.rem_minutes:<15.0f} {sleepnet.rem_seconds/60:<15.1f}")
        print(f"{'Awake (min)':<20} {native.awake_minutes:<15.0f} {sleepnet.awake_seconds/60:<15.1f}")
        print(f"{'Efficiency (%)':<20} {native.sleep_efficiency:<15.1f} {sleepnet.sleep_efficiency:<15.1f}")

    print("\n" + "=" * 70)
    print("Test complete!")
    print("=" * 70)

    return 0 if all(status.values()) else 1


if __name__ == '__main__':
    sys.exit(main())
