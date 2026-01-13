#!/usr/bin/env python3
"""
test_sleep_stages.py - Test unified sleep staging pipeline

Uses:
1. SleepNetModel (sleepnet_moonstone_1_1_0.pt)
2. EcoreWrapper for IBI correction (libappecore.so)
"""

import sys
from oura.data.reader import RingDataReader
from ml_inference.sleepnet import SleepNetModel
from collections import Counter


def main():
    print("=" * 70)
    print("Unified Sleep Stage Classification Test")
    print("Uses: SleepNet + EcoreWrapper (native IBI correction)")
    print("=" * 70)

    # Load ring data
    print("\n1. Loading ring data...")
    try:
        reader = RingDataReader('ring_data_fresh.pb')
        print(f"   Loaded {reader.heart_rate.sample_count} IBI samples")
        print(f"   Loaded {reader.sleep.total_samples} sleep samples")
    except Exception as e:
        print(f"   ERROR: {e}")
        return 1

    # Run SleepNet with native IBI correction
    print("\n2. Running SleepNet model...")
    try:
        model = SleepNetModel(use_moonstone=True)
        result = model.predict_from_reader(reader)
        print(f"   Classification complete: {len(result.stages)} epochs")
    except Exception as e:
        print(f"   ERROR: {e}")
        import traceback
        traceback.print_exc()
        return 1

    # Display results
    print("\n" + "=" * 70)
    print("Sleep Stage Results")
    print("=" * 70)

    stage_names = {0: 'AWAKE', 1: 'LIGHT', 2: 'DEEP', 3: 'REM'}

    print(f"\nDurations:")
    print(f"  Deep Sleep:  {result.deep_seconds/60:6.1f} min ({result.deep_seconds/60/60:.1f} hrs)")
    print(f"  Light Sleep: {result.light_seconds/60:6.1f} min ({result.light_seconds/60/60:.1f} hrs)")
    print(f"  REM Sleep:   {result.rem_seconds/60:6.1f} min ({result.rem_seconds/60/60:.1f} hrs)")
    print(f"  Awake:       {result.awake_seconds/60:6.1f} min")
    print(f"  ----------------------------------------")
    print(f"  Total Sleep: {result.total_sleep_seconds/60:6.1f} min ({result.total_sleep_seconds/60/60:.1f} hrs)")
    print(f"  Efficiency:  {result.sleep_efficiency:6.1f}%")

    # Stage distribution
    print("\nStage Distribution:")
    counts = Counter(result.stages.tolist())
    total = len(result.stages)
    for stage in [0, 1, 2, 3]:
        count = counts.get(stage, 0)
        name = stage_names.get(stage, 'UNKNOWN')
        pct = count / total * 100 if total > 0 else 0
        bar = "#" * int(pct / 2)
        print(f"  {name:6s}: {count:4d} epochs ({pct:5.1f}%) {bar}")

    # Show sleep architecture (hourly)
    if len(result.stages) >= 12:
        print("\n" + "-" * 70)
        print("Sleep Architecture (30-second epochs per hour):")
        print("-" * 70)

        epochs_per_hour = 120  # 120 x 30sec = 1 hour
        hours = len(result.stages) // epochs_per_hour + 1

        for hour in range(min(hours, 10)):
            start = hour * epochs_per_hour
            end = min(start + epochs_per_hour, len(result.stages))
            if start >= len(result.stages):
                break

            hour_stages = result.stages[start:end]
            counts = Counter(hour_stages.tolist())

            bar = ""
            bar += "D" * (counts.get(2, 0) // 6)  # Deep
            bar += "L" * (counts.get(1, 0) // 6)  # Light
            bar += "R" * (counts.get(3, 0) // 6)  # REM
            bar += "." * (counts.get(0, 0) // 6)  # Awake

            print(f"  Hour {hour+1:2d}: {bar:20s} "
                  f"D:{counts.get(2,0):3d} L:{counts.get(1,0):3d} "
                  f"R:{counts.get(3,0):3d} A:{counts.get(0,0):3d}")

        print("\n  Legend: D=Deep L=Light R=REM .=Awake")

    # Compare with native ring data
    print("\n" + "-" * 70)
    print("Comparison with Native Ring Data:")
    print("-" * 70)

    native = reader.get_native_sleep_stages()
    print(f"\n{'Metric':<20} {'Native':<15} {'SleepNet':<15}")
    print("-" * 50)
    print(f"{'Deep (min)':<20} {native.deep_minutes:<15.0f} {result.deep_seconds/60:<15.1f}")
    print(f"{'Light (min)':<20} {native.light_minutes:<15.0f} {result.light_seconds/60:<15.1f}")
    print(f"{'REM (min)':<20} {native.rem_minutes:<15.0f} {result.rem_seconds/60:<15.1f}")
    print(f"{'Awake (min)':<20} {native.awake_minutes:<15.0f} {result.awake_seconds/60:<15.1f}")

    print("\n" + "=" * 70)
    print("Test complete!")
    print("=" * 70)

    return 0


if __name__ == '__main__':
    sys.exit(main())
