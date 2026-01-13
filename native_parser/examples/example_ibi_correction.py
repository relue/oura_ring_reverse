#!/usr/bin/env python3
"""
example_ibi_correction.py - Demonstrate IBI correction functionality

Shows how to use the native Oura library to correct raw IBI measurements.
"""

import sys
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from oura_ecore import EcoreWrapper


def main():
    print("=" * 70)
    print("IBI Correction Example")
    print("=" * 70)

    # Initialize wrapper
    print("\n1. Initializing EcoreWrapper...")
    ecore = EcoreWrapper()
    print("✅ Initialized")

    # Sample IBI data from ring
    # Format: (timestamp_ms, ibi_ms, amplitude)
    print("\n2. Sample IBI data (raw from ring):")
    raw_ibi_data = [
        (1704672000000, 857, 12450),  # Normal beat
        (1704672000857, 892, 11230),  # Normal beat
        (1704672001749, 2500, 3000),  # Outlier (missed beat or error)
        (1704672004249, 876, 12100),  # Normal beat
        (1704672005125, 923, 11450),  # Normal beat
        (1704672006048, 901, 11890),  # Normal beat
        (1704672006949, 850, 12200),  # Normal beat
    ]

    for ts, ibi, amp in raw_ibi_data:
        hr = 60000 // ibi if ibi > 0 else 0
        print(f"   {ts}: IBI={ibi}ms ({hr} BPM), Amplitude={amp}")

    # Run correction
    print("\n3. Running native IBI correction...")
    corrected = ecore.correct_ibi(raw_ibi_data)
    print(f"✅ Corrected {len(raw_ibi_data)} samples → {len(corrected)} results")

    # Display results
    print("\n4. Corrected Results:")
    print("   Timestamp          | IBI (ms) | HR (BPM) | Amplitude | Validity")
    print("   " + "-" * 70)

    for result in corrected:
        hr = 60000 // result.ibi if result.ibi > 0 else 0
        validity_str = {
            0: "Valid",
            1: "Invalid",
            2: "Interpolated"
        }.get(result.validity, "Unknown")

        print(f"   {result.timestamp:15d} | {result.ibi:8d} | {hr:8d} | "
              f"{result.amplitude:9d} | {validity_str}")

    # Analysis
    print("\n5. Analysis:")
    valid_count = sum(1 for r in corrected if r.validity == 0)
    invalid_count = sum(1 for r in corrected if r.validity == 1)
    interpolated_count = sum(1 for r in corrected if r.validity == 2)

    print(f"   Valid samples:        {valid_count}")
    print(f"   Invalid samples:      {invalid_count}")
    print(f"   Interpolated samples: {interpolated_count}")

    # Calculate average HR from valid samples
    valid_hrs = [60000 // r.ibi for r in corrected if r.validity == 0 and r.ibi > 0]
    if valid_hrs:
        avg_hr = sum(valid_hrs) / len(valid_hrs)
        print(f"\n   Average HR (valid samples): {avg_hr:.1f} BPM")
        print(f"   HR Range: {min(valid_hrs)}-{max(valid_hrs)} BPM")

    print("\n" + "=" * 70)
    print("✅ Example complete!")
    print("=" * 70)


if __name__ == "__main__":
    main()
