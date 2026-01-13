#!/usr/bin/env python3
"""
example_daytime_hr.py - Demonstrate daytime HR processing

Shows how to process IBI data into heart rate measurements.
"""

import sys
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from oura_ecore import EcoreWrapper


def generate_sample_workout_data():
    """Generate sample IBI data representing a workout."""
    # Simulate a 10-minute workout with varying intensity
    data = []
    timestamp = 1704672000000

    # Resting (first 2 min): 60-70 BPM
    for i in range(120):
        ibi = 900 - (i % 100)  # ~67 BPM
        amp = 12000 + (i % 1000)
        data.append((timestamp, ibi, amp))
        timestamp += ibi

    # Warm-up (next 2 min): 70-90 BPM
    for i in range(120):
        ibi = 750 - (i % 80)  # ~80 BPM
        amp = 11000 + (i % 1500)
        data.append((timestamp, ibi, amp))
        timestamp += ibi

    # Peak effort (next 3 min): 140-160 BPM
    for i in range(180):
        ibi = 400 + (i % 40)  # ~150 BPM
        amp = 10000 + (i % 2000)
        data.append((timestamp, ibi, amp))
        timestamp += ibi

    # Cool-down (last 3 min): 100-120 BPM -> 70-80 BPM
    for i in range(180):
        ibi = 550 + i  # Gradually increasing IBI (decreasing HR)
        amp = 11000 + (i % 1000)
        data.append((timestamp, ibi, amp))
        timestamp += ibi

    return data


def analyze_hr_zones(hr_results):
    """Analyze time in different HR zones."""
    zones = {
        'Rest': (0, 70),
        'Light': (70, 100),
        'Moderate': (100, 130),
        'Hard': (130, 160),
        'Maximum': (160, 220)
    }

    zone_counts = {name: 0 for name in zones}

    for result in hr_results:
        for zone_name, (min_hr, max_hr) in zones.items():
            if min_hr <= result.hr_bpm < max_hr:
                zone_counts[zone_name] += 1
                break

    return zone_counts


def main():
    print("=" * 70)
    print("Daytime HR Processing Example")
    print("=" * 70)

    # Initialize wrapper
    print("\n1. Initializing EcoreWrapper...")
    ecore = EcoreWrapper()
    print("✅ Initialized")

    # Generate workout data
    print("\n2. Generating sample workout IBI data...")
    workout_data = generate_sample_workout_data()
    print(f"✅ Generated {len(workout_data)} IBI samples (~10 minutes)")

    # Process HR
    print("\n3. Processing IBI data to HR...")
    hr_results = ecore.process_daytime_hr(workout_data)
    print(f"✅ Processed {len(workout_data)} samples → {len(hr_results)} HR values")

    # Calculate statistics
    print("\n4. Heart Rate Statistics:")
    hr_values = [r.hr_bpm for r in hr_results]

    avg_hr = sum(hr_values) / len(hr_values)
    min_hr = min(hr_values)
    max_hr = max(hr_values)
    median_hr = sorted(hr_values)[len(hr_values) // 2]

    print(f"   Average HR:  {avg_hr:.1f} BPM")
    print(f"   Minimum HR:  {min_hr} BPM")
    print(f"   Maximum HR:  {max_hr} BPM")
    print(f"   Median HR:   {median_hr} BPM")

    # Analyze HR zones
    print("\n5. Time in HR Zones:")
    zone_counts = analyze_hr_zones(hr_results)

    for zone_name, count in zone_counts.items():
        percentage = (count / len(hr_results)) * 100
        bar_length = int(percentage / 2)  # Scale for display
        bar = "█" * bar_length
        print(f"   {zone_name:8s} ({zone_counts[zone_name]:3d} samples): "
              f"{bar:25s} {percentage:5.1f}%")

    # Show sample data points
    print("\n6. Sample HR Data Points:")
    print("   Time (min) | IBI (ms) | HR (BPM) | Quality")
    print("   " + "-" * 50)

    sample_indices = [0, len(hr_results)//4, len(hr_results)//2,
                      3*len(hr_results)//4, len(hr_results)-1]

    for idx in sample_indices:
        if idx < len(hr_results):
            r = hr_results[idx]
            time_sec = (r.timestamp - hr_results[0].timestamp) / 1000
            time_min = time_sec / 60
            print(f"   {time_min:9.1f} | {r.ibi:8d} | {r.hr_bpm:8d} | {r.quality:7d}")

    # Workout summary
    print("\n7. Workout Summary:")
    resting_hr = sum(r.hr_bpm for r in hr_results[:120]) / 120
    peak_hr = max_hr
    recovery_hr = sum(r.hr_bpm for r in hr_results[-60:]) / 60

    print(f"   Resting HR:  {resting_hr:.1f} BPM (first 2 min)")
    print(f"   Peak HR:     {peak_hr} BPM")
    print(f"   Recovery HR: {recovery_hr:.1f} BPM (last 1 min)")
    print(f"   HR Reserve:  {peak_hr - resting_hr:.0f} BPM")

    print("\n" + "=" * 70)
    print("✅ Example complete!")
    print("=" * 70)


if __name__ == "__main__":
    main()
