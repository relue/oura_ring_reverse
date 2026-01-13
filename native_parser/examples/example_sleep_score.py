#!/usr/bin/env python3
"""
example_sleep_score.py - Demonstrate sleep score calculation

Shows how to calculate sleep scores using the native Oura library.
"""

import sys
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from oura_ecore import EcoreWrapper


def format_sleep_duration(minutes):
    """Format minutes as hours:minutes."""
    hours = minutes // 60
    mins = minutes % 60
    return f"{hours}h{mins:02d}m"


def print_sleep_analysis(title, result, sleep_data):
    """Print sleep score analysis."""
    print(f"\n{title}")
    print("=" * 70)

    print("\nInput Sleep Data:")
    print(f"  Total Sleep:    {format_sleep_duration(sleep_data['total'])}")
    print(f"  Deep Sleep:     {format_sleep_duration(sleep_data['deep'])} ({sleep_data['deep']/sleep_data['total']*100:.1f}%)")
    print(f"  REM Sleep:      {format_sleep_duration(sleep_data['rem'])} ({sleep_data['rem']/sleep_data['total']*100:.1f}%)")
    print(f"  Efficiency:     {sleep_data['efficiency']}%")
    print(f"  Latency:        {sleep_data['latency']} min")
    print(f"  Wake-ups:       {sleep_data['wakeups']}")
    print(f"  Awake Time:     {sleep_data['awake']//60} min")
    print(f"  Restless:       {sleep_data['restless']} periods")
    print(f"  Temp Deviation: {sleep_data['temp_dev']}°C")

    print(f"\n📊 Sleep Score: {result.score}/100")

    print("\nScore Contributors:")
    print(f"  Total Sleep:      {result.total_contrib}/100")
    print(f"  Efficiency:       {result.efficiency_contrib}/100")
    print(f"  Restfulness:      {result.restfulness_contrib}/100")
    print(f"  Deep Sleep:       {result.deep_contrib}/100")
    print(f"  Latency:          {result.latency_contrib}/100")
    print(f"  Timing:           {result.timing_contrib}/100")
    print(f"  Unknown (2):      {result.contrib2}/100")

    # Interpretation
    if result.score >= 85:
        rating = "Excellent 🌟"
    elif result.score >= 70:
        rating = "Good ✅"
    elif result.score >= 50:
        rating = "Fair ⚠️"
    else:
        rating = "Poor ❌"

    print(f"\nOverall Rating: {rating}")


def main():
    print("=" * 70)
    print("Sleep Score Calculation Examples")
    print("=" * 70)

    # Initialize wrapper
    print("\nInitializing EcoreWrapper...")
    ecore = EcoreWrapper()
    print("✅ Initialized\n")

    # Example 1: Excellent Sleep
    print("\n" + "=" * 70)
    print("Example 1: Excellent Sleep Night")
    print("=" * 70)

    excellent_sleep = {
        'total': 480,      # 8 hours
        'deep': 120,       # 25% (120 min)
        'rem': 120,        # 25% (120 min)
        'efficiency': 95,  # 95%
        'latency': 5,      # 5 min
        'wakeups': 1,
        'awake': 120,      # 2 min
        'restless': 2,
        'temp_dev': 0
    }

    result1 = ecore.calculate_sleep_score(
        total_sleep_min=excellent_sleep['total'],
        deep_sleep_min=excellent_sleep['deep'],
        rem_sleep_min=excellent_sleep['rem'],
        efficiency=excellent_sleep['efficiency'],
        latency_min=excellent_sleep['latency'],
        wakeup_count=excellent_sleep['wakeups'],
        awake_sec=excellent_sleep['awake'],
        restless_periods=excellent_sleep['restless'],
        temp_deviation=excellent_sleep['temp_dev']
    )

    print_sleep_analysis("Excellent Sleep Analysis", result1, excellent_sleep)

    # Example 2: Typical Sleep
    print("\n" + "=" * 70)
    print("Example 2: Typical Sleep Night")
    print("=" * 70)

    typical_sleep = {
        'total': 420,      # 7 hours
        'deep': 84,        # 20% (84 min)
        'rem': 105,        # 25% (105 min)
        'efficiency': 88,  # 88%
        'latency': 10,     # 10 min
        'wakeups': 2,
        'awake': 300,      # 5 min
        'restless': 4,
        'temp_dev': 0
    }

    result2 = ecore.calculate_sleep_score(
        total_sleep_min=typical_sleep['total'],
        deep_sleep_min=typical_sleep['deep'],
        rem_sleep_min=typical_sleep['rem'],
        efficiency=typical_sleep['efficiency'],
        latency_min=typical_sleep['latency'],
        wakeup_count=typical_sleep['wakeups'],
        awake_sec=typical_sleep['awake'],
        restless_periods=typical_sleep['restless'],
        temp_deviation=typical_sleep['temp_dev']
    )

    print_sleep_analysis("Typical Sleep Analysis", result2, typical_sleep)

    # Example 3: Poor Sleep
    print("\n" + "=" * 70)
    print("Example 3: Poor Sleep Night")
    print("=" * 70)

    poor_sleep = {
        'total': 300,      # 5 hours (short)
        'deep': 30,        # 10% (low)
        'rem': 45,         # 15% (low)
        'efficiency': 70,  # 70% (poor)
        'latency': 30,     # 30 min (poor)
        'wakeups': 8,      # Many wakeups
        'awake': 1800,     # 30 min awake
        'restless': 15,    # Very restless
        'temp_dev': 50     # Temperature issue
    }

    result3 = ecore.calculate_sleep_score(
        total_sleep_min=poor_sleep['total'],
        deep_sleep_min=poor_sleep['deep'],
        rem_sleep_min=poor_sleep['rem'],
        efficiency=poor_sleep['efficiency'],
        latency_min=poor_sleep['latency'],
        wakeup_count=poor_sleep['wakeups'],
        awake_sec=poor_sleep['awake'],
        restless_periods=poor_sleep['restless'],
        temp_deviation=poor_sleep['temp_dev']
    )

    print_sleep_analysis("Poor Sleep Analysis", result3, poor_sleep)

    # Comparison
    print("\n" + "=" * 70)
    print("Score Comparison")
    print("=" * 70)
    print(f"\nExcellent Sleep: {result1.score}/100")
    print(f"Typical Sleep:   {result2.score}/100")
    print(f"Poor Sleep:      {result3.score}/100")

    print("\n✅ All examples completed successfully!")


if __name__ == "__main__":
    main()
