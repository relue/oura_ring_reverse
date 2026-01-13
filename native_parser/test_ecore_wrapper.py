#!/usr/bin/env python3
"""
test_ecore_wrapper.py - Comprehensive test suite for EcoreWrapper

Tests all working native library bridges:
- IBI correction
- Daytime HR processing
- Sleep score calculation
"""

import sys
import unittest
from pathlib import Path

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent))

from oura_ecore import EcoreWrapper, IbiResult, HrResult, SleepScoreResult


class TestEcoreWrapper(unittest.TestCase):
    """Test suite for EcoreWrapper functionality."""

    @classmethod
    def setUpClass(cls):
        """Initialize EcoreWrapper once for all tests."""
        try:
            cls.ecore = EcoreWrapper()
            print(f"✅ EcoreWrapper initialized successfully")
        except Exception as e:
            print(f"❌ Failed to initialize EcoreWrapper: {e}")
            raise

    def test_01_ibi_correction_basic(self):
        """Test IBI correction with basic sample data."""
        print("\n🧪 Test 1: IBI Correction - Basic")

        # Sample IBI data: (timestamp_ms, ibi_ms, amplitude)
        test_data = [
            (1000000, 857, 12450),
            (1000857, 892, 11230),
            (1001749, 901, 11890),
            (1002650, 876, 12100),
            (1003526, 923, 11450),
        ]

        results = self.ecore.correct_ibi(test_data)

        # Verify we got results
        self.assertIsNotNone(results)
        self.assertGreater(len(results), 0)

        # Verify result structure
        for result in results:
            self.assertIsInstance(result, IbiResult)
            self.assertIsInstance(result.timestamp, int)
            self.assertIsInstance(result.ibi, int)
            self.assertIsInstance(result.amplitude, int)
            self.assertIn(result.validity, [0, 1, 2])  # Valid, Invalid, Interpolated

        print(f"✅ Processed {len(test_data)} samples → {len(results)} corrected")
        print(f"   Sample result: ts={results[0].timestamp}, ibi={results[0].ibi}, validity={results[0].validity}")

    def test_02_ibi_correction_with_outliers(self):
        """Test IBI correction with outlier values."""
        print("\n🧪 Test 2: IBI Correction - With Outliers")

        # Include an outlier (very high IBI)
        test_data = [
            (1000000, 857, 12450),
            (1000857, 892, 11230),
            (1001749, 2500, 5000),  # Outlier
            (1004249, 876, 12100),
            (1005125, 923, 11450),
        ]

        results = self.ecore.correct_ibi(test_data)

        # Check if outlier was marked invalid or interpolated
        validity_counts = {0: 0, 1: 0, 2: 0}
        for result in results:
            validity_counts[result.validity] += 1

        print(f"✅ Valid: {validity_counts[0]}, Invalid: {validity_counts[1]}, Interpolated: {validity_counts[2]}")

        # Should have some invalid or interpolated samples
        self.assertGreater(validity_counts[1] + validity_counts[2], 0)

    def test_03_daytime_hr_basic(self):
        """Test daytime HR processing with basic data."""
        print("\n🧪 Test 3: Daytime HR - Basic")

        test_data = [
            (1000000, 857, 12450),  # ~70 BPM
            (1000857, 892, 11230),  # ~67 BPM
            (1001749, 901, 11890),  # ~67 BPM
            (1002650, 876, 12100),  # ~68 BPM
            (1003526, 923, 11450),  # ~65 BPM
        ]

        results = self.ecore.process_daytime_hr(test_data)

        self.assertIsNotNone(results)
        self.assertGreater(len(results), 0)

        # Verify HR values are reasonable
        for result in results:
            self.assertIsInstance(result, HrResult)
            self.assertGreater(result.hr_bpm, 40)  # Minimum plausible HR
            self.assertLess(result.hr_bpm, 200)    # Maximum plausible HR

        avg_hr = sum(r.hr_bpm for r in results) / len(results)
        print(f"✅ Processed {len(test_data)} samples")
        print(f"   Average HR: {avg_hr:.1f} BPM")
        print(f"   Range: {min(r.hr_bpm for r in results)}-{max(r.hr_bpm for r in results)} BPM")

    def test_04_sleep_score_excellent(self):
        """Test sleep score calculation with excellent sleep."""
        print("\n🧪 Test 4: Sleep Score - Excellent Sleep")

        # 8 hours, excellent quality
        result = self.ecore.calculate_sleep_score(
            total_sleep_min=480,     # 8 hours
            deep_sleep_min=120,      # 25% (excellent)
            rem_sleep_min=120,       # 25% (excellent)
            efficiency=95,           # 95% (excellent)
            latency_min=5,           # 5 min (excellent)
            wakeup_count=1,          # Minimal wakeups
            awake_sec=120,           # 2 min awake
            restless_periods=2,      # Minimal restlessness
            temp_deviation=0         # Normal temp
        )

        self.assertIsInstance(result, SleepScoreResult)
        self.assertGreaterEqual(result.score, 75)  # Should be high
        self.assertLessEqual(result.score, 100)

        print(f"✅ Sleep Score: {result.score}/100")
        print(f"   Contributors: total={result.total_contrib}, efficiency={result.efficiency_contrib}, "
              f"deep={result.deep_contrib}, latency={result.latency_contrib}")

    def test_05_sleep_score_poor(self):
        """Test sleep score calculation with poor sleep."""
        print("\n🧪 Test 5: Sleep Score - Poor Sleep")

        # 5 hours, poor quality
        result = self.ecore.calculate_sleep_score(
            total_sleep_min=300,     # 5 hours (short)
            deep_sleep_min=30,       # 10% (low)
            rem_sleep_min=45,        # 15% (low)
            efficiency=70,           # 70% (poor)
            latency_min=30,          # 30 min (poor)
            wakeup_count=8,          # Many wakeups
            awake_sec=1800,          # 30 min awake
            restless_periods=15,     # Very restless
            temp_deviation=50        # Temp issue
        )

        self.assertIsInstance(result, SleepScoreResult)
        self.assertLess(result.score, 60)  # Should be low
        self.assertGreaterEqual(result.score, 0)

        print(f"✅ Sleep Score: {result.score}/100 (appropriately low)")
        print(f"   Contributors: total={result.total_contrib}, efficiency={result.efficiency_contrib}")

    def test_06_sleep_score_typical(self):
        """Test sleep score calculation with typical sleep."""
        print("\n🧪 Test 6: Sleep Score - Typical Sleep")

        # 7 hours, average quality
        result = self.ecore.calculate_sleep_score(
            total_sleep_min=420,     # 7 hours
            deep_sleep_min=84,       # 20%
            rem_sleep_min=105,       # 25%
            efficiency=88,           # 88%
            latency_min=10,          # 10 min
            wakeup_count=2,
            awake_sec=300,           # 5 min
            restless_periods=4,
            temp_deviation=0
        )

        self.assertIsInstance(result, SleepScoreResult)
        self.assertGreaterEqual(result.score, 40)
        self.assertLessEqual(result.score, 80)

        print(f"✅ Sleep Score: {result.score}/100 (typical range)")

    def test_07_sleep_score_edge_cases(self):
        """Test sleep score with edge case values."""
        print("\n🧪 Test 7: Sleep Score - Edge Cases")

        # Minimal sleep
        result_min = self.ecore.calculate_sleep_score(
            total_sleep_min=180,     # 3 hours (minimum)
            deep_sleep_min=20,
            rem_sleep_min=30,
            efficiency=50,
            latency_min=60,
            wakeup_count=15,
            awake_sec=3600,
            restless_periods=20,
            temp_deviation=100
        )

        self.assertGreaterEqual(result_min.score, 0)
        self.assertLessEqual(result_min.score, 100)
        print(f"✅ Minimal sleep: {result_min.score}/100")

        # Maximum sleep
        result_max = self.ecore.calculate_sleep_score(
            total_sleep_min=600,     # 10 hours (very long)
            deep_sleep_min=180,
            rem_sleep_min=180,
            efficiency=100,
            latency_min=0,
            wakeup_count=0,
            awake_sec=0,
            restless_periods=0,
            temp_deviation=0
        )

        self.assertGreaterEqual(result_max.score, 0)
        self.assertLessEqual(result_max.score, 100)
        print(f"✅ Maximum sleep: {result_max.score}/100")

    def test_08_error_handling(self):
        """Test error handling with invalid inputs."""
        print("\n🧪 Test 8: Error Handling")

        # Empty IBI data
        with self.assertRaises(Exception):
            self.ecore.correct_ibi([])
            print("❌ Should have raised exception for empty data")
        print("✅ Empty data handled correctly")

        # Invalid sleep score parameters (will still compute, but check it doesn't crash)
        try:
            result = self.ecore.calculate_sleep_score(
                total_sleep_min=-1,  # Invalid
                deep_sleep_min=0,
                rem_sleep_min=0,
                efficiency=0
            )
            print(f"✅ Invalid parameters handled: score={result.score}")
        except Exception as e:
            print(f"⚠️  Exception with invalid params (acceptable): {e}")

    def test_09_performance(self):
        """Test performance with larger datasets."""
        print("\n🧪 Test 9: Performance Test")

        import time

        # Generate larger dataset (1 hour of data at 1Hz)
        large_dataset = [
            (1000000 + i*1000, 857 + (i % 100), 12000 + (i % 2000))
            for i in range(3600)
        ]

        start = time.time()
        results = self.ecore.correct_ibi(large_dataset)
        elapsed = time.time() - start

        samples_per_sec = len(large_dataset) / elapsed
        print(f"✅ Processed {len(large_dataset)} samples in {elapsed:.2f}s")
        print(f"   Throughput: {samples_per_sec:.0f} samples/sec")

        self.assertLess(elapsed, 10.0)  # Should complete in reasonable time

    def test_10_unimplemented_functions(self):
        """Test that unimplemented functions raise appropriate errors."""
        print("\n🧪 Test 10: Unimplemented Functions")

        # Readiness score (blocked by struct complexity)
        with self.assertRaises(NotImplementedError):
            self.ecore.calculate_readiness_score({})
        print("✅ Readiness score correctly raises NotImplementedError")

        # Activity score (blocked by struct complexity)
        with self.assertRaises(NotImplementedError):
            self.ecore.calculate_activity_score({})
        print("✅ Activity score correctly raises NotImplementedError")


def run_tests():
    """Run all tests with detailed output."""
    print("=" * 70)
    print("EcoreWrapper Test Suite")
    print("=" * 70)

    # Create test suite
    loader = unittest.TestLoader()
    suite = loader.loadTestsFromTestCase(TestEcoreWrapper)

    # Run with detailed output
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)

    # Summary
    print("\n" + "=" * 70)
    print("Test Summary")
    print("=" * 70)
    print(f"Tests run: {result.testsRun}")
    print(f"Successes: {result.testsRun - len(result.failures) - len(result.errors)}")
    print(f"Failures: {len(result.failures)}")
    print(f"Errors: {len(result.errors)}")

    if result.wasSuccessful():
        print("\n✅ All tests passed!")
        return 0
    else:
        print("\n❌ Some tests failed")
        return 1


if __name__ == "__main__":
    sys.exit(run_tests())
