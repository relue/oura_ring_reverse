"""Oura Ring data analysis library.

High-level API for parsing and analyzing Oura Ring protobuf data.

Example:
    from oura import OuraAnalyzer

    analyzer = OuraAnalyzer("input_data/ring_data.pb")
    print(analyzer.dashboard.sleep_score)
    print(analyzer.hrv.average_rmssd)
"""

from oura.analyzer import OuraAnalyzer
from oura.data.reader import RingDataReader
from oura.data.models import (
    HeartRateData,
    SleepData,
    HRVData,
    TemperatureData,
    ActivityData,
    SpO2Data,
    MotionData,
    RingInfo,
    NativeSleepStages,
)
from oura.analysis.scores import (
    SleepScore,
    ReadinessScore,
    ActivityScore,
    StageDurations,
)
from oura.dashboard.api import Dashboard

__all__ = [
    "OuraAnalyzer",
    "RingDataReader",
    "Dashboard",
    "SleepScore",
    "ReadinessScore",
    "ActivityScore",
    "StageDurations",
    "HeartRateData",
    "SleepData",
    "HRVData",
    "TemperatureData",
    "ActivityData",
    "SpO2Data",
    "MotionData",
    "RingInfo",
    "NativeSleepStages",
]

__version__ = "0.1.0"
