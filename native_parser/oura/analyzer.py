"""
Oura Analyzer

Main entry point for Oura Ring data analysis.
"""

from __future__ import annotations

from typing import Dict, Any, Optional
from pathlib import Path

from oura.data.reader import RingDataReader
from oura.analysis.sleep import SleepAnalyzer
from oura.analysis.hrv import HRVAnalyzer
from oura.dashboard.api import Dashboard


class OuraAnalyzer:
    """High-level analyzer for Oura Ring data.

    This is the main entry point for the oura library. It provides
    convenient access to all analysis functions and dashboard data.

    Example:
        from oura import OuraAnalyzer

        analyzer = OuraAnalyzer("ring_data.pb")

        # Dashboard overview
        print(analyzer.dashboard.sleep_score)
        print(analyzer.dashboard.hrv_average)

        # Detailed analysis
        print(analyzer.sleep.stages)
        print(analyzer.hrv.by_sleep_stage())

        # Raw data access
        print(analyzer.raw.heart_rate.ibi_ms)

    Attributes:
        raw: RingDataReader for raw protobuf data access
        sleep: SleepAnalyzer for sleep-specific analysis
        hrv: HRVAnalyzer for HRV-specific analysis
        dashboard: Dashboard with aggregated metrics
    """

    def __init__(self, pb_path: str):
        """Initialize analyzer with protobuf file.

        Args:
            pb_path: Path to ring_data.pb file
        """
        self._path = Path(pb_path)
        self._reader = RingDataReader(pb_path)

        # Lazy-loaded analyzers
        self._sleep: Optional[SleepAnalyzer] = None
        self._hrv: Optional[HRVAnalyzer] = None
        self._dashboard: Optional[Dashboard] = None

    @property
    def raw(self) -> RingDataReader:
        """Access raw protobuf data through RingDataReader."""
        return self._reader

    @property
    def sleep(self) -> SleepAnalyzer:
        """Sleep analysis functions."""
        if self._sleep is None:
            self._sleep = SleepAnalyzer(self._reader)
        return self._sleep

    @property
    def hrv(self) -> HRVAnalyzer:
        """HRV analysis functions."""
        if self._hrv is None:
            self._hrv = HRVAnalyzer(self._reader)
        return self._hrv

    @property
    def dashboard(self) -> Dashboard:
        """Dashboard with aggregated metrics."""
        if self._dashboard is None:
            self._dashboard = Dashboard.from_reader(self._reader)
        return self._dashboard

    def summary(self) -> str:
        """Generate a complete summary of all data."""
        return self.dashboard.summary()

    def to_dict(self) -> Dict[str, Any]:
        """Convert all analysis results to dictionary."""
        return {
            "file": str(self._path),
            "dashboard": self.dashboard.to_dict(),
            "sleep": self.sleep.to_dict(),
            "hrv": self.hrv.to_dict(),
            "raw_summary": {
                "fields_present": self._reader.fields_present,
                "heart_rate_samples": self._reader.heart_rate.sample_count,
                "hrv_samples": self._reader.hrv.sample_count,
                "sleep_samples": self._reader.sleep.total_samples,
            },
        }

    def to_json(self, indent: int = 2) -> str:
        """Convert all analysis results to JSON."""
        import json
        return json.dumps(self.to_dict(), indent=indent)

    def __repr__(self) -> str:
        return f"OuraAnalyzer('{self._path}')"
