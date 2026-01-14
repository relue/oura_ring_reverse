"""
FastAPI Backend for Oura Ring Data Dashboard

Provides REST API endpoints for:
- Raw ring data browsing
- Sleep analysis
- Exercise/activity data
- Heart rate and stress metrics
"""

import sys
from pathlib import Path
from datetime import datetime
from typing import Optional, List, Dict, Any

from fastapi import FastAPI, HTTPException, Query, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

# Use high-level OuraAnalyzer API
from oura import OuraAnalyzer
from oura.data.reader import RingDataReader
from oura.analysis.hrv import HRVAnalyzer
from oura.analysis.sleep import SleepAnalyzer

# BLE handler for WebSocket communication
from ble_handler import get_ble_manager, BLEConnectionManager
from oura.ble.bonding import list_bluetooth_adapters

app = FastAPI(
    title="Oura Ring Data API",
    description="API for accessing and analyzing Oura Ring data",
    version="1.0.0"
)

# Enable CORS for React frontend
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "http://localhost:5173", "http://localhost:5174", "http://localhost:5175"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Global analyzer (loaded once) - provides high-level API
INPUT_DIR = Path(__file__).parent.parent.parent / "input_data"
DATA_FILE = INPUT_DIR / "ring_data.pb"
_analyzer: Optional[OuraAnalyzer] = None
_reader: Optional[RingDataReader] = None


def get_analyzer() -> OuraAnalyzer:
    """Get or create the OuraAnalyzer (high-level API)."""
    global _analyzer
    if _analyzer is None:
        if not DATA_FILE.exists():
            raise HTTPException(status_code=404, detail=f"Data file not found: {DATA_FILE}")
        _analyzer = OuraAnalyzer(str(DATA_FILE))
    return _analyzer


def get_reader() -> RingDataReader:
    """Get the raw data reader with real UTC timestamps.

    Uses events file for real timestamps when available.
    """
    global _reader
    if _reader is None:
        if not DATA_FILE.exists():
            raise HTTPException(status_code=404, detail=f"Data file not found: {DATA_FILE}")

        # Protobuf has UTC timestamps from preprocessing
        _reader = RingDataReader(str(DATA_FILE))
        print(f"[Backend] Loaded {DATA_FILE.name}")

    return _reader


# ============== Pydantic Models ==============

class RingInfo(BaseModel):
    ring_type: int
    firmware_version: str
    hardware_version: str
    serial_number: str
    bootloader_version: str


class DataSummary(BaseModel):
    heart_rate_samples: int
    sleep_samples: int
    temperature_samples: int
    hrv_samples: int
    spo2_samples: int
    activity_samples: int
    motion_samples: int
    ring_info: RingInfo


class HeartRateSample(BaseModel):
    timestamp: int
    ibi_ms: int
    amplitude: int
    bpm: float


class HeartRateData(BaseModel):
    sample_count: int
    average_bpm: float
    min_bpm: float
    max_bpm: float
    samples: List[HeartRateSample]


class SleepSample(BaseModel):
    timestamp: int
    average_hr: float
    breath_rate: float
    motion_count: int
    sleep_state: int
    rmssd_5min: float


class SleepData(BaseModel):
    total_samples: int
    duration_hours: float
    average_heart_rate: float
    average_breath_rate: float
    samples: List[SleepSample]


class TemperatureSample(BaseModel):
    timestamp: int
    temp_celsius: float


class TemperatureData(BaseModel):
    sample_count: int
    average_celsius: float
    min_celsius: float
    max_celsius: float
    samples: List[TemperatureSample]


class HRVSample(BaseModel):
    timestamp: int
    rmssd_ms: float
    coverage: float


class HRVData(BaseModel):
    sample_count: int
    average_rmssd: float
    samples: List[HRVSample]


class ActivitySample(BaseModel):
    timestamp: int
    met: float
    met_minutes: float
    steps: int
    calories: float


class ActivityData(BaseModel):
    sample_count: int
    total_steps: int
    total_calories: float
    total_met_minutes: float
    samples: List[ActivitySample]


class MotionSample(BaseModel):
    timestamp: int
    orientation: int
    motion_seconds: int
    avg_x: float
    avg_y: float
    avg_z: float


class MotionData(BaseModel):
    sample_count: int
    total_motion_seconds: int
    samples: List[MotionSample]


class SpO2Sample(BaseModel):
    timestamp: int
    spo2_percent: float
    state: int


class SpO2Data(BaseModel):
    sample_count: int
    average_spo2: float
    samples: List[SpO2Sample]


# ============== API Endpoints ==============

@app.get("/")
async def root():
    """API root endpoint."""
    return {
        "name": "Oura Ring Data API",
        "version": "1.0.0",
        "endpoints": [
            "/summary",
            "/raw/heart-rate",
            "/raw/sleep",
            "/raw/temperature",
            "/raw/hrv",
            "/raw/activity",
            "/raw/motion",
            "/raw/spo2",
            "/dashboard/sleep",
            "/dashboard/sleep-stages",
            "/dashboard/hrv",
            "/dashboard/activity",
            "/dashboard/stress-hr",
        ]
    }


@app.get("/summary", response_model=DataSummary)
async def get_summary():
    """Get summary of available data."""
    reader = get_reader()

    ring_info = RingInfo(
        ring_type=reader.ring_info.ring_type,
        firmware_version=reader.ring_info.firmware_version,
        hardware_version=reader.ring_info.hardware_version,
        serial_number=reader.ring_info.serial_number,
        bootloader_version=reader.ring_info.bootloader_version,
    )

    return DataSummary(
        heart_rate_samples=reader.heart_rate.sample_count,
        sleep_samples=reader.sleep.total_samples,
        temperature_samples=reader.temperature.sample_count,
        hrv_samples=reader.hrv.sample_count,
        spo2_samples=reader.spo2.sample_count,
        activity_samples=reader.activity.sample_count,
        motion_samples=reader.motion.sample_count,
        ring_info=ring_info,
    )


@app.get("/raw/heart-rate", response_model=HeartRateData)
async def get_heart_rate(
    limit: int = Query(default=1000, ge=1, le=50000),
    offset: int = Query(default=0, ge=0)
):
    """Get raw heart rate / IBI data."""
    reader = get_reader()
    hr = reader.heart_rate

    samples = []
    end = min(offset + limit, hr.sample_count)
    for i in range(offset, end):
        ibi = hr.ibi_ms[i] if i < len(hr.ibi_ms) else 0
        bpm = 60000 / ibi if ibi > 0 else 0
        samples.append(HeartRateSample(
            timestamp=hr.timestamps[i] if i < len(hr.timestamps) else 0,
            ibi_ms=ibi,
            amplitude=hr.amplitudes[i] if i < len(hr.amplitudes) else 0,
            bpm=round(bpm, 1),
        ))

    return HeartRateData(
        sample_count=hr.sample_count,
        average_bpm=round(hr.average_bpm, 1),
        min_bpm=round(hr.min_bpm, 1),
        max_bpm=round(hr.max_bpm, 1),
        samples=samples,
    )


@app.get("/raw/sleep", response_model=SleepData)
async def get_sleep(
    limit: int = Query(default=500, ge=1, le=5000),
    offset: int = Query(default=0, ge=0)
):
    """Get raw sleep data."""
    reader = get_reader()
    sleep = reader.sleep

    samples = []
    end = min(offset + limit, sleep.total_samples)
    for i in range(offset, end):
        samples.append(SleepSample(
            timestamp=sleep.timestamps[i] if i < len(sleep.timestamps) else 0,
            average_hr=sleep.average_hr[i] if i < len(sleep.average_hr) else 0,
            breath_rate=sleep.breath_rate[i] if i < len(sleep.breath_rate) else 0,
            motion_count=sleep.motion_count[i] if i < len(sleep.motion_count) else 0,
            sleep_state=sleep.sleep_state[i] if i < len(sleep.sleep_state) else 0,
            rmssd_5min=sleep.rmssd_5min[i] if i < len(sleep.rmssd_5min) else 0,
        ))

    return SleepData(
        total_samples=sleep.total_samples,
        duration_hours=round(sleep.duration_hours, 2),
        average_heart_rate=round(sleep.average_heart_rate, 1),
        average_breath_rate=round(sleep.average_breath_rate, 1),
        samples=samples,
    )


@app.get("/raw/temperature", response_model=TemperatureData)
async def get_temperature(
    limit: int = Query(default=500, ge=1, le=5000),
    offset: int = Query(default=0, ge=0)
):
    """Get raw temperature data."""
    reader = get_reader()
    temp = reader.temperature

    samples = []
    end = min(offset + limit, temp.sample_count)
    for i in range(offset, end):
        samples.append(TemperatureSample(
            timestamp=temp.timestamps[i] if i < len(temp.timestamps) else 0,
            temp_celsius=round(temp.temp_celsius[i], 2) if i < len(temp.temp_celsius) else 0,
        ))

    return TemperatureData(
        sample_count=temp.sample_count,
        average_celsius=round(temp.average_celsius, 2),
        min_celsius=round(temp.min_celsius, 2),
        max_celsius=round(temp.max_celsius, 2),
        samples=samples,
    )


@app.get("/raw/hrv", response_model=HRVData)
async def get_hrv(
    limit: int = Query(default=500, ge=1, le=5000),
    offset: int = Query(default=0, ge=0)
):
    """Get raw HRV data."""
    reader = get_reader()
    hrv = reader.hrv

    samples = []
    end = min(offset + limit, hrv.sample_count)
    for i in range(offset, end):
        samples.append(HRVSample(
            timestamp=hrv.timestamps[i] if i < len(hrv.timestamps) else 0,
            rmssd_ms=round(hrv.average_rmssd_5min[i], 2) if i < len(hrv.average_rmssd_5min) else 0,
            coverage=1.0,  # Not available in data
        ))

    return HRVData(
        sample_count=hrv.sample_count,
        average_rmssd=round(hrv.average_rmssd, 2),
        samples=samples,
    )


@app.get("/raw/activity", response_model=ActivityData)
async def get_activity(
    limit: int = Query(default=500, ge=1, le=5000),
    offset: int = Query(default=0, ge=0)
):
    """Get raw activity data."""
    reader = get_reader()
    act = reader.activity

    samples = []
    end = min(offset + limit, act.sample_count)
    for i in range(offset, end):
        samples.append(ActivitySample(
            timestamp=act.timestamps[i] if i < len(act.timestamps) else 0,
            met=0.0,  # Not directly available
            met_minutes=0.0,  # Not directly available
            steps=act.step_count[i] if i < len(act.step_count) else 0,
            calories=0.0,  # Not directly available
        ))

    return ActivityData(
        sample_count=act.sample_count,
        total_steps=act.total_steps,
        total_calories=0.0,  # Not available
        total_met_minutes=0.0,  # Not available
        samples=samples,
    )


@app.get("/raw/motion", response_model=MotionData)
async def get_motion(
    limit: int = Query(default=500, ge=1, le=5000),
    offset: int = Query(default=0, ge=0)
):
    """Get raw motion data."""
    reader = get_reader()
    motion = reader.motion

    samples = []
    end = min(offset + limit, motion.sample_count)
    for i in range(offset, end):
        samples.append(MotionSample(
            timestamp=motion.timestamps[i] if i < len(motion.timestamps) else 0,
            orientation=motion.orientation[i] if i < len(motion.orientation) else 0,
            motion_seconds=motion.motion_seconds[i] if i < len(motion.motion_seconds) else 0,
            avg_x=round(motion.average_x[i], 4) if i < len(motion.average_x) else 0,
            avg_y=round(motion.average_y[i], 4) if i < len(motion.average_y) else 0,
            avg_z=round(motion.average_z[i], 4) if i < len(motion.average_z) else 0,
        ))

    return MotionData(
        sample_count=motion.sample_count,
        total_motion_seconds=motion.total_motion_seconds,
        samples=samples,
    )


@app.get("/raw/spo2", response_model=SpO2Data)
async def get_spo2(
    limit: int = Query(default=500, ge=1, le=5000),
    offset: int = Query(default=0, ge=0)
):
    """Get raw SpO2 data."""
    reader = get_reader()
    spo2 = reader.spo2

    samples = []
    end = min(offset + limit, spo2.sample_count)
    for i in range(offset, end):
        samples.append(SpO2Sample(
            timestamp=spo2.timestamps[i] if i < len(spo2.timestamps) else 0,
            spo2_percent=round(spo2.spo2_percent[i], 1) if i < len(spo2.spo2_percent) else 0,
            state=spo2.state[i] if i < len(spo2.state) else 0,
        ))

    return SpO2Data(
        sample_count=spo2.sample_count,
        average_spo2=round(spo2.average_spo2, 1),
        samples=samples,
    )


# ============== Nights Browser ==============

class NightInfo(BaseModel):
    index: int
    start_timestamp: int
    end_timestamp: int
    start_time: str
    end_time: str
    date: str
    duration_hours: float


class NightsResponse(BaseModel):
    nights: List[NightInfo]
    total: int
    selected: int


@app.get("/nights", response_model=NightsResponse)
async def get_nights(selected: int = Query(default=-1, description="Selected night index (-1 = last)")):
    """Get list of all available sleep nights (bedtime periods).

    Returns all nights sorted by date with the selected one marked.
    """
    reader = get_reader()
    rd = reader.raw

    nights = []
    if rd.HasField('bedtime_period'):
        bp = rd.bedtime_period
        # Get unique bedtime periods
        periods = set()
        for i in range(len(bp.bedtime_start)):
            periods.add((bp.bedtime_start[i], bp.bedtime_end[i]))

        sorted_periods = sorted(periods)

        for idx, (start_ms, end_ms) in enumerate(sorted_periods):
            start_dt = datetime.fromtimestamp(start_ms / 1000)
            end_dt = datetime.fromtimestamp(end_ms / 1000)
            duration = (end_ms - start_ms) / 1000 / 3600

            nights.append(NightInfo(
                index=idx,
                start_timestamp=start_ms,
                end_timestamp=end_ms,
                start_time=start_dt.strftime("%H:%M"),
                end_time=end_dt.strftime("%H:%M"),
                date=start_dt.strftime("%Y-%m-%d"),
                duration_hours=round(duration, 1),
            ))

    # Resolve selected index (-1 means last)
    resolved_selected = selected
    if selected == -1 and nights:
        resolved_selected = len(nights) - 1

    return NightsResponse(
        nights=nights,
        total=len(nights),
        selected=resolved_selected,
    )


# ============== Dashboard Endpoints ==============

class SleepDashboard(BaseModel):
    total_sleep_minutes: float
    sleep_efficiency: float
    average_hr_during_sleep: float
    average_hrv_during_sleep: float
    average_breath_rate: float
    deep_sleep_percent: float
    light_sleep_percent: float
    rem_sleep_percent: float
    awake_percent: float
    hypnogram: List[Dict[str, Any]]
    hr_trend: List[Dict[str, Any]]
    hrv_trend: List[Dict[str, Any]]


@app.get("/dashboard/sleep", response_model=SleepDashboard)
async def get_sleep_dashboard(
    night: int = Query(default=-1, description="Night index (-1 = last/most recent)")
):
    """Get sleep dashboard data using high-level SleepAnalyzer.

    Uses SleepAnalyzer which automatically handles ML inference when available.
    """
    reader = get_reader()
    sleep_analyzer = SleepAnalyzer(reader, night_index=night)  # ML with night selection
    raw_sleep = reader.sleep  # Raw data for HR/HRV trends

    # Get ML-aware stage durations
    durations = sleep_analyzer.stage_durations
    total_time = durations.total_time

    # Calculate percentages from ML-aware durations
    deep_pct = round(100 * durations.deep / total_time, 1) if total_time > 0 else 0
    light_pct = round(100 * durations.light / total_time, 1) if total_time > 0 else 0
    rem_pct = round(100 * durations.rem / total_time, 1) if total_time > 0 else 0
    awake_pct = round(100 * durations.awake / total_time, 1) if total_time > 0 else 0

    print(f"[dashboard/sleep] Using ML: {sleep_analyzer.uses_ml}")
    print(f"[dashboard/sleep] Deep={deep_pct}%, Light={light_pct}%, REM={rem_pct}%, Awake={awake_pct}%")

    # Build hypnogram from ML-aware stages
    stages = sleep_analyzer.stages
    hypnogram = []
    for i, stage in enumerate(stages):
        # Standard encoding: 0=Awake, 1=Light, 2=Deep, 3=REM
        hypnogram.append({
            "epoch": i,
            "state": int(stage),
            "state_name": ["Awake", "Light", "Deep", "REM"][int(stage)] if int(stage) < 4 else "Unknown",
        })

    # HR trend during sleep
    hr_trend = []
    for i, hr in enumerate(raw_sleep.average_hr[:100]):
        hr_trend.append({"epoch": i, "hr": round(hr, 1)})

    # HRV trend during sleep
    hrv_trend = []
    for i, hrv in enumerate(raw_sleep.rmssd_5min[:100]):
        hrv_trend.append({"epoch": i, "hrv": round(hrv, 1)})

    return SleepDashboard(
        total_sleep_minutes=durations.total_sleep,
        sleep_efficiency=durations.efficiency,
        average_hr_during_sleep=round(raw_sleep.average_heart_rate, 1),
        average_hrv_during_sleep=round(sum(raw_sleep.rmssd_5min) / len(raw_sleep.rmssd_5min), 1) if raw_sleep.rmssd_5min else 0,
        average_breath_rate=round(raw_sleep.average_breath_rate, 1),
        deep_sleep_percent=deep_pct,
        light_sleep_percent=light_pct,
        rem_sleep_percent=rem_pct,
        awake_percent=awake_pct,
        hypnogram=hypnogram,
        hr_trend=hr_trend,
        hrv_trend=hrv_trend,
    )


class ActivityDashboard(BaseModel):
    total_steps: int
    total_calories: float
    total_met_minutes: float
    active_hours: int
    steps_per_hour: List[Dict[str, Any]]
    calories_per_hour: List[Dict[str, Any]]


@app.get("/dashboard/activity", response_model=ActivityDashboard)
async def get_activity_dashboard():
    """Get activity dashboard data."""
    reader = get_reader()
    act = reader.activity

    # Aggregate by hour (assuming 5-min epochs)
    epochs_per_hour = 12
    steps_per_hour = []
    calories_per_hour = []

    for hour in range(min(24, max(1, act.sample_count // epochs_per_hour))):
        start_idx = hour * epochs_per_hour
        end_idx = min(start_idx + epochs_per_hour, act.sample_count)

        hour_steps = sum(act.step_count[start_idx:end_idx]) if act.step_count else 0
        hour_calories = 0  # Not available

        steps_per_hour.append({"hour": hour, "steps": hour_steps})
        calories_per_hour.append({"hour": hour, "calories": round(hour_calories, 1)})

    active_hours = len([s for s in steps_per_hour if s["steps"] > 100])

    return ActivityDashboard(
        total_steps=act.total_steps,
        total_calories=0.0,  # Not available
        total_met_minutes=0.0,  # Not available
        active_hours=active_hours,
        steps_per_hour=steps_per_hour,
        calories_per_hour=calories_per_hour,
    )


class StressHRDashboard(BaseModel):
    current_hr: float
    resting_hr: float
    max_hr: float
    average_hrv: float
    hrv_trend: str  # "up", "down", "stable"
    stress_level: str  # "low", "moderate", "high"
    hr_samples: List[Dict[str, Any]]
    hrv_samples: List[Dict[str, Any]]


@app.get("/dashboard/stress-hr", response_model=StressHRDashboard)
async def get_stress_hr_dashboard():
    """Get stress and heart rate dashboard data."""
    reader = get_reader()
    hr = reader.heart_rate
    hrv = reader.hrv

    # HR samples (downsample to 100 points)
    hr_samples = []
    step = max(1, hr.sample_count // 100)
    for i in range(0, min(100 * step, hr.sample_count), step):
        ibi = hr.ibi_ms[i]
        bpm = 60000 / ibi if ibi > 0 else 0
        hr_samples.append({
            "index": i,
            "timestamp": hr.timestamps[i] if i < len(hr.timestamps) else 0,
            "bpm": round(bpm, 1),
        })

    # HRV samples
    hrv_samples = []
    rmssd_data = hrv.average_rmssd_5min[:100] if hrv.average_rmssd_5min else []
    for i, rmssd in enumerate(rmssd_data):
        hrv_samples.append({
            "index": i,
            "timestamp": hrv.timestamps[i] if i < len(hrv.timestamps) else 0,
            "rmssd": round(rmssd, 1),
        })

    # Calculate HRV trend (compare first half to second half)
    avg_hrv = hrv.average_rmssd
    rmssd_list = hrv.average_rmssd_5min
    if len(rmssd_list) > 10:
        first_half = sum(rmssd_list[:len(rmssd_list)//2]) / (len(rmssd_list)//2)
        second_half = sum(rmssd_list[len(rmssd_list)//2:]) / (len(rmssd_list) - len(rmssd_list)//2)
        if second_half > first_half * 1.1:
            hrv_trend = "up"
        elif second_half < first_half * 0.9:
            hrv_trend = "down"
        else:
            hrv_trend = "stable"
    else:
        hrv_trend = "stable"

    # Estimate stress level from HRV (simplified)
    if avg_hrv > 50:
        stress_level = "low"
    elif avg_hrv > 30:
        stress_level = "moderate"
    else:
        stress_level = "high"

    return StressHRDashboard(
        current_hr=round(hr.average_bpm, 1),
        resting_hr=round(hr.min_bpm, 1),
        max_hr=round(hr.max_bpm, 1),
        average_hrv=round(avg_hrv, 1),
        hrv_trend=hrv_trend,
        stress_level=stress_level,
        hr_samples=hr_samples,
        hrv_samples=hrv_samples,
    )


# ============== New Dashboard Endpoints ==============

class HRVDashboard(BaseModel):
    average_rmssd: float
    min_rmssd: float
    max_rmssd: float
    sample_count: int
    samples_5min: List[Dict[str, Any]]
    by_sleep_stage: Dict[str, float]


@app.get("/dashboard/hrv", response_model=HRVDashboard)
async def get_hrv_dashboard():
    """Get detailed HRV dashboard data with 5-min samples and by-stage breakdown.

    Uses high-level HRVAnalyzer from OuraAnalyzer.
    """
    analyzer = get_analyzer()
    hrv_analyzer = analyzer.hrv  # High-level API
    hrv_data = analyzer.raw.hrv  # Raw data for timestamps

    # Get 5-min samples with timestamps
    samples_5min = []
    timestamps = hrv_data.timestamps
    rmssd_values = hrv_data.average_rmssd_5min

    for i, (ts, rmssd) in enumerate(zip(timestamps, rmssd_values)):
        # Convert timestamp to readable time
        try:
            dt = datetime.fromtimestamp(ts / 1000)  # Convert ms to seconds
            time_str = dt.strftime("%H:%M")
        except:
            time_str = f"Sample {i}"

        samples_5min.append({
            "index": i,
            "timestamp": ts,
            "rmssd": round(rmssd, 1),
            "time": time_str,
        })

    # Get HRV by sleep stage
    by_stage = hrv_analyzer.by_sleep_stage()

    return HRVDashboard(
        average_rmssd=round(hrv_analyzer.average_rmssd, 1),
        min_rmssd=round(hrv_analyzer.min_rmssd, 1),
        max_rmssd=round(hrv_analyzer.max_rmssd, 1),
        sample_count=hrv_data.sample_count,
        samples_5min=samples_5min,
        by_sleep_stage={k: round(v, 1) for k, v in by_stage.items()},
    )


class SleepScoreResponse(BaseModel):
    score: int
    total_sleep: int
    efficiency: int
    restfulness: int
    rem_sleep: int
    deep_sleep: int
    latency: int
    timing: int


class SleepStagesDashboard(BaseModel):
    night_index: int
    night_date: str
    epochs: List[Dict[str, Any]]
    durations: Dict[str, float]
    hypnogram_data: List[Dict[str, Any]]
    stage_mapping: Dict[str, str]
    score: SleepScoreResponse
    bedtime_start: str
    bedtime_end: str


@app.get("/dashboard/sleep-stages", response_model=SleepStagesDashboard)
async def get_sleep_stages_dashboard(
    night: int = Query(default=-1, description="Night index (-1 = last/most recent)")
):
    """Get detailed sleep stages data with timestamps for hypnogram.

    Uses the high-level SleepAnalyzer which automatically uses SleepNet ML
    for proper REM classification when available.
    Timestamps come from ring_events.txt via time sync for real UTC times.
    """
    reader = get_reader()  # Reader with real UTC timestamps
    sleep_analyzer = SleepAnalyzer(reader, night_index=night)  # ML with night selection

    # Display stage mapping: 0=Deep, 1=Light, 2=REM, 3=Awake (for hypnogram Y-axis)
    # SleepAnalyzer returns: 0=Awake, 1=Light, 2=Deep, 3=REM
    stage_names = {0: "Deep", 1: "Light", 2: "REM", 3: "Awake"}
    stage_colors = {0: "#6366f1", 1: "#3b82f6", 2: "#a855f7", 3: "#ef4444"}
    standard_to_display = {0: 3, 1: 1, 2: 0, 3: 2}  # awake→3, light→1, deep→0, rem→2

    print(f"[sleep-stages] Using ML: {sleep_analyzer.uses_ml}")

    # Get stages AND timestamps from SleepAnalyzer (both from ML model)
    # This ensures stages and timestamps are aligned (same source)
    stages = sleep_analyzer.stages
    ml_timestamps = sleep_analyzer.timestamps  # Unix seconds from SleepNet

    # Convert ML timestamps (seconds) to milliseconds for API
    sleep_timestamps = [int(ts * 1000) for ts in ml_timestamps]
    epochs = []

    n_epochs = len(stages)
    print(f"[sleep-stages] ML epochs: {n_epochs}, timestamps: {len(sleep_timestamps)}")

    # Calculate time increment for interpolating missing timestamps
    if sleep_timestamps and len(sleep_timestamps) >= 2:
        epoch_duration_ms = 30 * 1000  # 30 seconds per epoch
        first_ts = sleep_timestamps[0]
    else:
        epoch_duration_ms = 30 * 1000
        first_ts = 0

    for i in range(n_epochs):
        stage = stages[i] if i < len(stages) else 0

        # Use real UTC timestamp from events file (in milliseconds)
        if i < len(sleep_timestamps):
            ts_ms = sleep_timestamps[i]
        else:
            # Interpolate for any missing timestamps
            ts_ms = first_ts + (i * epoch_duration_ms)

        ts_sec = ts_ms / 1000

        # Convert Unix timestamp to readable time
        try:
            dt = datetime.fromtimestamp(ts_sec)
            time_str = dt.strftime("%H:%M")
        except:
            time_str = f"Epoch {i}"

        display_stage = standard_to_display.get(int(stage), int(stage))
        epochs.append({
            "index": i,
            "timestamp": int(ts_ms),  # Already in milliseconds
            "stage": display_stage,
            "stage_name": stage_names.get(display_stage, "Unknown"),
            "time": time_str,
            "color": stage_colors.get(display_stage, "#gray"),
        })

    # Get bedtime window from ML timestamps (aligned with stages)
    bedtime_start_str = ""
    bedtime_end_str = ""
    night_date_str = ""
    if len(ml_timestamps) > 0:
        start_dt = datetime.fromtimestamp(ml_timestamps[0])
        end_dt = datetime.fromtimestamp(ml_timestamps[-1])
        bedtime_start_str = start_dt.strftime("%H:%M")
        bedtime_end_str = end_dt.strftime("%H:%M")
        night_date_str = start_dt.strftime("%Y-%m-%d")
        duration_hours = (ml_timestamps[-1] - ml_timestamps[0]) / 3600
        print(f"[sleep-stages] Night {night}: {night_date_str} {bedtime_start_str} - {bedtime_end_str} ({duration_hours:.1f}h)")

    # Get stage durations from analyzer (automatically uses ML)
    stage_durations = sleep_analyzer.stage_durations
    durations = {
        "deep_minutes": round(stage_durations.deep, 1),
        "light_minutes": round(stage_durations.light, 1),
        "rem_minutes": round(stage_durations.rem, 1),
        "awake_minutes": round(stage_durations.awake, 1),
        "total_sleep_minutes": round(stage_durations.total_sleep, 1),
        "total_time_minutes": round(stage_durations.total_time, 1),
        "efficiency_percent": round(stage_durations.efficiency, 1),
    }

    print(f"[sleep-stages] Deep={durations['deep_minutes']}m, "
          f"Light={durations['light_minutes']}m, REM={durations['rem_minutes']}m, "
          f"Awake={durations['awake_minutes']}m")

    # Build hypnogram data (simplified for charting - fewer points)
    # Group consecutive same-stage epochs
    hypnogram_data = []
    if epochs:
        current_stage = epochs[0]["stage"]
        current_start = epochs[0]["time"]
        current_start_idx = 0

        for i, epoch in enumerate(epochs):
            if epoch["stage"] != current_stage or i == len(epochs) - 1:
                hypnogram_data.append({
                    "start_time": current_start,
                    "end_time": epochs[i-1]["time"] if i > 0 else current_start,
                    "stage": current_stage,
                    "stage_name": stage_names.get(current_stage, "Unknown"),
                    "duration_epochs": i - current_start_idx,
                    "color": stage_colors.get(current_stage, "#gray"),
                })
                current_stage = epoch["stage"]
                current_start = epoch["time"]
                current_start_idx = i

    # Get sleep score from analyzer
    sleep_score = sleep_analyzer.score
    score_response = SleepScoreResponse(
        score=sleep_score.score,
        total_sleep=sleep_score.total_sleep,
        efficiency=sleep_score.efficiency,
        restfulness=sleep_score.restfulness,
        rem_sleep=sleep_score.rem_sleep,
        deep_sleep=sleep_score.deep_sleep,
        latency=sleep_score.latency,
        timing=sleep_score.timing,
    )
    print(f"[sleep-stages] Score: {sleep_score.score}")

    return SleepStagesDashboard(
        night_index=night,
        night_date=night_date_str,
        epochs=epochs,
        durations=durations,
        hypnogram_data=hypnogram_data,
        stage_mapping={str(k): v for k, v in stage_names.items()},
        score=score_response,
        bedtime_start=bedtime_start_str,
        bedtime_end=bedtime_end_str,
    )


# ============== BLE WebSocket & REST Endpoints ==============

@app.websocket("/ble/ws")
async def ble_websocket(websocket: WebSocket):
    """WebSocket endpoint for real-time BLE communication.

    Streams logs, status updates, heartbeat data, and progress to connected clients.
    Accepts commands: connect, disconnect, auth, sync-time, get-data, heartbeat, bond, factory-reset
    """
    await websocket.accept()
    ble_manager = get_ble_manager()
    ble_manager.websockets.append(websocket)

    # Send current status on connect
    await ble_manager.send_status()

    try:
        while True:
            data = await websocket.receive_json()
            action = data.get("action")

            if action == "connect":
                adapter = data.get("adapter")
                await ble_manager.connect_ring(adapter=adapter)

            elif action == "disconnect":
                await ble_manager.disconnect_ring()

            elif action == "auth":
                key_hex = data.get("key")
                await ble_manager.authenticate(key_hex=key_hex)

            elif action == "sync-time":
                await ble_manager.sync_time()

            elif action == "get-data":
                filters = data.get("filters")
                await ble_manager.get_data(filters=filters)

            elif action == "heartbeat":
                command = data.get("command", "start")
                if command == "start":
                    await ble_manager.start_heartbeat()
                else:
                    await ble_manager.stop_heartbeat()

            elif action == "bond":
                adapter = data.get("adapter")
                await ble_manager.bond_ring_async(adapter=adapter)

            elif action == "factory-reset":
                await ble_manager.factory_reset()

            elif action == "parse":
                await ble_manager.parse_events()

            else:
                await websocket.send_json({
                    "type": "error",
                    "message": f"Unknown action: {action}"
                })

    except WebSocketDisconnect:
        if websocket in ble_manager.websockets:
            ble_manager.websockets.remove(websocket)


class BLEStatus(BaseModel):
    connected: bool
    authenticated: bool
    is_busy: bool
    current_action: Optional[str]
    adapter: str


@app.get("/ble/status", response_model=BLEStatus)
async def get_ble_status():
    """Get current BLE connection status."""
    ble_manager = get_ble_manager()
    return BLEStatus(
        connected=ble_manager.client.is_connected if ble_manager.client else False,
        authenticated=ble_manager.client.is_authenticated if ble_manager.client else False,
        is_busy=ble_manager.is_busy,
        current_action=ble_manager.current_action,
        adapter=ble_manager.adapter,
    )


class AdapterList(BaseModel):
    adapters: List[str]
    default: str


@app.get("/ble/adapters", response_model=AdapterList)
async def get_ble_adapters():
    """List available Bluetooth adapters."""
    adapters = list_bluetooth_adapters()
    return AdapterList(
        adapters=adapters if adapters else ["hci0"],
        default="hci0",
    )


@app.post("/ble/reload-data")
async def reload_ring_data():
    """Reload ring data after a successful get-data operation.

    This clears the cached reader/analyzer so fresh data is loaded.
    """
    global _analyzer, _reader
    _analyzer = None
    _reader = None
    return {"status": "ok", "message": "Data cache cleared, will reload on next request"}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
