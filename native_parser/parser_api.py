"""
Minimal Parser + ML API for Docker

Provides endpoints for:
- POST /parse - Parse ring_events.txt to ring_data.pb
- POST /ml/sleep-stages - Run SleepNet ML on a night
- GET /health - Health check
"""

from pathlib import Path
from typing import Optional, List, Dict, Any
from datetime import datetime

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

# Parser imports
from oura.native.parser import parse_events_sync, check_parser_available, ParseResult
from oura.data.reader import RingDataReader
from oura.analysis.sleep import SleepAnalyzer

app = FastAPI(
    title="Oura Parser API",
    description="Parser and ML inference API (runs in Docker with QEMU)",
    version="1.0.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Paths
INPUT_DIR = Path("/app/input_data")
DATA_FILE = INPUT_DIR / "ring_data.pb"


# Response models
class HealthResponse(BaseModel):
    status: str
    parser_available: bool
    parser_message: str
    data_file_exists: bool


class ParseResponse(BaseModel):
    success: bool
    input_events: int
    output_size: int
    output_path: str
    error: Optional[str]
    duration_sec: float


class SleepEpoch(BaseModel):
    index: int
    timestamp: int
    stage: int
    stage_name: str
    time: str


class SleepStagesResponse(BaseModel):
    night_index: int
    night_date: str
    epochs: List[SleepEpoch]
    durations: Dict[str, float]
    score: Optional[Dict[str, Any]]
    uses_ml: bool


@app.get("/health", response_model=HealthResponse)
async def health_check():
    """Health check with parser status."""
    available, message = check_parser_available()
    return HealthResponse(
        status="healthy",
        parser_available=available,
        parser_message=message,
        data_file_exists=DATA_FILE.exists()
    )


@app.post("/parse", response_model=ParseResponse)
async def parse_events():
    """Parse ring_events.txt to ring_data.pb using native QEMU parser."""
    available, message = check_parser_available()
    if not available:
        raise HTTPException(status_code=503, detail=f"Parser not available: {message}")

    events_file = INPUT_DIR / "ring_events.txt"
    if not events_file.exists():
        raise HTTPException(status_code=404, detail="ring_events.txt not found in input_data/")

    result: ParseResult = parse_events_sync()

    return ParseResponse(
        success=result.success,
        input_events=result.input_events,
        output_size=result.output_size,
        output_path=str(result.output_path),
        error=result.error,
        duration_sec=result.duration_sec
    )


@app.post("/ml/sleep-stages", response_model=SleepStagesResponse)
async def get_ml_sleep_stages(night: int = -1):
    """Run SleepNet ML inference for a specific night.

    Args:
        night: Night index (-1 = most recent)

    Returns:
        Sleep stages with 4-class ML classification (Awake, Light, Deep, REM)
    """
    if not DATA_FILE.exists():
        raise HTTPException(status_code=404, detail="ring_data.pb not found. Run /parse first.")

    try:
        reader = RingDataReader(str(DATA_FILE))
        sleep_analyzer = SleepAnalyzer(reader, night_index=night)

        # Stage mapping for display
        stage_names = {0: "Awake", 1: "Light", 2: "Deep", 3: "REM"}

        stages = sleep_analyzer.stages
        timestamps = sleep_analyzer.timestamps

        epochs = []
        for i, (stage, ts) in enumerate(zip(stages, timestamps)):
            ts_ms = int(ts * 1000)
            time_str = datetime.fromtimestamp(ts).strftime("%H:%M")
            epochs.append(SleepEpoch(
                index=i,
                timestamp=ts_ms,
                stage=stage,
                stage_name=stage_names.get(stage, "Unknown"),
                time=time_str
            ))

        # Calculate durations (30 sec per epoch)
        from collections import Counter
        counts = Counter(stages)
        durations = {
            "awake": counts.get(0, 0) * 0.5,
            "light": counts.get(1, 0) * 0.5,
            "deep": counts.get(2, 0) * 0.5,
            "rem": counts.get(3, 0) * 0.5,
        }

        # Get score if available
        score = None
        try:
            sleep_score = sleep_analyzer.score
            score = {
                "score": sleep_score.score,
                "total_sleep": sleep_score.total_sleep,
                "efficiency": sleep_score.efficiency,
                "restfulness": sleep_score.restfulness,
                "rem_sleep": sleep_score.rem_sleep,
                "deep_sleep": sleep_score.deep_sleep,
                "latency": sleep_score.latency,
                "timing": sleep_score.timing,
            }
        except Exception as e:
            print(f"[ml/sleep-stages] Score calculation failed: {e}")
            score = None

        # Get night date
        night_date = "unknown"
        if len(timestamps) > 0:
            night_date = datetime.fromtimestamp(timestamps[0]).strftime("%Y-%m-%d")

        return SleepStagesResponse(
            night_index=night,
            night_date=night_date,
            epochs=epochs,
            durations=durations,
            score=score,
            uses_ml=sleep_analyzer.uses_ml
        )

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/nights")
async def get_available_nights():
    """Get list of available nights in the data."""
    if not DATA_FILE.exists():
        raise HTTPException(status_code=404, detail="ring_data.pb not found")

    try:
        reader = RingDataReader(str(DATA_FILE))
        # Get unique nights from sleep data
        sleep_data = reader.get_sleep_data()

        nights = []
        seen_dates = set()
        for i, entry in enumerate(sleep_data):
            if hasattr(entry, 'timestamp_utc_ms'):
                ts = entry.timestamp_utc_ms / 1000
                date_str = datetime.fromtimestamp(ts).strftime("%Y-%m-%d")
                if date_str not in seen_dates:
                    seen_dates.add(date_str)
                    nights.append({
                        "index": len(nights),
                        "date": date_str,
                        "timestamp": entry.timestamp_utc_ms
                    })

        return {"nights": nights}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8001)
