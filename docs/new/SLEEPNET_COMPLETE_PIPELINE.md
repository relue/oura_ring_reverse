# SleepNet Complete Data Pipeline: Ring to Dashboard

**Date:** 2026-01-12
**Model:** `sleepnet_moonstone_1_1_0.pt` (for Ring 4)

---

## Executive Summary

The SleepNet model **does NOT require any other models** to function. It's a self-contained deep learning model that takes raw sensor data and produces sleep stages directly.

---

## Complete Data Pipeline

```
┌─────────────────────────────────────────────────────────────────────────────────────────┐
│                          SLEEPNET COMPLETE DATA PIPELINE                                 │
├─────────────────────────────────────────────────────────────────────────────────────────┤
│                                                                                          │
│  ┌─────────────────────────────────────────────────────────────────────────────────┐    │
│  │ LAYER 1: Ring Hardware → BLE Events (Binary Protobuf)                            │    │
│  ├─────────────────────────────────────────────────────────────────────────────────┤    │
│  │                                                                                  │    │
│  │  Oura Ring 4 (Moonstone)                                                         │    │
│  │  ├── PPG Sensor ──► 0x60 (96) API_IBI_AND_AMPLITUDE_EVENT                       │    │
│  │  ├── Accelerometer ──► 0x47 (71) API_MOTION_EVENT                               │    │
│  │  ├── Temperature ──► 0x75 (117) API_SLEEP_TEMP_EVENT                            │    │
│  │  ├── SpO2 Sensor ──► 0x6F (111) API_SPO2_EVENT                                  │    │
│  │  └── Session Control ──► 0x6C (108) API_FEATURE_SESSION                         │    │
│  │                                                                                  │    │
│  └─────────────────────────────────────────────────────────────────────────────────┘    │
│                                          │                                               │
│                                          ▼                                               │
│  ┌─────────────────────────────────────────────────────────────────────────────────┐    │
│  │ LAYER 2: Protobuf Parsing (libringeventparser.so / RingEventParserModel)        │    │
│  ├─────────────────────────────────────────────────────────────────────────────────┤    │
│  │                                                                                  │    │
│  │  message IbiAndAmplitudeEvent {           message MotionEvent {                 │    │
│  │    repeated int64 timestamp = 1;            repeated int64 timestamp = 1;       │    │
│  │    repeated int32 ibi = 2;      ────►       repeated int32 motion_seconds = 3;  │    │
│  │    repeated int32 amp = 3;                  repeated float average_x/y/z = 4-6; │    │
│  │  }                                        }                                      │    │
│  │                                                                                  │    │
│  │  message SleepTempEvent {                 message Spo2Event {                   │    │
│  │    repeated int64 timestamp = 1;            repeated int64 timestamp = 1;       │    │
│  │    repeated float temp = 2;     ────►       repeated int32 spo2_value = 4;      │    │
│  │  }                                        }                                      │    │
│  │                                                                                  │    │
│  └─────────────────────────────────────────────────────────────────────────────────┘    │
│                                          │                                               │
│                                          ▼                                               │
│  ┌─────────────────────────────────────────────────────────────────────────────────┐    │
│  │ LAYER 3: Data Classes (Kotlin/Java Domain Models)                                │    │
│  ├─────────────────────────────────────────────────────────────────────────────────┤    │
│  │                                                                                  │    │
│  │  class IbiAndAmplitudeEvent(              class MotionEvent(                    │    │
│  │    timestamp: Long,       ────────►         timestamp: Long,                    │    │
│  │    ibi: Int,              (ms)              motion_seconds: Int,                │    │
│  │    amp: Int               (amplitude)       orientation: Int                    │    │
│  │  )                                        )                                      │    │
│  │                                                                                  │    │
│  │  class SleepTempEvent(                    class Spo2Event(                      │    │
│  │    timestamp: Long,       ────────►         timestamp: Long,                    │    │
│  │    temp: Float            (°C)              spo2_value: Int   (%)               │    │
│  │  )                                        )                                      │    │
│  │                                                                                  │    │
│  └─────────────────────────────────────────────────────────────────────────────────┘    │
│                                          │                                               │
│                                          ▼                                               │
│  ┌─────────────────────────────────────────────────────────────────────────────────┐    │
│  │ LAYER 4: SleepNet Input Builder (SleepNetHandler.kt)                             │    │
│  ├─────────────────────────────────────────────────────────────────────────────────┤    │
│  │                                                                                  │    │
│  │  TRANSFORMATION STEPS:                                                           │    │
│  │                                                                                  │    │
│  │  1. Collect raw events within bedtime window                                    │    │
│  │  2. IBI correction (EcoreWrapper.correctIbiAndAmplitudeEvents)                  │    │
│  │  3. Convert timestamps to seconds (float64)                                     │    │
│  │  4. Build 2D arrays for each input type                                         │    │
│  │  5. Get demographics from DbUserSettings                                        │    │
│  │                                                                                  │    │
│  │  class SleepNetModelInput(                                                      │    │
│  │    bedtime: double[2],      // [start_unix_sec, end_unix_sec]                   │    │
│  │    ibi: double[N][4],       // [timestamp, ibi_ms, ?, validity]                 │    │
│  │    acm: double[N][2],       // [timestamp, motion_count]                        │    │
│  │    temperature: double[N][2], // [timestamp, celsius]                           │    │
│  │    spo2: double[N][2],      // [timestamp, spo2_percent]                        │    │
│  │    scalars: double[5],      // [age, weight_kg, sex, ?, ?]                      │    │
│  │    tst: double[1]           // total_sleep_time_hint                            │    │
│  │  )                                                                               │    │
│  │                                                                                  │    │
│  └─────────────────────────────────────────────────────────────────────────────────┘    │
│                                          │                                               │
│                                          ▼                                               │
│  ┌─────────────────────────────────────────────────────────────────────────────────┐    │
│  │ LAYER 5: PyTorch Model Inference (sleepnet_moonstone_1_1_0.pt)                   │    │
│  ├─────────────────────────────────────────────────────────────────────────────────┤    │
│  │                                                                                  │    │
│  │  model = torch.jit.load('sleepnet_moonstone_1_1_0.pt')                          │    │
│  │                                                                                  │    │
│  │  INPUTS (7 tensors):                    OUTPUTS (5 tensors):                    │    │
│  │  ┌──────────────────────┐               ┌──────────────────────┐                │    │
│  │  │ bedtime_input (2,)   │               │ staging_outputs      │                │    │
│  │  │ ibi_input (N, 4)     │      ───►     │ apnea_outputs        │                │    │
│  │  │ acm_input (N, 2)     │   INFERENCE   │ spo2_outputs         │                │    │
│  │  │ temp_input (N, 2)    │      ───►     │ output_metrics       │                │    │
│  │  │ spo2_input (N, 2)    │               │ debug_metrics        │                │    │
│  │  │ scalars_input (5,)   │               └──────────────────────┘                │    │
│  │  │ tst_input (1,)       │                                                       │    │
│  │  └──────────────────────┘                                                       │    │
│  │                                                                                  │    │
│  └─────────────────────────────────────────────────────────────────────────────────┘    │
│                                          │                                               │
│                                          ▼                                               │
│  ┌─────────────────────────────────────────────────────────────────────────────────┐    │
│  │ LAYER 6: Output Processing → Database → Dashboard                                │    │
│  ├─────────────────────────────────────────────────────────────────────────────────┤    │
│  │                                                                                  │    │
│  │  staging_outputs shape: (num_epochs, 6)                                         │    │
│  │  ├── Column 0: Epoch timestamp (Unix seconds)                                   │    │
│  │  ├── Column 1: Sleep stage (0=awake, 1=light, 2=deep, 3=REM)                   │    │
│  │  ├── Column 2: Probability of Light sleep                                       │    │
│  │  ├── Column 3: Probability of Deep sleep                                        │    │
│  │  ├── Column 4: Probability of REM sleep                                         │    │
│  │  └── Column 5: Probability of Awake                                             │    │
│  │                                                                                  │    │
│  │  30-second epochs → DbSleep (Realm DB) → Sleep Dashboard UI                    │    │
│  │                                                                                  │    │
│  └─────────────────────────────────────────────────────────────────────────────────┘    │
│                                                                                          │
└─────────────────────────────────────────────────────────────────────────────────────────┘
```

---

## Detailed Input Specifications

### 1. Bedtime Input (`bedtime_input`)
```python
# Shape: (2,) dtype=float64
# Source: Sleep detection algorithm or user-set bedtime

bedtime_input = [
    1704931200.0,  # Sleep period start (Unix timestamp in seconds)
    1704960000.0   # Sleep period end (Unix timestamp in seconds)
]
```

**Where it comes from:**
- `API_FEATURE_SESSION` event (0x6C) contains session start/end
- Or derived from `API_SLEEP_PERIOD_INFO` (0x6A)
- Or user-configured bedtime in app settings

---

### 2. IBI Input (`ibi_input`)
```python
# Shape: (N, 4) dtype=float64
# Source: API_IBI_AND_AMPLITUDE_EVENT (0x60)

# Protobuf message:
# message IbiAndAmplitudeEvent {
#   repeated int64 timestamp = 1;  # Ring time (deciseconds)
#   repeated int32 ibi = 2;        # Inter-beat interval (ms)
#   repeated int32 amp = 3;        # PPG amplitude
# }

ibi_input = [
    [1704931230.0, 850.0, 0.0, 1.0],  # [timestamp_sec, ibi_ms, unknown, validity]
    [1704931231.5, 820.0, 0.0, 1.0],
    [1704931232.3, 870.0, 0.0, 1.0],
    # ... more beats
]
```

**Transformation:**
1. Raw BLE event → Protobuf decode
2. Ring timestamp (deciseconds) → UTC seconds
3. IBI correction via `EcoreWrapper.correctIbiAndAmplitudeEvents()`
4. Column 3 validity: 1.0 = valid beat, 0.0 = invalid

---

### 3. Motion Input (`acm_input`)
```python
# Shape: (N, 2) dtype=float64
# Source: API_MOTION_EVENT (0x47)

# Protobuf message:
# message MotionEvent {
#   repeated int64 timestamp = 1;
#   repeated int32 orientation = 2;
#   repeated int32 motion_seconds = 3;  # Used for acm
#   repeated float average_x = 4;
#   repeated float average_y = 5;
#   repeated float average_z = 6;
# }

acm_input = [
    [1704931200.0, 2.0],   # [timestamp_sec, motion_count]
    [1704931230.0, 0.0],   # Low motion = likely asleep
    [1704931260.0, 15.0],  # High motion = movement
    # ... 30-second epochs
]
```

**Transformation:**
- Motion counts are typically in range 0-30 per epoch
- Each epoch is 30 seconds
- Higher values = more movement

---

### 4. Temperature Input (`temp_input`)
```python
# Shape: (N, 2) dtype=float64
# Source: API_SLEEP_TEMP_EVENT (0x75)

# Protobuf message:
# message SleepTempEvent {
#   repeated int64 timestamp = 1;
#   repeated float temp = 2;  # Celsius
# }

temp_input = [
    [1704931200.0, 35.2],  # [timestamp_sec, celsius]
    [1704931500.0, 35.5],
    [1704931800.0, 35.8],  # Temperature rises during sleep
    # ... typically every 5 minutes
]
```

**Transformation:**
- Skin temperature in Celsius
- Valid range: 0-70°C
- Typical sleep range: 32-38°C

---

### 5. SpO2 Input (`spo2_input`)
```python
# Shape: (N, 2) dtype=float64 or (0, 2) if not available
# Source: API_SPO2_EVENT (0x6F)

# Protobuf message:
# message Spo2Event {
#   repeated int64 timestamp = 1;
#   repeated int32 spo2_value = 4;  # Percentage
# }

spo2_input = [
    [1704931200.0, 97.0],  # [timestamp_sec, spo2_percent]
    [1704931500.0, 96.0],
    [1704931800.0, 98.0],
]

# OR if SpO2 not available:
spo2_input = np.zeros((0, 2), dtype=np.float64)  # Empty array
```

**Note:** SpO2 can be empty - model handles this gracefully.

---

### 6. Scalars Input (`scalars_input`)
```python
# Shape: (5,) dtype=float64
# Source: DbUserSettings (user profile in app)

# From DbUserSettingsUtils.java:
# - age: calculated from birthdate
# - weight: in kg (default 75.0)
# - sex: encoded as int (Male=2, Female=1, Other=3)

scalars_input = [
    35.0,   # Age in years (from birthdate)
    70.0,   # Weight in kg
    2.0,    # Sex (1=Female, 2=Male, 3=Other)
    0.0,    # Unknown (possibly BMI or height)
    0.0     # Unknown
]
```

**Demographics class (`c.java`):**
```java
class Demographics {
    int age;       // f39817a
    float bmi;     // f39818b
    int sex;       // f39819c
}
```

---

### 7. TST Input (`tst_input`)
```python
# Shape: (1,) dtype=float64
# Total Sleep Time hint in minutes

tst_input = [0.0]  # 0 = let model determine, or hint from previous analysis
```

---

## Model Output Format

```python
staging, apnea, spo2, metrics, debug = model(
    bedtime, ibi, acm, temp, spo2_in, scalars, tst
)

# staging_outputs: (num_epochs, 6)
# Each row is a 30-second epoch:
# [timestamp, stage, prob_light, prob_deep, prob_rem, prob_awake]

# Stage values:
# 0 = Awake
# 1 = Light Sleep (N1/N2)
# 2 = Deep Sleep (N3)
# 3 = REM Sleep
```

---

## What You DON'T Need

| Not Required | Why |
|--------------|-----|
| **Other ML models** | SleepNet is self-contained |
| **NSSA system** | Parallel system, not a dependency |
| **Custom operators** | Pure PyTorch - no libalgos.so |
| **Native libraries** | Standard torch.jit.load() |
| **Server communication** | All processing is on-device |

---

## Complete Implementation Example

```python
#!/usr/bin/env python3
"""Complete SleepNet pipeline implementation."""

import torch
import numpy as np
from datetime import datetime

def run_sleepnet_inference(
    model_path: str,
    bedtime_start: float,  # Unix timestamp
    bedtime_end: float,
    ibi_events: list,      # [(timestamp, ibi_ms), ...]
    motion_events: list,   # [(timestamp, motion_count), ...]
    temp_events: list,     # [(timestamp, celsius), ...]
    spo2_events: list,     # [(timestamp, percent), ...] or empty
    age: float,
    weight_kg: float,
    sex: int,              # 1=Female, 2=Male, 3=Other
):
    """Run complete SleepNet inference pipeline."""

    # Load model
    model = torch.jit.load(model_path, map_location='cpu')
    model.eval()

    # Prepare bedtime
    bedtime = torch.tensor([bedtime_start, bedtime_end], dtype=torch.float64)

    # Prepare IBI (add validity column)
    if ibi_events:
        ibi_data = [[ts, ibi, 0.0, 1.0] for ts, ibi in ibi_events]
        ibi = torch.tensor(ibi_data, dtype=torch.float64)
    else:
        ibi = torch.zeros((0, 4), dtype=torch.float64)

    # Prepare motion
    if motion_events:
        acm = torch.tensor(motion_events, dtype=torch.float64)
    else:
        acm = torch.zeros((0, 2), dtype=torch.float64)

    # Prepare temperature
    if temp_events:
        temp = torch.tensor(temp_events, dtype=torch.float64)
    else:
        temp = torch.zeros((0, 2), dtype=torch.float64)

    # Prepare SpO2 (can be empty)
    if spo2_events:
        spo2 = torch.tensor(spo2_events, dtype=torch.float64)
    else:
        spo2 = torch.zeros((0, 2), dtype=torch.float64)

    # Prepare demographics
    scalars = torch.tensor([age, weight_kg, float(sex), 0.0, 0.0], dtype=torch.float64)

    # TST hint (0 = auto)
    tst = torch.tensor([0.0], dtype=torch.float64)

    # Run inference
    with torch.no_grad():
        staging, apnea, spo2_out, metrics, debug = model(
            bedtime, ibi, acm, temp, spo2, scalars, tst
        )

    # Process output
    staging_np = staging.numpy()

    stages = []
    stage_names = {0: 'Awake', 1: 'Light', 2: 'Deep', 3: 'REM'}

    for row in staging_np:
        timestamp = row[0]
        stage = int(row[1])
        probabilities = row[2:6]

        stages.append({
            'timestamp': datetime.fromtimestamp(timestamp),
            'stage': stage_names.get(stage, 'Unknown'),
            'probabilities': {
                'light': probabilities[0],
                'deep': probabilities[1],
                'rem': probabilities[2],
                'awake': probabilities[3],
            }
        })

    return {
        'stages': stages,
        'apnea': apnea.numpy(),
        'spo2_analysis': spo2_out.numpy(),
        'metrics': metrics.numpy(),
    }


# Example usage:
if __name__ == '__main__':
    result = run_sleepnet_inference(
        model_path='sleepnet_moonstone_1_1_0.pt',
        bedtime_start=1704931200.0,  # 2024-01-11 00:00:00
        bedtime_end=1704960000.0,    # 2024-01-11 08:00:00
        ibi_events=[
            (1704931230.0, 850),
            (1704931231.5, 820),
            # ... more IBI data
        ],
        motion_events=[
            (1704931200.0, 2),
            (1704931230.0, 0),
            # ... 30-second epochs
        ],
        temp_events=[
            (1704931200.0, 35.2),
            (1704931500.0, 35.5),
            # ... temperature readings
        ],
        spo2_events=[],  # Optional - can be empty
        age=35,
        weight_kg=70,
        sex=2,  # Male
    )

    print(f"Total epochs: {len(result['stages'])}")
    for stage in result['stages'][:5]:
        print(f"{stage['timestamp']}: {stage['stage']}")
```

---

## Data Collection from Ring

To collect the raw data needed for SleepNet, you need:

1. **BLE Connection** to ring (UUID: `98ed0001-a541-11e4-b6a0-0002a5d5c51b`)
2. **GetEvent command** (0x10) to retrieve stored events
3. **Parse Protobuf** messages for each event type
4. **Time synchronization** using TIME_SYNC (0x12) to convert ring timestamps

See `docs/protocol/events.md` for full event parsing details.

---

## References

- `SleepNetHandler` (i.java) - Data preparation
- `SleepNetModel` (f.java) - Model invocation
- `SleepNetPytorchModel.java` - PyTorch wrapper
- `RingEventType.java` - Event type definitions
- `ringeventparser.proto` - Protobuf schema
- `DbUserSettingsUtils.java` - Demographics extraction
