# SleepNet Model Input Specification

**Model:** `sleepnet_moonstone_1_1_0.pt`
**Date:** 2026-01-12
**Source:** Decompiled Oura Android App

---

## Input Summary

| # | Name | Shape | Dtype | Description |
|---|------|-------|-------|-------------|
| 1 | `bedtime_input` | `(2,)` | float64 | Sleep period start/end |
| 2 | `ibi_input` | `(N, 4)` | float64 | Heart rate IBI data |
| 3 | `acm_input` | `(M, 2)` | float64 | Motion/accelerometer |
| 4 | `temp_input` | `(P, 2)` | float64 | Skin temperature |
| 5 | `spo2_input` | `(Q, 2)` | float64 | Blood oxygen (can be empty) |
| 6 | `scalars_input` | `(5,)` | float64 | User demographics |
| 7 | `tst_input` | `(1,)` | float64 | Total sleep time hint |

---

## Input 1: `bedtime_input`

**Shape:** `(2,)`
**Dtype:** `float64`

| Index | Field | Unit | Description |
|-------|-------|------|-------------|
| 0 | `start` | Unix seconds | Sleep period start timestamp |
| 1 | `end` | Unix seconds | Sleep period end timestamp |

**Example:**
```python
bedtime_input = np.array([
    1704931200.0,  # 2024-01-11 00:00:00 UTC
    1704960000.0   # 2024-01-11 08:00:00 UTC
], dtype=np.float64)
```

**Source:** `API_FEATURE_SESSION` (0x6C) or `API_BEDTIME_PERIOD` (0x76)

---

## Input 2: `ibi_input`

**Shape:** `(N, 4)` where N = number of heartbeats
**Dtype:** `float64`

| Column | Field | Unit | Range | Description |
|--------|-------|------|-------|-------------|
| 0 | `timestamp` | seconds | Unix timestamp | Beat occurrence time |
| 1 | `ibi` | milliseconds | 300-2000 | Inter-beat interval |
| 2 | `amplitude` | arbitrary | 0-65535 | PPG signal amplitude |
| 3 | `validity` | flag | 0 or 1 | 1 = valid beat, 0 = invalid |

**Example:**
```python
ibi_input = np.array([
    [1704931200.5, 857.0, 12450.0, 1.0],
    [1704931201.4, 892.0, 11230.0, 1.0],
    [1704931202.3, 845.0, 13100.0, 1.0],
    [1704931203.1, 823.0, 10050.0, 0.0],  # Invalid beat
    [1704931204.0, 867.0, 12800.0, 1.0],
    # ... one row per heartbeat
], dtype=np.float64)
```

**Source:** `API_IBI_AND_AMPLITUDE_EVENT` (0x60 / tag 96)

**Protobuf:**
```protobuf
message IbiAndAmplitudeEvent {
  repeated int64 timestamp = 1;  // Ring time (deciseconds)
  repeated int32 ibi = 2;        // IBI in milliseconds
  repeated int32 amp = 3;        // PPG amplitude
}
```

**Transformation:**
1. Parse protobuf from ring event
2. Convert ring timestamp (deciseconds) → UTC seconds
3. Run through `EcoreWrapper.correctIbiAndAmplitudeEvents()`
4. Adds `validity` column (0 or 1)

---

## Input 3: `acm_input`

**Shape:** `(M, 2)` where M = number of motion epochs
**Dtype:** `float64`

| Column | Field | Unit | Range | Description |
|--------|-------|------|-------|-------------|
| 0 | `timestamp` | seconds | Unix timestamp | Epoch start time |
| 1 | `motion_count` | count | 0-30 | Motion intensity per 30s epoch |

**Example:**
```python
acm_input = np.array([
    [1704931200.0, 2.0],   # Low motion - likely asleep
    [1704931230.0, 0.0],   # No motion
    [1704931260.0, 1.0],   # Minimal motion
    [1704931290.0, 18.0],  # High motion - movement/wake
    [1704931320.0, 3.0],   # Low motion
    # ... one row per 30-second epoch
], dtype=np.float64)
```

**Source:** `API_MOTION_EVENT` (0x47 / tag 71)

**Protobuf:**
```protobuf
message MotionEvent {
  repeated int64 timestamp = 1;
  repeated int32 orientation = 2;
  repeated int32 motion_seconds = 3;  // ← This field used
  repeated float average_x = 4;
  repeated float average_y = 5;
  repeated float average_z = 6;
  repeated int32 regularity = 7;
  repeated int32 low_intensity = 8;
  repeated int32 high_intensity = 9;
}
```

---

## Input 4: `temp_input`

**Shape:** `(P, 2)` where P = number of temperature readings
**Dtype:** `float64`

| Column | Field | Unit | Range | Description |
|--------|-------|------|-------|-------------|
| 0 | `timestamp` | seconds | Unix timestamp | Reading time |
| 1 | `temperature` | Celsius | 25.0-42.0 | Skin temperature |

**Example:**
```python
temp_input = np.array([
    [1704931200.0, 35.2],
    [1704931500.0, 35.5],  # +5 min
    [1704931800.0, 35.8],  # +10 min
    [1704932100.0, 36.1],  # +15 min
    [1704932400.0, 36.0],  # +20 min
    # ... typically every 5 minutes
], dtype=np.float64)
```

**Source:** `API_SLEEP_TEMP_EVENT` (0x75 / tag 117)

**Protobuf:**
```protobuf
message SleepTempEvent {
  repeated int64 timestamp = 1;
  repeated float temp = 2;  // Celsius
}
```

---

## Input 5: `spo2_input`

**Shape:** `(Q, 2)` where Q = number of SpO2 readings (can be 0)
**Dtype:** `float64`

| Column | Field | Unit | Range | Description |
|--------|-------|------|-------|-------------|
| 0 | `timestamp` | seconds | Unix timestamp | Reading time |
| 1 | `spo2` | percent | 70-100 | Blood oxygen saturation |

**Example:**
```python
# With SpO2 data:
spo2_input = np.array([
    [1704931200.0, 97.0],
    [1704931500.0, 96.0],
    [1704931800.0, 98.0],
    [1704932100.0, 97.0],
    # ... periodic readings
], dtype=np.float64)

# Without SpO2 data (valid - model handles empty):
spo2_input = np.zeros((0, 2), dtype=np.float64)
```

**Source:** `API_SPO2_EVENT` (0x6F / tag 111)

**Protobuf:**
```protobuf
message Spo2Event {
  repeated int64 timestamp = 1;
  repeated int32 beat_offset = 2;
  repeated int32 beat_index = 3;
  repeated int32 spo2_value = 4;  // ← This field used
  repeated int64 timestamp_fixed = 5;
  repeated bool flush = 6;
}
```

---

## Input 6: `scalars_input`

**Shape:** `(5,)`
**Dtype:** `float64`

| Index | Field | Unit | Range | Description |
|-------|-------|------|-------|-------------|
| 0 | `age` | years | 5-140 | User age (from birthdate) |
| 1 | `weight` | kg | 20-200 | User weight |
| 2 | `sex` | encoded | 1-3 | 1=Female, 2=Male, 3=Other |
| 3 | `unknown_1` | ? | ? | Possibly BMI or height |
| 4 | `unknown_2` | ? | ? | Possibly ring hardware type |

**Example:**
```python
scalars_input = np.array([
    35.0,   # Age: 35 years
    70.0,   # Weight: 70 kg
    2.0,    # Sex: Male
    0.0,    # Unknown - use 0.0
    0.0     # Unknown - use 0.0
], dtype=np.float64)
```

**Source:** `DbUserSettings` (Realm database in app)

**Sex encoding** (from `DbUserSettingsUtils.java`):
```java
GENDER_FEMALE = 1
GENDER_MALE = 2
GENDER_OTHER = 3
```

**Age calculation:**
```java
// From DbUserSettingsUtils.java
Period period = Period.between(birthDate, LocalDate.now());
int age = period.getYears();
```

---

## Input 7: `tst_input`

**Shape:** `(1,)`
**Dtype:** `float64`

| Index | Field | Unit | Range | Description |
|-------|-------|------|-------|-------------|
| 0 | `tst_hint` | minutes | 0-900 | Total sleep time hint (0 = auto) |

**Example:**
```python
tst_input = np.array([0.0], dtype=np.float64)  # Let model determine
# OR
tst_input = np.array([420.0], dtype=np.float64)  # Hint: 7 hours
```

---

## Complete Python Example

```python
import torch
import numpy as np

def create_sleepnet_inputs(
    sleep_start_unix: float,
    sleep_end_unix: float,
    ibi_data: list,      # [(timestamp, ibi_ms, amplitude, validity), ...]
    motion_data: list,   # [(timestamp, motion_count), ...]
    temp_data: list,     # [(timestamp, celsius), ...]
    spo2_data: list,     # [(timestamp, percent), ...] or []
    age: float,
    weight_kg: float,
    sex: int,            # 1=Female, 2=Male, 3=Other
    tst_hint: float = 0.0
):
    """Create all 7 inputs for SleepNet model."""

    # Input 1: Bedtime
    bedtime = torch.tensor([sleep_start_unix, sleep_end_unix], dtype=torch.float64)

    # Input 2: IBI (N, 4)
    if ibi_data:
        ibi = torch.tensor(ibi_data, dtype=torch.float64)
    else:
        ibi = torch.zeros((0, 4), dtype=torch.float64)

    # Input 3: Motion (M, 2)
    if motion_data:
        acm = torch.tensor(motion_data, dtype=torch.float64)
    else:
        acm = torch.zeros((0, 2), dtype=torch.float64)

    # Input 4: Temperature (P, 2)
    if temp_data:
        temp = torch.tensor(temp_data, dtype=torch.float64)
    else:
        temp = torch.zeros((0, 2), dtype=torch.float64)

    # Input 5: SpO2 (Q, 2) - can be empty
    if spo2_data:
        spo2 = torch.tensor(spo2_data, dtype=torch.float64)
    else:
        spo2 = torch.zeros((0, 2), dtype=torch.float64)

    # Input 6: Demographics (5,)
    scalars = torch.tensor([
        float(age),
        float(weight_kg),
        float(sex),
        0.0,  # Unknown - default to 0
        0.0   # Unknown - default to 0
    ], dtype=torch.float64)

    # Input 7: TST hint (1,)
    tst = torch.tensor([tst_hint], dtype=torch.float64)

    return bedtime, ibi, acm, temp, spo2, scalars, tst


# Example usage:
bedtime, ibi, acm, temp, spo2, scalars, tst = create_sleepnet_inputs(
    sleep_start_unix=1704931200.0,
    sleep_end_unix=1704960000.0,
    ibi_data=[
        [1704931200.5, 857.0, 12450.0, 1.0],
        [1704931201.4, 892.0, 11230.0, 1.0],
        [1704931202.3, 845.0, 13100.0, 1.0],
        # ... ~28000 beats for 8 hours (avg 60 bpm)
    ],
    motion_data=[
        [1704931200.0, 2.0],
        [1704931230.0, 0.0],
        [1704931260.0, 1.0],
        # ... ~960 epochs for 8 hours (30s each)
    ],
    temp_data=[
        [1704931200.0, 35.2],
        [1704931500.0, 35.5],
        [1704931800.0, 35.8],
        # ... ~96 readings for 8 hours (5 min each)
    ],
    spo2_data=[],  # Optional
    age=35,
    weight_kg=70,
    sex=2,  # Male
    tst_hint=0.0
)

# Load and run model
model = torch.jit.load('sleepnet_moonstone_1_1_0.pt', map_location='cpu')
model.eval()

with torch.no_grad():
    staging, apnea, spo2_out, metrics, debug = model(
        bedtime, ibi, acm, temp, spo2, scalars, tst
    )

print(f"Output shape: {staging.shape}")  # (num_epochs, 6)
```

---

## Output Format

**Returns:** Tuple of 5 tensors

### `staging_outputs` - Shape: `(num_epochs, 6)`

| Column | Field | Description |
|--------|-------|-------------|
| 0 | `timestamp` | Epoch timestamp (Unix seconds) |
| 1 | `stage` | Sleep stage (0=Awake, 1=Light, 2=Deep, 3=REM) |
| 2 | `prob_light` | Probability of Light sleep |
| 3 | `prob_deep` | Probability of Deep sleep |
| 4 | `prob_rem` | Probability of REM sleep |
| 5 | `prob_awake` | Probability of Awake |

Each row = one 30-second epoch.

### Other outputs
- `apnea_outputs` - Sleep apnea indicators
- `spo2_outputs` - SpO2 analysis
- `output_metrics` - Sleep quality metrics
- `debug_metrics` - Debug information

---

## Validation Constraints

From decompiled validation code:

| Input | Constraint |
|-------|------------|
| Timestamps | 1262304000 - 7258118400 (2010 - 2200) |
| IBI values | 0 - ∞ (typically 300-2000 ms) |
| IBI validity | Must have at least one `1` in column 3 |
| Motion count | 0 - 30 |
| Temperature | 0 - 70°C |
| SpO2 | 0 - 110% |
| Age | 5 - 140 years |
| Weight | 0 - 200 kg |
| Sex | 1, 2, or 3 |
| TST hint | 0 - 900 minutes |

---

## Ring Event to Model Input Mapping

```
Ring Event (BLE)              → Model Input Column
─────────────────────────────────────────────────
API_IBI_AND_AMPLITUDE_EVENT
  └─ timestamp (decisec)      → ibi[n][0] (convert to UTC sec)
  └─ ibi                      → ibi[n][1]
  └─ amp                      → ibi[n][2]
  └─ (computed validity)      → ibi[n][3]

API_MOTION_EVENT
  └─ timestamp                → acm[n][0]
  └─ motion_seconds           → acm[n][1]

API_SLEEP_TEMP_EVENT
  └─ timestamp                → temp[n][0]
  └─ temp                     → temp[n][1]

API_SPO2_EVENT
  └─ timestamp                → spo2[n][0]
  └─ spo2_value               → spo2[n][1]

API_FEATURE_SESSION / API_BEDTIME_PERIOD
  └─ start                    → bedtime[0]
  └─ end                      → bedtime[1]

DbUserSettings (app database)
  └─ birthDate → age          → scalars[0]
  └─ weight                   → scalars[1]
  └─ biologicalSex            → scalars[2]
```

---

## CRITICAL: No ML Models Required for Preprocessing

**Confirmed through deep analysis of decompiled sources:**

### All SleepNet Inputs Are Non-ML Derived

| Input | Source | ML Model Used? |
|-------|--------|----------------|
| `bedtime_input` | Ring event `API_FEATURE_SESSION` | **NO** - Direct from ring |
| `ibi_input` | Ring event + EcoreWrapper correction | **NO** - Algorithmic |
| `acm_input` | Ring event `API_MOTION_EVENT` | **NO** - Direct from ring |
| `temp_input` | Ring event `API_SLEEP_TEMP_EVENT` | **NO** - Direct from ring |
| `spo2_input` | Ring event `API_SPO2_EVENT` | **NO** - Direct from ring |
| `scalars_input` | User settings (`DbUserSettings`) | **NO** - User profile data |
| `tst_input` | App-provided hint or 0.0 | **NO** - Optional hint |

### IBI Correction is Purely Algorithmic

The `validity` column in `ibi_input` is computed by `EcoreWrapper.correctIbiAndAmplitudeEvents()`:

**Native Library:** `libappecore.so`

**Algorithm Components (from symbol analysis):**
- `ibi_correction` - Base correction algorithm
- `ppg_filter_init/run` - PPG signal filtering
- `median7` - Median filtering
- `peak` detection functions
- `is_ibi_acceptable` - Threshold-based validation
- `calculate_sri_and_validity` - Signal quality metrics

**Processing Pipeline:**
```
Raw IBI Events (3 fields)
    ↓
PPG Signal Filtering (digital signal processing)
    ↓
Peak Detection & Validation (threshold-based)
    ↓
Quality Estimation (statistical metrics)
    ↓
Validity Flag Assignment (0 or 1)
    ↓
Corrected IBI Events (4 fields)
```

**No ML frameworks found in libappecore.so:**
- Zero PyTorch references
- Zero TensorFlow references
- Zero ONNX references
- Pure C/C++ signal processing

### Demographics Come from User Settings

The 5 scalars are read directly from `DbUserSettings` (Realm database):

| Index | Field | Source |
|-------|-------|--------|
| 0 | `age` | Calculated from `dateOfBirth` |
| 1 | `weight` | `DbUserSettings.weight` (kg) |
| 2 | `sex` | `DbUserSettings.biologicalSex` (1/2/3) |
| 3 | Unknown | Likely BMI (`weight / (height/100)²`) or height |
| 4 | Unknown | Possibly ring hardware type |

### TST Input is a Hint, Not ML-Derived

The `tst_input` (Total Sleep Time hint) is:
- **Value 0.0** = Let model auto-detect sleep duration
- **Value > 0** = Provide a hint in minutes (e.g., 420.0 = 7 hours)

The debug metrics output includes both:
- `tst_app` - The hint value provided as input
- `tst_model` - The model's calculated total sleep time

This is NOT derived from another ML model - it's either 0 (auto) or user/app-provided.

---

## Implementation Confidence

With these findings, **100% of SleepNet inputs can be constructed without other ML models:**

```python
# Complete input pipeline - NO ML PREPROCESSING REQUIRED
def prepare_sleepnet_inputs(
    ring_events: dict,      # Parsed protobuf events
    user_profile: dict,     # User settings
    bedtime_start: float,
    bedtime_end: float
):
    # 1. Bedtime - direct from ring/app
    bedtime = [bedtime_start, bedtime_end]

    # 2. IBI - ring events + algorithmic correction
    ibi_raw = parse_ibi_events(ring_events['ibi'])
    ibi_corrected = correct_ibi_algorithmic(ibi_raw)  # NOT ML

    # 3. Motion - direct from ring
    acm = parse_motion_events(ring_events['motion'])

    # 4. Temperature - direct from ring
    temp = parse_temp_events(ring_events['temp'])

    # 5. SpO2 - direct from ring (can be empty)
    spo2 = parse_spo2_events(ring_events.get('spo2', []))

    # 6. Demographics - from user profile
    scalars = [
        calculate_age(user_profile['dateOfBirth']),
        user_profile['weight'],
        encode_sex(user_profile['biologicalSex']),
        user_profile.get('bmi', 0.0),  # or height
        0.0  # unknown - default
    ]

    # 7. TST hint - just use 0.0 for auto-detect
    tst = [0.0]

    return bedtime, ibi_corrected, acm, temp, spo2, scalars, tst
```
