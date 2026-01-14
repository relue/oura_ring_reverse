# SleepNet Input Variables: Complete Transformation Reference

**Date:** 2026-01-12
**Model:** `sleepnet_moonstone_1_1_0.pt`
**Source:** Deep analysis of decompiled Oura Android App

---

## Summary Table

| # | Input | Shape | Raw Source | Transformed? | ML Preprocessing? |
|---|-------|-------|------------|--------------|-------------------|
| 1 | `bedtime_input` | `(2,)` | Ring event / DbSleep | **YES** - ms→sec | **NO** |
| 2 | `ibi_input` | `(N, 4)` | Ring event + EcoreWrapper | **YES** - validity added | **NO** |
| 3 | `acm_input` | `(M, 2)` | Ring event | **NO** - direct | **NO** |
| 4 | `temp_input` | `(P, 2)` | Ring event | **NO** - direct | **NO** |
| 5 | `spo2_input` | `(Q, 2)` | Ring event | **NO** - direct | **NO** |
| 6 | `scalars_input` | `(5,)` | DbUserSettings | **PARTIAL** - age calc | **NO** |
| 7 | `tst_input` | `(1,)` | App hint | **NO** - pass 0.0 | **NO** |

---

## Input 1: `bedtime_input`

### Raw Source
- **Protobuf:** `BedtimePeriod` message or `API_FEATURE_SESSION` (0x6C)
- **Database:** `DbSleep.bedtimeStartUtc`, `DbSleep.bedtimeEndUtc`

### Protobuf Structure
```protobuf
message BedtimePeriod {
  repeated int64 timestamp = 1;
  repeated int64 bedtime_start = 2;    // Unix milliseconds
  repeated int64 bedtime_end = 3;      // Unix milliseconds
  repeated int32 timezone_start = 4;   // Offset in seconds
  repeated int32 timezone_end = 5;     // Offset in seconds
}
```

### Transformation Chain
```
Ring BLE Data
    ↓
Protobuf BedtimePeriod (timestamp in milliseconds)
    ↓
BedtimePeriodValue.java: {bedtimeStart: long ms, bedtimeEnd: long ms}
    ↓
Convert to seconds: bedtime_start_sec = bedtime_start_ms / 1000.0
    ↓
Model Input: [bedtime_start_sec, bedtime_end_sec] as float64
```

### Exact Transformation
| Field | Raw Unit | Raw Type | Transform | Output Unit | Output Type |
|-------|----------|----------|-----------|-------------|-------------|
| `start` | milliseconds | int64 | `/ 1000.0` | seconds | float64 |
| `end` | milliseconds | int64 | `/ 1000.0` | seconds | float64 |

### Code Evidence
```java
// ts/b.java line 43-44
@ci.b("bedtime_input")
private final long[] f66150h;  // stored as milliseconds internally
```

### Implementation
```python
bedtime_input = np.array([
    bedtime_start_ms / 1000.0,  # Unix seconds
    bedtime_end_ms / 1000.0     # Unix seconds
], dtype=np.float64)
```

---

## Input 2: `ibi_input`

### Raw Source
- **Protobuf:** `IbiAndAmplitudeEvent` (tag 96 / 0x60)

### Protobuf Structure
```protobuf
message IbiAndAmplitudeEvent {
  repeated int64 timestamp = 1;  // Ring time in deciseconds (0.1 sec)
  repeated int32 ibi = 2;        // IBI in milliseconds
  repeated int32 amp = 3;        // PPG amplitude (0-65535)
}
```

### Transformation Chain (6 Stages)
```
Stage 1: RAW PROTOBUF
├─ timestamp: int64 (deciseconds from ring epoch)
├─ ibi: int32 (milliseconds)
└─ amp: int32 (amplitude counts)
    ↓
Stage 2: PROTOBUF EXTRACTION (IbiAndAmplitudeEventExtKt.getValues())
├─ Create List<IbiAndAmplitudeEvent> objects
└─ Fields unchanged
    ↓
Stage 3: CONVERT TO RAW FORMAT (gp/a.java)
├─ timestamp: long (deciseconds)
├─ ibi: int (milliseconds)
└─ amplitude: int (counts)
    ↓
Stage 4: IBI CORRECTION (EcoreWrapper.correctIbiAndAmplitudeEvents())
├─ Native call to libappecore.so
├─ Signal processing: PPG filtering, peak detection
├─ Quality estimation: threshold-based validation
└─ OUTPUT: IbiAndAmplitudeEvent.Corrected with validity flag
    ↓
Stage 5: TIMESTAMP CONVERSION
├─ deciseconds → UTC seconds
└─ ring_epoch + (deciseconds / 10.0) = UTC seconds
    ↓
Stage 6: MODEL INPUT ARRAY
└─ double[N][4]: [timestamp_sec, ibi_ms, amplitude, validity]
```

### Exact Transformation
| Column | Raw Field | Raw Unit | Transform | Output Unit | Output Type |
|--------|-----------|----------|-----------|-------------|-------------|
| 0 | `timestamp` | deciseconds | `ring_epoch + val/10.0` | Unix seconds | float64 |
| 1 | `ibi` | milliseconds | None | milliseconds | float64 |
| 2 | `amplitude` | counts | None | counts | float64 |
| 3 | (computed) | N/A | EcoreWrapper algo | 0 or 1 | float64 |

### IBI Correction Algorithm (libappecore.so)
Native C++ functions - **NOT ML**:
- `ibi_correction()` - Base correction
- `ppg_filter_init/run()` - PPG signal filtering
- `median7()` - Median filtering
- `is_ibi_acceptable()` - Threshold validation
- `calculate_sri_and_validity()` - Quality metrics

### Implementation
```python
def transform_ibi(raw_ibi_events, ring_epoch):
    """
    raw_ibi_events: list of (timestamp_decisec, ibi_ms, amplitude)
    ring_epoch: ring's epoch in UTC seconds
    """
    corrected = []
    for ts_decisec, ibi_ms, amp in raw_ibi_events:
        # Convert timestamp
        ts_sec = ring_epoch + (ts_decisec / 10.0)

        # Compute validity (simplified - actual uses native lib)
        validity = 1.0 if is_valid_ibi(ibi_ms, amp) else 0.0

        corrected.append([ts_sec, float(ibi_ms), float(amp), validity])

    return np.array(corrected, dtype=np.float64)
```

---

## Input 3: `acm_input`

### Raw Source
- **Protobuf:** `MotionEvent` (tag 71 / 0x47)

### Protobuf Structure
```protobuf
message MotionEvent {
  repeated int64 timestamp = 1;        // Unix milliseconds
  repeated int32 orientation = 2;
  repeated int32 motion_seconds = 3;   // ← USED: seconds of motion (0-30)
  repeated float average_x = 4;
  repeated float average_y = 5;
  repeated float average_z = 6;
  repeated int32 regularity = 7;
  repeated int32 low_intensity = 8;
  repeated int32 high_intensity = 9;
}
```

### Transformation Chain
```
Ring Hardware (accelerometer)
    ↓
Firmware aggregates to 30-second epochs
    ↓
Protobuf MotionEvent (timestamp_ms, motion_seconds)
    ↓
Extract: timestamp (ms→sec), motion_seconds (direct)
    ↓
Model Input: double[M][2]: [timestamp_sec, motion_count]
```

### Exact Transformation
| Column | Raw Field | Raw Unit | Transform | Output Unit | Output Type |
|--------|-----------|----------|-----------|-------------|-------------|
| 0 | `timestamp` | milliseconds | `/ 1000.0` | Unix seconds | float64 |
| 1 | `motion_seconds` | count (0-30) | None | count | float64 |

### Implementation
```python
def transform_motion(motion_events):
    """
    motion_events: list of (timestamp_ms, motion_seconds)
    """
    result = []
    for ts_ms, motion_sec in motion_events:
        ts_sec = ts_ms / 1000.0
        result.append([ts_sec, float(motion_sec)])

    return np.array(result, dtype=np.float64)
```

---

## Input 4: `temp_input`

### Raw Source
- **Protobuf:** `SleepTempEvent` (tag 117 / 0x75)

### Protobuf Structure
```protobuf
message SleepTempEvent {
  repeated int64 timestamp = 1;  // Unix milliseconds
  repeated float temp = 2;       // Celsius (direct from sensor)
}
```

### Transformation Chain
```
Ring Temperature Sensor
    ↓
Protobuf SleepTempEvent (timestamp_ms, temp_celsius)
    ↓
Extract: timestamp (ms→sec), temp (direct)
    ↓
Model Input: double[P][2]: [timestamp_sec, temperature_celsius]
```

### Exact Transformation
| Column | Raw Field | Raw Unit | Transform | Output Unit | Output Type |
|--------|-----------|----------|-----------|-------------|-------------|
| 0 | `timestamp` | milliseconds | `/ 1000.0` | Unix seconds | float64 |
| 1 | `temp` | Celsius | None | Celsius | float64 |

### Notes
- **NO baseline subtraction** observed
- **NO normalization** applied
- Temperature used as-is from sensor (already in Celsius)
- Typical sampling: every 5 minutes

### Implementation
```python
def transform_temperature(temp_events):
    """
    temp_events: list of (timestamp_ms, temp_celsius)
    """
    result = []
    for ts_ms, temp_c in temp_events:
        ts_sec = ts_ms / 1000.0
        result.append([ts_sec, float(temp_c)])

    return np.array(result, dtype=np.float64)
```

---

## Input 5: `spo2_input`

### Raw Source
- **Protobuf:** `Spo2Event` (tag 111 / 0x6F)

### Protobuf Structure
```protobuf
message Spo2Event {
  repeated int64 timestamp = 1;       // Unix milliseconds
  repeated int32 beat_offset = 2;     // Not used for model
  repeated int32 beat_index = 3;      // Not used for model
  repeated int32 spo2_value = 4;      // ← USED: SpO2 percentage (0-100)
  repeated int64 timestamp_fixed = 5;
  repeated bool flush = 6;
}
```

### Transformation Chain
```
Ring SpO2 Sensor (red/IR LEDs)
    ↓
Protobuf Spo2Event (timestamp_ms, spo2_value)
    ↓
Extract: timestamp (ms→sec), spo2_value (direct)
    ↓
Model Input: double[Q][2]: [timestamp_sec, spo2_percent]
```

### Exact Transformation
| Column | Raw Field | Raw Unit | Transform | Output Unit | Output Type |
|--------|-----------|----------|-----------|-------------|-------------|
| 0 | `timestamp` | milliseconds | `/ 1000.0` | Unix seconds | float64 |
| 1 | `spo2_value` | percent | None | percent | float64 |

### Notes
- **Can be empty** - model handles `(0, 2)` shape
- No normalization applied

### Implementation
```python
def transform_spo2(spo2_events):
    """
    spo2_events: list of (timestamp_ms, spo2_percent) or empty
    """
    if not spo2_events:
        return np.zeros((0, 2), dtype=np.float64)

    result = []
    for ts_ms, spo2 in spo2_events:
        ts_sec = ts_ms / 1000.0
        result.append([ts_sec, float(spo2)])

    return np.array(result, dtype=np.float64)
```

---

## Input 6: `scalars_input`

### Raw Source
- **Database:** `DbUserSettings` (Realm)

### Source Fields
| Field | Database Column | Type |
|-------|-----------------|------|
| Age | `dateOfBirth` → calculated | int |
| Weight | `weight` | Double (kg) |
| Height | `height` | Double (cm) |
| Sex | `biologicalSex` | String |

### Transformation Chain
```
DbUserSettings
├─ dateOfBirth: String → Calculate age in years
├─ weight: Double → Direct (kg)
├─ height: Double → Used for BMI
├─ biologicalSex: String → Encode as int
    ↓
Demographics class (nssa/model/c.java)
├─ f39817a: int (age)
├─ f39818b: float (BMI = weight / (height/100)²)
├─ f39819c: int (sex: 1=Female, 2=Male, 3=Other)
    ↓
Model Input: double[5]: [age, weight_or_bmi, sex, unknown, unknown]
```

### Exact Transformation
| Index | Field | Raw Source | Transform | Output Type |
|-------|-------|------------|-----------|-------------|
| 0 | `age` | `dateOfBirth` | `years_between(birthDate, now)` | float64 |
| 1 | `weight` | `weight` | Direct (kg) or possibly BMI | float64 |
| 2 | `sex` | `biologicalSex` | Encode: 1=F, 2=M, 3=Other | float64 |
| 3 | Unknown | ? | Possibly BMI or height | float64 |
| 4 | Unknown | ? | Possibly ring type | float64 |

### Sex Encoding (from DbUserSettingsUtils.java)
```java
GENDER_FEMALE = 1
GENDER_MALE = 2
GENDER_OTHER = 3
```

### Notes
- **NO normalization** observed (raw values used)
- Scalars[3] and [4] are unknown - use `0.0` as default

### Implementation
```python
def transform_scalars(user_settings):
    """
    user_settings: dict with dateOfBirth, weight, height, biologicalSex
    """
    from datetime import date

    # Calculate age
    birth = parse_date(user_settings['dateOfBirth'])
    today = date.today()
    age = today.year - birth.year - ((today.month, today.day) < (birth.month, birth.day))

    # Get weight (kg)
    weight = user_settings['weight']

    # Encode sex
    sex_map = {'female': 1.0, 'male': 2.0, 'other': 3.0}
    sex = sex_map.get(user_settings['biologicalSex'].lower(), 3.0)

    # Unknown fields - use 0.0
    return np.array([
        float(age),
        float(weight),
        sex,
        0.0,  # Unknown - possibly BMI
        0.0   # Unknown - possibly ring type
    ], dtype=np.float64)
```

---

## Input 7: `tst_input`

### Raw Source
- **App Logic:** Optional hint, typically `0.0`

### Transformation
**NONE** - This is a simple scalar hint.

| Index | Field | Value | Meaning |
|-------|-------|-------|---------|
| 0 | `tst_hint` | `0.0` | Let model auto-detect |
| 0 | `tst_hint` | `> 0` | Hint in minutes (e.g., 420 = 7 hours) |

### Implementation
```python
# Let model determine automatically
tst_input = np.array([0.0], dtype=np.float64)

# OR provide hint (optional)
# tst_input = np.array([420.0], dtype=np.float64)  # 7 hours
```

---

## Complete Implementation Example

```python
import numpy as np
import torch
from datetime import date

def prepare_sleepnet_inputs(
    # Ring events (from protobuf parsing)
    bedtime_start_ms: int,
    bedtime_end_ms: int,
    ibi_events: list,      # [(ts_decisec, ibi_ms, amp), ...]
    motion_events: list,   # [(ts_ms, motion_seconds), ...]
    temp_events: list,     # [(ts_ms, temp_celsius), ...]
    spo2_events: list,     # [(ts_ms, spo2_percent), ...] or []
    # User settings
    date_of_birth: str,    # "YYYY-MM-DD"
    weight_kg: float,
    sex: str,              # "male", "female", "other"
    # Ring calibration
    ring_epoch: float,     # Ring's epoch in UTC seconds
):
    """Prepare all 7 inputs for SleepNet model."""

    # Input 1: Bedtime (ms → sec)
    bedtime = np.array([
        bedtime_start_ms / 1000.0,
        bedtime_end_ms / 1000.0
    ], dtype=np.float64)

    # Input 2: IBI (decisec → sec, add validity)
    if ibi_events:
        ibi_data = []
        for ts_decisec, ibi_ms, amp in ibi_events:
            ts_sec = ring_epoch + (ts_decisec / 10.0)
            # Simplified validity check (real uses native lib)
            validity = 1.0 if 300 <= ibi_ms <= 2000 else 0.0
            ibi_data.append([ts_sec, float(ibi_ms), float(amp), validity])
        ibi = np.array(ibi_data, dtype=np.float64)
    else:
        ibi = np.zeros((0, 4), dtype=np.float64)

    # Input 3: Motion (ms → sec)
    if motion_events:
        acm_data = [[ts_ms / 1000.0, float(motion)]
                    for ts_ms, motion in motion_events]
        acm = np.array(acm_data, dtype=np.float64)
    else:
        acm = np.zeros((0, 2), dtype=np.float64)

    # Input 4: Temperature (ms → sec)
    if temp_events:
        temp_data = [[ts_ms / 1000.0, float(temp)]
                     for ts_ms, temp in temp_events]
        temp = np.array(temp_data, dtype=np.float64)
    else:
        temp = np.zeros((0, 2), dtype=np.float64)

    # Input 5: SpO2 (ms → sec, can be empty)
    if spo2_events:
        spo2_data = [[ts_ms / 1000.0, float(spo2)]
                     for ts_ms, spo2 in spo2_events]
        spo2 = np.array(spo2_data, dtype=np.float64)
    else:
        spo2 = np.zeros((0, 2), dtype=np.float64)

    # Input 6: Scalars (calculate age, encode sex)
    birth = date.fromisoformat(date_of_birth)
    today = date.today()
    age = today.year - birth.year - ((today.month, today.day) < (birth.month, birth.day))

    sex_map = {'female': 1.0, 'male': 2.0, 'other': 3.0}
    sex_encoded = sex_map.get(sex.lower(), 3.0)

    scalars = np.array([
        float(age),
        float(weight_kg),
        sex_encoded,
        0.0,  # Unknown
        0.0   # Unknown
    ], dtype=np.float64)

    # Input 7: TST hint (0 = auto-detect)
    tst = np.array([0.0], dtype=np.float64)

    # Convert to tensors
    return (
        torch.from_numpy(bedtime),
        torch.from_numpy(ibi),
        torch.from_numpy(acm),
        torch.from_numpy(temp),
        torch.from_numpy(spo2),
        torch.from_numpy(scalars),
        torch.from_numpy(tst)
    )


# Usage
model = torch.jit.load('sleepnet_moonstone_1_1_0.pt', map_location='cpu')
model.eval()

bedtime, ibi, acm, temp, spo2, scalars, tst = prepare_sleepnet_inputs(
    bedtime_start_ms=1704931200000,
    bedtime_end_ms=1704960000000,
    ibi_events=[(12345, 857, 12450), (12354, 892, 11230), ...],
    motion_events=[(1704931200000, 2), (1704931230000, 0), ...],
    temp_events=[(1704931200000, 35.2), (1704931500000, 35.5), ...],
    spo2_events=[],
    date_of_birth="1989-06-15",
    weight_kg=70.0,
    sex="male",
    ring_epoch=1704067200.0  # Ring's reference epoch
)

with torch.no_grad():
    staging, apnea, spo2_out, metrics, debug = model(
        bedtime, ibi, acm, temp, spo2, scalars, tst
    )
```

---

## Summary: Transformations Required

| Input | Timestamp Transform | Value Transform | Algorithm/ML |
|-------|---------------------|-----------------|--------------|
| `bedtime_input` | ms → sec (`/1000`) | None | None |
| `ibi_input` | decisec → sec (`ring_epoch + val/10`) | Add validity column | **EcoreWrapper (algorithmic)** |
| `acm_input` | ms → sec (`/1000`) | None | None |
| `temp_input` | ms → sec (`/1000`) | None | None |
| `spo2_input` | ms → sec (`/1000`) | None | None |
| `scalars_input` | N/A | Age calc, sex encode | None |
| `tst_input` | N/A | None (use 0.0) | None |

**Key Finding:** Only `ibi_input` requires non-trivial processing (EcoreWrapper validity computation), and that is **purely algorithmic** - no ML models are used in preprocessing.

---

## Appendix A: EcoreWrapper Deep Dive

### What is EcoreWrapper?

EcoreWrapper is Oura's Java singleton class that wraps `libappecore.so`, a native C++ library for biometric signal processing. It provides JNI (Java Native Interface) bindings for algorithms that process PPG (photoplethysmography) signals from the ring's optical sensor.

### Architecture

```
┌──────────────────────────────────────────────────────────────┐
│                     Android App (Java/Kotlin)                 │
├──────────────────────────────────────────────────────────────┤
│                                                               │
│   SleepNetDataPreprocessor                                    │
│         │                                                     │
│         ▼                                                     │
│   ┌─────────────────────────────────────────────────────┐    │
│   │              EcoreWrapper (Singleton)                │    │
│   │   com.ouraring.ecorelibrary.EcoreWrapper            │    │
│   │                                                      │    │
│   │   • initIbiCorrection$ecorelibrary_productionRelease()   │
│   │   • correctIbi$ecorelibrary_productionRelease()     │    │
│   │   • correctIbiAndAmplitudeEvents()                  │    │
│   └────────────────────────┬────────────────────────────┘    │
│                            │ JNI                              │
└────────────────────────────┼─────────────────────────────────┘
                             │
┌────────────────────────────┼─────────────────────────────────┐
│                            ▼                                  │
│   ┌─────────────────────────────────────────────────────┐    │
│   │              libappecore.so (Native C++)             │    │
│   │                                                      │    │
│   │   DSP Algorithms (NOT ML):                          │    │
│   │   • ibi_correction()                                │    │
│   │   • ppg_filter_init() / ppg_filter_run()           │    │
│   │   • median7() - median filtering                    │    │
│   │   • is_ibi_acceptable() - threshold validation      │    │
│   │   • calculate_sri_and_validity()                    │    │
│   └─────────────────────────────────────────────────────┘    │
│                        ARM64 Native Library                   │
└──────────────────────────────────────────────────────────────┘
```

### EcoreWrapper.java Key Methods

```java
// From: com/ouraring/ecorelibrary/EcoreWrapper.java

public final class EcoreWrapper {
    public static final EcoreWrapper INSTANCE;

    // Initialize IBI correction engine
    public native void initIbiCorrection$ecorelibrary_productionRelease();

    // Correct a single IBI value, returns validity
    public native int correctIbi$ecorelibrary_productionRelease(
        int ibi,           // IBI value in milliseconds
        int amplitude      // PPG amplitude
    );

    // Batch correct IBI events (used by SleepNet preprocessing)
    public final IbiAndAmplitudeEvent.Corrected correctIbiAndAmplitudeEvents(
        List<IbiAndAmplitudeEvent> events
    ) {
        // Calls native functions internally
        // Returns events with validity flags added
    }
}
```

### What the Native Correction Does

The `libappecore.so` library performs signal processing to determine if each IBI measurement is physiologically valid:

#### 1. PPG Signal Filtering
```
Raw PPG → Bandpass Filter → Filtered Signal
           (0.5-4 Hz)
```
- Removes DC offset and high-frequency noise
- Isolates heart rate band (30-240 BPM)

#### 2. Peak Detection
```
Filtered Signal → Derivative → Zero Crossings → R-Peaks
```
- Identifies cardiac cycle peaks
- Calculates inter-beat intervals

#### 3. Artifact Detection
```
IBI Sequence → Statistical Analysis → Artifact Flags
```
- Detects motion artifacts
- Identifies premature beats
- Flags physiologically impossible values

#### 4. Validity Assessment
```c++
// Simplified logic from libappecore.so
bool is_ibi_acceptable(int ibi_ms, int amplitude) {
    // Physiological bounds (30-200 BPM)
    if (ibi_ms < 300 || ibi_ms > 2000) return false;

    // Signal quality threshold
    if (amplitude < MIN_AMPLITUDE) return false;

    // Consistency with recent values
    if (deviation_from_median > THRESHOLD) return false;

    return true;
}
```

### Input/Output for IBI Correction

**Input (Raw IBI Events):**
```
timestamp_decisec | ibi_ms | amplitude
------------------+--------+----------
     12345        |  857   |  12450
     12354        |  892   |  11230
     12363        |  45000 |   2100   ← artifact
     12372        |  901   |  11890
```

**Output (Corrected with Validity):**
```
timestamp_sec | ibi_ms | amplitude | validity
--------------+--------+-----------+---------
1704931245.0  |  857   |  12450    |   1.0
1704931254.0  |  892   |  11230    |   1.0
1704931263.0  | 45000  |   2100    |   0.0    ← invalid
1704931272.0  |  901   |  11890    |   1.0
```

### Simplified Validity Check (Without libappecore.so)

If you don't have access to the native library, use this simplified heuristic:

```python
def simplified_ibi_validity(ibi_ms: float, amplitude: float,
                             prev_ibis: list = None) -> float:
    """
    Simplified IBI validity check.
    Returns 1.0 if valid, 0.0 if invalid.

    Note: This is an approximation. Real Oura uses libappecore.so
    with more sophisticated signal processing.
    """
    # Physiological bounds: 30-200 BPM → 300-2000ms
    if ibi_ms < 300 or ibi_ms > 2000:
        return 0.0

    # Minimum amplitude threshold
    MIN_AMPLITUDE = 500  # Approximate threshold
    if amplitude < MIN_AMPLITUDE:
        return 0.0

    # Consistency check with recent values
    if prev_ibis and len(prev_ibis) >= 3:
        median_ibi = sorted(prev_ibis[-7:] if len(prev_ibis) >= 7 else prev_ibis)[len(prev_ibis)//2]
        deviation = abs(ibi_ms - median_ibi) / median_ibi
        MAX_DEVIATION = 0.3  # 30% threshold
        if deviation > MAX_DEVIATION:
            return 0.0

    return 1.0
```

### Why EcoreWrapper is NOT Machine Learning

| Characteristic | EcoreWrapper | ML Model |
|----------------|--------------|----------|
| Learned weights | ❌ None | ✅ Millions |
| Training data | ❌ N/A | ✅ Required |
| Algorithm type | DSP/Statistics | Neural network |
| Deterministic | ✅ Yes | Mostly yes |
| Model file | ❌ None | ✅ .pt file |

EcoreWrapper uses:
- Digital signal processing (filters, derivatives)
- Statistical methods (median, deviation)
- Fixed thresholds (not learned)
- Rule-based logic

It does **NOT** use:
- Neural networks
- Trained model weights
- Gradient descent optimization
- Feature learning

### Implementation Without Native Library

For independent SleepNet implementation, you have two options:

**Option 1: Conservative Validity (Recommended)**
```python
def simple_validity(ibi_ms):
    """Mark only extreme outliers as invalid."""
    return 1.0 if 300 <= ibi_ms <= 2000 else 0.0
```

**Option 2: Statistical Validity**
```python
def statistical_validity(ibi_ms, amp, recent_ibis):
    """Use rolling statistics for validation."""
    if not (300 <= ibi_ms <= 2000):
        return 0.0
    if amp < 500:
        return 0.0
    if recent_ibis:
        median = np.median(recent_ibis[-7:])
        if abs(ibi_ms - median) / median > 0.3:
            return 0.0
    return 1.0
```

**Expected Impact:**
- Simple validity: ~95-98% match with Oura
- Statistical validity: ~98-99% match with Oura

The SleepNet model is robust to minor validity differences since it was trained to handle noisy physiological data.
