# SleepNet Input Complete Specification

**Date:** 2026-01-12
**Status:** Comprehensive analysis from decompiled Oura Android app
**Model:** `sleepnet_moonstone_1_1_0.pt`

---

## Executive Summary

SleepNet requires **7 input tensors**. The critical discovery is that the Oura Ring has **no real-time clock** - it uses a monotonic decisecond counter. The app converts ring timestamps to UTC using **TIME_SYNC_IND** events during BLE sync.

### What We Know (CLEAR)

| Input | Shape | Source | Transformation | Status |
|-------|-------|--------|----------------|--------|
| bedtime_input | (2,) | BedtimePeriod protobuf | ms → seconds (÷1000) | ✅ CLEAR |
| ibi_input | (N, 4) | IbiAndAmplitudeEvent + EcoreWrapper | ring_time → UTC via sync | ✅ CLEAR |
| acm_input | (M, 2) | MotionEvent.motion_seconds | ms → seconds, 30s epochs | ✅ CLEAR |
| temp_input | (P, 2) | SleepTempEvent | ms → seconds | ✅ CLEAR |
| spo2_input | (Q, 2) | Spo2Event | ms → seconds | ✅ CLEAR |
| scalars_input | (5,) | User settings | sex normalized to [-1,0,1] | ✅ CLEAR |
| tst_input | (1,) | App hint | Pass 0.0 | ✅ CLEAR |

### What's Missing (OUR DATA)

| Data | Required | Our Status |
|------|----------|------------|
| TIME_SYNC_IND | For timestamp conversion | ❌ EMPTY |
| BedtimePeriod | For sleep window | ❌ EMPTY |
| Motion timestamps | For alignment | ❌ ALL ZEROS |
| ring_epoch | For IBI conversion | ❌ NOT AVAILABLE |

---

## Input 1: `bedtime_input`

### Specification
```
Shape: (2,)
Type: float64
Values: [bedtime_start_seconds, bedtime_end_seconds]
```

### Data Flow (Decompiled App)
```
Ring BLE → BedtimePeriod protobuf (milliseconds)
         → BedtimePeriodEventParser.parseEvent()
         → BedtimePeriodValue {bedtimeStart: Long ms, bedtimeEnd: Long ms}
         → Realm Database (NexusDbAppUpdateBedtimePeriod)
         → SleepNetBdiPyTorchModel.createModelInput()
         → DIVIDE BY 1000 → seconds
         → Model Input: [start_sec, end_sec]
```

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

### Key Classes
- `com.ouraring.ringeventparser.message.BedtimePeriodValue`
- `com.ouraring.oura.sleep.bedtimeperiod.BedtimePeriodEventParser`
- `com.ouraring.core.realm.model.dist.android.NexusDbAppUpdateBedtimePeriod`

### Our Issue
**BedtimePeriod is EMPTY in our protobuf extract.** Ring computes bedtime internally but we didn't capture it.

### Workaround
Derive from sleep_period_info epoch count:
```python
n_epochs = len(sleep.sleep_state)  # 709 epochs
sleep_duration_sec = n_epochs * 30  # 21270 seconds
bedtime_end = reference_time  # e.g., time.time()
bedtime_start = bedtime_end - sleep_duration_sec
```

---

## Input 2: `ibi_input`

### Specification
```
Shape: (N, 4)
Type: float64
Columns: [timestamp_seconds, ibi_ms, amplitude, validity]
```

### Column Details
| Col | Name | Unit | Range | Source |
|-----|------|------|-------|--------|
| 0 | timestamp | Unix seconds | absolute | Converted from ring_time |
| 1 | ibi | milliseconds | 300-2000 | Direct from protobuf |
| 2 | amplitude | counts | 0-65535 | Direct from protobuf |
| 3 | validity | binary | 0.0 or 1.0 | From EcoreWrapper |

### Data Flow (Decompiled App)
```
Ring BLE (0x60) → IbiAndAmplitudeEvent protobuf
    │
    │  Fields: timestamp (deciseconds), ibi (ms), amp (counts)
    │
    ▼
IbiAndAmplitudeEventExtKt.getValues()
    │
    │  Creates: List<IbiAndAmplitudeEvent>
    │
    ▼
gp.a.a() conversion
    │
    │  Creates: IbiAndAmplitudeEvent.Raw
    │
    ▼
EcoreWrapper.correctIbiAndAmplitudeEvents()
    │
    │  Native libappecore.so processing
    │  Adds validity flag (0=Valid, 1=Invalid, 2=Interpolated)
    │
    ▼
TIMESTAMP CONVERSION (CRITICAL!)
    │
    │  event_utc_ms = sync_utc_ms - ((sync_ring_time - event_ring_time) * 100)
    │
    ▼
Model Input: [timestamp_sec, ibi_ms, amplitude, validity]
```

### Ring Time Conversion Formula

**The Ring has NO real-time clock.** It uses a monotonic decisecond counter.

```
TIME_SYNC_IND provides:
  - sync_utc_ms: Phone's UTC time in milliseconds
  - sync_ring_time: Ring's current time in deciseconds

For any event with ring_time (deciseconds):
  time_diff_decisec = sync_ring_time - event_ring_time
  event_utc_ms = sync_utc_ms - (time_diff_decisec * 100)
  event_utc_sec = event_utc_ms / 1000.0
```

**Example:**
```
sync_utc_ms = 1731353414000 (Nov 11, 2025, 19:43:34 UTC)
sync_ring_time = 177799 deciseconds
event_ring_time = 136559 deciseconds

time_diff = 177799 - 136559 = 41240 deciseconds
event_utc_ms = 1731353414000 - (41240 * 100) = 1731349290000
event_utc_sec = 1731349290.0 (Nov 11, 2025, 18:34:50 UTC)
```

### EcoreWrapper Validity
```java
// Native call
ecoreWrapper.nativeIbiCorrection(ibi, amplitude, timestamp);

// Validity mapping for model:
// Native 0 (Valid) → 1.0
// Native 1 (Invalid) → 0.0
// Native 2 (Interpolated) → 0.0
```

### Our Issues
1. **TIME_SYNC_IND is EMPTY** - Cannot convert ring timestamps to UTC
2. **IBI has session boundaries** - Timestamps jump backward every 6 samples
3. **EcoreWrapper marks 94.5% invalid** - Possibly wrong input format

### IBI Session Pattern in Our Data
```
Timestamps: [-6812, -5760, -4826, -3881, -2925, -2000, -5507, ...]
                                              ↑ JUMP BACK
Session boundaries at indices: 6, 12, 18, 24, 30... (every 6 samples)
```

---

## Input 3: `acm_input`

### Specification
```
Shape: (M, 2)
Type: float64
Columns: [timestamp_seconds, motion_seconds]
```

### Data Flow (Decompiled App)
```
Ring BLE (0x47) → MotionEvent protobuf
    │
    │  Fields: timestamp (ms), motion_seconds (0-30), acm_x/y/z, etc.
    │
    ▼
TimeseriesDbMotion (Database)
    │
    │  Stores: motionSeconds, timestamp, acm values
    │
    ▼
MotionEventModel.MOTION_EVENT_TIME_SPAN = 30000ms
    │
    │  Aligns to 30-second epochs
    │  Fills gaps with EMPTY motion events
    │
    ▼
Model Input: [timestamp_sec, motion_seconds]
```

### Key Constants
```java
// MotionEventModel.java line 31
public static final int MOTION_EVENT_TIME_SPAN = 30000;  // 30 seconds
```

### Which Field to Use
**USE `motion_seconds`** (0-30 range), NOT motion_count.

```java
// Domain model conversion
return new MotionEvent(
    motionEvent.getMotionSeconds(),  // ← THIS FIELD
    ...
);
```

### Our Issue
**MotionEvent timestamps are ALL ZEROS** in our data.

```python
# Our data:
motion.motion_seconds: 331 values, mean=10.08, range 0-28  ✅ Values OK
motion_event.timestamp: 331 values, ALL ZEROS  ❌ No timestamps
```

### Workaround
Interpolate timestamps across bedtime window:
```python
n_motion = len(motion.motion_seconds)
motion_interval = (bedtime_end - bedtime_start) / n_motion
for i in range(n_motion):
    ts = bedtime_start + i * motion_interval
    acm_data.append([ts, motion.motion_seconds[i]])
```

---

## Input 4: `temp_input`

### Specification
```
Shape: (P, 2)
Type: float64
Columns: [timestamp_seconds, temperature_celsius]
```

### Data Flow
```
Ring BLE (0x75) → SleepTempEvent protobuf
    │
    │  Fields: timestamp (ms), temp (Celsius)
    │
    ▼
No transformation - direct values
    │
    ▼
Model Input: [timestamp_sec, temp_celsius]
```

### Notes
- NO baseline subtraction
- NO normalization
- Direct Celsius values from sensor
- Typical range: 33-36°C (skin temperature)

### Our Data
```python
temp.temp_celsius: 728 values, range 33.8-35.7°C  ✅ OK
# Timestamps need interpolation (same issue as motion)
```

---

## Input 5: `spo2_input`

### Specification
```
Shape: (Q, 2)
Type: float64
Columns: [timestamp_seconds, spo2_percent]
```

### Data Flow
```
Ring BLE (0x6F) → Spo2Event protobuf
    │
    │  Fields: timestamp (ms), spo2_value (0-100)
    │
    ▼
Model Input: [timestamp_sec, spo2_percent]
```

### Notes
- Can be EMPTY - model handles (0, 2) shape
- No normalization
- Typical range: 95-100%

### Our Data
```python
# SpO2 data appears minimal or empty
# Use placeholder: [[bedtime_start, 97.0], [bedtime_end, 97.0]]
```

---

## Input 6: `scalars_input`

### Specification
```
Shape: (5,)
Type: float64
Values: [age, weight_kg, sex_normalized, unknown, unknown]
```

### Field Details
| Index | Field | Source | Transformation |
|-------|-------|--------|----------------|
| 0 | age | dateOfBirth | years since birth |
| 1 | weight | weight | kg, direct |
| 2 | sex | biologicalSex | NORMALIZED: (raw-2)/1 |
| 3 | unknown | ? | Use 0.0 |
| 4 | unknown | ? | Use 0.0 |

### Sex Encoding
```
Database values: Female=1, Male=2, Other=3
Normalized for model: (raw - 2) / 1
  Female: (1-2)/1 = -1.0
  Male:   (2-2)/1 =  0.0
  Other:  (3-2)/1 =  1.0

Model validation: scalars[2] must be in range [-1, 1]
```

### Implementation
```python
scalars_input = np.array([
    age,           # e.g., 37.0
    weight_kg,     # e.g., 88.0
    sex_norm,      # -1.0, 0.0, or 1.0
    0.0,           # Unknown
    0.0            # Unknown
], dtype=np.float64)
```

---

## Input 7: `tst_input`

### Specification
```
Shape: (1,)
Type: float64
Values: [total_sleep_time_hint]
```

### Usage
```python
# Let model auto-detect (recommended)
tst_input = np.array([0.0], dtype=np.float64)

# OR provide hint in minutes
# tst_input = np.array([420.0], dtype=np.float64)  # 7 hours
```

---

## Model Output Structure

### Output Tensors
```python
outputs = model(bedtime, ibi, acm, temp, spo2, scalars, tst)

staging_outputs = outputs[0]  # Shape: (N, 6)
apnea_outputs = outputs[1]    # Apnea detection
spo2_outputs = outputs[2]     # SpO2 analysis
metrics = outputs[3]          # Summary metrics
debug_metrics = outputs[4]    # Debug info
```

### Staging Output Columns
```
Column 0: timestamp (Unix seconds)
Column 1: stage (1=Light, 2=Deep, 3=REM, 4=Awake)
Column 2: prob_light
Column 3: prob_deep
Column 4: prob_rem
Column 5: prob_awake
```

### Stage Mapping
```python
# Model output → Standard encoding
# Model: 1=Light, 2=Deep, 3=REM, 4=Awake
# Standard: 0=Awake, 1=Light, 2=Deep, 3=REM
stage_mapping = {1: 1, 2: 2, 3: 3, 4: 0}
```

---

## Complete Data Flow Diagram

```
┌─────────────────────────────────────────────────────────────────────────┐
│                         RING BLE SYNC                                   │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│  TIME_SYNC_IND (0x42) ──────────────────────────────────────────────┐  │
│    │                                                                 │  │
│    │  Provides: sync_utc_ms, sync_ring_time                         │  │
│    │  Used to convert ALL ring timestamps to UTC                    │  │
│    ▼                                                                 │  │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐ │  │
│  │BedtimePeriod│  │IbiAndAmpEvt │  │MotionEvent  │  │SleepTempEvt │ │  │
│  │   (0x6C?)   │  │   (0x60)    │  │   (0x47)    │  │   (0x75)    │ │  │
│  └──────┬──────┘  └──────┬──────┘  └──────┬──────┘  └──────┬──────┘ │  │
│         │                │                │                │        │  │
│         ▼                ▼                ▼                ▼        │  │
│  ┌─────────────────────────────────────────────────────────────────┐│  │
│  │              libringeventparser.so (Native)                     ││  │
│  │  Input: raw_events[], ringTime (decisec), utcTime (ms)         ││  │
│  │  Output: Ringeventparser.RingData protobuf with UTC timestamps ││  │
│  └─────────────────────────────────────────────────────────────────┘│  │
│                                                                      │  │
└──────────────────────────────────────────────────────────────────────┘  │
                                                                          │
┌─────────────────────────────────────────────────────────────────────────┐
│                      ANDROID APP PROCESSING                             │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│  BedtimePeriodValue ───► Database ───► bedtime_input (÷1000)           │
│                                                                         │
│  IbiAndAmplitudeEvent ───► EcoreWrapper ───► ibi_input                 │
│       │                        │                                        │
│       │                        └─► Adds validity flag                   │
│       └─► Timestamp: ring_epoch + decisec/10                           │
│                                                                         │
│  MotionEvent ───► 30s epoch alignment ───► acm_input                   │
│                                                                         │
│  SleepTempEvent ───► Direct values ───► temp_input                     │
│                                                                         │
│  Spo2Event ───► Direct values ───► spo2_input                          │
│                                                                         │
│  DbUserSettings ───► Age calc, sex normalize ───► scalars_input        │
│                                                                         │
│  App hint (0.0) ───► tst_input                                         │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
┌─────────────────────────────────────────────────────────────────────────┐
│                      SLEEPNET PYTORCH MODEL                             │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│  model(bedtime, ibi, acm, temp, spo2, scalars, tst)                    │
│       │                                                                 │
│       ▼                                                                 │
│  staging_outputs: [timestamp, stage, prob_L, prob_D, prob_R, prob_A]   │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘
```

---

## What's Still UNCLEAR

### 1. TIME_SYNC_IND Acquisition
- **Question:** How to capture TIME_SYNC_IND during ring sync?
- **Impact:** Cannot convert ring timestamps to UTC without it
- **Status:** Need to capture during live BLE sync

### 2. IBI Session Boundaries
- **Question:** Why do IBI timestamps jump backward every 6 samples?
- **Hypothesis:** Multiple PPG recording sessions during night
- **Impact:** Need to handle session merging properly

### 3. EcoreWrapper Invalid Rate
- **Question:** Why does EcoreWrapper mark 94.5% of IBI as invalid?
- **Hypothesis:** Input format mismatch or amplitude encoding issue
- **Impact:** Model receives mostly invalid IBI data

### 4. scalars_input[3] and [4]
- **Question:** What are these unknown fields?
- **Hypothesis:** Possibly BMI, height, or ring type
- **Impact:** Low - using 0.0 seems acceptable

### 5. Bedtime Computation
- **Question:** If BedtimePeriod is empty, how does ring compute it?
- **Hypothesis:** Ring algorithm detects sleep onset/offset
- **Impact:** Need to either capture it or implement detection

---

## Implementation Checklist

### To Fix in sleepnet.py

- [ ] **IBI timestamps**: Use TIME_SYNC_IND formula when available
- [ ] **Motion source**: Use `motion.motion_seconds` not `sleep.motion_count`
- [ ] **Motion timestamps**: Interpolate across bedtime window
- [ ] **EcoreWrapper**: Investigate why 94% invalid, consider fallback
- [ ] **Bedtime**: Extract from BedtimePeriod or derive from epochs

### Data to Capture

- [ ] **TIME_SYNC_IND**: Capture during live ring sync
- [ ] **BedtimePeriod**: Capture bedtime boundaries
- [ ] **Full event timestamps**: Ensure timestamps are preserved

---

## References

### Key Decompiled Classes
```
com.ouraring.ringeventparser.message.BedtimePeriodValue
com.ouraring.ringeventparser.message.IbiAndAmplitudeEvent
com.ouraring.ringeventparser.message.IbiAndAmplitudeEventExtKt
com.ouraring.ringeventparser.message.MotionEvent
com.ouraring.ringeventparser.message.TimeSyncIndValue
com.ouraring.ringeventparser.RingEventParserObj
com.ouraring.ecorelibrary.EcoreWrapper
com.ouraring.ecorelibrary.ibi.IbiAndAmplitudeEventExtKt
com.ouraring.oura.sleep.sleepnet.i (SleepNetHandler)
com.ouraring.oura.sleep.sleepnet.model.b (Input container)
com.ouraring.oura.sleep.sleepnet.model.l (Output container)
com.ouraring.oura.model.MotionEventModel
```

### Native Libraries
```
libringeventparser.so - BLE event parsing with timestamp conversion
libappecore.so - IBI correction, sleep score, other algorithms
```

### BLE Event IDs
```
0x42 (66)  - TIME_SYNC_IND
0x47 (71)  - MOTION_EVENT
0x60 (96)  - IBI_AND_AMPLITUDE_EVENT
0x6A (106) - SLEEP_PERIOD_INFO
0x6C (108) - FEATURE_SESSION / BedtimePeriod
0x6F (111) - SPO2_EVENT
0x75 (117) - SLEEP_TEMP_EVENT
```
