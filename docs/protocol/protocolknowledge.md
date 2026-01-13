# Oura Ring Protocol Knowledge Base

Extracted from decompiled Oura app sources and native library analysis.

---

## Event Types (0x41 - 0x83)

| Tag (Hex) | Tag (Dec) | Event Name | Description |
|-----------|-----------|------------|-------------|
| 0x41 | 65 | API_RING_START_IND | Ring initialization/boot |
| 0x42 | 66 | API_TIME_SYNC_IND | Time synchronization |
| 0x43 | 67 | API_DEBUG_EVENT_IND | Debug events |
| 0x44 | 68 | API_IBI_EVENT | Inter-Beat Interval |
| 0x45 | 69 | API_STATE_CHANGE_IND | State changes |
| 0x46 | 70 | API_TEMP_EVENT | Temperature (7 sensors) |
| 0x47 | 71 | API_MOTION_EVENT | Motion/accelerometer |
| 0x48 | 72 | API_SLEEP_PERIOD_INFO | Sleep period summary |
| 0x49 | 73 | API_SLEEP_SUMMARY_1 | Sleep summary variant 1 |
| 0x4A | 74 | API_PPG_AMPLITUDE_IND | PPG signal amplitude |
| 0x4B | 75 | API_SLEEP_PHASE_INFO | Sleep phase classification |
| 0x4C | 76 | API_SLEEP_SUMMARY_2 | Sleep summary variant 2 |
| 0x4D | 77 | API_RING_SLEEP_FEATURE_INFO | Sleep features |
| 0x4E | 78 | API_SLEEP_PHASE_DETAILS | Detailed sleep phases |
| 0x4F | 79 | API_SLEEP_SUMMARY_3 | Sleep summary variant 3 |
| 0x50 | 80 | API_ACTIVITY_INFO | Activity metrics (steps, MET) |
| 0x51 | 81 | API_ACTIVITY_SUMMARY_1 | Activity summary 1 |
| 0x52 | 82 | API_ACTIVITY_SUMMARY_2 | Activity summary 2 |
| 0x53 | 83 | API_WEAR_EVENT | Ring wear detection |
| 0x54 | 84 | API_RECOVERY_SUMMARY | Recovery score |
| 0x55 | 85 | API_SLEEP_HR | Sleep heart rate |
| 0x56 | 86 | API_ALERT_EVENT | Alert events |
| 0x57 | 87 | API_RING_SLEEP_FEATURE_INFO_2 | Extended sleep features |
| 0x58 | 88 | API_SLEEP_SUMMARY_4 | Sleep summary variant 4 |
| 0x59 | 89 | API_EDA_EVENT | Electrodermal activity |
| 0x5A | 90 | API_SLEEP_PHASE_DATA | Sleep phase raw data |
| 0x5B | 91 | API_BLE_CONNECTION_IND | BLE connection state |
| 0x5C | 92 | API_USER_INFO | User information |
| 0x5D | 93 | API_HRV_EVENT | Heart Rate Variability |
| 0x5E | 94 | API_SELFTEST_EVENT | Self-test results |
| 0x5F | 95 | API_RAW_ACM_EVENT | Raw accelerometer |
| 0x60 | 96 | API_IBI_AND_AMPLITUDE_EVENT | IBI + PPG amplitude |
| 0x61 | 97 | API_DEBUG_DATA | Debug data packets |
| 0x62 | 98 | API_ON_DEMAND_MEAS | On-demand measurements |
| 0x63 | 99 | API_PPG_PEAK_EVENT | PPG peak detection |
| 0x64 | 100 | API_RAW_PPG_EVENT | Raw PPG waveform |
| 0x65 | 101 | API_ON_DEMAND_SESSION | On-demand session |
| 0x66 | 102 | API_ON_DEMAND_MOTION | On-demand motion |
| 0x67 | 103 | API_RAW_PPG_SUMMARY | PPG summary stats |
| 0x68 | 104 | API_RAW_PPG_DATA | Raw PPG data |
| 0x69 | 105 | API_TEMP_PERIOD | Temperature period |
| 0x6A | 106 | API_SLEEP_PERIOD_INFO_2 | Extended sleep period (minute-by-minute) |
| 0x6B | 107 | API_MOTION_PERIOD | Motion period summary |
| 0x6C | 108 | API_FEATURE_SESSION | Feature session container |
| 0x6D | 109 | API_MEAS_QUALITY_EVENT | Measurement quality |
| 0x6E | 110 | API_SPO2_IBI_AND_AMPLITUDE_EVENT | SpO2 + IBI + amplitude |
| 0x6F | 111 | API_SPO2_EVENT | Blood oxygen (SpO2) |
| 0x70 | 112 | API_SPO2_SMOOTHED_EVENT | Filtered SpO2 |
| 0x71 | 113 | API_GREEN_IBI_AND_AMP_EVENT | Green LED IBI + amplitude |
| 0x72 | 114 | API_SLEEP_ACM_PERIOD | Sleep accelerometer period |
| 0x73 | 115 | API_EHR_TRACE_EVENT | Exercise HR trace |
| 0x74 | 116 | API_EHR_ACM_INTENSITY_EVENT | Exercise accelerometer intensity |
| 0x75 | 117 | API_SLEEP_TEMP_EVENT | Sleep temperature |
| 0x76 | 118 | API_BEDTIME_PERIOD | Bedtime period |
| 0x77 | 119 | API_SPO2_DC_EVENT | SpO2 DC component |
| 0x79 | 121 | API_SELFTEST_DATA_EVENT | Self-test data |
| 0x7A | 122 | API_TAG_EVENT | User tags |
| 0x7E | 126 | API_REAL_STEP_EVENT_FEATURE_ONE | RealSteps feature 1 |
| 0x7F | 127 | API_REAL_STEP_EVENT_FEATURE_TWO | RealSteps feature 2 |
| 0x80 | 128 | API_GREEN_IBI_QUALITY_EVENT | Green IBI quality |
| 0x81 | 129 | API_CVA_RAW_PPG_DATA | CVA PPG raw |
| 0x82 | 130 | API_SCAN_START | Scan session start |
| 0x83 | 131 | API_SCAN_END | Scan session end |

**Note:** Tags 0x78 (120), 0x7B-0x7D (123-125) appear unused.

---

## Data Models

### SleepPeriodInfoValue (0x48, 0x6A)

**Source:** `com.ouraring.ringeventparser.message.SleepPeriodInfoValue`

| Field | Type | Description |
|-------|------|-------------|
| timestamp | long | Unix timestamp (ms) |
| avgHr | float | Average heart rate (BPM) |
| hrTrend | float | Heart rate trend indicator |
| avgIBI | float | Average inter-beat interval (ms) |
| stdIBI | float | Standard deviation of IBI (ms) |
| avgBreathingRate | float | Average breathing rate (breaths/min) |
| stdBreathingRate | float | Std dev of breathing rate |
| motionCount | int | Motion/movement count |
| sleepState | int | Sleep state: 0=Awake, 1=Light, 2=Deep, 3=REM |
| cvPPGSignalAmplitude | float | PPG signal quality (CV) |

### HrvEvent (0x5D)

**Source:** `com.ouraring.ringeventparser.HrvEventKt`

| Field | Type | Description |
|-------|------|-------------|
| timestamp | repeated long | Timestamps (ms) |
| averageHr5Min | repeated int | Average HR over 5-min window (BPM) |
| averageRmssd5Min | repeated int | Average RMSSD over 5-min window (ms) |

### TempEvent (0x46)

**Source:** `com.ouraring.ringeventparser.TempEventKt`

| Field | Type | Description |
|-------|------|-------------|
| timestamp | repeated long | Timestamps (ms) |
| temp1 | repeated float | Temperature sensor 1 (°C) |
| temp2 | repeated float | Temperature sensor 2 (°C) |
| temp3 | repeated float | Temperature sensor 3 (°C) |
| temp4 | repeated float | Temperature sensor 4 (°C) |
| temp5 | repeated float | Temperature sensor 5 (°C) |
| temp6 | repeated float | Temperature sensor 6 (°C) |
| temp7 | repeated float | Temperature sensor 7 (°C) |

### IbiAndAmplitudeEvent (0x60)

**Source:** `com.ouraring.ringeventparser.IbiAndAmplitudeEventKt`

| Field | Type | Description |
|-------|------|-------------|
| timestamp | repeated long | Timestamps (ms) |
| ibi | repeated int | Inter-beat interval (ms) |
| amp | repeated int | PPG amplitude (raw units) |

### ActivityInfoEvent (0x50)

**Source:** `com.ouraring.ringeventparser.message.ActivityInfoEvent`

| Field | Type | Description |
|-------|------|-------------|
| timestamp | long | Unix timestamp (ms) |
| stepCount | int | Step count |
| metLevel1 | float | MET level 1 intensity |
| metLevel2 | float | MET level 2 intensity |
| metLevel3 | float | MET level 3 intensity |
| ... | ... | ... |
| metLevel13 | float | MET level 13 intensity |

**Note:** 13 MET levels represent different activity intensity buckets.

### MotionEvent (0x47)

**Source:** `com.ouraring.ringeventparser.message.MotionEvent`

| Field | Type | Description |
|-------|------|-------------|
| timestamp | long | Unix timestamp (ms) |
| orientation | int | Ring orientation on finger |
| motionSeconds | int | Seconds of motion detected |
| averageX | float | Average accelerometer X-axis |
| averageY | float | Average accelerometer Y-axis |
| averageZ | float | Average accelerometer Z-axis |
| regularity | int | Motion regularity metric |
| lowIntensity | int | Low-intensity motion count |
| highIntensity | int | High-intensity motion count |

### WearEvent (0x53)

**Source:** `com.ouraring.ringeventparser.message.WearEvent`

| Field | Type | Description |
|-------|------|-------------|
| timestamp | long | Unix timestamp (ms) |
| state | int | Wear state (enum: ON_FINGER, OFF_FINGER, etc.) |
| text | String | Optional text description |

### Spo2Event (0x6F)

**Source:** `com.ouraring.ringeventparser.message.Spo2Event`

| Field | Type | Description |
|-------|------|-------------|
| timestamp | long | Unix timestamp (ms) |
| beatOffset | int | Offset from beat |
| beatIndex | int | Index of the heartbeat |
| spo2Value | int | SpO2 percentage (0-100) |

### StateChangeIndValue (0x45)

**Source:** `com.ouraring.ringeventparser.message.StateChangeIndValue`

| Field | Type | Description |
|-------|------|-------------|
| timestamp | long | Unix timestamp (ms) |
| state | StateChange | Ring state enum |
| text | String | State description |

### SleepPhaseDetails (0x4E)

**Source:** `com.ouraring.ringeventparser.SleepPhaseDetailsKt`

| Field | Type | Description |
|-------|------|-------------|
| timestamp | repeated long | Timestamps (ms) |
| startTime | repeated int | Phase start times (offset) |
| sleepPhases | repeated SleepPhase_OSSAv1 | Sleep phase classifications |

---

## Binary Format: 0x6A (SLEEP_PERIOD_INFO_2)

**16 bytes total** - Custom binary format (NOT protobuf)

```
Offset  Size  Field              Scaling
------  ----  -----              -------
0       1     Event ID (0x6A)    -
1       1     Length (0x0E = 14) -
2-5     4     Ring timestamp     deciseconds since boot (LE)
6       1     avgHr              * 0.5 (BPM)
7       1     hrTrend            * 0.0625
8       1     mzci               * 0.0625 (HRV metric)
9       1     dzci               * 0.0625 (HRV metric)
10-11   2     (reserved)         -
12      1     motionCount        0-120 seconds
13      1     sleepState         0=awake, 1=light, 2=deep/REM
14-15   2     cv                 / 65536.0 (PPG quality)
```

---

## Binary Format: 0x46 (TEMP_EVENT)

**13 bytes total** - Custom binary format

```
Offset  Size  Field              Scaling
------  ----  -----              -------
0       1     Event ID (0x46)    -
1       1     Length             -
2       1     Format marker      0x0A
3-4     2     Timestamp/counter  uint16 LE
5-6     2     (reserved)         -
7-8     2     Temp sensor 1      / 100.0 (°C)
9-10    2     Reference temp     / 100.0 (~32°C)
11-12   2     Temp sensor 2      / 100.0 (°C)
```

---

## Protobuf Wire Format

Most events use standard protobuf encoding:

| Wire Type | Value | Encoding |
|-----------|-------|----------|
| 0 | Varint | int32, int64, uint32, bool |
| 1 | 64-bit | fixed64, double |
| 2 | Length-delimited | string, bytes, nested, packed repeated |
| 5 | 32-bit | fixed32, float |

**Field header:** `(field_number << 3) | wire_type`

---

## Native Library Interface

### libringeventparser.so (3.2 MB)

**JNI Entry Points:**
```cpp
// Constructor
RingEventParser::RingEventParser()
Mangled: _ZN15RingEventParserC1Ev

// Main parsing function
void* RingEventParser::parse_events(
    const unsigned char* data,
    unsigned int len,
    unsigned int* events_received
)
Mangled: _ZN15RingEventParser12parse_eventsEPKhjPj

// Sleep period parser
void EventParser::parse_api_sleep_period_info(const Event& event)
Mangled: _ZN11EventParser27parse_api_sleep_period_infoERK5Event
```

**Kotlin Wrapper:** `RingEventParserObj.kt`
```kotlin
external fun nativeParseEvents(
    ringEvents: ByteArray,
    ringTime: Int,
    utcTime: Long,
    jzLogMode: Boolean
): Ringeventparser.RingData
```

---

## Sleep State Values

| Value | State | Description |
|-------|-------|-------------|
| 0 | Awake | User is awake |
| 1 | Light | Light sleep stage |
| 2 | Deep | Deep sleep / SWS |
| 3 | REM | REM sleep stage |

---

## MET Levels (Activity)

MET = Metabolic Equivalent of Task

| Level | Intensity | Example |
|-------|-----------|---------|
| 1-3 | Light | Sitting, standing |
| 4-6 | Moderate | Walking |
| 7-9 | Vigorous | Jogging |
| 10-13 | Very high | Running, sports |

---

## Source Files Reference

| Data Model | Source File |
|------------|-------------|
| RingEventType | `ringeventparser/data/RingEventType.java` |
| SleepPeriodInfoValue | `ringeventparser/message/SleepPeriodInfoValue.java` |
| ActivityInfoEvent | `ringeventparser/message/ActivityInfoEvent.java` |
| HrvEvent | `ringeventparser/HrvEventKt.java` |
| TempEvent | `ringeventparser/TempEventKt.java` |
| IbiAndAmplitudeEvent | `ringeventparser/IbiAndAmplitudeEventKt.java` |
| MotionEvent | `ringeventparser/message/MotionEvent.java` |
| WearEvent | `ringeventparser/message/WearEvent.java` |
| Spo2Event | `ringeventparser/message/Spo2Event.java` |
| StateChangeIndValue | `ringeventparser/message/StateChangeIndValue.java` |
| SleepPhaseDetails | `ringeventparser/SleepPhaseDetailsKt.java` |

All paths relative to: `_large_files/decompiled/sources/com/ouraring/`

---

## Live Verification Results (2026-01-11 to 2026-01-12)

### Initial Capture (184 events)

| Event Type | Count | Status | Sample Values |
|------------|-------|--------|---------------|
| 0x41 RING_START_IND | 1 | ✓ | Boot timestamp |
| 0x45 STATE_CHANGE_IND | 14 | ✓ | "chg. stopped", "hr enable" |
| 0x46 TEMP_EVENT | 36 | ✓ | 30.05°C, 31.00°C, 25.71°C |
| 0x47 MOTION_EVENT | 32 | ✓ | Accelerometer data |
| 0x50 ACTIVITY_INFO | 2 | ✓ | 87 steps |
| 0x53 WEAR_EVENT | 1 | ✓ | State=3 (on finger) |
| 0x5b BLE_CONNECTION_IND | 8 | ✓ | Connection params |
| 0x69 TEMP_PERIOD | 1 | ✓ | 30.08°C avg |
| 0x6c FEATURE_SESSION | 9 | ✓ | Session type/state |
| 0x6d MEAS_QUALITY_EVENT | 23 | ✓ | Quality metrics |
| 0x80 GREEN_IBI_QUALITY_EVENT | 55 | ✓ | ~107 BPM avg |
| 0x82 SCAN_START | 1 | ✓ | Scan config |
| 0x83 SCAN_END | 1 | ✓ | Scan results |

### Overnight Sleep Capture (4794 events, 9 hours)

| Event Type | Count | Status | Sample Values |
|------------|-------|--------|---------------|
| 0x60 IBI_AND_AMPLITUDE_EVENT | 2774 | ✓ | Raw IBI + PPG amplitude |
| 0x72 SLEEP_ACM_PERIOD | 553 | ✓ | Sleep activity/motion |
| 0x6a SLEEP_PERIOD_INFO_2 | 549 | ✓ | HR, sleep state, breath |
| 0x46 TEMP_EVENT | 314 | ✓ | Body/ambient temps |
| 0x80 GREEN_IBI_QUALITY_EVENT | 228 | ✓ | Green LED IBI quality |
| 0x45 STATE_CHANGE_IND | 84 | ✓ | State transitions |
| 0x47 MOTION_EVENT | 77 | ✓ | Movement detection |
| 0x75 SLEEP_TEMP_EVENT | 69 | ✓ | 7 temp sensors (~35°C) |
| 0x6d MEAS_QUALITY_EVENT | 38 | ✓ | Measurement quality |
| 0x83 SCAN_END | 25 | ✓ | PPG scan results |
| 0x50 ACTIVITY_INFO | 17 | ✓ | Steps/activity |
| 0x5b BLE_CONNECTION_IND | 13 | ✓ | BLE events |
| 0x82 SCAN_START | 13 | ✓ | PPG scan start |
| 0x6c FEATURE_SESSION | 11 | ✓ | Session lifecycle |
| 0x6b MOTION_PERIOD | 11 | ✓ | Motion summaries |
| 0x5d HRV_EVENT | 8 | ✓ | RMSSD/SDNN |
| 0x69 TEMP_PERIOD | 6 | ✓ | Temp summaries |
| 0x41 RING_START_IND | 2 | ✓ | Boot events |
| 0x53 WEAR_EVENT | 1 | ✓ | On-finger detection |
| 0x5c USER_INFO | 1 | ✓ | User config |

### Sleep Analysis (0x6a SLEEP_PERIOD_INFO_2)

**Summary (387 unique samples over 9.01 hours):**
- **Heart Rate:** 51.5 - 70.0 BPM (avg: 59.0 BPM)
- **Sleep States:** 22.6% awake, 77.4% light
- **Motion Count:** 0-29 seconds (avg: 1.5)

**Sleep State Distribution:**
```
State 0 (awake): 124 samples (22.6%)
State 1 (light): 425 samples (77.4%)
State 2 (deep):  0 samples (0%)
```

### Additional Event Formats Verified

**SLEEP_ACM_PERIOD (0x72) - 18 bytes:**
```
[0]    tag: 0x72
[1]    len: 16
[2-5]  timestamp (deciseconds LE)
[6-7]  activity metric 1
[8-9]  activity metric 2
...
```

**SLEEP_TEMP_EVENT (0x75) - 20 bytes:**
```
[0]    tag: 0x75
[1]    len: 18
[2-5]  timestamp (deciseconds LE)
[6-7]  temp1: ~35°C (body)
[8-9]  temp2: ~35°C
...    (7 temperature sensors total)
```

**HRV_EVENT (0x5d) - 18 bytes:**
```
[0]    tag: 0x5d
[1]    len: 16
[2-5]  timestamp (deciseconds LE)
[6-7]  HRV metric 1 (RMSSD-related)
[8-9]  HRV metric 2
...    (up to 6 values)
```

---

## Real-time Heartbeat Monitoring

**IBI Streaming Protocol:**
- IBI streaming works correctly
- Sample: 66.2 BPM (IBI: 907ms), 65.6 BPM (IBI: 914ms)
- Data format: `[8:9]` = IBI in milliseconds (little-endian uint16)

---

## Temperature Sensor Mapping

**0x46 TEMP_EVENT (3 sensors):**
- Temp1: Body-side sensor (~30°C on finger during day)
- Temp2: Reference sensor (~31°C)
- Temp3: Ambient/external (~26°C)

**0x75 SLEEP_TEMP_EVENT (7 sensors):**
- All sensors ~35°C during sleep (finger skin temperature)
- Higher precision for sleep tracking

---

## Implementation Notes

1. **Ring factory reset clears stored events**
2. **Sleep data (0x6A) requires overnight wear**
3. **Events consumed when read** (single-read buffer)
4. **Timestamps are deciseconds** (divide by 10 for seconds)
5. **Export immediately after data fetch** - events cleared on re-fetch
