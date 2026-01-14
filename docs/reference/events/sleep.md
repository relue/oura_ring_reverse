# Sleep Events

Sleep period tracking, summaries, phases, and sleep-specific measurements.

---

## Event Summary

| Tag | Hex | Event Name | Priority | Description |
|-----|-----|------------|----------|-------------|
| 79 | 0x4F | API_SLEEP_PERIOD_INFO | High | Primary sleep session data |
| 80 | 0x50 | API_SLEEP_SUMMARY_1 | Medium | Sleep metrics summary 1 |
| 81 | 0x51 | API_SLEEP_SUMMARY_2 | Medium | Sleep metrics summary 2 |
| 82 | 0x52 | API_SLEEP_SUMMARY_3 | Medium | Sleep metrics summary 3 |
| 83 | 0x53 | API_SLEEP_SUMMARY_4 | Medium | Sleep metrics summary 4 |
| 90 | 0x5A | API_SLEEP_PHASE_INFO | High | Sleep phase breakdown |
| 92 | 0x5C | API_SLEEP_TEMP_EVENT | Medium | Temperature during sleep |
| 94 | 0x5E | API_SLEEP_HR_EVENT | High | Heart rate during sleep |
| 99 | 0x63 | API_BEDTIME_PERIOD_EVENT | Medium | Bedtime period tracking |
| 100 | 0x64 | API_SLEEP_ACM_PERIOD_EVENT | Medium | Sleep accelerometer period |
| 101 | 0x65 | API_SLEEP_PHASE_DETAILS | High | Detailed sleep phases |
| 102 | 0x66 | API_SLEEP_PHASE_DATA | Medium | Raw sleep phase data |
| 113 | 0x71 | API_SLEEP_PERIOD_INFO_2 | High | Extended minute-by-minute |
| 114 | 0x72 | API_RING_SLEEP_FEATURE_INFO | Medium | Sleep features |
| 115 | 0x73 | API_RING_SLEEP_FEATURE_INFO_2 | Medium | Extended sleep features |

---

## Sleep State Values

| Value | State | Description |
|-------|-------|-------------|
| 0 | Awake | User is awake |
| 1 | Light | Light sleep stage (N1/N2) |
| 2 | Deep | Deep sleep / SWS (N3) |
| 3 | REM | REM sleep stage |

---

## 0x4F - API_SLEEP_PERIOD_INFO (Primary)

**Source:** `com.ouraring.ringeventparser.message.SleepPeriodInfoValue`
**File:** `SleepPeriodInfoValue.java:5-13`
**Priority:** High - Primary sleep session data
**Frequency:** Once per sleep period (typically every minute)

### Protobuf Fields

| Field | Name | Type | Description |
|-------|------|------|-------------|
| 1 | timestamp | uint32/long | Unix timestamp of sleep start (ms) |
| 2 | avgHr | float | Average heart rate (BPM) |
| 3 | hrTrend | float/int32 | Heart rate trend indicator |
| 4 | avgIBI | float | Average inter-beat interval (ms) |
| 5 | stdIBI | float | Standard deviation of IBI (ms) |
| 6 | avgBreathingRate | float | Average breathing rate (breaths/min) |
| 7 | stdBreathingRate | float | Std dev of breathing rate |
| 8 | motionCount | int | Motion/movement count |
| 9 | sleepState | int | Sleep state: 0=Awake, 1=Light, 2=Deep, 3=REM |
| 10 | cvPPGSignalAmplitude | float | PPG signal quality (CV) |

### Binary Example

```hex
48 08 80 B8 D4 01 10 46 18 00 20 8C 03 28 DC 02 30 0E 38 05 40 32 48 02 50 14
```

**Decoded:**
- Field 1 (timestamp): 3450000
- Field 2 (avgHr): 70 BPM
- Field 3 (hrTrend): 0
- Field 4 (avgIBI/mzci): 396 ms
- Field 5 (stdIBI/dzci): 348 ms
- Field 6 (breath): 14 breaths/min
- Field 7 (breathV): 5
- Field 8 (motionCount): 50
- Field 9 (sleepState): 2 (Deep sleep)
- Field 10 (cv): 20

---

## 0x71 - API_SLEEP_PERIOD_INFO_2 (Extended)

**Priority:** High - Minute-by-minute sleep data
**Format:** Custom binary (NOT protobuf)

### Binary Format (16 bytes total)

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

### Live Capture Analysis (387 unique samples, 9.01 hours)

- **Heart Rate:** 51.5 - 70.0 BPM (avg: 59.0 BPM)
- **Sleep States:** 22.6% awake, 77.4% light
- **Motion Count:** 0-29 seconds (avg: 1.5)

**Sleep State Distribution:**
```
State 0 (awake): 124 samples (22.6%)
State 1 (light): 425 samples (77.4%)
State 2 (deep):  0 samples (0%)
```

---

## 0x5E - API_SLEEP_HR_EVENT

**Priority:** High - Sleep heart rate
**Frequency:** Multiple per sleep session (every 5 minutes)

### Protobuf Fields

| Field | Name | Type | Description |
|-------|------|------|-------------|
| 1 | timestamp | uint32 | Unix timestamp of measurement |
| 2 | heartRate | uint32 | Heart rate value (BPM) |
| 3 | quality | uint32 | Signal quality (0-100) |
| 4 | beatIndex | uint32 | Beat sequence index |
| 5 | flags | uint32 | Status flags |
| 6 | reserved | bytes | Reserved for future use |

### Binary Example

```hex
55 08 A0 B8 D4 01 10 48 18 5A 20 0A 28 00
```

**Decoded:**
- Field 1 (timestamp): 3450016
- Field 2 (heartRate): 72 BPM
- Field 3 (quality): 90%
- Field 4 (beatIndex): 10
- Field 5 (flags): 0

---

## 0x65 - API_SLEEP_PHASE_DETAILS

**Source:** `com.ouraring.ringeventparser.SleepPhaseDetailsKt`
**Priority:** High - Per sleep session

### Protobuf Fields

| Field | Name | Type | Description |
|-------|------|------|-------------|
| 1 | timestamp | repeated long | Timestamps (ms) |
| 2 | startTime | repeated int | Phase start times (offset) |
| 3 | sleepPhases | repeated SleepPhase_OSSAv1 | Sleep phase classifications |

---

## 0x64 - API_SLEEP_ACM_PERIOD_EVENT

**Source:** `com.ouraring.ringeventparser.message.SleepAcmPeriodValue`
**File:** `SleepAcmPeriodValue.java:5-10`
**Priority:** Medium - Sleep accelerometer period

### Protobuf Fields

| Field | Name | Type | Description |
|-------|------|------|-------------|
| 1 | fingerAngleMean | float | Mean finger angle |
| 2 | fingerAngleMax | float | Max finger angle |
| 3 | fingerAngleIrq | float | Finger angle interquartile range |
| 4 | madTrimmedMean | float | MAD trimmed mean (motion) |
| 5 | madTrimmedMax | float | MAD trimmed max |
| 6 | madTrimmedIqr | float | MAD interquartile range |

**Usage:** Finger angle indicates hand position changes during sleep. MAD = Median Absolute Deviation for motion detection.

### Binary Format (18 bytes total)

```
Offset  Size  Field              Description
------  ----  -----              -----------
0       1     tag                0x72
1       1     len                16
2-5     4     timestamp          deciseconds LE
6-7     2     activity metric 1  Movement intensity
8-9     2     activity metric 2  Movement intensity
...
```

### Live Capture Data

553 events captured during overnight sleep session.

---

## 0x63 - API_BEDTIME_PERIOD_EVENT

**Source:** `com.ouraring.ringeventparser.message.BedtimePeriodValue`
**File:** `BedtimePeriodValue.java:5-10`
**Priority:** Medium - Bedtime period tracking

### Protobuf Fields

| Field | Name | Type | Description |
|-------|------|------|-------------|
| 1 | startTime | long | Bedtime period start |
| 2 | endTime | long | Bedtime period end |
| 3 | avgMadTrimmedMean | float | Average motion |
| 4 | avgMadTrimmedMax | float | Max motion |
| 5 | avgMadTrimmedIqr | float | Motion variability |

---

## Sleep Summary Events (0x50-0x53)

| Tag | Event | Content |
|-----|-------|---------|
| 0x50 | API_SLEEP_SUMMARY_1 | Basic sleep metrics |
| 0x51 | API_SLEEP_SUMMARY_2 | Extended sleep data |
| 0x52 | API_SLEEP_SUMMARY_3 | Sleep phase breakdowns |
| 0x53 | API_SLEEP_SUMMARY_4 | Additional sleep stats |

---

## 0x5C - API_SLEEP_TEMP_EVENT

**Priority:** Medium - Temperature during sleep
**Format:** Custom binary (20 bytes total)

### Binary Format

```
Offset  Size  Field              Description
------  ----  -----              -----------
0       1     tag                0x75
1       1     len                18
2-5     4     timestamp          deciseconds LE
6-7     2     temp1              ~35C (body)
8-9     2     temp2              ~35C
...                              (7 temperature sensors total)
```

### Live Capture Data

69 events captured during overnight sleep. All 7 sensors ~35C (finger skin temperature during sleep).

---

## Sleep Data Collection Flow

```
1. Ring detects bedtime → API_BEDTIME_PERIOD_EVENT (0x63)
2. Continuous collection:
   - API_IBI_AND_AMPLITUDE_EVENT (0x60) - every heartbeat
   - API_TEMP_EVENT (0x46) - periodic temperature
   - API_MOTION_EVENT (0x45) - motion detection
3. Sleep period aggregation:
   - API_SLEEP_PERIOD_INFO (0x4F) - periodic summaries
   - API_SLEEP_ACM_PERIOD_EVENT (0x64) - motion summaries
4. Wake detection → API_SLEEP_SUMMARY_1-4 (0x50-0x53)
```

---

## Sleep Staging

Sleep stages are classified by SleepNet ML model or NSSA native algorithm:

| Stage | Code | Duration Target |
|-------|------|-----------------|
| Awake | A | < 10% of time in bed |
| Light | L | ~55% of total sleep |
| Deep | D | 15-20% of total sleep |
| REM | R | 20-25% of total sleep |

**Output format:** String per 5-minute epoch, e.g., "LLLLLDDDLLLRRRRLLLL"

---

## Source References

**Decompiled Classes:**
- `com.ouraring.ringeventparser.message.SleepPeriodInfoValue`
- `com.ouraring.ringeventparser.SleepPhaseDetailsKt`
- `com.ouraring.ringeventparser.message.SleepAcmPeriodValue`
- `com.ouraring.ringeventparser.message.BedtimePeriodValue`

**Source Files:**
```
_large_files/decompiled/sources/com/ouraring/
├── ringeventparser/
│   ├── SleepPeriodInfoKt.java
│   ├── SleepPhaseDetailsKt.java
│   └── message/
│       ├── SleepPeriodInfoValue.java
│       ├── SleepAcmPeriodValue.java
│       └── BedtimePeriodValue.java
└── ecorelibrary/
    └── info/SleepInfo.java
```

**Native Methods:**
- `EcoreWrapper.nativeCalculateSleepScore()` - Sleep scoring
- `NssaManager.handleSleepScores()` - NSSA processing

**Related:**
- `ecorelibrary/info/SleepInfo.java` - Main sleep output structure
- `oura/sleep/sleepnet/model/SleepNetPytorchModel.java` - ML sleep staging

---

## See Also

- [Data Structures](../structures/sleep.md) - SleepInfo, SleepSummary structures
- [ML Models](../ml/sleepnet.md) - SleepNet model details
- [Temperature Events](temperature.md) - Sleep temperature (0x5C, 0x75)
