# Activity Events

Step counting, MET levels, activity summaries, and RealSteps feature events.

---

## Event Summary

| Tag | Hex | Event Name | Priority | Description |
|-----|-----|------------|----------|-------------|
| 87 | 0x57 | API_ACTIVITY_SUMMARY_1 | Medium | Activity summary 1 |
| 88 | 0x58 | API_ACTIVITY_SUMMARY_2 | Medium | Activity summary 2 |
| 89 | 0x59 | API_RECOVERY_SUMMARY | Medium | Recovery score |
| 103 | 0x67 | API_ACTIVITY_INFO_EVENT | High | Activity metrics (steps, MET) |
| 105 | 0x69 | API_EHR_ACM_INTENSITY_EVENT | Medium | Exercise accelerometer intensity |
| 121 | 0x79 | API_REAL_STEP_EVENT_FEATURE_1 | Medium | RealSteps feature 1 |
| 122 | 0x7A | API_REAL_STEP_EVENT_FEATURE_2 | Medium | RealSteps feature 2 |
| 126 | 0x7E | API_WHR_EVENT | Medium | Workout heart rate |
| 127 | 0x7F | API_WHR_SESSION_EVENT | Medium | Workout HR session |

---

## MET Level Reference

MET = Metabolic Equivalent of Task

| Level | Intensity | Example |
|-------|-----------|---------|
| 1-3 | Light | Sitting, standing |
| 4-6 | Moderate | Walking |
| 7-9 | Vigorous | Jogging |
| 10-13 | Very high | Running, sports |

---

## 0x67 - API_ACTIVITY_INFO_EVENT (Primary)

**Source:** `com.ouraring.ringeventparser.message.ActivityInfoEvent`
**File:** `ActivityInfoEvent.java:8-22`
**Priority:** High - Main activity metrics
**Frequency:** Periodic during activity

### Protobuf Fields

| Field | Name | Type | Description |
|-------|------|------|-------------|
| 1 | timestamp | long | Unix timestamp (ms) |
| 2 | stepCount | int | Step count |
| 3 | metLevel1 | float | MET level 1 duration |
| 4 | metLevel2 | float | MET level 2 duration |
| 5 | metLevel3 | float | MET level 3 duration |
| 6 | metLevel4 | float | MET level 4 duration |
| 7 | metLevel5 | float | MET level 5 duration |
| 8 | metLevel6 | float | MET level 6 duration |
| 9 | metLevel7 | float | MET level 7 duration |
| 10 | metLevel8 | float | MET level 8 duration |
| 11 | metLevel9 | float | MET level 9 duration |
| 12 | metLevel10 | float | MET level 10 duration |
| 13 | metLevel11 | float | MET level 11 duration |
| 14 | metLevel12 | float | MET level 12 duration |
| 15 | metLevel13 | float | MET level 13 duration |

**Note:** 13 MET levels represent different activity intensity buckets from sedentary (1) to vigorous exercise (13).

### Live Capture Data

- 2 events in initial capture: 87 steps
- 17 events in overnight capture (minimal activity during sleep)

---

## 0x79 - API_REAL_STEP_EVENT_FEATURE_1

**Priority:** Medium - FFT-based step detection

### Protobuf Fields

| Field | Name | Type | Description |
|-------|------|------|-------------|
| 1 | timestamp | long | Ring milliseconds |
| 2 | realStepFeature | RealStepsFeatures | Step feature data |

### RealStepsFeatures Structure

| Field | Type | Description |
|-------|------|-------------|
| isHandrail | int | Handrail detected flag |
| isPocket | int | Phone in pocket flag |
| cadence | int | Steps per minute |
| isLeftRight | int | Left/right detection |
| leftRightConf | int | L/R confidence |
| armSwing | int | Arm swing detected |
| motionType | int | Motion classification |
| handrailSteps | int | Steps while holding handrail |
| fftBins | RealStepsFFTset | 24 FFT bin values |

### Usage

FFT-based step detection using frequency analysis of accelerometer data. The 24 FFT bins capture the frequency spectrum of motion for accurate step counting.

---

## 0x7A - API_REAL_STEP_EVENT_FEATURE_2

**Priority:** Medium - Extended step features

Extended step features with additional motion classification data.

---

## Activity Summary Events

### 0x57 - API_ACTIVITY_SUMMARY_1

Basic activity metrics summary.

### 0x58 - API_ACTIVITY_SUMMARY_2

Extended activity data summary.

---

## 0x59 - API_RECOVERY_SUMMARY

Recovery score calculation data.

---

## Workout HR Events

### 0x7E - API_WHR_EVENT

Workout heart rate measurements during exercise.

### 0x7F - API_WHR_SESSION_EVENT

Workout HR session metadata and configuration.

---

## 0x69 - API_EHR_ACM_INTENSITY_EVENT

**Priority:** Medium - Exercise accelerometer intensity

Accelerometer intensity data during exercise for activity classification.

---

## Activity Tracking Flow

```
1. Wear detection → API_WEAR_EVENT (0x47)
2. Step counting:
   - API_REAL_STEP_EVENT_FEATURE_1 (0x79) - FFT features
   - API_ACTIVITY_INFO_EVENT (0x67) - step counts + MET
3. Activity summaries → API_ACTIVITY_SUMMARY_1/2 (0x57/0x58)
```

---

## Activity Score Contributors

From `ActInfo` structure:

| Contributor | Field | Description |
|-------------|-------|-------------|
| Meet Daily Goals | `sevenDayTargetScore` | Target completion |
| Stay Active | `twentyFourHourInactiveTimeScore` | Active minutes |
| Move Every Hour | `twentyFourHourInactiveAlertScore` | Hourly movement |
| Training Frequency | `sevenDayExerciseFrequencyScore` | Exercise days |
| Training Volume | `sevenDayExerciseAmountScore` | Exercise intensity |
| Recovery Time | `sevenDayRestScore` | Rest days |

---

## Source References

**Decompiled Classes:**
- `com.ouraring.ringeventparser.message.ActivityInfoEvent`
- `com.ouraring.ringeventparser.RealStepsFeatures`
- `com.ouraring.ringeventparser.RealStepsFFTset`

**Source Files:**
```
_large_files/decompiled/sources/com/ouraring/
├── ringeventparser/
│   ├── ActivityInfoEventKt.java
│   └── message/
│       └── ActivityInfoEvent.java
└── ecorelibrary/
    └── info/ActInfo.java
```

**Native Methods:**
- `EcoreWrapper.nativeCalculateActivityScore()` - Activity scoring

**ML Models:**
- `STEP_COUNTER` - Step counting ML model
- `AUTOMATIC_ACTIVITY` - Auto activity detection (5.7 MB)

**Related:**
- `ecorelibrary/info/ActInfo.java` - Activity output structure (35+ fields)
- `pytorch/PyTorchModelType.STEP_COUNTER` - Step ML model

---

## See Also

- [Data Structures](../structures/activity.md) - ActInfo, ActivityInput structures
- [ML Models](../ml/_index.md) - STEP_COUNTER, AUTOMATIC_ACTIVITY models
- [Motion Events](motion.md) - Raw accelerometer data
