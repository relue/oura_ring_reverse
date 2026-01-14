# Motion Events

Accelerometer data, motion detection, and wear state events.

---

## Event Summary

| Tag | Hex | Event Name | Priority | Description |
|-----|-----|------------|----------|-------------|
| 69 | 0x45 | API_MOTION_EVENT | High | Motion/accelerometer |
| 71 | 0x47 | API_WEAR_EVENT | High | Ring wear detection |
| 76 | 0x4C | API_RAW_ACM_EVENT | Low | Raw accelerometer data |
| 98 | 0x62 | API_MOTION_PERIOD_EVENT | Medium | Motion period summary |
| 100 | 0x64 | API_SLEEP_ACM_PERIOD_EVENT | Medium | Sleep accelerometer period |
| 105 | 0x69 | API_EHR_ACM_INTENSITY_EVENT | Medium | Exercise accelerometer |
| 110 | 0x6E | API_ON_DEMAND_MOTION_EVENT | Low | On-demand motion |

---

## 0x45 - API_MOTION_EVENT (Primary)

**Source:** `com.ouraring.ringeventparser.message.MotionEvent`
**File:** `MotionEvent.java:10-18`
**Priority:** High - Motion detection
**Frequency:** During motion detection

### Protobuf Fields

| Field | Name | Type | Description |
|-------|------|------|-------------|
| 1 | timestamp | long | Unix timestamp (ms) |
| 2 | orientation | int | Ring orientation on finger |
| 3 | motionSeconds | int | Seconds of motion in period |
| 4 | averageX | float | Average accelerometer X-axis |
| 5 | averageY | float | Average accelerometer Y-axis |
| 6 | averageZ | float | Average accelerometer Z-axis |
| 7 | regularity | int | Motion regularity metric |
| 8 | lowIntensity | int | Low-intensity motion count |
| 9 | highIntensity | int | High-intensity motion count |

### Live Capture Data

- **Initial capture:** 32 events verified
- **Overnight capture:** 77 events (motion during sleep)

---

## 0x47 - API_WEAR_EVENT

**Source:** `com.ouraring.ringeventparser.message.WearEvent`
**File:** `WearEvent.java:7-10`
**Priority:** High - Ring wear state
**Frequency:** On wear state change

### Protobuf Fields

| Field | Name | Type | Description |
|-------|------|------|-------------|
| 1 | timestamp | long | Unix timestamp (ms) |
| 2 | wearState | int | Wear state enum |
| 3 | confidence | int | Detection confidence |

### Wear State Values

| Value | State | Description |
|-------|-------|-------------|
| 0 | NOT_WORN | Ring not on finger |
| 1 | WORN | Ring on finger |
| 2 | UNKNOWN | Cannot determine |
| 3 | ON_FINGER | Confirmed on finger |

### Live Capture Data

- **Initial capture:** 1 event, State=3 (on finger)
- **Overnight capture:** 1 event (constant wear during sleep)

---

## 0x4C - API_RAW_ACM_EVENT

**Priority:** Low - Raw accelerometer data

Raw accelerometer samples for detailed motion analysis.

---

## 0x62 - API_MOTION_PERIOD_EVENT

**Priority:** Medium - Motion period summary

Aggregated motion data for a time period.

### Live Capture Data

11 events captured during overnight session.

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

### Binary Format (18 bytes)

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

## 0x69 - API_EHR_ACM_INTENSITY_EVENT

**Priority:** Medium - Exercise accelerometer intensity

Accelerometer intensity data during exercise for activity classification and calorie estimation.

---

## 0x6E - API_ON_DEMAND_MOTION_EVENT

**Priority:** Low - On-demand motion

Motion data captured during on-demand measurement sessions.

---

## Accelerometer Specifications

| Parameter | Value |
|-----------|-------|
| Axes | 3 (X, Y, Z) |
| Sample Rate | Variable (activity-dependent) |
| Resolution | 16-bit |
| Range | ±8g (typical) |

---

## Motion Detection Flow

```
1. Accelerometer samples captured continuously
2. Motion detected via threshold crossing
3. API_MOTION_EVENT generated with:
   - Average acceleration per axis
   - Motion duration in seconds
   - Intensity classification
4. Sleep motion tracked separately via 0x64
5. Activity classification via ML models
```

---

## Source References

**Decompiled Classes:**
- `com.ouraring.ringeventparser.message.MotionEvent`
- `com.ouraring.ringeventparser.message.WearEvent`
- `com.ouraring.ringeventparser.message.SleepAcmPeriodValue`

**Source Files:**
```
_large_files/decompiled/sources/com/ouraring/
├── ringeventparser/
│   ├── MotionEventKt.java
│   ├── WearEventKt.java
│   └── message/
│       ├── MotionEvent.java
│       ├── WearEvent.java
│       └── SleepAcmPeriodValue.java
└── ecorelibrary/
    └── info/ActInfo.java
```

**ML Models:**
- `AUTOMATIC_ACTIVITY` - Motion-based activity detection
- `STEP_COUNTER` - Step detection from accelerometer

**Related:**
- `ecorelibrary/info/ActInfo.java` - Activity output with motion metrics

---

## See Also

- [Activity Events](activity.md) - Step counting and activity summaries
- [Sleep Events](sleep.md) - Sleep motion tracking (0x64)
