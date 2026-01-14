# Activity Score

Activity score calculation with 6 contributors.

---

## Overview

| Metric | Value |
|--------|-------|
| Score Range | 0-100 |
| Contributors | 6 |
| Native Method | `nativeCalculateActivityScore()` |
| Output Class | `ActInfo` |

---

## 6 Activity Score Contributors

| # | Contributor | Field | Description |
|---|-------------|-------|-------------|
| 1 | Meet Daily Goals | `sevenDayTargetScore` | Target completion over 7 days |
| 2 | Stay Active | `twentyFourHourInactiveTimeScore` | Active minutes in 24h |
| 3 | Move Every Hour | `twentyFourHourInactiveAlertScore` | Hourly movement alerts |
| 4 | Training Frequency | `sevenDayExerciseFrequencyScore` | Exercise days over 7 days |
| 5 | Training Volume | `sevenDayExerciseAmountScore` | Exercise intensity over 7 days |
| 6 | Recovery Time | `sevenDayRestScore` | Rest days over 7 days |

---

## ActInfo Structure (35+ fields)

```java
ActInfo implements EcoreInfo {
    // Timestamps
    long timestampUtc, dayStartUtc
    int timeZone, dayStartTimeZone

    // Distance & Time
    int equivalentWalkingDistanceInMeters
    int nonWearTimeInMinutes
    int restingTimeInMinutes
    int sedentaryTimeInMinutes
    int lightActivityTimeInMinutes
    int moderateActivityTimeInMinutes
    int vigorousActivityTimeInMinutes

    // MET & Calories
    int metTimes32                 // MET × 32
    int steps
    int activeCalories
    int totalCalories
    int targetCalories
    int metMinSedentary
    int metMinLightActivity
    int metMinModerateActivity
    int metMinVigorousActivity

    // Activity Score (0-100)
    int score

    // Score Contributors
    int sevenDayTargetScore              // Meet daily goals
    int twentyFourHourInactiveTimeScore  // Stay active
    int twentyFourHourInactiveAlertScore // Move every hour
    int sevenDayExerciseFrequencyScore   // Training frequency
    int sevenDayExerciseAmountScore      // Training volume
    int sevenDayRestScore                // Recovery time

    // Targets
    int targetDistanceInMeters
    int metersToTarget
    int targetType, targetMultiplier, targetSteps
    int inactivityAlertCount

    // Flags
    int isDummyDay
    boolean isUpdate
}
```

**Source:** `ecorelibrary/info/ActInfo.java`

---

## Input Requirements

### ActivityInput (20 fields)

```java
ActivityInput {
    long midnightUtc
    int timeZone
    int equivalentWalkingDistanceMeters
    int nonWearTimeMinutes
    int sedentaryTimeMinutes
    int vigorousTimeMinutes
    int lightTimeMinutes
    int moderateTimeMinutes
    int restingTimeMinutes
    int steps
    int inactivityAlertCount
    int metTimes32
    long dataTimestamp
    boolean isUpdate
    int totalCalories
    int activeCalories
    int targetCalories
    int metMinSedentary
    // ... more MET fields
}
```

---

## MET Level Reference

MET = Metabolic Equivalent of Task

| MET Range | Intensity | Example Activities |
|-----------|-----------|-------------------|
| 1-3 | Light | Sitting, standing, slow walk |
| 4-6 | Moderate | Walking, light cycling |
| 7-9 | Vigorous | Jogging, swimming |
| 10-13 | Very high | Running, sports |

**Note:** `metTimes32` is MET × 32 for fixed-point precision (divide by 32 for actual value).

---

## Time Categories

| Category | Field | Description |
|----------|-------|-------------|
| Non-wear | `nonWearTimeInMinutes` | Ring not worn |
| Resting | `restingTimeInMinutes` | Sleeping, low activity |
| Sedentary | `sedentaryTimeInMinutes` | Sitting, minimal movement |
| Light | `lightActivityTimeInMinutes` | Light activity |
| Moderate | `moderateActivityTimeInMinutes` | Medium intensity |
| Vigorous | `vigorousActivityTimeInMinutes` | High intensity |

---

## Baseline Requirements

Activity uses these baselines:

| Baseline | Field | Window | Purpose |
|----------|-------|--------|---------|
| Distance | `activityDistanceAverage` | 14 days | Target distance |
| Distance deviation | `activityDistanceDeviation` | 14 days | Variance |
| Vigorous activity | `vigorousActivityAverage` | 14 days | Exercise baseline |
| Sedentary | `sedentaryActivityAverage` | 14 days | Inactivity baseline |

---

## Target Calculation

```
Daily Target = activityDistanceAverage × targetMultiplier

targetType values:
- 0: Standard (maintain)
- 1: Increase
- 2: Recovery (reduce)

metersToTarget = targetDistanceInMeters - equivalentWalkingDistanceInMeters
```

---

## Calculation Flow

```
1. Collect daily activity data
   - Steps from ring
   - Motion intensity
   - Time per category

2. Calculate metrics
   - Equivalent walking distance
   - MET minutes per category
   - Calories (active + total)

3. Load 7-day history
   - Previous days' targets met
   - Exercise days
   - Rest days

4. Compute contributors
   - Each contributor 0-100
   - Based on 7-day windows

5. Aggregate final score
   - Weighted combination
   - Output 0-100
```

---

## Contributor Interpretation

| Contributor | Measures | Improves By |
|-------------|----------|-------------|
| Meet Daily Goals | Target % over 7 days | Hitting daily movement targets |
| Stay Active | Active time in 24h | Avoiding long sedentary periods |
| Move Every Hour | Hourly alerts | Standing/moving hourly |
| Training Frequency | Exercise days | Working out regularly |
| Training Volume | Exercise intensity | Increasing workout intensity |
| Recovery Time | Rest days | Taking adequate rest |

---

## Step Counting

Steps are counted using ML models:

| Model | Purpose |
|-------|---------|
| STEP_COUNTER | Step counting (1.2.0) |
| STEPS_MOTION_DECODER | Motion decoding (1.0.0) |

**Source:** [ML Models](../ml/_index.md)

---

## Source References

**Decompiled Classes:**
- `com.ouraring.ecorelibrary.EcoreWrapper`
- `com.ouraring.ecorelibrary.info.ActInfo`
- `com.ouraring.ecorelibrary.activity.ActivityInput`
- `com.ouraring.ecorelibrary.baseline.Baseline`

**Source Files:**
```
_large_files/decompiled/sources/com/ouraring/ecorelibrary/
├── EcoreWrapper.java
├── info/ActInfo.java
├── activity/ActivityInput.java
└── baseline/Baseline.java
```

---

## See Also

- [Activity Structures](../structures/activity.md) - Full ActInfo definition
- [Activity Events](../events/activity.md) - BLE activity events
- [ML Models](../ml/_index.md) - Step counter models
