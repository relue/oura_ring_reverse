# Readiness Score

Readiness score calculation with 8+ contributors.

---

## Overview

| Metric | Value |
|--------|-------|
| Score Range | 0-100 |
| Contributors | 8 core + 4 optional |
| Native Method | `nativeCalculateReadinessScore()` |
| Output Class | `ReadinessScoreOutput` |

---

## 8 Core Contributors

| # | Contributor | Field | Description |
|---|-------------|-------|-------------|
| 1 | Activity Balance | `activityBalance` | Activity vs recovery balance |
| 2 | Previous Day Activity | `lastDayActivity` | Yesterday's activity level |
| 3 | Last Night's Sleep | `lastNightSleep` | Sleep quality/duration |
| 4 | Resting HR | `restingHr` | RHR vs baseline |
| 5 | RHR Time | `restingHrTime` | Time of lowest HR |
| 6 | Sleep Balance | `sleepBalance` | Sleep debt status |
| 7 | Temperature | `temperature` | Temp vs baseline |
| 8 | HRV Balance | `hrvBalance` | HRV vs baseline |

---

## 4 Optional Contributors

| Contributor | Field | When Used |
|-------------|-------|-----------|
| Sleep Regularity | `sleepRegularity` | Consistency score |
| Temperature Deviation | `temperatureDeviation` | Temp anomaly |
| Temperature Trend | `temperatureTrendDeviation` | Temp trending |

---

## ReadinessScoreOutput Structure

```java
ReadinessScoreOutput {
    int score                       // Overall readiness 0-100

    // 8 Core Contributors (each 0-100)
    int activityBalance             // Activity vs recovery
    int lastDayActivity             // Previous day activity
    int lastNightSleep              // Last night's sleep quality
    int restingHr                   // RHR vs baseline
    int restingHrTime               // Time of lowest HR
    int sleepBalance                // Sleep debt status
    int temperature                 // Temp vs baseline

    // 4 Optional Contributors
    Integer hrvBalance              // HRV vs baseline
    Integer sleepRegularity         // Consistency
    Integer temperatureDeviation    // Temp deviation
    Integer temperatureTrendDeviation
}
```

**Source:** `ecorelibrary/readiness/ReadinessScoreOutput.java`

---

## Input Requirements

### ReadinessScoreSleepInput (13 fields)

Sleep data required for readiness calculation.

```java
ReadinessScoreSleepInput {
    long sleepDateUtcSeconds
    int dayNumber
    int sleepScore
    int timeInBedSeconds
    int totalSleepSeconds
    int remSleepSeconds
    int deepSleepSeconds
    int latencySeconds
    int wakeUpCount
    int highestTempCentidegrees
    int lowestHr
    int lowestHrTimeSeconds
    int rmssd                    // HRV (RMSSD in ms)
}
```

### ReadinessScoreHistoryInput (6 arrays)

Historical data for readiness trending.

```java
ReadinessScoreHistoryInput {
    int[] temperatureDeviationHistory3Days
    int[] highestTempCentidegHistory90Days
    int[] totalSleepSecondsHistory14Days
    int[] walkingDistanceMetersHistory14Days
    byte[] wearPercentageHistory14Days
    int[] rmssdHistory14Days
}
```

### PreviousDayInput (7 fields)

Previous day activity for readiness calculation.

```java
PreviousDayInput {
    int equivalentWalkingDistanceMeters
    int nonWearTimeMinutes
    int sedentaryTimeMinutes
    int vigorousTimeMinutes
    int lightTimeMinutes
    int moderateTimeMinutes
    int restingTimeMinutes
}
```

---

## Baseline Requirements

Readiness uses these baselines:

| Baseline | Field | Window | Purpose |
|----------|-------|--------|---------|
| Resting HR | `restingHrAverage` | 14 days | HR normalization |
| RHR deviation | `restingHrDeviation` | 14 days | Variance |
| RHR time | `restingHrTimeAverage` | 14 days | Timing baseline |
| HRV | `hrvAverage` | 14 days | HRV normalization |
| Temperature | `temperatureAverage` | 90 days | Temp baseline |
| Sleep time | `sleepTimeAverage` | 14 days | Sleep target |
| Activity | `activityDistanceAverage` | 14 days | Activity target |

---

## Calculation Flow

```
1. Collect last night's sleep data
   - Sleep score
   - Duration metrics
   - HR/HRV data
   - Temperature

2. Collect previous day activity
   - Walking distance
   - Activity intensity levels
   - Rest time

3. Load historical data
   - 14-day sleep history
   - 14-day activity history
   - 90-day temperature history

4. Load baselines
   - Rolling averages
   - Standard deviations

5. Compute contributors
   - Each contributor 0-100
   - Compare to baselines

6. Aggregate final score
   - Weighted combination
   - Output 0-100
```

---

## Contributor Interpretation

| Score Range | Interpretation |
|-------------|----------------|
| 85-100 | Optimal readiness |
| 70-84 | Good readiness |
| 60-69 | Pay attention |
| < 60 | Take it easy |

### Key Signals

| Contributor | Low Score Means |
|-------------|-----------------|
| `restingHr` | HR elevated vs baseline |
| `hrvBalance` | HRV suppressed vs baseline |
| `temperature` | Temp deviation from normal |
| `sleepBalance` | Accumulated sleep debt |
| `lastNightSleep` | Poor sleep last night |

---

## Source References

**Decompiled Classes:**
- `com.ouraring.ecorelibrary.EcoreWrapper`
- `com.ouraring.ecorelibrary.readiness.ReadinessScoreOutput`
- `com.ouraring.ecorelibrary.readiness.ReadinessScoreSleepInput`
- `com.ouraring.ecorelibrary.readiness.ReadinessScoreHistoryInput`
- `com.ouraring.ecorelibrary.activity.PreviousDayInput`
- `com.ouraring.ecorelibrary.baseline.Baseline`

**Source Files:**
```
_large_files/decompiled/sources/com/ouraring/ecorelibrary/
├── EcoreWrapper.java
├── readiness/
│   ├── ReadinessScoreOutput.java
│   ├── ReadinessScoreSleepInput.java
│   └── ReadinessScoreHistoryInput.java
├── activity/PreviousDayInput.java
└── baseline/Baseline.java
```

---

## See Also

- [Readiness Structures](../structures/readiness.md) - Full structure definitions
- [Sleep Score](sleep.md) - Sleep score input
- [Activity Score](activity.md) - Activity balance input
