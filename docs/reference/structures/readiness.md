# Readiness Data Structures

Readiness score inputs and outputs.

---

## ReadinessScoreOutput (12 fields)

Output from `nativeCalculateReadinessScore()`.

**Source:** `ecorelibrary/readiness/ReadinessScoreOutput.java`

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

---

## ReadinessScoreSleepInput (13 fields)

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

---

## ReadinessScoreHistoryInput (6 arrays)

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

---

## Baseline (20 fields)

Rolling averages and deviations for score normalization.

**Source:** `ecorelibrary/baseline/Baseline.java`

```java
Baseline {
    long dayMidnightUtcSeconds
    int dayTimeZone

    // Sleep baseline
    int sleepScoreAverage
    int sleepScoreDeviation
    int sleepTimeAverage
    int sleepTimeDeviation

    // Resting HR baseline
    int restingHrAverage
    int restingHrDeviation
    int restingHrTimeAverage      // Avg time of lowest HR
    int restingHrTimeDeviation

    // Activity baseline
    int activityDistanceAverage
    int activityDistanceDeviation
    int vigorousActivityAverage
    int vigorousActivityDeviation
    int sedentaryActivityAverage
    int sedentaryActivityDeviation

    // Temperature baseline
    int temperatureAverage        // Centidegrees
    int temperatureDeviation

    // HRV baseline
    int hrvAverage                // RMSSD in ms
    int hrvDeviation
}
```

---

## BaselineItem (4 fields)

Single baseline value with statistics.

```java
BaselineItem {
    long dayMidnightUtcSeconds
    int dayTimeZone
    int average
    int deviation
}
```

---

## PreviousDayInput (7 fields)

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

## RestModeInput (3 fields)

```java
RestModeInput {
    long restPeriodStartUtcTimeSeconds
    long restPeriodEndUtcTimeSeconds
    long currentMidnightUtcTimeSeconds
}
```

---

## Readiness Score Contributors Summary

| Contributor | Field | Description |
|-------------|-------|-------------|
| Activity Balance | `activityBalance` | Activity vs recovery |
| Previous Day | `lastDayActivity` | Yesterday's activity |
| Sleep | `lastNightSleep` | Last night's sleep |
| Resting HR | `restingHr` | RHR vs baseline |
| RHR Time | `restingHrTime` | Time of lowest HR |
| Sleep Balance | `sleepBalance` | Sleep debt status |
| Temperature | `temperature` | Temp vs baseline |
| HRV Balance | `hrvBalance` | HRV vs baseline (optional) |

---

## Source References

**Decompiled Classes:**
- `com.ouraring.ecorelibrary.readiness.ReadinessScoreOutput`
- `com.ouraring.ecorelibrary.readiness.ReadinessScoreSleepInput`
- `com.ouraring.ecorelibrary.readiness.ReadinessScoreHistoryInput`
- `com.ouraring.ecorelibrary.baseline.Baseline`
- `com.ouraring.ecorelibrary.activity.PreviousDayInput`

**Source Files:**
```
_large_files/decompiled/sources/com/ouraring/ecorelibrary/
├── readiness/
│   ├── ReadinessScoreOutput.java
│   ├── ReadinessScoreSleepInput.java
│   └── ReadinessScoreHistoryInput.java
├── baseline/Baseline.java
└── activity/PreviousDayInput.java
```

---

## See Also

- [Scores](../scores/readiness.md) - Readiness score calculation
- [Native Libraries](../native/ecore.md) - nativeCalculateReadinessScore
