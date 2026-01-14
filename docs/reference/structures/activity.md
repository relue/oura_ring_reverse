# Activity Data Structures

Activity score inputs and outputs.

---

## ActInfo (35+ fields)

Complete activity output from `nativeCalculateActivityScore()`.

**Source:** `ecorelibrary/info/ActInfo.java`

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

---

## ActivityInput (20 fields)

Input for activity score calculation.

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

## Activity Score Contributors Summary

| Contributor | Field | Description |
|-------------|-------|-------------|
| Meet Daily Goals | `sevenDayTargetScore` | Target completion |
| Stay Active | `twentyFourHourInactiveTimeScore` | Active minutes |
| Move Every Hour | `twentyFourHourInactiveAlertScore` | Hourly movement |
| Training Frequency | `sevenDayExerciseFrequencyScore` | Exercise days |
| Training Volume | `sevenDayExerciseAmountScore` | Exercise intensity |
| Recovery Time | `sevenDayRestScore` | Rest days |

---

## MET Level Reference

MET = Metabolic Equivalent of Task

| Level | Intensity | Example |
|-------|-----------|---------|
| 1-3 | Light | Sitting, standing |
| 4-6 | Moderate | Walking |
| 7-9 | Vigorous | Jogging |
| 10-13 | Very high | Running, sports |

**Note:** `metTimes32` is MET × 32 for fixed-point precision.

---

## Source References

**Decompiled Classes:**
- `com.ouraring.ecorelibrary.info.ActInfo`
- `com.ouraring.ecorelibrary.activity.ActivityInput`

**Source Files:**
```
_large_files/decompiled/sources/com/ouraring/ecorelibrary/
├── info/ActInfo.java
└── activity/ActivityInput.java
```

---

## See Also

- [Activity Events](../events/activity.md) - Events producing activity data
- [Scores](../scores/activity.md) - Activity score calculation
