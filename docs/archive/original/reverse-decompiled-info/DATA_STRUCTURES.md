# Data Structures Reference

Quick reference for all key data classes in the Oura Ring app.

---

## Sleep Structures

### SleepInfo (Main Sleep Output)

Complete sleep analysis output from `nativeCalculateSleepScore()`.

```java
SleepInfo implements EcoreInfo {
    // Timestamps
    long timestampUtc
    int timeZone
    long bedtimeStartUtc, bedtimeEndUtc
    int bedtimeStartTimeZone, bedtimeEndTimeZone

    // Core metrics
    int sleepPeriodId
    int timeInBedInSeconds
    int isLongestSleepPeriod     // 1 = main sleep period
    int alertInfo

    // Heart metrics
    int averageHrv, averageNonRemHrv, averageRemHrv
    int lowestHr5min
    int lowestHr5minTimeInSecondsSinceBedtimeStart

    // Time series (strings encode per-interval values)
    String nightlyMovements30sec    // Motion per 30s
    String sleepPhasesPer5Minutes   // Phase symbols (D/L/R/A)
    String sleepPhasesPer30Seconds
    int[] hrPer5Minutes, hrPer10Minutes
    int[] hrvPer5Minutes

    // Nested summaries
    SleepSummary2 sleepSummary2
    SleepSummary3 sleepSummary3
    SleepSummary4 sleepSummary4
    RecoverySummary recoverySummary
}
```

**Source:** `ecorelibrary/info/SleepInfo.java`

### SleepSummary2 (9 fields) - Duration & Efficiency

```java
SleepSummary2 {
    int wakeTimeInSeconds
    int remSleepTimeInSeconds
    int lightSleepTimeInSeconds
    int deepSleepTimeInSeconds
    int totalSleepTimeInSeconds
    int latencyInSeconds        // Time to fall asleep
    int wakeUpCount
    int score                   // Sleep score 0-100
    int efficiency              // Sleep efficiency %
}
```

### SleepSummary3 (7 fields) - Physiology

```java
SleepSummary3 {
    int breathAverageTimesEight     // Avg breathing rate × 8
    int breathVAverageTimesEight    // Breathing variability × 8
    int hrAverageTimesEight         // Avg HR × 8
    int sleepMidPoint               // Midpoint time (seconds from midnight?)
    int highestTemperatureInCentidegrees
    int restlessPeriods
    int gotUpCount
}
```

**Note:** Values multiplied by 8 for fixed-point precision (divide by 8 for actual value).

### SleepSummary4 (7 fields) - Score Contributors

```java
SleepSummary4 {
    int totalSleepScore         // Contributor: total duration
    int deepSleepScore          // Contributor: deep sleep
    int remSleepScore           // Contributor: REM sleep
    int sleepEfficiency         // Contributor: efficiency
    int sleepLatency            // Contributor: time to fall asleep
    int sleepDisturbances       // Contributor: wake-ups
    int circadianAlignment      // Contributor: timing
}
```

**These are the 7 Sleep Score contributors (each 0-100).**

### SleepDebtInput (3 fields)

```java
SleepDebtInput {
    int historyDaysCount
    int[] longTermSleepTimeAvgSeconds  // Rolling average
    int[] dailySleepsDurationSeconds   // Recent days
}
```

### SleepDebtOutput (3 fields)

```java
SleepDebtOutput {
    int dailySleepDebt        // Today's deficit (seconds)
    int cumulativeSleepDebt   // Accumulated deficit
    boolean isPersistent      // Is debt chronic?
}
```

---

## Readiness Structures

### ReadinessScoreOutput (12 fields)

Output from `nativeCalculateReadinessScore()`.

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

---

## Activity Structures

### ActInfo (35+ fields)

Complete activity output from `nativeCalculateActivityScore()`.

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

### ActivityInput (20 fields)

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

## Baseline Structures

### Baseline (20 fields)

Rolling averages and deviations for score normalization.

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

**Source:** `ecorelibrary/baseline/Baseline.java`

### BaselineItem (4 fields)

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

## IBI (Inter-Beat Interval) Structures

### IbiAndAmplitudeEvent

Raw IBI from ring vs corrected by native algorithm.

```java
// Raw from BLE (before correction)
IbiAndAmplitudeEvent.Raw {
    long timestamp          // Unix millis
    int ibi                 // Inter-beat interval (ms)
    int amplitude           // PPG signal amplitude
}

// After nativeIbiCorrection()
IbiAndAmplitudeEvent.Corrected {
    long timestamp
    int ibi
    int amplitude
    int validity            // 0-3 quality indicator
}
```

**Source:** `ecorelibrary/ibi/IbiAndAmplitudeEvent.java`

---

## HR/HRV Output Structures

### HrHrvOutputInfo (14 fields)

Heart rate and HRV measurement output.

```java
HrHrvOutputInfo implements EcoreInfo {
    long timestampUtcSeconds
    int timeZoneMinutes
    int hr                          // Heart rate BPM
    int hrv                         // HRV (RMSSD) in ms
    int hrvScaled                   // Scaled HRV
    int sourceValue                 // LED source (enum)
    boolean restorative             // Is restorative time?
    int cqi                         // Contact quality index
    int pqi                         // PPG quality index
    int quality                     // Overall quality
    int hrvAccuracy                 // HRV accuracy (-1 = N/A)
    int measurementDurationMinutes
    int _ibiQuality                 // IBI quality (255 = N/A)
    HrHrvInputStatisticsInfo inputStatistics
}
```

### HrHrvOutputInfo.Source (8 values)

PPG LED source combinations.

| Value | Name | Description |
|-------|------|-------------|
| 0 | UNKNOWN | Unknown source |
| 1 | IR | Infrared LED |
| 2 | GREEN | Green LED |
| 3 | RED | Red LED |
| 4 | IR_AND_GREEN | IR + Green |
| 5 | IR_AND_RED | IR + Red |
| 6 | GREEN_AND_RED | Green + Red |
| 7 | IR_AND_GREEN_AND_RED | All three |

---

## SpO2 Structures

### SpO2Info (6 fields)

Blood oxygen measurement output.

```java
SpO2Info implements EcoreInfo {
    long timestampUtcMillis
    int timeZone
    int dataTypeEcoreValue      // SpO2EcoreDataType enum value
    int spo2AvgValue            // Average SpO2 %
    float spo2AvgQuality        // Quality score
    SpO2Drop drop               // Drop event details (optional)
}
```

### SpO2Drop (20 fields!)

Detailed SpO2 drop (desaturation) event.

```java
SpO2Drop {
    // Timing
    long startTimeMillis
    long lowestTimeMillis

    // Drop characteristics
    float riseRate              // Recovery rate
    float dropRate              // Desaturation rate
    int duration                // Duration (seconds)
    int depth                   // Depth (% points)

    // Signal quality
    float dcDiffDropRate1, dcDiffDropRate2
    boolean peak

    // Context
    float avgTemp               // Temperature during drop
    float meanMotion            // Motion during drop
    float medianPi              // Perfusion index
    float dcCorr1, dcCorr2      // DC correlation

    // HR correlation
    float hrPeakPerc
    float pulseCount
    float hrDelta               // HR change during drop

    // Classification
    float dropThreshold
    float dropProbability       // ML probability
    boolean drop                // Is valid drop?
}
```

**Source:** `ecorelibrary/info/SpO2Drop.java`

---

## Breathing Structures

### BreathingRateInput (4 fields)

Input for breathing rate calculation.

```java
BreathingRateInput {
    long bedtimeStartMillis
    short[] ibiValues           // IBI array (ms)
    long[] ibiTimestampsMillis
    byte[] motionSeconds        // Motion per second
}
```

### BreathingRateOutput (3 fields)

```java
BreathingRateOutput {
    float avgBreathingRate          // Breaths per minute
    float avgBreathingRateVariability
    float avgHeartRate              // Concurrent HR
}
```

---

## Rest Mode Structures

### RestModeInput (3 fields)

```java
RestModeInput {
    long restPeriodStartUtcTimeSeconds
    long restPeriodEndUtcTimeSeconds
    long currentMidnightUtcTimeSeconds
}
```

---

## Utility Structures

### PostProcessEventsResult (2 fields)

Result of event post-processing.

```java
PostProcessEventsResult {
    int ringTime        // Ring internal timestamp
    long utcTime        // UTC timestamp

    // Derived
    boolean timeMissing // True if both are 0
}
```

### DailyOutput (2 fields)

Simple daily scores output.

```java
DailyOutput {
    int sleepScore      // 0-100
    int readinessScore  // 0-100
}
```

---

## Score Contributors Summary

### Sleep Score (7 Contributors)

| Contributor | Field | Description |
|-------------|-------|-------------|
| Total Sleep | `totalSleepScore` | Duration vs target |
| Deep Sleep | `deepSleepScore` | Deep sleep duration |
| REM Sleep | `remSleepScore` | REM duration |
| Efficiency | `sleepEfficiency` | Time asleep / time in bed |
| Latency | `sleepLatency` | Time to fall asleep |
| Disturbances | `sleepDisturbances` | Wake-up count |
| Timing | `circadianAlignment` | Bedtime consistency |

### Readiness Score (8+ Contributors)

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

### Activity Score (6 Contributors)

| Contributor | Field | Description |
|-------------|-------|-------------|
| Meet Daily Goals | `sevenDayTargetScore` | Target completion |
| Stay Active | `twentyFourHourInactiveTimeScore` | Active minutes |
| Move Every Hour | `twentyFourHourInactiveAlertScore` | Hourly movement |
| Training Frequency | `sevenDayExerciseFrequencyScore` | Exercise days |
| Training Volume | `sevenDayExerciseAmountScore` | Exercise intensity |
| Recovery Time | `sevenDayRestScore` | Rest days |

---

## Data Type Scaling

Many fields use fixed-point scaling for precision:

| Pattern | Scaling | Example |
|---------|---------|---------|
| `*TimesEight` | × 8 | breathAverageTimesEight / 8 = actual BPM |
| `*Times32` | × 32 | metTimes32 / 32 = actual MET |
| `*Centidegrees` | × 100 | 3700 = 37.00°C |
| `*Minutes` | minutes | Direct value |
| `*Seconds` | seconds | Direct value |
| `*Millis` | milliseconds | Unix timestamp |

---

## EcoreInfo Interface

Marker interface for all ecore output structures.

```java
interface EcoreInfo {
    // Marker interface - no methods
    // Implemented by: SleepInfo, ActInfo, SpO2Info, HrHrvOutputInfo, etc.
}
```

---

## File References

| Structure | Location |
|-----------|----------|
| SleepInfo | `ecorelibrary/info/SleepInfo.java` |
| ActInfo | `ecorelibrary/info/ActInfo.java` |
| Baseline | `ecorelibrary/baseline/Baseline.java` |
| ReadinessScoreOutput | `ecorelibrary/readiness/ReadinessScoreOutput.java` |
| IbiAndAmplitudeEvent | `ecorelibrary/ibi/IbiAndAmplitudeEvent.java` |
| SpO2Info / SpO2Drop | `ecorelibrary/info/SpO2Info.java`, `SpO2Drop.java` |
| HrHrvOutputInfo | `ecorelibrary/info/HrHrvOutputInfo.java` |
| SleepDebt* | `ecorelibrary/sleep/SleepDebt*.java` |
| BreathingRate* | `ecorelibrary/sleep/BreathingRate*.java` |

---

**See also:** [NATIVE_LIBRARIES.md](NATIVE_LIBRARIES.md), [EVENT_TYPES.md](EVENT_TYPES.md), [BLE_COMMANDS.md](BLE_COMMANDS.md)
