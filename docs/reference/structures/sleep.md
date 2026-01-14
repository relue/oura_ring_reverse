# Sleep Data Structures

Sleep output structures from native algorithms.

---

## SleepInfo (Main Sleep Output)

Complete sleep analysis output from `nativeCalculateSleepScore()`.

**Source:** `ecorelibrary/info/SleepInfo.java`

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

---

## SleepSummary2 (Duration & Efficiency)

9 fields for sleep duration and efficiency metrics.

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

---

## SleepSummary3 (Physiology)

7 fields for physiological metrics.

```java
SleepSummary3 {
    int breathAverageTimesEight     // Avg breathing rate × 8
    int breathVAverageTimesEight    // Breathing variability × 8
    int hrAverageTimesEight         // Avg HR × 8
    int sleepMidPoint               // Midpoint time
    int highestTemperatureInCentidegrees
    int restlessPeriods
    int gotUpCount
}
```

**Note:** Values multiplied by 8 for fixed-point precision (divide by 8 for actual value).

---

## SleepSummary4 (Score Contributors)

7 fields - the 7 Sleep Score contributors (each 0-100).

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

---

## SleepDebtInput

```java
SleepDebtInput {
    int historyDaysCount
    int[] longTermSleepTimeAvgSeconds  // Rolling average
    int[] dailySleepsDurationSeconds   // Recent days
}
```

---

## SleepDebtOutput

```java
SleepDebtOutput {
    int dailySleepDebt        // Today's deficit (seconds)
    int cumulativeSleepDebt   // Accumulated deficit
    boolean isPersistent      // Is debt chronic?
}
```

---

## BreathingRateInput

```java
BreathingRateInput {
    long bedtimeStartMillis
    short[] ibiValues           // IBI array (ms)
    long[] ibiTimestampsMillis
    byte[] motionSeconds        // Motion per second
}
```

---

## BreathingRateOutput

```java
BreathingRateOutput {
    float avgBreathingRate          // Breaths per minute
    float avgBreathingRateVariability
    float avgHeartRate              // Concurrent HR
}
```

---

## Sleep Score Contributors Summary

| Contributor | Field | Description |
|-------------|-------|-------------|
| Total Sleep | `totalSleepScore` | Duration vs target |
| Deep Sleep | `deepSleepScore` | Deep sleep duration |
| REM Sleep | `remSleepScore` | REM duration |
| Efficiency | `sleepEfficiency` | Time asleep / time in bed |
| Latency | `sleepLatency` | Time to fall asleep |
| Disturbances | `sleepDisturbances` | Wake-up count |
| Timing | `circadianAlignment` | Bedtime consistency |

---

## Source References

**Decompiled Classes:**
- `com.ouraring.ecorelibrary.info.SleepInfo`
- `com.ouraring.ecorelibrary.sleep.SleepDebtInput`
- `com.ouraring.ecorelibrary.sleep.SleepDebtOutput`
- `com.ouraring.ecorelibrary.sleep.BreathingRateInput`
- `com.ouraring.ecorelibrary.sleep.BreathingRateOutput`

**Source Files:**
```
_large_files/decompiled/sources/com/ouraring/ecorelibrary/
├── info/SleepInfo.java
└── sleep/
    ├── SleepDebtInput.java
    ├── SleepDebtOutput.java
    ├── BreathingRateInput.java
    └── BreathingRateOutput.java
```

---

## See Also

- [Sleep Events](../events/sleep.md) - Events that produce sleep data
- [Scores](../scores/sleep.md) - Sleep score calculation
