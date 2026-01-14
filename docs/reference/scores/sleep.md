# Sleep Score

Sleep score calculation with 7 contributors.

---

## Overview

| Metric | Value |
|--------|-------|
| Score Range | 0-100 |
| Contributors | 7 |
| Native Method | `nativeCalculateSleepScore()` |
| Output Class | `SleepInfo` |

---

## 7 Sleep Score Contributors

Stored in `SleepSummary4`:

| # | Contributor | Field | Description |
|---|-------------|-------|-------------|
| 1 | Total Sleep | `totalSleepScore` | Duration vs target (7-9 hours) |
| 2 | Deep Sleep | `deepSleepScore` | Deep sleep percentage (15-20% target) |
| 3 | REM Sleep | `remSleepScore` | REM percentage (20-25% target) |
| 4 | Efficiency | `sleepEfficiency` | Time asleep / time in bed (>85% good) |
| 5 | Latency | `sleepLatency` | Time to fall asleep (<20 min good) |
| 6 | Disturbances | `sleepDisturbances` | Wake-up count (fewer is better) |
| 7 | Timing | `circadianAlignment` | Bedtime consistency |

---

## SleepSummary4 Structure

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

**Source:** `ecorelibrary/info/SleepSummary4.java`

---

## Input Data Requirements

### From SleepInfo

```java
// Core sleep metrics
int timeInBedInSeconds
String sleepPhasesPer5Minutes   // Phase symbols (D/L/R/A)
int[] hrPer5Minutes
int[] hrvPer5Minutes

// Nested summaries
SleepSummary2 sleepSummary2     // Duration & efficiency
SleepSummary3 sleepSummary3     // Physiology
```

### SleepSummary2 (Duration Data)

```java
SleepSummary2 {
    int wakeTimeInSeconds
    int remSleepTimeInSeconds
    int lightSleepTimeInSeconds
    int deepSleepTimeInSeconds
    int totalSleepTimeInSeconds
    int latencyInSeconds        // Time to fall asleep
    int wakeUpCount
    int score                   // Final score 0-100
    int efficiency              // Sleep efficiency %
}
```

---

## Baseline Usage

Sleep score uses these baselines:

| Baseline | Field | Purpose |
|----------|-------|---------|
| Sleep time average | `sleepTimeAverage` | Duration target |
| Sleep time deviation | `sleepTimeDeviation` | Normalization |
| Sleep score average | `sleepScoreAverage` | Trending |

---

## Sleep Stages

Sleep is classified into 4 stages per 5-minute epoch:

| Code | Stage | Description |
|------|-------|-------------|
| A | Awake | User is awake |
| L | Light | Light sleep (N1/N2) |
| D | Deep | Deep sleep / SWS (N3) |
| R | REM | REM sleep stage |

**Output format:** String per 5-minute epoch
```
"LLLLLDDDLLLRRRRLLLL"
```

---

## Sleep Debt

Sleep debt tracks accumulated sleep deficit.

```java
SleepDebtInput {
    int historyDaysCount
    int[] longTermSleepTimeAvgSeconds  // Rolling average
    int[] dailySleepsDurationSeconds   // Recent days
}

SleepDebtOutput {
    int dailySleepDebt        // Today's deficit (seconds)
    int cumulativeSleepDebt   // Accumulated deficit
    boolean isPersistent      // Is debt chronic?
}
```

**Source:** `ecorelibrary/sleep/SleepDebtInput.java`, `SleepDebtOutput.java`

---

## Calculation Flow

```
1. Collect sleep events from ring
   - IBI events
   - Temperature events
   - Motion events

2. Run sleep staging
   - SleepNet ML model (Ring 3/4)
   - Or NSSA native algorithm

3. Calculate durations
   - Total sleep time
   - Time per stage (Deep/Light/REM)
   - Time awake

4. Compute contributors
   - Each contributor 0-100
   - Based on targets and baselines

5. Aggregate final score
   - Weighted combination
   - Output 0-100
```

---

## Source References

**Decompiled Classes:**
- `com.ouraring.ecorelibrary.EcoreWrapper`
- `com.ouraring.ecorelibrary.info.SleepInfo`
- `com.ouraring.ecorelibrary.info.SleepSummary2`
- `com.ouraring.ecorelibrary.info.SleepSummary3`
- `com.ouraring.ecorelibrary.info.SleepSummary4`
- `com.ouraring.ecorelibrary.sleep.SleepDebtInput`
- `com.ouraring.ecorelibrary.sleep.SleepDebtOutput`

**Source Files:**
```
_large_files/decompiled/sources/com/ouraring/ecorelibrary/
├── EcoreWrapper.java
├── info/
│   ├── SleepInfo.java
│   ├── SleepSummary2.java
│   ├── SleepSummary3.java
│   └── SleepSummary4.java
└── sleep/
    ├── SleepDebtInput.java
    └── SleepDebtOutput.java
```

---

## See Also

- [Sleep Structures](../structures/sleep.md) - Full SleepInfo definition
- [Sleep Events](../events/sleep.md) - BLE sleep events
- [SleepNet Models](../ml/sleepnet.md) - ML staging
