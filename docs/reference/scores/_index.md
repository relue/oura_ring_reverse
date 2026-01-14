# Score Algorithms Reference

Sleep, Readiness, and Activity score calculations.

---

## Score Overview

| Score | Range | Contributors | Native Method |
|-------|-------|--------------|---------------|
| Sleep | 0-100 | 7 | `nativeCalculateSleepScore()` |
| Readiness | 0-100 | 8+ | `nativeCalculateReadinessScore()` |
| Activity | 0-100 | 6 | `nativeCalculateActivityScore()` |

---

## Quick Navigation

| Score | Document | Description |
|-------|----------|-------------|
| Sleep | [sleep.md](sleep.md) | 7 contributors, SleepSummary4 |
| Readiness | [readiness.md](readiness.md) | 8+ contributors, ReadinessScoreOutput |
| Activity | [activity.md](activity.md) | 6 contributors, ActInfo |

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

## Baseline Requirements

All scores are normalized against rolling baselines.

| Baseline | Purpose | Window |
|----------|---------|--------|
| Sleep time | Sleep duration target | 14 days |
| Resting HR | HR normalization | 14 days |
| HRV | HRV normalization | 14 days |
| Temperature | Temp deviation | 90 days |
| Activity distance | Activity target | 14 days |

**Source:** `ecorelibrary/baseline/Baseline.java`

---

## Source References

**Decompiled Classes:**
- `com.ouraring.ecorelibrary.EcoreWrapper`
- `com.ouraring.ecorelibrary.info.SleepInfo`
- `com.ouraring.ecorelibrary.info.ActInfo`
- `com.ouraring.ecorelibrary.readiness.ReadinessScoreOutput`
- `com.ouraring.ecorelibrary.baseline.Baseline`

**Source Files:**
```
_large_files/decompiled/sources/com/ouraring/ecorelibrary/
├── EcoreWrapper.java
├── info/SleepInfo.java
├── info/ActInfo.java
├── readiness/ReadinessScoreOutput.java
└── baseline/Baseline.java
```

---

## See Also

- [Structures](../structures/_index.md) - Data class definitions
- [Native Libraries](../native/ecore.md) - EcoreWrapper methods
- [Data Flow](../flow/processing.md) - Score calculation pipeline
