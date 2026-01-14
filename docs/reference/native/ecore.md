# EcoreWrapper JNI Interface

Main Java interface to native algorithms with 68+ native methods.

**Source:** `com/ouraring/ecorelibrary/EcoreWrapper.java`

---

## Initialization Methods

| Method | Parameters | Returns |
|--------|------------|---------|
| `nativeInitialize` | macAddress, persistentStateV1, activityTypes, isPersistentV2, debugEnabled | long (handle) |
| `nativeClose` | - | void |
| `nativeInitIbiCorrection` | - | void |
| `nativeInitRestorativeTime` | nightAvgTemp, nightAvgHr | boolean |
| `nativeInitSleepRegularity` | SleepRegularityInitInput[] | boolean |

---

## Score Calculation Methods

### nativeCalculateSleepScore

```java
SleepInfo nativeCalculateSleepScore(
    String sleepPhases,
    int[] motionSeconds,
    BedtimePeriod bedtimePeriod,
    HrHrv5MinAverage[] hrHrv5MinAverages
)
```

**Returns:** `SleepInfo` with score 0-100 and all contributors

### nativeCalculateReadinessScore

```java
ReadinessScoreOutput nativeCalculateReadinessScore(
    ReadinessScoreSleepInput sleepInput,
    PreviousDayInput previousDayInput,
    Baseline baseline,
    ReadinessScoreHistoryInput historyInput
)
```

**Returns:** `ReadinessScoreOutput` with score and 8+ contributors

### nativeCalculateActivityScore

```java
ActInfo nativeCalculateActivityScore(ActivityInput input)
```

**Returns:** `ActInfo` with score and 6 contributors

### nativeCalculateBaseline

```java
Baseline nativeCalculateBaseline(
    Baseline currentBaseline,
    // Plus 16 params: scores, times, HR, temp, HRV
)
```

**Returns:** Updated `Baseline` with rolling averages

### nativeCalculateSleepDebt

```java
SleepDebtOutput nativeCalculateSleepDebt(SleepDebtInput input)
```

### nativeCalculateBreathingRate

```java
BreathingRateOutput nativeCalculateBreathingRate(BreathingRateInput input)
```

### nativeCalculateBdi

```java
double nativeCalculateBdi(
    int totalSleepSec,
    int validSpO2Sec,
    SpO2Drop[] drops
)
```

---

## IBI Correction Pipeline

The IBI correction algorithm filters and validates raw inter-beat interval data.

```java
// 1. Initialize correction
nativeInitIbiCorrection();

// 2. Feed raw IBI values (call for each beat)
nativeIbiCorrection(int ibi, int amplitude, long timestamp);

// 3. Get corrected values via callbacks
// → IbiAndAmplitudeEvent.Corrected (adds validity field)
```

### Validity Values

| Value | Meaning |
|-------|---------|
| 0 | Invalid |
| 1 | Uncertain |
| 2 | Interpolated |
| 3 | Valid |

---

## Event Processing Methods

| Method | Input | Returns |
|--------|-------|---------|
| `nativeProcessEvents` | byte[] ringEvents, count | boolean |
| `nativePostProcessEvents` | ringEvents, count, ringTime, utcTime | PostProcessEventsResult |
| `nativeProcessActivityEvent` | byte[] event | int |
| `nativeProcessRestModeEvent` | byte[] event | int |

---

## Baseline Methods

| Method | Purpose |
|--------|---------|
| `nativeGetBaseline` | Get current baseline |
| `nativeSetBaseline` | Set baseline |
| `nativeCalculateTemperatureBaseline` | Update temp baseline |
| `nativeGetDefaultTemperatureBaseline` | Default temp baseline |

---

## State Serialization

| Method | Purpose |
|--------|---------|
| `nativeSerializePersistentStateV1` | Get V1 state bytes |
| `nativeSerializePersistentStateV2` | Get V2 state size |
| `nativeDeserializePersistentStateV2` | Restore V2 state |

---

## Activity Helper Methods

| Method | Purpose |
|--------|---------|
| `nativeGetBmr` | Basal metabolic rate |
| `nativeGetBaseActivityTarget` | Base activity target |
| `nativeCalculateCalories` | Calories from METs |
| `nativeCalculateWearPercentage` | Ring wear % |
| `getAvoidSitting` | Sitting alert score |
| `getDoExercise` | Exercise score |
| `getTargetCal` | Target calories |
| `getUserBmr` | User BMR |

---

## MET Processing

| Method | Purpose |
|--------|---------|
| `metSetUserInfo` | Set user age/gender |
| `metToClass` | MET value to class |
| `met320LowerLimitForLight` | Light activity threshold |
| `met320LowerLimitForModerate` | Moderate threshold |
| `met320LowerLimitForVigorous` | Vigorous threshold |
| `met320LowerLimitForSedentary` | Sedentary threshold |
| `nativeMetTimes32ToU8` | Convert MET format |
| `unpackMetLevel` | Unpack MET level |

---

## Sleep Phase Symbols

```java
nativeGetSleepPhaseAwakeSymbol()   // Returns char for awake (A)
nativeGetSleepPhaseDeepSymbol()    // Returns char for deep (D)
nativeGetSleepPhaseLightSymbol()   // Returns char for light (L)
nativeGetSleepPhaseREMSymbol()     // Returns char for REM (R)
```

---

## Feature Management

| Method | Purpose |
|--------|---------|
| `nativeEnableFeature(type)` | Enable feature |
| `nativeDisableFeature(type)` | Disable feature |
| `nativeIsEnabled(type)` | Check if enabled |
| `nativeSetFeature(type, value)` | Set feature value |
| `nativeCheckFeatureSession` | Check feature session |

### EcoreFeature Values

| Value | Name | Description |
|-------|------|-------------|
| 1 | HRV_IN_READINESS | HRV contributor |
| 3 | RECOVERY_TIME_FIX | Recovery time fix |
| 4 | REST_MODE | Rest/recovery mode |
| 5 | CYCLE_TRACKING | Menstrual cycle |
| 6 | MET_SCALING | MET scaling |
| 7 | MULTIPLE_SLEEP_PERIODS | Multiple periods |
| 11 | DAYTIME_HR | Daytime HR feature |
| 12 | EXERCISE_HR | Exercise HR feature |
| 13 | PERIOD_PREDICTION | Period prediction |
| 19 | SPO2 | SpO2 feature |
| 20 | SLEEP_REGULARITY | Sleep regularity |

**Source:** `ecorelibrary/feature/EcoreFeature.java`

---

## Cycle Tracking

| Method | Purpose |
|--------|---------|
| `nativeCalculateCycleDayType` | Cycle day classification |
| `nativeLatestCycleDayType` | Latest day type |
| `nativeGetPeriodPrediction` | Period prediction |

---

## Daily Outputs

| Method | Purpose |
|--------|---------|
| `nativeGetDailyOutputs` | Sleep + readiness scores |
| `nativeGetDailyOutputsStateless` | Stateless calculation |

---

## Utility Methods

| Method | Purpose |
|--------|---------|
| `nativeGetEcoreVersion` | Library version |
| `nativeGetLastRingTime` | Last ring timestamp |
| `nativeNotifyFactoryResetFinished` | Factory reset notification |
| `nativeParseJzLog` | Parse JZ log |
| `nativeRecalculateSleep` | Recalculate after edit |
| `nativeBedtimeEditLimits` | Bedtime edit constraints |
| `nativeSetPreviousSleepPeriods` | Set sleep history |
| `nativeSetUserInfo` | Set user demographics |
| `nativeStatelessCalculateDHR` | Daytime HR calculation |

---

## Source References

**Decompiled Classes:**
- `com.ouraring.ecorelibrary.EcoreWrapper`
- `com.ouraring.ecorelibrary.feature.EcoreFeature`
- `com.ouraring.ecorelibrary.baseline.Baseline`
- `com.ouraring.ecorelibrary.readiness.ReadinessScoreOutput`
- `com.ouraring.ecorelibrary.info.SleepInfo`
- `com.ouraring.ecorelibrary.info.ActInfo`

**Source Files:**
```
_large_files/decompiled/sources/com/ouraring/ecorelibrary/
├── EcoreWrapper.java
├── feature/EcoreFeature.java
├── baseline/Baseline.java
├── readiness/
│   ├── ReadinessScoreOutput.java
│   ├── ReadinessScoreSleepInput.java
│   └── ReadinessScoreHistoryInput.java
├── info/
│   ├── SleepInfo.java
│   ├── ActInfo.java
│   └── SpO2Drop.java
├── ibi/IbiAndAmplitudeEvent.java
└── activity/ActivityInput.java
```

---

## See Also

- [Data Structures](../structures/_index.md) - Input/output data classes
- [Events Reference](../events/_index.md) - Events processed by EcoreWrapper
