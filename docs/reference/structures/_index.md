# Data Structures Reference

All key data classes from the Oura Ring app.

---

## Quick Navigation

| Topic | Doc | Description |
|-------|-----|-------------|
| Sleep | [sleep.md](sleep.md) | SleepInfo, SleepSummary structures |
| Readiness | [readiness.md](readiness.md) | ReadinessScoreOutput, inputs |
| Activity | [activity.md](activity.md) | ActInfo, ActivityInput |
| Vitals | [vitals.md](vitals.md) | HR/HRV, SpO2, Temperature |

---

## Data Scaling Conventions

| Pattern | Scaling | Example |
|---------|---------|---------|
| `*TimesEight` | ÷ 8 | `breathAverageTimesEight / 8` = BPM |
| `*Times32` | ÷ 32 | `metTimes32 / 32` = MET value |
| `*Centidegrees` | ÷ 100 | `3700` = 37.00°C |
| `*Seconds` | seconds | Direct value |
| `*Millis` | milliseconds | Unix timestamp |

---

## EcoreInfo Interface

Marker interface for all ecore output structures:

```java
interface EcoreInfo {
    // Marker interface - no methods
    // Implemented by: SleepInfo, ActInfo, SpO2Info, HrHrvOutputInfo, etc.
}
```

---

## Source References

**Package:**
```
_large_files/decompiled/sources/com/ouraring/ecorelibrary/
├── info/
│   ├── SleepInfo.java
│   ├── ActInfo.java
│   ├── SpO2Info.java
│   ├── SpO2Drop.java
│   └── HrHrvOutputInfo.java
├── baseline/Baseline.java
├── readiness/
│   ├── ReadinessScoreOutput.java
│   ├── ReadinessScoreSleepInput.java
│   └── ReadinessScoreHistoryInput.java
├── sleep/
│   ├── SleepDebtInput.java
│   ├── SleepDebtOutput.java
│   ├── BreathingRateInput.java
│   └── BreathingRateOutput.java
└── ibi/IbiAndAmplitudeEvent.java
```

---

## See Also

- [Native Libraries](../native/ecore.md) - JNI methods using these structures
- [Events Reference](../events/_index.md) - Raw events that produce these structures
