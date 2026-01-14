# Native Libraries & JNI Interface

Quick reference for Oura Ring's native libraries and JNI bindings.

---

## Library Overview

| Library | Size | Purpose |
|---------|------|---------|
| `libtorch_cpu.so` | 70 MB | PyTorch runtime for ML models |
| `libnexusengine.so` | 16.5 MB | NSSA sleep analysis system |
| `librealm-jni.so` | 8.5 MB | Realm database JNI |
| `libalgos.so` | 5.7 MB | Additional algorithms |
| `libringeventparser.so` | 3.3 MB | Protobuf event parsing |
| `libappecore.so` | 2.1 MB | Core score algorithms |
| `libc++_shared.so` | 1.3 MB | C++ runtime |
| `libecore.so` | 1.1 MB | Core native + cJSON |
| `libsecrets.so` | 8.7 KB | ML model encryption keys |

**Location:** `_large_files/native/lib/arm64-v8a/`

---

## libsecrets.so - Model Encryption Keys

Tiny library exposing two JNI functions for ML model decryption:

```
Java_com_ouraring_core_utils_Secrets_getapiKey
Java_com_ouraring_core_utils_Secrets_getfallbackKey
```

**Internal functions:**
- `customDecode(char*)` - Custom decoding
- `getOriginalKey(char*, int, _jstring*, _JNIEnv*)` - Key retrieval
- `sha256(const char*, char*)` - SHA-256 hashing

**Usage:** Keys decrypt `.pt.enc` model files (AES-GCM).

**Source:** `com/ouraring/core/utils/Secrets.java`

---

## libringeventparser.so - Event Parsing

Parses raw BLE bytes into structured protobuf events.

### JNI Entry Point
```
Java_com_ouraring_ringeventparser_RingEventParserObj_nativeParseEvents
```

### Native API
| Function | Description |
|----------|-------------|
| `rep_parseEvents` | Parse event buffer |
| `rep_create_session` | Create parser session |
| `rep_end_session` | End parser session |
| `rep_process_chunk` | Process data chunk |
| `rep_fix_spo2_timestamps` | Fix SpO2 timestamps |
| `rep_free_protobuf` | Free protobuf memory |
| `rep_get_state` / `rep_set_state` | State management |

**Source:** `com/ouraring/ringeventparser/RingEventParserObj.java`

---

## libnexusengine.so - NSSA Sleep Analysis

Alternative sleep analysis system (16.5 MB). Uses SQLite internally.

### Namespace: `nexus::assa`

**Sleep Data Classes:**
| Class | Purpose |
|-------|---------|
| `Sleep` | Main sleep record |
| `DailySleep` | Daily aggregation |
| `SleepFeature` | Sleep features |
| `RingSleepPeriodInfo` | Period metadata |
| `RingSleepSummary1/2/3` | Summary levels |
| `RingSleepTemp` | Sleep temperature |
| `RingSleepAcmPeriod` | ACM period data |
| `UserSleepSettings` | User preferences |
| `RingDebugDataSleepStatistics` | Debug stats |

**Storage:** Uses `TableStore` with select/upsert/delete operations.

**Note:** NSSA appears to be Oura's next-gen sleep analysis, possibly replacing/supplementing SleepNet ML models.

---

## libappecore.so - Core Algorithms

Main algorithm library for score calculations.

### Key Functions
| Symbol | Purpose |
|--------|---------|
| `calculate_sleep_score_numerical` | Sleep score calculation |
| `actinfo_get_activity_target` | Activity target |
| `actinfo_target_to_cal` | Target to calories |
| `actinfo_target_to_steps` | Target to steps |
| `actinfo_resolve_readiness_percent` | Readiness % |
| `activity_score_get_avoid_sitting` | Sitting avoidance |
| `bedtime_merge_periods` | Merge sleep periods |
| `bpm_from_ibi` | BPM from IBI |
| `bpm_init` | BPM initialization |

**Also includes:** cJSON library for JSON parsing.

---

## EcoreWrapper.java - JNI Interface

Main Java interface to native algorithms. 68+ native methods.

**Source:** `com/ouraring/ecorelibrary/EcoreWrapper.java`

### Initialization Methods

| Method | Parameters | Returns |
|--------|------------|---------|
| `nativeInitialize` | macAddress, persistentStateV1, activityTypes, isPersistentV2, debugEnabled | long (handle) |
| `nativeClose` | - | void |
| `nativeInitIbiCorrection` | - | void |
| `nativeInitRestorativeTime` | nightAvgTemp, nightAvgHr | boolean |
| `nativeInitSleepRegularity` | SleepRegularityInitInput[] | boolean |

### Score Calculation Methods

| Method | Key Inputs | Returns |
|--------|------------|---------|
| `nativeCalculateSleepScore` | sleepPhases, motionSeconds, bedtimePeriod, hrHrv5MinAverages | SleepInfo |
| `nativeCalculateReadinessScore` | ReadinessScoreSleepInput, PreviousDayInput, Baseline, HistoryInput | ReadinessScoreOutput |
| `nativeCalculateActivityScore` | ActivityInput | ActInfo |
| `nativeCalculateBaseline` | baseline + 16 params (scores, times, HR, temp, HRV) | Baseline |
| `nativeCalculateSleepDebt` | SleepDebtInput | SleepDebtOutput |
| `nativeCalculateBreathingRate` | BreathingRateInput | BreathingRateOutput |
| `nativeCalculateBdi` | totalSleepSec, validSpO2Sec, SpO2Drop[] | double |

### IBI Correction Pipeline

```java
// 1. Initialize correction
nativeInitIbiCorrection();

// 2. Feed raw IBI values (call for each beat)
nativeIbiCorrection(int ibi, int amplitude, long timestamp);

// 3. Get corrected values via callbacks
// → IbiAndAmplitudeEvent.Corrected (adds validity field)
```

### Event Processing Methods

| Method | Input | Returns |
|--------|-------|---------|
| `nativeProcessEvents` | byte[] ringEvents, count | boolean |
| `nativePostProcessEvents` | ringEvents, count, ringTime, utcTime | PostProcessEventsResult |
| `nativeProcessActivityEvent` | byte[] event | int |
| `nativeProcessRestModeEvent` | byte[] event | int |

### State Serialization

| Method | Purpose |
|--------|---------|
| `nativeSerializePersistentStateV1` | Get V1 state bytes |
| `nativeSerializePersistentStateV2` | Get V2 state size |
| `nativeDeserializePersistentStateV2` | Restore V2 state |

### Baseline Methods

| Method | Purpose |
|--------|---------|
| `nativeGetBaseline` | Get current baseline |
| `nativeSetBaseline` | Set baseline |
| `nativeCalculateTemperatureBaseline` | Update temp baseline |
| `nativeGetDefaultTemperatureBaseline` | Default temp baseline |

### Activity Helper Methods

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

### MET Processing

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

### Sleep Phase Symbols

```java
nativeGetSleepPhaseAwakeSymbol()   // Returns char for awake
nativeGetSleepPhaseDeepSymbol()    // Returns char for deep
nativeGetSleepPhaseLightSymbol()   // Returns char for light
nativeGetSleepPhaseREMSymbol()     // Returns char for REM
```

### Feature Management

| Method | Purpose |
|--------|---------|
| `nativeEnableFeature(type)` | Enable feature |
| `nativeDisableFeature(type)` | Disable feature |
| `nativeIsEnabled(type)` | Check if enabled |
| `nativeSetFeature(type, value)` | Set feature value |
| `nativeCheckFeatureSession` | Check feature session |

### Cycle Tracking

| Method | Purpose |
|--------|---------|
| `nativeCalculateCycleDayType` | Cycle day classification |
| `nativeLatestCycleDayType` | Latest day type |
| `nativeGetPeriodPrediction` | Period prediction |

### Daily Outputs

| Method | Purpose |
|--------|---------|
| `nativeGetDailyOutputs` | Sleep + readiness scores |
| `nativeGetDailyOutputsStateless` | Stateless calculation |

### Utility Methods

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

## Key Data Structures

### Baseline (20 fields)
Rolling averages and deviations for score calculations.

```java
Baseline {
    long dayMidnightUtcSeconds
    int dayTimeZone
    int sleepScoreAverage, sleepScoreDeviation
    int sleepTimeAverage, sleepTimeDeviation
    int restingHrAverage, restingHrDeviation
    int restingHrTimeAverage, restingHrTimeDeviation
    int activityDistanceAverage, activityDistanceDeviation
    int vigorousActivityAverage, vigorousActivityDeviation
    int sedentaryActivityAverage, sedentaryActivityDeviation
    int temperatureAverage, temperatureDeviation
    int hrvAverage, hrvDeviation
}
```

**Source:** `ecorelibrary/baseline/Baseline.java`

### IbiAndAmplitudeEvent

```java
// Raw from ring
IbiAndAmplitudeEvent.Raw {
    long timestamp
    int ibi        // Inter-beat interval (ms)
    int amplitude  // Signal amplitude
}

// After correction
IbiAndAmplitudeEvent.Corrected {
    long timestamp
    int ibi
    int amplitude
    int validity   // Quality indicator (0-3?)
}
```

**Source:** `ecorelibrary/ibi/IbiAndAmplitudeEvent.java`

### ReadinessScoreOutput (12 fields)

```java
ReadinessScoreOutput {
    int score                    // Overall 0-100
    int activityBalance          // Contributor
    int lastDayActivity          // Contributor
    int lastNightSleep           // Contributor
    int restingHr                // Contributor
    int restingHrTime            // Contributor
    int sleepBalance             // Contributor
    int temperature              // Contributor
    Integer hrvBalance           // Optional
    Integer sleepRegularity      // Optional
    Integer temperatureDeviation // Optional
    Integer temperatureTrendDeviation // Optional
}
```

**Source:** `ecorelibrary/readiness/ReadinessScoreOutput.java`

### ReadinessScoreSleepInput (13 fields)

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
    int rmssd                    // HRV (RMSSD)
}
```

### ReadinessScoreHistoryInput (6 arrays)

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

### ActInfo (35 fields) - Activity Output

```java
ActInfo implements EcoreInfo {
    long timestampUtc, dayStartUtc
    int timeZone, dayStartTimeZone
    int equivalentWalkingDistanceInMeters
    int nonWearTimeInMinutes
    int restingTimeInMinutes
    int sedentaryTimeInMinutes
    int lightActivityTimeInMinutes
    int moderateActivityTimeInMinutes
    int vigorousActivityTimeInMinutes
    int metTimes32
    int steps
    int activeCalories, totalCalories, targetCalories
    int metMinSedentary, metMinLightActivity
    int metMinModerateActivity, metMinVigorousActivity
    int inactivityAlertCount
    int targetDistanceInMeters
    int score                           // Activity score 0-100
    int sevenDayTargetScore
    int twentyFourHourInactiveTimeScore
    int twentyFourHourInactiveAlertScore
    int sevenDayExerciseFrequencyScore
    int sevenDayExerciseAmountScore
    int sevenDayRestScore
    int isDummyDay
    int metersToTarget
    int targetType, targetMultiplier, targetSteps
    boolean isUpdate
    // Plus mutable fields for per-minute data
}
```

**Source:** `ecorelibrary/info/ActInfo.java`

### SleepInfo (25+ fields)

```java
SleepInfo implements EcoreInfo {
    long timestampUtc
    int timeZone
    int sleepPeriodId
    long bedtimeStartUtc, bedtimeEndUtc
    int bedtimeStartTimeZone, bedtimeEndTimeZone
    int timeInBedInSeconds
    int alertInfo
    int isLongestSleepPeriod
    int averageHrv, averageNonRemHrv, averageRemHrv
    int lowestHr5min
    int lowestHr5minTimeInSecondsSinceBedtimeStart
    String nightlyMovements30sec   // Movement string
    String sleepPhasesPer5Minutes  // Phase symbols (D/L/R/A)
    String sleepPhasesPer30Seconds
    int[] hrPer5Minutes, hrPer10Minutes
    int[] hrvPer5Minutes
    SleepSummary2 sleepSummary2    // Nested summary
    SleepSummary3 sleepSummary3
    SleepSummary4 sleepSummary4
    RecoverySummary recoverySummary
}
```

### PreviousDayInput (7 fields)

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

### PostProcessEventsResult

```java
PostProcessEventsResult {
    int ringTime       // Ring internal time
    long utcTime       // UTC timestamp
    boolean timeMissing // True if both are 0
}
```

### BreathingRateInput (4 fields)

```java
BreathingRateInput {
    long bedtimeStartMillis      // Period start
    short[] ibiValues            // IBI values (ms)
    long[] ibiTimestampsMillis   // IBI timestamps
    byte[] motionSeconds         // Motion per second
}
```

### BreathingRateOutput (3 fields)

```java
BreathingRateOutput {
    float avgBreathingRate           // Breaths per minute
    float avgBreathingRateVariability // Variability
    float avgHeartRate               // Average HR
}
```

### RestModeInput (3 fields)

```java
RestModeInput {
    long restPeriodStartUtcTimeSeconds
    long restPeriodEndUtcTimeSeconds
    long currentMidnightUtcTimeSeconds
}
```

---

## Enums

### FeatureEventType (15 values)

| Value | Name | Description |
|-------|------|-------------|
| 0 | BACKGROUND_DFU | Background firmware update |
| 1 | RESEARCH_DATA | Research data collection |
| 2 | DAYTIME_HR | Daytime heart rate |
| 3 | EXERCISE_HR | Exercise heart rate |
| 4 | SPO2 | Blood oxygen |
| 5 | BUNDLING | Data bundling |
| 6 | ENCRYPTED_API | Encrypted API |
| 7 | TAP_TO_TAG | Tap to tag feature |
| 8 | RESTING_HR | Resting heart rate |
| 9 | APP_AUTH | App authentication |
| 10 | BLE_MODE | BLE mode |
| 11 | REAL_STEPS | Real step counting |
| 12 | EXPERIMENTAL | Experimental features |
| 13 | CVA_PPG_SAMPLER | CVA PPG sampler |
| 14 | FEATURE_UNKNOWN | Unknown feature |

**Source:** `ecorelibrary/FeatureEventType.java`

### EcoreFeature (15 values)

| Value | Name | Description |
|-------|------|-------------|
| 1 | HRV_IN_READINESS | HRV contributor |
| 3 | RECOVERY_TIME_FIX | Recovery time fix |
| 4 | REST_MODE | Rest/recovery mode |
| 5 | CYCLE_TRACKING | Menstrual cycle |
| 6 | MET_SCALING | MET scaling |
| 7 | MULTIPLE_SLEEP_PERIODS | Multiple periods |
| 9 | PREVIOUS_NIGHT_CONTRIBUTOR_MIN | Previous night min |
| 11 | DAYTIME_HR | Daytime HR feature |
| 12 | EXERCISE_HR | Exercise HR feature |
| 13 | PERIOD_PREDICTION | Period prediction |
| 16 | HR_LOWEST_UPDATE | HR lowest update |
| 19 | SPO2 | SpO2 feature |
| 20 | SLEEP_REGULARITY | Sleep regularity |
| 23 | CONTRIBUTOR_FIXING_FOR_ATHLETES | Athlete adjustment |
| 24 | GENERAL_HR_OUTPUT | General HR output |

**Source:** `ecorelibrary/feature/EcoreFeature.java`

---

## Processing Flow

```
Ring Events (BLE)
       │
       ▼
libringeventparser.so
  ├─ nativeParseEvents()
  └─ rep_process_chunk()
       │
       ▼
EcoreWrapper (Java)
  ├─ nativeProcessEvents()
  ├─ nativeIbiCorrection()  ──→ Raw IBI → Corrected IBI
  └─ nativePostProcessEvents()
       │
       ▼
Score Calculations
  ├─ nativeCalculateSleepScore()
  ├─ nativeCalculateReadinessScore()
  ├─ nativeCalculateActivityScore()
  └─ nativeCalculateBaseline()
       │
       ▼
libappecore.so
  └─ calculate_sleep_score_numerical()
       │
       ▼
Output Structures
  ├─ SleepInfo
  ├─ ReadinessScoreOutput
  ├─ ActInfo
  └─ Baseline
```

---

## Open Questions

- **NSSA vs SleepNet:** How do libnexusengine.so (NSSA) and PyTorch SleepNet models interact?
- **IBI Correction Algorithm:** What does the correction pipeline do internally?
- **Feature Flags:** Complete mapping of EcoreFeature values to behaviors
- **Baseline Rolling Window:** How long is the window for each baseline type?
- **MET Scaling:** Exact thresholds for activity classification

---

## File References

| Component | Location |
|-----------|----------|
| Native libs | `_large_files/native/lib/arm64-v8a/` |
| EcoreWrapper | `com/ouraring/ecorelibrary/EcoreWrapper.java` |
| IBI types | `com/ouraring/ecorelibrary/ibi/IbiAndAmplitudeEvent.java` |
| Baseline | `com/ouraring/ecorelibrary/baseline/Baseline.java` |
| Readiness | `com/ouraring/ecorelibrary/readiness/*.java` |
| Activity | `com/ouraring/ecorelibrary/activity/*.java` |
| Info types | `com/ouraring/ecorelibrary/info/*.java` |
| Features | `com/ouraring/ecorelibrary/feature/*.java` |

---

**See also:** [EVENT_TYPES.md](EVENT_TYPES.md), [BLE_COMMANDS.md](BLE_COMMANDS.md)
