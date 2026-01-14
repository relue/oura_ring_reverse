# Processing Layer Data Flow

Event parsing, database storage, and score calculation.

---

## Layer 2: Event Parsing

### RingEventParserObj

JNI wrapper for native event parser.

**Source:** `ringeventparser/RingEventParserObj.java`

```java
// Loads libringeventparser.so
static { System.loadLibrary("ringeventparser"); }

// Parse raw bytes to protobuf
Ringeventparser.RingData parseEvents(List<byte[]> ringEvents, int ringTime, long utcTime) {
    byte[] concatEvents = RingEventParserObjKt.concatEvents(ringEvents);
    return nativeParseEvents(concatEvents, ringTime, utcTime, false);
}

// Native method declaration
private native Ringeventparser.RingData nativeParseEvents(
    byte[] ringEvents,
    int ringTime,
    long utcTime,
    boolean jzLogMode
);
```

### Ringeventparser.RingData (Protobuf)

Output from native parser containing typed events.

**Key Fields:**
- `ibiAndAmplitudeEvents` - Heart rate IBI data
- `tempEvents` - Temperature (7 sensors)
- `motionEvents` - Accelerometer
- `sleepPeriodInfoEvents` - Sleep periods
- `hrvEvents` - Heart rate variability
- `spo2Events` - Blood oxygen
- `activityInfoEvents` - Activity data

---

## Layer 3: Database Storage

### Realm Models

| Model | Purpose | Key Fields |
|-------|---------|------------|
| `DbSleep` | Sleep records | score, stages, hrv, temp |
| `DbReadiness` | Readiness records | score, contributors |
| `DbActivity` | Activity records | score, steps, calories |
| `DbRawEvent` | Raw event storage | bytes, timestamp, type |
| `DbBaseline` | Rolling baselines | hr, hrv, temp averages |

### NexusTransactionPlugin

Handles database upserts with processing hooks.

**Source:** `oura/nssa/k.java`

```java
// Example: NssaManager's sleep transaction plugin
class k implements NexusTransactionPlugin {
    // Called when sleep record is being inserted
    onWillStartUpsert(List<DbSleep> sleeps) {
        for (sleep in sleeps) {
            // Calculate readiness from new sleep data
            calculateReadiness(sleep)
        }
    }
}
```

---

## Layer 4: Score Calculation

### Two Pathways

**Path A: NSSA (Native Sleep Analysis)**
- Uses `libnexusengine.so` (16.5 MB)
- C++ implementation in `nexus::assa` namespace
- Alternative to SleepNet ML models

**Path B: EcoreWrapper (JNI)**
- Uses `libappecore.so` (2.1 MB)
- Traditional algorithm-based scoring

### NssaManager

Coordinates NSSA-based processing.

**Source:** `oura/nssa/NssaManager.java`

```java
// Sleep score calculation
handleSleepScores(DbSleep sleep) {
    // Uses NSSA engine
    nativeCalculateSleepScore(...)
}

// Readiness calculation
handleReadinessAndDailyScores(DbSleep sleep) {
    SleepHandler.calculateReadiness(sleep)
}

// Sleep staging
handleSleepPhases(DbSleep sleep) {
    // Either SleepNet ML or NSSA staging
}
```

### EcoreWrapper Native Methods

Key processing methods:

| Method | Input | Output |
|--------|-------|--------|
| `nativeIbiCorrection` | Raw IBI array | Corrected IBI + validity |
| `nativeCalculateSleepScore` | Sleep events | SleepInfo |
| `nativeCalculateReadinessScore` | Sleep + history | ReadinessScoreOutput |
| `nativeCalculateActivityScore` | Activity events | ActInfo |
| `nativeCalculateBaseline` | Historical data | Baseline |

---

## Complete Flow Example: Sleep Score

### 1. Ring Wakes Up, Sends Events

```
Ring → BLE Notification → RxAndroidBleOuraRing
```

### 2. App Requests Events

```kotlin
// Execute GetEvent operation
ring.execute(GetEvent(startTime, endTime))

// Ring responds with raw event bytes
RxAndroidBleOuraRing.notificationListener(bytes)
```

### 3. Parse Raw Events

```kotlin
// Parse bytes to typed events
val ringData = RingEventParserObj.parseEvents(eventBytes, ringTime, utcTime)

// Extract relevant events
val ibiEvents = ringData.ibiAndAmplitudeEvents
val tempEvents = ringData.tempEvents
val motionEvents = ringData.motionEvents
```

### 4. IBI Correction

```kotlin
// Correct raw IBI values
val correctedIbi = EcoreWrapper.nativeIbiCorrection(
    rawIbi = ibiEvents.map { it.ibi },
    amplitude = ibiEvents.map { it.amplitude },
    timestamp = ibiEvents.map { it.timestamp }
)
// Output: corrected IBI values with validity scores (0-3)
```

### 5. Sleep Staging (ML Path)

```kotlin
// Prepare SleepNet inputs
val input = SleepNetInput(
    timestamps = [bedtimeStart, bedtimeEnd],
    ibiData = correctedIbi,
    motion = motionEvents,
    temperature = tempEvents
)

// Run SleepNet model
val staging = sleepNetModel.execute(input)
// Output: sleep phases per 5-minute epoch (D/L/R/A)
```

### 6. Calculate Sleep Score

```kotlin
// Native score calculation
val sleepInfo = EcoreWrapper.nativeCalculateSleepScore(
    stagingResult = staging,
    ibiData = correctedIbi,
    tempData = tempEvents,
    baseline = currentBaseline
)
// Output: SleepInfo with score 0-100 + contributors
```

### 7. Store in Database

```kotlin
// Create Realm object
val dbSleep = DbSleep(
    id = generateId(),
    date = sleepDate,
    score = sleepInfo.sleepSummary2.score,
    totalSleep = sleepInfo.sleepSummary2.totalSleepTimeInSeconds,
    // ... more fields
)

// Trigger transaction plugins
realm.write { copyToRealm(dbSleep) }
// NssaManager.onWillStartUpsert() called
```

### 8. Calculate Readiness

```kotlin
// Triggered by transaction plugin
NssaManager.handleReadinessAndDailyScores(dbSleep)

// Uses sleep + historical data
val readiness = EcoreWrapper.nativeCalculateReadinessScore(
    sleepInput = sleepInput,
    historyInput = historyInput,
    baseline = baseline
)
```

---

## Error Handling

```
Parse Error
    ├── Returns RingData.getDefaultInstance()
    └── Logged to Timber

Calculation Error
    ├── EcoreException thrown
    └── Fallback to previous values

Database Error
    ├── RealmException thrown
    └── Transaction rolled back
```

---

## Source References

**Decompiled Classes:**
- `com.ouraring.ringeventparser.RingEventParserObj`
- `com.ouraring.ringeventparser.Ringeventparser`
- `com.ouraring.ecorelibrary.EcoreWrapper`
- `com.ouraring.oura.nssa.NssaManager`
- `com.ouraring.oura.nssa.SleepHandler`
- `com.ouraring.core.realm.model.DbSleep`
- `com.ouraring.core.realm.model.DbReadiness`
- `com.ouraring.core.realm.nexus.NexusTransactionPlugin`

**Source Files:**
```
_large_files/decompiled/sources/com/ouraring/
├── ringeventparser/
│   ├── RingEventParserObj.java
│   └── Ringeventparser.java
├── ecorelibrary/EcoreWrapper.java
├── oura/nssa/
│   ├── NssaManager.java
│   └── SleepHandler.java
└── core/realm/
    ├── model/DbSleep.java
    └── nexus/NexusTransactionPlugin.java
```

---

## See Also

- [Native Libraries](../native/_index.md) - JNI methods
- [EcoreWrapper](../native/ecore.md) - 68+ native methods
- [ML Models](../ml/_index.md) - SleepNet and other models
