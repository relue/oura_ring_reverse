# Data Flow Reference

Complete trace from BLE notifications to UI display.

---

## Flow Overview

```
┌─────────────────────────────────────────────────────────────────┐
│                         OURA RING                               │
│                    (BLE Notifications)                          │
└─────────────────────┬───────────────────────────────────────────┘
                      │ Raw bytes via BLE characteristic
                      ▼
┌─────────────────────────────────────────────────────────────────┐
│              RxAndroidBleOuraRing                               │
│  - Receives notifications on READ_CHARACTERISTIC_UUID           │
│  - Routes to subscriptionNotificationRelay                      │
│  - Dispatches to listeners                                      │
└─────────────────────┬───────────────────────────────────────────┘
                      │ byte[] events
                      ▼
┌─────────────────────────────────────────────────────────────────┐
│              RingEventParserObj (JNI)                           │
│  - nativeParseEvents(bytes, ringTime, utcTime)                  │
│  - Returns Ringeventparser.RingData (protobuf)                  │
└─────────────────────┬───────────────────────────────────────────┘
                      │ Typed events (IBI, Temp, Motion, etc.)
                      ▼
┌─────────────────────────────────────────────────────────────────┐
│                  Realm Database                                 │
│  - DbSleep, DbReadiness, DbActivity                             │
│  - DbRawEvent stores raw for reprocessing                       │
└─────────────────────┬───────────────────────────────────────────┘
                      │ Domain objects
                      ▼
┌─────────────────────────────────────────────────────────────────┐
│           NssaManager / EcoreWrapper (JNI)                      │
│  - Sleep staging (SleepNet or NSSA)                             │
│  - Score calculations (native algorithms)                       │
│  - Baseline updates                                             │
└─────────────────────┬───────────────────────────────────────────┘
                      │ Scores (0-100)
                      ▼
┌─────────────────────────────────────────────────────────────────┐
│                ViewModels (Compose State)                       │
│  - Today, Sleep, Readiness, Activity screens                    │
│  - Expose Flow<UiState> to UI                                   │
└─────────────────────┬───────────────────────────────────────────┘
                      │ UiState
                      ▼
┌─────────────────────────────────────────────────────────────────┐
│                  Compose UI                                     │
│  - Score cards, graphs, contributors                            │
└─────────────────────────────────────────────────────────────────┘
```

---

## Layer 1: BLE Communication

### RxAndroidBleOuraRing

Main BLE connection handler using RxAndroidBle library.

**Key Components:**

| Field | Type | Purpose |
|-------|------|---------|
| `connection` | `t` (RxBleConnection) | Active BLE connection |
| `subscriptionNotificationRelay` | `kk.b` (ReplayRelay) | Buffers incoming notifications |
| `notificationListener` | `Function1<RingNotificationEvent, Unit>` | Callback for events |
| `operationRelay` | `c` (PublishRelay) | Queue for outgoing operations |

**Notification Flow:**

```java
// 1. Setup notification observation
observeNotificationEvents() {
    connection.setupNotification(READ_CHARACTERISTIC_UUID)
        .subscribe { bytes ->
            subscriptionNotificationRelay.accept(bytes)
        }
}

// 2. Poll and route notifications
pollNotificationEvents() {
    subscriptionNotificationRelay.subscribe { event ->
        // Check event type
        if (isSubscriptionEvent(event)) -> featureSubscriptionListener
        if (isNotification(event)) -> notificationListener
        if (isRealTimeMeasurementEvent(event)) -> realTimeMeasurementListener
        if (isAuthFailureInd(event)) -> authenticationFailureListener
    }
}
```

**Operation Execution:**

```java
// Send command to ring
execute(operation) {
    operationRelay.accept(operation)  // Queue it
}

// Process queue
pollBleOperations() {
    operationRelay.flatMapSingle { operation ->
        handleOperation(operation.request, operation)
    }
}

// Write + read response
handleOperation(bytes, operation) {
    connection.write(WRITE_CHARACTERISTIC_UUID, bytes)
    readBuffer().flatMap { response ->
        operation.handleResponse(response)
    }
}
```

**Source:** `ourakit/rxandroidble/RxAndroidBleOuraRing.java`

---

## Layer 2: Event Parsing

### RingEventParserObj

JNI wrapper for native event parser.

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

**Source:** `ringeventparser/RingEventParserObj.java`

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

**Source:** `core/realm/model/`, `oura/nssa/k.java`

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

**Source:** `ecorelibrary/EcoreWrapper.java`, `oura/nssa/NssaManager.java`

---

## Layer 5: Repository Pattern

### Data Access Layer

```
Repository
    ├── query Realm database
    ├── transform to domain models
    └── expose as Flow<T>
```

**Example Pattern:**
```kotlin
class SleepRepository {
    fun getSleep(date: LocalDate): Flow<Sleep> {
        return realm.query<DbSleep>("date == $date")
            .asFlow()
            .map { it.toDomainModel() }
    }
}
```

---

## Layer 6: ViewModel Layer

ViewModels observe repositories and expose UI state.

**Pattern:**
```kotlin
class SleepViewModel : ViewModel() {
    val state: StateFlow<UiState> = sleepRepository
        .getSleepFlow()
        .map { sleep ->
            UiState(
                score = sleep.score,
                contributors = sleep.contributors,
                stages = sleep.stages
            )
        }
        .stateIn(viewModelScope)
}
```

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

### 9. UI Update

```kotlin
// Repository emits new data
sleepRepository.getSleep(date).collect { sleep ->
    // ViewModel updates state
    _state.value = SleepUiState(
        score = sleep.score,
        duration = formatDuration(sleep.totalSleep),
        contributors = sleep.contributors.map { it.toUi() }
    )
}

// Compose observes and recomposes
@Composable
fun SleepScreen(viewModel: SleepViewModel) {
    val state by viewModel.state.collectAsState()
    SleepScoreCard(score = state.score)
    ContributorsList(contributors = state.contributors)
}
```

---

## Key Classes by Layer

### BLE Layer
| Class | Location | Purpose |
|-------|----------|---------|
| RxAndroidBleOuraRing | `ourakit/rxandroidble/` | BLE connection |
| RingOperation | `ourakit/operations/` | Command base class |
| GetEvent | `ourakit/operations/` | Fetch events |
| Constants | `ourakit/internal/` | UUIDs, tags |

### Parser Layer
| Class | Location | Purpose |
|-------|----------|---------|
| RingEventParserObj | `ringeventparser/` | JNI wrapper |
| Ringeventparser | `ringeventparser/` | Protobuf classes |
| RingEventType | `ringeventparser/data/` | Event type enum |

### Processing Layer
| Class | Location | Purpose |
|-------|----------|---------|
| EcoreWrapper | `ecorelibrary/` | JNI algorithms |
| NssaManager | `oura/nssa/` | NSSA coordinator |
| SleepHandler | `oura/nssa/` | Sleep processing |

### Database Layer
| Class | Location | Purpose |
|-------|----------|---------|
| DbSleep | `core/realm/model/` | Sleep storage |
| DbReadiness | `core/realm/model/` | Readiness storage |
| NexusTransactionPlugin | `core/realm/nexus/` | Upsert hooks |

### ML Layer
| Class | Location | Purpose |
|-------|----------|---------|
| SleepNetPytorchModel | `oura/sleep/sleepnet/model/` | Sleep staging |
| PytorchModelFactory | `pytorch/` | Model loading |

---

## Threading Model

| Operation | Thread | Reason |
|-----------|--------|--------|
| BLE notifications | RxSchedulers.io() | I/O bound |
| Event parsing | Dispatchers.Default | CPU bound |
| Database writes | Realm thread | Thread safety |
| Score calculation | Dispatchers.Default | CPU bound |
| UI updates | Main | UI thread |

---

## Error Handling Flow

```
BLE Error
    ├── RingException thrown
    ├── cancelPendingOperation() called
    ├── Operation.onError() invoked
    └── Retry logic in connect()

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

## Realtime Measurement Flow

For live HR during workouts:

```
1. App enables realtime mode
   SetRealtimeMeasurements(bitmask = HR | MOTION)

2. Ring streams data
   RealTimeMeasurementIndicator events

3. App receives via listener
   realTimeMeasurementListener(indicator)

4. Immediate UI update
   No database storage (too frequent)
```

---

**See also:** [BLE_COMMANDS.md](BLE_COMMANDS.md), [EVENT_TYPES.md](EVENT_TYPES.md), [NATIVE_LIBRARIES.md](NATIVE_LIBRARIES.md)
