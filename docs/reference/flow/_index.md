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

## Documentation

| Layer | Document | Description |
|-------|----------|-------------|
| BLE | [ble-layer.md](ble-layer.md) | BLE communication, notification routing |
| Processing | [processing.md](processing.md) | Event parsing, database, score calculation |
| Timestamps | [timestamps.md](timestamps.md) | Ring time sync, UTC conversion, pitfalls |
| UI | [ui.md](ui.md) | Repository, ViewModel, Compose patterns |

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

## Source References

**Decompiled Classes:**
- `com.ouraring.ourakit.rxandroidble.RxAndroidBleOuraRing`
- `com.ouraring.ringeventparser.RingEventParserObj`
- `com.ouraring.ecorelibrary.EcoreWrapper`
- `com.ouraring.oura.nssa.NssaManager`
- `com.ouraring.core.realm.model.DbSleep`

**Source Files:**
```
_large_files/decompiled/sources/com/ouraring/
├── ourakit/rxandroidble/RxAndroidBleOuraRing.java
├── ringeventparser/RingEventParserObj.java
├── ecorelibrary/EcoreWrapper.java
├── oura/nssa/NssaManager.java
└── core/realm/model/DbSleep.java
```

---

## See Also

- [Events](../events/_index.md) - Event type definitions
- [BLE Commands](../ble/_index.md) - BLE protocol
- [Native Libraries](../native/_index.md) - JNI methods
