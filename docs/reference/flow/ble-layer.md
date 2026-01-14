# BLE Layer Data Flow

BLE communication, notification routing, and operation execution.

---

## RxAndroidBleOuraRing

Main BLE connection handler using RxAndroidBle library.

**Source:** `ourakit/rxandroidble/RxAndroidBleOuraRing.java`

---

## Key Components

| Field | Type | Purpose |
|-------|------|---------|
| `connection` | `t` (RxBleConnection) | Active BLE connection |
| `subscriptionNotificationRelay` | `kk.b` (ReplayRelay) | Buffers incoming notifications |
| `notificationListener` | `Function1<RingNotificationEvent, Unit>` | Callback for events |
| `operationRelay` | `c` (PublishRelay) | Queue for outgoing operations |

---

## Notification Flow

### 1. Setup Notification Observation

```java
// 1. Setup notification observation
observeNotificationEvents() {
    connection.setupNotification(READ_CHARACTERISTIC_UUID)
        .subscribe { bytes ->
            subscriptionNotificationRelay.accept(bytes)
        }
}
```

### 2. Poll and Route Notifications

```java
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

---

## Operation Execution

### Queue-Based Processing

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

## Error Handling

```
BLE Error
    ├── RingException thrown
    ├── cancelPendingOperation() called
    ├── Operation.onError() invoked
    └── Retry logic in connect()
```

---

## Source References

**Decompiled Classes:**
- `com.ouraring.ourakit.rxandroidble.RxAndroidBleOuraRing`
- `com.ouraring.ourakit.operations.RingOperation`
- `com.ouraring.ourakit.operations.GetEvent`
- `com.ouraring.ourakit.internal.Constants`

**Source Files:**
```
_large_files/decompiled/sources/com/ouraring/ourakit/
├── rxandroidble/RxAndroidBleOuraRing.java
├── operations/
│   ├── RingOperation.java
│   └── GetEvent.java
└── internal/Constants.java
```

---

## See Also

- [BLE Protocol](../ble/protocol.md) - Packet structure
- [BLE Sync](../ble/sync.md) - GetEvent command details
- [BLE Realtime](../ble/realtime.md) - Live measurement protocol
