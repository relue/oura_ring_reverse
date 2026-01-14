# BLE Protocol Reference

Complete documentation of the Oura Ring BLE communication protocol.

---

## BLE Connection Details

| Parameter | Value |
|-----------|-------|
| Service UUID | `98ed0001-a541-11e4-b6a0-0002a5d5c51b` |
| Write Characteristic | `98ed0002-a541-11e4-b6a0-0002a5d5c51b` |
| Notify Characteristic | `98ed0003-a541-11e4-b6a0-0002a5d5c51b` |
| CCCD Descriptor | `00002902-0000-1000-8000-00805f9b34fb` |

---

## Quick Navigation

| Topic | Doc | Description |
|-------|-----|-------------|
| Packet Structure | [protocol.md](protocol.md) | Command/response format, enums |
| Authentication | [auth.md](auth.md) | GetAuthNonce, Authenticate flow |
| Data Sync | [sync.md](sync.md) | GetEvent, RData protocol |
| Live Measurements | [realtime.md](realtime.md) | SetRealtimeMeasurements, heartbeat streaming |

---

## Command Reference Table

### Basic Commands

| Request | Response | Hex | Operation | Source |
|---------|----------|-----|-----------|--------|
| 3 | 3/21 | 0x03 | RData operations | `RDataStart.java`, `RDataGetPage.java` |
| 6 | 7 | 0x06/0x07 | SetRealtimeMeasurements | `SetRealtimeMeasurements.java` |
| 8 | 9 | 0x08/0x09 | GetFirmwareVersion | `GetFirmwareVersion.java` |
| 12 | 13 | 0x0C/0x0D | GetBatteryLevel | `GetBatteryLevel.java` |
| 16 | 17 | 0x10/0x11 | GetEvent | `GetEvent.java` |
| 18 | 19 | 0x12/0x13 | SyncTime | `SyncTime.java` |
| 43 | 43 | 0x2B | DFU operations | `DFUStart.java` |
| 47 | 47 | 0x2F | Extended operations | Multiple files |

### Extended Commands (Tag 47/0x2F)

| Extended Req | Extended Resp | Hex | Operation |
|--------------|---------------|-----|-----------|
| 1 | 2 | 0x01/0x02 | GetCapabilities |
| 32 | 33 | 0x20/0x21 | GetFeatureStatus |
| 34 | 35 | 0x22/0x23 | SetFeatureMode |
| 38 | 39 | 0x26/0x27 | SetFeatureSubscription |
| 40 | - | 0x28 | FeatureSubscriptionEvent (notification) |
| 43 | 44 | 0x2B/0x2C | GetAuthNonce |
| 45 | 46 | 0x2D/0x2E | Authenticate |
| - | 47 | 0x2F | Auth Failure |

---

## Packet Structure

### Request Format

```
[REQUEST_TAG] [LENGTH] [PAYLOAD...]
```

### Response Format

```
[RESPONSE_TAG] [LENGTH] [EXTENDED_TAG (if any)] [PAYLOAD...]
```

### Extended Tag System

For complex operations, extended tags are placed at `response[2]`:
- Used for multiplexing multiple operations on the same base tag
- Example: Auth operations use base tag 47 (0x2F) with different extended tags

### Byte Order

All multi-byte integers use **Little Endian** format.

---

## Response Codes

| Code | Name | Description |
|------|------|-------------|
| 0 | RESPONSE_LAST_REQUEST | Operation complete |
| 1 | RESPONSE_MORE_REQUEST | More data available (pagination) |
| 2 | RESPONSE_NOT_RECOGNIZED | Invalid/unrecognized command |
| 3 | RESPONSE_PARTIAL_RESPONSE | Partial data received |
| 4 | RESPONSE_INVALID_BUNDLE | Bundle error |

**Source:** `RingOperation.java:22-26`

---

## Typical Connection Flow

```
1. BLE Connect
2. Enable Notifications on Notify Characteristic
3. SyncTime to establish timestamp baseline
4. GetCapabilities to query ring features
5. Authentication (GetAuthNonce → Authenticate)
6. GetEvent or RealTime measurements
7. Process events via RingEventParser
```

---

## Source References

**Operation Classes:**
```
_large_files/decompiled/sources/com/ouraring/ourakit/operations/
├── RingOperation.java          # Base class
├── GetAuthNonce.java           # Auth challenge
├── Authenticate.java           # Auth response
├── GetEvent.java               # Event fetching
├── SetRealtimeMeasurements.java
├── SyncTime.java
├── GetBatteryLevel.java
├── GetFirmwareVersion.java
├── GetCapabilities.java
├── SetFeatureMode.java
├── SetFeatureSubscription.java
├── GetFeatureStatus.java
├── RDataStart.java
├── RDataGetPage.java
├── DFUStart.java
└── DFUPacket.java
```

**Domain Classes:**
```
_large_files/decompiled/sources/com/ouraring/ourakit/domain/
├── FeatureCapabilityId.java
├── FeatureMode.java
├── FeatureState.java
├── FeatureStatusValue.java
├── SubscriptionMode.java
├── AuthResponse.java
└── FeatureSubscriptionEvent.java
```

**BLE Layer:**
```
_large_files/decompiled/sources/com/ouraring/ourakit/
├── rxandroidble/RxAndroidBleOuraRing.java
└── internal/Constants.java
```

---

## See Also

- [Events Reference](../events/_index.md) - Event types received via GetEvent
- [Native Libraries](../native/_index.md) - Event parsing native code
