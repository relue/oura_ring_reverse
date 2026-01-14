# System Events

Ring initialization, time sync, debug, BLE connection, and system state events.

---

## Event Summary

| Tag | Hex | Event Name | Priority | Description |
|-----|-----|------------|----------|-------------|
| 65 | 0x41 | API_RING_START_IND | High | Ring boot/restart |
| 66 | 0x42 | API_TIME_SYNC_IND | High | Time synchronization |
| 67 | 0x43 | API_ALERT | Medium | Alert events |
| 72 | 0x48 | API_STATE_CHANGE_IND | Medium | State changes |
| 73 | 0x49 | API_DEBUG_EVENT_IND | Low | Debug events |
| 74 | 0x4A | API_DEBUG_DATA | Low | Debug data |
| 77 | 0x4D | API_SELFTEST_EVENT | Low | Self-test results |
| 78 | 0x4E | API_SELFTEST_DATA | Low | Self-test data |
| 84 | 0x54 | API_USER_INFO | Low | User information |
| 85 | 0x55 | API_TAG_EVENT | Medium | User tags |
| 86 | 0x56 | API_BLE_CONNECTION_IND | Medium | BLE connection state |
| 106 | 0x6A | API_MEAS_QUALITY_EVENT | Medium | Measurement quality |
| 108 | 0x6C | API_FEATURE_SESSION_EVENT | Medium | Feature sessions |
| 128 | 0x80 | API_SCAN_START | Low | Scan session start |
| 129 | 0x81 | API_TIME_SYNC_IND_SKIPPED | Low | Time sync skipped |
| 131 | 0x83 | API_SCAN_END | Low | Scan session end |

---

## 0x41 - API_RING_START_IND

**Priority:** High - Ring boot/restart notification
**Frequency:** On boot/restart

### Protobuf Fields

| Field | Name | Type | Description |
|-------|------|------|-------------|
| 1 | firmwareVersion | string | Firmware version string |
| 2 | bootloaderVersion | string | Bootloader version |
| 3 | resetReason | uint32 | Reason for restart |
| 4 | uptimeSeconds | uint32 | Previous uptime |
| 5 | batteryLevel | uint32 | Battery level (%) |
| 6 | hardwareRevision | string | Hardware revision |
| 7 | serialNumber | bytes | Device serial number |
| 8-15 | (various) | - | System diagnostic data |

### Live Capture Data

- **Initial capture:** 1 event (boot timestamp)
- **Overnight capture:** 2 events

---

## 0x42 - API_TIME_SYNC_IND

**Priority:** High - Time synchronization
**Frequency:** On sync request/response

### Protobuf Fields

| Field | Name | Type | Description |
|-------|------|------|-------------|
| 1 | timestamp | long | Ring timestamp at sync |
| 2 | syncSource | int | Sync source identifier |

---

## 0x81 - API_TIME_SYNC_IND_SKIPPED

**Priority:** Low

Indicates time sync was skipped (e.g., already synced recently).

---

## 0x48 - API_STATE_CHANGE_IND

**Source:** `com.ouraring.ringeventparser.message.StateChangeIndValue`
**Priority:** Medium - Ring state transitions
**Frequency:** On state change

### Protobuf Fields

| Field | Name | Type | Description |
|-------|------|------|-------------|
| 1 | timestamp | long | Unix timestamp (ms) |
| 2 | state | StateChange | Ring state enum |
| 3 | text | String | State description |

### State Values (from StateChange.java)

| State | Description |
|-------|-------------|
| IDLE | Ring idle/standby |
| MEASURING | Active measurement |
| SLEEPING | Sleep mode detected |
| CHARGING | On charger |
| DFU_MODE | Device firmware update |

### Live Capture Data

- **Initial capture:** 14 events verified
- **Sample texts:** "chg. stopped", "hr enable"
- **Overnight capture:** 84 events (state transitions)

---

## 0x43 - API_ALERT

**Priority:** Medium - Ring alerts/notifications

### Protobuf Fields

| Field | Name | Type | Description |
|-------|------|------|-------------|
| 1 | timestamp | long | Alert timestamp |
| 2 | alertType | int | Alert type enum |
| 3 | alertData | bytes | Alert payload |

---

## 0x56 - API_BLE_CONNECTION_IND

**Priority:** Medium - BLE connection state

### Live Capture Data

- **Initial capture:** 8 events (connection params)
- **Overnight capture:** 13 events

---

## 0x6C - API_FEATURE_SESSION_EVENT

**Source:** `com.ouraring.ringeventparser.FeatureSession`
**File:** `FeatureSession.java:7-24`
**Priority:** Medium - Feature session management

### Protobuf Fields

| Field | Name | Type | Description |
|-------|------|------|-------------|
| 1 | timestamp | long | Session timestamp |
| 2 | capability | int | Feature capability ID |
| 3 | status | int | Session status |

### Session Type Fields

**CVA (Cardiovascular Age) Session:**
- `cvaPpgSamplerSessionV1Version`
- `cvaPpgSamplerSessionV1SampleRateHz`
- `cvaPpgSamplerSessionV1MeasAveraging`

**Daytime HR Session:**
- `daytimeHrSessionAlgorithmVersion`
- `daytimeHrSessionV4Meditation`

**Exercise HR Session:**
- `exerciseHrSessionV1Activity`
- `exerciseHrSessionV1MaxHr`
- `exerciseHrSessionV1MinHr`
- `exerciseHrSessionV2AlgorithmVersion`

**Real Steps Session:**
- `realStepsSessionV1Version`

**SpO2 Session:**
- `spo2SessionVersion`
- `spo2SessionV3HighFrequencyMode`

**Resting HR Session:**
- `restingHrSessionAlgorithmVersion`
- `restingHrV2HighFrequencyMode`

### Live Capture Data

- **Initial capture:** 9 events (session type/state)
- **Overnight capture:** 11 events

---

## 0x6A - API_MEAS_QUALITY_EVENT

**Priority:** Medium - Measurement quality indicators

### Quality Metrics

| Metric | Description |
|--------|-------------|
| CQI | Contact Quality Index |
| PQI | PPG Quality Index |

### Live Capture Data

- **Initial capture:** 23 events
- **Overnight capture:** 38 events

---

## Scan Events

### 0x80 - API_SCAN_START

PPG scan session start.

### Live Capture Data

- **Initial capture:** 1 event (scan config)
- **Overnight capture:** 13 events

### 0x83 - API_SCAN_END

PPG scan session end with results.

### Live Capture Data

- **Initial capture:** 1 event (scan results)
- **Overnight capture:** 25 events (PPG scan results)

---

## Debug Events

### 0x49 - API_DEBUG_EVENT_IND

Debug event indication for development/diagnostics.

### 0x4A - API_DEBUG_DATA

Raw debug data payload.

---

## Self-Test Events

### 0x4D - API_SELFTEST_EVENT

Self-test results for hardware validation.

### 0x4E - API_SELFTEST_DATA

Detailed self-test data.

---

## User Events

### 0x54 - API_USER_INFO

User information/configuration.

### Live Capture Data

1 event in overnight capture (user config).

### 0x55 - API_TAG_EVENT

User-created tags (e.g., "took medication", "felt stressed").

---

## Implementation Notes

1. **Ring factory reset clears stored events**
2. **Events consumed when read** (single-read buffer)
3. **Timestamps are deciseconds** (divide by 10 for seconds)
4. **Export immediately after data fetch** - events cleared on re-fetch

---

## Source References

**Decompiled Classes:**
- `com.ouraring.ringeventparser.message.StateChangeIndValue`
- `com.ouraring.ringeventparser.FeatureSession`
- `com.ouraring.ringeventparser.data.StateChange`

**Source Files:**
```
_large_files/decompiled/sources/com/ouraring/
├── ringeventparser/
│   ├── FeatureSessionEventKt.java
│   └── message/
│       ├── StateChangeIndValue.java
│       └── FeatureSession.java
│   └── data/
│       └── StateChange.java
└── ourakit/
    └── internal/Constants.java
```

**Related:**
- `ourakit/internal/Constants.java` - BLE UUIDs and tags
- `RingEventType.java` - Event type enum definition

---

## See Also

- [BLE Protocol](../ble/_index.md) - BLE communication details
- [Feature Sessions](../ble/realtime.md) - Live measurement sessions
