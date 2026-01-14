# Real-Time Measurements

Live heartbeat streaming and on-demand measurement protocols.

---

## Live Heartbeat Monitoring Flow

```
Phase 1: GetFeatureStatus (check sensor state)
Phase 2: SetFeatureMode (enable CONNECTED_LIVE)
Phase 3: SetFeatureSubscription (subscribe to LATEST)
Phase 4: Receive heartbeat stream (notifications)
Phase 5: SetFeatureMode (return to AUTOMATIC)
```

---

## GetFeatureStatus

Query current feature status.

### Tags

| Extended Tag | Value | Hex |
|--------------|-------|-----|
| Request | 32 | 0x20 |
| Response | 33 | 0x21 |

### Request Format

```
TX: 2f 02 20 02
    │  │  │  └─ FeatureCapabilityId.CAP_DAYTIME_HR (0x02)
    │  │  └──── Extended tag (0x20)
    │  └─────── Length: 2 bytes
    └────────── Request tag (0x2f)
```

### Response Format

```
RX: 2f 06 21 02 01 00 00 00
    │  │  │  │  │  │  │  └─ FeatureRequestResult (SUCCESS=0)
    │  │  │  │  │  │  └──── FeatureState (IDLE=0, MEASURING=2)
    │  │  │  │  │  └─────── FeatureStatusValue flags
    │  │  │  │  └────────── FeatureMode (AUTOMATIC=1)
    │  │  │  └───────────── FeatureCapabilityId
    │  │  └──────────────── Extended response tag
    │  └─────────────────── Length
    └────────────────────── Response tag
```

**Critical:** Byte 5 (status flags) and Byte 6 (state) indicate sensor readiness:
- `0x00 0x00` = Sensors OFF, IDLE - will NOT stream data
- `0x11 0x02` = Sensors ON, MEASURING - ready to stream

**Source:** `GetFeatureStatus.java`

---

## SetFeatureMode

Set feature operating mode.

### Tags

| Extended Tag | Value | Hex |
|--------------|-------|-----|
| Request | 34 | 0x22 |
| Response | 35 | 0x23 |

### Request Format (Enable Live)

```
TX: 2f 03 22 02 03
    │  │  │  │  └─ FeatureMode.CONNECTED_LIVE (0x03)
    │  │  │  └──── FeatureCapabilityId.CAP_DAYTIME_HR
    │  │  └─────── Extended tag (0x22)
    │  └────────── Length: 3 bytes
    └───────────── Request tag
```

### Request Format (Disable)

```
TX: 2f 03 22 02 01
              └─ FeatureMode.AUTOMATIC (0x01)
```

### Response Format

```
RX: 2f 03 23 02 00
              └─ FeatureRequestResult.SUCCESS (0x00)
```

**Source:** `SetFeatureMode.java`

---

## SetFeatureSubscription

Configure data subscription mode.

### Tags

| Extended Tag | Value | Hex |
|--------------|-------|-----|
| Request | 38 | 0x26 |
| Response | 39 | 0x27 |

### Request Format

```
TX: 2f 03 26 02 02
    │  │  │  │  └─ SubscriptionMode.LATEST (0x02)
    │  │  │  └──── FeatureCapabilityId.CAP_DAYTIME_HR
    │  │  └─────── Extended tag (0x26)
    │  └────────── Length
    └───────────── Request tag
```

### Response Format

```
RX: 2f 03 27 02 00
              └─ SUCCESS
```

**Source:** `SetFeatureSubscription.java`

---

## FeatureSubscriptionEvent

Heartbeat notification packets sent by ring.

### Extended Tag: 40 (0x28)

### Packet Format (API < 1.10.0, 15 bytes)

```
RX: 2f 0f 28 02 [flags] [state] [seq_lo] [seq_hi] [ibi_lo] [ibi_hi] [temp_lo] [temp_mid] [temp_hi] [cqi_lo] [cqi_hi]
    Byte:  0  1  2  3     4       5        6        7        8        9        10        11        12       13      14
```

### Packet Format (API >= 1.10.0, 17 bytes)

Additional PQI field at byte 16.

### Field Extraction

**IBI (Inter-Beat Interval) - bytes 8-9:**
```kotlin
val ibiLow = response[8].toInt() and 0xFF
val ibiHigh = response[9].toInt() and 0x0F  // Only lower 4 bits
val ibiMs = (ibiHigh shl 8) or ibiLow
```

**BPM Calculation:**
```kotlin
val bpm = 60000.0 / ibiMs
```

**Temperature - bytes 10-12:**
```kotlin
val temp = ((response[10] shl 8) or (response[11] shl 16) or (response[12] shl 24)) shr 8
// 24-bit signed integer
```

**CQI (Cardio Quality Indicator) - bytes 13-14:**
```kotlin
val cqi = (response[13] and 0xFF) or ((response[14] and 0xFF) shl 8)
// 16-bit unsigned integer
```

**PQI (Perfusion Quality Indicator) - byte 16 (API >= 1.10.0):**
```kotlin
val pqi = response[16].toInt()
```

**Source:** `FeatureSubscriptionEvent.java`

---

## SetRealtimeMeasurements (Legacy)

Legacy API for real-time measurements.

### Tags

| Type | Tag | Hex |
|------|-----|-----|
| REQUEST_TAG | 6 | 0x06 |
| RESPONSE_TAG | 7 | 0x07 |

### Request Format (Enable, 9 bytes)

```
[6] [7] [bitmask: 4 bytes int32 LE] [maxDuration: 2 bytes short LE] [delay: 1 byte]
```

### Request Format (Disable, 6 bytes)

```
[6] [4] [0x00000000: 4 bytes]
```

### Measurement Type Bitmasks

| Type | Bitmask | Response Tag | Description |
|------|---------|--------------|-------------|
| ON_DEMAND | 512 (0x200) | 5 | On-demand HR |
| ACM | 32 (0x20) | 51 (0x33) | Raw accelerometer |
| TWO_HERTZ_MODE | 1024 (0x400) | - | 2Hz sampling mode |

### Response Format

```
[7] [length] [result: 1 byte]
```
- `result == 0`: Success
- `result != 0`: Failure

**Source:** `SetRealtimeMeasurements.java`, `RealTimeMeasurementType.java`

---

## Complete Monitoring Example

```kotlin
// Phase 1: Check status
sendCommand(byteArrayOf(0x2f, 0x02, 0x20, 0x02))
// Expected: 2f 06 21 02 01 11 02 00 (sensors ON, MEASURING)

// Phase 2: Enable live mode
sendCommand(byteArrayOf(0x2f, 0x03, 0x22, 0x02, 0x03))
// Expected: 2f 03 23 02 00 (SUCCESS)

// Phase 3: Subscribe
sendCommand(byteArrayOf(0x2f, 0x03, 0x26, 0x02, 0x02))
// Expected: 2f 03 27 02 00 (SUCCESS)

// Phase 4: Receive heartbeat notifications
// Ring sends: 2f 0f 28 02 ... at ~1 Hz

// Phase 5: Stop
sendCommand(byteArrayOf(0x2f, 0x03, 0x22, 0x02, 0x01))
```

---

## Troubleshooting

### Ring Reports IDLE/OFF State

**Problem:** Ring reports `FeatureState.IDLE` (0x00) with sensors `OFF` (0x00)

**Likely Causes:**
- Ring not detecting proper skin contact
- Ring needs 30-60 seconds on finger before sensors activate
- Some fingers work better than others (index/middle best)
- Low battery preventing sensor activation

**Solutions:**
1. Wear ring on index or middle finger (best blood flow)
2. Wait 30-60 seconds after putting on
3. Try official app first to activate sensors
4. Check battery level

### No Heartbeat Packets

Even with successful protocol exchange, packets require:
- Ring on finger with skin contact
- FeatureState = MEASURING (0x02)
- FeatureStatusValue bit 0 = ON

---

## Implementation Notes

1. **Packet frequency:** ~1 Hz when actively detecting pulse
2. **No packets if ring not on finger**
3. **Connection timeout:** 60 seconds of inactivity
4. **Command sequence must be in order:** Status → Mode → Subscribe

---

## Source References

**Decompiled Classes:**
- `com.ouraring.ourakit.operations.GetFeatureStatus`
- `com.ouraring.ourakit.operations.SetFeatureMode`
- `com.ouraring.ourakit.operations.SetFeatureSubscription`
- `com.ouraring.ourakit.domain.FeatureSubscriptionEvent`
- `com.ouraring.ourakit.operations.SetRealtimeMeasurements`

**Source Files:**
```
_large_files/decompiled/sources/com/ouraring/
├── ourakit/operations/
│   ├── GetFeatureStatus.java
│   ├── SetFeatureMode.java
│   ├── SetFeatureSubscription.java
│   └── SetRealtimeMeasurements.java
├── ourakit/domain/
│   ├── FeatureSubscriptionEvent.java
│   └── RealTimeMeasurementType.java
└── oura/pillars/data/daytimehr/
    └── LiveHeartRateMeasurer.java
```

---

## See Also

- [Protocol](protocol.md) - Enum definitions
- [Heart Events](../events/heart.md) - IBI event parsing
