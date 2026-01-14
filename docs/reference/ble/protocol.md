# BLE Protocol Structure

Packet formats, enumerations, and wire protocol details.

---

## Packet Structure

### General Request Format

```
Byte 0:  [REQUEST_TAG]     (command type)
Byte 1:  [LENGTH]          (number of bytes that follow)
Byte 2+: [PAYLOAD...]      (command-specific data)
```

### General Response Format

```
Byte 0:  [RESPONSE_TAG]    (response type)
Byte 1:  [LENGTH]          (number of bytes that follow)
Byte 2+: [DATA...]         (response-specific data)
```

### Extended Tag Format (Tag 47/0x2F)

```
Request:
Byte 0:  0x2f              (REQUEST_TAG - always 47)
Byte 1:  [length]          (number of bytes that follow)
Byte 2:  [extended_tag]    (command type)
Byte 3+: [parameters...]   (command-specific data)

Response:
Byte 0:  0x2f              (RESPONSE_TAG - always 47)
Byte 1:  [length]          (number of bytes that follow)
Byte 2:  [extended_tag+1]  (response type = request tag + 1)
Byte 3+: [data...]         (response-specific data)
```

---

## Byte Order

All multi-byte integers use **Little Endian** format.

```java
// Example timestamp conversion
ByteBuffer.wrap(bytes).order(ByteOrder.LITTLE_ENDIAN).getInt();
```

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

## FeatureCapabilityId (18 values)

| ID | Hex | Name | Description |
|----|-----|------|-------------|
| 0 | 0x00 | CAP_BACKGROUND_DFU | Background firmware update |
| 1 | 0x01 | CAP_RESEARCH_DATA | Research data collection |
| 2 | 0x02 | CAP_DAYTIME_HR | Daytime heart rate |
| 3 | 0x03 | CAP_EXERCISE_HR | Exercise heart rate |
| 4 | 0x04 | CAP_SPO2 | Blood oxygen measurement |
| 5 | 0x05 | CAP_BUNDLING | Data bundling |
| 6 | 0x06 | CAP_ENCRYPTED_API | Encrypted API support |
| 7 | 0x07 | CAP_TAP_TO_TAG | Tap to tag feature |
| 8 | 0x08 | CAP_RESTING_HR | Resting heart rate |
| 9 | 0x09 | CAP_APP_AUTH | App authentication |
| 10 | 0x0A | CAP_BLE_MODE | BLE mode control |
| 11 | 0x0B | CAP_REAL_STEPS | Real steps feature |
| 12 | 0x0C | CAP_EXPERIMENTAL | Experimental features |
| 13 | 0x0D | CAP_CVA_PPG_SAMPLER | CVA PPG sampling |
| 14 | 0x0E | CAP_CHARGING_CONTROL | Charging control |
| 16 | 0x10 | CAP_AMBIENT_LIGHT | Ambient light sensor |
| 17 | 0x11 | CAP_SPECIAL_FEATURE | Special feature |
| 18 | 0x12 | CAP_RAW_DATA_SAMPLER | Raw data sampling |

**Source:** `FeatureCapabilityId.java`

---

## FeatureMode (4 values)

| Value | Name | Description |
|-------|------|-------------|
| 0 | OFF | Feature disabled |
| 1 | AUTOMATIC | Auto-enabled by ring |
| 2 | REQUESTED | Requested by app |
| 3 | CONNECTED_LIVE | Live streaming mode |

**Source:** `FeatureMode.java`

---

## FeatureState (4 values)

| Value | Name | Description |
|-------|------|-------------|
| 0 | IDLE | Sensors inactive |
| 1 | SCANNING | Looking for pulse signal |
| 2 | MEASURING | Actively measuring |
| 3 | POSTPROCESSING | Processing data |

**Source:** `FeatureState.java`

---

## FeatureStatusValue (Bitfield)

Byte representing sensor status flags:

| Bit | Flag | Hex | Meaning |
|-----|------|-----|---------|
| 0 | ON/OFF | 0x01 | Bit 0 = 1: Sensor ON |
| 1 | SEARCHING | 0x02 | Searching for signal |
| 2 | NO_RELIABLE_PPG_SIGNAL | 0x04 | Cannot detect pulse |
| 3 | COLD_FINGERS | 0x08 | Temperature too low |
| 4 | TOO_MUCH_MOVEMENTS | 0x10 | Movement interference |
| 5 | IDENTIFYING_SIGNAL | 0x20 | Identifying pulse |

**Decoding:**
```kotlin
val flags = response[5].toInt()
val isOn = (flags and 0x01) != 0
val searching = (flags and 0x02) != 0
val noSignal = (flags and 0x04) != 0
val coldFingers = (flags and 0x08) != 0
val tooMuchMovement = (flags and 0x10) != 0
```

**Examples:**
- `0x00` = Sensors OFF (will NOT stream data)
- `0x01` = Sensor ON, clean signal
- `0x11` = Sensor ON + too much movement
- `0x05` = Sensor ON + no reliable signal

**Source:** `FeatureStatusValue.java`

---

## SubscriptionMode (3 values)

| Value | Name | Description |
|-------|------|-------------|
| 0 | OFF | No subscription |
| 1 | STATE | State changes only |
| 2 | LATEST | Continuous stream |

**Source:** `SubscriptionMode.java`

---

## RDataRequestSubtag (6 values)

| Code | Name | Description |
|------|------|-------------|
| 0 | UNKNOWN | Unknown |
| 1 | GET_PAGE | Get data page |
| 2 | CONFIGURE | Configure data sync |
| 3 | STOP | Stop data sync |
| 4 | CLEAR | Clear data |
| 5 | STATE | Query state |

**Source:** `RDataRequestSubtag.java`

---

## RDataRequestDataType (32 values)

| Code | Name | Description |
|------|------|-------------|
| 0 | NONE | No data |
| 1 | PPG_250HZ | PPG at 250Hz |
| 2 | PPG_125HZ | PPG at 125Hz |
| 3 | ACM_8G_50HZ | Accelerometer 8G at 50Hz |
| 4 | ACM_2G_50HZ | Accelerometer 2G at 50Hz |
| 5 | GYRO_2000_50HZ | Gyroscope 2000 at 50Hz |
| 6 | TEMP_1M | Temperature every 1 minute |
| 7 | TEMP_10S | Temperature every 10 seconds |
| 8 | METADATA | Metadata |
| 9 | PPG_50HZ | PPG at 50Hz |
| 10 | TEMP_10HZ | Temperature at 10Hz |
| 11 | ACM_4G_50HZ | Accelerometer 4G at 50Hz |
| 12 | GYRO_500_50HZ | Gyroscope 500 at 50Hz |
| 13 | GYRO_125_50HZ | Gyroscope 125 at 50Hz |
| 19 | ACM_8G_10HZ | Accelerometer 8G at 10Hz |
| 20 | ACM_2G_10HZ | Accelerometer 2G at 10Hz |
| 21 | GYRO_2000_10HZ | Gyroscope 2000 at 10Hz |
| 27 | ACM_4G_10HZ | Accelerometer 4G at 10Hz |
| 28 | GYRO_500_10HZ | Gyroscope 500 at 10Hz |
| 29 | GYRO_125_10HZ | Gyroscope 125 at 10Hz |
| 35-61 | *_ANTIALIAS | Anti-aliased variants |

**Source:** `RDataRequestDataType.java`

---

## AuthResponse Values

| Value | Name | Description |
|-------|------|-------------|
| 0 | SUCCESS | Authentication successful |
| 1 | FAILURE_AUTHENTICATION_ERROR | Wrong key/encryption |
| 2 | FAILURE_IN_FACTORY_RESET | Ring is in factory reset |
| 3 | FAILURE_NOT_ORIGINAL_ONBOARDED_DEVICE | Wrong device |

**Source:** `AuthResponse.java`

---

## DFU Status Codes

| Value | Status | Description |
|-------|--------|-------------|
| 0 | DOWNLOADED_AND_VERIFIED | Complete |
| 1 | REQUESTING_BLOCK | Ready for next block |
| 2 | INCORRECT_STATE | Invalid state |
| 3 | OTHER_ERROR | General error |
| 4 | FEATURE_DISABLED | DFU disabled |
| 5 | INCORRECT_RING_TYPE | Wrong ring type |

**Source:** `DFUStart.java`

---

## Source References

**Enum Files:**
```
_large_files/decompiled/sources/com/ouraring/ourakit/domain/
├── FeatureCapabilityId.java
├── FeatureMode.java
├── FeatureState.java
├── FeatureStatusValue.java
├── SubscriptionMode.java
├── AuthResponse.java
└── RealTimeMeasurementType.java
```

**Protocol Files:**
```
_large_files/decompiled/sources/com/ouraring/ourakit/
├── operations/RingOperation.java
└── internal/Constants.java
```

---

## See Also

- [Authentication](auth.md) - Auth flow details
- [Data Sync](sync.md) - GetEvent protocol
- [Realtime](realtime.md) - Live measurements
