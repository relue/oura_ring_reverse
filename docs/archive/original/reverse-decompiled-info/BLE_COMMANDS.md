# Oura Ring BLE Protocol Reference

Comprehensive documentation of all BLE operations from decompiled source.

---

## Protocol Overview

### Packet Structure

All BLE commands follow this basic structure:
```
[REQUEST_TAG] [LENGTH] [PAYLOAD...]
```

Response structure:
```
[RESPONSE_TAG] [LENGTH] [EXTENDED_TAG (if any)] [PAYLOAD...]
```

### Extended Tag System

For complex operations, the protocol uses extended tags within the payload:
- Extended tags are placed at `response[2]` position
- Used for multiplexing multiple operations on the same base tag
- Example: Auth operations all use base tag 47 (0x2F) with different extended tags

### Response Codes

| Code | Name | Description |
|------|------|-------------|
| 0 | RESPONSE_LAST_REQUEST | Operation complete |
| 1 | RESPONSE_MORE_REQUEST | More data available (pagination) |
| 2 | RESPONSE_NOT_RECOGNIZED | Invalid/unrecognized command |
| 3 | RESPONSE_PARTIAL_RESPONSE | Partial data received |
| 4 | RESPONSE_INVALID_BUNDLE | Bundle error |

**Source:** `RingOperation.java:22-26`

---

## Command Reference

### Authentication Commands

#### GetAuthNonce (Request Authentication Challenge)

**Tags:**
| Type | Tag | Hex |
|------|-----|-----|
| REQUEST_TAG | 47 | 0x2F |
| EXTENDED_REQUEST_TAG | 43 | 0x2B |
| RESPONSE_TAG | 47 | 0x2F |
| EXTENDED_RESPONSE_TAG | 44 | 0x2C |

**Request Format:**
```
[47] [1] [43]  (3 bytes)
```

**Response Format:**
```
[47] [length] [44] [nonce: 15 bytes]
```
- Minimum response length: 18 bytes
- Nonce is at bytes 3-17

**Source:** `GetAuthNonce.java`

---

#### Authenticate (Submit Encrypted Nonce)

**Tags:**
| Type | Tag | Hex |
|------|-----|-----|
| REQUEST_TAG | 47 | 0x2F |
| EXTENDED_REQUEST_TAG | 45 | 0x2D |
| RESPONSE_TAG | 47 | 0x2F |
| EXTENDED_RESPONSE_TAG | 46 | 0x2E |

**Request Format:**
```
[47] [17] [45] [encryptedNonce: 16 bytes]
```

**Response Format:**
```
[47] [length] [46] [authResult: 1 byte]
```

**AuthResponse Values:**
| Value | Name | Description |
|-------|------|-------------|
| 0 | SUCCESS | Authentication successful |
| 1 | FAILURE_AUTHENTICATION_ERROR | Wrong key/encryption |
| 2 | FAILURE_IN_FACTORY_RESET | Ring is in factory reset |
| 3 | FAILURE_NOT_ORIGINAL_ONBOARDED_DEVICE | Wrong device |

**Auth Failure Indicator:**
If `response[0] == 47 && response[2] == 47`, the operation failed with auth error.
The failure reason is at `response[3]`.

**Source:** `Authenticate.java`, `AuthResponse.java`

---

### Event Operations

#### GetEvent (Fetch Historical Events)

**Tags:**
| Type | Tag | Hex |
|------|-----|-----|
| REQUEST_TAG | 16 | 0x10 |
| RESPONSE_TAG | 17 | 0x11 |

**Request Format:**
```
[16] [9] [timestamp: 4 bytes uint32 LE] [maxEvents: 1 byte] [flags: 4 bytes int32 LE]
```
- Total: 11 bytes
- `timestamp`: Event start timestamp (ring milliseconds)
- `maxEvents`: Max 255 events per request
- `flags`: Event filter flags

**Response Format:**

If `response[0] >= 65 (0x41)`:
- This is an actual event (tags 0x41-0x83)
- Pass to event parser

If `response[0] == 17`:
- This is a summary response
```
[17] [length] [eventCount] [???] [nextTimestamp: 4 bytes uint32 LE]
```
- `eventCount`: Number of events fetched
- `nextTimestamp`: Continue from this timestamp for next request

**Timeout:** 120 seconds (extended for large transfers)

**Source:** `GetEvent.java`

---

### Real-Time Measurements

#### SetRealtimeMeasurements (Enable/Disable Live Data)

**Tags:**
| Type | Tag | Hex |
|------|-----|-----|
| REQUEST_TAG | 6 | 0x06 |
| RESPONSE_TAG | 7 | 0x07 |

**Request Format (Enable):**
```
[6] [7] [bitmask: 4 bytes int32 LE] [maxDuration: 2 bytes short LE] [delay: 1 byte]
```
- Total: 9 bytes

**Request Format (Disable):**
```
[6] [4] [0x00000000: 4 bytes]
```
- Total: 6 bytes

**Measurement Type Bitmasks:**
| Type | Bitmask | Response Tag | Description |
|------|---------|--------------|-------------|
| ON_DEMAND | 512 (0x200) | 5 | On-demand HR measurement |
| ACM | 32 (0x20) | 51 (0x33) | Raw accelerometer data |
| TWO_HERTZ_MODE | 1024 (0x400) | - | 2Hz sampling mode |

**Response Format:**
```
[7] [length] [result: 1 byte]
```
- `result == 0`: Success
- `result != 0`: Failure

**Source:** `SetRealtimeMeasurements.java`, `RealTimeMeasurementType.java`

---

### Time Synchronization

#### SyncTime (Synchronize Ring Clock)

**Tags:**
| Type | Tag | Hex |
|------|-----|-----|
| REQUEST_TAG | 18 | 0x12 |
| RESPONSE_TAG | 19 | 0x13 |

**Request Format:**
```
[18] [length] [currentTimeSeconds: 8 bytes int64 LE] [timezoneOffset: 1 byte] [forceSync: 1 byte (optional)]
```
- `currentTimeSeconds`: Unix timestamp in seconds
- `timezoneOffset`: Timezone offset in 30-minute increments
- `forceSync`: Optional byte to force resync

**Response Format:**
```
[19] [length] [response data...]
```

**Timezone Calculation:**
```java
byte timezoneOffset = (byte)(timezoneOffsetMillis / 1800000);  // 30 min = 1800000 ms
```

**Source:** `SyncTime.java`

---

### Battery Status

#### GetBatteryLevel

**Tags:**
| Type | Tag | Hex |
|------|-----|-----|
| REQUEST_TAG | 12 | 0x0C |
| RESPONSE_TAG | 13 | 0x0D |

**Request Format:**
```
[12] [0]  (2 bytes)
```

**Response Format:**
```
[13] [length] [level: 1 byte] [state: 1 byte] [voltage?: 1 byte]
```
- `level`: Battery percentage (0-100)
- `state`: Charging state
- Third byte: Additional battery info

**Source:** `GetBatteryLevel.java`

---

### Ring Data Synchronization (RData Protocol)

#### RDataStart (Initialize Data Sync)

**Tags:**
| Type | Tag | Hex |
|------|-----|-----|
| REQUEST_TAG | 3 | 0x03 |
| RESPONSE_TAG | 3 | 0x03 |

**Subtag:** CONFIGURE

**Request Format:**
```
[3] [length] [subtag] [startTime: 4 bytes int32 LE] [currentTime: 4 bytes int32 LE] [dataTypes: up to 4 bytes]
```
- Maximum 4 data types per request
- Each data type is 1 byte

**Source:** `RDataStart.java`

---

#### RDataGetPage (Fetch Data Page)

**Tags:**
| Type | Tag | Hex |
|------|-----|-----|
| REQUEST_TAG | 3 | 0x03 |
| RESPONSE_TAG | 3 | 0x03 (confirmation) or 21 / 0x15 (data) |

**Subtag:** GET_PAGE

**Request Format:**
```
[3] [3] [subtag] [pageIndex: 2 bytes short LE]
```
- Total: 5 bytes

**Response:**
- If `response[0] == 21`: Data packet, continue reading
- Otherwise: Completion confirmation

**Source:** `RDataGetPage.java`

---

### Capabilities

#### GetCapabilities (Query Ring Features)

**Tags:**
| Type | Tag | Hex |
|------|-----|-----|
| REQUEST_TAG | 47 | 0x2F |
| EXTENDED_REQUEST_TAG | 1 | 0x01 |
| RESPONSE_TAG | 47 | 0x2F |
| EXTENDED_RESPONSE_TAG | 2 | 0x02 |

**Request Format:**
```
[47] [2] [1] [pageNumber: 1 byte]
```

**Response Format:**
```
[47] [length] [2] [totalPages] [capability pairs...]
```
- Capabilities come in pairs: [capabilityId, version]
- Paginated response (check totalPages)

**Pagination:**
- If `response[3] > currentPage`, send another request with incremented page
- Returns `RESPONSE_MORE_REQUEST (1)` until all pages fetched

**Source:** `GetCapabilities.java`

---

## Extended Tag Summary

| Base Tag | Extended Req | Extended Resp | Operation |
|----------|--------------|---------------|-----------|
| 47 (0x2F) | 43 (0x2B) | 44 (0x2C) | GetAuthNonce |
| 47 (0x2F) | 45 (0x2D) | 46 (0x2E) | Authenticate |
| 47 (0x2F) | 1 (0x01) | 2 (0x02) | GetCapabilities |
| 47 (0x2F) | - | 47 (0x2F) | Auth Failure |

---

## All Command Tags

| Request | Response | Operation | File |
|---------|----------|-----------|------|
| 3 | 3 | RData operations | RDataStart.java, RDataGetPage.java |
| 6 | 7 | SetRealtimeMeasurements | SetRealtimeMeasurements.java |
| 12 | 13 | GetBatteryLevel | GetBatteryLevel.java |
| 16 | 17 | GetEvent | GetEvent.java |
| 18 | 19 | SyncTime | SyncTime.java |
| 47 | 47 | Auth + Capabilities (extended) | Multiple files |

---

## Authentication Flow

```
1. App → Ring: GetAuthNonce request
   [47] [1] [43]

2. Ring → App: Nonce response
   [47] [16] [44] [nonce: 15 bytes]

3. App: Encrypt nonce with shared secret (AES?)
   encryptedNonce = encrypt(nonce, sharedSecret)

4. App → Ring: Authenticate request
   [47] [17] [45] [encryptedNonce: 16 bytes]

5. Ring → App: Auth result
   [47] [length] [46] [0=SUCCESS / 1-3=FAILURE]
```

**Key Exchange:**
- The shared secret is established during ring onboarding
- Encryption appears to be AES-128 based on 16-byte encrypted nonce

---

## Event Sync Flow

```
1. SyncTime to establish timestamp baseline
2. GetEvent with timestamp=0 for initial sync
3. For each event response:
   - If tag >= 0x41: Parse as ring event
   - If tag == 0x11: Check summary for more events
4. Continue GetEvent with nextTimestamp until no more events
```

---

## Byte Order

All multi-byte integers use **Little Endian** format.

Example timestamp conversion:
```java
ByteBuffer.wrap(bytes).order(ByteOrder.LITTLE_ENDIAN).getInt();
```

---

## Related Files

| File | Purpose |
|------|---------|
| `RingOperation.java` | Base class for all operations |
| `GetAuthNonce.java` | Authentication challenge request |
| `Authenticate.java` | Authentication response |
| `AuthResponse.java` | Auth result enum |
| `GetEvent.java` | Historical event fetching |
| `SetRealtimeMeasurements.java` | Live measurement mode |
| `SyncTime.java` | Time synchronization |
| `GetBatteryLevel.java` | Battery status |
| `RDataStart.java` | Data sync initialization |
| `RDataGetPage.java` | Data page fetching |
| `GetCapabilities.java` | Feature capability query |
| `RealTimeMeasurementType.java` | Measurement bitmasks |

All files located at:
```
_large_files/decompiled/sources/com/ouraring/ourakit/operations/
```

---

---

## Firmware Version

#### GetFirmwareVersion

**Tags:**
| Type | Tag | Hex |
|------|-----|-----|
| REQUEST_TAG | 8 | 0x08 |
| RESPONSE_TAG | 9 | 0x09 |

**Request Format:**
```
[8] [3] [0] [0] [0]  (5 bytes)
```

**Response Format:**
```
[9] [length] [apiVersion: 3 bytes] [bootloader: 3 bytes] [firmware: 3 bytes] [btStack: 3 bytes] [deviceId: 6 bytes]
```
- Bytes 2-4: API version (major, minor, patch)
- Bytes 5-7: Bootloader version
- Bytes 8-10: Firmware version
- Bytes 11-13: BT stack version
- Bytes 14-19: Device ID (reversed hex)

**Source:** `GetFirmwareVersion.java`

---

## Feature Mode Operations

#### SetFeatureMode

**Tags:**
| Type | Tag | Hex |
|------|-----|-----|
| REQUEST_TAG | 47 | 0x2F |
| EXTENDED_REQUEST_TAG | 34 | 0x22 |
| RESPONSE_TAG | 47 | 0x2F |
| EXTENDED_RESPONSE_TAG | 35 | 0x23 |

**Request Format:**
```
[47] [3] [34] [capabilityId: 1 byte] [mode: 1 byte]
```

**Response Format:**
```
[47] [length] [35] [capabilityId: 1 byte] [result: 1 byte]
```

**Source:** `SetFeatureMode.java`

---

## DFU (Firmware Update) Protocol

#### DFUStart

**Tags:**
| Type | Tag | Hex |
|------|-----|-----|
| REQUEST_TAG | 43 | 0x2B |
| RESPONSE_TAG | 43 | 0x2B |
| DFU_SUBTAG | 2 | 0x02 |

**Request Format (20 bytes):**
```
[43] [18] [2] [appId: 1] [major: 1] [mid: 1] [minor: 1] [startAddr: 4 LE] [imgLen: 4 LE] [crc32: 4 LE] [hwType: 1]
```

**Response Format (8 bytes):**
```
[43] [6] [2] [appId: 1] [status: 1] [blockType: 1] [blockIndex: 2 LE]
```

**DFU Status Codes:**
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

#### DFUPacket

**Tag:** 44 (0x2C)

**Format:**
```
[44] [length] [data...]
```

**Source:** `DFUPacket.java`

---

## Complete Enums Reference

### FeatureCapabilityId (18 values)

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

### FeatureMode (4 values)

| Value | Name | Description |
|-------|------|-------------|
| 0 | OFF | Feature disabled |
| 1 | AUTOMATIC | Auto-enabled by ring |
| 2 | REQUESTED | Requested by app |
| 3 | CONNECTED_LIVE | Live streaming mode |

**Source:** `FeatureMode.java`

---

### RDataRequestSubtag (6 values)

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

### RDataRequestDataType (32 values)

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
| 35 | ACM_8G_50HZ_ANTIALIAS | 8G 50Hz with anti-alias |
| 36 | ACM_2G_50HZ_ANTIALIAS | 2G 50Hz with anti-alias |
| 37 | GYRO_2000_50HZ_ANTIALIAS | Gyro 2000 50Hz anti-alias |
| 43 | ACM_4G_50HZ_ANTIALIAS | 4G 50Hz with anti-alias |
| 44 | GYRO_500_50HZ_ANTIALIAS | Gyro 500 50Hz anti-alias |
| 45 | GYRO_125_50HZ_ANTIALIAS | Gyro 125 50Hz anti-alias |
| 51 | ACM_8G_10HZ_ANTIALIAS | 8G 10Hz with anti-alias |
| 52 | ACM_2G_10HZ_ANTIALIAS | 2G 10Hz with anti-alias |
| 53 | GYRO_2000_10HZ_ANTIALIAS | Gyro 2000 10Hz anti-alias |
| 59 | ACM_4G_10HZ_ANTIALIAS | 4G 10Hz with anti-alias |
| 60 | GYRO_500_10HZ_ANTIALIAS | Gyro 500 10Hz anti-alias |
| 61 | GYRO_125_10HZ_ANTIALIAS | Gyro 125 10Hz anti-alias |

**Source:** `RDataRequestDataType.java`

---

## Extended Tag Summary (Updated)

| Base Tag | Extended Req | Extended Resp | Operation |
|----------|--------------|---------------|-----------|
| 47 (0x2F) | 43 (0x2B) | 44 (0x2C) | GetAuthNonce |
| 47 (0x2F) | 45 (0x2D) | 46 (0x2E) | Authenticate |
| 47 (0x2F) | 1 (0x01) | 2 (0x02) | GetCapabilities |
| 47 (0x2F) | 34 (0x22) | 35 (0x23) | SetFeatureMode |
| 47 (0x2F) | - | 47 (0x2F) | Auth Failure |

---

## All Command Tags (Complete)

| Request | Response | Operation | File |
|---------|----------|-----------|------|
| 3 | 3/21 | RData operations | RDataStart.java, RDataGetPage.java |
| 6 | 7 | SetRealtimeMeasurements | SetRealtimeMeasurements.java |
| 8 | 9 | GetFirmwareVersion | GetFirmwareVersion.java |
| 12 | 13 | GetBatteryLevel | GetBatteryLevel.java |
| 16 | 17 | GetEvent | GetEvent.java |
| 18 | 19 | SyncTime | SyncTime.java |
| 43 | 43 | DFU operations | DFUStart.java |
| 44 | - | DFUPacket (data only) | DFUPacket.java |
| 47 | 47 | Auth + Capabilities + Features (extended) | Multiple files |

---

## Open Questions

- [ ] DFUActivate, DFUReset complete protocol
- [ ] SetFeatureParameters payload structure
- [ ] SetAuthKey for initial onboarding
- [ ] SetUserInfo payload structure
- [ ] Complete RingNotificationEvent handling
