# Oura Ring Gen 3 - Command Reference

**Total Commands:** 36+
**Source:** Decompiled Oura Android app (`com.ouraring.ourakit.operations`)
**Last Updated:** 2026-01-12

---

## Architecture Overview

### Base Class: RingOperation

**Location:** `com.ouraring.ourakit.operations.RingOperation<T>`

**Key Properties:**
- Default timeout: 60 seconds
- Extended format prefix: `0x2f` (47)
- Response validation via `parseResponse(byte[] response)`

**Common Response Codes:**
```
0x00 = SUCCESS / RESPONSE_LAST_REQUEST
0x01 = ERROR / RESPONSE_MORE_REQUEST (partial)
0x02 = RESPONSE_NOT_RECOGNIZED (error)
0x03 = RESPONSE_PARTIAL_RESPONSE
0x04 = RESPONSE_INVALID_BUNDLE
```

### BLE Service & Characteristics

```
Primary Service:     98ed0001-a541-11e4-b6a0-0002a5d5c51b
Write Characteristic: 98ed0002-a541-11e4-b6a0-0002a5d5c51b (WRITE, WRITE_NO_RESPONSE)
Notify Characteristic: 98ed0003-a541-11e4-b6a0-0002a5d5c51b (NOTIFY)
```

### Command Structure

**Standard Commands:**
```
Byte 0:  [REQUEST_TAG]     Command identifier
Byte 1:  [length]          Number of bytes that follow (if needed)
Byte 2+: [parameters...]   Command-specific data
```

**Extended Commands (0x2f prefix):**
```
Byte 0:  0x2f              Extended format prefix
Byte 1:  [length]          Number of bytes following
Byte 2:  [EXTENDED_TAG]    Command type
Byte 3+: [parameters...]   Command-specific data
```

**Response Pattern:**
- Ring echoes prefix and length
- Command ID incremented by 1 (e.g., `0x20` → `0x21`)
- Status/data bytes follow

---

## Authentication & Security

### SetAuthKey (0x24 → 0x25)
**Purpose:** Set 16-byte authentication key on ring (first time only)
**Request:** `0x24 0x10 [16-byte auth key]`
**Response:** `0x25 0x01 [status]`
- `0x00` = SUCCESS
- `0x05` = ERROR_PRODUCTION_TESTS_MISSING (acceptable)

**Key Generation:**
```java
UUID randomUUID = UUID.randomUUID();
byte[] bArr = new byte[16];
ByteBuffer.wrap(bArr).order(ByteOrder.LITTLE_ENDIAN)
    .putLong(randomUUID.getMostSignificantBits())
    .putLong(randomUUID.getLeastSignificantBits());
```

### GetAuthNonce (0x2F/0x2B → 0x2F/0x2C)
**Purpose:** Get random nonce for authentication challenge
**Request:** `0x2f 0x01 0x2b`
**Response:** `0x2f 0x10 0x2c [16-byte nonce]`

### Authenticate (0x2F/0x2D → 0x2F/0x2E)
**Purpose:** Complete authentication via encrypted nonce
**Request:** `0x2f 0x11 0x2d [16-byte encrypted nonce]`
**Response:** `0x2f 0x02 0x2e [status]`
- `0x00` = SUCCESS
- `0x01` = FAILURE_AUTHENTICATION_ERROR
- `0x02` = FAILURE_IN_FACTORY_RESET
- `0x03` = FAILURE_NOT_ORIGINAL_ONBOARDED_DEVICE

**Encryption:**
```java
SecretKeySpec keySpec = new SecretKeySpec(authKey, "AES");
Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
cipher.init(Cipher.ENCRYPT_MODE, keySpec);
byte[] encrypted = cipher.doFinal(nonce);
```

---

## Data Retrieval Commands

### GetEvent (0x10 → 0x11)
**Purpose:** Retrieve historical events from ring
**Request:** `[0x10, 0x09, seqNum(4 bytes LE), maxEvents(1 byte), flags(4 bytes LE)]`
**Response:** `[0x11, length, eventsReceived, sleepProgress, bytesLeft(4 bytes LE)]`
**Notes:**
- `seqNum` is event sequence number (NOT Unix timestamp)
- Must loop until `bytesLeft == 0`
- Max 255 events per request

### GetBatteryLevel (0x0C → 0x0D)
**Purpose:** Query current battery level

### GetProductInfo (0x18 → 0x19)
**Purpose:** Retrieve ring product information (model, serial, etc.)

### GetFirmwareVersion (0x08 → 0x09)
**Purpose:** Query firmware version

### GetCapabilities (0x2F/0x01 → 0x2F/0x02)
**Purpose:** Query supported features
**Note:** Paginated, may require multiple requests

---

## Feature Management (Extended Commands)

### GetFeatureStatus (0x2F/0x20 → 0x2F/0x21)
**Purpose:** Query current status of a feature
**Request:** `0x2f 0x02 0x20 [feature_id]`
**Response:** `0x2f 0x0a 0x21 [feature_id] [state] [mode] [subscription] [sensors] ...`

**States:**
- `0x00` = IDLE
- `0x02` = MEASURING

**Modes:**
- `0x01` = AUTO_DISABLE / AUTOMATIC
- `0x03` = CONNECTED_LIVE

### SetFeatureMode (0x2F/0x22 → 0x2F/0x23)
**Purpose:** Enable/disable specific feature
**Request:** `0x2f 0x03 0x22 [feature_id] [mode]`
**Response:** `0x2f 0x03 0x23 [feature_id] 0x00`

**Example:**
```
Request:  2f 03 22 02 03  (Enable heart rate for live monitoring)
Response: 2f 03 23 02 00  (Acknowledged)
```

### SetFeatureSubscription (0x2F/0x26 → 0x2F/0x27)
**Purpose:** Subscribe/unsubscribe to feature updates
**Request:** `0x2f 0x03 0x26 [feature_id] [subscription_mode]`
**Response:** `0x2f 0x03 0x27 [feature_id] 0x00`

**Subscription Modes:**
- `0x00` = Unsubscribe
- `0x02` = LATEST (subscribe to stream)

### GetFeatureLatestValues (0x2F/0x24 → 0x2F/0x25)
**Purpose:** Get most recent measurements from feature

### SetFeatureParameters (0x2F/0x29 → 0x2F/0x2A)
**Purpose:** Configure feature-specific parameters

### EnableBundling (0x2F/0x03 → 0x2F/0x04)
**Purpose:** Bundle multiple commands into single transmission

---

## Time & Synchronization

### SyncTime (0x12 → 0x13)
**Purpose:** Synchronize ring's real-time clock
**Frequency:** Required every 30 minutes for accuracy

---

## User Configuration

### SetUserInfo (0x20 → 0x21)
**Purpose:** Configure user physical attributes
**Parameters:**
- Gender (byte 2)
- Date of birth (8 bytes LE)
- Height (2 bytes LE)
- Weight (2 bytes LE)

---

## Ring Operating Modes

### SetRingMode (0x31 → 0x32)
**Purpose:** Set ring operating mode (Normal, Sleep tracking, etc.)

### SetBleMode (0x16 → 0x17)
**Purpose:** Configure BLE mode
**Modes:**
- `0x00` = Foreground mode (active connection)
- `0x01` = Background mode (low power)
- `0x02` = Disconnect mode

### EnableFlightMode (0x26 → 0x27)
**Purpose:** Enable/disable airplane mode (RF off)

---

## Real-time Measurements

### SetRealtimeMeasurements (0x06 → 0x07)
**Purpose:** Configure real-time streaming mode
**Supported Measurements:**
- Heart rate
- HRV
- Temperature
- Accelerometer
- PPG (photoplethysmogram)

---

## Sleep Analysis

### CheckSleepAnalysis (0x28 → 0x29)
**Purpose:** Trigger or check sleep analysis status
**Request:** `[0x28, 0x01, force(0/1)]`
**Response:** `[0x29, length, status]`

---

## Maintenance & Diagnostics

### RunSelfTest (0x0A → 0x0B)
**Purpose:** Execute hardware self-test diagnostics

### ResetMemory (0x1A → 0x1B)
**Purpose:** Factory reset - clear all data from ring
**Request:**
- Standard: `0x1a 0x00`
- BLE Factory: `0x1a 0x01 0x01`
**Response:** `0x1b 0x01 0x00` (success)
**Timeout:** 360 seconds (6 minutes)
**Warning:** DESTRUCTIVE - erases all events and user data

---

## Notifications

### SetNotification (0x1C → 0x1D)
**Purpose:** Configure notification events from ring

---

## Firmware Update (DFU)

All DFU commands share tags 0x2B → 0x2B

### DFUStart (0x2B → 0x2B)
**Purpose:** Initialize firmware update process

### DFUBlockTransfer (0x2B → 0x2B)
**Purpose:** Transfer firmware data block

### DFUActivate (0x2B → 0x2B)
**Purpose:** Activate newly transferred firmware

### DFUReset (0x2B → 0x2B)
**Purpose:** Reset ring after firmware update

### StartFwUpdate (0x0E → 0x0F)
**Purpose:** Alternative firmware update initiation

---

## Manufacturing & Factory Operations

### SetManufacturingInfo (0x37 → 0x38)
**Purpose:** Set manufacturing/calibration data (factory only)

### SyncManufacturingInfo (0x39 → 0x3A)
**Purpose:** Synchronize manufacturing data (factory only)

---

## R-Data (Research Data)

### RDataStart/Stop/GetPage/Clear/CollectionState (0x03 → 0x03)
**Purpose:** Raw sensor data collection for research

---

## Extended Tag Reference

**Request Tags:**
| Tag | Command |
|-----|---------|
| 0x01 | GetCapabilities |
| 0x03 | EnableBundling |
| 0x20 | GetFeatureStatus |
| 0x22 | SetFeatureMode |
| 0x24 | GetFeatureLatestValues |
| 0x26 | SetFeatureSubscription |
| 0x29 | SetFeatureParameters |
| 0x2B | GetAuthNonce |
| 0x2D | Authenticate |

**Response Tags:** Request tag + 1

---

## Quick Reference Table

| Cmd | Name | Request | Response | Purpose |
|-----|------|---------|----------|---------|
| 0x08 | GetFirmwareVersion | 0x08 | 0x09 | Firmware version |
| 0x0C | GetBatteryLevel | 0x0c | 0x0d | Battery status |
| 0x10 | GetEvent | 0x10 | 0x11 | Historical events |
| 0x12 | SyncTime | 0x12 | 0x13 | Time sync |
| 0x18 | GetProductInfo | 0x18 | 0x19 | Product info |
| 0x1A | ResetMemory | 0x1a | 0x1b | Factory reset |
| 0x20 | GetFeatureStatus | 0x2f 0x20 | 0x2f 0x21 | Feature state |
| 0x22 | SetFeatureMode | 0x2f 0x22 | 0x2f 0x23 | Feature mode |
| 0x24 | SetAuthKey | 0x24 | 0x25 | Set auth key |
| 0x26 | SetFeatureSubscription | 0x2f 0x26 | 0x2f 0x27 | Subscribe |
| 0x2B | GetAuthNonce | 0x2f 0x2b | 0x2f 0x2c | Auth nonce |
| 0x2D | Authenticate | 0x2f 0x2d | 0x2f 0x2e | Authenticate |

---

## Protocol Notes

1. **Little-Endian Encoding:** Multi-byte values use little-endian byte order
2. **Sequence Numbers:** GetEvent uses incrementing sequence numbers, not timestamps
3. **Max Request Size:** BLE MTU typically limits requests to ~244 bytes
4. **Response Chunking:** Large responses may be split across multiple BLE packets
5. **Command Sequencing:** Some commands require authentication first
6. **Timing:** Commands may timeout after 60-120 seconds
7. **Event Persistence:** Events remain on ring until synced and cleared

---

*Merged from: OURA_RING_COMMANDS.md + oura_ring_command_reference.md*
