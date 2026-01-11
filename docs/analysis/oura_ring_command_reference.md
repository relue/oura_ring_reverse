# Oura Ring Gen 3 - Command Reference & Architecture

*Last Updated: 2025-11-09*

## Overview

This document contains hard facts discovered through reverse engineering the Oura Ring Gen 3 official app, including all command-sending classes, factory reset procedures, and complete protocol architecture.

---

## Command-Sending Architecture

### Base Class: RingOperation

**Location:** `com.ouraring.ourakit.operations.RingOperation<T>`

**Key Properties:**
- Default timeout: 60 seconds
- Extended format prefix: `0x2f` (47)
- Response validation via `parseResponse(byte[] response)`
- Callback mechanism via `OperationCallback<T>`

**Common Response Codes:**
```
0x00 = RESPONSE_LAST_REQUEST (success)
0x01 = RESPONSE_MORE_REQUEST (partial)
0x02 = RESPONSE_NOT_RECOGNIZED (error)
0x03 = RESPONSE_PARTIAL_RESPONSE
0x04 = RESPONSE_INVALID_BUNDLE
```

---

## Factory Reset Commands

### ResetMemory Operation (0x1a/0x1b)

**Class:** `com.ouraring.ourakit.operations.ResetMemory`

**Request Format:**
```
Standard:        0x1a 0x00
BLE Factory:     0x1a 0x01 0x01
```

**Response Format:**
```
0x1b [length] [status]
  - 0x1b 0x01 0x00 = Success
  - Other = Failure
```

**Properties:**
- Timeout: **360 seconds** (6 minutes)
- Request tag: `0x1a` (26)
- Response tag: `0x1b` (27)
- Reset flags: `0x01` for BLE factory reset

**Code Reference:**
```java
// ResetMemory.java:29-34
public byte[] getRequest() {
    if (this.completed) return null;
    byte[] bArr = {getRequestTag()};
    return this.bleFactoryReset ?
        n.n0(bArr, new byte[]{1, 1}) :  // 0x1a 0x01 0x01
        n.n0(bArr, new byte[]{0});      // 0x1a 0x00
}
```

**High-Level Trigger Chain:**
```
UI Button Click
  ↓
RingModel.factoryReset()
  ↓
safelyTriggerTransition(FACTORY_RESET)
  ↓
ResetMemory operation queued
  ↓
ResetMemory.getRequest() → 0x1a [flags]
  ↓
SweetBlue BLE write to 98ed0002-...-c51b
  ↓
Ring responds: 0x1b 01 00
```

---

## Feature Control Commands

### 1. GetFeatureStatus (0x20/0x21)

**Class:** `com.ouraring.ourakit.operations.GetFeatureStatus`

**Request:**
```
Extended: 0x2f 0x02 0x20 [feature_id]
Simple:   0x20 [feature_id]
```

**Response:**
```
0x2f 0x0a 0x21 [feature_id] [state] [mode] [subscription] [sensors] ...

Fields:
  - feature_id: Feature identifier (0x02 = heart rate)
  - state: 0x00=IDLE, 0x02=MEASURING
  - mode: 0x01=AUTO_DISABLE, 0x03=CONNECTED_LIVE
  - subscription: 0x00=NONE, 0x02=LATEST
  - sensors: Bitmask of active sensors
```

### 2. SetFeatureMode (0x22/0x23)

**Class:** `com.ouraring.ourakit.operations.SetFeatureMode`

**Request:**
```
0x2f 0x03 0x22 [feature_id] [mode]

Modes:
  0x01 = AUTOMATIC (disable)
  0x03 = CONNECTED_LIVE (enable for live monitoring)
```

**Response:**
```
0x2f 0x03 0x23 [feature_id] 0x00  (ACK)
```

**Example:**
```
Request:  2f 03 22 02 03  (Enable heart rate for live monitoring)
Response: 2f 03 23 02 00  (Acknowledged)
```

### 3. SetFeatureSubscription (0x26/0x27)

**Class:** `com.ouraring.ourakit.operations.SetFeatureSubscription`

**Request:**
```
0x2f 0x03 0x26 [feature_id] [subscription_mode]

Subscription Modes:
  0x00 = Unsubscribe (stop streaming)
  0x02 = LATEST (subscribe to data stream)
```

**Response:**
```
0x2f 0x03 0x27 [feature_id] 0x00  (ACK)
```

**Example:**
```
Request:  2f 03 26 02 02  (Subscribe to heart rate data)
Response: 2f 03 27 02 00  (Acknowledged)
```

---

## Authentication Protocol (CRITICAL FOR POST-FACTORY-RESET)

### Overview

After factory reset or initial pairing, the ring **requires authentication** before accepting any other commands. Without this, the ring will not respond to SetFeatureMode, SetFeatureSubscription, or other operations.

### Authentication Key Generation

**Source:** `com.ouraring.oura.ringtracker.v0.k()` (v0.java:190-200)

```java
public static byte[] k() {
    if (!jj.a.a()) {
        return com.ouraring.core.features.ringconfiguration.r0.f19521a;  // Hardcoded fallback
    }
    UUID randomUUID = UUID.randomUUID();
    byte[] bArr = new byte[16];
    ByteBuffer order = ByteBuffer.wrap(bArr).order(ByteOrder.LITTLE_ENDIAN);
    order.putLong(randomUUID.getMostSignificantBits());
    order.putLong(randomUUID.getLeastSignificantBits());
    return bArr;
}
```

**Key Generation:**
- **16 bytes** (128 bits)
- Generated from random UUID
- Stored in `DbRingConfiguration.authKey`
- Sent to ring via SetAuthKey operation (0x24)

### Authentication Sequence

**1. SetAuthKey (0x24/0x25) - First Time Only**

Send the generated 16-byte authentication key to the ring:

```
Request:  0x24 0x10 [16-byte auth key]
Response: 0x25 0x01 [status]
  - 0x00 = SUCCESS
  - 0x05 = ERROR_PRODUCTION_TESTS_MISSING (acceptable)
```

**Code Reference:** `com.ouraring.ourakit.operations.SetAuthKey` (SetAuthKey.java:41-52)

**2. GetAuthNonce (0x2b/0x2c) - Every Connection**

Request a random nonce from the ring:

```
Request:  0x2f 0x01 0x2b
Response: 0x2f 0x10 0x2c [16-byte nonce]
```

The nonce is extracted from bytes 3-18 of the response.

**Code Reference:** `com.ouraring.ourakit.operations.GetAuthNonce` (GetAuthNonce.java:23-54)

**3. Encrypt Nonce**

**Source:** `com.ouraring.oura.ringtracker.w` (w.java:44-58)

```java
SecretKeySpec secretKeySpec = new SecretKeySpec(authKey, "AES");
Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec);
byte[] encryptedNonce = cipher.doFinal(nonce);
```

**Encryption Details:**
- **Algorithm:** AES/ECB/PKCS5Padding
- **Key:** 16-byte authKey from database
- **Input:** 16-byte nonce from ring
- **Output:** 16 bytes (encrypted nonce)

**4. Authenticate (0x2d/0x2e)**

Send the encrypted nonce to prove possession of the auth key:

```
Request:  0x2f 0x11 0x2d [16-byte encrypted nonce]
Response: 0x2f 0x02 0x2e [status]
  - 0x00 = SUCCESS
  - 0x01 = FAILURE_AUTHENTICATION_ERROR
  - 0x02 = FAILURE_IN_FACTORY_RESET
  - 0x03 = FAILURE_NOT_ORIGINAL_ONBOARDED_DEVICE
```

**Code Reference:** `com.ouraring.ourakit.operations.Authenticate` (Authenticate.java:22-64)

### Complete Authentication Flow

```
FIRST TIME (after factory reset):
1. Generate 16-byte random key (UUID-based)
2. SetAuthKey (0x24) → Send key to ring
3. Store key in DbRingConfiguration.authKey
4. [Continue to connection flow below]

EVERY CONNECTION:
1. GetAuthNonce (0x2f 0x01 0x2b)
   ← Ring responds with 16-byte nonce

2. Load authKey from DbRingConfiguration

3. Encrypt nonce:
   encrypted = AES_ECB_PKCS5(authKey, nonce)

4. Authenticate (0x2f 0x11 0x2d [encrypted])
   ← Ring responds 0x2f 0x02 0x2e 0x00 (SUCCESS)

5. NOW other commands work (SetFeatureMode, etc.)
```

### Why Custom App Fails After Factory Reset

**Problem:** The custom app was missing the authentication sequence.

**Solution:** Must implement:
1. Generate 16-byte random auth key
2. Send SetAuthKey to ring
3. Before every connection: GetAuthNonce → Encrypt → Authenticate
4. Only then proceed with SetFeatureMode/SetFeatureSubscription

---

## Complete Operation Classes (52 Total)

### Authentication & Security
- `SetAuthKey` (0x24/0x25) - Set 16-byte authentication key on ring
- `GetAuthNonce` (0x2b/0x2c) - Get random nonce for authentication
- `Authenticate` (0x2d/0x2e) - Prove possession of auth key via encrypted nonce
- `AuthResponse` - Authentication response status enum

### Feature Management
- `SetFeatureMode` - Control feature operating mode
- `SetFeatureSubscription` - Control data streaming
- `GetFeatureStatus` - Query feature state
- `GetFeatureLatestValues` - Get latest measurements
- `SetFeatureParameters` - Configure feature parameters

### Device Information
- `GetBatteryLevel` - Query battery status
- `GetProductInfo` - Get hardware info
- `GetFirmwareVersion` - Get firmware version
- `GetCapabilities` - Query ring capabilities

### Real-Time Measurements
- `SetRealtimeMeasurements` - Configure real-time data

### R-Data (Research Data)
- `RDataStart` - Start R-data collection
- `RDataStop` - Stop R-data collection
- `RDataRequest` - Request R-data
- `RDataGetPage` - Get R-data page
- `RDataClear` - Clear R-data
- `RDataCollectionState` - Get collection state

### DFU (Device Firmware Update)
- `DFUStart` - Initiate firmware update
- `DFUActivate` - Activate DFU mode
- `DFUPacket` - Send firmware packet
- `DFUReset` - Reset after DFU
- `DFUBlockTransfer` - Transfer firmware block
- `StartFwUpdate` - Start firmware update

### Configuration
- `SetBleMode` - Configure BLE mode
- `SetRingMode` - Set ring operating mode
- `SetNotification` - Enable/disable notifications
- `SetUserInfo` - Set user information
- `SyncTime` - Synchronize time
- `EnableFlightMode` - Enable flight mode
- `EnableBundling` - Enable data bundling

### Memory & Reset
- `ResetMemory` - **Factory reset operation**

### Testing & Diagnostics
- `RunSelfTest` - Execute self-test
- `CheckSleepAnalysis` - Check sleep analysis

### Manufacturing
- `SetManufacturingInfo` - Set manufacturing data
- `SyncManufacturingInfo` - Sync manufacturing data

### Events
- `GetEvent` - Get ring events
- `RingHistoryEvent` - Historical event data

---

## Heartbeat Streaming Protocol

### Initialization Sequence

```
1. GetFeatureStatus (0x20)
   → 2f 02 20 02
   ← 2f 0a 21 02 00 01 00 00 ...  (State: IDLE, Mode: AUTO_DISABLE)

2. SetFeatureMode (0x22)
   → 2f 03 22 02 03  (Mode: CONNECTED_LIVE)
   ← 2f 03 23 02 00  (ACK)

3. SetFeatureSubscription (0x26)
   → 2f 03 26 02 02  (Subscription: LATEST)
   ← 2f 03 27 02 00  (ACK)

4. Heartbeat Stream (0x28) - arrives ~1Hz
   ← 2f 0f 28 02 01 02 00 00 [IBI_low] [IBI_high] ...
```

### Heartbeat Data Format (17 bytes)

```
Offset  Size  Field           Description
------  ----  --------------  ---------------------------
0       1     Prefix          0x2f (extended format)
1       1     Length          0x0f (15 bytes payload)
2       1     Command         0x28 (heartbeat notification)
3       1     Feature ID      0x02 (heart rate)
4       1     Flags           Status flags
5       1     State           Feature state
6-7     2     Sequence        Packet sequence number (LE)
8-9     2     IBI             Inter-beat interval in ms (12-bit LE)
10-11   2     Reserved
12-13   2     Reserved
14-15   2     Reserved
16      1     Checksum

BPM Calculation:
  IBI_ms = (data[9] & 0x0F) << 8 | data[8]
  BPM = 60000 / IBI_ms
```

### Example Heartbeat Packet

```
Hex:  2f 0f 28 02 01 02 00 00 34 05 00 00 00 00 48 0d 7f

Parsed:
  IBI_low  = 0x34 (52)
  IBI_high = 0x05 (5)
  IBI_ms   = (0x05 << 8) | 0x34 = 0x0534 = 1332 ms
  BPM      = 60000 / 1332 = 45 BPM
```

---

## State Machine Transitions

**Class:** `com.ouraring.oura.model.RingModel`

**Method:** `safelyTriggerTransition(RingStateMachine$Transition)`

**Key Transitions:**
```
FACTORY_RESET       - Trigger factory reset
RING_AUTHENTICATED  - Ring authenticated
FIRMWARE_UPDATE_*   - Firmware update states
CONNECT            - Initiate connection
DISCONNECT         - Disconnect from ring
```

**Factory Reset Flow:**
```java
// RingModel.java
public final RingStateMachine$State factoryReset() {
    Timber.f66065a.a("factoryReset", new Object[0]);
    com.bumptech.glide.c.J(this.sharedPreferences, this.macAddress, "factory reset");
    this.deviceLifecycleReporter.recordDeviceFactoryReset(
        TimeseriesModels.HardwareTypeValue.Ring,
        getRingConfigurationManager().d().getSerialNumber()
    );
    return safelyTriggerTransition(RingStateMachine$Transition.FACTORY_RESET);
}
```

---

## BLE Service & Characteristics

**Primary Service UUID:**
```
98ed0001-a541-11e4-b6a0-0002a5d5c51b
```

**Write Characteristic (Commands):**
```
98ed0002-a541-11e4-b6a0-0002a5d5c51b
Properties: WRITE, WRITE_NO_RESPONSE
```

**Notify Characteristic (Responses):**
```
98ed0003-a541-11e4-b6a0-0002a5d5c51b
Properties: NOTIFY
```

---

## Frida Hooks for Analysis

### Hook All Operations

**Script:** `/home/picke/reverse_oura/analysis/frida_scripts/trace-all-operations.js`

**Run:** `/tmp/trace_all_operations.sh`

**Captures:**
- All RingOperation.getRequest() calls
- ResetMemory operations with full backtrace
- SetFeatureMode/Subscription commands
- State machine transitions
- Complete call chain from UI to BLE

**Output Legend:**
- `⭐` = Oura app code (`com.ouraring.oura.*`)
- `🔧` = OuraKit operations (`com.ouraring.ourakit.*`)
- `🔵` = SweetBlue BLE library

---

## Discovered Commands Summary

| Cmd  | Name                      | Request Tag | Response Tag | Purpose                    |
|------|---------------------------|-------------|--------------|----------------------------|
| 0x1a | ResetMemory               | 0x1a        | 0x1b         | Factory reset              |
| 0x20 | GetFeatureStatus          | 0x20        | 0x21         | Query feature state        |
| 0x22 | SetFeatureMode            | 0x22        | 0x23         | Set feature mode           |
| 0x24 | SetAuthKey                | 0x24        | 0x25         | Set 16-byte auth key       |
| 0x26 | SetFeatureSubscription    | 0x26        | 0x27         | Subscribe to data          |
| 0x28 | HeartbeatNotification     | -           | 0x28         | Heartbeat data stream      |
| 0x2b | GetAuthNonce              | 0x2f 0x01 0x2b | 0x2f 0x10 0x2c | Get authentication nonce |
| 0x2d | Authenticate              | 0x2f 0x11 0x2d | 0x2f 0x02 0x2e | Challenge-response auth  |
| 0x0c | Unknown Status Query      | 0x0c        | 0x0d         | Status polling (reset?)    |

---

## Key Findings

### 1. Factory Reset Protocol
- Uses dedicated `ResetMemory` operation class
- 6-minute timeout (longest of all operations)
- Two modes: standard (0x00) and BLE factory (0x01 0x01)
- Requires FACTORY_RESET state machine transition

### 2. Asynchronous BLE Operations
- BLE writes happen in separate thread/callback
- Stack traces at BLE level don't show originating app code
- Need to hook at RingOperation level for full context

### 3. Extended Command Format
- Prefix: `0x2f` (47 decimal)
- Length byte follows prefix
- Allows variable-length commands and responses

### 4. Live Monitoring Requirements
- Feature Mode: `0x03` (CONNECTED_LIVE)
- Subscription Mode: `0x02` (LATEST)
- Ring must be in MEASURING state (0x02)
- Sensors must be active (non-zero sensor mask)

### 5. Command Execution Flow
```
App UI Layer (Kotlin/Activities)
    ↓
Business Logic (RingModel, Processors)
    ↓
OuraKit Operations (RingOperation subclasses)
    ↓
SweetBlue BLE Library (Android BLE wrapper)
    ↓
Android Bluetooth Stack
    ↓
Oura Ring Hardware
```

---

## Files Created

1. **Comprehensive Operation Trace**
   - Script: `/home/picke/reverse_oura/analysis/frida_scripts/trace-all-operations.js`
   - Runner: `/tmp/trace_all_operations.sh`
   - Hooks: All 52 operation classes + state machine

2. **Command Reference**
   - This file: `/home/picke/reverse_oura/analysis/oura_ring_command_reference.md`

3. **Previous Documentation**
   - Protocol: `/home/picke/reverse_oura/analysis/oura_ring_complete_protocol.md`
   - Backtrace logs: `/home/picke/reverse_oura/analysis/backtrace_*.log`

---

## Next Steps for Further Analysis

1. **Hook specific operations** to decode more commands
2. **Analyze R-Data protocol** for research data collection
3. **DFU protocol analysis** for firmware update procedure
4. **Event logging** to understand ring history storage
5. **Manufacturing commands** for production/testing features

---

*Generated from reverse engineering Oura Ring Gen 3 official app v4.x*
*Decompiled source: `/home/picke/reverse_oura/analysis/decompiled/sources/`*
