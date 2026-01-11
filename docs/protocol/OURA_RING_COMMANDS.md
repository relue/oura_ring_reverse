# Oura Ring Protocol - Complete Command Reference

**Source Location:** `/home/picke/reverse_oura/analysis/decompiled/sources/com/ouraring/ourakit/operations/`

**Total Commands:** 36

---

## Data Retrieval Commands

### GetEvent (0x10 → 0x11)
**Class:** `GetEvent.java`
**Purpose:** Retrieve historical events from ring (sleep, activity, etc.)
**Request Format:** `[0x10, 0x09, seqNum(4 bytes LE), maxEvents(1 byte), flags(4 bytes LE)]`
**Response:** `[0x11, length, eventsReceived, sleepProgress, bytesLeft(4 bytes LE)]`
**Notes:**
- `seqNum` is event sequence number (NOT Unix timestamp), starts from 0
- Response followed by individual event payloads (tags ≥0x41)
- Must loop until `bytesLeft == 0` to fetch all events
- Max 255 events per request

### RDataGetPage (0x03 → 0x03)
**Class:** `RDataGetPage.java`
**Purpose:** Get paginated raw sensor data
**Shared Tag:** Multiple RData operations use 0x03

### RDataStart (0x03 → 0x03)
**Class:** `RDataStart.java`
**Purpose:** Start raw data collection session

### RDataStop (0x03 → 0x03)
**Class:** `RDataStop.java`
**Purpose:** Stop raw data collection session

### RDataClear (0x03 → 0x03)
**Class:** `RDataClear.java`
**Purpose:** Clear raw data buffer

### RDataCollectionState (0x03 → 0x03)
**Class:** `RDataCollectionState.java`
**Purpose:** Query current raw data collection state

### GetBatteryLevel (0x0C → 0x0D)
**Class:** `GetBatteryLevel.java`
**Purpose:** Query current battery level

### GetProductInfo (0x18 → 0x19)
**Class:** `GetProductInfo.java`
**Purpose:** Retrieve ring product information (model, serial, etc.)

### GetFirmwareVersion (0x08 → 0x09)
**Class:** `GetFirmwareVersion.java`
**Purpose:** Query firmware version

### GetCapabilities (0x2F/0x01 → 0x2F/0x02)
**Class:** `GetCapabilities.java`
**Purpose:** Query supported features
**Extended Command:** Prefix with 0x2F, then 0x01
**Note:** Paginated, may require multiple requests

---

## Authentication & Security

### SetAuthKey (0x24 → 0x25)
**Class:** `SetAuthKey.java`
**Purpose:** Set authentication key on ring
**Security:** Production tests must pass first
**Key Length:** Fixed size (check KEY_LENGTH constant)

### GetAuthNonce (0x2F/0x2B → 0x2F/0x2C)
**Class:** `GetAuthNonce.java`
**Purpose:** Get authentication challenge/nonce
**Extended Command:** Uses 0x2F prefix

### Authenticate (0x2F/0x2D → 0x2F/0x2E)
**Class:** `Authenticate.java`
**Purpose:** Complete authentication handshake
**Extended Command:** Uses 0x2F prefix

---

## Time & Synchronization

### SyncTime (0x12 → 0x13)
**Class:** `SyncTime.java`
**Purpose:** Synchronize ring's real-time clock
**Format:** Unix timestamp transmission
**Frequency:** Required every 30 minutes for accuracy

---

## User Configuration

### SetUserInfo (0x20 → 0x21)
**Class:** `SetUserInfo.java`
**Purpose:** Configure user physical attributes
**Parameters:**
- Gender (byte 2)
- Date of birth (8 bytes LE)
- Height (2 bytes LE, bytes 3-4)
- Weight (2 bytes LE, bytes 3-4)

---

## Ring Operating Modes

### SetRingMode (0x31 → 0x32)
**Class:** `SetRingMode.java`
**Purpose:** Set ring operating mode
**Modes:** Normal, Sleep tracking, etc.

### SetBleMode (0x16 → 0x17)
**Class:** `SetBleMode.java`
**Purpose:** Configure Bluetooth Low Energy mode
**Modes:**
- `0x00` - Foreground mode (active connection)
- `0x01` - Background mode (low power)
- `0x02` - Disconnect mode

### EnableFlightMode (0x26 → 0x27)
**Class:** `EnableFlightMode.java`
**Purpose:** Enable/disable airplane mode (RF off)

---

## Notifications

### SetNotification (0x1C → 0x1D)
**Class:** `SetNotification.java`
**Purpose:** Configure notification events from ring
**Events:** Battery, sync complete, error conditions, etc.

---

## Feature Management (Extended Commands - 0x2F prefix)

### GetFeatureStatus (0x2F/0x20 → 0x2F/0x21)
**Class:** `GetFeatureStatus.java`
**Purpose:** Query current status of a feature
**Parameter:** Feature capability ID

### SetFeatureMode (0x2F/0x22 → 0x2F/0x23)
**Class:** `SetFeatureMode.java`
**Purpose:** Enable/disable specific feature
**Parameter:** Feature capability ID + mode

### GetFeatureLatestValues (0x2F/0x24 → 0x2F/0x25)
**Class:** `GetFeatureLatestValues.java`
**Purpose:** Get most recent measurements from feature
**Parameter:** Feature capability ID

### SetFeatureSubscription (0x2F/0x26 → 0x2F/0x27)
**Class:** `SetFeatureSubscription.java`
**Purpose:** Subscribe/unsubscribe to feature updates
**Parameter:** Feature capability ID + subscription mode

### SetFeatureParameters (0x2F/0x29 → 0x2F/0x2A)
**Class:** `SetFeatureParameters.java`
**Purpose:** Configure feature-specific parameters
**Parameter:** Feature capability ID + parameters blob

### EnableBundling (0x2F/0x03 → 0x2F/0x04)
**Class:** `EnableBundling.java`
**Purpose:** Bundle multiple commands into single transmission
**Note:** Reduces BLE overhead for batch operations

---

## Real-time Measurements

### SetRealtimeMeasurements (0x06 → 0x07)
**Class:** `SetRealtimeMeasurements.java`
**Purpose:** Configure real-time streaming mode
**Parameters:**
- Measurement types to stream
- Sample rate
- Duration

**Supported Measurements:**
- Heart rate
- HRV
- Temperature
- Accelerometer
- PPG (photoplethysmogram)

---

## Sleep Analysis

### CheckSleepAnalysis (0x28 → 0x29)
**Class:** `CheckSleepAnalysis.java`
**Purpose:** Trigger or check sleep analysis status
**Request:** `[0x28, 0x01, force(0/1)]`
**Response:** `[0x29, length, status]`
**Note:** Returns boolean success/failure, does NOT provide event counts

---

## Maintenance & Diagnostics

### RunSelfTest (0x0A → 0x0B)
**Class:** `RunSelfTest.java`
**Purpose:** Execute hardware self-test diagnostics
**Tests:** Sensors, memory, connectivity

### ResetMemory (0x1A → 0x1B)
**Class:** `ResetMemory.java`
**Purpose:** Clear all data from ring storage
**Warning:** DESTRUCTIVE - erases all events and user data

---

## Manufacturing & Factory Operations

### SetManufacturingInfo (0x37 → 0x38)
**Class:** `SetManufacturingInfo.java`
**Purpose:** Set manufacturing/calibration data
**Access:** Factory/production only

### SyncManufacturingInfo (0x39 → 0x3A)
**Class:** `SyncManufacturingInfo.java`
**Purpose:** Synchronize manufacturing data
**Access:** Factory/production only

---

## Firmware Update (DFU - Device Firmware Update)

All DFU commands share tags 0x2B → 0x2B

### DFUStart (0x2B → 0x2B)
**Class:** `DFUStart.java`
**Purpose:** Initialize firmware update process
**Parameters:** Firmware size, CRC

### DFUBlockTransfer (0x2B → 0x2B)
**Class:** `DFUBlockTransfer.java`
**Purpose:** Transfer firmware data block
**Parameters:** Block number, data payload

### DFUActivate (0x2B → 0x2B)
**Class:** `DFUActivate.java`
**Purpose:** Activate newly transferred firmware

### DFUReset (0x2B → 0x2B)
**Class:** `DFUReset.java`
**Purpose:** Reset ring after firmware update

### StartFwUpdate (0x0E → 0x0F)
**Class:** `StartFwUpdate.java`
**Purpose:** Alternative firmware update initiation method

---

## Extended Command Format

Extended commands use a two-byte tag system:
```
[0x2F, EXTENDED_TAG, length, ...]
```

**Extended Request Tags:**
- 0x01 - GetCapabilities
- 0x03 - EnableBundling
- 0x20 - GetFeatureStatus
- 0x22 - SetFeatureMode
- 0x24 - GetFeatureLatestValues
- 0x26 - SetFeatureSubscription
- 0x29 - SetFeatureParameters
- 0x2B - GetAuthNonce
- 0x2D - Authenticate

**Extended Response Tags:**
- 0x02 - GetCapabilities response
- 0x04 - EnableBundling response
- 0x21 - GetFeatureStatus response
- 0x23 - SetFeatureMode response
- 0x25 - GetFeatureLatestValues response
- 0x27 - SetFeatureSubscription response
- 0x2A - SetFeatureParameters response
- 0x2C - GetAuthNonce response
- 0x2E - Authenticate response

---

## Event Tags (0x41+)

Individual event payloads returned by GetEvent use tags ≥ 0x41:

- `0x41` - Unknown event type
- `0x42` - Unknown event type
- `0x43` - Unknown event type
- `0x44` - Unknown event type
- `0x45` - Unknown event type
- `0x46` - Temperature event (custom 12-byte format)
- `0x47` - Unknown event type
- `0x48` - SLEEP_PERIOD_INFO
- `0x49` - SLEEP_SUMMARY_1
- `0x4B` - SLEEP_PHASE_INFO
- `0x4C` - SLEEP_SUMMARY_2
- `0x4E` - SLEEP_PHASE_DETAILS
- `0x55` - SLEEP_HR (Heart rate during sleep)
- `0x58` - SLEEP_SUMMARY_4
- `0x5A` - SLEEP_PHASE_DATA
- `0x75` - SLEEP_TEMP_EVENT

Most events use Protobuf encoding except temperature (0x46) which uses custom binary format.

---

## Common Response Status Codes

- `0x00` - Success
- `0x01` - Error/Failure
- `0x02` - Invalid command/parse error
- `0x03` - Not authenticated
- `0x04` - Not supported
- `0x05` - Busy/operation in progress

---

## Protocol Notes

1. **Little-Endian Encoding:** Multi-byte values use little-endian byte order
2. **Sequence Numbers:** GetEvent uses incrementing sequence numbers, not timestamps
3. **Max Request Size:** BLE MTU typically limits requests to ~244 bytes
4. **Response Chunking:** Large responses may be split across multiple BLE packets
5. **Command Sequencing:** Some commands require authentication before use
6. **Timing:** Commands may timeout after 60-120 seconds
7. **Event Persistence:** Events remain on ring until synced and cleared

---

## Known Limitations

- **No Event Count Query:** No command to query total events without fetching
- **Sequential Access Only:** Cannot skip to end of event stream
- **No Reverse Fetch:** Must fetch from beginning to get newest events
- **Pagination Limit:** Max 255 events per GetEvent request
- **Memory Constraints:** Fetching thousands of events may cause OOM on mobile

---

## References

- **Source Code:** `/home/picke/reverse_oura/analysis/decompiled/sources/com/ouraring/ourakit/operations/*.java`
- **Protocol Analyzer:** See Frida scripts in `/home/picke/reverse_oura/analysis/frida_scripts/`
- **Event Parsers:** See `RingHistoryEvent.java` for event decoding
- **Feature IDs:** See `FeatureCapabilityId` enum for feature constants

---

**Last Updated:** 2025-11-11
**Decompiled From:** Oura Android App (production release)
**Analysis Tools:** jadx, Frida, custom parsers
