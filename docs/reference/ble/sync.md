# Data Sync Protocol

GetEvent and RData protocols for retrieving historical data from the ring.

---

## GetEvent

Primary method for fetching historical events from ring storage.

### Tags

| Type | Tag | Hex |
|------|-----|-----|
| REQUEST_TAG | 16 | 0x10 |
| RESPONSE_TAG | 17 | 0x11 |

### Request Format (11 bytes)

```
[16] [9] [timestamp: 4 bytes uint32 LE] [maxEvents: 1 byte] [flags: 4 bytes int32 LE]
```

| Field | Offset | Size | Description |
|-------|--------|------|-------------|
| Tag | 0 | 1 | 0x10 |
| Length | 1 | 1 | 0x09 (9 bytes follow) |
| Timestamp | 2-5 | 4 | Event start timestamp (ring ms, LE) |
| MaxEvents | 6 | 1 | Max events per request (255 max) |
| Flags | 7-10 | 4 | Event filter flags (LE) |

### Response Formats

**Event Response (tag >= 0x41):**
```
[event_tag] [length] [protobuf_payload...]
```
- When `response[0] >= 65 (0x41)`, this is an actual event
- Pass to RingEventParser for decoding

**Summary Response (tag 0x11):**
```
[17] [length] [eventCount] [???] [nextTimestamp: 4 bytes uint32 LE]
```
- `eventCount`: Number of events fetched
- `nextTimestamp`: Continue from this timestamp

### Timeout

120 seconds (extended for large transfers)

### Event Sync Flow

```
1. SyncTime to establish timestamp baseline
2. GetEvent with timestamp=0 for initial sync
3. For each response:
   - If tag >= 0x41: Parse as ring event
   - If tag == 0x11: Check summary for more events
4. Continue with nextTimestamp until no more events
```

**Source:** `GetEvent.java`

---

## SyncTime

Synchronize ring clock with phone time.

### Tags

| Type | Tag | Hex |
|------|-----|-----|
| REQUEST_TAG | 18 | 0x12 |
| RESPONSE_TAG | 19 | 0x13 |

### Request Format

```
[18] [length] [currentTimeSeconds: 8 bytes int64 LE] [timezoneOffset: 1 byte] [forceSync: 1 byte (optional)]
```

| Field | Description |
|-------|-------------|
| currentTimeSeconds | Unix timestamp in seconds |
| timezoneOffset | Timezone offset in 30-minute increments |
| forceSync | Optional byte to force resync |

### Timezone Calculation

```java
byte timezoneOffset = (byte)(timezoneOffsetMillis / 1800000);  // 30 min = 1800000 ms
```

**Source:** `SyncTime.java`

---

## RData Protocol

Alternative data sync protocol for specific data types.

### RDataStart (Initialize)

**Tags:**
| Type | Tag |
|------|-----|
| REQUEST_TAG | 3 (0x03) |
| RESPONSE_TAG | 3 (0x03) |

**Subtag:** CONFIGURE (2)

**Request Format:**
```
[3] [length] [subtag] [startTime: 4 bytes int32 LE] [currentTime: 4 bytes int32 LE] [dataTypes: up to 4 bytes]
```

- Maximum 4 data types per request
- Each data type is 1 byte (see RDataRequestDataType enum)

**Source:** `RDataStart.java`

---

### RDataGetPage (Fetch Page)

**Tags:**
| Type | Tag |
|------|-----|
| REQUEST_TAG | 3 (0x03) |
| RESPONSE_TAG | 3 or 21 (0x15) |

**Subtag:** GET_PAGE (1)

**Request Format:**
```
[3] [3] [subtag] [pageIndex: 2 bytes short LE]
```

**Response:**
- If `response[0] == 21`: Data packet, continue reading
- Otherwise: Completion confirmation

**Source:** `RDataGetPage.java`

---

## GetBatteryLevel

### Tags

| Type | Tag | Hex |
|------|-----|-----|
| REQUEST_TAG | 12 | 0x0C |
| RESPONSE_TAG | 13 | 0x0D |

### Request Format (2 bytes)

```
[12] [0]
```

### Response Format

```
[13] [length] [level: 1 byte] [state: 1 byte] [voltage?: 1 byte]
```

| Field | Description |
|-------|-------------|
| level | Battery percentage (0-100) |
| state | Charging state |
| Third byte | Additional battery info |

**Source:** `GetBatteryLevel.java`

---

## GetFirmwareVersion

### Tags

| Type | Tag | Hex |
|------|-----|-----|
| REQUEST_TAG | 8 | 0x08 |
| RESPONSE_TAG | 9 | 0x09 |

### Request Format (5 bytes)

```
[8] [3] [0] [0] [0]
```

### Response Format

```
[9] [length] [apiVersion: 3 bytes] [bootloader: 3 bytes] [firmware: 3 bytes] [btStack: 3 bytes] [deviceId: 6 bytes]
```

| Offset | Size | Field |
|--------|------|-------|
| 2-4 | 3 | API version (major, minor, patch) |
| 5-7 | 3 | Bootloader version |
| 8-10 | 3 | Firmware version |
| 11-13 | 3 | BT stack version |
| 14-19 | 6 | Device ID (reversed hex) |

**Source:** `GetFirmwareVersion.java`

---

## GetCapabilities

Query ring feature capabilities.

### Tags

| Type | Tag | Hex |
|------|-----|-----|
| REQUEST_TAG | 47 | 0x2F |
| EXTENDED_REQUEST_TAG | 1 | 0x01 |
| RESPONSE_TAG | 47 | 0x2F |
| EXTENDED_RESPONSE_TAG | 2 | 0x02 |

### Request Format

```
[47] [2] [1] [pageNumber: 1 byte]
```

### Response Format

```
[47] [length] [2] [totalPages] [capability pairs...]
```

- Capabilities come in pairs: `[capabilityId, version]`
- Paginated response (check totalPages)

### Pagination

- If `response[3] > currentPage`, send another request with incremented page
- Returns `RESPONSE_MORE_REQUEST (1)` until all pages fetched

**Source:** `GetCapabilities.java`

---

## Implementation Notes

1. **Events consumed when read** - Single-read buffer
2. **Export immediately after data fetch** - Events cleared on re-fetch
3. **Ring factory reset clears stored events**
4. **Timestamps are deciseconds** - Divide by 10 for seconds

---

## Source References

**Decompiled Classes:**
- `com.ouraring.ourakit.operations.GetEvent`
- `com.ouraring.ourakit.operations.SyncTime`
- `com.ouraring.ourakit.operations.RDataStart`
- `com.ouraring.ourakit.operations.RDataGetPage`
- `com.ouraring.ourakit.operations.GetBatteryLevel`
- `com.ouraring.ourakit.operations.GetFirmwareVersion`
- `com.ouraring.ourakit.operations.GetCapabilities`

**Source Files:**
```
_large_files/decompiled/sources/com/ouraring/ourakit/operations/
├── GetEvent.java
├── SyncTime.java
├── RDataStart.java
├── RDataGetPage.java
├── GetBatteryLevel.java
├── GetFirmwareVersion.java
└── GetCapabilities.java
```

---

## See Also

- [Events Reference](../events/_index.md) - Event types and parsing
- [Protocol](protocol.md) - RDataRequestDataType enum
