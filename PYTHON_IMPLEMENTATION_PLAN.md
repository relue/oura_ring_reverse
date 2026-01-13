# Python Client Implementation Plan - Full Android App Parity

This document outlines all functionality from the Android app that needs to be implemented in the Python client to achieve feature parity.

## Current Status Summary

### ✅ Already Implemented
- [x] BLE scanning and connection (with RPA support)
- [x] Authentication (GetAuthNonce + AES-ECB encryption)
- [x] Heartbeat monitoring (live BPM streaming)
- [x] Basic data retrieval (GetEvent command)
- [x] Time sync command building
- [x] SetAuthKey command
- [x] Basic event type names (~40 types)
- [x] Factory reset command constant

### 🔴 Missing Critical Features

## 1. Event Parsers (HIGH PRIORITY)

### 1.1 SleepPeriodInfo Parser (Event 0x6A)
**Source:** `SleepPeriodInfoParser.kt`

**Format:** 16 bytes total
```
Byte 0:      Event ID (0x6A)
Byte 1:      Length (14)
Bytes 2-5:   Ring timestamp (uint32 LE, deciseconds since boot)
Bytes 6-9:   Packed metrics (uVar13)
  byte6: average_hr = value * 0.5
  byte7: hr_trend = value * 0.0625
  byte8: mzci (HRV) = value * 0.0625
  byte9: dzci (HRV) = value * 0.0625
Bytes 10-11: (overwritten in C++, unused)
Byte 12:     motion_count (0-120)
Byte 13:     sleep_state (0=awake, 1=light, 2=deep/REM)
Bytes 14-15: cv (PPG quality) = value / 65536.0
```

**Implementation:**
```python
class SleepPeriodInfo:
    def __init__(self, data: bytes):
        self.ring_timestamp = struct.unpack('<I', data[2:6])[0]

        # Extract packed metrics from bytes 6-9
        uvar13 = struct.unpack('<I', data[6:10])[0]
        byte0 = uvar13 & 0xFF
        byte1 = (uvar13 >> 8) & 0xFF
        byte2 = (uvar13 >> 16) & 0xFF
        byte3 = (uvar13 >> 24) & 0xFF

        self.average_hr = byte0 * 0.5
        self.hr_trend = byte1 * 0.0625
        self.mzci = byte2 * 0.0625  # HRV metric
        self.dzci = byte3 * 0.0625  # HRV metric
        self.breath = byte2 * 0.0625  # Same as mzci
        self.breath_v = byte3 * 0.0625  # Same as dzci

        self.motion_count = data[12]
        self.sleep_state = data[13]  # 0=awake, 1=light, 2=deep/REM
        self.cv = struct.unpack('<H', data[14:16])[0] / 65536.0
```

**Test Data:** `6a 0e ed 8d 00 00 9b 00 6d 50 6d 32 08 01 00 00`
- Expected: timestamp=36333, avg_hr=77.5, hr_trend=0.0, mzci=6.8125, dzci=5.0, motion=8, sleep_state=1(light), cv=0.0

### 1.2 Temperature Event Parser (Event 0x46)
**Source:** `DataBrowserActivity.kt:parseTemperatureEvent()`

**Format:** Variable length
```
Byte 0:    Event ID (0x46)
Byte 1:    Length
Bytes 2-5: Ring timestamp (uint32 LE, deciseconds)
Byte 6:    Temperature (celsius * 4) - signed byte
Remaining: Additional data (TBD from more samples)
```

**Implementation:**
```python
class TemperatureEvent:
    def __init__(self, data: bytes):
        self.ring_timestamp = struct.unpack('<I', data[2:6])[0]
        temp_raw = struct.unpack('<b', data[6:7])[0]  # signed byte
        self.temperature_celsius = temp_raw / 4.0
```

### 1.3 Generic Protobuf Parser
**Source:** `DataBrowserActivity.kt:parseProtobufGeneric()`

Parse protobuf wire format for events that use it.

**Wire Format:**
- Field: `(field_number << 3) | wire_type`
- Wire types:
  - 0: varint
  - 1: fixed64
  - 2: length-delimited (string/bytes/message)
  - 5: fixed32

**Implementation:**
```python
def parse_protobuf_generic(data: bytes, start_offset: int = 0):
    """Parse protobuf wire format into dict of fields."""
    fields = {}
    offset = start_offset

    while offset < len(data):
        # Read field tag
        tag_byte = data[offset]
        field_num = tag_byte >> 3
        wire_type = tag_byte & 0x07
        offset += 1

        if wire_type == 0:  # varint
            value, bytes_read = read_varint(data, offset)
            fields[field_num] = value
            offset += bytes_read
        elif wire_type == 1:  # fixed64
            value = struct.unpack('<Q', data[offset:offset+8])[0]
            fields[field_num] = value
            offset += 8
        elif wire_type == 2:  # length-delimited
            length, bytes_read = read_varint(data, offset)
            offset += bytes_read
            fields[field_num] = data[offset:offset+length]
            offset += length
        elif wire_type == 5:  # fixed32
            value = struct.unpack('<I', data[offset:offset+4])[0]
            fields[field_num] = value
            offset += 4

    return fields

def read_varint(data: bytes, offset: int):
    """Read protobuf varint from data."""
    result = 0
    shift = 0
    bytes_read = 0

    while offset + bytes_read < len(data):
        byte = data[offset + bytes_read]
        bytes_read += 1
        result |= (byte & 0x7F) << shift
        if (byte & 0x80) == 0:
            break
        shift += 7

    return result, bytes_read
```

### 1.4 Complete Event Type Mapping
**Source:** `MainActivity.kt:getEventTypeName()`

Currently Python has ~40 types, Android has 50+ types. Missing types:

```python
EVENT_TYPES = {
    # ... existing types ...
    0x72: "SLEEP_PERIOD_INFO_3",
    0x73: "MOTION_EVENT_2",
    0x74: "TEMP_EVENT_2",
    0x75: "SLEEP_SUMMARY_5",
    0x76: "SLEEP_PHASE_INFO_2",
    0x77: "HR_EVENT",
    0x78: "ACTIVITY_SESSION",
    0x79: "STRESS_EVENT",
    0x7a: "RESILIENCE_EVENT",
    0x7b: "VO2MAX_EVENT",
    0x7c: "WORKOUT_EVENT",
    0x7d: "RING_CONFIG",
    0x7e: "FIRMWARE_VERSION",
    0x7f: "HARDWARE_VERSION",
    0x80: "SERIAL_NUMBER",
    0x81: "BATTERY_INFO",
    0x82: "CHARGING_STATE",
    0x83: "POWER_STATE",
}
```

---

## 2. Time Sync Correlation (HIGH PRIORITY)

### 2.1 Time Sync Point Storage
**Source:** `MainActivity.kt:saveTimeSyncPoint()`

Store ring time -> UTC mappings for timestamp conversion.

**Implementation:**
```python
class TimeSyncManager:
    def __init__(self, storage_file="time_sync_points.json"):
        self.storage_file = storage_file
        self.sync_points = []  # List of (ring_time_deciseconds, utc_millis) tuples
        self.load()

    def save_sync_point(self, ring_time_deciseconds: int, utc_millis: int):
        """Save a time sync point."""
        self.sync_points.append({
            'ring_time': ring_time_deciseconds,
            'utc_millis': utc_millis,
            'local_time': datetime.now().isoformat()
        })
        self.save()

    def save(self):
        with open(self.storage_file, 'w') as f:
            json.dump(self.sync_points, f, indent=2)

    def load(self):
        if Path(self.storage_file).exists():
            with open(self.storage_file, 'r') as f:
                self.sync_points = json.load(f)
```

### 2.2 UTC Timestamp Calculation
**Source:** `DataBrowserActivity.kt:calculateUtcFromRingTime()`

Convert ring timestamp (deciseconds) to UTC timestamp.

**Formula:**
```
utc_millis = sync_utc_millis - (sync_ring_time - ring_time) * 100
```

**Implementation:**
```python
def calculate_utc_from_ring_time(self, ring_time_deciseconds: int) -> Optional[int]:
    """Calculate UTC timestamp from ring time using most recent sync point."""
    if not self.sync_points:
        return None

    # Use most recent sync point
    sync_point = self.sync_points[-1]
    sync_ring_time = sync_point['ring_time']
    sync_utc_millis = sync_point['utc_millis']

    # Calculate UTC time
    # Ring time is in deciseconds (0.1 second units)
    # UTC is in milliseconds
    utc_millis = sync_utc_millis - (sync_ring_time - ring_time_deciseconds) * 100

    return utc_millis

def format_utc_timestamp(self, utc_millis: int) -> str:
    """Format UTC milliseconds as ISO 8601 string."""
    dt = datetime.fromtimestamp(utc_millis / 1000.0)
    return dt.isoformat()
```

### 2.3 Parse TIME_SYNC Response
**Source:** `MainActivity.kt` notification handler

**Format:** `13 05 <ring_time:4LE>`
- Response tag: 0x13
- Length: 0x05
- Ring time: 4 bytes, little-endian, in deciseconds

**Implementation:**
```python
# In notification handler:
if tag == 0x13 and len(data) >= 6:
    # TIME_SYNC response
    ring_time = struct.unpack('<I', data[2:6])[0]
    utc_millis = int(time.time() * 1000)
    self.time_sync_mgr.save_sync_point(ring_time, utc_millis)
    print(f"Time sync: ring_time={ring_time} deciseconds")
```

---

## 3. Data Retrieval Enhancements (MEDIUM PRIORITY)

### 3.1 Binary Search for Last Event
**Source:** `MainActivity.kt:getDataFromRing()`

Use binary search to find the last event index before fetching all data.

**Algorithm:**
```python
async def find_last_event_index(self) -> int:
    """Use binary search to find the last event index on ring."""
    print("Finding last event using binary search...")

    low = 0
    high = 16777215  # Max seq number (24-bit)
    last_valid = 0

    while low <= high:
        mid = (low + high) // 2

        # Request event at mid
        cmd = build_get_event_cmd(mid, max_events=1)
        await self.send_command(cmd)
        await asyncio.sleep(0.5)

        # Check if we got data
        if self.last_fetch_had_data:
            last_valid = mid
            low = mid + 1  # Search higher
        else:
            high = mid - 1  # Search lower

    print(f"Last event found at index: {last_valid}")
    return last_valid
```

### 3.2 Stop After N Events
**Source:** `MainActivity.kt:stopAfterCount`

Stop fetching after receiving N events of a specific type.

**Implementation:**
```python
async def get_data_with_limit(self, event_type: int, max_count: int):
    """Fetch data and stop after max_count events of event_type."""
    event_count = 0

    while not self.fetch_complete and event_count < max_count:
        cmd = build_get_event_cmd(self.current_seq_num)
        await self.send_command(cmd)
        await asyncio.sleep(0.5)

        # Count events of target type
        for event in self.event_data:
            if event[0] == event_type:
                event_count += 1
                if event_count >= max_count:
                    break
```

### 3.3 Event Filtering (Whitelist/Blacklist)
**Source:** `MainActivity.kt:getSleepDataFromRing()` and DataBrowserActivity

**Implementation:**
```python
class EventFilter:
    def __init__(self):
        self.whitelist = set()  # If non-empty, only include these
        self.blacklist = set()  # Exclude these

    def should_include(self, event_type: int) -> bool:
        """Check if event should be included."""
        if self.whitelist and event_type not in self.whitelist:
            return False
        if event_type in self.blacklist:
            return False
        return True

# Sleep event filter (from Android app)
SLEEP_EVENT_FILTER = {0x48, 0x49, 0x4B, 0x4C, 0x4D, 0x4E, 0x4F,
                      0x55, 0x57, 0x58, 0x5A, 0x6a, 0x72, 0x75, 0x76}
```

---

## 4. Export Functionality (MEDIUM PRIORITY)

### 4.1 Formatted Event Export
**Source:** `MainActivity.kt:exportEventData()`

**Implementation:**
```python
class EventExporter:
    def __init__(self, time_sync_mgr: TimeSyncManager):
        self.time_sync_mgr = time_sync_mgr

    def export_to_text(self, events: List[bytes], output_file: str):
        """Export events to human-readable text file."""
        with open(output_file, 'w') as f:
            f.write(f"Oura Ring Event Export\n")
            f.write(f"Generated: {datetime.now().isoformat()}\n")
            f.write(f"Total events: {len(events)}\n")
            f.write("=" * 80 + "\n\n")

            for i, event in enumerate(events):
                tag = event[0]
                name = get_event_name(tag)

                f.write(f"[{i}] {name} (0x{tag:02x})\n")
                f.write(f"  Raw: {event.hex()}\n")

                # Parse if known type
                if tag == 0x6a:
                    info = SleepPeriodInfo(event)
                    utc = self.time_sync_mgr.calculate_utc_from_ring_time(info.ring_timestamp)
                    f.write(f"  Timestamp: {info.ring_timestamp} deciseconds\n")
                    if utc:
                        f.write(f"  UTC: {self.time_sync_mgr.format_utc_timestamp(utc)}\n")
                    f.write(f"  Sleep State: {info.sleep_state} ({['awake','light','deep/REM'][info.sleep_state]})\n")
                    f.write(f"  Heart Rate: {info.average_hr:.1f} bpm\n")
                    f.write(f"  Motion: {info.motion_count}\n")
                elif tag == 0x46:
                    temp = TemperatureEvent(event)
                    f.write(f"  Temperature: {temp.temperature_celsius:.2f}°C\n")

                f.write("\n")

    def export_to_csv(self, events: List[bytes], output_file: str):
        """Export events to CSV format."""
        import csv

        with open(output_file, 'w', newline='') as f:
            writer = csv.writer(f)
            writer.writerow(['Index', 'Event Type', 'Event Name', 'Ring Time',
                           'UTC Time', 'Raw Hex'])

            for i, event in enumerate(events):
                tag = event[0]
                name = get_event_name(tag)

                # Extract timestamp if available
                ring_time = ""
                utc_time = ""
                if len(event) >= 6:
                    try:
                        rt = struct.unpack('<I', event[2:6])[0]
                        ring_time = str(rt)
                        utc = self.time_sync_mgr.calculate_utc_from_ring_time(rt)
                        if utc:
                            utc_time = self.time_sync_mgr.format_utc_timestamp(utc)
                    except:
                        pass

                writer.writerow([i, f'0x{tag:02x}', name, ring_time,
                               utc_time, event.hex()])

    def export_to_json(self, events: List[bytes], output_file: str):
        """Export events to JSON format."""
        export_data = {
            'metadata': {
                'export_time': datetime.now().isoformat(),
                'total_events': len(events),
                'sync_points': self.time_sync_mgr.sync_points
            },
            'events': []
        }

        for i, event in enumerate(events):
            tag = event[0]
            event_obj = {
                'index': i,
                'type': f'0x{tag:02x}',
                'name': get_event_name(tag),
                'raw_hex': event.hex()
            }

            # Parse known types
            if tag == 0x6a and len(event) >= 16:
                info = SleepPeriodInfo(event)
                event_obj['parsed'] = {
                    'ring_timestamp': info.ring_timestamp,
                    'average_hr': info.average_hr,
                    'hr_trend': info.hr_trend,
                    'mzci': info.mzci,
                    'dzci': info.dzci,
                    'breath': info.breath,
                    'breath_v': info.breath_v,
                    'motion_count': info.motion_count,
                    'sleep_state': info.sleep_state,
                    'cv': info.cv
                }
                utc = self.time_sync_mgr.calculate_utc_from_ring_time(info.ring_timestamp)
                if utc:
                    event_obj['utc_time'] = self.time_sync_mgr.format_utc_timestamp(utc)

            export_data['events'].append(event_obj)

        with open(output_file, 'w') as f:
            json.dump(export_data, f, indent=2)
```

---

## 5. Additional Features (LOW PRIORITY)

### 5.1 Factory Reset (DANGEROUS)
**Already implemented** as constant `CMD_FACTORY_RESET`, just needs to be exposed in CLI.

**Add to menu:**
```python
async def factory_reset(self):
    """DANGEROUS: Wipe all data from ring including auth key."""
    print("WARNING: This will ERASE ALL DATA and reset auth key!")
    confirm = input("Type 'RESET' to confirm: ")
    if confirm == "RESET":
        await self.send_command(CMD_FACTORY_RESET, "Factory Reset")
        print("Factory reset sent. Ring will restart.")
    else:
        print("Cancelled")
```

### 5.2 Event Statistics
**Source:** DataBrowserActivity event counting

**Implementation:**
```python
def analyze_events(events: List[bytes]):
    """Generate event statistics."""
    stats = {}
    for event in events:
        tag = event[0]
        name = get_event_name(tag)
        stats[name] = stats.get(name, 0) + 1

    print("\nEvent Statistics:")
    print("-" * 50)
    for name, count in sorted(stats.items(), key=lambda x: x[1], reverse=True):
        print(f"{name:30s}: {count:6d}")
    print("-" * 50)
    print(f"Total events: {len(events)}")
```

---

## Implementation Priority Order

### Phase 1: Critical Parsing (Week 1)
1. ✅ SleepPeriodInfo parser (0x6A) - most important event type
2. ✅ Time sync point storage and UTC calculation
3. ✅ Complete event type name mapping

### Phase 2: Enhanced Retrieval (Week 2)
4. Binary search for last event
5. Event filtering (whitelist/blacklist)
6. Stop after N events feature

### Phase 3: Export & Analysis (Week 3)
7. Export to text/CSV/JSON formats
8. Temperature event parser (0x46)
9. Event statistics and analysis

### Phase 4: Advanced Features (Week 4)
10. Generic protobuf parser
11. Factory reset CLI exposure
12. Batch processing tools

---

## File Structure for New Code

```
python_client/
├── oura_ble_client.py          # Main client (existing)
├── parsers.py                  # NEW: Event parsers
│   ├── SleepPeriodInfo
│   ├── TemperatureEvent
│   └── ProtobufParser
├── time_sync.py                # NEW: Time sync manager
├── event_filter.py             # NEW: Event filtering
├── export.py                   # NEW: Export functionality
├── analysis.py                 # NEW: Event analysis tools
└── time_sync_points.json       # Generated: Time sync storage
```

---

## Testing Strategy

1. **Unit Tests:**
   - Test SleepPeriodInfo parser with known data: `6a 0e ed 8d 00 00 9b 00 6d 50 6d 32 08 01 00 00`
   - Expected: avg_hr=77.5, sleep_state=1(light), motion=8

2. **Integration Tests:**
   - Connect to real ring and fetch data
   - Verify time sync correlation accuracy
   - Test export formats

3. **Validation:**
   - Compare parsed values with Android app output
   - Verify timestamp calculations match Android

---

## Notes

- Ring timestamp is in **deciseconds** (0.1 second units), UTC is in milliseconds
- SleepPeriodInfo 0x6A has redundant fields: breath=mzci, breath_v=dzci
- TIME_SYNC response is 0x13 (not 0x12 which is request)
- Binary search assumes events are sequential from 0
- Factory reset is PERMANENT and requires re-pairing
