# Sleep Data Collection Guide

*Last updated: 2026-01-12*

## Overview

The Oura Ring collects minute-by-minute sleep data using the **SLEEP_PERIOD_INFO_2** event type (0x6A). Each event represents one minute of sleep data, containing physiological metrics like heart rate, heart rate variability (HRV), breathing rate, motion count, and sleep stage classification.

Sleep data is transmitted as individual binary events during synchronization. The ring has no real-time clock (RTC) - instead, it uses a monotonic decisecond counter since boot. UTC timestamps must be calculated using the TIME_SYNC protocol which pairs ring time with phone UTC.

## Event 0x6A (SLEEP_PERIOD_INFO_2) Format

### Event Structure

The 0x6A events use a **custom 14-byte binary format** (NOT protobuf):

```
Total: 16 bytes
+-- Byte 0: Tag (0x6a = 106)
+-- Byte 1: Length (0x0e = 14)
+-- Bytes 2-15: Payload (14 bytes)
```

### Payload Structure (14 Bytes)

| Offset | Size | Type   | Field               | Notes                                   |
|--------|------|--------|---------------------|-----------------------------------------|
| 0-3    | 4    | uint32 | Timestamp Offset    | Deciseconds since boot (little-endian)  |
| 4      | 1    | uint8  | Heart Rate          | BPM (observed: 133-143)                 |
| 5      | 1    | uint8  | HR Trend/Quality    | TBD - varies widely (0-247)             |
| 6-7    | 2    | uint16 | Value (IBI-related) | TBD - varies (2488-11405)               |
| 8-9    | 2    | uint16 | Value (Breathing)   | TBD - varies (2488-12173)               |
| 10-11  | 2    | uint16 | Motion Count        | Often 0 or small (0-256)                |
| 12-13  | 2    | uint16 | Sleep State         | Mostly 0 in samples                     |

### Example Decoding

```
Event: 6a 0e 95 05 02 00 87 0a 36 1e 92 22 00 01 00 00

Tag: 0x6a
Length: 0x0e (14 bytes)
Payload breakdown:
  [0-3]   95 05 02 00 -> 0x00020595 = 132501 deciseconds (timestamp offset)
  [4]     87          -> 0x87 = 135 BPM (heart rate)
  [5]     0a          -> 0x0a = 10 (HR trend/quality)
  [6-7]   36 1e       -> 0x1e36 = 7734
  [8-9]   92 22       -> 0x2292 = 8850
  [10-11] 00 01       -> 0x0100 = 256
  [12-13] 00 00       -> 0x0000 = 0
```

## UTC Timestamp Calculation

### Ring Time System

- **No RTC**: The ring has no real-time clock
- **Monotonic counter**: Uses deciseconds (0.1 second units) since boot/factory reset
- **Synchronization required**: TIME_SYNC protocol pairs ring time with phone UTC

### TIME_SYNC Protocol (0x12/0x13)

The TIME_SYNC protocol establishes the relationship between ring time and UTC:

- **Request (0x12)**: Phone sends 8 bytes UTC time (little-endian) + 1 byte timezone (30-min units)
- **Response (0x13)**: Ring responds with its current time in **deciseconds**

### UTC Conversion Formula

```kotlin
// Ring time is in DECISECONDS (0.1 second units)
val timeDiffDeciseconds = syncRingTimeDeciseconds - eventRingTimeDeciseconds
val eventUtcMillis = syncUtcTimeMillis - (timeDiffDeciseconds * 100)
```

### Example Calculation

```
Event ring time: 136559 deciseconds
Sync ring time:  177799 deciseconds
Sync UTC time:   1731353414000 ms (11.11.2025 19:43:34)

Time difference: 177799 - 136559 = 41240 deciseconds
               = 4124 seconds = 68.73 minutes

Event UTC: 1731353414000 - (41240 * 100) = 1731349290000 ms
         = 11.11.2025 18:34:50
```

### Critical Note: Decisecond Units

The ring timestamps are in **deciseconds**, not seconds. A common bug is treating them as seconds:

- Event timestamp: 136559 (raw value from bytes 0-3)
- **Incorrect**: `136559 * 10 = 1,365,590` deciseconds (wrong!)
- **Correct**: `136559` deciseconds = 13655.9 seconds

**Discovery method**: Analyzing two TIME_SYNC responses 5 minutes 26 seconds apart showed a difference of 3252 units / 326 seconds = ~10x ratio, confirming decisecond units.

## SleepPeriodInfoValue Fields

The `SleepPeriodInfoValue` class (from decompiled Oura app) defines 10 fields:

```java
class SleepPeriodInfoValue {
    long timestamp;              // Unix timestamp (milliseconds)
    float avgHr;                 // Average heart rate (BPM)
    float hrTrend;               // Heart rate trend indicator
    float avgIBI;                // Average Inter-Beat Interval
    float stdIBI;                // Standard deviation of IBI (HRV)
    float avgBreathingRate;      // Average breathing rate (breaths/min)
    float stdBreathingRate;      // Breathing variability (std dev)
    int motionCount;             // Motion/movement count
    int sleepState;              // Sleep state (0=awake, 1=light, 2=deep, 3=REM)
    float cvPPGSignalAmplitude;  // PPG signal quality (coefficient of variation)
}
```

### Sleep State Values

| Value | State |
|-------|-------|
| 0     | Awake |
| 1     | Light |
| 2     | Deep  |
| 3     | REM   |

## Data Assembly Pattern

### Step 1: Collection

The ring sends many 0x6a events during sync:

```
Event #572: 6a 0e 95 05 02 00 87 0a 36 1e 92 22 00 01 00 00  (ts=132501 decisec)
Event #573: 6a 0e 2e 03 02 00 85 00 26 0d b8 09 00 01 00 00  (ts=131886 decisec)
Event #574: 6a 0e d7 c9 00 00 85 f7 41 2c 8d 2c 00 01 00 00  (ts=51671 decisec)
...
```

### Step 2: Sorting

Events arrive in **reverse chronological order** (descending timestamps). They must be sorted chronologically before assembly.

### Step 3: UTC Conversion

Apply the TIME_SYNC formula to convert each event's ring timestamp to UTC:

```kotlin
val eventUtcMillis = syncUtcTimeMillis - ((syncRingTimeDeciseconds - eventRingTimeDeciseconds) * 100)
```

### Step 4: Assembly

Build protobuf arrays for the final `SleepPeriodInfo` message:

```protobuf
message SleepPeriodInfo {
  repeated int64 timestamp = 1;       // [49899000, 50156000, 50441000, ...]
  repeated float average_hr = 2;      // [134.0, 143.0, 140.0, ...]
  repeated float hr_trend = 3;        // [...]
  repeated float mzci = 4;            // HRV data
  repeated float dzci = 5;            // HRV data
  repeated float breath = 6;          // [...]
  repeated float breath_v = 7;        // [...]
  repeated int32 motion_count = 8;    // [...]
  repeated int32 sleep_state = 9;     // [0, 1, 2, 3, ...] (awake/light/deep/REM)
  repeated float cv = 10;             // PPG quality
}
```

## Implementation Example

### Python: Parse Single 0x6A Event

```python
import struct

def parse_sleep_event(data: bytes) -> dict:
    """Parse a single 0x6A sleep event (16 bytes total)."""
    if len(data) < 16:
        raise ValueError(f"Expected 16 bytes, got {len(data)}")

    tag = data[0]
    length = data[1]

    if tag != 0x6a or length != 0x0e:
        raise ValueError(f"Invalid event: tag=0x{tag:02x}, length={length}")

    payload = data[2:16]

    # Parse 14-byte payload (little-endian)
    timestamp_decisec = struct.unpack('<I', payload[0:4])[0]
    heart_rate = payload[4]
    hr_trend = payload[5]
    value1 = struct.unpack('<H', payload[6:8])[0]
    value2 = struct.unpack('<H', payload[8:10])[0]
    motion_count = struct.unpack('<H', payload[10:12])[0]
    sleep_state = struct.unpack('<H', payload[12:14])[0]

    return {
        'timestamp_decisec': timestamp_decisec,
        'timestamp_sec': timestamp_decisec / 10.0,
        'heart_rate_bpm': heart_rate,
        'hr_trend': hr_trend,
        'value1': value1,
        'value2': value2,
        'motion_count': motion_count,
        'sleep_state': sleep_state
    }
```

### Kotlin: UTC Timestamp Calculation

```kotlin
/**
 * Calculate UTC timestamp from ring event time using TIME_SYNC data.
 *
 * @param eventRingTimeDecisec Ring timestamp from event (deciseconds)
 * @param syncRingTimeDecisec Ring time at sync point (deciseconds)
 * @param syncUtcTimeMillis UTC time at sync point (milliseconds)
 * @return Event time as UTC milliseconds
 */
fun calculateUtcFromRingTime(
    eventRingTimeDecisec: Long,
    syncRingTimeDecisec: Long,
    syncUtcTimeMillis: Long
): Long {
    val timeDiffDecisec = syncRingTimeDecisec - eventRingTimeDecisec
    return syncUtcTimeMillis - (timeDiffDecisec * 100)
}

// Usage example:
val eventUtcMillis = calculateUtcFromRingTime(
    eventRingTimeDecisec = 136559,
    syncRingTimeDecisec = 177799,
    syncUtcTimeMillis = 1731353414000
)
// Result: 1731349290000 (11.11.2025 18:34:50)
```

### Python: Assemble Sleep Session

```python
from datetime import datetime
from typing import List, Dict

def assemble_sleep_session(
    events: List[Dict],
    sync_ring_time_decisec: int,
    sync_utc_time_ms: int
) -> Dict:
    """
    Assemble multiple 0x6A events into a sleep session.

    Events arrive in reverse chronological order and must be sorted.
    """
    # Sort events chronologically (ascending timestamp)
    sorted_events = sorted(events, key=lambda e: e['timestamp_decisec'])

    # Convert ring timestamps to UTC
    session = {
        'timestamps_utc': [],
        'heart_rates': [],
        'sleep_states': [],
        'motion_counts': []
    }

    for event in sorted_events:
        time_diff_decisec = sync_ring_time_decisec - event['timestamp_decisec']
        event_utc_ms = sync_utc_time_ms - (time_diff_decisec * 100)

        session['timestamps_utc'].append(event_utc_ms)
        session['heart_rates'].append(event['heart_rate_bpm'])
        session['sleep_states'].append(event['sleep_state'])
        session['motion_counts'].append(event['motion_count'])

    # Add session metadata
    if session['timestamps_utc']:
        session['start_time'] = datetime.fromtimestamp(session['timestamps_utc'][0] / 1000)
        session['end_time'] = datetime.fromtimestamp(session['timestamps_utc'][-1] / 1000)
        session['duration_minutes'] = len(sorted_events)

    return session
```

---

*Merged from: 0x6a_format_analysis.md + SESSION_2025-11-11_UTC_TIMESTAMPS.md*
