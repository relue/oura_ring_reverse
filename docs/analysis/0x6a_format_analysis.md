# 0x6a (SLEEP_PERIOD_INFO_2) Event Format Analysis

## Overview

The 0x6a events are **individual minute-by-minute sleep samples** sent by the Oura Ring during sleep data synchronization. Each event represents ONE minute of sleep data and uses a **custom 14-byte binary format** (NOT protobuf).

## Discovery Process

### Key Findings from Decompiled Oura App

1. **Event Type**: `RingEventType.API_SLEEP_PERIOD_INFO_2` (tag = 0x6a = 106 decimal)
   - Location: `com/ouraring/ringeventparser/data/RingEventType.java:61`

2. **Data Structure**: `SleepPeriodInfoValue` class has 10 fields:
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

3. **Assembly Pattern**: The app collects multiple 0x6a events and assembles them into protobuf arrays:
   - Each 0x6a event = 1 minute sample
   - Multiple events → collected into arrays (one per field)
   - Arrays stored as `SleepPeriodInfo` protobuf message

## Binary Format (14 Bytes)

### Event Structure
```
Total: 16 bytes
├─ Byte 0: Tag (0x6a = 106)
├─ Byte 1: Length (0x0e = 14)
└─ Bytes 2-15: Payload (14 bytes)
```

### Payload Structure (14 Bytes)

| Offset | Size | Type     | Field                    | Notes                                    |
|--------|------|----------|--------------------------|------------------------------------------|
| 0-3    | 4    | uint32   | Timestamp Offset         | Seconds since base time (little-endian)  |
| 4      | 1    | uint8    | Heart Rate               | BPM (observed: 133-143)                  |
| 5      | 1    | uint8    | HR Trend/Quality         | TBD - varies widely (0-247)              |
| 6-7    | 2    | uint16   | Value (IBI-related?)     | TBD - varies (2488-11405)                |
| 8-9    | 2    | uint16   | Value (Breathing?)       | TBD - varies (2488-12173)                |
| 10-11  | 2    | uint16   | Motion Count?            | Often 0 or small (0-256)                 |
| 12-13  | 2    | uint16   | Sleep State?             | Mostly 0 in samples                      |

### Example Decoding

```
Event: 6a 0e 95 05 02 00 87 0a 36 1e 92 22 00 01 00 00

Tag: 0x6a
Length: 0x0e (14 bytes)
Payload breakdown:
  [0-3]  95 05 02 00 → 0x00020595 = 132501 seconds (timestamp offset)
  [4]    87          → 0x87 = 135 BPM (heart rate)
  [5]    0a          → 0x0a = 10 (HR trend/quality)
  [6-7]  36 1e       → 0x1e36 = 7734
  [8-9]  92 22       → 0x2292 = 8850
  [10-11] 00 01      → 0x0100 = 256
  [12-13] 00 00      → 0x0000 = 0
```

## Data Assembly Pattern

### Step 1: Collection
The ring sends many 0x6a events during sync:
```
Event #572: 6a 0e 95 05 02 00 87 0a 36 1e 92 22 00 01 00 00  (ts=132501s)
Event #573: 6a 0e 2e 03 02 00 85 00 26 0d b8 09 00 01 00 00  (ts=131886s)
Event #574: 6a 0e d7 c9 00 00 85 f7 41 2c 8d 2c 00 01 00 00  (ts=51671s)
...
```

### Step 2: Sorting
Events arrive in **reverse chronological order** (descending timestamps).
The app must sort them chronologically before assembly.

### Step 3: Assembly
Build protobuf arrays:
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

## Test Results

Using the Python decoder with 9 sample events:

```
Total samples: 9
Timestamp offsets:
  First: 132501 (0x00020595)
  Last:  49899 (0x0000c2eb)
  Order: Descending (reverse chronological)

Heart Rate (BPM):
  Min: 133, Max: 143, Avg: 136.6

After sorting and assembly:
  Duration: 9 minutes
  First entry: ts=49899000ms (49899 seconds), hr=134 BPM
  Last entry: ts=132501000ms (132501 seconds), hr=135 BPM
```

## Implementation Status

### ✅ Completed
- Event tag identification (0x6a = 106)
- Payload size verification (14 bytes)
- Timestamp offset parsing (bytes 0-3)
- Heart rate extraction (byte 4)
- Event sorting (reverse chronological → chronological)
- Assembly pattern understanding
- Python decoder prototype

### 🔨 In Progress
- Exact field mapping for bytes 5-13
- Breathing rate extraction
- IBI/HRV calculation
- Motion count interpretation
- Sleep state decoding
- PPG quality (CV) calculation

### 📋 Next Steps
1. Compare with actual Oura app data to verify field mappings
2. Test with larger datasets (100+ events covering full sleep session)
3. Implement complete Python assembler
4. Port to Kotlin for Android app integration
5. Validate against Oura protobuf schema

## Files

- `decode_0x6a_binary.py` - Python decoder for individual events
- `analyze_0x6a_structure.py` - Initial structure analysis
- `decode_sleep_period_info.py` - Protobuf decoder (for assembled data)
- `sleep_period_info.proto` - Protobuf schema documentation

## References

- Decompiled Oura app: `/home/picke/reverse_oura/analysis/decompiled/sources/`
- RingEventType enum: `com/ouraring/ringeventparser/data/RingEventType.java`
- SleepPeriodInfoValue class: `com/ouraring/ringeventparser/message/SleepPeriodInfoValue.java`
- Assembly logic: `com/ouraring/ringeventparser/message/SleepPeriodInfoExtKt.java`
