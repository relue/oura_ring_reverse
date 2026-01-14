# Ring Event Types Reference

Complete documentation of all 63 BLE event types (0x41-0x83) transmitted from Oura Ring.

---

## Event Structure

```
[Tag Byte][Protobuf Payload]
|          |
|          +-- Variable length, Protobuf wire format
+-- 1 byte (0x41-0x83)
```

All events use Protocol Buffers encoding with List<> wrappers for fields.

---

## Quick Navigation

| Category | Events | Doc |
|----------|--------|-----|
| Heart/PPG | IBI, HRV, amplitude | [heart.md](heart.md) |
| Sleep | Period info, summaries, phases | [sleep.md](sleep.md) |
| Activity | Steps, MET levels, summaries | [activity.md](activity.md) |
| SpO2 | Blood oxygen, drops | [spo2.md](spo2.md) |
| Temperature | 7-sensor temp data | [temperature.md](temperature.md) |
| Motion | Accelerometer, wear | [motion.md](motion.md) |
| System | Ring start, sync, debug | [system.md](system.md) |

---

## Complete Event Table (63 Events)

| Tag | Hex | Event Name | Category | Source Class |
|-----|-----|------------|----------|--------------|
| 65 | 0x41 | API_RING_START_IND | System | - |
| 66 | 0x42 | API_TIME_SYNC_IND | System | - |
| 67 | 0x43 | API_ALERT | System | - |
| 68 | 0x44 | API_IBI_EVENT | PPG/Heart | `IbiEvent` |
| 69 | 0x45 | API_MOTION_EVENT | Motion | `MotionEvent` |
| 70 | 0x46 | API_TEMP_EVENT | Temperature | `TempValue` |
| 71 | 0x47 | API_WEAR_EVENT | Wear | `WearEvent` |
| 72 | 0x48 | API_STATE_CHANGE_IND | System | `StateChangeIndValue` |
| 73 | 0x49 | API_DEBUG_EVENT_IND | Debug | - |
| 74 | 0x4A | API_DEBUG_DATA | Debug | - |
| 75 | 0x4B | API_RAW_PPG_EVENT | PPG/Raw | - |
| 76 | 0x4C | API_RAW_ACM_EVENT | Motion/Raw | - |
| 77 | 0x4D | API_SELFTEST_EVENT | System | - |
| 78 | 0x4E | API_SELFTEST_DATA | System | - |
| 79 | 0x4F | API_SLEEP_PERIOD_INFO | Sleep | `SleepPeriodInfoValue` |
| 80 | 0x50 | API_SLEEP_SUMMARY_1 | Sleep | - |
| 81 | 0x51 | API_SLEEP_SUMMARY_2 | Sleep | - |
| 82 | 0x52 | API_SLEEP_SUMMARY_3 | Sleep | - |
| 83 | 0x53 | API_SLEEP_SUMMARY_4 | Sleep | - |
| 84 | 0x54 | API_USER_INFO | System | - |
| 85 | 0x55 | API_TAG_EVENT | User Input | - |
| 86 | 0x56 | API_BLE_CONNECTION_IND | System | - |
| 87 | 0x57 | API_ACTIVITY_SUMMARY_1 | Activity | - |
| 88 | 0x58 | API_ACTIVITY_SUMMARY_2 | Activity | - |
| 89 | 0x59 | API_RECOVERY_SUMMARY | Recovery | - |
| 90 | 0x5A | API_SLEEP_PHASE_INFO | Sleep | - |
| 91 | 0x5B | API_GREEN_IBI_AMP_EVENT | PPG/Green | `GreenIbiAndAmpEvent` |
| 92 | 0x5C | API_SLEEP_TEMP_EVENT | Sleep/Temp | - |
| 93 | 0x5D | API_HRV_EVENT | HRV | `HrvValue` |
| 94 | 0x5E | API_SLEEP_HR_EVENT | Sleep/HR | - |
| 95 | 0x5F | API_GREEN_IBI_QUALITY_EVENT | PPG/Quality | - |
| 96 | 0x60 | API_IBI_AND_AMPLITUDE_EVENT | PPG/Heart | `IbiAndAmplitudeEvent` |
| 97 | 0x61 | API_TEMP_PERIOD_EVENT | Temperature | - |
| 98 | 0x62 | API_MOTION_PERIOD_EVENT | Motion | - |
| 99 | 0x63 | API_BEDTIME_PERIOD_EVENT | Sleep | `BedtimePeriodValue` |
| 100 | 0x64 | API_SLEEP_ACM_PERIOD_EVENT | Sleep/Motion | `SleepAcmPeriodValue` |
| 101 | 0x65 | API_SLEEP_PHASE_DETAILS | Sleep | `SleepPhaseDetails` |
| 102 | 0x66 | API_SLEEP_PHASE_DATA | Sleep | - |
| 103 | 0x67 | API_ACTIVITY_INFO_EVENT | Activity | `ActivityInfoEvent` |
| 104 | 0x68 | API_EHR_TRACE_EVENT | Exercise HR | - |
| 105 | 0x69 | API_EHR_ACM_INTENSITY_EVENT | Exercise | - |
| 106 | 0x6A | API_MEAS_QUALITY_EVENT | Quality | - |
| 107 | 0x6B | API_ON_DEMAND_SESSION_EVENT | On-Demand | - |
| 108 | 0x6C | API_FEATURE_SESSION_EVENT | Session | `FeatureSession` |
| 109 | 0x6D | API_ON_DEMAND_MEAS_EVENT | On-Demand | - |
| 110 | 0x6E | API_ON_DEMAND_MOTION_EVENT | On-Demand | - |
| 111 | 0x6F | API_SPO2_EVENT | SpO2 | `Spo2Event` |
| 112 | 0x70 | API_SPO2_IBI_AND_AMPLITUDE_EVENT | SpO2/IBI | - |
| 113 | 0x71 | API_SLEEP_PERIOD_INFO_2 | Sleep | - |
| 114 | 0x72 | API_RING_SLEEP_FEATURE_INFO | Sleep | - |
| 115 | 0x73 | API_RING_SLEEP_FEATURE_INFO_2 | Sleep | - |
| 116 | 0x74 | API_PPG_AMPLITUDE_IND | PPG/Quality | - |
| 117 | 0x75 | API_TEMP_EVENT_2 | Temperature | - |
| 118 | 0x76 | API_PPG_PEAK_EVENT | PPG | - |
| 119 | 0x77 | API_SPO2_COMBO_EVENT | SpO2 | - |
| 120 | 0x78 | API_SPO2_DC_EVENT | SpO2/Raw | - |
| 121 | 0x79 | API_REAL_STEP_EVENT_FEATURE_1 | Steps | `RealStepsFeatures` |
| 122 | 0x7A | API_REAL_STEP_EVENT_FEATURE_2 | Steps | - |
| 123 | 0x7B | API_CVA_RAW_PPG_DATA_EVENT | CVA | - |
| 124 | 0x7C | API_DAYTIME_HR_EVENT | Daytime HR | - |
| 125 | 0x7D | API_DAYTIME_HR_SESSION_EVENT | Daytime HR | - |
| 126 | 0x7E | API_WHR_EVENT | Workout HR | - |
| 127 | 0x7F | API_WHR_SESSION_EVENT | Workout HR | - |
| 128 | 0x80 | API_SCAN_START | System | - |
| 129 | 0x81 | API_TIME_SYNC_IND_SKIPPED | System | - |
| 130 | 0x82 | API_IBI_GAP_EVENT | PPG/Gap | - |
| 131 | 0x83 | API_SCAN_END | System | - |

**Source:** `RingEventType.java:8-72`

---

## Tag Range Summary

| Range | Hex | Purpose | Count |
|-------|-----|---------|-------|
| 65-78 | 0x41-0x4E | Core system + basic sensors | 14 |
| 79-86 | 0x4F-0x56 | Sleep + user events | 8 |
| 87-95 | 0x57-0x5F | Activity + green LED | 9 |
| 96-110 | 0x60-0x6E | Advanced PPG + sessions | 15 |
| 111-119 | 0x6F-0x77 | SpO2 events | 9 |
| 120-127 | 0x78-0x7F | Steps + CVA + WHR | 8 |
| 128-131 | 0x80-0x83 | System (scan, sync skip, gap) | 4 |

---

## Protobuf Wire Types

| Wire Type | Value | Encoding |
|-----------|-------|----------|
| 0 | Varint | int32, int64, uint32, bool |
| 1 | 64-bit | fixed64, double |
| 2 | Length-delimited | string, bytes, nested, packed repeated |
| 5 | 32-bit | fixed32, float |

Field header format: `field_header = (field_number << 3) | wire_type`

---

## Event Groupings (from RawEventTypes.java)

| Group | Events | Purpose |
|-------|--------|---------|
| TIME | Ring start, time sync | Timestamp management |
| TIMESERIES_DATA | IBI, motion, temp, wear | Continuous data streams |
| PPG | Raw PPG, peaks, amplitude | Photoplethysmography data |
| FEATURE_SESSION | Session events (0x6C) | Feature configuration |
| STATELESS_ACTIVITY_EVENTS | Activity summaries | Activity tracking |
| WHR | WHR events, sessions | Workout heart rate |

---

## Data Format Notes

### Timestamp Format
- **Ring timestamps:** Milliseconds since ring boot or last time sync
- **Conversion:** Add to sync baseline to get Unix timestamp
- **Byte order:** Little Endian (all multi-byte integers)

### Protobuf Structure
All events use Protocol Buffers with Kotlin DSL builders:
```kotlin
// All fields use List<> wrapper, even for single values
val timestamp: List<Long>
val ibi: List<Int>
val amp: List<Int>

// Access via index 0
val ts = event.timestamp[0]
val ibiValue = event.ibi[0]
```

---

## Processing Pipeline

```
Ring → BLE → RingEventParser (libringeventparser.so) → Typed Events → Database
```

**Detailed flow:**
1. BLE receives raw bytes via notification
2. `RingEventParserObj.nativeParseEvents()` decodes protobuf
3. Events stored in `DbRawEvent` (Realm database)
4. `EcoreWrapper.nativeProcessEvents()` (libappecore.so)
5. ML models process features (SleepNet, StepCounter, etc.)
6. Final scores → UI via ViewModels

---

## Source References

**Enum Definition:**
- `com.ouraring.ringeventparser.data.RingEventType` - All 63 event type enums

**Event Parser Files:**
```
_large_files/decompiled/sources/com/ouraring/ringeventparser/
├── IbiAndAmplitudeEventKt.java
├── HrvEventKt.java
├── TempEventKt.java
├── MotionEventKt.java
├── WearEventKt.java
├── SleepPeriodInfoKt.java
├── Spo2EventKt.java
├── ActivityInfoEventKt.java
├── FeatureSessionEventKt.java
├── GreenIbiAndAmpEventKt.java
├── SleepPhaseDetailsKt.java
└── data/RingEventType.java
```

**Native Library:**
- `libringeventparser.so` (3.3 MB) - Protobuf parsing
- JNI: `nativeParseEvents(byte[], int, long, boolean)`
- Symbol: `_ZN15RingEventParser12parse_eventsEPKhjPj`

**Related Classes:**
- `RingEventParserObj.java` - Kotlin JNI wrapper
- `Ringeventparser.RingData` - Protobuf output container

---

## See Also

- [BLE Commands](../ble/_index.md) - How to request events from ring
- [Data Structures](../structures/_index.md) - Processed data structures
- [Native Libraries](../native/_index.md) - Event processing in native code
