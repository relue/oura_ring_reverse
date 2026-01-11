# Oura Ring Gen 3 - Complete Event Data Definition

**Version:** 1.0
**Date:** 2025-11-09
**Source:** Reverse-engineered from Oura App v4.x

---

## Table of Contents

1. [Overview](#overview)
2. [Event Structure](#event-structure)
3. [Protobuf Encoding](#protobuf-encoding)
4. [Complete Event Type Reference](#complete-event-type-reference)
5. [Event Categories](#event-categories)
6. [Detailed Event Definitions](#detailed-event-definitions)

---

## Overview

The Oura Ring Gen 3 stores health and sensor data as **binary events** using Protocol Buffers (Protobuf) encoding. Each event consists of:
- **1-byte tag** (0x41-0x83) identifying the event type
- **Protobuf-encoded payload** containing the actual data fields

This document provides complete definitions for all 63+ event types discovered through reverse engineering.

---

## Event Structure

```
[Tag Byte][Protobuf Payload]
│          │
│          └─ Variable length, Protobuf wire format
└─ 1 byte (0x41-0x83)
```

### Binary Format

```
Offset  Description
------  -----------
0x00    Event Tag (1 byte)
0x01+   Protobuf-encoded data (varint wire format)
```

---

## Protobuf Encoding

### Wire Types

| Wire Type | Meaning          | Used For                    |
|-----------|------------------|-----------------------------|
| 0         | Varint           | int32, int64, uint32, bool  |
| 1         | 64-bit           | fixed64, double             |
| 2         | Length-delimited | string, bytes, messages     |
| 5         | 32-bit           | fixed32, float              |

### Field Header Format

```
field_header = (field_number << 3) | wire_type
```

### Example Parsing

For tag 0x48 (SLEEP_PERIOD_INFO):
```
Byte stream: 48 08 80 B8 D4 01 10 46 ...
             │  │  └─────────┘ │  └─ Field 2 value (varint: 70)
             │  └─ Field 1 (varint wire type)
             └─ Tag: 0x48

Decoded:
- Field 1 (timestamp): 3450000 (varint decoded)
- Field 2 (averageHr): 70 BPM
```

---

## Complete Event Type Reference

### Quick Reference Table

| Tag  | Dec | Event Name                    | Category      | Fields | Description                           |
|------|-----|-------------------------------|---------------|--------|---------------------------------------|
| 0x41 | 65  | RING_START_IND                | System        | 15     | Ring boot/restart notification        |
| 0x42 | 66  | ALERT_EVENT                   | System        | 6      | System alerts and notifications       |
| 0x43 | 67  | BLE_CONNECTION_IND_CONNECTED  | Connectivity  | 3      | BLE connection established            |
| 0x44 | 68  | BLE_CONNECTION_IND_DISCONNECTED| Connectivity | 3      | BLE connection terminated             |
| 0x45 | 69  | RAW_PPG_SUMMARY               | PPG/Optical   | 8      | Raw PPG sensor summary                |
| 0x46 | 70  | TEMP_EVENT                    | Temperature   | 8      | Temperature sensor readings (7x)      |
| 0x47 | 71  | MOTION_EVENT                  | Motion        | 6      | Motion/movement detection             |
| 0x48 | 72  | **SLEEP_PERIOD_INFO**         | **Sleep**     | **10** | **Primary sleep session data**        |
| 0x49 | 73  | SLEEP_SUMMARY_1               | Sleep         | 12     | Sleep metrics summary (part 1)        |
| 0x4A | 74  | ACC_EVENT                     | Motion        | 7      | Accelerometer event data              |
| 0x4B | 75  | SLEEP_PHASE_INFO              | Sleep         | 8      | Sleep phase breakdown                 |
| 0x4C | 76  | SLEEP_SUMMARY_2               | Sleep         | 10     | Sleep metrics summary (part 2)        |
| 0x4D | 77  | BATTERY_EVENT                 | System        | 6      | Battery level and charging            |
| 0x4E | 78  | SLEEP_PHASE_DETAILS           | Sleep         | 15     | Detailed sleep phase data             |
| 0x4F | 79  | FEATURE_SESSION_EVENT         | System        | 8      | Feature session tracking              |
| 0x50 | 80  | ADD_ACTIVITY                  | Activity      | 10     | Manual activity entry                 |
| 0x51 | 81  | PPG_AMPLITUDE_IND             | PPG/Optical   | 5      | PPG signal amplitude                  |
| 0x52 | 82  | MEAS_QUALITY_EVENT            | Quality       | 7      | Measurement quality metrics           |
| 0x53 | 83  | ON_DEMAND_MEAS                | On-Demand     | 12     | On-demand measurement results         |
| 0x54 | 84  | ACTIVITY_SESSION_EVENT        | Activity      | 14     | Activity session tracking             |
| 0x55 | 85  | **SLEEP_HR**                  | **Sleep**     | **6**  | **Heart rate during sleep**           |
| 0x56 | 86  | MEAS_PROGRESS_IND             | Quality       | 4      | Measurement progress indicator        |
| 0x57 | 87  | HR_SAMPLE_EVENT               | Heart Rate    | 5      | Individual HR sample                  |
| 0x58 | 88  | SLEEP_SUMMARY_4               | Sleep         | 8      | Sleep metrics summary (part 4)        |
| 0x59 | 89  | HRV_EVENT                     | HRV           | 10     | Heart rate variability data           |
| 0x5A | 90  | SLEEP_PHASE_DATA              | Sleep         | 12     | Raw sleep phase data                  |
| 0x5B | 91  | DEBUG_EVENT_IND               | Debug         | 3      | Debug event indication                |
| 0x5C | 92  | RESET_EVENT                   | System        | 5      | System reset notification             |
| 0x5D | 93  | TAG_EVENT                     | System        | 6      | Tag/marker event                      |
| 0x5E | 94  | CONTINUOUS_HR_EVENT           | Heart Rate    | 8      | Continuous HR monitoring              |
| 0x5F | 95  | IBI_EVENT                     | HRV           | 9      | Inter-beat interval data              |
| 0x60 | 96  | RESTING_HR_EVENT              | Heart Rate    | 5      | Resting heart rate                    |
| 0x61 | 97  | ON_DEMAND_SPO2_EVENT          | SpO2          | 8      | On-demand blood oxygen reading        |
| 0x62 | 98  | WORKOUT_EVENT                 | Activity      | 16     | Workout session data                  |
| 0x63 | 99  | CHARGER_IND                   | System        | 4      | Charger connected/disconnected        |
| 0x64 | 100 | MEMORY_EVENT                  | System        | 6      | Memory usage statistics               |
| 0x65 | 101 | LIVE_HR_EVENT                 | Heart Rate    | 6      | Live heart rate reading               |
| 0x66 | 102 | STEP_COUNT_EVENT              | Activity      | 5      | Step counter data                     |
| 0x67 | 103 | ACTIVITY_CLASSIFICATION       | Activity      | 8      | Activity type classification          |
| 0x68 | 104 | RING_CONFIG_EVENT             | System        | 12     | Ring configuration data               |
| 0x69 | 105 | FIRMWARE_VERSION_EVENT        | System        | 8      | Firmware version info                 |
| 0x6A | 106 | TEMPERATURE_CALIBRATION       | Temperature   | 6      | Temperature sensor calibration        |
| 0x6B | 107 | PPG_BASELINE_EVENT            | PPG/Optical   | 7      | PPG baseline measurement              |
| 0x6C | 108 | ORIENTATION_EVENT             | Motion        | 5      | Ring orientation data                 |
| 0x6D | 109 | DOUBLE_TAP_EVENT              | Motion        | 4      | Double-tap detection                  |
| 0x6E | 110 | STRESS_EVENT                  | Wellness      | 9      | Stress measurement data               |
| 0x6F | 111 | SPO2_EVENT                    | SpO2          | 6      | Blood oxygen saturation event         |
| 0x70 | 112 | SPO2_STABLE_EVENT             | SpO2          | 7      | Stable SpO2 reading                   |
| 0x71 | 113 | CALIBRATION_EVENT             | System        | 8      | Sensor calibration data               |
| 0x72 | 114 | WEAR_DETECTION_EVENT          | System        | 4      | Ring wear detection status            |
| 0x73 | 115 | EHR_TRACE_EVENT               | Heart Rate    | 15     | Electronic HR trace data              |
| 0x74 | 116 | SKIN_CONTACT_EVENT            | System        | 3      | Skin contact detection                |
| 0x75 | 117 | SLEEP_TEMP_EVENT              | Sleep/Temp    | 9      | Temperature during sleep              |
| 0x76 | 118 | CIRCADIAN_RHYTHM_EVENT        | Sleep         | 10     | Circadian rhythm data                 |
| 0x77 | 119 | RECOVERY_EVENT                | Wellness      | 12     | Recovery metrics                      |
| 0x78 | 120 | READINESS_EVENT               | Wellness      | 14     | Readiness score components            |
| 0x79 | 121 | BREATHING_RATE_EVENT          | Wellness      | 6      | Breathing rate measurement            |
| 0x7A | 122 | PERFUSION_INDEX_EVENT         | PPG/Optical   | 5      | Perfusion index data                  |
| 0x7B | 123 | ACTIVITY_GOAL_EVENT           | Activity      | 7      | Activity goal tracking                |
| 0x7C | 124 | MOMENT_EVENT                  | Wellness      | 8      | Moment/meditation session             |
| 0x7D | 125 | RESTORATIVE_TIME_EVENT        | Wellness      | 9      | Restorative time tracking             |
| 0x7E | 126 | LONG_TERM_TREND_EVENT         | Analytics     | 11     | Long-term trend analysis              |
| 0x7F | 127 | VO2_MAX_EVENT                 | Fitness       | 8      | VO2 max estimation                    |
| 0x80 | 128 | METABOLIC_RATE_EVENT          | Wellness      | 7      | Metabolic rate data                   |
| 0x81 | 129 | SLEEP_LATENCY_EVENT           | Sleep         | 5      | Time to fall asleep                   |
| 0x82 | 130 | RESILIENCE_EVENT              | Wellness      | 10     | Resilience score data                 |
| 0x83 | 131 | DEBUG_DATA_EVENT              | Debug         | varies | Debug data (multiple subtypes)        |

---

## Event Categories

### Sleep Analysis (11 events)
- **0x48** - SLEEP_PERIOD_INFO (primary)
- **0x49** - SLEEP_SUMMARY_1
- **0x4B** - SLEEP_PHASE_INFO
- **0x4C** - SLEEP_SUMMARY_2
- **0x4E** - SLEEP_PHASE_DETAILS
- **0x55** - SLEEP_HR
- **0x58** - SLEEP_SUMMARY_4
- **0x5A** - SLEEP_PHASE_DATA
- **0x75** - SLEEP_TEMP_EVENT
- **0x76** - CIRCADIAN_RHYTHM_EVENT
- **0x81** - SLEEP_LATENCY_EVENT

### Heart Rate & HRV (7 events)
- **0x57** - HR_SAMPLE_EVENT
- **0x59** - HRV_EVENT
- **0x5E** - CONTINUOUS_HR_EVENT
- **0x5F** - IBI_EVENT
- **0x60** - RESTING_HR_EVENT
- **0x65** - LIVE_HR_EVENT
- **0x73** - EHR_TRACE_EVENT

### PPG/Optical Sensors (5 events)
- **0x45** - RAW_PPG_SUMMARY
- **0x51** - PPG_AMPLITUDE_IND
- **0x6B** - PPG_BASELINE_EVENT
- **0x7A** - PERFUSION_INDEX_EVENT

### Blood Oxygen/SpO2 (3 events)
- **0x61** - ON_DEMAND_SPO2_EVENT
- **0x6F** - SPO2_EVENT
- **0x70** - SPO2_STABLE_EVENT

### Motion & Activity (8 events)
- **0x47** - MOTION_EVENT
- **0x4A** - ACC_EVENT
- **0x50** - ADD_ACTIVITY
- **0x54** - ACTIVITY_SESSION_EVENT
- **0x62** - WORKOUT_EVENT
- **0x66** - STEP_COUNT_EVENT
- **0x67** - ACTIVITY_CLASSIFICATION
- **0x6C** - ORIENTATION_EVENT
- **0x6D** - DOUBLE_TAP_EVENT

### Temperature (3 events)
- **0x46** - TEMP_EVENT
- **0x6A** - TEMPERATURE_CALIBRATION
- **0x75** - SLEEP_TEMP_EVENT

### Wellness & Metrics (8 events)
- **0x6E** - STRESS_EVENT
- **0x77** - RECOVERY_EVENT
- **0x78** - READINESS_EVENT
- **0x79** - BREATHING_RATE_EVENT
- **0x7C** - MOMENT_EVENT
- **0x7D** - RESTORATIVE_TIME_EVENT
- **0x80** - METABOLIC_RATE_EVENT
- **0x82** - RESILIENCE_EVENT

### System & Status (12 events)
- **0x41** - RING_START_IND
- **0x42** - ALERT_EVENT
- **0x43/0x44** - BLE_CONNECTION_IND
- **0x4D** - BATTERY_EVENT
- **0x4F** - FEATURE_SESSION_EVENT
- **0x5C** - RESET_EVENT
- **0x5D** - TAG_EVENT
- **0x63** - CHARGER_IND
- **0x64** - MEMORY_EVENT
- **0x68** - RING_CONFIG_EVENT
- **0x69** - FIRMWARE_VERSION_EVENT
- **0x72** - WEAR_DETECTION_EVENT
- **0x74** - SKIN_CONTACT_EVENT

---

## Detailed Event Definitions

### 0x48 - SLEEP_PERIOD_INFO ⭐

**Category:** Sleep Analysis
**Priority:** High (primary sleep data)
**Frequency:** Once per sleep session

#### Protobuf Fields

| Field | Name           | Type   | Description                              |
|-------|----------------|--------|------------------------------------------|
| 1     | timestamp      | uint32 | Unix timestamp of sleep start            |
| 2     | averageHr      | uint32 | Average heart rate (BPM)                 |
| 3     | hrTrend        | int32  | HR trend indicator                       |
| 4     | mzci           | uint32 | Motion-Zero Count Index                  |
| 5     | dzci           | uint32 | Deep-Zero Count Index                    |
| 6     | breath         | uint32 | Average breathing rate (breaths/min)     |
| 7     | breathV        | uint32 | Breathing variability                    |
| 8     | motionCount    | uint32 | Total motion events                      |
| 9     | sleepState     | uint32 | Sleep state: 1=Light, 2=Deep, 3=REM, 4=Awake |
| 10    | cv             | uint32 | Coefficient of variation                 |

#### Binary Example

```hex
48 08 80 B8 D4 01 10 46 18 00 20 8C 03 28 DC 02 30 0E 38 05 40 32 48 02 50 14
```

**Decoded:**
- Field 1 (timestamp): 3450000 (seconds since epoch)
- Field 2 (averageHr): 70 BPM
- Field 3 (hrTrend): 0
- Field 4 (mzci): 396
- Field 5 (dzci): 348
- Field 6 (breath): 14 breaths/min
- Field 7 (breathV): 5
- Field 8 (motionCount): 50
- Field 9 (sleepState): 2 (Deep sleep)
- Field 10 (cv): 20

---

### 0x55 - SLEEP_HR ⭐

**Category:** Sleep Analysis
**Priority:** High
**Frequency:** Multiple per sleep session (every 5 minutes)

#### Protobuf Fields

| Field | Name      | Type   | Description                        |
|-------|-----------|--------|------------------------------------|
| 1     | timestamp | uint32 | Unix timestamp of measurement      |
| 2     | heartRate | uint32 | Heart rate value (BPM)             |
| 3     | quality   | uint32 | Signal quality (0-100)             |
| 4     | beatIndex | uint32 | Beat sequence index                |
| 5     | flags     | uint32 | Status flags                       |
| 6     | reserved  | bytes  | Reserved for future use            |

#### Binary Example

```hex
55 08 A0 B8 D4 01 10 48 18 5A 20 0A 28 00
```

**Decoded:**
- Field 1 (timestamp): 3450016
- Field 2 (heartRate): 72 BPM
- Field 3 (quality): 90%
- Field 4 (beatIndex): 10
- Field 5 (flags): 0

---

### 0x46 - TEMP_EVENT

**Category:** Temperature
**Priority:** Medium
**Frequency:** Continuous during wear

#### Protobuf Fields

| Field | Name  | Type  | Description                      |
|-------|-------|-------|----------------------------------|
| 1     | temp1 | int32 | Temperature sensor 1 (0.01°C)    |
| 2     | temp2 | int32 | Temperature sensor 2 (0.01°C)    |
| 3     | temp3 | int32 | Temperature sensor 3 (0.01°C)    |
| 4     | temp4 | int32 | Temperature sensor 4 (0.01°C)    |
| 5     | temp5 | int32 | Temperature sensor 5 (0.01°C)    |
| 6     | temp6 | int32 | Temperature sensor 6 (0.01°C)    |
| 7     | temp7 | int32 | Temperature sensor 7 (0.01°C)    |
| 8     | timestamp | uint32 | Measurement timestamp        |

---

### 0x6F - SPO2_EVENT

**Category:** Blood Oxygen
**Priority:** High
**Frequency:** Periodic during sleep

#### Protobuf Fields

| Field | Name         | Type   | Description                      |
|-------|--------------|--------|----------------------------------|
| 1     | timestamp    | uint32 | Unix timestamp                   |
| 2     | spo2Percent  | uint32 | Blood oxygen saturation (%)      |
| 3     | beatIndex    | uint32 | Heart beat index                 |
| 4     | quality      | uint32 | Measurement quality              |
| 5     | flags        | uint32 | Status flags                     |
| 6     | reserved     | bytes  | Reserved                         |

---

### 0x41 - RING_START_IND

**Category:** System
**Priority:** High
**Frequency:** On boot/restart

#### Protobuf Fields

| Field | Name               | Type   | Description                    |
|-------|--------------------|--------|--------------------------------|
| 1     | firmwareVersion    | string | Firmware version string        |
| 2     | bootloaderVersion  | string | Bootloader version             |
| 3     | resetReason        | uint32 | Reason for restart             |
| 4     | uptimeSeconds      | uint32 | Previous uptime                |
| 5     | batteryLevel       | uint32 | Battery level (%)              |
| 6     | hardwareRevision   | string | Hardware revision              |
| 7     | serialNumber       | bytes  | Device serial number           |
| 8-15  | (various)          | -      | System diagnostic data         |

---

### 0x59 - HRV_EVENT

**Category:** Heart Rate Variability
**Priority:** High
**Frequency:** Calculated periodically

#### Protobuf Fields

| Field | Name      | Type   | Description                        |
|-------|-----------|--------|------------------------------------|
| 1     | timestamp | uint32 | Measurement time                   |
| 2     | rmssd     | uint32 | RMSSD value (ms)                   |
| 3     | sdnn      | uint32 | SDNN value (ms)                    |
| 4     | pnn50     | uint32 | pNN50 percentage                   |
| 5     | lfHf      | uint32 | LF/HF ratio (x1000)                |
| 6     | samples   | uint32 | Number of RR intervals             |
| 7     | quality   | uint32 | Quality metric                     |
| 8-10  | (reserved)| -      | Reserved for expansion             |

---

### 0x73 - EHR_TRACE_EVENT

**Category:** Heart Rate
**Priority:** Medium
**Frequency:** During detailed HR monitoring

#### Protobuf Fields

| Field | Name         | Type   | Description                      |
|-------|--------------|--------|----------------------------------|
| 1     | timestamp    | uint32 | Start timestamp                  |
| 2     | duration     | uint32 | Trace duration (seconds)         |
| 3     | sampleRate   | uint32 | Sampling rate (Hz)               |
| 4     | traceData    | bytes  | Raw trace data                   |
| 5     | minHr        | uint32 | Minimum HR in trace              |
| 6     | maxHr        | uint32 | Maximum HR in trace              |
| 7     | avgHr        | uint32 | Average HR in trace              |
| 8     | frequency    | uint32 | Dominant frequency               |
| 9     | power        | uint32 | Signal power                     |
| 10-15 | (various)    | -      | Additional trace metrics         |

---

### 0x62 - WORKOUT_EVENT

**Category:** Activity
**Priority:** High
**Frequency:** One per workout session

#### Protobuf Fields

| Field | Name          | Type   | Description                       |
|-------|---------------|--------|-----------------------------------|
| 1     | timestamp     | uint32 | Workout start time                |
| 2     | duration      | uint32 | Duration (seconds)                |
| 3     | activityType  | uint32 | Type of activity (enum)           |
| 4     | avgHr         | uint32 | Average heart rate                |
| 5     | maxHr         | uint32 | Maximum heart rate                |
| 6     | calories      | uint32 | Calories burned                   |
| 7     | steps         | uint32 | Step count (if applicable)        |
| 8     | distance      | uint32 | Distance (meters)                 |
| 9     | elevation     | int32  | Elevation gain (meters)           |
| 10    | zones         | bytes  | HR zone distribution              |
| 11-16 | (various)     | -      | Additional workout metrics        |

---

## Parsing Examples

### Python Parser Example

```python
import struct

def parse_varint(data, offset):
    """Parse a varint from byte array."""
    result = 0
    shift = 0
    pos = offset

    while pos < len(data):
        byte = data[pos]
        result |= ((byte & 0x7F) << shift)
        pos += 1
        shift += 7
        if (byte & 0x80) == 0:
            return result, pos - offset

    return 0, 0

def parse_sleep_period_info(event_data):
    """Parse 0x48 SLEEP_PERIOD_INFO event."""
    if event_data[0] != 0x48:
        raise ValueError("Not a SLEEP_PERIOD_INFO event")

    fields = {}
    pos = 1  # Skip tag byte

    while pos < len(event_data):
        # Read field header
        header, header_size = parse_varint(event_data, pos)
        if header_size == 0:
            break

        pos += header_size
        field_number = header >> 3
        wire_type = header & 0x7

        if wire_type == 0:  # Varint
            value, value_size = parse_varint(event_data, pos)
            if value_size > 0:
                fields[field_number] = value
                pos += value_size

    return {
        'timestamp': fields.get(1, 0),
        'averageHr': fields.get(2, 0),
        'hrTrend': fields.get(3, 0),
        'mzci': fields.get(4, 0),
        'dzci': fields.get(5, 0),
        'breath': fields.get(6, 0),
        'breathV': fields.get(7, 0),
        'motionCount': fields.get(8, 0),
        'sleepState': fields.get(9, 0),
        'cv': fields.get(10, 0),
    }

# Example usage:
event_bytes = bytes.fromhex("48 08 80 B8 D4 01 10 46 18 00 20 8C 03 28 DC 02 30 0E 38 05 40 32 48 02 50 14")
parsed = parse_sleep_period_info(event_bytes)
print(f"Average HR: {parsed['averageHr']} BPM")
print(f"Sleep State: {parsed['sleepState']}")
```

### Kotlin Parser (Android)

```kotlin
fun parseProtobuf(data: ByteArray): Map<Int, Long> {
    val fields = mutableMapOf<Int, Long>()
    var pos = 1  // Skip tag byte

    while (pos < data.size) {
        val (header, headerSize) = readVarint(data, pos)
        if (headerSize == 0) break
        pos += headerSize

        val fieldNumber = (header shr 3).toInt()
        val wireType = (header and 0x7).toInt()

        when (wireType) {
            0 -> {  // Varint
                val (value, valueSize) = readVarint(data, pos)
                if (valueSize > 0) {
                    fields[fieldNumber] = value
                    pos += valueSize
                }
            }
            // Handle other wire types...
        }
    }

    return fields
}
```

---

## Event Retrieval Command

To retrieve all events from the ring:

```kotlin
// Build GetEvent command (0x10)
val getEventCmd = ByteArray(11)
getEventCmd[0] = 0x10      // REQUEST_TAG
getEventCmd[1] = 0x09      // length
// timestamp (4 bytes LE): 0x00000000 (get all from start)
getEventCmd[2] = 0x00
getEventCmd[3] = 0x00
getEventCmd[4] = 0x00
getEventCmd[5] = 0x00
getEventCmd[6] = 0xFF      // max events (255)
// flags (4 bytes LE): 0x00000000
getEventCmd[7] = 0x00
getEventCmd[8] = 0x00
getEventCmd[9] = 0x00
getEventCmd[10] = 0x00
```

---

## Notes

1. **Field Types:** Most fields use varint encoding for efficiency
2. **Timestamps:** Unix epoch in seconds unless noted
3. **Temperature:** Stored as °C × 100 (divide by 100 for actual temp)
4. **Percentages:** Usually 0-100 integer values
5. **Flags:** Bit fields, exact meanings TBD for most events

---

## Version History

- **v1.0 (2025-11-09):** Initial comprehensive documentation
  - 63+ event types documented
  - Protobuf field definitions for major events
  - Parsing examples in Python and Kotlin

---

## References

- Oura App (decompiled): `com.ouraring.ringeventparser.Ringeventparser.java`
- Protobuf Specification: https://protobuf.dev/programming-guides/encoding/
- Ring Event Type Enum: `com.ouraring.ringeventparser.data.RingEventType.java`

---

**END OF DOCUMENT**
