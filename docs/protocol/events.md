# Oura Ring Gen 3 - Event Types Reference

**Last Updated:** 2026-01-12
**Source:** Reverse-engineered from Oura App v4.x and native library analysis

---

## Table of Contents

1. [Overview](#overview)
2. [Event Structure & Protobuf Encoding](#event-structure--protobuf-encoding)
3. [Quick Reference Table](#quick-reference-table)
4. [Events by Category](#events-by-category)
5. [Detailed Field Definitions](#detailed-field-definitions)
6. [Binary Format Reference](#binary-format-reference)
7. [Parsing Examples](#parsing-examples)
8. [Live Verification Data](#live-verification-data)
9. [Implementation Notes](#implementation-notes)

---

## Overview

The Oura Ring Gen 3 stores health and sensor data as **binary events** using Protocol Buffers (Protobuf) encoding. Each event consists of:
- **1-byte tag** (0x41-0x83) identifying the event type
- **Protobuf-encoded payload** containing the actual data fields

This document provides complete definitions for all 63+ event types discovered through reverse engineering.

### Event Structure

```
[Tag Byte][Protobuf Payload]
|          |
|          +-- Variable length, Protobuf wire format
+-- 1 byte (0x41-0x83)
```

### Binary Format

```
Offset  Description
------  -----------
0x00    Event Tag (1 byte)
0x01+   Protobuf-encoded data (varint wire format)
```

---

## Event Structure & Protobuf Encoding

### Wire Types

| Wire Type | Value | Encoding                          |
|-----------|-------|-----------------------------------|
| 0         | Varint | int32, int64, uint32, bool       |
| 1         | 64-bit | fixed64, double                  |
| 2         | Length-delimited | string, bytes, nested, packed repeated |
| 5         | 32-bit | fixed32, float                   |

### Field Header Format

```
field_header = (field_number << 3) | wire_type
```

### Example Parsing

For tag 0x48 (SLEEP_PERIOD_INFO):
```
Byte stream: 48 08 80 B8 D4 01 10 46 ...
             |  |  +----------+ |  +-- Field 2 value (varint: 70)
             |  +-- Field 1 (varint wire type)
             +-- Tag: 0x48

Decoded:
- Field 1 (timestamp): 3450000 (varint decoded)
- Field 2 (averageHr): 70 BPM
```

---

## Quick Reference Table

All 63+ event types discovered through reverse engineering (0x41-0x83):

| Tag (Hex) | Tag (Dec) | Event Name | Description |
|-----------|-----------|------------|-------------|
| 0x41 | 65 | API_RING_START_IND | Ring initialization/boot |
| 0x42 | 66 | API_TIME_SYNC_IND | Time synchronization |
| 0x43 | 67 | API_DEBUG_EVENT_IND | Debug events |
| 0x44 | 68 | API_IBI_EVENT | Inter-Beat Interval |
| 0x45 | 69 | API_STATE_CHANGE_IND | State changes |
| 0x46 | 70 | API_TEMP_EVENT | Temperature (7 sensors) |
| 0x47 | 71 | API_MOTION_EVENT | Motion/accelerometer |
| 0x48 | 72 | API_SLEEP_PERIOD_INFO | Sleep period summary |
| 0x49 | 73 | API_SLEEP_SUMMARY_1 | Sleep summary variant 1 |
| 0x4A | 74 | API_PPG_AMPLITUDE_IND | PPG signal amplitude |
| 0x4B | 75 | API_SLEEP_PHASE_INFO | Sleep phase classification |
| 0x4C | 76 | API_SLEEP_SUMMARY_2 | Sleep summary variant 2 |
| 0x4D | 77 | API_RING_SLEEP_FEATURE_INFO | Sleep features |
| 0x4E | 78 | API_SLEEP_PHASE_DETAILS | Detailed sleep phases |
| 0x4F | 79 | API_SLEEP_SUMMARY_3 | Sleep summary variant 3 |
| 0x50 | 80 | API_ACTIVITY_INFO | Activity metrics (steps, MET) |
| 0x51 | 81 | API_ACTIVITY_SUMMARY_1 | Activity summary 1 |
| 0x52 | 82 | API_ACTIVITY_SUMMARY_2 | Activity summary 2 |
| 0x53 | 83 | API_WEAR_EVENT | Ring wear detection |
| 0x54 | 84 | API_RECOVERY_SUMMARY | Recovery score |
| 0x55 | 85 | API_SLEEP_HR | Sleep heart rate |
| 0x56 | 86 | API_ALERT_EVENT | Alert events |
| 0x57 | 87 | API_RING_SLEEP_FEATURE_INFO_2 | Extended sleep features |
| 0x58 | 88 | API_SLEEP_SUMMARY_4 | Sleep summary variant 4 |
| 0x59 | 89 | API_EDA_EVENT | Electrodermal activity |
| 0x5A | 90 | API_SLEEP_PHASE_DATA | Sleep phase raw data |
| 0x5B | 91 | API_BLE_CONNECTION_IND | BLE connection state |
| 0x5C | 92 | API_USER_INFO | User information |
| 0x5D | 93 | API_HRV_EVENT | Heart Rate Variability |
| 0x5E | 94 | API_SELFTEST_EVENT | Self-test results |
| 0x5F | 95 | API_RAW_ACM_EVENT | Raw accelerometer |
| 0x60 | 96 | API_IBI_AND_AMPLITUDE_EVENT | IBI + PPG amplitude |
| 0x61 | 97 | API_DEBUG_DATA | Debug data packets |
| 0x62 | 98 | API_ON_DEMAND_MEAS | On-demand measurements |
| 0x63 | 99 | API_PPG_PEAK_EVENT | PPG peak detection |
| 0x64 | 100 | API_RAW_PPG_EVENT | Raw PPG waveform |
| 0x65 | 101 | API_ON_DEMAND_SESSION | On-demand session |
| 0x66 | 102 | API_ON_DEMAND_MOTION | On-demand motion |
| 0x67 | 103 | API_RAW_PPG_SUMMARY | PPG summary stats |
| 0x68 | 104 | API_RAW_PPG_DATA | Raw PPG data |
| 0x69 | 105 | API_TEMP_PERIOD | Temperature period |
| 0x6A | 106 | API_SLEEP_PERIOD_INFO_2 | Extended sleep period (minute-by-minute) |
| 0x6B | 107 | API_MOTION_PERIOD | Motion period summary |
| 0x6C | 108 | API_FEATURE_SESSION | Feature session container |
| 0x6D | 109 | API_MEAS_QUALITY_EVENT | Measurement quality |
| 0x6E | 110 | API_SPO2_IBI_AND_AMPLITUDE_EVENT | SpO2 + IBI + amplitude |
| 0x6F | 111 | API_SPO2_EVENT | Blood oxygen (SpO2) |
| 0x70 | 112 | API_SPO2_SMOOTHED_EVENT | Filtered SpO2 |
| 0x71 | 113 | API_GREEN_IBI_AND_AMP_EVENT | Green LED IBI + amplitude |
| 0x72 | 114 | API_SLEEP_ACM_PERIOD | Sleep accelerometer period |
| 0x73 | 115 | API_EHR_TRACE_EVENT | Exercise HR trace |
| 0x74 | 116 | API_EHR_ACM_INTENSITY_EVENT | Exercise accelerometer intensity |
| 0x75 | 117 | API_SLEEP_TEMP_EVENT | Sleep temperature |
| 0x76 | 118 | API_BEDTIME_PERIOD | Bedtime period |
| 0x77 | 119 | API_SPO2_DC_EVENT | SpO2 DC component |
| 0x79 | 121 | API_SELFTEST_DATA_EVENT | Self-test data |
| 0x7A | 122 | API_TAG_EVENT | User tags |
| 0x7E | 126 | API_REAL_STEP_EVENT_FEATURE_ONE | RealSteps feature 1 |
| 0x7F | 127 | API_REAL_STEP_EVENT_FEATURE_TWO | RealSteps feature 2 |
| 0x80 | 128 | API_GREEN_IBI_QUALITY_EVENT | Green IBI quality |
| 0x81 | 129 | API_CVA_RAW_PPG_DATA | CVA PPG raw |
| 0x82 | 130 | API_SCAN_START | Scan session start |
| 0x83 | 131 | API_SCAN_END | Scan session end |

**Note:** Tags 0x78 (120), 0x7B-0x7D (123-125) appear unused.

---

## Events by Category

### Sleep Analysis (11+ events)

| Tag | Event | Priority | Description |
|-----|-------|----------|-------------|
| 0x48 | SLEEP_PERIOD_INFO | High | Primary sleep session data |
| 0x49 | SLEEP_SUMMARY_1 | Medium | Sleep metrics summary (part 1) |
| 0x4B | SLEEP_PHASE_INFO | High | Sleep phase breakdown |
| 0x4C | SLEEP_SUMMARY_2 | Medium | Sleep metrics summary (part 2) |
| 0x4E | SLEEP_PHASE_DETAILS | High | Detailed sleep phase data |
| 0x55 | SLEEP_HR | High | Heart rate during sleep |
| 0x58 | SLEEP_SUMMARY_4 | Medium | Sleep metrics summary (part 4) |
| 0x5A | SLEEP_PHASE_DATA | Medium | Raw sleep phase data |
| 0x6A | SLEEP_PERIOD_INFO_2 | High | Extended minute-by-minute sleep data |
| 0x72 | SLEEP_ACM_PERIOD | Medium | Sleep accelerometer period |
| 0x75 | SLEEP_TEMP_EVENT | Medium | Temperature during sleep |
| 0x76 | BEDTIME_PERIOD | Medium | Bedtime period tracking |

#### Sleep State Values

| Value | State | Description |
|-------|-------|-------------|
| 0 | Awake | User is awake |
| 1 | Light | Light sleep stage |
| 2 | Deep | Deep sleep / SWS |
| 3 | REM | REM sleep stage |

---

### Heart Rate & HRV (7+ events)

| Tag | Event | Priority | Description |
|-----|-------|----------|-------------|
| 0x44 | IBI_EVENT | High | Inter-beat interval data |
| 0x55 | SLEEP_HR | High | Sleep heart rate |
| 0x5D | HRV_EVENT | High | Heart Rate Variability metrics |
| 0x60 | IBI_AND_AMPLITUDE_EVENT | High | IBI + PPG amplitude combined |
| 0x71 | GREEN_IBI_AND_AMP_EVENT | Medium | Green LED IBI + amplitude |
| 0x73 | EHR_TRACE_EVENT | Medium | Exercise HR trace |
| 0x80 | GREEN_IBI_QUALITY_EVENT | Medium | Green IBI quality metrics |

---

### PPG/Optical Sensors (6+ events)

| Tag | Event | Priority | Description |
|-----|-------|----------|-------------|
| 0x4A | PPG_AMPLITUDE_IND | Medium | PPG signal amplitude |
| 0x63 | PPG_PEAK_EVENT | Medium | PPG peak detection |
| 0x64 | RAW_PPG_EVENT | Low | Raw PPG waveform |
| 0x67 | RAW_PPG_SUMMARY | Medium | PPG summary stats |
| 0x68 | RAW_PPG_DATA | Low | Raw PPG data |
| 0x81 | CVA_RAW_PPG_DATA | Low | CVA PPG raw data |

---

### Blood Oxygen/SpO2 (4+ events)

| Tag | Event | Priority | Description |
|-----|-------|----------|-------------|
| 0x6E | SPO2_IBI_AND_AMPLITUDE_EVENT | High | SpO2 + IBI + amplitude |
| 0x6F | SPO2_EVENT | High | Blood oxygen saturation |
| 0x70 | SPO2_SMOOTHED_EVENT | High | Filtered SpO2 |
| 0x77 | SPO2_DC_EVENT | Medium | SpO2 DC component |

---

### Motion & Activity (10+ events)

| Tag | Event | Priority | Description |
|-----|-------|----------|-------------|
| 0x47 | MOTION_EVENT | Medium | Motion/movement detection |
| 0x50 | ACTIVITY_INFO | High | Activity metrics (steps, MET) |
| 0x51 | ACTIVITY_SUMMARY_1 | Medium | Activity summary 1 |
| 0x52 | ACTIVITY_SUMMARY_2 | Medium | Activity summary 2 |
| 0x5F | RAW_ACM_EVENT | Low | Raw accelerometer data |
| 0x66 | ON_DEMAND_MOTION | Medium | On-demand motion data |
| 0x6B | MOTION_PERIOD | Medium | Motion period summary |
| 0x74 | EHR_ACM_INTENSITY_EVENT | Medium | Exercise accelerometer intensity |
| 0x7E | REAL_STEP_EVENT_FEATURE_ONE | Medium | RealSteps feature 1 |
| 0x7F | REAL_STEP_EVENT_FEATURE_TWO | Medium | RealSteps feature 2 |

#### MET Levels (Activity)

MET = Metabolic Equivalent of Task

| Level | Intensity | Example |
|-------|-----------|---------|
| 1-3 | Light | Sitting, standing |
| 4-6 | Moderate | Walking |
| 7-9 | Vigorous | Jogging |
| 10-13 | Very high | Running, sports |

---

### Temperature (3+ events)

| Tag | Event | Priority | Description |
|-----|-------|----------|-------------|
| 0x46 | TEMP_EVENT | High | Temperature (7 sensors) |
| 0x69 | TEMP_PERIOD | Medium | Temperature period summary |
| 0x75 | SLEEP_TEMP_EVENT | Medium | Sleep temperature |

#### Temperature Sensor Mapping

**0x46 TEMP_EVENT (3 active sensors):**
- Temp1: Body-side sensor (~30C on finger during day)
- Temp2: Reference sensor (~31C)
- Temp3: Ambient/external (~26C)

**0x75 SLEEP_TEMP_EVENT (7 sensors):**
- All sensors ~35C during sleep (finger skin temperature)
- Higher precision for sleep tracking

---

### System & Status (10+ events)

| Tag | Event | Priority | Description |
|-----|-------|----------|-------------|
| 0x41 | RING_START_IND | High | Ring boot/restart notification |
| 0x42 | TIME_SYNC_IND | High | Time synchronization |
| 0x45 | STATE_CHANGE_IND | Medium | State changes |
| 0x53 | WEAR_EVENT | High | Ring wear detection |
| 0x56 | ALERT_EVENT | Medium | Alert events |
| 0x5B | BLE_CONNECTION_IND | Medium | BLE connection state |
| 0x5C | USER_INFO | Low | User information |
| 0x5E | SELFTEST_EVENT | Low | Self-test results |
| 0x6C | FEATURE_SESSION | Medium | Feature session container |
| 0x6D | MEAS_QUALITY_EVENT | Medium | Measurement quality |
| 0x79 | SELFTEST_DATA_EVENT | Low | Self-test data |
| 0x82 | SCAN_START | Low | Scan session start |
| 0x83 | SCAN_END | Low | Scan session end |

---

## Detailed Field Definitions

### 0x48 - SLEEP_PERIOD_INFO

**Source:** `com.ouraring.ringeventparser.message.SleepPeriodInfoValue`
**Category:** Sleep Analysis
**Priority:** High
**Frequency:** Once per sleep session

#### Protobuf Fields

| Field | Name | Type | Description |
|-------|------|------|-------------|
| 1 | timestamp | uint32/long | Unix timestamp of sleep start (ms) |
| 2 | avgHr | float | Average heart rate (BPM) |
| 3 | hrTrend | float/int32 | Heart rate trend indicator |
| 4 | avgIBI | float | Average inter-beat interval (ms) |
| 5 | stdIBI | float | Standard deviation of IBI (ms) |
| 6 | avgBreathingRate | float | Average breathing rate (breaths/min) |
| 7 | stdBreathingRate | float | Std dev of breathing rate |
| 8 | motionCount | int | Motion/movement count |
| 9 | sleepState | int | Sleep state: 0=Awake, 1=Light, 2=Deep, 3=REM |
| 10 | cvPPGSignalAmplitude | float | PPG signal quality (CV) |

#### Binary Example

```hex
48 08 80 B8 D4 01 10 46 18 00 20 8C 03 28 DC 02 30 0E 38 05 40 32 48 02 50 14
```

**Decoded:**
- Field 1 (timestamp): 3450000
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

### 0x55 - SLEEP_HR

**Category:** Sleep Analysis
**Priority:** High
**Frequency:** Multiple per sleep session (every 5 minutes)

#### Protobuf Fields

| Field | Name | Type | Description |
|-------|------|------|-------------|
| 1 | timestamp | uint32 | Unix timestamp of measurement |
| 2 | heartRate | uint32 | Heart rate value (BPM) |
| 3 | quality | uint32 | Signal quality (0-100) |
| 4 | beatIndex | uint32 | Beat sequence index |
| 5 | flags | uint32 | Status flags |
| 6 | reserved | bytes | Reserved for future use |

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

### 0x5D - HRV_EVENT

**Source:** `com.ouraring.ringeventparser.HrvEventKt`
**Category:** Heart Rate Variability
**Priority:** High
**Frequency:** Calculated periodically

#### Protobuf Fields

| Field | Name | Type | Description |
|-------|------|------|-------------|
| 1 | timestamp | repeated long | Timestamps (ms) |
| 2 | averageHr5Min | repeated int | Average HR over 5-min window (BPM) |
| 3 | averageRmssd5Min | repeated int | Average RMSSD over 5-min window (ms) |
| 4 | pnn50 | uint32 | pNN50 percentage |
| 5 | lfHf | uint32 | LF/HF ratio (x1000) |
| 6 | samples | uint32 | Number of RR intervals |
| 7 | quality | uint32 | Quality metric |

---

### 0x46 - TEMP_EVENT

**Source:** `com.ouraring.ringeventparser.TempEventKt`
**Category:** Temperature
**Priority:** Medium
**Frequency:** Continuous during wear

#### Protobuf Fields

| Field | Name | Type | Description |
|-------|------|------|-------------|
| 1 | timestamp | repeated long | Timestamps (ms) |
| 2 | temp1 | repeated float | Temperature sensor 1 (C) |
| 3 | temp2 | repeated float | Temperature sensor 2 (C) |
| 4 | temp3 | repeated float | Temperature sensor 3 (C) |
| 5 | temp4 | repeated float | Temperature sensor 4 (C) |
| 6 | temp5 | repeated float | Temperature sensor 5 (C) |
| 7 | temp6 | repeated float | Temperature sensor 6 (C) |
| 8 | temp7 | repeated float | Temperature sensor 7 (C) |

---

### 0x60 - IBI_AND_AMPLITUDE_EVENT

**Source:** `com.ouraring.ringeventparser.IbiAndAmplitudeEventKt`
**Category:** Heart Rate
**Priority:** High
**Frequency:** Continuous during monitoring

#### Protobuf Fields

| Field | Name | Type | Description |
|-------|------|------|-------------|
| 1 | timestamp | repeated long | Timestamps (ms) |
| 2 | ibi | repeated int | Inter-beat interval (ms) |
| 3 | amp | repeated int | PPG amplitude (raw units) |

---

### 0x6F - SPO2_EVENT

**Source:** `com.ouraring.ringeventparser.message.Spo2Event`
**Category:** Blood Oxygen
**Priority:** High
**Frequency:** Periodic during sleep

#### Protobuf Fields

| Field | Name | Type | Description |
|-------|------|------|-------------|
| 1 | timestamp | long | Unix timestamp (ms) |
| 2 | beatOffset | int | Offset from beat |
| 3 | beatIndex | int | Index of the heartbeat |
| 4 | spo2Value | int | SpO2 percentage (0-100) |
| 5 | quality | uint32 | Measurement quality |
| 6 | flags | uint32 | Status flags |

---

### 0x50 - ACTIVITY_INFO

**Source:** `com.ouraring.ringeventparser.message.ActivityInfoEvent`
**Category:** Activity
**Priority:** High
**Frequency:** Periodic during activity

#### Protobuf Fields

| Field | Name | Type | Description |
|-------|------|------|-------------|
| 1 | timestamp | long | Unix timestamp (ms) |
| 2 | stepCount | int | Step count |
| 3 | metLevel1 | float | MET level 1 intensity |
| 4 | metLevel2 | float | MET level 2 intensity |
| ... | ... | ... | ... |
| 14 | metLevel13 | float | MET level 13 intensity |

**Note:** 13 MET levels represent different activity intensity buckets.

---

### 0x47 - MOTION_EVENT

**Source:** `com.ouraring.ringeventparser.message.MotionEvent`
**Category:** Motion
**Priority:** Medium
**Frequency:** During motion detection

#### Protobuf Fields

| Field | Name | Type | Description |
|-------|------|------|-------------|
| 1 | timestamp | long | Unix timestamp (ms) |
| 2 | orientation | int | Ring orientation on finger |
| 3 | motionSeconds | int | Seconds of motion detected |
| 4 | averageX | float | Average accelerometer X-axis |
| 5 | averageY | float | Average accelerometer Y-axis |
| 6 | averageZ | float | Average accelerometer Z-axis |
| 7 | regularity | int | Motion regularity metric |
| 8 | lowIntensity | int | Low-intensity motion count |
| 9 | highIntensity | int | High-intensity motion count |

---

### 0x53 - WEAR_EVENT

**Source:** `com.ouraring.ringeventparser.message.WearEvent`
**Category:** System
**Priority:** High
**Frequency:** On wear state change

#### Protobuf Fields

| Field | Name | Type | Description |
|-------|------|------|-------------|
| 1 | timestamp | long | Unix timestamp (ms) |
| 2 | state | int | Wear state (enum: ON_FINGER, OFF_FINGER, etc.) |
| 3 | text | String | Optional text description |

---

### 0x45 - STATE_CHANGE_IND

**Source:** `com.ouraring.ringeventparser.message.StateChangeIndValue`
**Category:** System
**Priority:** Medium
**Frequency:** On state change

#### Protobuf Fields

| Field | Name | Type | Description |
|-------|------|------|-------------|
| 1 | timestamp | long | Unix timestamp (ms) |
| 2 | state | StateChange | Ring state enum |
| 3 | text | String | State description |

---

### 0x4E - SLEEP_PHASE_DETAILS

**Source:** `com.ouraring.ringeventparser.SleepPhaseDetailsKt`
**Category:** Sleep
**Priority:** High
**Frequency:** Per sleep session

#### Protobuf Fields

| Field | Name | Type | Description |
|-------|------|------|-------------|
| 1 | timestamp | repeated long | Timestamps (ms) |
| 2 | startTime | repeated int | Phase start times (offset) |
| 3 | sleepPhases | repeated SleepPhase_OSSAv1 | Sleep phase classifications |

---

### 0x41 - RING_START_IND

**Category:** System
**Priority:** High
**Frequency:** On boot/restart

#### Protobuf Fields

| Field | Name | Type | Description |
|-------|------|------|-------------|
| 1 | firmwareVersion | string | Firmware version string |
| 2 | bootloaderVersion | string | Bootloader version |
| 3 | resetReason | uint32 | Reason for restart |
| 4 | uptimeSeconds | uint32 | Previous uptime |
| 5 | batteryLevel | uint32 | Battery level (%) |
| 6 | hardwareRevision | string | Hardware revision |
| 7 | serialNumber | bytes | Device serial number |
| 8-15 | (various) | - | System diagnostic data |

---

### 0x73 - EHR_TRACE_EVENT

**Category:** Heart Rate
**Priority:** Medium
**Frequency:** During detailed HR monitoring

#### Protobuf Fields

| Field | Name | Type | Description |
|-------|------|------|-------------|
| 1 | timestamp | uint32 | Start timestamp |
| 2 | duration | uint32 | Trace duration (seconds) |
| 3 | sampleRate | uint32 | Sampling rate (Hz) |
| 4 | traceData | bytes | Raw trace data |
| 5 | minHr | uint32 | Minimum HR in trace |
| 6 | maxHr | uint32 | Maximum HR in trace |
| 7 | avgHr | uint32 | Average HR in trace |
| 8 | frequency | uint32 | Dominant frequency |
| 9 | power | uint32 | Signal power |

---

## Binary Format Reference

Some events use custom binary formats instead of protobuf encoding.

### 0x6A - SLEEP_PERIOD_INFO_2 (Binary Format)

**16 bytes total** - Custom binary format (NOT protobuf)

```
Offset  Size  Field              Scaling
------  ----  -----              -------
0       1     Event ID (0x6A)    -
1       1     Length (0x0E = 14) -
2-5     4     Ring timestamp     deciseconds since boot (LE)
6       1     avgHr              * 0.5 (BPM)
7       1     hrTrend            * 0.0625
8       1     mzci               * 0.0625 (HRV metric)
9       1     dzci               * 0.0625 (HRV metric)
10-11   2     (reserved)         -
12      1     motionCount        0-120 seconds
13      1     sleepState         0=awake, 1=light, 2=deep/REM
14-15   2     cv                 / 65536.0 (PPG quality)
```

---

### 0x46 - TEMP_EVENT (Binary Format)

**13 bytes total** - Custom binary format

```
Offset  Size  Field              Scaling
------  ----  -----              -------
0       1     Event ID (0x46)    -
1       1     Length             -
2       1     Format marker      0x0A
3-4     2     Timestamp/counter  uint16 LE
5-6     2     (reserved)         -
7-8     2     Temp sensor 1      / 100.0 (C)
9-10    2     Reference temp     / 100.0 (~32C)
11-12   2     Temp sensor 2      / 100.0 (C)
```

---

### 0x72 - SLEEP_ACM_PERIOD (Binary Format)

**18 bytes total**

```
Offset  Size  Field              Description
------  ----  -----              -----------
0       1     tag                0x72
1       1     len                16
2-5     4     timestamp          deciseconds LE
6-7     2     activity metric 1  Movement intensity
8-9     2     activity metric 2  Movement intensity
...
```

---

### 0x75 - SLEEP_TEMP_EVENT (Binary Format)

**20 bytes total**

```
Offset  Size  Field              Description
------  ----  -----              -----------
0       1     tag                0x75
1       1     len                18
2-5     4     timestamp          deciseconds LE
6-7     2     temp1              ~35C (body)
8-9     2     temp2              ~35C
...                              (7 temperature sensors total)
```

---

### 0x5D - HRV_EVENT (Binary Format)

**18 bytes total**

```
Offset  Size  Field              Description
------  ----  -----              -----------
0       1     tag                0x5d
1       1     len                16
2-5     4     timestamp          deciseconds LE
6-7     2     HRV metric 1       RMSSD-related
8-9     2     HRV metric 2
...                              (up to 6 values)
```

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

### Event Retrieval Command

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

## Live Verification Data

Data captured from actual Oura Ring Gen 3 device (2026-01-11 to 2026-01-12).

### Initial Capture (184 events)

| Event Type | Count | Status | Sample Values |
|------------|-------|--------|---------------|
| 0x41 RING_START_IND | 1 | Verified | Boot timestamp |
| 0x45 STATE_CHANGE_IND | 14 | Verified | "chg. stopped", "hr enable" |
| 0x46 TEMP_EVENT | 36 | Verified | 30.05C, 31.00C, 25.71C |
| 0x47 MOTION_EVENT | 32 | Verified | Accelerometer data |
| 0x50 ACTIVITY_INFO | 2 | Verified | 87 steps |
| 0x53 WEAR_EVENT | 1 | Verified | State=3 (on finger) |
| 0x5b BLE_CONNECTION_IND | 8 | Verified | Connection params |
| 0x69 TEMP_PERIOD | 1 | Verified | 30.08C avg |
| 0x6c FEATURE_SESSION | 9 | Verified | Session type/state |
| 0x6d MEAS_QUALITY_EVENT | 23 | Verified | Quality metrics |
| 0x80 GREEN_IBI_QUALITY_EVENT | 55 | Verified | ~107 BPM avg |
| 0x82 SCAN_START | 1 | Verified | Scan config |
| 0x83 SCAN_END | 1 | Verified | Scan results |

### Overnight Sleep Capture (4794 events, 9 hours)

| Event Type | Count | Status | Sample Values |
|------------|-------|--------|---------------|
| 0x60 IBI_AND_AMPLITUDE_EVENT | 2774 | Verified | Raw IBI + PPG amplitude |
| 0x72 SLEEP_ACM_PERIOD | 553 | Verified | Sleep activity/motion |
| 0x6a SLEEP_PERIOD_INFO_2 | 549 | Verified | HR, sleep state, breath |
| 0x46 TEMP_EVENT | 314 | Verified | Body/ambient temps |
| 0x80 GREEN_IBI_QUALITY_EVENT | 228 | Verified | Green LED IBI quality |
| 0x45 STATE_CHANGE_IND | 84 | Verified | State transitions |
| 0x47 MOTION_EVENT | 77 | Verified | Movement detection |
| 0x75 SLEEP_TEMP_EVENT | 69 | Verified | 7 temp sensors (~35C) |
| 0x6d MEAS_QUALITY_EVENT | 38 | Verified | Measurement quality |
| 0x83 SCAN_END | 25 | Verified | PPG scan results |
| 0x50 ACTIVITY_INFO | 17 | Verified | Steps/activity |
| 0x5b BLE_CONNECTION_IND | 13 | Verified | BLE events |
| 0x82 SCAN_START | 13 | Verified | PPG scan start |
| 0x6c FEATURE_SESSION | 11 | Verified | Session lifecycle |
| 0x6b MOTION_PERIOD | 11 | Verified | Motion summaries |
| 0x5d HRV_EVENT | 8 | Verified | RMSSD/SDNN |
| 0x69 TEMP_PERIOD | 6 | Verified | Temp summaries |
| 0x41 RING_START_IND | 2 | Verified | Boot events |
| 0x53 WEAR_EVENT | 1 | Verified | On-finger detection |
| 0x5c USER_INFO | 1 | Verified | User config |

### Sleep Analysis (0x6a SLEEP_PERIOD_INFO_2)

**Summary (387 unique samples over 9.01 hours):**
- **Heart Rate:** 51.5 - 70.0 BPM (avg: 59.0 BPM)
- **Sleep States:** 22.6% awake, 77.4% light
- **Motion Count:** 0-29 seconds (avg: 1.5)

**Sleep State Distribution:**
```
State 0 (awake): 124 samples (22.6%)
State 1 (light): 425 samples (77.4%)
State 2 (deep):  0 samples (0%)
```

### Real-time Heartbeat Monitoring

**IBI Streaming Protocol:**
- IBI streaming works correctly
- Sample: 66.2 BPM (IBI: 907ms), 65.6 BPM (IBI: 914ms)
- Data format: `[8:9]` = IBI in milliseconds (little-endian uint16)

---

## Implementation Notes

1. **Ring factory reset clears stored events**
2. **Sleep data (0x6A) requires overnight wear**
3. **Events consumed when read** (single-read buffer)
4. **Timestamps are deciseconds** (divide by 10 for seconds)
5. **Export immediately after data fetch** - events cleared on re-fetch
6. **Field Types:** Most fields use varint encoding for efficiency
7. **Temperature:** Stored as C x 100 (divide by 100 for actual temp)
8. **Percentages:** Usually 0-100 integer values
9. **Flags:** Bit fields, exact meanings TBD for most events

---

## Native Library Interface

### libringeventparser.so (3.2 MB)

**JNI Entry Points:**
```cpp
// Constructor
RingEventParser::RingEventParser()
Mangled: _ZN15RingEventParserC1Ev

// Main parsing function
void* RingEventParser::parse_events(
    const unsigned char* data,
    unsigned int len,
    unsigned int* events_received
)
Mangled: _ZN15RingEventParser12parse_eventsEPKhjPj

// Sleep period parser
void EventParser::parse_api_sleep_period_info(const Event& event)
Mangled: _ZN11EventParser27parse_api_sleep_period_infoERK5Event
```

**Kotlin Wrapper:** `RingEventParserObj.kt`
```kotlin
external fun nativeParseEvents(
    ringEvents: ByteArray,
    ringTime: Int,
    utcTime: Long,
    jzLogMode: Boolean
): Ringeventparser.RingData
```

---

## Source Files Reference

| Data Model | Source File |
|------------|-------------|
| RingEventType | `ringeventparser/data/RingEventType.java` |
| SleepPeriodInfoValue | `ringeventparser/message/SleepPeriodInfoValue.java` |
| ActivityInfoEvent | `ringeventparser/message/ActivityInfoEvent.java` |
| HrvEvent | `ringeventparser/HrvEventKt.java` |
| TempEvent | `ringeventparser/TempEventKt.java` |
| IbiAndAmplitudeEvent | `ringeventparser/IbiAndAmplitudeEventKt.java` |
| MotionEvent | `ringeventparser/message/MotionEvent.java` |
| WearEvent | `ringeventparser/message/WearEvent.java` |
| Spo2Event | `ringeventparser/message/Spo2Event.java` |
| StateChangeIndValue | `ringeventparser/message/StateChangeIndValue.java` |
| SleepPhaseDetails | `ringeventparser/SleepPhaseDetailsKt.java` |

All paths relative to: `_large_files/decompiled/sources/com/ouraring/`

---

## References

- Oura App (decompiled): `com.ouraring.ringeventparser.Ringeventparser.java`
- Protobuf Specification: https://protobuf.dev/programming-guides/encoding/
- Ring Event Type Enum: `com.ouraring.ringeventparser.data.RingEventType.java`

---

*Merged from: protocolknowledge.md + event_data_definition.md*
