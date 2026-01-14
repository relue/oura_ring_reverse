# Heart & PPG Events

Inter-beat interval (IBI), heart rate variability (HRV), and PPG amplitude events.

---

## Event Summary

| Tag | Hex | Event Name | Priority | Description |
|-----|-----|------------|----------|-------------|
| 68 | 0x44 | API_IBI_EVENT | Medium | Legacy inter-beat interval |
| 91 | 0x5B | API_GREEN_IBI_AMP_EVENT | High | Green LED IBI + amplitude |
| 93 | 0x5D | API_HRV_EVENT | High | Heart rate variability metrics |
| 95 | 0x5F | API_GREEN_IBI_QUALITY_EVENT | Medium | Green LED IBI quality |
| 96 | 0x60 | API_IBI_AND_AMPLITUDE_EVENT | High | Primary IBI + PPG amplitude |
| 104 | 0x68 | API_EHR_TRACE_EVENT | Medium | Exercise HR trace |
| 116 | 0x74 | API_PPG_AMPLITUDE_IND | Low | PPG signal amplitude |
| 118 | 0x76 | API_PPG_PEAK_EVENT | Low | PPG peak detection |
| 130 | 0x82 | API_IBI_GAP_EVENT | Low | IBI data gaps |

---

## 0x60 - API_IBI_AND_AMPLITUDE_EVENT (Primary)

**Source:** `com.ouraring.ringeventparser.IbiAndAmplitudeEventKt`
**File:** `IbiAndAmplitudeEvent.java:7-15`
**Priority:** High - Primary event for HRV calculation

### Protobuf Fields

| Field | Name | Type | Description |
|-------|------|------|-------------|
| 1 | timestamp | repeated long | Ring milliseconds |
| 2 | ibi | repeated int | Inter-beat interval (ms) |
| 3 | amp | repeated int | PPG amplitude (raw units) |

### Usage

Primary event for HRV calculation. IBI (inter-beat interval) is the time between heartbeats. Amplitude indicates signal quality - higher amplitude means better skin contact.

```kotlin
// Access pattern (all fields are List<>)
val ts = event.timestamp[0]
val ibiValue = event.ibi[0]
val amplitude = event.amp[0]
```

### Live Capture Data (Verified)

**Overnight capture:** 2774 events over 9 hours
- IBI streaming works correctly
- Sample: 66.2 BPM (IBI: 907ms), 65.6 BPM (IBI: 914ms)
- Data format: bytes [8:9] = IBI in milliseconds (little-endian uint16)

---

## 0x44 - API_IBI_EVENT (Legacy)

**Source:** `com.ouraring.ringeventparser.IbiEventKt`
**Priority:** Medium - Older event type

### Protobuf Fields

| Field | Name | Type | Description |
|-------|------|------|-------------|
| 1 | timestamp | repeated long | Ring milliseconds |
| 2 | ibi | repeated int | Inter-beat interval (ms) |

**Note:** API_IBI_AND_AMPLITUDE_EVENT (0x60) is preferred as it includes amplitude for quality assessment.

---

## 0x5D - API_HRV_EVENT

**Source:** `com.ouraring.ringeventparser.HrvEventKt`
**File:** `HrvValue.java:5-7`
**Priority:** High - Heart rate variability metrics

### Protobuf Fields

| Field | Name | Type | Description |
|-------|------|------|-------------|
| 1 | timestamp | repeated long | Timestamps (ms) |
| 2 | averageHr5Min | repeated int | Average HR over 5-min window (BPM) |
| 3 | averageRmssd5Min | repeated int | Average RMSSD over 5-min window (ms) |
| 4 | pnn50 | uint32 | pNN50 percentage |
| 5 | lfHf | uint32 | LF/HF ratio (x1000) |
| 6 | samples | uint32 | Number of RR intervals |
| 7 | quality | uint32 | Quality metric |

### Binary Format (18 bytes total)

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

### Live Capture Data

8 events captured during overnight sleep session.

---

## 0x5B - API_GREEN_IBI_AMP_EVENT

**Source:** `com.ouraring.ringeventparser.GreenIbiAndAmpEventKt`
**Priority:** High - Green LED measurements

### Protobuf Fields

| Field | Name | Type | Description |
|-------|------|------|-------------|
| 1 | timestamp | repeated long | Ring milliseconds |
| 2 | ibi | repeated int | Inter-beat interval (ms) |
| 3 | amp | repeated int | PPG amplitude from green LED |

### Usage

Green LED provides better accuracy during motion/exercise compared to IR. Used for workout HR and daytime measurements.

---

## 0x5F - API_GREEN_IBI_QUALITY_EVENT

**Priority:** Medium - Quality metrics for green LED

### Live Capture Data

- 55 events in initial capture
- 228 events in overnight capture
- Average HR: ~107 BPM
- Quality metrics for green LED IBI measurements

---

## 0x68 - API_EHR_TRACE_EVENT

**Category:** Exercise Heart Rate
**Priority:** Medium - Detailed HR monitoring during workouts

### Protobuf Fields

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

## 0x74 - API_PPG_AMPLITUDE_IND

**Priority:** Low - Signal quality indication

PPG signal amplitude for quality assessment. Higher values indicate better skin contact and signal quality.

---

## 0x76 - API_PPG_PEAK_EVENT

**Priority:** Low - Peak detection data

PPG peak detection events for beat-by-beat analysis.

---

## 0x82 - API_IBI_GAP_EVENT

**Priority:** Low - Data gap tracking

Indicates gaps in IBI data collection (e.g., ring removed, poor contact).

---

## IBI Processing Flow

```
1. Ring captures PPG waveform (IR, Green, Red LEDs)
2. Firmware detects peaks → IBI events generated
3. API_IBI_AND_AMPLITUDE_EVENT (0x60) sent via BLE
4. App receives and parses with RingEventParser
5. EcoreWrapper.nativeIbiCorrection() corrects raw IBI
6. Corrected IBI stored with validity scores (0-3)
7. HRV metrics calculated (RMSSD, pNN50, etc.)
```

### IBI Correction (Native)

```java
// EcoreWrapper.java
IbiCorrectionResult nativeIbiCorrection(
    int[] rawIbi,
    int[] amplitude,
    long[] timestamp
)

// Output includes validity scores:
// 0 = invalid
// 1 = uncertain
// 2 = interpolated
// 3 = valid
```

---

## PPG LED Sources

| Value | Name | Description |
|-------|------|-------------|
| 0 | UNKNOWN | Unknown source |
| 1 | IR | Infrared LED (primary, always-on) |
| 2 | GREEN | Green LED (exercise, higher accuracy) |
| 3 | RED | Red LED (SpO2 measurements) |
| 4 | IR_AND_GREEN | IR + Green combined |
| 5 | IR_AND_RED | IR + Red combined |
| 6 | GREEN_AND_RED | Green + Red combined |
| 7 | IR_AND_GREEN_AND_RED | All three LEDs |

**Source:** `HrHrvOutputInfo.Source` enum

---

## Source References

**Decompiled Classes:**
- `com.ouraring.ringeventparser.IbiAndAmplitudeEventKt`
- `com.ouraring.ringeventparser.HrvEventKt`
- `com.ouraring.ringeventparser.GreenIbiAndAmpEventKt`

**Source Files:**
```
_large_files/decompiled/sources/com/ouraring/
├── ringeventparser/
│   ├── IbiAndAmplitudeEventKt.java
│   ├── HrvEventKt.java
│   ├── GreenIbiAndAmpEventKt.java
│   └── message/
│       ├── IbiAndAmplitudeEvent.java
│       └── HrvValue.java
└── ecorelibrary/
    ├── ibi/IbiAndAmplitudeEvent.java
    └── EcoreWrapper.java
```

**Native Methods:**
- `EcoreWrapper.nativeIbiCorrection()` - IBI correction algorithm
- Symbol: `_ZN11EcoreEngine14ibi_correctionEPKiPKiPKliii`

**Related:**
- `ecorelibrary/info/HrHrvOutputInfo.java` - HR/HRV output structures
- `ecorelibrary/ibi/IbiAndAmplitudeEvent.java` - IBI data structures

---

## See Also

- [Sleep Events](sleep.md) - Sleep HR events (0x55, 0x5E)
- [Data Structures](../structures/vitals.md) - HR/HRV output structures
- [Native Libraries](../native/ecore.md) - IBI correction details
