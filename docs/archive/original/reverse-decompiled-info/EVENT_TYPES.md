# Oura Ring Event Types Reference

Complete documentation of all 63 BLE event types from decompiled source.

---

## Quick Reference Table

| Tag | Hex | Event Name | Category |
|-----|-----|------------|----------|
| 65 | 0x41 | API_RING_START_IND | System |
| 66 | 0x42 | API_TIME_SYNC_IND | System |
| 67 | 0x43 | API_ALERT | System |
| 68 | 0x44 | API_IBI_EVENT | PPG/Heart |
| 69 | 0x45 | API_MOTION_EVENT | Motion |
| 70 | 0x46 | API_TEMP_EVENT | Temperature |
| 71 | 0x47 | API_WEAR_EVENT | Wear |
| 72 | 0x48 | API_STATE_CHANGE_IND | System |
| 73 | 0x49 | API_DEBUG_EVENT_IND | Debug |
| 74 | 0x4A | API_DEBUG_DATA | Debug |
| 75 | 0x4B | API_RAW_PPG_EVENT | PPG/Raw |
| 76 | 0x4C | API_RAW_ACM_EVENT | Motion/Raw |
| 77 | 0x4D | API_SELFTEST_EVENT | System |
| 78 | 0x4E | API_SELFTEST_DATA | System |
| 79 | 0x4F | API_SLEEP_PERIOD_INFO | Sleep |
| 80 | 0x50 | API_SLEEP_SUMMARY_1 | Sleep |
| 81 | 0x51 | API_SLEEP_SUMMARY_2 | Sleep |
| 82 | 0x52 | API_SLEEP_SUMMARY_3 | Sleep |
| 83 | 0x53 | API_SLEEP_SUMMARY_4 | Sleep |
| 84 | 0x54 | API_USER_INFO | System |
| 85 | 0x55 | API_TAG_EVENT | User Input |
| 86 | 0x56 | API_BLE_CONNECTION_IND | System |
| 87 | 0x57 | API_ACTIVITY_SUMMARY_1 | Activity |
| 88 | 0x58 | API_ACTIVITY_SUMMARY_2 | Activity |
| 89 | 0x59 | API_RECOVERY_SUMMARY | Recovery |
| 90 | 0x5A | API_SLEEP_PHASE_INFO | Sleep |
| 91 | 0x5B | API_GREEN_IBI_AMP_EVENT | PPG/Green |
| 92 | 0x5C | API_SLEEP_TEMP_EVENT | Sleep/Temp |
| 93 | 0x5D | API_HRV_EVENT | HRV |
| 94 | 0x5E | API_SLEEP_HR_EVENT | Sleep/HR |
| 95 | 0x5F | API_GREEN_IBI_QUALITY_EVENT | PPG/Quality |
| 96 | 0x60 | API_IBI_AND_AMPLITUDE_EVENT | PPG/Heart |
| 97 | 0x61 | API_TEMP_PERIOD_EVENT | Temperature |
| 98 | 0x62 | API_MOTION_PERIOD_EVENT | Motion |
| 99 | 0x63 | API_BEDTIME_PERIOD_EVENT | Sleep |
| 100 | 0x64 | API_SLEEP_ACM_PERIOD_EVENT | Sleep/Motion |
| 101 | 0x65 | API_SLEEP_PHASE_DETAILS | Sleep |
| 102 | 0x66 | API_SLEEP_PHASE_DATA | Sleep |
| 103 | 0x67 | API_ACTIVITY_INFO_EVENT | Activity |
| 104 | 0x68 | API_EHR_TRACE_EVENT | Exercise HR |
| 105 | 0x69 | API_EHR_ACM_INTENSITY_EVENT | Exercise |
| 106 | 0x6A | API_MEAS_QUALITY_EVENT | Quality |
| 107 | 0x6B | API_ON_DEMAND_SESSION_EVENT | On-Demand |
| 108 | 0x6C | API_FEATURE_SESSION_EVENT | Session |
| 109 | 0x6D | API_ON_DEMAND_MEAS_EVENT | On-Demand |
| 110 | 0x6E | API_ON_DEMAND_MOTION_EVENT | On-Demand |
| 111 | 0x6F | API_SPO2_EVENT | SpO2 |
| 112 | 0x70 | API_SPO2_IBI_AND_AMPLITUDE_EVENT | SpO2/IBI |
| 113 | 0x71 | API_SLEEP_PERIOD_INFO_2 | Sleep |
| 114 | 0x72 | API_RING_SLEEP_FEATURE_INFO | Sleep |
| 115 | 0x73 | API_RING_SLEEP_FEATURE_INFO_2 | Sleep |
| 116 | 0x74 | API_PPG_AMPLITUDE_IND | PPG/Quality |
| 117 | 0x75 | API_TEMP_EVENT_2 | Temperature |
| 118 | 0x76 | API_PPG_PEAK_EVENT | PPG |
| 119 | 0x77 | API_SPO2_COMBO_EVENT | SpO2 |
| 120 | 0x78 | API_SPO2_DC_EVENT | SpO2/Raw |
| 121 | 0x79 | API_REAL_STEP_EVENT_FEATURE_1 | Steps |
| 122 | 0x7A | API_REAL_STEP_EVENT_FEATURE_2 | Steps |
| 123 | 0x7B | API_CVA_RAW_PPG_DATA_EVENT | CVA |
| 124 | 0x7C | API_DAYTIME_HR_EVENT | Daytime HR |
| 125 | 0x7D | API_DAYTIME_HR_SESSION_EVENT | Daytime HR |
| 126 | 0x7E | API_WHR_EVENT | Workout HR |
| 127 | 0x7F | API_WHR_SESSION_EVENT | Workout HR |
| 128 | 0x80 | API_SCAN_START | System |
| 129 | 0x81 | API_TIME_SYNC_IND_SKIPPED | System |
| 130 | 0x82 | API_IBI_GAP_EVENT | PPG/Gap |
| 131 | 0x83 | API_SCAN_END | System |

**Source:** `RingEventType.java:8-72`

---

## Event Categories

### Event Groupings (from RawEventTypes.java)

| Group | Events | Purpose |
|-------|--------|---------|
| TIME | Ring start, time sync | Timestamp management |
| TIMESERIES_DATA | IBI, motion, temp, wear | Continuous data streams |
| PPG | Raw PPG, peaks, amplitude | Photoplethysmography data |
| FEATURE_SESSION | Session events (0x6C) | Feature configuration |
| STATELESS_ACTIVITY_EVENTS | Activity summaries | Activity tracking |
| WHR | WHR events, sessions | Workout heart rate |

---

## Core Event Definitions

### IBI & Heart Rate Events

#### API_IBI_AND_AMPLITUDE_EVENT (0x60) - Primary HRV Source

```
Fields:
  timestamp: Long    - Ring milliseconds
  ibi: Int           - Inter-beat interval (ms)
  amp: Int           - PPG amplitude
```

**Usage:** Primary event for HRV calculation. IBI (inter-beat interval) is the time between heartbeats. Amplitude indicates signal quality.

**Source:** `IbiAndAmplitudeEvent.java:7-15`

---

#### API_IBI_EVENT (0x44) - Legacy IBI

```
Fields:
  timestamp: Long    - Ring milliseconds
  ibi: Int           - Inter-beat interval (ms)
```

**Note:** Older event type. API_IBI_AND_AMPLITUDE_EVENT (0x60) is preferred as it includes amplitude for quality assessment.

---

#### API_HRV_EVENT (0x5D)

```
Fields:
  timestamp: Long    - Ring milliseconds
  hrv: Int           - HRV value (RMSSD in ms)
```

**Source:** `HrvValue.java:5-7`

---

### Temperature Events

#### API_TEMP_EVENT (0x46)

```
Fields:
  timestamp: Long
  temp1: Float       - Sensor 1 temperature
  temp2: Float       - Sensor 2 temperature
  temp3: Float       - Sensor 3 temperature
  temp4: Float       - Sensor 4 temperature
  temp5: Float       - Sensor 5 temperature
  temp6: Float       - Sensor 6 temperature
  temp7: Float       - Sensor 7 temperature
```

**Note:** Ring has 7 temperature sensors for accurate skin temperature measurement.

**Source:** `TempValue.java:5-13`

---

#### API_SLEEP_TEMP_EVENT (0x5C)

```
Fields:
  timestamp: Long
  temp1-temp7: Float - Same 7-sensor array
```

**Usage:** Temperature data specifically during detected sleep periods.

---

### Motion Events

#### API_MOTION_EVENT (0x45)

```
Fields:
  timestamp: Long
  orientation: Int      - Ring orientation state
  motionSeconds: Int    - Seconds of motion in period
  averageX: Float       - Average X acceleration
  averageY: Float       - Average Y acceleration
  averageZ: Float       - Average Z acceleration
  regularity: Int       - Motion regularity metric
  lowIntensity: Int     - Low intensity motion count
  highIntensity: Int    - High intensity motion count
```

**Source:** `MotionEvent.java:10-18`

---

#### API_MOTION_PERIOD_EVENT (0x62)

Aggregated motion data for a time period.

---

### Sleep Events

#### API_SLEEP_PERIOD_INFO (0x4F) - Core Sleep Event

```
Fields:
  avgHr: Int                  - Average heart rate (bpm)
  hrTrend: Int                - HR trend direction
  avgIBI: Int                 - Average inter-beat interval (ms)
  stdIBI: Int                 - IBI standard deviation
  avgBreathingRate: Int       - Average breathing rate
  stdBreathingRate: Int       - Breathing rate std dev
  motionCount: Int            - Motion events in period
  sleepState: Int             - Sleep stage (awake/light/deep/REM)
  cvPPGSignalAmplitude: Int   - Coefficient of variation for PPG
```

**Source:** `SleepPeriodInfoValue.java:5-13`

---

#### API_SLEEP_ACM_PERIOD_EVENT (0x64) - Sleep Accelerometer

```
Fields:
  fingerAngleMean: Float   - Mean finger angle
  fingerAngleMax: Float    - Max finger angle
  fingerAngleIrq: Float    - Finger angle interquartile range
  madTrimmedMean: Float    - MAD trimmed mean (motion)
  madTrimmedMax: Float     - MAD trimmed max
  madTrimmedIqr: Float     - MAD interquartile range
```

**Usage:** Finger angle indicates hand position changes during sleep. MAD = Median Absolute Deviation for motion detection.

**Source:** `SleepAcmPeriodValue.java:5-10`

---

#### API_BEDTIME_PERIOD_EVENT (0x63)

```
Fields:
  startTime: Long          - Bedtime period start
  endTime: Long            - Bedtime period end
  avgMadTrimmedMean: Float - Average motion
  avgMadTrimmedMax: Float  - Max motion
  avgMadTrimmedIqr: Float  - Motion variability
```

**Source:** `BedtimePeriodValue.java:5-10`

---

#### Sleep Summary Events (0x50-0x53)

| Tag | Event | Content |
|-----|-------|---------|
| 0x50 | API_SLEEP_SUMMARY_1 | Basic sleep metrics |
| 0x51 | API_SLEEP_SUMMARY_2 | Extended sleep data |
| 0x52 | API_SLEEP_SUMMARY_3 | Sleep phase breakdowns |
| 0x53 | API_SLEEP_SUMMARY_4 | Additional sleep stats |

---

### SpO2 Events

#### API_SPO2_EVENT (0x6F)

```
Fields:
  timestamp: Long
  spo2: Int         - Blood oxygen percentage (0-100)
  quality: Int      - Measurement quality
```

---

#### API_SPO2_COMBO_EVENT (0x77) - Smoothed SpO2

Contains smoothed/processed SpO2 values for better accuracy.

---

#### API_SPO2_IBI_AND_AMPLITUDE_EVENT (0x70)

SpO2 measurement combined with IBI data from red/IR LEDs.

---

### Activity Events

#### API_ACTIVITY_INFO_EVENT (0x67)

```
Fields:
  timestamp: Long
  stepCount: Int      - Steps in period
  metLevel1: Float    - MET category 1 duration
  metLevel2: Float    - MET category 2 duration
  metLevel3: Float    - MET category 3 duration
  metLevel4: Float    - MET category 4 duration
  metLevel5: Float    - MET category 5 duration
  metLevel6: Float    - MET category 6 duration
  metLevel7: Float    - MET category 7 duration
  metLevel8: Float    - MET category 8 duration
  metLevel9: Float    - MET category 9 duration
  metLevel10: Float   - MET category 10 duration
  metLevel11: Float   - MET category 11 duration
  metLevel12: Float   - MET category 12 duration
  metLevel13: Float   - MET category 13 duration
```

**MET Levels:** Metabolic Equivalent of Task - 13 intensity buckets from sedentary (1) to vigorous exercise (13).

**Source:** `ActivityInfoEvent.java:8-22`

---

### Wear Detection

#### API_WEAR_EVENT (0x47)

```
Fields:
  timestamp: Long
  wearState: Int    - 0=not worn, 1=worn
  confidence: Int   - Detection confidence
```

**Source:** `WearEvent.java:7-10`

---

### Feature Session Events

#### API_FEATURE_SESSION_EVENT (0x6C)

Controls feature measurement sessions on the ring.

```
Fields:
  timestamp: Long
  capability: Int                           - Feature capability ID
  status: Int                               - Session status

  # CVA (Cardiovascular Age) Session
  cvaPpgSamplerSessionV1Version: Int
  cvaPpgSamplerSessionV1SampleRateHz: Int
  cvaPpgSamplerSessionV1MeasAveraging: Int

  # Daytime HR Session
  daytimeHrSessionAlgorithmVersion: Int
  daytimeHrSessionV4Meditation: Int

  # Exercise HR Session
  exerciseHrSessionV1Activity: Int
  exerciseHrSessionV1MaxHr: Int
  exerciseHrSessionV1MinHr: Int
  exerciseHrSessionV2AlgorithmVersion: Int

  # Real Steps Session
  realStepsSessionV1Version: Int

  # SpO2 Session
  spo2SessionVersion: Int
  spo2SessionV3HighFrequencyMode: Int

  # Resting HR Session
  restingHrSessionAlgorithmVersion: Int
  restingHrV2HighFrequencyMode: Int
```

**Source:** `FeatureSession.java:7-24`

---

### Step Detection Events

#### API_REAL_STEP_EVENT_FEATURE_1 (0x79)

```
Fields:
  timestamp: Long
  realStepFeature: RealStepsFeatures
    - isHandrail: Int
    - isPocket: Int
    - cadence: Int
    - isLeftRight: Int
    - leftRightConf: Int
    - armSwing: Int
    - motionType: Int
    - handrailSteps: Int
    - fftBins: RealStepsFFTset (24 FFT bin values)
```

**Usage:** FFT-based step detection using frequency analysis of accelerometer data.

---

#### API_REAL_STEP_EVENT_FEATURE_2 (0x7A)

Extended step features with additional motion classification.

---

### CVA Events

#### API_CVA_RAW_PPG_DATA_EVENT (0x7B)

Raw PPG waveform data for Cardiovascular Age calculation.

---

### Workout HR Events

#### API_WHR_EVENT (0x7E)

Workout heart rate measurements during exercise.

---

#### API_WHR_SESSION_EVENT (0x7F)

Workout HR session metadata and configuration.

---

### System Events

#### API_RING_START_IND (0x41)

Ring boot/startup indication.

---

#### API_TIME_SYNC_IND (0x42)

Time synchronization acknowledgment.

```
Fields:
  timestamp: Long      - Ring timestamp at sync
  syncSource: Int      - Sync source identifier
```

---

#### API_TIME_SYNC_IND_SKIPPED (0x81)

Indicates time sync was skipped (e.g., already synced recently).

---

#### API_STATE_CHANGE_IND (0x48)

Ring state transitions.

```
States (from StateChange.java):
  - IDLE
  - MEASURING
  - SLEEPING
  - CHARGING
  - DFU_MODE
```

---

#### API_ALERT (0x43)

Ring alerts/notifications.

```
Fields:
  timestamp: Long
  alertType: Int
  alertData: ByteArray
```

---

### Debug Events

#### API_DEBUG_EVENT_IND (0x49)

Debug event indication.

---

#### API_DEBUG_DATA (0x4A)

Raw debug data payload.

---

### Quality Events

#### API_MEAS_QUALITY_EVENT (0x6A)

Measurement quality indicators.

```
Quality Metrics:
  - CQI: Contact Quality Index
  - PQI: PPG Quality Index
```

---

#### API_GREEN_IBI_QUALITY_EVENT (0x5F)

Quality metrics for green LED IBI measurements.

---

#### API_PPG_AMPLITUDE_IND (0x74)

PPG signal amplitude indication for quality assessment.

---

## Data Format Notes

### Protobuf Structure

All events use Protocol Buffers with Kotlin DSL builders:

```kotlin
// Example field definition (all use List<> wrapper)
val timestamp: List<Long>
val ibi: List<Int>
val amp: List<Int>
```

**Important:** All protobuf fields are wrapped in List<> types, even for single values. Access via index 0:
```kotlin
val ts = event.timestamp[0]
val ibiValue = event.ibi[0]
```

---

### Timestamp Format

- **Ring timestamps:** Milliseconds since ring boot or last time sync
- **Conversion:** Add to sync baseline to get Unix timestamp
- **Byte order:** Little Endian (all multi-byte integers)

---

### Event Tag Range

| Range | Purpose |
|-------|---------|
| 0x41-0x4E | Core system + basic sensors |
| 0x4F-0x56 | Sleep + user events |
| 0x57-0x5F | Activity + green LED |
| 0x60-0x6E | Advanced PPG + sessions |
| 0x6F-0x77 | SpO2 events |
| 0x78-0x7F | Steps + CVA + WHR |
| 0x80-0x83 | System (scan, sync skip, gap) |

---

## Event Flow

### Sleep Data Collection

```
1. Ring detects bedtime → API_BEDTIME_PERIOD_EVENT (0x63)
2. Continuous collection:
   - API_IBI_AND_AMPLITUDE_EVENT (0x60) - every heartbeat
   - API_TEMP_EVENT (0x46) - periodic temperature
   - API_MOTION_EVENT (0x45) - motion detection
3. Sleep period aggregation:
   - API_SLEEP_PERIOD_INFO (0x4F) - periodic summaries
   - API_SLEEP_ACM_PERIOD_EVENT (0x64) - motion summaries
4. Wake detection → API_SLEEP_SUMMARY_1-4 (0x50-0x53)
```

---

### Activity Tracking Flow

```
1. Wear detection → API_WEAR_EVENT (0x47)
2. Step counting:
   - API_REAL_STEP_EVENT_FEATURE_1 (0x79) - FFT features
   - API_ACTIVITY_INFO_EVENT (0x67) - step counts + MET
3. Activity summaries → API_ACTIVITY_SUMMARY_1/2 (0x57/0x58)
```

---

## Data Processing Pipeline

```
Ring Events → Protobuf Parse → Native Processing → Scores

Detailed flow:
1. BLE receives raw bytes
2. RingEventParser decodes protobuf (libringeventparser.so)
3. Events stored in DbRawEvent (Realm database)
4. EcoreWrapper.nativeProcessEvents() (libappecore.so)
   - IBI correction: nativeIbiCorrection()
   - Sleep analysis: nativeCalculateSleepScore()
   - Readiness: nativeCalculateReadinessScore()
5. ML models process features:
   - SleepNet for sleep staging
   - Step counter for validated steps
   - CVA for cardiovascular age
6. Final scores → UI via ViewModels
```

---

## Source Files

All event parsers located at:
```
_large_files/decompiled/sources/com/ouraring/ringeventparser/
```

| File | Event Type |
|------|------------|
| `IbiAndAmplitudeEventKt.java` | API_IBI_AND_AMPLITUDE_EVENT |
| `HrvEventKt.java` | API_HRV_EVENT |
| `TempEventKt.java` | API_TEMP_EVENT |
| `MotionEventKt.java` | API_MOTION_EVENT |
| `WearEventKt.java` | API_WEAR_EVENT |
| `SleepPeriodInfoKt.java` | API_SLEEP_PERIOD_INFO |
| `Spo2EventKt.java` | API_SPO2_EVENT |
| `ActivityInfoEventKt.java` | API_ACTIVITY_INFO_EVENT |
| `FeatureSessionEventKt.java` | API_FEATURE_SESSION_EVENT |
| `GreenIbiAndAmpEventKt.java` | API_GREEN_IBI_AMP_EVENT |
| `data/RingEventType.java` | All 63 event type enums |

---

## Related Files

### Processing Files
| File | Purpose |
|------|---------|
| `ecorelibrary/EcoreWrapper.java` | JNI interface to libappecore.so |
| `ecorelibrary/ibi/IbiAndAmplitudeEvent.java` | IBI data structures |
| `ourakit/operations/GetEvent.java` | BLE event fetching |

### Native Libraries
| Library | Purpose |
|---------|---------|
| `libringeventparser.so` | Protobuf parsing (3.3 MB) |
| `libappecore.so` | Core algorithms (2.1 MB) |
| `libnexusengine.so` | NSSA sleep system (16.5 MB) |

---

## Open Questions

- [ ] Exact MET level thresholds (what activity intensity maps to each level?)
- [ ] Sleep state enum values (awake=0? light=1? deep=2? REM=3?)
- [ ] Temperature sensor placement (which sensor is where on ring?)
- [ ] CVA PPG waveform format (sample rate, duration, encoding)
- [ ] Feature session capability IDs (complete list)
- [ ] Exact field contents for sleep summary events (0x50-0x53)
- [ ] StateChange enum complete values beyond basic states

---

## See Also

- [BLE_COMMANDS.md](BLE_COMMANDS.md) - How to request events from ring
- [DATA_STRUCTURES.md](DATA_STRUCTURES.md) - Processed data structures
- [NATIVE_LIBRARIES.md](NATIVE_LIBRARIES.md) - Event processing in native code
