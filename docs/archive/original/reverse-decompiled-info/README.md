# Oura Ring Reverse Engineering Documentation

Comprehensive technical documentation of the Oura Ring app internals, extracted from decompiled APK.

---

## Quick Navigation

| Document | What You'll Find |
|----------|------------------|
| [EVENT_TYPES.md](EVENT_TYPES.md) | 63 BLE event types (0x41-0x83) |
| [BLE_COMMANDS.md](BLE_COMMANDS.md) | Ring operations protocol |
| [NATIVE_LIBRARIES.md](NATIVE_LIBRARIES.md) | .so files & JNI interface |
| [DATA_STRUCTURES.md](DATA_STRUCTURES.md) | Score structures & contributors |
| [ML_MODELS.md](ML_MODELS.md) | 27 PyTorch models |
| [DATA_FLOW_DETAILED.md](DATA_FLOW_DETAILED.md) | BLE → JNI → UI trace |

---

## Architecture Overview

```
┌──────────────────────────────────────────────────────────────┐
│                        OURA RING                             │
│   Sensors: PPG (3-LED), Accelerometer, Temperature           │
└───────────────────────────┬──────────────────────────────────┘
                            │ BLE (Nordic Semiconductor)
                            ▼
┌──────────────────────────────────────────────────────────────┐
│                    Android App                               │
│  ┌────────────┐  ┌────────────┐  ┌────────────────────┐     │
│  │  ourakit   │  │ ringevent  │  │   ecorelibrary     │     │
│  │  (BLE)     │→ │  parser    │→ │   (JNI scores)     │     │
│  └────────────┘  └────────────┘  └────────────────────┘     │
│        ▲                              ▼                      │
│  ┌────────────┐              ┌────────────────────┐         │
│  │  Realm DB  │←─────────────│   PyTorch Models   │         │
│  └────────────┘              └────────────────────┘         │
│        ▼                                                     │
│  ┌────────────────────────────────────────────────┐         │
│  │            Compose UI (ViewModels)             │         │
│  └────────────────────────────────────────────────┘         │
└──────────────────────────────────────────────────────────────┘
```

---

## Key Packages

| Package | Purpose | Key Files |
|---------|---------|-----------|
| `com.ouraring.ourakit` | BLE communication | `operations/*.java`, `RxBleOuraRing.java` |
| `com.ouraring.ringeventparser` | Event parsing | `RingEventParserObj.java`, `RingEventType.java` |
| `com.ouraring.ecorelibrary` | Native algorithms | `EcoreWrapper.java`, `info/*.java` |
| `com.ouraring.pytorch` | ML models | `PytorchModelFactory.java`, `PyTorchModelType.java` |
| `com.ouraring.oura.nssa` | NSSA sleep analysis | `NssaManager.java`, `SleepHandler.java` |
| `com.ouraring.core.realm` | Database | `model/*.java`, `nexus/*.java` |

---

## Native Libraries

| Library | Size | Purpose |
|---------|------|---------|
| `libtorch_cpu.so` | 70 MB | PyTorch runtime |
| `libnexusengine.so` | 16.5 MB | NSSA sleep analysis |
| `librealm-jni.so` | 8.5 MB | Realm database |
| `libalgos.so` | 5.7 MB | Additional algorithms |
| `libringeventparser.so` | 3.3 MB | Event parsing |
| `libappecore.so` | 2.1 MB | Score calculations |
| `libsecrets.so` | 8.7 KB | Model encryption keys |

See [NATIVE_LIBRARIES.md](NATIVE_LIBRARIES.md) for JNI method details.

---

## The 3 Core Scores

### Sleep Score (0-100)

**7 Contributors:**
| Contributor | Field | Weight |
|-------------|-------|--------|
| Total Sleep | `totalSleepScore` | Duration vs 7-9h target |
| Deep Sleep | `deepSleepScore` | ~15-20% of total |
| REM Sleep | `remSleepScore` | ~20-25% of total |
| Efficiency | `sleepEfficiency` | Time asleep / time in bed |
| Latency | `sleepLatency` | Time to fall asleep |
| Disturbances | `sleepDisturbances` | Wake-up count |
| Timing | `circadianAlignment` | Consistency with baseline |

**Source:** `SleepSummary4` in [DATA_STRUCTURES.md](DATA_STRUCTURES.md)

### Readiness Score (0-100)

**8+ Contributors:**
| Contributor | Field | Source |
|-------------|-------|--------|
| Activity Balance | `activityBalance` | 7-day activity load |
| Last Day Activity | `lastDayActivity` | Previous day exertion |
| Last Night Sleep | `lastNightSleep` | Sleep score |
| Resting HR | `restingHr` | RHR vs baseline |
| RHR Time | `restingHrTime` | Timing of lowest HR |
| Sleep Balance | `sleepBalance` | Sleep debt status |
| Temperature | `temperature` | Temp vs baseline |
| HRV Balance | `hrvBalance` | HRV vs baseline (optional) |

**Source:** `ReadinessScoreOutput` in [DATA_STRUCTURES.md](DATA_STRUCTURES.md)

### Activity Score (0-100)

**6 Contributors:**
| Contributor | Field | Source |
|-------------|-------|--------|
| Meet Daily Goals | `sevenDayTargetScore` | Target completion |
| Stay Active | `twentyFourHourInactiveTimeScore` | Active minutes |
| Move Every Hour | `twentyFourHourInactiveAlertScore` | Hourly movement |
| Training Frequency | `sevenDayExerciseFrequencyScore` | Exercise days |
| Training Volume | `sevenDayExerciseAmountScore` | Intensity |
| Recovery Time | `sevenDayRestScore` | Rest days |

**Source:** `ActInfo` in [DATA_STRUCTURES.md](DATA_STRUCTURES.md)

---

## ML Model Categories

| Category | Models | Purpose |
|----------|--------|---------|
| **Sleep** | SLEEPNET, SLEEPNET_MOONSTONE, SLEEPNET_BDI | Sleep staging, breathing |
| **Heart** | CVA, CVA2, WHR, AWHR, DHRV | Cardiovascular analysis |
| **Stress** | STRESS_RESILIENCE, DAYTIME_STRESS, CUMULATIVE | Stress tracking |
| **Activity** | STEP_COUNTER, AUTOMATIC_ACTIVITY | Movement detection |
| **Health** | ILLNESS_DETECTION, HALITE | Symptom detection |

All models encrypted with AES-GCM. See [ML_MODELS.md](ML_MODELS.md).

---

## BLE Protocol Quick Reference

### Common Tags

| Tag | Hex | Operation |
|-----|-----|-----------|
| 47 | 0x2F | Authentication |
| 44 | 0x2C | GetEvent |
| 33 | 0x21 | SyncTime |
| 32 | 0x20 | GetBatteryLevel |
| 53 | 0x35 | SetRealtimeMeasurements |
| 55 | 0x37 | GetCapabilities |

### Extended Tags (Auth)

| Tag | Purpose |
|-----|---------|
| 0x2B | GetAuthNonce |
| 0x2C | Authenticate |
| 0x2D | SetAuthKey |
| 0x2E | GetAuthKeyCount |

See [BLE_COMMANDS.md](BLE_COMMANDS.md) for complete protocol.

---

## Event Type Categories

| Range | Category | Count | Examples |
|-------|----------|-------|----------|
| 0x41-0x48 | System | 8 | Ring start, time sync, alerts |
| 0x44, 0x60, 0x5B | PPG/Heart | 3 | IBI, amplitude, green LED |
| 0x4F-0x53, 0x5A | Sleep | 6 | Period info, summaries, phases |
| 0x46, 0x61, 0x75 | Temperature | 3 | Events, periods, sleep temp |
| 0x45, 0x62, 0x64 | Motion | 3 | Events, periods, sleep ACM |
| 0x6F-0x77 | SpO2 | 6 | Events, drops, combos |

See [EVENT_TYPES.md](EVENT_TYPES.md) for all 63 types.

---

## Data Flow Summary

```
1. BLE Notification      →  RxAndroidBleOuraRing
2. Event Parsing         →  RingEventParserObj.nativeParseEvents()
3. Database Storage      →  Realm (DbSleep, DbReadiness, etc.)
4. Score Calculation     →  EcoreWrapper / NssaManager
5. ML Processing         →  SleepNetPytorchModel, etc.
6. UI Display            →  ViewModel → Compose
```

See [DATA_FLOW_DETAILED.md](DATA_FLOW_DETAILED.md) for complete trace.

---

## Open Questions

### Unknown Systems
- **NSSA**: Alternative to SleepNet in `libnexusengine.so` - when is each used?
- **POPSICLE model**: Purpose unknown (1.2 MB model)
- **Feature Sessions (0x6C event)**: Session management mechanism

### Protocol Questions
- Difference between `API_IBI_EVENT` (0x44) vs `API_IBI_AND_AMPLITUDE_EVENT` (0x60)?
- Complete FeatureCapabilityId value list?
- DFU (firmware update) detailed protocol?

### Algorithm Questions
- Temperature baseline calculation method?
- CVA model input format (PPG waveform specifics)?
- Sleep period detection trigger on ring firmware?

---

## File Structure

```
docs/reverse_decompiled_info/
├── README.md                 # This file
├── EVENT_TYPES.md            # 63 BLE event types
├── BLE_COMMANDS.md           # Ring operations protocol
├── NATIVE_LIBRARIES.md       # .so files & JNI
├── DATA_STRUCTURES.md        # Score structures
├── ML_MODELS.md              # 27 PyTorch models
└── DATA_FLOW_DETAILED.md     # Complete data flow

_large_files/
├── decompiled/sources/com/ouraring/
│   ├── ourakit/              # BLE layer
│   ├── ringeventparser/      # Event parsing
│   ├── ecorelibrary/         # Native interface
│   ├── pytorch/              # ML models
│   └── oura/                 # App features
├── native/lib/arm64-v8a/     # Native libraries
└── models/assets/            # Encrypted models
```

---

## Data Scaling Conventions

| Pattern | Scaling | Example |
|---------|---------|---------|
| `*TimesEight` | ÷ 8 | `breathAverageTimesEight / 8` = BPM |
| `*Times32` | ÷ 32 | `metTimes32 / 32` = MET value |
| `*Centidegrees` | ÷ 100 | `3700` = 37.00°C |
| `*Seconds` | seconds | Direct value |
| `*Millis` | milliseconds | Unix timestamp |

---

## Useful Searches

Find specific functionality:

```bash
# Find score calculation
grep -r "nativeCalculate" decompiled/

# Find ML model usage
grep -r "PytorchModel" decompiled/

# Find event types
grep -r "API_.*_EVENT" decompiled/

# Find BLE operations
ls decompiled/sources/com/ouraring/ourakit/operations/

# Find database models
ls decompiled/sources/com/ouraring/core/realm/model/
```

---

## Related Resources

- Research plan: [RESEARCH_PLAN_FOR_RE_GUIDE.md](../RESEARCH_PLAN_FOR_RE_GUIDE.md)
- Package from: Oura Ring Android APK (decompiled with jadx)
- Native analysis: `nm -D lib*.so` for symbol extraction

---

*Documentation generated through systematic analysis of decompiled Oura Ring application.*
