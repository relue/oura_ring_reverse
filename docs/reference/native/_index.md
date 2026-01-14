# Native Libraries Reference

Documentation for Oura Ring's native libraries and JNI bindings.

---

## Library Overview

| Library | Size | Purpose |
|---------|------|---------|
| `libtorch_cpu.so` | 70 MB | PyTorch runtime for ML models |
| `libnexusengine.so` | 16.5 MB | NSSA sleep analysis system |
| `librealm-jni.so` | 8.5 MB | Realm database JNI |
| `libalgos.so` | 5.7 MB | Additional algorithms |
| `libringeventparser.so` | 3.3 MB | Protobuf event parsing |
| `libappecore.so` | 2.1 MB | Core score algorithms |
| `libc++_shared.so` | 1.3 MB | C++ runtime |
| `libecore.so` | 1.1 MB | Core native + cJSON |
| `libsecrets.so` | 8.7 KB | ML model encryption keys |

**Location:** `_large_files/native/lib/arm64-v8a/`

---

## Quick Navigation

| Topic | Doc | Description |
|-------|-----|-------------|
| EcoreWrapper | [ecore.md](ecore.md) | 68+ JNI methods for score calculations |
| Event Parser | [parser.md](parser.md) | libringeventparser.so protobuf parsing |
| Model Decryption | [secrets.md](secrets.md) | libsecrets.so key retrieval |

---

## Processing Pipeline

```
Ring Events (BLE)
       │
       ▼
libringeventparser.so
  ├─ nativeParseEvents()
  └─ rep_process_chunk()
       │
       ▼
EcoreWrapper (Java)
  ├─ nativeProcessEvents()
  ├─ nativeIbiCorrection()  ──→ Raw IBI → Corrected IBI
  └─ nativePostProcessEvents()
       │
       ▼
Score Calculations
  ├─ nativeCalculateSleepScore()
  ├─ nativeCalculateReadinessScore()
  ├─ nativeCalculateActivityScore()
  └─ nativeCalculateBaseline()
       │
       ▼
libappecore.so
  └─ calculate_sleep_score_numerical()
       │
       ▼
Output Structures
  ├─ SleepInfo
  ├─ ReadinessScoreOutput
  ├─ ActInfo
  └─ Baseline
```

---

## libnexusengine.so - NSSA Sleep Analysis

Alternative sleep analysis system (16.5 MB). Uses SQLite internally.

### Namespace: `nexus::assa`

**Sleep Data Classes:**

| Class | Purpose |
|-------|---------|
| `Sleep` | Main sleep record |
| `DailySleep` | Daily aggregation |
| `SleepFeature` | Sleep features |
| `RingSleepPeriodInfo` | Period metadata |
| `RingSleepSummary1/2/3` | Summary levels |
| `RingSleepTemp` | Sleep temperature |
| `RingSleepAcmPeriod` | ACM period data |
| `UserSleepSettings` | User preferences |
| `RingDebugDataSleepStatistics` | Debug stats |

**Storage:** Uses `TableStore` with select/upsert/delete operations.

**Note:** NSSA appears to be Oura's next-gen sleep analysis, possibly replacing/supplementing SleepNet ML models.

---

## libappecore.so - Core Algorithms

Main algorithm library for score calculations.

### Key Functions

| Symbol | Purpose |
|--------|---------|
| `calculate_sleep_score_numerical` | Sleep score calculation |
| `actinfo_get_activity_target` | Activity target |
| `actinfo_target_to_cal` | Target to calories |
| `actinfo_target_to_steps` | Target to steps |
| `actinfo_resolve_readiness_percent` | Readiness % |
| `activity_score_get_avoid_sitting` | Sitting avoidance |
| `bedtime_merge_periods` | Merge sleep periods |
| `bpm_from_ibi` | BPM from IBI |
| `bpm_init` | BPM initialization |

**Also includes:** cJSON library for JSON parsing.

---

## libalgos.so - Additional Algorithms

5.7 MB library with additional algorithmic functionality.

---

## Source References

**Native Libraries:**
```
_large_files/native/lib/arm64-v8a/
├── libtorch_cpu.so       (70 MB)
├── libnexusengine.so     (16.5 MB)
├── librealm-jni.so       (8.5 MB)
├── libalgos.so           (5.7 MB)
├── libringeventparser.so (3.3 MB)
├── libappecore.so        (2.1 MB)
├── libc++_shared.so      (1.3 MB)
├── libecore.so           (1.1 MB)
└── libsecrets.so         (8.7 KB)
```

**Java Wrappers:**
```
_large_files/decompiled/sources/com/ouraring/
├── ecorelibrary/
│   ├── EcoreWrapper.java
│   ├── baseline/Baseline.java
│   ├── readiness/ReadinessScoreOutput.java
│   ├── info/SleepInfo.java
│   └── info/ActInfo.java
├── ringeventparser/
│   └── RingEventParserObj.java
└── core/utils/
    └── Secrets.java
```

---

## Open Questions

- **NSSA vs SleepNet:** How do libnexusengine.so (NSSA) and PyTorch SleepNet models interact?
- **IBI Correction Algorithm:** What does the correction pipeline do internally?
- **Baseline Rolling Window:** How long is the window for each baseline type?
- **MET Scaling:** Exact thresholds for activity classification

---

## See Also

- [Events Reference](../events/_index.md) - Event types parsed by libringeventparser
- [ML Models](../ml/_index.md) - PyTorch models using libtorch_cpu
- [Data Structures](../structures/_index.md) - Output data structures
