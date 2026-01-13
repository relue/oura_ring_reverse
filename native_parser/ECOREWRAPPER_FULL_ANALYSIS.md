# EcoreWrapper Full Replication Analysis via QEMU

**Date:** 2026-01-12
**Conclusion:** ✅ **YES - Full replication is FEASIBLE**

---

## Executive Summary

The `libappecore.so` library exports **2,183 functions**, including:
- **66 JNI functions** (`Java_com_ouraring_ecorelibrary_EcoreWrapper_*`)
- **~160 ecore functions** (both `ecore_*` and `ecore_cpp_*` variants)
- **~25 IBI/HR functions** (IBI correction, daytime HR processing)
- **cJSON library** (complete JSON parsing built-in)

**Key Finding:** The library has a **dual API**:
1. **JNI Functions** - Take Java objects (complex to call directly)
2. **C Functions** (`ecore_*`, `ecore_cpp_*`) - Take C types/JSON (EASY to call)

We can bypass JNI entirely and use the C functions directly via QEMU bridges.

---

## Function Categories

### Category 1: IBI Correction ✅ WORKING

```
ibi_correction_init()
ibi_correction_alloc_state(context, callback)
ibi_correction_set_active_state(state)
ibi_correction(ibi, amplitude, timestamp)  // NO state param!
ibi_correction_free_state(state)
ibi_correction_stateless()                 // Alternative API
```

**Status:** Already implemented in `ibi_correction_bridge_v9.c`

---

### Category 2: Score Calculations 🔶 HIGH FEASIBILITY

```
ecore_calculate_sleep_score()
ecore_calculate_readiness_score()
ecore_calculate_activity_score()
ecore_cpp_* variants also available
```

JNI wrappers:
```
nativeCalculateSleepScore
nativeCalculateReadinessScore
nativeCalculateActivityScore
```

**Approach:** Use `ecore_calculate_*_score()` C functions with JSON inputs.

---

### Category 3: Baseline Calculations 🔶 HIGH FEASIBILITY

```
ecore_calculate_baseline()
ecore_get_baseline()
ecore_set_baseline()
ecore_calculate_temperature_baseline()
ecore_get_default_temperature_baseline()
```

**Approach:** JSON-based configuration, callback for outputs.

---

### Category 4: Daytime HR Processing 🔶 HIGH FEASIBILITY

```
daytime_hr_init()
daytime_hr_init_with_state()
daytime_hr_process_event()
daytime_hr_set_handler(callback)
daytime_hr_get_corrected_ibi()
daytime_hr_get_corrected_ibi_count()
daytime_hr_set_averages()
daytime_hr_set_percentiles()
daytime_hr_set_thresholds()
```

**Pattern:** Same as IBI correction - init, set handler, process events.

---

### Category 5: Sleep Processing 🔶 MEDIUM FEASIBILITY

```
ecore_process_events()                    // Main event processor
ecore_merge_sleep_periods()
ecore_set_previous_sleep_periods()
ecore_clear_previous_sleep_periods()
ecore_recalculate_sleep()
ecore_detect_bedtime()                    // Bedtime detection
sleep_period_insert()
sleep_period_allocate_and_insert()
```

**Note:** Requires understanding the event format.

---

### Category 6: Activity Processing 🔶 MEDIUM FEASIBILITY

```
ecore_process_act_event()
ecore_get_act_type()
ecore_get_all_act_types()
ecore_map_google_fit_act_type()
ecore_map_healthkit_act_type()
ecore_set_act_types_config()
ecore_trace_act_event()
ecore_get_actinfo_output()
```

**Note:** Activity classification and tracking.

---

### Category 7: Breathing/SpO2 🔶 HIGH FEASIBILITY

```
ecore_calculate_breathing_rate()
ecore_process_spo2_inputs()
ecore_spo2_get_BDI()                      // Breathing Disturbance Index
ecore_spo2_get_OVI()                      // Oxygen Variability Index
```

---

### Category 8: MET/Calories 🔶 HIGH FEASIBILITY

```
metSetUserInfo()
metToClass()
met320LowerLimitForSedentary()
met320LowerLimitForLight()
met320LowerLimitForModerate()
met320LowerLimitForVigorous()
nativeCalculateCalories()
```

**Note:** Simple numeric inputs/outputs.

---

### Category 9: State Persistence 🔶 MEDIUM FEASIBILITY

```
ecore_serialize_persistent()
ecore_serialize_persistent_v2()
ecore_deserialize_persistent_v2()
ecore_free_serialization()
```

**Use:** Save/restore library state across sessions.

---

### Category 10: Menstrual Cycle 🔶 HIGH FEASIBILITY

```
ecore_calculate_cycle_day()
ecore_get_latest_cycle_day_type()
ecore_init_cycle_prediction()
ecore_get_period_prediction()
```

---

## Library Architecture

```
┌─────────────────────────────────────────────────────────────────────────┐
│                         libappecore.so                                   │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                          │
│  ┌──────────────────┐     ┌──────────────────┐     ┌─────────────────┐ │
│  │   JNI Layer      │     │   C/C++ Core     │     │    cJSON       │ │
│  │ Java_com_oura... │────▶│  ecore_*         │◀───│   (embedded)   │ │
│  │ 66 functions     │     │  ecore_cpp_*     │     │   JSON I/O     │ │
│  └──────────────────┘     │  ~160 functions  │     └─────────────────┘ │
│           │               └──────────────────┘              │          │
│           │                        │                        │          │
│           │               ┌────────┴────────┐               │          │
│           │               │                 │               │          │
│           ▼               ▼                 ▼               ▼          │
│  ┌──────────────────────────────────────────────────────────────────┐  │
│  │                      Internal State                               │  │
│  │  • Sleep periods    • Baselines    • Activity data               │  │
│  │  • HR buffers       • Cycle data   • Persistent state            │  │
│  └──────────────────────────────────────────────────────────────────┘  │
│                                                                          │
│  ┌────────────────┐  ┌────────────────┐  ┌────────────────────────┐   │
│  │ IBI Correction │  │ Daytime HR     │  │ Score Calculations     │   │
│  │ ibi_correction*│  │ daytime_hr_*   │  │ calculate_*_score      │   │
│  └────────────────┘  └────────────────┘  └────────────────────────┘   │
│                                                                          │
└─────────────────────────────────────────────────────────────────────────┘
```

---

## Implementation Strategy

### Phase 1: Core Framework

Create `libappecore_bridge.c` with common infrastructure:

```c
// Core initialization
void* ecore_handle;
int bridge_init() {
    ecore_handle = dlopen("libappecore.so", RTLD_NOW);
    // Call ecore_init() or ecore_cpp_init()
    return ecore_handle ? 0 : -1;
}
```

### Phase 2: Individual Function Wrappers

For each category, create bridges following the IBI correction pattern:

```c
// Example: Daytime HR Bridge
typedef void (*daytime_hr_init_t)(void);
typedef void (*daytime_hr_set_handler_t)(void* callback);
typedef void (*daytime_hr_process_event_t)(uint64_t ts, uint16_t ibi, uint16_t amp);

void hr_callback(void* data) {
    // Receive corrected HR data
}

int process_daytime_hr(const char* input_csv) {
    daytime_hr_init();
    daytime_hr_set_handler(hr_callback);
    // Process events...
}
```

### Phase 3: Python ctypes/cffi Wrapper

Create Python interface for all bridges:

```python
# oura_ecore.py
import ctypes
import subprocess
import json

class EcoreWrapper:
    """Python wrapper for libappecore.so via QEMU bridges"""

    def __init__(self, android_root="/path/to/android_root"):
        self.android_root = android_root

    def correct_ibi(self, ibi_data):
        """Run IBI correction on list of (ts, ibi, amp) tuples"""
        # Use existing run_ibi_correction.sh
        pass

    def calculate_sleep_score(self, sleep_data):
        """Calculate sleep score from processed sleep data"""
        # Call sleep_score_bridge
        pass

    def process_daytime_hr(self, hr_events):
        """Process daytime HR events"""
        # Call daytime_hr_bridge
        pass
```

---

## Challenges and Solutions

### Challenge 1: Complex Data Structures

**Problem:** JNI functions expect Java objects.

**Solution:** Use C functions that accept JSON strings or simple types.
The library includes cJSON for JSON parsing.

### Challenge 2: Global State Management

**Problem:** Library maintains internal state.

**Solution:**
- Call `ecore_init()` at startup
- Use `ecore_serialize_persistent_v2()` / `ecore_deserialize_persistent_v2()` for state persistence
- One bridge process per session

### Challenge 3: Callbacks

**Problem:** Many functions use callbacks to return data asynchronously.

**Solution:** Same pattern as IBI correction:
```c
void* state = alloc_state(NULL, our_callback);
set_handler(our_callback);
// Process data
// Callback receives results
```

### Challenge 4: Understanding Input Formats

**Problem:** Need to know exact parameter formats.

**Solution:**
- Analyze JNI wrappers to see what data they pass
- Use Ghidra disassembly to trace parameter handling
- Trial and error with test data

---

## Function Calling Patterns

### Pattern A: Simple Numeric I/O
```c
// MET classification
int met_class = metToClass(met_value);
float threshold = met320LowerLimitForLight();
```

### Pattern B: Init + Process + Get Results
```c
// Daytime HR
daytime_hr_init();
daytime_hr_set_handler(callback);
for (event in events) {
    daytime_hr_process_event(ts, ibi, amp);
}
int count = daytime_hr_get_corrected_ibi_count();
```

### Pattern C: Stateful with Callbacks
```c
// IBI Correction (already working)
ibi_correction_init();
void* state = ibi_correction_alloc_state(NULL, callback);
ibi_correction_set_active_state(state);
for (sample in samples) {
    ibi_correction(ibi, amp, ts);  // Results via callback
}
```

### Pattern D: JSON Config + JSON Output
```c
// Score calculations (likely)
const char* config_json = "{\"baselines\": {...}, \"data\": {...}}";
char* result_json = ecore_calculate_sleep_score(config_json);
// Parse result_json
cJSON_free(result_json);
```

---

## Priority Implementation Order

| Priority | Function | Bridge Name | Complexity |
|----------|----------|-------------|------------|
| P0 | IBI Correction | ✅ DONE | Low |
| P1 | Daytime HR | daytime_hr_bridge | Medium |
| P1 | Sleep Score | sleep_score_bridge | Medium |
| P1 | Readiness Score | readiness_score_bridge | Medium |
| P1 | Activity Score | activity_score_bridge | Medium |
| P2 | Baselines | baseline_bridge | Low |
| P2 | Temperature | temperature_bridge | Low |
| P2 | Breathing Rate | breathing_bridge | Low |
| P3 | SpO2/BDI | spo2_bridge | Medium |
| P3 | MET/Calories | met_bridge | Low |
| P3 | Cycle Prediction | cycle_bridge | Medium |

---

## Estimated Effort

| Task | Time Estimate |
|------|---------------|
| Daytime HR bridge | 2-4 hours |
| Score calculation bridges (3) | 4-8 hours |
| Baseline bridges | 2-3 hours |
| Python wrapper | 4-6 hours |
| Testing & debugging | 8-12 hours |
| **Total** | **20-33 hours** |

---

## Conclusion

**YES, we can completely replicate EcoreWrapper in Python using libappecore.so via QEMU.**

The key insight is that:
1. JNI functions are wrappers around C functions
2. C functions (`ecore_*`, `ecore_cpp_*`) are directly callable
3. Library uses JSON for complex data (cJSON embedded)
4. Callback pattern for asynchronous results (proven with IBI correction)

**Next Steps:**
1. Create `daytime_hr_bridge.c` following IBI correction pattern
2. Reverse engineer score calculation input formats
3. Build unified Python wrapper (`oura_ecore.py`)
4. Integrate with existing `oura_ring_data.py` and ML models

---

## Appendix: Complete Function List

### JNI Functions (66 total)
```
nativeBedtimeEditLimits
nativeCalculateActivityScore
nativeCalculateBaseline
nativeCalculateBdi
nativeCalculateBreathingRate
nativeCalculateCalories
nativeCalculateCycleDayType
nativeCalculateNightlyTemperature
nativeCalculateReadinessScore
nativeCalculateSleepDebt
nativeCalculateSleepScore
nativeCalculateTemperatureBaseline
nativeCalculateWearPercentage
nativeCheckFeatureSession
nativeClose
nativeDeserializePersistentStateV2
nativeDisableFeature
nativeEnableFeature
nativeGetBaseActivityTarget
nativeGetBaseline
nativeGetBmr
nativeGetDailyOutputs
nativeGetDailyOutputsStateless
nativeGetDefaultTemperatureBaseline
nativeGetEcoreVersion
nativeGetLastRingTime
nativeGetPeriodPrediction
nativeGetSleepPhaseAwakeSymbol
nativeGetSleepPhaseDeepSymbol
nativeGetSleepPhaseLightSymbol
nativeGetSleepPhaseREMSymbol
nativeIbiCorrection
nativeInitialize
nativeInitIbiCorrection
nativeInitRestorativeTime
nativeInitSleepRegularity
nativeIsEnabled
nativeLatestCycleDayType
nativeMetTimes32ToU8
nativeNotifyFactoryResetFinished
nativeParseJzLog
nativePostProcessEvents
nativeProcessActivityEvent
nativeProcessEvents
nativeProcessRestModeEvent
nativeProduceActInfo
nativeRecalculateSleep
nativeSerializePersistentStateV1
nativeSerializePersistentStateV2
nativeSetBaseline
nativeSetFeature
nativeSetPreviousSleepPeriods
nativeSetUserInfo
nativeStatelessCalculateDHR
calculateVo2MaxAnthropometric
calculateVo2MaxUkk6Min
getAvoidSitting
getDoExercise
getRestModeState
getTargetCal
getUserBmr
met320LowerLimitFor*
metSetUserInfo
metToClass
unpackMetLevel
```

### Key C Functions
```
ecore_init / ecore_cpp_init
ecore_calculate_sleep_score / ecore_cpp_calculate_sleep_score
ecore_calculate_readiness_score / ecore_cpp_calculate_readiness_score
ecore_calculate_activity_score / ecore_cpp_calculate_activity_score
ecore_calculate_baseline / ecore_cpp_calculate_baseline
ecore_calculate_breathing_rate / ecore_cpp_calculate_breathing_rate
ecore_process_events / ecore_cpp_process_events
ecore_get_daily_outputs / ecore_cpp_get_daily_outputs
ecore_get_daily_outputs_stateless / ecore_cpp_get_daily_outputs_stateless
ecore_serialize_persistent_v2 / ecore_cpp_serialize_persistent_v2
ecore_deserialize_persistent_v2 / ecore_cpp_deserialize_persistent_v2
daytime_hr_init / daytime_hr_process_event / daytime_hr_set_handler
ibi_correction_init / ibi_correction / ibi_correction_stateless
```
