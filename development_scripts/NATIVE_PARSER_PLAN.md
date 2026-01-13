# Native Library Integration Plan

## Goal
Use Oura's own `libringeventparser.so` to parse ALL ring events, bypassing manual reverse engineering.

## Architecture

```
Current (Manual Parsing):
┌─────────────┐    ┌──────────────────┐    ┌─────────────────┐
│ Raw BLE     │───▶│ Manual Parsers   │───▶│ Partial Data    │
│ Events      │    │ (SleepPeriod,    │    │ (0x6A, 0x46...) │
│             │    │  Temp, etc.)     │    │                 │
└─────────────┘    └──────────────────┘    └─────────────────┘

Proposed (Native Parsing):
┌─────────────┐    ┌──────────────────┐    ┌─────────────────┐
│ Raw BLE     │───▶│ libringeventparser│───▶│ RingData        │
│ Events      │    │ .so (Oura's own) │    │ (ALL events!)   │
│             │    └──────────────────┘    │                 │
│             │             │              │ • SleepPeriodInfo│
│             │             │              │ • HrvEvent       │
│             │             │              │ • ActivityInfo   │
│             │             │              │ • IbiEvent       │
│             │             │              │ • TempEvent      │
│             │             │              │ • SpO2Event      │
│             │             │              │ • 100+ more...   │
└─────────────┘             │              └─────────────────┘
                            │
                    ┌───────▼───────┐
                    │ JNI Bridge    │
                    │ (already built)│
                    └───────────────┘
```

## What We Already Have

### Native Libraries (in jniLibs/)
- `libringeventparser.so` - Oura's event parser (3.2MB)
- `libprotobuf-lite.so` - Protobuf dependency
- `libringeventparser_jni.so` - Our JNI bridge

### Kotlin Wrapper
- `RingEventParser.kt` - Wrapper class with:
  - `nativeParseEvents()` - Parse batch of events
  - `nativeParseSleepPeriodInfo()` - Parse single 0x6A

### JNI Bridge (C++)
- `ringeventparser_jni.cpp` - Calls native functions via dlopen/dlsym

## What's Missing

1. **RingData.proto** - Protobuf schema for native output
2. **Deserialization** - Convert raw bytes to protobuf object
3. **Pipeline Connection** - Feed BLE events to native parser

---

## Phase 1: Test Existing JNI Bridge

### Test Command
Add to MainActivity.kt:
```kotlin
"test_native", "native" -> {
    val parser = RingEventParser()

    // Real 0x6A event from overnight capture
    val testEvent = hexStringToByteArray("6a0e57cb000080002911401900010000")
    log("Testing native parser with 0x6A event...")

    // Method 1: Direct sleep period parsing
    val sleepResult = parser.parseSleepPeriodInfoNative(testEvent)
    if (sleepResult != null) {
        log("Native parse result (9 floats):")
        sleepResult.forEachIndexed { i, v ->
            val name = when(i) {
                0 -> "avgHr"
                1 -> "hrTrend"
                2 -> "mzci"
                3 -> "dzci"
                4 -> "breath"
                5 -> "breathV"
                6 -> "motionCount"
                7 -> "sleepState"
                8 -> "cv"
                else -> "unknown"
            }
            log("  [$i] $name = $v")
        }
    } else {
        log("Native parse returned null")
    }

    // Method 2: Full event parsing
    val fullResult = parser.parseEvents(listOf(testEvent))
    log("Full parse result: $fullResult")
}
```

### Run Test
```bash
adb shell am broadcast -a com.example.reverseoura.COMMAND --es cmd "test_native"
adb logcat -s RingEventParser:D RingEventParserJNI:D
```

---

## Phase 2: Extract RingData.proto Schema

### Source
File: `_large_files/decompiled/sources/com/ouraring/ringeventparser/Ringeventparser.java`

### Extract Field Definitions
```bash
grep "FIELD_NUMBER = " Ringeventparser.java | head -50
```

### Key Fields Identified
```protobuf
message RingData {
  RingStartInd ring_start_ind = 1;
  DebugEventInd debug_event_ind = 3;
  repeated SleepPeriodInfo sleep_period_info = 4;
  repeated MotionEvent motion_event = 5;
  repeated BedtimePeriod bedtime_period = 6;
  repeated IbiAndAmplitudeEvent ibi_and_amplitude_event = 7;
  repeated SleepAcmPeriod sleep_acm_period = 8;
  repeated HrvEvent hrv_event = 11;
  repeated AlertEvent alert_event = 12;
  repeated RealStepsFeatures real_steps_features = 15;
  repeated FeatureSession feature_session = 16;
  repeated RawPpgData raw_ppg_data = 17;
  repeated ActivityInfoEvent activity_info_event = 19;
  repeated EhrTraceEvent ehr_trace_event = 20;
  repeated EhrAcmIntensityEvent ehr_acm_intensity_event = 21;
  repeated SleepSummary1 sleep_summary_1 = 22;
  // ... 100+ more fields
}
```

### Create Proto File
Generate `ring_data.proto` from decompiled sources:
```protobuf
syntax = "proto3";
package ringeventparser;

message RingData {
    repeated SleepPeriodInfo sleep_period_info = 4;
    repeated HrvEvent hrv_event = 11;
    repeated ActivityInfoEvent activity_info_event = 19;
    // ... extract all fields
}

message SleepPeriodInfo {
    int64 timestamp = 1;
    float average_hr = 2;
    float hr_trend = 3;
    // ... extract all fields from SleepPeriodInfoOrBuilder
}
```

---

## Phase 3: Generate Kotlin Protobuf Classes

### build.gradle Configuration
```groovy
plugins {
    id 'com.google.protobuf' version '0.9.4'
}

dependencies {
    implementation 'com.google.protobuf:protobuf-kotlin-lite:3.25.1'
}

protobuf {
    protoc {
        artifact = 'com.google.protobuf:protoc:3.25.1'
    }
    generateProtoTasks {
        all().each { task ->
            task.builtins {
                kotlin { option 'lite' }
                java { option 'lite' }
            }
        }
    }
}
```

### Proto Location
```
app/src/main/proto/ring_data.proto
```

---

## Phase 4: Deserialize Native Parse Result

### Update JNI Bridge
Modify `ringeventparser_jni.cpp` to return serialized protobuf:

```cpp
// After calling parse_events, serialize the result
// The result is a Ringeventparser::RingData protobuf object
auto serialize = (SerializeToString_t)dlsym(handle,
    "_ZNK6google8protobuf11MessageLite17SerializeToStringEPNSt6__ndk112basic_stringIcNS2_11char_traitsIcEENS2_9allocatorIcEEEE");

std::string serialized;
if (serialize && result) {
    google::protobuf::MessageLite* msg = (google::protobuf::MessageLite*)result;
    msg->SerializeToString(&serialized);

    // Return as byte array
    jbyteArray output = env->NewByteArray(serialized.size());
    env->SetByteArrayRegion(output, 0, serialized.size(),
        (jbyte*)serialized.data());
    return output;
}
```

### Kotlin Deserialization
```kotlin
fun parseEventsToRingData(events: List<ByteArray>): RingData? {
    val rawResult = nativeParseEventsRaw(concatenate(events))
    if (rawResult != null) {
        return RingData.parseFrom(rawResult)
    }
    return null
}
```

---

## Phase 5: Connect BLE Pipeline

### In MainActivity.kt
```kotlin
"parse_all" -> {
    if (eventData.isEmpty()) {
        log("No events - run 'data' first")
        return
    }

    val parser = RingEventParser()
    val ringData = parser.parseEventsToRingData(eventData)

    if (ringData != null) {
        log("=== PARSED RING DATA ===")
        log("Sleep periods: ${ringData.sleepPeriodInfoCount}")
        log("HRV events: ${ringData.hrvEventCount}")
        log("Activity events: ${ringData.activityInfoEventCount}")
        log("IBI events: ${ringData.ibiAndAmplitudeEventCount}")

        // Show sample data
        ringData.sleepPeriodInfoList.take(3).forEach { sleep ->
            log("  Sleep: HR=${sleep.averageHr} state=${sleep.sleepState}")
        }

        ringData.hrvEventList.forEach { hrv ->
            log("  HRV: RMSSD=${hrv.averageRmssd5Min}")
        }
    }
}
```

---

## Phase 6: Export All Health Metrics

### Comprehensive Export
```kotlin
"export_health" -> {
    val ringData = parser.parseEventsToRingData(eventData)

    val exportFile = File(exportDir, "health_data_$timestamp.json")
    val json = buildJsonObject {
        put("timestamp", System.currentTimeMillis())
        put("events_parsed", ringData.eventsCount)

        putJsonArray("sleep") {
            ringData.sleepPeriodInfoList.forEach { s ->
                addJsonObject {
                    put("timestamp", s.timestamp)
                    put("avgHr", s.averageHr)
                    put("sleepState", s.sleepState)
                    put("hrv_rmssd", s.mzci)
                }
            }
        }

        putJsonArray("hrv") {
            ringData.hrvEventList.forEach { h ->
                addJsonObject {
                    put("timestamp", h.timestamp)
                    put("rmssd", h.averageRmssd5Min)
                    put("hr", h.averageHr5Min)
                }
            }
        }

        // ... more event types
    }

    exportFile.writeText(json.toString())
    log("Exported health data to: ${exportFile.path}")
}
```

---

## Dependencies

### Libraries Already Present
- ✅ `libringeventparser.so` (Oura's parser)
- ✅ `libprotobuf-lite.so` (protobuf runtime)
- ✅ `libringeventparser_jni.so` (our JNI bridge)

### Additional Required
- `com.google.protobuf:protobuf-kotlin-lite` (for Kotlin protobuf classes)

---

## Testing Strategy

1. **Unit Test**: Parse single 0x6A event, verify fields
2. **Integration Test**: Parse overnight capture (4794 events)
3. **Comparison Test**: Compare native results with manual parsers
4. **Full Pipeline**: BLE → Native → JSON export

---

## Success Criteria

1. ✅ Native parser returns valid RingData protobuf
2. ✅ All sleep period fields match manual parser output
3. ✅ HRV, Activity, IBI events properly extracted
4. ✅ Export contains all health metrics
5. ✅ Processing time < 1 second for 5000 events

---

## Risks & Mitigations

| Risk | Mitigation |
|------|------------|
| Library ABI incompatibility | Test on same Android version as Oura app |
| Missing dependencies | Include all libs from original APK |
| Protobuf version mismatch | Use protobuf-lite, match Oura's version |
| Crash in native code | Wrap in try-catch, log stack traces |

---

## Timeline Estimate

- Phase 1 (Test JNI): 1 hour
- Phase 2 (Extract Proto): 2-3 hours
- Phase 3 (Generate Classes): 1 hour
- Phase 4 (Deserialize): 2 hours
- Phase 5 (Pipeline): 1 hour
- Phase 6 (Export): 1-2 hours

**Total: ~10 hours of focused work**
