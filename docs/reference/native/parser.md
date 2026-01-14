# libringeventparser.so - Event Parsing

Parses raw BLE bytes into structured protobuf events.

**Size:** 3.3 MB
**Location:** `_large_files/native/lib/arm64-v8a/libringeventparser.so`

---

## JNI Entry Point

```
Java_com_ouraring_ringeventparser_RingEventParserObj_nativeParseEvents
```

### Kotlin Wrapper

```kotlin
// RingEventParserObj.kt
external fun nativeParseEvents(
    ringEvents: ByteArray,
    ringTime: Int,
    utcTime: Long,
    jzLogMode: Boolean
): Ringeventparser.RingData
```

**Source:** `com/ouraring/ringeventparser/RingEventParserObj.java`

---

## Native API Functions

| Function | Description |
|----------|-------------|
| `rep_parseEvents` | Parse event buffer |
| `rep_create_session` | Create parser session |
| `rep_end_session` | End parser session |
| `rep_process_chunk` | Process data chunk |
| `rep_fix_spo2_timestamps` | Fix SpO2 timestamps |
| `rep_free_protobuf` | Free protobuf memory |
| `rep_get_state` | Get parser state |
| `rep_set_state` | Set parser state |

---

## Native Symbols

From symbol extraction (`nm -D`):

```
_ZN15RingEventParser12parse_eventsEPKhjPj
_ZN15RingEventParserC1Ev
_ZN11EventParser27parse_api_sleep_period_infoERK5Event
```

### Demangled Names

| Mangled | Demangled |
|---------|-----------|
| `_ZN15RingEventParserC1Ev` | `RingEventParser::RingEventParser()` |
| `_ZN15RingEventParser12parse_eventsEPKhjPj` | `RingEventParser::parse_events(unsigned char const*, unsigned int, unsigned int*)` |
| `_ZN11EventParser27parse_api_sleep_period_infoERK5Event` | `EventParser::parse_api_sleep_period_info(Event const&)` |

---

## Usage Pattern

```kotlin
// 1. Load native library
static { System.loadLibrary("ringeventparser"); }

// 2. Parse raw bytes to protobuf
fun parseEvents(ringEvents: List<ByteArray>, ringTime: Int, utcTime: Long): RingData {
    val concatEvents = concatEvents(ringEvents)
    return nativeParseEvents(concatEvents, ringTime, utcTime, false)
}
```

---

## Output: Ringeventparser.RingData

Protobuf container with typed events:

| Field | Type | Description |
|-------|------|-------------|
| `ibiAndAmplitudeEvents` | List | Heart rate IBI data |
| `tempEvents` | List | Temperature (7 sensors) |
| `motionEvents` | List | Accelerometer |
| `sleepPeriodInfoEvents` | List | Sleep periods |
| `hrvEvents` | List | Heart rate variability |
| `spo2Events` | List | Blood oxygen |
| `activityInfoEvents` | List | Activity data |

---

## Source References

**Decompiled Classes:**
- `com.ouraring.ringeventparser.RingEventParserObj`
- `com.ouraring.ringeventparser.Ringeventparser`
- `com.ouraring.ringeventparser.data.RingEventType`

**Source Files:**
```
_large_files/decompiled/sources/com/ouraring/ringeventparser/
├── RingEventParserObj.java
├── RingEventParserObjKt.java
├── Ringeventparser.java
└── data/
    └── RingEventType.java
```

---

## See Also

- [Events Reference](../events/_index.md) - Event types and field definitions
- [BLE Protocol](../ble/_index.md) - How events are received
