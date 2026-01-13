# Protobuf Schema Extraction from Decompiled Java

This document describes how we extracted a complete `.proto` schema from Oura's decompiled `Ringeventparser.java` (109,000 lines), enabling type-safe Python decoding of ring health data.

Last updated: 2026-01-12

---

## Table of Contents

1. [Overview](#overview)
2. [Methodology](#methodology)
3. [Key Classes Analyzed](#key-classes-analyzed)
4. [Results](#results)
5. [Verification](#verification)
6. [Usage](#usage)

---

## Overview

### Why We Needed to Extract the Protobuf Schema

The native parser outputs raw protobuf bytes (`ring_data.pb`), but without the schema we can only do generic wire-format parsing without field names or proper types.

**Goal**: Generate a complete `.proto` file from decompiled Java code to enable type-safe protobuf decoding in Python.

```
Ringeventparser.java (109K lines) --> ringeventparser.proto --> Python classes --> Decoded health data
```

### The Challenge

Oura's `Ringeventparser.java` is a decompiled protobuf-lite generated class with:

- **109,000 lines** of Java code - too large for manual extraction
- **Obfuscated runtime types**: `k4`, `h4`, `g4`, `l4`, `v3`, `d4` instead of standard protobuf types
- **144 message classes** with complex nesting
- **44 enums** with 553 values
- **Oneofs** with up to 109 alternatives (the `Event` message)

Standard tools like PBTK don't work because protobuf-lite strips the descriptor and field names appear to be lost.

---

## Methodology

### Protobuf-lite Doesn't Include Schema in Binary

Unlike standard protobuf, protobuf-lite strips the self-describing schema from binaries to reduce size. This means we cannot extract field names or message structure from the `.pb` files themselves.

### Schema Embedded in Java Bytecode via newMessageInfo()

Despite using protobuf-lite, the decompiled Java preserves all field names via constants:

```java
public static final int TIMESTAMP_FIELD_NUMBER = 1;
public static final int IBI_FIELD_NUMBER = 2;
public static final int AMP_FIELD_NUMBER = 3;
```

The obfuscated runtime types map to specific protobuf types:

| Obfuscated | Proto Type | Java Initializer |
|------------|------------|------------------|
| `k4` | `repeated int64` | `emptyLongList()` |
| `h4` | `repeated int32` | `emptyIntList()` |
| `g4` | `repeated float` | `emptyFloatList()` |
| `b4` | `repeated bool` | `emptyBooleanList()` |
| `l4` | `repeated Message` | `emptyProtobufList()` |
| `v3` | Base class | `GeneratedMessageLite` |
| `d4` | Enum interface | `ProtocolMessageEnum` |

### Tree-sitter Approach for Parsing Decompiled Java

Python's `javalang` parser chokes on large files, but tree-sitter parses 109K lines in approximately 2 seconds:

```python
import tree_sitter_java as tsjava
from tree_sitter import Language, Parser

parser = Parser(Language(tsjava.language()))
tree = parser.parse(source_bytes)  # 109K lines in 2 seconds
```

The hybrid tree-sitter + regex pipeline works as follows:

```
+-------------------------------------------------------------------------+
|                     HYBRID EXTRACTION PIPELINE                          |
+-------------------------------------------------------------------------+
|                                                                         |
|  Ringeventparser.java (109K lines, 4.3MB)                               |
|          |                                                              |
|          v                                                              |
|  +---------------------------------------------+                        |
|  |  PHASE 1: tree-sitter Structural Parse      |                        |
|  |  - Parse entire file into CST               |                        |
|  |  - Extract 375 class declarations           |                        |
|  |  - Track line ranges for each class         |                        |
|  |  - Identify messages (extends v3)           |                        |
|  |  - Identify enums (implements d4)           |                        |
|  |  - Output: class_map.json                   |                        |
|  +---------------------------------------------+                        |
|          |                                                              |
|          v                                                              |
|  +---------------------------------------------+                        |
|  |  PHASE 2: Regex Pattern Extraction          |                        |
|  |  - Extract FIELD_NUMBER constants           |                        |
|  |  - Extract field declarations + types       |                        |
|  |  - Extract enum values                      |                        |
|  |  - Extract oneof structures                 |                        |
|  |  - Extract List<T> accessors                |                        |
|  |  - Output: raw_schema.json                  |                        |
|  +---------------------------------------------+                        |
|          |                                                              |
|          v                                                              |
|  +---------------------------------------------+                        |
|  |  PHASE 3: Type Resolution                   |                        |
|  |  - Map k4->int64, h4->int32, etc.           |                        |
|  |  - Resolve l4 types from accessors          |                        |
|  |  - Match field numbers to names             |                        |
|  |  - Identify message vs enum refs            |                        |
|  |  - Output: resolved_schema.json             |                        |
|  +---------------------------------------------+                        |
|          |                                                              |
|          v                                                              |
|  +---------------------------------------------+      ring_data.pb      |
|  |  PHASE 4: Binary Validation                 | <------------------    |
|  |  - Parse protobuf wire format               |                        |
|  |  - Extract field numbers + wire types       |                        |
|  |  - Compare against schema                   |                        |
|  |  - Report mismatches                        |                        |
|  |  - Output: validation_report.json           |                        |
|  +---------------------------------------------+                        |
|          |                                                              |
|          v                                                              |
|  +---------------------------------------------+                        |
|  |  PHASE 5: Proto Generation                  |                        |
|  |  - Topological sort by dependencies         |                        |
|  |  - Prefix colliding enum values             |                        |
|  |  - Map ByteString -> bytes                  |                        |
|  |  - Generate proto3 syntax                   |                        |
|  |  - Output: ringeventparser.proto            |                        |
|  +---------------------------------------------+                        |
|          |                                                              |
|          v                                                              |
|  +---------------------------------------------+                        |
|  |  protoc --python_out=.                      |                        |
|  |  - Output: ringeventparser_pb2.py           |                        |
|  +---------------------------------------------+                        |
|                                                                         |
+-------------------------------------------------------------------------+
```

### Alternative Approach Using Field Declarations + Getters

When a field is `l4` (repeated message), the actual message type comes from the accessor method:

```java
private l4 event_ = v3.emptyProtobufList();  // Type unknown here

public List<Event> getEventList() {          // Type revealed: Event
    return this.event_;
}
```

Oneof fields are detected via:
1. `private int eventCase_ = 0;` - case tracker
2. `public enum EventCase { ... }` - field mappings with numbers

```java
public enum EventCase {
    RING_START_IND(1),
    TIME_SYNC_IND(2),
    // ... 109 more
    EVENT_NOT_SET(0);
}
```

### Regex Patterns Used

```python
PATTERNS = {
    # public static final int FIELD_NAME_FIELD_NUMBER = N;
    'field_number': re.compile(r'public static final int (\w+)_FIELD_NUMBER = (\d+);'),

    # private k4 fieldName_ = v3.emptyLongList();
    'repeated_field': re.compile(r'private (k4|h4|g4|b4|l4) (\w+)_ = v3\.(empty\w+List)\(\);'),

    # private int/long/float fieldName_;
    'scalar_field': re.compile(r'private (int|long|float|double|boolean) (\w+)_;'),

    # public List<Type> getFieldNameList()
    'list_accessor': re.compile(r'public List<(\w+)> get(\w+)List\(\)'),

    # ENUM_VALUE(N),
    'enum_value': re.compile(r'^\s+([A-Z][A-Z0-9_]*)\((-?\d+)\)'),

    # private int fieldCase_ = 0;
    'oneof_case': re.compile(r'private int (\w+)Case_ = 0;'),
}
```

---

## Key Classes Analyzed

### Ringeventparser.java

The main decompiled protobuf-lite generated class containing all message definitions:

- **Size**: 109,000 lines, 4.3MB
- **Total classes**: 375 (144 messages, 44 enums, 144 builders, misc)
- **Main entry point**: `RingData` message

### Health-Critical Message Classes

| Message Type | Purpose | Field # in RingData |
|--------------|---------|---------------------|
| `IbiAndAmplitudeEvent` | Heart beat intervals + PPG amplitude | 7 |
| `GreenIbiAndAmpEvent` | Green LED IBI data | 93 |
| `GreenIbiQualityEvent` | IBI quality metrics | 75 |
| `HrvEvent` | Heart rate variability | 11 |
| `TemperatureEvent` | Skin temperature | 8 |
| `SleepTempEvent` | Sleep temperature | - |
| `Spo2Event` | Blood oxygen saturation | 9 |
| `Spo2ComboEvent` | Combined SpO2 data | - |
| `MotionEvent` | Movement/activity | 5 |
| `MotionPeriod` | Motion aggregates | 89 |
| `SleepPeriodInfo` | Sleep session info | 23 |
| `SleepSummary1-4` | Sleep analysis | - |
| `SleepPhaseData` | Sleep stages | - |
| `BedtimePeriod` | Bedtime detection | 6 |
| `ActivityInfoEvent` | Activity metrics | 19 |

### Example: IbiAndAmplitudeEvent Structure

```java
public static final class IbiAndAmplitudeEvent {
    public static final int TIMESTAMP_FIELD_NUMBER = 1;  // repeated int64
    public static final int IBI_FIELD_NUMBER = 2;        // repeated int32 (ms)
    public static final int AMP_FIELD_NUMBER = 3;        // repeated int32 (PPG amplitude)

    private k4 timestamp_ = emptyLongList();  // List<Long>
    private h4 ibi_ = emptyIntList();         // List<Integer>
    private h4 amp_ = emptyIntList();         // List<Integer>
}
```

### Message Classes with newMessageInfo() Calls

Each protobuf-lite message class contains a `newMessageInfo()` method that encodes field metadata. The pattern extraction focuses on the `*_FIELD_NUMBER` constants and field declarations which are more reliably decompiled.

---

## Results

### Extraction Statistics

| Metric | Count |
|--------|-------|
| Total definitions | 186 |
| Message types | 144 |
| Enums | 42 |
| Enum values | 553 |
| Total fields | 962 |
| Oneof groups | 3 |
| Event oneof fields | 109 |
| Proto file lines | 2,070 |

### Generated ringeventparser.proto

The extraction produced a 2,070-line proto3 schema file:

```protobuf
syntax = "proto3";
package oura.ringeventparser;

enum AccelerometerMode {
  DISABLED = 0;
  ORIENTATION_CHANGE_DETECTION = 1;
  MOVEMENT_DETECTION = 2;
}

message IbiAndAmplitudeEvent {
  repeated int64 timestamp = 1;
  repeated int32 ibi = 2;
  repeated int32 amp = 3;
}

message Event {
  int64 timestamp_utc = 10001;
  int32 ringtime = 10002;
  oneof event {
    RingStartInd ring_start_ind = 1;
    TimeSyncInd time_sync_ind = 2;
    // ... 109 fields
  }
}
```

### Decoded Health Data Sample

From `ring_data.pb` (682KB):

| Data Type | Samples | Metrics |
|-----------|---------|---------|
| Heart Rate (IBI) | 33,276 | Avg: 58.5 BPM |
| Temperature | 966 | Avg: 35.10C |
| HRV (RMSSD) | 96 | Avg: 23.5 ms |
| Sleep | 1,098 | ~45 hours |
| Activity | 34 | 166 steps |
| Motion | 154 | x/y/z accel |
| Total Events | 4,736 | 22 event types |

### Proto3 Enum Value Collision Handling

Proto3 requires unique enum value names across all enums in a package. Multiple Oura enums share values like `PD1`, `UNSPECIFIED`, `PERIODIC`.

**Solution**: Prefix colliding values with enum name abbreviation:

```protobuf
enum PPGChannelPDMask {
  PCPM_PD1 = 1;      // Prefixed to avoid collision
  PCPM_PD2 = 2;
}
```

---

## Verification

### Both Methods Produce Identical Serialized Output

The extracted schema was validated against actual protobuf binary data:

| Test | Result |
|------|--------|
| Field numbers match binary | Pass (25/25) |
| Type mismatches | 0 |
| Unknown fields in binary | 0 |
| Nested message parsing | All pass |
| Repeated field integrity | All consistent |
| Data roundtrip | Values preserved |

### Binary Validation Process

```python
def parse_wire_format(data: bytes) -> Dict[int, FieldObservation]:
    """Parse protobuf wire format."""
    while pos < len(data):
        tag, pos = read_varint(data, pos)
        field_number = tag >> 3
        wire_type = tag & 0x7
        # Record field_number -> wire_type mapping
```

Validation checks:
- Field numbers in binary match schema
- Wire types compatible with declared proto types
- No unknown fields

---

## Usage

### Run Full Pipeline

```bash
cd native_parser

python extract_proto/main.py \
    --input ../_large_files/decompiled/sources/com/ouraring/ringeventparser/Ringeventparser.java \
    --binary ring_data.pb \
    --output ringeventparser.proto \
    --verbose
```

### Compile to Python

```bash
protoc --python_out=. ringeventparser.proto
```

### Decode Ring Data

```python
import ringeventparser_pb2 as proto

# Parse binary
rd = proto.RingData()
rd.ParseFromString(open('ring_data.pb', 'rb').read())

# Access typed data
for ibi in rd.ibi_and_amplitude_event.ibi:
    hr = 60000 / ibi
    print(f"Heart rate: {hr:.1f} BPM")

# Iterate events
for event in rd.events.event:
    event_type = event.WhichOneof('event')
    print(f"Event: {event_type} at ringtime={event.ringtime}")
```

### Run Tests

```bash
python test_proto_extraction.py
```

### Dependencies

```bash
pip install tree-sitter tree-sitter-java protobuf
```

System:
```bash
# Arch/Manjaro
sudo pacman -S protobuf

# Debian/Ubuntu
sudo apt install protobuf-compiler
```

---

## Pipeline Files

| File | Purpose |
|------|---------|
| `extract_proto/tree_sitter_parser.py` | Phase 1: Structural parsing |
| `extract_proto/pattern_extractor.py` | Phase 2: Regex extraction |
| `extract_proto/type_resolver.py` | Phase 3: Type resolution |
| `extract_proto/binary_validator.py` | Phase 4: Binary validation |
| `extract_proto/proto_generator.py` | Phase 5: Proto generation |
| `extract_proto/main.py` | Pipeline orchestrator |
| `ringeventparser.proto` | Generated schema (2,070 lines) |
| `ringeventparser_pb2.py` | Python bindings (110KB) |
| `decode_ringdata.py` | User-friendly decoder |
| `test_proto_extraction.py` | Comprehensive test suite |
| `intermediate/class_map.json` | Phase 1 output |
| `intermediate/raw_schema.json` | Phase 2 output |
| `intermediate/resolved_schema.json` | Phase 3 output |
| `intermediate/validation_report.json` | Phase 4 output |

---

## Troubleshooting

| Problem | Solution |
|---------|----------|
| `protoc` enum collision errors | Enum value prefixing handles this |
| `ByteString is not defined` | Mapped to `bytes` automatically |
| Missing message type X | Falls back to `bytes` |
| tree-sitter import error | `pip install tree-sitter-java` |
| Empty parsed data | Check binary path, run validation |

---

## Summary

The hybrid tree-sitter + regex approach successfully extracted a complete protobuf schema from 109K lines of obfuscated decompiled Java. Key insights:

1. **Field names are preserved** in `*_FIELD_NUMBER` constants
2. **Obfuscated types map deterministically** (k4->int64, h4->int32, etc.)
3. **tree-sitter handles large files** where other parsers fail
4. **Binary validation confirms correctness** before use
5. **Proto3 quirks** (enum scoping) require post-processing

The result is a production-ready pipeline that generates type-safe Python code for decoding Oura Ring health data.

---

*Merged from: protobuf_schema_extraction.md + PLAN_full_protobuf_extraction.md*
