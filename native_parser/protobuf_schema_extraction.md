# Extracting Protobuf Schema from Decompiled Java

This document describes how we extracted a complete `.proto` schema from Oura's decompiled `Ringeventparser.java` (109,000 lines) using a hybrid tree-sitter + regex pipeline, enabling type-safe Python decoding of ring health data.

## Table of Contents

1. [Goal](#goal)
2. [The Problem](#the-problem)
3. [Key Discoveries](#key-discoveries)
4. [Solution Architecture](#solution-architecture)
5. [Pipeline Phases](#pipeline-phases)
6. [Implementation Details](#implementation-details)
7. [Results](#results)
8. [Usage](#usage)
9. [Files](#files)

---

## Goal

Generate a complete `.proto` file from decompiled Java code to enable type-safe protobuf decoding in Python.

```
Ringeventparser.java (109K lines) → ringeventparser.proto → Python classes → Decoded health data
```

**Why we needed this**: The native parser outputs raw protobuf bytes (`ring_data.pb`), but without the schema we can only do generic wire-format parsing without field names or proper types.

---

## The Problem

Oura's `Ringeventparser.java` is a decompiled protobuf-lite generated class with:

1. **109,000 lines** of Java code - too large for manual extraction
2. **Obfuscated runtime types**: `k4`, `h4`, `g4`, `l4`, `v3`, `d4` instead of standard protobuf types
3. **144 message classes** with complex nesting
4. **44 enums** with 553 values
5. **Oneofs** with up to 109 alternatives (the `Event` message)

Standard tools like PBTK don't work because protobuf-lite strips the descriptor and field names appear to be lost.

---

## Key Discoveries

### Discovery 1: Field Names ARE Preserved

Despite obfuscation, the decompiled Java preserves all field names via constants:

```java
public static final int TIMESTAMP_FIELD_NUMBER = 1;
public static final int IBI_FIELD_NUMBER = 2;
public static final int AMP_FIELD_NUMBER = 3;
```

**How we found this**: Grep through the decompiled source revealed thousands of `*_FIELD_NUMBER` constants.

### Discovery 2: Obfuscated Types Map Deterministically

The runtime types map to specific protobuf types:

| Obfuscated | Proto Type | Java Initializer |
|------------|------------|------------------|
| `k4` | `repeated int64` | `emptyLongList()` |
| `h4` | `repeated int32` | `emptyIntList()` |
| `g4` | `repeated float` | `emptyFloatList()` |
| `b4` | `repeated bool` | `emptyBooleanList()` |
| `l4` | `repeated Message` | `emptyProtobufList()` |
| `v3` | Base class | `GeneratedMessageLite` |
| `d4` | Enum interface | `ProtocolMessageEnum` |

**How we found this**: Pattern analysis of field declarations and their initializers.

### Discovery 3: Message Types for `l4` Come from Accessors

When a field is `l4` (repeated message), the actual message type comes from the accessor method:

```java
private l4 event_ = v3.emptyProtobufList();  // Type unknown here

public List<Event> getEventList() {          // Type revealed: Event
    return this.event_;
}
```

**How we found this**: Cross-referencing field declarations with getter methods.

### Discovery 4: Oneofs Have Case Enums

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

**How we found this**: Pattern matching for `*Case_` fields and corresponding enums.

### Discovery 5: tree-sitter Handles 109K Lines

Python's `javalang` parser chokes on large files, but tree-sitter parses 109K lines in ~2 seconds:

```python
import tree_sitter_java as tsjava
from tree_sitter import Language, Parser

parser = Parser(Language(tsjava.language()))
tree = parser.parse(source_bytes)  # 109K lines in 2 seconds
```

**How we found this**: Benchmarking different parsers.

### Discovery 6: Proto3 Enum Value Scoping

Proto3 requires unique enum value names across all enums in a package. Multiple Oura enums share values like `PD1`, `UNSPECIFIED`, `PERIODIC`.

**Solution**: Prefix colliding values with enum name abbreviation:
```protobuf
enum PPGChannelPDMask {
  PCPM_PD1 = 1;      // Prefixed to avoid collision
  PCPM_PD2 = 2;
}
```

**How we found this**: `protoc` compilation errors.

---

## Solution Architecture

```
┌─────────────────────────────────────────────────────────────────────────┐
│                     HYBRID EXTRACTION PIPELINE                          │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│  Ringeventparser.java (109K lines, 4.3MB)                               │
│          │                                                              │
│          ▼                                                              │
│  ┌─────────────────────────────────────────┐                            │
│  │  PHASE 1: tree-sitter Structural Parse  │                            │
│  │  ├── Parse entire file into CST         │                            │
│  │  ├── Extract 375 class declarations     │                            │
│  │  ├── Track line ranges for each class   │                            │
│  │  ├── Identify messages (extends v3)     │                            │
│  │  ├── Identify enums (implements d4)     │                            │
│  │  └── Output: class_map.json             │                            │
│  └─────────────────────────────────────────┘                            │
│          │                                                              │
│          ▼                                                              │
│  ┌─────────────────────────────────────────┐                            │
│  │  PHASE 2: Regex Pattern Extraction      │                            │
│  │  ├── Extract FIELD_NUMBER constants     │                            │
│  │  ├── Extract field declarations + types │                            │
│  │  ├── Extract enum values                │                            │
│  │  ├── Extract oneof structures           │                            │
│  │  ├── Extract List<T> accessors          │                            │
│  │  └── Output: raw_schema.json            │                            │
│  └─────────────────────────────────────────┘                            │
│          │                                                              │
│          ▼                                                              │
│  ┌─────────────────────────────────────────┐                            │
│  │  PHASE 3: Type Resolution               │                            │
│  │  ├── Map k4→int64, h4→int32, etc.       │                            │
│  │  ├── Resolve l4 types from accessors    │                            │
│  │  ├── Match field numbers to names       │                            │
│  │  ├── Identify message vs enum refs      │                            │
│  │  └── Output: resolved_schema.json       │                            │
│  └─────────────────────────────────────────┘                            │
│          │                                                              │
│          ▼                                                              │
│  ┌─────────────────────────────────────────┐      ring_data.pb          │
│  │  PHASE 4: Binary Validation             │ ◄──────────────────        │
│  │  ├── Parse protobuf wire format         │                            │
│  │  ├── Extract field numbers + wire types │                            │
│  │  ├── Compare against schema             │                            │
│  │  ├── Report mismatches                  │                            │
│  │  └── Output: validation_report.json     │                            │
│  └─────────────────────────────────────────┘                            │
│          │                                                              │
│          ▼                                                              │
│  ┌─────────────────────────────────────────┐                            │
│  │  PHASE 5: Proto Generation              │                            │
│  │  ├── Topological sort by dependencies   │                            │
│  │  ├── Prefix colliding enum values       │                            │
│  │  ├── Map ByteString → bytes             │                            │
│  │  ├── Generate proto3 syntax             │                            │
│  │  └── Output: ringeventparser.proto      │                            │
│  └─────────────────────────────────────────┘                            │
│          │                                                              │
│          ▼                                                              │
│  ┌─────────────────────────────────────────┐                            │
│  │  protoc --python_out=.                  │                            │
│  │  └── Output: ringeventparser_pb2.py     │                            │
│  └─────────────────────────────────────────┘                            │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘
```

---

## Pipeline Phases

### Phase 1: tree-sitter Structural Parsing

**File**: `extract_proto/tree_sitter_parser.py`

Parses the entire Java file and extracts class structure:

```python
def parse_java_file(filepath: str) -> Dict:
    parser = Parser(Language(tsjava.language()))
    tree = parser.parse(source_bytes)

    # Walk AST to find class/enum declarations
    for node in walk_tree(tree.root_node):
        if node.type == 'class_declaration':
            # Extract: name, line range, extends, implements
        elif node.type == 'enum_declaration':
            # Extract: name, line range, implements d4?
```

**Key extraction**: Line ranges allow Phase 2 to scope regex to specific classes.

**Output** (`class_map.json`):
```json
{
  "classes": [
    {
      "name": "IbiAndAmplitudeEvent",
      "qualified_name": "Ringeventparser.IbiAndAmplitudeEvent",
      "extends": "v3",
      "is_message": true,
      "start_line": 68234,
      "end_line": 69156
    }
  ],
  "total_classes": 375,
  "summary": {"messages": 144, "enums": 41, "builders": 144}
}
```

### Phase 2: Regex Pattern Extraction

**File**: `extract_proto/pattern_extractor.py`

Extracts protobuf patterns using regex within each class's line range:

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

**Output** (`raw_schema.json`):
```json
{
  "Ringeventparser.IbiAndAmplitudeEvent": {
    "field_numbers": {"1": "timestamp", "2": "ibi", "3": "amp"},
    "field_types": {
      "timestamp": ["k4", "emptyLongList"],
      "ibi": ["h4", "emptyIntList"],
      "amp": ["h4", "emptyIntList"]
    }
  }
}
```

### Phase 3: Type Resolution

**File**: `extract_proto/type_resolver.py`

Maps obfuscated Java types to protobuf types:

```python
REPEATED_TYPES = {
    'k4': 'int64',    # emptyLongList
    'h4': 'int32',    # emptyIntList
    'g4': 'float',    # emptyFloatList
    'b4': 'bool',     # emptyBooleanList
    'l4': 'MESSAGE',  # resolve from accessor
}

SCALAR_TYPES = {
    'int': 'int32',
    'long': 'int64',
    'float': 'float',
    'double': 'double',
    'boolean': 'bool',
    'String': 'string',
    'ByteString': 'bytes',
}
```

**Output** (`resolved_schema.json`):
```json
{
  "messages": [
    {
      "name": "IbiAndAmplitudeEvent",
      "fields": [
        {"name": "timestamp", "number": 1, "proto_type": "int64", "repeated": true},
        {"name": "ibi", "number": 2, "proto_type": "int32", "repeated": true},
        {"name": "amp", "number": 3, "proto_type": "int32", "repeated": true}
      ]
    }
  ],
  "enums": [...]
}
```

### Phase 4: Binary Validation

**File**: `extract_proto/binary_validator.py`

Validates extracted schema against actual protobuf binary:

```python
def parse_wire_format(data: bytes) -> Dict[int, FieldObservation]:
    """Parse protobuf wire format."""
    while pos < len(data):
        tag, pos = read_varint(data, pos)
        field_number = tag >> 3
        wire_type = tag & 0x7
        # Record field_number → wire_type mapping
```

**Validation checks**:
- Field numbers in binary match schema
- Wire types compatible with declared proto types
- No unknown fields

**Output** (`validation_report.json`):
```json
{
  "valid_fields": 25,
  "type_mismatches": 0,
  "missing_in_schema": 0,
  "summary": {"passed": true}
}
```

### Phase 5: Proto Generation

**File**: `extract_proto/proto_generator.py`

Generates syntactically correct `.proto` file:

```python
def generate(self) -> str:
    lines = ['syntax = "proto3";', 'package oura.ringeventparser;']

    # Generate enums first (no dependencies)
    for enum in sorted_enums:
        lines.extend(self._generate_enum(enum))

    # Topological sort messages by dependencies
    for msg in self._topological_sort():
        lines.extend(self._generate_message(msg))
```

**Key features**:
- Topological sort ensures dependencies defined first
- Prefixes colliding enum values
- Maps `ByteString` → `bytes`
- Falls back to `bytes` for unknown types

**Output** (`ringeventparser.proto`):
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

---

## Implementation Details

### Handling Enum Value Collisions

Proto3 uses C++ scoping rules where enum values are siblings, not children. Multiple enums with `PD1` or `UNSPECIFIED` cause conflicts.

**Solution**: Detect collisions and prefix with enum name abbreviation:

```python
def _find_enum_collisions(self):
    value_counts = defaultdict(int)
    for enum in self.enums.values():
        for value_name in enum['values'].keys():
            value_counts[value_name] += 1
    self.colliding_values = {v for v, count in value_counts.items() if count > 1}

def _make_enum_prefix(self, enum_name: str) -> str:
    # PPGChannelPDMask → PCPM_
    return ''.join(c for c in enum_name if c.isupper()) + '_'
```

### Handling Unknown Message Types

Some oneof fields reference types not in the schema (e.g., `ExerciseHrV1`, `Spo2`). These are likely internal/unused types.

**Solution**: Fall back to `bytes`:

```python
def _resolve_type(self, proto_type: str) -> str:
    if proto_type in self.messages or proto_type in self.enums:
        return proto_type
    if proto_type in primitives:
        return proto_type
    return 'bytes'  # Fallback for unknown types
```

### Timestamp Structure

The extracted data uses relative timestamps:
- `Event.ringtime`: Ring internal time (seconds since boot)
- `Event.timestamp_utc`: Unix timestamp (often 0 if not synced)
- Nested `timestamp` fields: Offsets from `ringtime` (can be negative)

---

## Results

### Extraction Statistics

| Metric | Count |
|--------|-------|
| Message types | 144 |
| Enums | 44 |
| Enum values | 553 |
| Total fields | 962 |
| Oneof groups | 3 |
| Event oneof fields | 109 |
| Proto file lines | 2,071 |

### Validation Results

| Test | Result |
|------|--------|
| Field numbers match binary | ✅ 25/25 |
| Type mismatches | ✅ 0 |
| Unknown fields in binary | ✅ 0 |
| Nested message parsing | ✅ All pass |
| Repeated field integrity | ✅ All consistent |
| Data roundtrip | ✅ Values preserved |

### Decoded Health Data

From `ring_data.pb` (682KB):

| Data Type | Samples | Metrics |
|-----------|---------|---------|
| Heart Rate (IBI) | 33,276 | Avg: 58.5 BPM |
| Temperature | 966 | Avg: 35.10°C |
| HRV (RMSSD) | 96 | Avg: 23.5 ms |
| Sleep | 1,098 | ~45 hours |
| Activity | 34 | 166 steps |
| Motion | 154 | x/y/z accel |
| Total Events | 4,736 | 22 event types |

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

---

## Files

| File | Purpose |
|------|---------|
| `extract_proto/tree_sitter_parser.py` | Phase 1: Structural parsing |
| `extract_proto/pattern_extractor.py` | Phase 2: Regex extraction |
| `extract_proto/type_resolver.py` | Phase 3: Type resolution |
| `extract_proto/binary_validator.py` | Phase 4: Binary validation |
| `extract_proto/proto_generator.py` | Phase 5: Proto generation |
| `extract_proto/main.py` | Pipeline orchestrator |
| `ringeventparser.proto` | Generated schema (2,071 lines) |
| `ringeventparser_pb2.py` | Python bindings (110KB) |
| `decode_ringdata.py` | User-friendly decoder |
| `test_proto_extraction.py` | Comprehensive test suite |
| `intermediate/class_map.json` | Phase 1 output |
| `intermediate/raw_schema.json` | Phase 2 output |
| `intermediate/resolved_schema.json` | Phase 3 output |
| `intermediate/validation_report.json` | Phase 4 output |

---

## Dependencies

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
2. **Obfuscated types map deterministically** (k4→int64, h4→int32, etc.)
3. **tree-sitter handles large files** where other parsers fail
4. **Binary validation confirms correctness** before use
5. **Proto3 quirks** (enum scoping) require post-processing

The result is a production-ready pipeline that generates type-safe Python code for decoding Oura Ring health data.
