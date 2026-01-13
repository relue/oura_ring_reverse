# Plan: Full Protobuf Data Extraction Like Java App

## Current State

We have:
- ✅ 682KB serialized protobuf from native parser
- ✅ Basic wire-format decoding in Python
- ✅ Field numbers from decompiled Java
- ✅ Successfully extracted: HR (64.8 BPM), Temperature (35.35°C), HRV (77.5ms RMSSD)

What Java app has that we don't:
- 109,000 lines of generated protobuf classes (`Ringeventparser.java`)
- 292 Kotlin/Java processing files
- Proper typed access to all nested message fields
- Full semantic understanding of all data types

---

## Analysis: What's in the Java Classes

### Message Types (from Ringeventparser.java)

**Health-Critical Messages:**
| Message Type | Purpose | Field # in RingData |
|--------------|---------|---------------------|
| `IbiAndAmplitudeEvent` | Heart beat intervals + PPG amplitude | 7 |
| `GreenIbiAndAmpEvent` | Green LED IBI data | 93 |
| `GreenIbiQualityEvent` | IBI quality metrics | 75 |
| `HrvEvent` | Heart rate variability | 11 |
| `TemperatureEvent` | Skin temperature | 8 |
| `SleepTempEvent` | Sleep temperature | ? |
| `Spo2Event` | Blood oxygen saturation | 9 |
| `Spo2ComboEvent` | Combined SpO2 data | ? |
| `MotionEvent` | Movement/activity | 5 |
| `MotionPeriod` | Motion aggregates | 89 |
| `SleepPeriodInfo` | Sleep session info | 23 |
| `SleepSummary1-4` | Sleep analysis | ? |
| `SleepPhaseData` | Sleep stages | ? |
| `BedtimePeriod` | Bedtime detection | 6 |
| `ActivityInfoEvent` | Activity metrics | 19 |

**Example: IbiAndAmplitudeEvent Structure:**
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

---

## Options

### Option 1: Reconstruct .proto Schema from Java ⭐ RECOMMENDED

**Approach:**
1. Parse `Ringeventparser.java` to extract message definitions
2. Generate a `.proto` file
3. Use `protoc` to generate Python classes
4. Decode protobuf properly with full type information

**Pros:**
- Clean, standard protobuf workflow
- Full type safety
- All nested messages properly decoded
- Can generate for any language

**Cons:**
- Need to parse 109K lines of decompiled Java
- Some type info may be lost in decompilation
- Requires careful extraction of field types

**Effort:** Medium-High (can be automated)

**Script outline:**
```python
# extract_proto.py
import re

# Parse patterns like:
# public static final int TIMESTAMP_FIELD_NUMBER = 1;
# private k4 timestamp_ = emptyLongList();  -> repeated int64

def extract_messages(java_file):
    messages = {}
    current_message = None

    for line in open(java_file):
        # Detect message class
        if match := re.match(r'public static final class (\w+) extends v3', line):
            current_message = match.group(1)
            messages[current_message] = {'fields': []}

        # Detect field number
        if match := re.match(r'public static final int (\w+)_FIELD_NUMBER = (\d+)', line):
            field_name = match.group(1).lower()
            field_num = int(match.group(2))
            messages[current_message]['fields'].append({
                'name': field_name,
                'number': field_num
            })

        # Detect field type from member variable
        if 'emptyLongList' in line:
            # repeated int64
            pass
        elif 'emptyIntList' in line:
            # repeated int32
            pass

    return messages
```

---

### Option 2: Run Java Directly with Decompiled Classes

**Approach:**
1. Set up Gradle/Maven project
2. Include decompiled Java files
3. Fix compilation errors (obfuscated names, missing deps)
4. Call `RingData.parseFrom(bytes)`
5. Use Java reflection or Kotlin to extract data

**Pros:**
- Uses exact same code as Oura app
- Guaranteed compatibility
- Access to all processing logic (not just protobuf)

**Cons:**
- Decompiled code has obfuscated names (k4, h4, v3, p3...)
- Missing dependencies need stubs
- Java/Kotlin runtime required
- Compilation errors to fix

**Effort:** High

**Example structure:**
```
oura_decoder/
├── build.gradle.kts
├── src/main/java/
│   └── com/ouraring/ringeventparser/
│       ├── Ringeventparser.java  (109K lines)
│       └── ... (291 more files)
└── src/main/kotlin/
    └── Decoder.kt
```

---

### Option 3: Pure Python Decoder for Key Messages ⭐ QUICK WIN

**Approach:**
1. Manually define Python dataclasses for top 10 health messages
2. Build decoder using wire-format parsing
3. Focus only on what we need (HR, HRV, temp, sleep, SpO2)

**Pros:**
- Pure Python, no dependencies
- Can start immediately
- Covers main use case
- Easy to extend

**Cons:**
- Manual work per message type
- Doesn't cover all 100+ message types
- May miss edge cases

**Effort:** Low-Medium

**Example:**
```python
from dataclasses import dataclass
from typing import List

@dataclass
class IbiAndAmplitudeEvent:
    """Field 7 in RingData"""
    timestamp: List[int]  # Field 1: repeated int64 (ms since epoch)
    ibi: List[int]        # Field 2: repeated int32 (IBI in ms)
    amp: List[int]        # Field 3: repeated int32 (PPG amplitude)

@dataclass
class SleepPeriodInfo:
    """Field 23 in RingData"""
    start_time: int       # Field 1
    temperatures: List[float]  # Field 2 (packed floats)

@dataclass
class RingData:
    """Top-level message"""
    ibi_and_amplitude_event: IbiAndAmplitudeEvent  # Field 7
    temperature_event: bytes  # Field 8
    hrv_event: bytes  # Field 11
    sleep_period_info: SleepPeriodInfo  # Field 23
    # ... etc
```

---

### Option 4: Hybrid - Auto-Generate Python from Java

**Approach:**
1. Write a Java-to-Python transpiler for protobuf classes
2. Parse `Ringeventparser.java`
3. Generate Python dataclasses + decoder

**Pros:**
- Automated
- Gets all message types
- Python-native

**Cons:**
- Complex to build the transpiler
- Need to handle Java protobuf-lite specifics

**Effort:** High

---

### Option 5: Use protobuf-inspector or similar tools

**Approach:**
1. Use existing tools like `protobuf-inspector` or `pbtk`
2. Analyze the binary protobuf
3. Generate schema from binary analysis

**Pros:**
- No Java parsing needed
- Tools exist

**Cons:**
- May not get field names
- Type inference is imperfect

**Effort:** Low

---

## Recommended Path

### Phase 1: Quick Python Decoder (1-2 days)
Focus on extracting the most valuable health data:

```python
# Priority messages to decode:
1. IbiAndAmplitudeEvent (field 7) → Heart Rate, HRV
2. SleepPeriodInfo (field 23) → Sleep times, temperature
3. MotionEvent (field 5) → Activity levels
4. Spo2Event (field 9) → Blood oxygen
5. HrvEvent (field 11) → HRV details
6. GreenIbiQualityEvent (field 75) → Quality metrics
```

### Phase 2: Auto-Generate .proto from Java (3-5 days)
Build a parser for `Ringeventparser.java`:

```python
# Goals:
1. Extract all message class names
2. Extract field numbers and names
3. Infer field types from Java type hints
4. Generate ringeventparser.proto
5. Run protoc --python_out to get proper classes
```

### Phase 3: Full Processing Logic (optional, 1-2 weeks)
Port Kotlin processing logic to Python:
- `SleepSummaryKt.java` → sleep score calculation
- `HrvEventKt.java` → HRV metric calculation
- etc.

---

## Implementation Details

### Phase 1: Python Decoder for Key Messages

**File: `oura_proto_decoder.py`**

```python
#!/usr/bin/env python3
"""
Decode Oura Ring protobuf data.
Based on reverse-engineered Ringeventparser.java
"""

import struct
from dataclasses import dataclass, field
from typing import List, Optional, Dict, Any

def decode_varint(data: bytes, pos: int) -> tuple[int, int]:
    """Decode a protobuf varint, return (value, new_position)"""
    result = 0
    shift = 0
    while pos < len(data):
        b = data[pos]
        result |= (b & 0x7f) << shift
        pos += 1
        if not (b & 0x80):
            break
        shift += 7
    return result, pos

def decode_signed_varint(val: int) -> int:
    """ZigZag decode for signed integers"""
    return (val >> 1) ^ -(val & 1)

def decode_packed_varints(data: bytes) -> List[int]:
    """Decode packed repeated varints"""
    values = []
    pos = 0
    while pos < len(data):
        val, pos = decode_varint(data, pos)
        values.append(val)
    return values

def decode_packed_signed_varints(data: bytes) -> List[int]:
    """Decode packed repeated signed varints (zigzag)"""
    return [decode_signed_varint(v) for v in decode_packed_varints(data)]

def decode_packed_floats(data: bytes) -> List[float]:
    """Decode packed repeated floats"""
    count = len(data) // 4
    return list(struct.unpack(f'<{count}f', data[:count*4]))


@dataclass
class IbiAndAmplitudeEvent:
    """
    Heart beat intervals and PPG amplitude.
    RingData field 7.

    From Java:
      TIMESTAMP_FIELD_NUMBER = 1  (repeated int64)
      IBI_FIELD_NUMBER = 2        (repeated int32, milliseconds)
      AMP_FIELD_NUMBER = 3        (repeated int32)
    """
    timestamps: List[int] = field(default_factory=list)
    ibi_ms: List[int] = field(default_factory=list)
    amplitude: List[int] = field(default_factory=list)

    @classmethod
    def decode(cls, data: bytes) -> 'IbiAndAmplitudeEvent':
        event = cls()
        pos = 0
        while pos < len(data):
            tag, pos = decode_varint(data, pos)
            field_num = tag >> 3
            wire_type = tag & 0x7

            if wire_type == 2:  # length-delimited (packed)
                length, pos = decode_varint(data, pos)
                field_data = data[pos:pos+length]
                pos += length

                if field_num == 1:
                    event.timestamps = decode_packed_varints(field_data)
                elif field_num == 2:
                    event.ibi_ms = decode_packed_varints(field_data)
                elif field_num == 3:
                    event.amplitude = decode_packed_varints(field_data)
            elif wire_type == 0:
                val, pos = decode_varint(data, pos)

        return event

    def heart_rates_bpm(self) -> List[float]:
        """Convert IBI to heart rate in BPM"""
        return [60000 / ibi for ibi in self.ibi_ms if ibi > 0]

    def average_hr(self) -> float:
        hrs = self.heart_rates_bpm()
        return sum(hrs) / len(hrs) if hrs else 0

    def rmssd(self) -> float:
        """Calculate RMSSD (HRV metric)"""
        if len(self.ibi_ms) < 2:
            return 0
        diffs = [abs(self.ibi_ms[i] - self.ibi_ms[i-1])
                 for i in range(1, len(self.ibi_ms))]
        return (sum(d**2 for d in diffs) / len(diffs)) ** 0.5


@dataclass
class SleepPeriodInfo:
    """
    Sleep period information.
    RingData field 23.
    """
    sleep_date_ms: int = 0
    temperatures: List[float] = field(default_factory=list)

    @classmethod
    def decode(cls, data: bytes) -> 'SleepPeriodInfo':
        info = cls()
        pos = 0
        while pos < len(data):
            tag, pos = decode_varint(data, pos)
            field_num = tag >> 3
            wire_type = tag & 0x7

            if wire_type == 2:
                length, pos = decode_varint(data, pos)
                field_data = data[pos:pos+length]
                pos += length

                if field_num == 2:
                    # Packed floats for temperature
                    info.temperatures = decode_packed_floats(field_data)
            elif wire_type == 0:
                val, pos = decode_varint(data, pos)
                if field_num == 1:
                    info.sleep_date_ms = val

        return info


@dataclass
class RingData:
    """
    Top-level protobuf message.
    """
    ibi_event: Optional[IbiAndAmplitudeEvent] = None
    sleep_info: Optional[SleepPeriodInfo] = None
    raw_fields: Dict[int, bytes] = field(default_factory=dict)

    @classmethod
    def decode(cls, data: bytes) -> 'RingData':
        ring_data = cls()
        pos = 0

        while pos < len(data):
            tag, pos = decode_varint(data, pos)
            field_num = tag >> 3
            wire_type = tag & 0x7

            if wire_type == 2:
                length, pos = decode_varint(data, pos)
                field_data = data[pos:pos+length]
                pos += length

                # Decode known message types
                if field_num == 7:
                    ring_data.ibi_event = IbiAndAmplitudeEvent.decode(field_data)
                elif field_num == 23:
                    ring_data.sleep_info = SleepPeriodInfo.decode(field_data)
                else:
                    ring_data.raw_fields[field_num] = field_data

            elif wire_type == 0:
                _, pos = decode_varint(data, pos)
            elif wire_type == 5:
                pos += 4
            elif wire_type == 1:
                pos += 8

        return ring_data


def main():
    import sys

    if len(sys.argv) < 2:
        print("Usage: python oura_proto_decoder.py <ring_data.pb>")
        sys.exit(1)

    data = open(sys.argv[1], 'rb').read()
    ring_data = RingData.decode(data)

    print("=== Oura Ring Data ===\n")

    if ring_data.ibi_event:
        ibi = ring_data.ibi_event
        print(f"Heart Rate Data:")
        print(f"  IBI measurements: {len(ibi.ibi_ms)}")
        print(f"  Average HR: {ibi.average_hr():.1f} BPM")
        print(f"  RMSSD (HRV): {ibi.rmssd():.1f} ms")
        print()

    if ring_data.sleep_info:
        sleep = ring_data.sleep_info
        print(f"Sleep Info:")
        print(f"  Temperatures: {sleep.temperatures}")
        if sleep.temperatures:
            print(f"  Avg temp: {sum(sleep.temperatures)/len(sleep.temperatures):.2f}°C")
        print()

    print(f"Other fields: {list(ring_data.raw_fields.keys())}")


if __name__ == "__main__":
    main()
```

---

### Phase 2: Auto-Generate .proto from Java

**File: `extract_proto_from_java.py`**

```python
#!/usr/bin/env python3
"""
Extract .proto schema from decompiled Ringeventparser.java
"""

import re
from pathlib import Path
from dataclasses import dataclass
from typing import List, Dict, Optional

@dataclass
class ProtoField:
    name: str
    number: int
    type: str  # int32, int64, float, string, bytes, message
    repeated: bool
    message_type: Optional[str] = None

@dataclass
class ProtoMessage:
    name: str
    fields: List[ProtoField]

def infer_type_from_java(java_type_hint: str, field_name: str) -> tuple[str, bool]:
    """Infer protobuf type from Java code patterns"""

    # Check for list types
    if 'emptyLongList' in java_type_hint or 'k4' in java_type_hint:
        return 'int64', True
    if 'emptyIntList' in java_type_hint or 'h4' in java_type_hint:
        return 'int32', True
    if 'emptyFloatList' in java_type_hint:
        return 'float', True
    if 'emptyProtobufList' in java_type_hint:
        return 'message', True  # Need to find message type

    # Check for scalar types
    if 'long' in java_type_hint.lower():
        return 'int64', False
    if 'int' in java_type_hint.lower():
        return 'int32', False
    if 'float' in java_type_hint.lower():
        return 'float', False
    if 'double' in java_type_hint.lower():
        return 'double', False
    if 'boolean' in java_type_hint.lower():
        return 'bool', False
    if 'String' in java_type_hint:
        return 'string', False
    if 'ByteString' in java_type_hint:
        return 'bytes', False

    return 'bytes', False  # Default

def parse_java_protobuf(java_file: Path) -> Dict[str, ProtoMessage]:
    """Parse Ringeventparser.java to extract message definitions"""

    content = java_file.read_text()
    messages = {}

    # Find all message classes
    class_pattern = r'public static final class (\w+) extends v3 implements \w+OrBuilder \{'
    field_num_pattern = r'public static final int (\w+)_FIELD_NUMBER = (\d+);'
    member_pattern = r'private (\w+) (\w+)_ ='

    current_message = None
    current_fields = {}

    for line in content.split('\n'):
        # Detect new message class
        if match := re.search(class_pattern, line):
            if current_message and current_fields:
                messages[current_message] = ProtoMessage(
                    name=current_message,
                    fields=list(current_fields.values())
                )
            current_message = match.group(1)
            current_fields = {}

        # Detect field number
        if current_message:
            if match := re.search(field_num_pattern, line):
                field_name = match.group(1).lower()
                field_num = int(match.group(2))
                if field_name not in current_fields:
                    current_fields[field_name] = ProtoField(
                        name=field_name,
                        number=field_num,
                        type='unknown',
                        repeated=False
                    )
                else:
                    current_fields[field_name].number = field_num

            # Detect field type from member
            if match := re.search(member_pattern, line):
                java_type = match.group(1)
                field_name = match.group(2)
                if field_name in current_fields:
                    proto_type, repeated = infer_type_from_java(java_type, field_name)
                    current_fields[field_name].type = proto_type
                    current_fields[field_name].repeated = repeated

    # Don't forget last message
    if current_message and current_fields:
        messages[current_message] = ProtoMessage(
            name=current_message,
            fields=list(current_fields.values())
        )

    return messages

def generate_proto(messages: Dict[str, ProtoMessage]) -> str:
    """Generate .proto file content"""

    lines = [
        'syntax = "proto3";',
        '',
        'package oura;',
        '',
    ]

    for name, msg in sorted(messages.items()):
        lines.append(f'message {name} {{')
        for f in sorted(msg.fields, key=lambda x: x.number):
            repeated = 'repeated ' if f.repeated else ''
            lines.append(f'  {repeated}{f.type} {f.name} = {f.number};')
        lines.append('}')
        lines.append('')

    return '\n'.join(lines)

def main():
    java_file = Path('Ringeventparser.java')
    messages = parse_java_protobuf(java_file)
    proto_content = generate_proto(messages)

    Path('ringeventparser.proto').write_text(proto_content)
    print(f"Generated {len(messages)} message types")

if __name__ == "__main__":
    main()
```

---

## Success Metrics

| Metric | Current | Phase 1 | Phase 2 |
|--------|---------|---------|---------|
| Messages decoded | ~5 (manual) | 10 (key health) | 100+ (all) |
| Field types known | Some | Most health fields | All |
| Type safety | None | Dataclasses | Full protobuf |
| Reusability | Low | Medium | High |

---

## Next Steps

1. **Immediate**: Implement Phase 1 Python decoder for key messages
2. **This week**: Build proto extractor for Phase 2
3. **Future**: Port Kotlin processing logic for sleep scores, activity analysis, etc.

---

## Files to Create

| File | Purpose | Phase |
|------|---------|-------|
| `oura_proto_decoder.py` | Python decoder for key messages | 1 |
| `extract_proto_from_java.py` | Generate .proto from Java | 2 |
| `ringeventparser.proto` | Generated proto schema | 2 |
| `oura_pb2.py` | Generated Python protobuf | 2 |
| `health_metrics.py` | HRV, sleep score calculations | 3 |
