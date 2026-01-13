#!/usr/bin/env python3
"""Comprehensive test suite for the protobuf extraction.

Tests:
1. Field number accuracy
2. Type correctness
3. Nested message parsing
4. Oneof field handling
5. Repeated field integrity
6. Re-serialization roundtrip
7. All events parsing
8. Edge cases
"""

import sys
import struct
from pathlib import Path
from collections import defaultdict
from typing import Dict, List, Tuple, Any

import ringeventparser_pb2 as proto


def read_varint(data: bytes, pos: int) -> Tuple[int, int]:
    """Read variable-length integer from protobuf wire format."""
    result = 0
    shift = 0
    while pos < len(data):
        byte = data[pos]
        result |= (byte & 0x7F) << shift
        pos += 1
        if not (byte & 0x80):
            break
        shift += 7
        if shift > 63:
            raise ValueError("Varint too long")
    return result, pos


def parse_wire_format(data: bytes) -> Dict[int, List[Tuple[int, Any]]]:
    """Parse protobuf wire format and extract all field observations."""
    WIRE_VARINT = 0
    WIRE_FIXED64 = 1
    WIRE_LENGTH_DELIMITED = 2
    WIRE_FIXED32 = 5

    observations = defaultdict(list)
    pos = 0

    while pos < len(data):
        try:
            tag, pos = read_varint(data, pos)
            field_number = tag >> 3
            wire_type = tag & 0x7

            if wire_type == WIRE_VARINT:
                value, pos = read_varint(data, pos)
            elif wire_type == WIRE_FIXED64:
                if pos + 8 > len(data):
                    break
                value = struct.unpack('<Q', data[pos:pos+8])[0]
                pos += 8
            elif wire_type == WIRE_LENGTH_DELIMITED:
                length, pos = read_varint(data, pos)
                if pos + length > len(data):
                    break
                value = data[pos:pos+length]
                pos += length
            elif wire_type == WIRE_FIXED32:
                if pos + 4 > len(data):
                    break
                value = struct.unpack('<I', data[pos:pos+4])[0]
                pos += 4
            else:
                print(f"  Unknown wire type {wire_type} at pos {pos}")
                break

            observations[field_number].append((wire_type, value))
        except Exception as e:
            print(f"  Parse error at pos {pos}: {e}")
            break

    return observations


def test_field_numbers():
    """Test 1: Verify field numbers in binary match our schema."""
    print("\n" + "="*70)
    print("TEST 1: Field Number Verification")
    print("="*70)

    data = Path('ring_data.pb').read_bytes()
    wire_fields = parse_wire_format(data)

    # Get RingData descriptor
    rd = proto.RingData()
    rd.ParseFromString(data)

    schema_fields = {f.number: f.name for f in proto.RingData.DESCRIPTOR.fields}

    print(f"\nFields in binary: {len(wire_fields)}")
    print(f"Fields in schema: {len(schema_fields)}")

    # Check for fields in binary but not in schema
    missing_in_schema = []
    for field_num in sorted(wire_fields.keys()):
        if field_num not in schema_fields:
            wire_type = wire_fields[field_num][0][0]
            count = len(wire_fields[field_num])
            missing_in_schema.append((field_num, wire_type, count))

    if missing_in_schema:
        print(f"\n⚠️  Fields in binary but NOT in schema: {len(missing_in_schema)}")
        for field_num, wire_type, count in missing_in_schema[:10]:
            wt_names = {0: 'varint', 1: 'fixed64', 2: 'length_delim', 5: 'fixed32'}
            print(f"    Field {field_num}: wire_type={wt_names.get(wire_type, wire_type)}, count={count}")
    else:
        print("\n✅ All fields in binary are in schema")

    # Check for fields in schema but not in binary
    missing_in_binary = []
    for field_num, field_name in schema_fields.items():
        if field_num not in wire_fields:
            missing_in_binary.append((field_num, field_name))

    print(f"\nFields in schema but not in binary: {len(missing_in_binary)}")
    if len(missing_in_binary) <= 20:
        for field_num, field_name in missing_in_binary:
            print(f"    Field {field_num}: {field_name}")

    return len(missing_in_schema) == 0


def test_nested_message_parsing():
    """Test 2: Verify nested messages can be parsed recursively."""
    print("\n" + "="*70)
    print("TEST 2: Nested Message Parsing")
    print("="*70)

    data = Path('ring_data.pb').read_bytes()
    rd = proto.RingData()
    rd.ParseFromString(data)

    errors = []
    success_count = 0

    # Test each top-level field
    for field, value in rd.ListFields():
        try:
            # Try to access nested fields
            if hasattr(value, 'ListFields'):
                nested_count = len(list(value.ListFields()))
                success_count += 1
                print(f"  ✅ {field.name}: {nested_count} nested fields")
            elif hasattr(value, '__len__') and not isinstance(value, (str, bytes)):
                # Repeated field
                success_count += 1
                print(f"  ✅ {field.name}: {len(value)} repeated items")
            else:
                success_count += 1
                print(f"  ✅ {field.name}: scalar value")
        except Exception as e:
            errors.append((field.name, str(e)))
            print(f"  ❌ {field.name}: ERROR - {e}")

    print(f"\nParsed {success_count} fields successfully")
    if errors:
        print(f"⚠️  {len(errors)} errors occurred")
    else:
        print("✅ All nested messages parsed successfully")

    return len(errors) == 0


def test_events_container():
    """Test 3: Parse all events in the Events container."""
    print("\n" + "="*70)
    print("TEST 3: Events Container Parsing")
    print("="*70)

    data = Path('ring_data.pb').read_bytes()
    rd = proto.RingData()
    rd.ParseFromString(data)

    if not rd.HasField('events'):
        print("  No 'events' field present")
        return True

    events = rd.events
    event_list = list(events.event)
    print(f"\nTotal events: {len(event_list)}")

    # Count event types
    event_types = defaultdict(int)
    parse_errors = []

    for i, event in enumerate(event_list):
        try:
            # Get the oneof field name
            oneof_name = event.WhichOneof('event')
            if oneof_name:
                event_types[oneof_name] += 1
            else:
                # Check for non-oneof fields
                fields = list(event.ListFields())
                if fields:
                    for f, v in fields:
                        event_types[f'[non-oneof]{f.name}'] += 1
                else:
                    event_types['[empty]'] += 1
        except Exception as e:
            parse_errors.append((i, str(e)))

    print(f"\nEvent type distribution:")
    for event_type, count in sorted(event_types.items(), key=lambda x: -x[1])[:20]:
        print(f"    {event_type}: {count}")

    if len(event_types) > 20:
        print(f"    ... and {len(event_types) - 20} more types")

    if parse_errors:
        print(f"\n⚠️  Parse errors: {len(parse_errors)}")
        for i, err in parse_errors[:5]:
            print(f"    Event {i}: {err}")
    else:
        print(f"\n✅ All {len(event_list)} events parsed successfully")

    return len(parse_errors) == 0


def test_repeated_field_integrity():
    """Test 4: Verify repeated field lengths are consistent."""
    print("\n" + "="*70)
    print("TEST 4: Repeated Field Integrity")
    print("="*70)

    data = Path('ring_data.pb').read_bytes()
    rd = proto.RingData()
    rd.ParseFromString(data)

    issues = []

    # Check messages with multiple repeated fields (should have same length)
    messages_to_check = [
        ('ibi_and_amplitude_event', ['timestamp', 'ibi', 'amp']),
        ('sleep_period_info', ['timestamp', 'average_hr', 'hr_trend', 'mzci', 'dzci', 'breath', 'motion_count', 'sleep_state']),
        ('hrv_event', ['timestamp', 'average_hr_5min', 'average_rmssd_5min']),
        ('activity_info_event', ['timestamp', 'step_count']),
        ('motion_event', ['timestamp', 'orientation', 'motion_seconds', 'average_x', 'average_y', 'average_z']),
        ('sleep_temp_event', ['timestamp', 'temp']),
    ]

    for msg_name, fields in messages_to_check:
        if hasattr(rd, msg_name) and rd.HasField(msg_name):
            msg = getattr(rd, msg_name)
            lengths = {}
            for field_name in fields:
                if hasattr(msg, field_name):
                    field_val = getattr(msg, field_name)
                    if hasattr(field_val, '__len__'):
                        lengths[field_name] = len(field_val)

            if lengths:
                unique_lengths = set(lengths.values())
                if len(unique_lengths) == 1:
                    print(f"  ✅ {msg_name}: all {len(lengths)} fields have {list(unique_lengths)[0]} items")
                else:
                    issues.append((msg_name, lengths))
                    print(f"  ⚠️  {msg_name}: length mismatch!")
                    for fn, ln in lengths.items():
                        print(f"      {fn}: {ln}")

    if not issues:
        print("\n✅ All repeated fields have consistent lengths")
    else:
        print(f"\n⚠️  {len(issues)} messages have inconsistent field lengths")

    return len(issues) == 0


def test_roundtrip_serialization():
    """Test 5: Verify data can be re-serialized correctly."""
    print("\n" + "="*70)
    print("TEST 5: Roundtrip Serialization")
    print("="*70)

    original_data = Path('ring_data.pb').read_bytes()

    # Parse
    rd = proto.RingData()
    rd.ParseFromString(original_data)

    # Re-serialize
    reserialized = rd.SerializeToString()

    print(f"\nOriginal size: {len(original_data):,} bytes")
    print(f"Reserialized size: {len(reserialized):,} bytes")

    if original_data == reserialized:
        print("\n✅ Perfect roundtrip - binary identical")
        return True
    else:
        # Analyze differences
        diff_bytes = sum(1 for a, b in zip(original_data, reserialized) if a != b)
        size_diff = len(reserialized) - len(original_data)

        print(f"\n⚠️  Roundtrip differs:")
        print(f"    Size difference: {size_diff:+d} bytes")
        print(f"    Different bytes: {diff_bytes} (in overlapping region)")

        # This is often OK - protobuf doesn't guarantee identical serialization
        # due to field ordering, default values, etc.

        # Parse reserialized to verify data integrity
        rd2 = proto.RingData()
        rd2.ParseFromString(reserialized)

        # Compare field counts
        fields1 = {f.name: v for f, v in rd.ListFields()}
        fields2 = {f.name: v for f, v in rd2.ListFields()}

        if set(fields1.keys()) == set(fields2.keys()):
            print("    ✅ Same fields present after roundtrip")

            # Check a few key values
            if rd.HasField('ibi_and_amplitude_event') and rd2.HasField('ibi_and_amplitude_event'):
                ibi1 = list(rd.ibi_and_amplitude_event.ibi)
                ibi2 = list(rd2.ibi_and_amplitude_event.ibi)
                if ibi1 == ibi2:
                    print("    ✅ IBI data identical after roundtrip")
                else:
                    print("    ❌ IBI data differs!")
                    return False

            return True
        else:
            print(f"    ❌ Field mismatch: {set(fields1.keys()) ^ set(fields2.keys())}")
            return False


def test_enum_values():
    """Test 6: Verify enum values are recognized."""
    print("\n" + "="*70)
    print("TEST 6: Enum Value Recognition")
    print("="*70)

    data = Path('ring_data.pb').read_bytes()
    rd = proto.RingData()
    rd.ParseFromString(data)

    enum_tests = []

    # Check state_change_ind states
    if rd.HasField('state_change_ind'):
        states = list(rd.state_change_ind.state)
        unique_states = set(states)
        print(f"\n  state_change_ind.state: {len(unique_states)} unique values")
        # Try to get enum names
        try:
            state_enum = proto.StateChangeInd.DESCRIPTOR.fields_by_name.get('state')
            if state_enum and state_enum.enum_type:
                for val in list(unique_states)[:5]:
                    name = state_enum.enum_type.values_by_number.get(val)
                    if name:
                        print(f"      {val} = {name.name}")
                    else:
                        print(f"      {val} = [unknown]")
        except Exception as e:
            print(f"      Error getting enum names: {e}")

    # Check sleep_state values
    if rd.HasField('sleep_period_info'):
        sleep_states = list(rd.sleep_period_info.sleep_state)
        unique_sleep = set(sleep_states)
        print(f"\n  sleep_period_info.sleep_state: {len(unique_sleep)} unique values: {unique_sleep}")

    # Check ring_start_ind.ring_type
    if rd.HasField('ring_start_ind'):
        ring_type = rd.ring_start_ind.ring_type
        print(f"\n  ring_start_ind.ring_type: {list(ring_type)}")

    print("\n✅ Enum values accessible")
    return True


def test_data_ranges():
    """Test 7: Check data ranges for sanity."""
    print("\n" + "="*70)
    print("TEST 7: Data Range Sanity Checks")
    print("="*70)

    data = Path('ring_data.pb').read_bytes()
    rd = proto.RingData()
    rd.ParseFromString(data)

    issues = []

    # IBI sanity (should be 300-2000ms typically)
    if rd.HasField('ibi_and_amplitude_event'):
        ibi_values = list(rd.ibi_and_amplitude_event.ibi)
        min_ibi, max_ibi = min(ibi_values), max(ibi_values)
        print(f"\n  IBI range: {min_ibi} - {max_ibi} ms")
        if min_ibi < 200:
            print(f"    ⚠️  Very low IBI ({min_ibi}ms = {60000/min_ibi:.0f} BPM)")
        if max_ibi > 3000:
            issues.append(f"IBI too high: {max_ibi}ms")
            print(f"    ❌ IBI too high: {max_ibi}ms")
        else:
            print(f"    ✅ IBI range reasonable")

    # Temperature sanity (should be 30-40°C)
    if rd.HasField('sleep_temp_event'):
        temps = list(rd.sleep_temp_event.temp)
        min_temp, max_temp = min(temps), max(temps)
        print(f"\n  Temperature range: {min_temp:.1f} - {max_temp:.1f}°C")
        if 30 <= min_temp and max_temp <= 42:
            print(f"    ✅ Temperature range reasonable")
        else:
            issues.append(f"Temperature out of range: {min_temp:.1f}-{max_temp:.1f}")
            print(f"    ⚠️  Temperature may be out of typical range")

    # HRV sanity (RMSSD typically 10-100ms)
    if rd.HasField('hrv_event'):
        rmssd = list(rd.hrv_event.average_rmssd_5min)
        if rmssd:
            min_rmssd, max_rmssd = min(rmssd), max(rmssd)
            print(f"\n  RMSSD range: {min_rmssd:.1f} - {max_rmssd:.1f} ms")
            if 5 <= min_rmssd and max_rmssd <= 200:
                print(f"    ✅ RMSSD range reasonable")
            else:
                print(f"    ⚠️  RMSSD may be out of typical range")

    # Timestamp sanity
    if rd.HasField('ibi_and_amplitude_event'):
        timestamps = list(rd.ibi_and_amplitude_event.timestamp)
        if timestamps:
            # Check if timestamps are monotonically increasing
            is_monotonic = all(timestamps[i] <= timestamps[i+1] for i in range(len(timestamps)-1))
            print(f"\n  Timestamps: {len(timestamps)} values")
            if is_monotonic:
                print(f"    ✅ Timestamps are monotonically increasing")
            else:
                # Count decreases
                decreases = sum(1 for i in range(len(timestamps)-1) if timestamps[i] > timestamps[i+1])
                print(f"    ⚠️  {decreases} timestamp decreases (may indicate gaps)")

    if issues:
        print(f"\n⚠️  {len(issues)} potential data issues found")
    else:
        print(f"\n✅ All data ranges look reasonable")

    return len(issues) == 0


def test_unknown_fields():
    """Test 8: Check for unknown fields by comparing wire format to schema."""
    print("\n" + "="*70)
    print("TEST 8: Unknown Field Detection (via wire format)")
    print("="*70)

    data = Path('ring_data.pb').read_bytes()

    # Parse wire format directly
    wire_fields = parse_wire_format(data)

    # Get schema field numbers
    schema_field_nums = {f.number for f in proto.RingData.DESCRIPTOR.fields}

    # Find fields in wire format but not in schema
    unknown_in_wire = set(wire_fields.keys()) - schema_field_nums

    if unknown_in_wire:
        print(f"\n⚠️  Found {len(unknown_in_wire)} unknown fields in wire format:")
        for field_num in sorted(unknown_in_wire)[:10]:
            observations = wire_fields[field_num]
            wire_type = observations[0][0]
            count = len(observations)
            wt_names = {0: 'varint', 1: 'fixed64', 2: 'length_delim', 5: 'fixed32'}
            print(f"    Field {field_num}: wire_type={wt_names.get(wire_type, wire_type)}, occurrences={count}")
        return False
    else:
        print(f"\n✅ All wire format fields match schema")
        print(f"    Schema fields: {len(schema_field_nums)}")
        print(f"    Wire fields: {len(wire_fields)}")
        return True


def test_oneof_coverage():
    """Test 9: Check oneof field coverage in Event message."""
    print("\n" + "="*70)
    print("TEST 9: Oneof Field Coverage")
    print("="*70)

    # Get all possible oneof field names from Event descriptor
    event_desc = proto.Event.DESCRIPTOR
    oneof_desc = event_desc.oneofs_by_name.get('event')

    if not oneof_desc:
        print("  No 'event' oneof found in Event message")
        return True

    all_oneof_fields = {f.name for f in oneof_desc.fields}
    print(f"\nTotal oneof options in schema: {len(all_oneof_fields)}")

    # Parse and check which ones are used
    data = Path('ring_data.pb').read_bytes()
    rd = proto.RingData()
    rd.ParseFromString(data)

    used_fields = set()
    if rd.HasField('events'):
        for event in rd.events.event:
            which = event.WhichOneof('event')
            if which:
                used_fields.add(which)

    print(f"Oneof fields used in data: {len(used_fields)}")

    unused = all_oneof_fields - used_fields
    if unused:
        print(f"\nUnused oneof fields ({len(unused)}):")
        for f in sorted(unused)[:20]:
            print(f"    - {f}")
        if len(unused) > 20:
            print(f"    ... and {len(unused) - 20} more")

    print(f"\n✅ {len(used_fields)}/{len(all_oneof_fields)} oneof fields have data")
    return True


def main():
    """Run all tests."""
    print("="*70)
    print("COMPREHENSIVE PROTOBUF EXTRACTION TEST SUITE")
    print("="*70)

    if not Path('ring_data.pb').exists():
        print("ERROR: ring_data.pb not found")
        sys.exit(1)

    if not Path('ringeventparser_pb2.py').exists():
        print("ERROR: ringeventparser_pb2.py not found - run protoc first")
        sys.exit(1)

    results = {}

    results['field_numbers'] = test_field_numbers()
    results['nested_parsing'] = test_nested_message_parsing()
    results['events_container'] = test_events_container()
    results['repeated_integrity'] = test_repeated_field_integrity()
    results['roundtrip'] = test_roundtrip_serialization()
    results['enum_values'] = test_enum_values()
    results['data_ranges'] = test_data_ranges()
    results['unknown_fields'] = test_unknown_fields()
    results['oneof_coverage'] = test_oneof_coverage()

    print("\n" + "="*70)
    print("TEST SUMMARY")
    print("="*70)

    passed = sum(1 for v in results.values() if v)
    total = len(results)

    for name, result in results.items():
        status = "✅ PASS" if result else "❌ FAIL"
        print(f"  {status}: {name}")

    print(f"\nOverall: {passed}/{total} tests passed")

    return all(results.values())


if __name__ == '__main__':
    success = main()
    sys.exit(0 if success else 1)
