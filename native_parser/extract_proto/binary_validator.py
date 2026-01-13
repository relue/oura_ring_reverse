#!/usr/bin/env python3
"""Validate extracted schema against binary protobuf data.

Phase 4 of the hybrid extraction pipeline.
Parses wire format and validates field numbers and types.
"""

import json
import sys
import struct
from dataclasses import dataclass, field
from typing import Dict, List, Set, Tuple, Any, Optional


# Wire types
WIRE_VARINT = 0
WIRE_FIXED64 = 1
WIRE_LENGTH_DELIMITED = 2
WIRE_START_GROUP = 3  # Deprecated
WIRE_END_GROUP = 4    # Deprecated
WIRE_FIXED32 = 5

WIRE_TYPE_NAMES = {
    0: 'varint',
    1: 'fixed64',
    2: 'length_delimited',
    3: 'start_group',
    4: 'end_group',
    5: 'fixed32',
}

# Wire type → compatible proto types
WIRE_TYPE_COMPATIBLE = {
    WIRE_VARINT: {'int32', 'int64', 'uint32', 'uint64', 'sint32', 'sint64', 'bool', 'enum'},
    WIRE_FIXED64: {'fixed64', 'sfixed64', 'double'},
    WIRE_LENGTH_DELIMITED: {'string', 'bytes', 'message', 'packed'},
    WIRE_FIXED32: {'fixed32', 'sfixed32', 'float'},
}


@dataclass
class FieldObservation:
    """Observed field from binary data."""
    field_number: int
    wire_type: int
    count: int = 0
    sample_values: List[Any] = field(default_factory=list)
    total_bytes: int = 0


@dataclass
class ValidationResult:
    """Result of validating a message."""
    message_name: str
    binary_size: int
    valid_fields: List[Dict] = field(default_factory=list)
    type_mismatches: List[Dict] = field(default_factory=list)
    missing_in_schema: List[Dict] = field(default_factory=list)
    missing_in_binary: List[Dict] = field(default_factory=list)


class BinaryValidator:
    """Parse binary protobuf and validate against schema."""

    def __init__(self, resolved_schema: Dict, verbose: bool = False):
        """Initialize with resolved schema."""
        self.schema = resolved_schema
        self.verbose = verbose

        # Build lookup tables
        self.messages_by_name: Dict[str, Dict] = {}
        for msg in self.schema.get('messages', []):
            self.messages_by_name[msg['name']] = msg

        self.enums_by_name: Set[str] = set()
        for enum in self.schema.get('enums', []):
            self.enums_by_name.add(enum['name'])

    def parse_wire_format(self, data: bytes) -> Dict[int, FieldObservation]:
        """Parse protobuf wire format and collect field observations."""
        observations: Dict[int, FieldObservation] = {}
        pos = 0

        while pos < len(data):
            try:
                # Read tag
                tag, pos = self._read_varint(data, pos)
                field_number = tag >> 3
                wire_type = tag & 0x7

                # Read value based on wire type
                value = None
                value_start = pos

                if wire_type == WIRE_VARINT:
                    value, pos = self._read_varint(data, pos)
                elif wire_type == WIRE_FIXED64:
                    if pos + 8 > len(data):
                        break
                    value = struct.unpack('<Q', data[pos:pos+8])[0]
                    pos += 8
                elif wire_type == WIRE_LENGTH_DELIMITED:
                    length, pos = self._read_varint(data, pos)
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
                    # Unknown wire type - skip
                    if self.verbose:
                        print(f"Unknown wire type {wire_type} at pos {pos}", file=sys.stderr)
                    break

                value_bytes = pos - value_start

                # Record observation
                if field_number not in observations:
                    observations[field_number] = FieldObservation(
                        field_number=field_number,
                        wire_type=wire_type,
                    )

                obs = observations[field_number]
                obs.count += 1
                obs.total_bytes += value_bytes
                if len(obs.sample_values) < 3:
                    if wire_type == WIRE_LENGTH_DELIMITED:
                        # Store length and first few bytes for messages
                        obs.sample_values.append(f"len={len(value)}, first={value[:20].hex() if value else 'empty'}")
                    else:
                        obs.sample_values.append(value)

            except Exception as e:
                if self.verbose:
                    print(f"Parse error at pos {pos}: {e}", file=sys.stderr)
                break

        return observations

    def validate(self, data: bytes, message_name: str = 'RingData') -> ValidationResult:
        """Validate binary data against schema for a message."""

        result = ValidationResult(
            message_name=message_name,
            binary_size=len(data),
        )

        # Parse wire format
        observations = self.parse_wire_format(data)

        # Get message schema
        msg_schema = self.messages_by_name.get(message_name)
        if not msg_schema:
            if self.verbose:
                print(f"Message {message_name} not found in schema", file=sys.stderr)
            return result

        # Build field lookup from schema
        schema_fields: Dict[int, Dict] = {}
        for f in msg_schema.get('fields', []):
            schema_fields[f['number']] = f

        # Also include oneof fields
        for oneof in msg_schema.get('oneofs', []):
            for field_name, field_num, field_type in oneof.get('fields', []):
                schema_fields[field_num] = {
                    'name': field_name,
                    'number': field_num,
                    'proto_type': field_type,
                    'repeated': False,
                    'is_message': True,  # Oneof fields are typically messages
                    'in_oneof': oneof['name'],
                }

        # Validate each observed field
        for field_num, obs in sorted(observations.items()):
            if field_num in schema_fields:
                schema_field = schema_fields[field_num]
                compatible = self._check_wire_type_compatible(
                    obs.wire_type,
                    schema_field.get('proto_type', 'bytes'),
                    schema_field.get('repeated', False),
                    schema_field.get('is_message', False),
                )

                field_info = {
                    'number': field_num,
                    'name': schema_field.get('name', f'field_{field_num}'),
                    'schema_type': schema_field.get('proto_type', 'unknown'),
                    'wire_type': WIRE_TYPE_NAMES.get(obs.wire_type, str(obs.wire_type)),
                    'count': obs.count,
                    'total_bytes': obs.total_bytes,
                }

                if compatible:
                    result.valid_fields.append(field_info)
                else:
                    field_info['expected_wire'] = self._expected_wire_type(schema_field.get('proto_type', 'bytes'))
                    result.type_mismatches.append(field_info)
            else:
                result.missing_in_schema.append({
                    'number': field_num,
                    'wire_type': WIRE_TYPE_NAMES.get(obs.wire_type, str(obs.wire_type)),
                    'count': obs.count,
                    'total_bytes': obs.total_bytes,
                    'samples': obs.sample_values[:2],
                })

        # Find schema fields not in binary
        observed_nums = set(observations.keys())
        for field_num, schema_field in schema_fields.items():
            if field_num not in observed_nums:
                result.missing_in_binary.append({
                    'number': field_num,
                    'name': schema_field.get('name', f'field_{field_num}'),
                    'type': schema_field.get('proto_type', 'unknown'),
                })

        return result

    def _read_varint(self, data: bytes, pos: int) -> Tuple[int, int]:
        """Read variable-length integer."""
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

    def _check_wire_type_compatible(self, wire_type: int, proto_type: str,
                                    repeated: bool, is_message: bool) -> bool:
        """Check if wire type is compatible with proto type."""

        # Length-delimited can be string, bytes, message, or packed repeated
        if wire_type == WIRE_LENGTH_DELIMITED:
            if is_message or proto_type[0].isupper():
                return True
            if proto_type in ('string', 'bytes'):
                return True
            if repeated:
                return True  # Packed repeated
            return False

        # Varint types
        if wire_type == WIRE_VARINT:
            if proto_type in ('int32', 'int64', 'uint32', 'uint64', 'sint32', 'sint64', 'bool'):
                return True
            if proto_type in self.enums_by_name:
                return True
            return False

        # Fixed types
        if wire_type == WIRE_FIXED64:
            return proto_type in ('fixed64', 'sfixed64', 'double')

        if wire_type == WIRE_FIXED32:
            return proto_type in ('fixed32', 'sfixed32', 'float')

        return False

    def _expected_wire_type(self, proto_type: str) -> str:
        """Get expected wire type for a proto type."""
        if proto_type in ('int32', 'int64', 'uint32', 'uint64', 'sint32', 'sint64', 'bool'):
            return 'varint'
        if proto_type in ('fixed64', 'sfixed64', 'double'):
            return 'fixed64'
        if proto_type in ('fixed32', 'sfixed32', 'float'):
            return 'fixed32'
        if proto_type in ('string', 'bytes'):
            return 'length_delimited'
        # Assume message for capitalized types
        if proto_type[0].isupper():
            return 'length_delimited'
        return 'unknown'


def validate_binary(resolved_schema_path: str, binary_path: str,
                   message_name: str = 'RingData',
                   output_path: str = None, verbose: bool = False) -> ValidationResult:
    """Main validation function."""

    # Load schema
    with open(resolved_schema_path, 'r') as f:
        schema = json.load(f)

    # Load binary
    with open(binary_path, 'rb') as f:
        data = f.read()

    if verbose:
        print(f"Loaded schema with {len(schema.get('messages', []))} messages", file=sys.stderr)
        print(f"Loaded binary: {len(data)} bytes", file=sys.stderr)

    # Create validator
    validator = BinaryValidator(schema, verbose=verbose)

    # Validate
    result = validator.validate(data, message_name)

    if verbose:
        print(f"\n=== Validation Results for {message_name} ===", file=sys.stderr)
        print(f"Binary size: {result.binary_size:,} bytes", file=sys.stderr)
        print(f"Valid fields: {len(result.valid_fields)}", file=sys.stderr)
        print(f"Type mismatches: {len(result.type_mismatches)}", file=sys.stderr)
        print(f"Missing in schema: {len(result.missing_in_schema)}", file=sys.stderr)
        print(f"Missing in binary: {len(result.missing_in_binary)}", file=sys.stderr)

        if result.type_mismatches:
            print("\nType mismatches:", file=sys.stderr)
            for m in result.type_mismatches:
                print(f"  Field {m['number']} ({m['name']}): schema={m['schema_type']}, wire={m['wire_type']}", file=sys.stderr)

    # Save output
    if output_path:
        output = {
            'message_name': result.message_name,
            'binary_size': result.binary_size,
            'valid_fields': result.valid_fields,
            'type_mismatches': result.type_mismatches,
            'missing_in_schema': result.missing_in_schema,
            'missing_in_binary': result.missing_in_binary,
            'summary': {
                'valid': len(result.valid_fields),
                'mismatches': len(result.type_mismatches),
                'missing_schema': len(result.missing_in_schema),
                'missing_binary': len(result.missing_in_binary),
                'passed': len(result.type_mismatches) == 0,
            }
        }
        with open(output_path, 'w') as f:
            json.dump(output, f, indent=2)
        if verbose:
            print(f"\nWrote {output_path}", file=sys.stderr)

    return result


def main():
    """CLI entry point."""
    import argparse

    parser = argparse.ArgumentParser(description='Validate schema against binary protobuf')
    parser.add_argument('--schema', required=True, help='Resolved schema JSON from Phase 3')
    parser.add_argument('--binary', required=True, help='Binary protobuf file')
    parser.add_argument('--message', default='RingData', help='Message name to validate')
    parser.add_argument('-o', '--output', help='Output JSON file')
    parser.add_argument('-v', '--verbose', action='store_true', help='Verbose output')

    args = parser.parse_args()

    validate_binary(
        args.schema,
        args.binary,
        args.message,
        args.output,
        verbose=args.verbose
    )


if __name__ == '__main__':
    main()
