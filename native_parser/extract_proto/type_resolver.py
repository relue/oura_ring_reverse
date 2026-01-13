#!/usr/bin/env python3
"""Resolve obfuscated Java types to protobuf types.

Phase 3 of the hybrid extraction pipeline.
Maps k4/h4/g4/l4 to proto types and resolves message references.
"""

import json
import sys
import re
from dataclasses import dataclass, field, asdict
from typing import Dict, List, Optional, Set, Tuple


@dataclass
class ProtoField:
    """Resolved protobuf field."""
    name: str
    number: int
    proto_type: str
    repeated: bool = False
    is_message: bool = False
    is_enum: bool = False


@dataclass
class ProtoEnum:
    """Resolved protobuf enum."""
    name: str
    values: Dict[str, int] = field(default_factory=dict)


@dataclass
class ProtoOneof:
    """Resolved protobuf oneof."""
    name: str
    fields: List[Tuple[str, int, str]] = field(default_factory=list)  # [(name, number, type), ...]


@dataclass
class ProtoMessage:
    """Resolved protobuf message."""
    name: str
    qualified_name: str
    fields: List[ProtoField] = field(default_factory=list)
    enums: List[ProtoEnum] = field(default_factory=list)
    oneofs: List[ProtoOneof] = field(default_factory=list)
    nested_messages: List[str] = field(default_factory=list)


class TypeResolver:
    """Resolve Java types to protobuf types."""

    # Obfuscated → Proto type mapping for repeated fields
    REPEATED_TYPES = {
        'k4': 'int64',    # emptyLongList
        'h4': 'int32',    # emptyIntList
        'g4': 'float',    # emptyFloatList
        'b4': 'bool',     # emptyBooleanList
        'l4': 'MESSAGE',  # resolve from accessor
    }

    # Java → Proto type mapping for scalar fields
    SCALAR_TYPES = {
        'int': 'int32',
        'long': 'int64',
        'float': 'float',
        'double': 'double',
        'boolean': 'bool',
        'String': 'string',
        'ByteString': 'bytes',
    }

    def __init__(self, class_map: Dict, raw_schema: Dict, verbose: bool = False):
        """Initialize with class map and raw schema."""
        self.class_map = class_map
        self.raw_schema = raw_schema
        self.verbose = verbose

        # Build sets for type classification
        self.all_messages: Set[str] = set()
        self.all_enums: Set[str] = set()
        self.nested_messages: Dict[str, str] = {}  # child -> parent

        self._build_type_sets()

    def _build_type_sets(self):
        """Build sets of message and enum names."""
        for class_info in self.class_map['classes']:
            name = class_info['name']
            qualified = class_info['qualified_name']
            parent = class_info.get('parent_class')

            if class_info.get('is_message'):
                self.all_messages.add(name)
                if parent and parent != 'Ringeventparser':
                    self.nested_messages[name] = parent.split('.')[-1]

            if class_info.get('is_enum') and 'd4' in class_info.get('implements', []):
                self.all_enums.add(name)

        if self.verbose:
            print(f"Built type sets: {len(self.all_messages)} messages, {len(self.all_enums)} enums", file=sys.stderr)

    def resolve_all(self) -> Dict:
        """Resolve all schemas."""
        messages = []
        enums = []

        for qualified_name, schema in self.raw_schema['schemas'].items():
            if schema['is_message']:
                msg = self.resolve_message(qualified_name, schema)
                if msg:
                    messages.append(msg)
            elif schema['is_enum']:
                enum = self.resolve_enum(qualified_name, schema)
                if enum:
                    enums.append(enum)

        return {
            'messages': [asdict(m) for m in messages],
            'enums': [asdict(e) for e in enums],
            'statistics': {
                'messages': len(messages),
                'enums': len(enums),
                'total_fields': sum(len(m.fields) for m in messages),
                'total_oneof_fields': sum(sum(len(o.fields) for o in m.oneofs) for m in messages),
            }
        }

    def resolve_message(self, qualified_name: str, schema: Dict) -> Optional[ProtoMessage]:
        """Resolve a single message."""
        name = schema['name']
        field_numbers = schema.get('field_numbers', {})
        field_types = schema.get('field_types', {})
        accessors = schema.get('accessors', {})
        raw_oneofs = schema.get('oneofs', [])

        # Build set of oneof field numbers
        oneof_field_nums = set()
        for oneof in raw_oneofs:
            for field_name, field_num in oneof.get('fields', []):
                oneof_field_nums.add(field_num)

        # Resolve regular fields (not in oneof)
        fields = []
        for num_str, field_name in field_numbers.items():
            num = int(num_str)

            # Skip if this field is part of a oneof
            if num in oneof_field_nums:
                continue

            proto_type, repeated, is_msg, is_enum = self._resolve_field_type(
                field_name, field_types, accessors
            )

            fields.append(ProtoField(
                name=field_name,
                number=num,
                proto_type=proto_type,
                repeated=repeated,
                is_message=is_msg,
                is_enum=is_enum,
            ))

        # Sort by field number
        fields.sort(key=lambda f: f.number)

        # Resolve oneofs
        oneofs = []
        for raw_oneof in raw_oneofs:
            oneof_name = raw_oneof['name']
            oneof_fields = []

            for field_name, field_num in raw_oneof.get('fields', []):
                # Infer type from field name (snake_case -> PascalCase)
                proto_type = self._infer_message_type(field_name)
                oneof_fields.append((field_name, field_num, proto_type))

            oneofs.append(ProtoOneof(
                name=oneof_name,
                fields=oneof_fields,
            ))

        # Find nested messages
        nested = []
        for msg_name in self.all_messages:
            if self.nested_messages.get(msg_name) == name:
                nested.append(msg_name)

        return ProtoMessage(
            name=name,
            qualified_name=qualified_name,
            fields=fields,
            enums=[],  # Nested enums handled separately
            oneofs=oneofs,
            nested_messages=nested,
        )

    def resolve_enum(self, qualified_name: str, schema: Dict) -> Optional[ProtoEnum]:
        """Resolve a single enum."""
        name = schema['name']
        values = schema.get('enum_values', {})

        if not values:
            return None

        return ProtoEnum(
            name=name,
            values=values,
        )

    def _resolve_field_type(self, field_name: str, field_types: Dict,
                           accessors: Dict) -> Tuple[str, bool, bool, bool]:
        """Resolve a field's protobuf type.

        Returns: (proto_type, is_repeated, is_message, is_enum)
        """
        # Convert snake_case field name to camelCase for lookup
        camel_name = self._to_camel(field_name)

        # Look up type info
        type_info = field_types.get(field_name) or field_types.get(camel_name)

        if type_info:
            java_type = type_info[0]
            initializer = type_info[1] if len(type_info) > 1 else None

            # Repeated primitive types
            if java_type in self.REPEATED_TYPES:
                proto_type = self.REPEATED_TYPES[java_type]

                # For l4 (repeated message), get type from accessor
                if proto_type == 'MESSAGE':
                    accessor_type = accessors.get(field_name) or accessors.get(camel_name)
                    if accessor_type:
                        proto_type = accessor_type
                    else:
                        # Fallback: infer from field name
                        proto_type = self._infer_message_type(field_name)

                is_msg = proto_type in self.all_messages
                is_enum = proto_type in self.all_enums
                return (proto_type, True, is_msg, is_enum)

            # Scalar primitive types
            if java_type in self.SCALAR_TYPES:
                return (self.SCALAR_TYPES[java_type], False, False, False)

            # Message or Enum reference (starts with capital)
            if java_type[0].isupper() and java_type not in ('Object',):
                is_msg = java_type in self.all_messages
                is_enum = java_type in self.all_enums
                return (java_type, False, is_msg, is_enum)

        # No type info - try to infer from field name
        inferred_type = self._infer_message_type(field_name)
        if inferred_type in self.all_messages:
            return (inferred_type, False, True, False)
        if inferred_type in self.all_enums:
            return (inferred_type, False, False, True)

        # Default to bytes if we can't determine type
        return ('bytes', False, False, False)

    def _to_camel(self, snake_name: str) -> str:
        """Convert snake_case to camelCase."""
        parts = snake_name.split('_')
        return parts[0] + ''.join(p.title() for p in parts[1:])

    def _infer_message_type(self, field_name: str) -> str:
        """Infer message type from field name (snake_case -> PascalCase)."""
        return ''.join(p.title() for p in field_name.split('_'))


def resolve_types(class_map_path: str, raw_schema_path: str,
                  output_path: str = None, verbose: bool = False) -> Dict:
    """Main type resolution function."""

    # Load inputs
    with open(class_map_path, 'r') as f:
        class_map = json.load(f)

    with open(raw_schema_path, 'r') as f:
        raw_schema = json.load(f)

    if verbose:
        print(f"Loaded class map with {class_map['total_classes']} classes", file=sys.stderr)
        print(f"Loaded raw schema with {len(raw_schema['schemas'])} schemas", file=sys.stderr)

    # Create resolver
    resolver = TypeResolver(class_map, raw_schema, verbose=verbose)

    # Resolve all types
    if verbose:
        print("\nResolving types...", file=sys.stderr)

    result = resolver.resolve_all()

    if verbose:
        print(f"\nStatistics:", file=sys.stderr)
        for k, v in result['statistics'].items():
            print(f"  {k}: {v}", file=sys.stderr)

    # Save output
    if output_path:
        with open(output_path, 'w') as f:
            json.dump(result, f, indent=2)
        if verbose:
            print(f"\nWrote {output_path}", file=sys.stderr)

    return result


def main():
    """CLI entry point."""
    import argparse

    parser = argparse.ArgumentParser(description='Resolve Java types to protobuf types')
    parser.add_argument('--class-map', required=True, help='Class map JSON from Phase 1')
    parser.add_argument('--raw-schema', required=True, help='Raw schema JSON from Phase 2')
    parser.add_argument('-o', '--output', help='Output JSON file')
    parser.add_argument('-v', '--verbose', action='store_true', help='Verbose output')

    args = parser.parse_args()

    result = resolve_types(
        args.class_map,
        args.raw_schema,
        args.output,
        verbose=args.verbose
    )

    if not args.output:
        print(json.dumps(result, indent=2))


if __name__ == '__main__':
    main()
