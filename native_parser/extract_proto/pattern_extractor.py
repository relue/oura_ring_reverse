#!/usr/bin/env python3
"""Extract protobuf patterns using regex on class line ranges.

Phase 2 of the hybrid extraction pipeline.
Uses the class map from Phase 1 to extract patterns within each class's scope.
"""

import re
import json
import sys
from dataclasses import dataclass, field, asdict
from typing import List, Dict, Optional, Tuple, Set
from pathlib import Path


# Fields to EXCLUDE (not protobuf fields)
EXCLUDE_PATTERNS = [
    re.compile(r'MemoizedSerializedSize$'),
    re.compile(r'^bitField\d+_$'),
    re.compile(r'^PARSER$'),
    re.compile(r'^DEFAULT_INSTANCE$'),
    re.compile(r'^memoizedHashCode$'),
    re.compile(r'^memoizedIsInitialized$'),
]


@dataclass
class RawField:
    """Raw field information extracted from Java."""
    name: str                    # e.g., "timestamp"
    number: int                  # e.g., 1
    java_type: Optional[str] = None  # e.g., "k4", "int", "SleepPeriodInfo"
    initializer: Optional[str] = None  # e.g., "emptyLongList"
    accessor_type: Optional[str] = None  # e.g., "Event" for l4 fields


@dataclass
class RawEnum:
    """Raw enum information extracted from Java."""
    name: str
    values: Dict[str, int] = field(default_factory=dict)  # {"DISABLED": 0, "ENABLED": 1}


@dataclass
class RawOneof:
    """Raw oneof information extracted from Java."""
    name: str                   # e.g., "event"
    case_enum: str             # e.g., "EventCase"
    fields: List[Tuple[str, int]] = field(default_factory=list)  # [(field_name, field_number), ...]


@dataclass
class ClassSchema:
    """Schema extracted from a single class."""
    name: str
    qualified_name: str
    is_message: bool
    is_enum: bool
    field_numbers: Dict[int, str] = field(default_factory=dict)  # {1: "timestamp", 2: "ibi"}
    field_types: Dict[str, Tuple[str, Optional[str]]] = field(default_factory=dict)  # {"timestamp": ("k4", "emptyLongList")}
    accessors: Dict[str, str] = field(default_factory=dict)  # {"event": "Event"} for l4 types
    enum_values: Dict[str, int] = field(default_factory=dict)  # {"DISABLED": 0}
    oneofs: List[Dict] = field(default_factory=list)


class PatternExtractor:
    """Extract protobuf patterns from Java source."""

    # Regex patterns
    PATTERNS = {
        # public static final int FIELD_NAME_FIELD_NUMBER = N;
        'field_number': re.compile(
            r'public static final int (\w+)_FIELD_NUMBER = (\d+);'
        ),

        # private k4 fieldName_ = v3.emptyLongList();
        'repeated_field': re.compile(
            r'private (k4|h4|g4|b4|l4) (\w+)_ = v3\.(empty\w+List)\(\);'
        ),

        # private int/long/float/etc fieldName_;
        'scalar_field': re.compile(
            r'private (int|long|float|double|boolean) (\w+)_;'
        ),

        # private String fieldName_ = "";
        'string_field': re.compile(
            r'private String (\w+)_ = "";'
        ),

        # private ByteString fieldName_ = ByteString.EMPTY;
        'bytes_field': re.compile(
            r'private ByteString (\w+)_ = ByteString\.\w+;'
        ),

        # private MessageType fieldName_; (capital letter start, not the types above)
        'message_field': re.compile(
            r'private ([A-Z][a-zA-Z0-9_]+) (\w+)_;'
        ),

        # public List<Type> getFieldNameList()
        'list_accessor': re.compile(
            r'public List<(\w+)> get(\w+)List\(\)'
        ),

        # ENUM_VALUE(N), - at start of line (with whitespace)
        'enum_value': re.compile(
            r'^\s+([A-Z][A-Z0-9_]*)\((-?\d+)\)'
        ),

        # private int fieldCase_ = 0;
        'oneof_case': re.compile(
            r'private int (\w+)Case_ = 0;'
        ),

        # public enum FieldCase {
        'oneof_enum': re.compile(
            r'public enum (\w+)Case \{'
        ),

        # Oneof field in enum: FIELD_NAME(N),
        'oneof_field': re.compile(
            r'^\s+([A-Z][A-Z0-9_]*)\((\d+)\)'
        ),
    }

    def __init__(self, source_path: str, class_map: Dict, verbose: bool = False):
        """Initialize with source file and class map from Phase 1."""
        self.source_path = source_path
        self.class_map = class_map
        self.verbose = verbose

        # Read source file as lines
        with open(source_path, 'r', encoding='utf-8') as f:
            self.lines = f.readlines()

        if verbose:
            print(f"Loaded {len(self.lines)} lines from {source_path}", file=sys.stderr)

    def should_exclude(self, field_name: str) -> bool:
        """Check if a field should be excluded (not a protobuf field)."""
        for pattern in EXCLUDE_PATTERNS:
            if pattern.search(field_name):
                return True
        return False

    def normalize_field_name(self, name: str) -> str:
        """Convert SCREAMING_SNAKE to snake_case."""
        return name.lower()

    def extract_all(self) -> Dict[str, ClassSchema]:
        """Extract patterns from all classes."""
        schemas = {}

        for class_info in self.class_map['classes']:
            # Skip builder classes
            if class_info.get('is_builder'):
                continue

            schema = self.extract_class(class_info)
            if schema:
                schemas[schema.qualified_name] = schema

        return schemas

    def extract_class(self, class_info: Dict) -> Optional[ClassSchema]:
        """Extract patterns from a single class."""
        name = class_info['name']
        qualified_name = class_info['qualified_name']
        start_line = class_info['start_line'] - 1  # Convert to 0-indexed
        end_line = class_info['end_line']
        is_message = class_info.get('is_message', False)
        is_enum = class_info.get('is_enum', False)

        # Get lines for this class
        class_lines = self.lines[start_line:end_line]

        schema = ClassSchema(
            name=name,
            qualified_name=qualified_name,
            is_message=is_message,
            is_enum=is_enum,
        )

        if is_enum:
            # Extract enum values
            schema.enum_values = self._extract_enum_values(class_lines)
            if self.verbose and schema.enum_values:
                print(f"  {name}: {len(schema.enum_values)} enum values", file=sys.stderr)
        elif is_message:
            # Extract message fields
            self._extract_message_fields(class_lines, schema)
            if self.verbose:
                print(f"  {name}: {len(schema.field_numbers)} fields", file=sys.stderr)

        return schema

    def _extract_message_fields(self, lines: List[str], schema: ClassSchema):
        """Extract all field information from a message class."""

        oneof_names = set()  # Track oneof field names to handle specially

        for i, line in enumerate(lines):
            # Skip excluded fields
            if any(p.search(line) for p in EXCLUDE_PATTERNS):
                continue

            # Extract FIELD_NUMBER constants
            if match := self.PATTERNS['field_number'].search(line):
                raw_name = match.group(1)
                number = int(match.group(2))
                name = self.normalize_field_name(raw_name)
                schema.field_numbers[number] = name

            # Extract repeated fields (k4, h4, g4, b4, l4)
            elif match := self.PATTERNS['repeated_field'].search(line):
                java_type = match.group(1)
                field_name = match.group(2)
                initializer = match.group(3)
                if not self.should_exclude(field_name):
                    schema.field_types[field_name] = (java_type, initializer)

            # Extract scalar fields
            elif match := self.PATTERNS['scalar_field'].search(line):
                java_type = match.group(1)
                field_name = match.group(2)
                if not self.should_exclude(field_name):
                    schema.field_types[field_name] = (java_type, None)

            # Extract string fields
            elif match := self.PATTERNS['string_field'].search(line):
                field_name = match.group(1)
                if not self.should_exclude(field_name):
                    schema.field_types[field_name] = ('String', None)

            # Extract bytes fields
            elif match := self.PATTERNS['bytes_field'].search(line):
                field_name = match.group(1)
                if not self.should_exclude(field_name):
                    schema.field_types[field_name] = ('ByteString', None)

            # Extract message reference fields
            elif match := self.PATTERNS['message_field'].search(line):
                java_type = match.group(1)
                field_name = match.group(2)
                # Skip if it's a known non-message type
                if java_type not in ('Object', 'String', 'ByteString') and not self.should_exclude(field_name):
                    # Check if it's not already captured
                    if field_name not in schema.field_types:
                        schema.field_types[field_name] = (java_type, None)

            # Extract List<Type> accessors (for l4 type resolution)
            elif match := self.PATTERNS['list_accessor'].search(line):
                element_type = match.group(1)
                accessor_name = match.group(2)
                field_name = accessor_name[0].lower() + accessor_name[1:]  # camelCase
                # Only record if it's a message type (not primitive wrappers)
                if element_type not in ('Float', 'Integer', 'Long', 'Boolean', 'Double', 'String'):
                    schema.accessors[field_name] = element_type

            # Detect oneof
            elif match := self.PATTERNS['oneof_case'].search(line):
                oneof_name = match.group(1)
                oneof_names.add(oneof_name)

        # Extract oneof field mappings
        for oneof_name in oneof_names:
            oneof_fields = self._extract_oneof_fields(lines, oneof_name)
            if oneof_fields:
                schema.oneofs.append({
                    'name': oneof_name,
                    'case_enum': f'{oneof_name.title()}Case',
                    'fields': oneof_fields,
                })

    def _extract_enum_values(self, lines: List[str]) -> Dict[str, int]:
        """Extract enum values from enum class lines."""
        values = {}
        in_enum_body = False

        for line in lines:
            # Detect enum body start
            if '{' in line and 'enum' in line:
                in_enum_body = True
                continue

            if not in_enum_body:
                continue

            # Stop at enum body declarations (;) or end
            if line.strip().startswith(';') or ('}' in line and '{' not in line):
                break

            # Extract enum value
            if match := self.PATTERNS['enum_value'].match(line):
                name = match.group(1)
                value = int(match.group(2))
                # Skip UNRECOGNIZED sentinel
                if name != 'UNRECOGNIZED':
                    values[name] = value

        return values

    def _extract_oneof_fields(self, lines: List[str], oneof_name: str) -> List[Tuple[str, int]]:
        """Extract oneof field mappings from the case enum."""
        fields = []

        # Look for the case enum
        in_case_enum = False
        case_enum_pattern = re.compile(rf'public enum {oneof_name.title()}Case|public enum {oneof_name}Case')

        for i, line in enumerate(lines):
            if case_enum_pattern.search(line):
                in_case_enum = True
                continue

            if not in_case_enum:
                continue

            # Stop at end of enum
            if line.strip().startswith(';') or ('}' in line and '{' not in line):
                break

            # Extract oneof field
            if match := self.PATTERNS['oneof_field'].match(line):
                field_name = self.normalize_field_name(match.group(1))
                field_num = int(match.group(2))
                # Skip the NOT_SET sentinel
                if not field_name.endswith('_not_set') and field_name != 'not_set':
                    fields.append((field_name, field_num))

        return fields


def extract_patterns(source_path: str, class_map_path: str, output_path: str = None, verbose: bool = False) -> Dict:
    """Main extraction function."""

    # Load class map
    with open(class_map_path, 'r') as f:
        class_map = json.load(f)

    if verbose:
        print(f"Loaded class map with {class_map['total_classes']} classes", file=sys.stderr)

    # Create extractor
    extractor = PatternExtractor(source_path, class_map, verbose=verbose)

    # Extract all patterns
    if verbose:
        print("\nExtracting patterns...", file=sys.stderr)

    schemas = extractor.extract_all()

    # Convert to serializable format
    result = {
        'schemas': {},
        'statistics': {
            'total_classes': len(schemas),
            'messages': 0,
            'enums': 0,
            'total_fields': 0,
            'total_enum_values': 0,
            'oneofs': 0,
        }
    }

    for qname, schema in schemas.items():
        result['schemas'][qname] = {
            'name': schema.name,
            'qualified_name': schema.qualified_name,
            'is_message': schema.is_message,
            'is_enum': schema.is_enum,
            'field_numbers': schema.field_numbers,
            'field_types': {k: list(v) for k, v in schema.field_types.items()},
            'accessors': schema.accessors,
            'enum_values': schema.enum_values,
            'oneofs': schema.oneofs,
        }

        if schema.is_message:
            result['statistics']['messages'] += 1
            result['statistics']['total_fields'] += len(schema.field_numbers)
            result['statistics']['oneofs'] += len(schema.oneofs)
        elif schema.is_enum:
            result['statistics']['enums'] += 1
            result['statistics']['total_enum_values'] += len(schema.enum_values)

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

    parser = argparse.ArgumentParser(description='Extract protobuf patterns from Java')
    parser.add_argument('input', help='Input Java file')
    parser.add_argument('--class-map', required=True, help='Class map JSON from Phase 1')
    parser.add_argument('-o', '--output', help='Output JSON file')
    parser.add_argument('-v', '--verbose', action='store_true', help='Verbose output')

    args = parser.parse_args()

    result = extract_patterns(
        args.input,
        args.class_map,
        args.output,
        verbose=args.verbose
    )

    if not args.output:
        print(json.dumps(result, indent=2))


if __name__ == '__main__':
    main()
