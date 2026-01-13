#!/usr/bin/env python3
"""Generate .proto file from resolved schema.

Phase 5 of the hybrid extraction pipeline.
Generates syntactically correct proto3 file with proper ordering.
"""

import json
import sys
from typing import Dict, List, Set, Tuple
from collections import defaultdict


class ProtoGenerator:
    """Generate .proto file from resolved schema."""

    # Types that need to be mapped to proto builtins
    TYPE_MAPPINGS = {
        'ByteString': 'bytes',
        'String': 'string',
        'Object': 'bytes',
    }

    def __init__(self, resolved_schema: Dict, verbose: bool = False):
        """Initialize with resolved schema."""
        self.schema = resolved_schema
        self.verbose = verbose

        # Build lookup tables
        self.messages = {m['name']: m for m in self.schema.get('messages', [])}
        self.enums = {e['name']: e for e in self.schema.get('enums', [])}

        # Track which types have been generated
        self.generated: Set[str] = set()

        # Track all enum values for collision detection
        self.all_enum_values: Set[str] = set()
        self._find_enum_collisions()

    def generate(self, package: str = 'oura.ringeventparser') -> str:
        """Generate complete .proto file."""
        lines = [
            'syntax = "proto3";',
            '',
            f'package {package};',
            '',
            '// Auto-generated from decompiled Ringeventparser.java',
            '// Using hybrid tree-sitter + regex extraction pipeline',
            '',
        ]

        # Generate enums first (no dependencies)
        if self.verbose:
            print(f"Generating {len(self.enums)} enums...", file=sys.stderr)

        for name in sorted(self.enums.keys()):
            if name not in self.generated:
                lines.extend(self._generate_enum(name))
                lines.append('')

        # Topological sort messages by dependencies
        if self.verbose:
            print(f"Sorting {len(self.messages)} messages by dependencies...", file=sys.stderr)

        sorted_messages = self._topological_sort()

        # Generate messages in dependency order
        if self.verbose:
            print(f"Generating messages...", file=sys.stderr)

        for name in sorted_messages:
            if name not in self.generated:
                lines.extend(self._generate_message(name))
                lines.append('')

        return '\n'.join(lines)

    def _find_enum_collisions(self):
        """Find enum values that appear in multiple enums (need prefixing)."""
        value_counts: Dict[str, int] = defaultdict(int)
        for enum in self.enums.values():
            for value_name in enum['values'].keys():
                value_counts[value_name] += 1

        # Values that appear more than once need prefixing
        self.colliding_values = {v for v, count in value_counts.items() if count > 1}

        if self.verbose and self.colliding_values:
            print(f"Found {len(self.colliding_values)} colliding enum values that need prefixing", file=sys.stderr)

    def _generate_enum(self, name: str) -> List[str]:
        """Generate enum definition."""
        if name in self.generated:
            return []

        enum = self.enums.get(name)
        if not enum:
            return []

        self.generated.add(name)

        lines = [f'enum {name} {{']

        # Sort by value to maintain order
        sorted_values = sorted(enum['values'].items(), key=lambda x: x[1])

        # Create prefix from enum name (e.g., PPGChannelPDMask -> PCPM_)
        prefix = self._make_enum_prefix(name)

        for value_name, value_num in sorted_values:
            # Prefix if this value collides with another enum
            if value_name in self.colliding_values:
                prefixed_name = f'{prefix}{value_name}'
            else:
                prefixed_name = value_name
            lines.append(f'  {prefixed_name} = {value_num};')

        lines.append('}')
        return lines

    def _make_enum_prefix(self, enum_name: str) -> str:
        """Create a prefix from enum name (e.g., PPGChannelPDMask -> PCPM_)."""
        # Extract capital letters and digits
        prefix = ''.join(c for c in enum_name if c.isupper() or c.isdigit())
        # If too short, use first few chars
        if len(prefix) < 2:
            prefix = enum_name[:4].upper()
        return prefix + '_'

    def _generate_message(self, name: str) -> List[str]:
        """Generate message definition."""
        if name in self.generated:
            return []

        msg = self.messages.get(name)
        if not msg:
            return []

        self.generated.add(name)

        lines = [f'message {name} {{']

        # Collect oneof field numbers
        oneof_field_nums: Set[int] = set()
        for oneof in msg.get('oneofs', []):
            for field_name, field_num, field_type in oneof.get('fields', []):
                oneof_field_nums.add(field_num)

        # Generate regular fields (not in oneof)
        regular_fields = [f for f in msg.get('fields', []) if f['number'] not in oneof_field_nums]

        for field in sorted(regular_fields, key=lambda f: f['number']):
            lines.append(self._format_field(field))

        # Generate oneofs
        for oneof in msg.get('oneofs', []):
            lines.append(f'  oneof {oneof["name"]} {{')

            # Sort oneof fields by number
            sorted_fields = sorted(oneof.get('fields', []), key=lambda x: x[1])

            for field_name, field_num, field_type in sorted_fields:
                resolved_type = self._resolve_type(field_type)
                lines.append(f'    {resolved_type} {field_name} = {field_num};')

            lines.append('  }')

        lines.append('}')
        return lines

    def _format_field(self, field: Dict) -> str:
        """Format a single field definition."""
        repeated = 'repeated ' if field.get('repeated', False) else ''
        proto_type = self._resolve_type(field.get('proto_type', 'bytes'))
        name = field.get('name', 'unknown')
        number = field.get('number', 0)

        return f'  {repeated}{proto_type} {name} = {number};'

    def _resolve_type(self, proto_type: str) -> str:
        """Resolve a type name to a valid proto type."""
        # Check for known mappings
        if proto_type in self.TYPE_MAPPINGS:
            return self.TYPE_MAPPINGS[proto_type]

        # Check if it's a known message or enum
        if proto_type in self.messages or proto_type in self.enums:
            return proto_type

        # Check if it's a proto primitive
        primitives = {'int32', 'int64', 'uint32', 'uint64', 'sint32', 'sint64',
                      'fixed32', 'fixed64', 'sfixed32', 'sfixed64',
                      'float', 'double', 'bool', 'string', 'bytes'}
        if proto_type in primitives:
            return proto_type

        # Unknown type - use bytes as fallback
        if self.verbose:
            print(f"  Unknown type '{proto_type}', using bytes", file=sys.stderr)
        return 'bytes'

    def _topological_sort(self) -> List[str]:
        """Sort messages by dependencies (referenced messages first)."""
        # Build dependency graph
        deps: Dict[str, Set[str]] = defaultdict(set)

        for name, msg in self.messages.items():
            # Check field types
            for field in msg.get('fields', []):
                field_type = field.get('proto_type', '')
                if field_type in self.messages and field_type != name:
                    deps[name].add(field_type)

            # Check oneof field types
            for oneof in msg.get('oneofs', []):
                for field_name, field_num, field_type in oneof.get('fields', []):
                    if field_type in self.messages and field_type != name:
                        deps[name].add(field_type)

        # Kahn's algorithm for topological sort
        in_degree: Dict[str, int] = defaultdict(int)
        for name in self.messages:
            for dep in deps[name]:
                in_degree[name] += 1

        # Start with nodes that have no dependencies
        queue = [name for name in self.messages if in_degree[name] == 0]
        result = []

        while queue:
            # Sort queue for deterministic output
            queue.sort()
            name = queue.pop(0)
            result.append(name)

            # For each message that depends on this one
            for other_name in self.messages:
                if name in deps[other_name]:
                    in_degree[other_name] -= 1
                    if in_degree[other_name] == 0:
                        queue.append(other_name)

        # Handle cycles - add remaining messages
        remaining = [name for name in self.messages if name not in result]
        if remaining:
            if self.verbose:
                print(f"Warning: {len(remaining)} messages may have circular dependencies", file=sys.stderr)
            result.extend(sorted(remaining))

        return result


def generate_proto(resolved_schema_path: str, output_path: str = None,
                  package: str = 'oura.ringeventparser',
                  verbose: bool = False) -> str:
    """Main proto generation function."""

    # Load schema
    with open(resolved_schema_path, 'r') as f:
        schema = json.load(f)

    if verbose:
        print(f"Loaded schema with {len(schema.get('messages', []))} messages, {len(schema.get('enums', []))} enums", file=sys.stderr)

    # Create generator
    generator = ProtoGenerator(schema, verbose=verbose)

    # Generate proto
    proto_content = generator.generate(package)

    # Count lines
    line_count = len(proto_content.split('\n'))
    if verbose:
        print(f"Generated {line_count} lines of proto", file=sys.stderr)

    # Save output
    if output_path:
        with open(output_path, 'w') as f:
            f.write(proto_content)
        if verbose:
            print(f"Wrote {output_path}", file=sys.stderr)

    return proto_content


def main():
    """CLI entry point."""
    import argparse

    parser = argparse.ArgumentParser(description='Generate .proto file from resolved schema')
    parser.add_argument('--schema', required=True, help='Resolved schema JSON from Phase 3')
    parser.add_argument('-o', '--output', help='Output .proto file')
    parser.add_argument('--package', default='oura.ringeventparser', help='Proto package name')
    parser.add_argument('-v', '--verbose', action='store_true', help='Verbose output')

    args = parser.parse_args()

    proto = generate_proto(
        args.schema,
        args.output,
        args.package,
        verbose=args.verbose
    )

    if not args.output:
        print(proto)


if __name__ == '__main__':
    main()
