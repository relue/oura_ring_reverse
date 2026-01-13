#!/usr/bin/env python3
"""Parse Ringeventparser.java using tree-sitter for robust structure extraction.

Phase 1 of the hybrid extraction pipeline.
Extracts class hierarchy, nested classes, and line ranges for each class.
"""

import tree_sitter_java as tsjava
from tree_sitter import Language, Parser
from dataclasses import dataclass, field, asdict
from typing import List, Dict, Optional
import json
import sys


@dataclass
class ClassInfo:
    """Information about a Java class."""
    name: str
    qualified_name: str  # e.g., "Ringeventparser.Event.Builder"
    parent_class: Optional[str]
    extends: Optional[str]  # e.g., "v3" for messages
    implements: List[str] = field(default_factory=list)
    start_line: int = 0
    end_line: int = 0
    start_byte: int = 0
    end_byte: int = 0
    is_enum: bool = False
    is_message: bool = False  # True if extends v3
    is_builder: bool = False  # True if extends p3 (Builder class)


def get_node_text(node, source: bytes) -> str:
    """Extract text from a tree-sitter node."""
    return source[node.start_byte:node.end_byte].decode('utf-8')


def find_child_by_type(node, type_name: str):
    """Find first child node of given type."""
    for child in node.children:
        if child.type == type_name:
            return child
    return None


def find_children_by_type(node, type_name: str) -> list:
    """Find all children of given type."""
    return [child for child in node.children if child.type == type_name]


def extract_class_info(node, source: bytes, parent_qualified: Optional[str]) -> ClassInfo:
    """Extract class information from a class_declaration node."""

    # Get class name
    name_node = find_child_by_type(node, 'identifier')
    name = get_node_text(name_node, source) if name_node else "Unknown"

    # Build qualified name
    if parent_qualified:
        qualified_name = f"{parent_qualified}.{name}"
    else:
        qualified_name = name

    # Get superclass (extends)
    extends = None
    superclass_node = find_child_by_type(node, 'superclass')
    if superclass_node:
        type_node = find_child_by_type(superclass_node, 'type_identifier')
        if type_node:
            extends = get_node_text(type_node, source)

    # Get interfaces (implements)
    implements = []
    interfaces_node = find_child_by_type(node, 'super_interfaces')
    if interfaces_node:
        for child in interfaces_node.children:
            if child.type == 'type_identifier':
                implements.append(get_node_text(child, source))

    # Determine if this is a protobuf message class
    is_message = extends == 'v3'
    is_builder = extends == 'p3'

    return ClassInfo(
        name=name,
        qualified_name=qualified_name,
        parent_class=parent_qualified,
        extends=extends,
        implements=implements,
        start_line=node.start_point[0] + 1,  # 1-indexed
        end_line=node.end_point[0] + 1,
        start_byte=node.start_byte,
        end_byte=node.end_byte,
        is_enum=False,
        is_message=is_message,
        is_builder=is_builder,
    )


def extract_enum_info(node, source: bytes, parent_qualified: Optional[str]) -> ClassInfo:
    """Extract enum information from an enum_declaration node."""

    # Get enum name
    name_node = find_child_by_type(node, 'identifier')
    name = get_node_text(name_node, source) if name_node else "Unknown"

    # Build qualified name
    if parent_qualified:
        qualified_name = f"{parent_qualified}.{name}"
    else:
        qualified_name = name

    # Get interfaces (implements d4 for protobuf enums)
    implements = []
    interfaces_node = find_child_by_type(node, 'super_interfaces')
    if interfaces_node:
        # Look for type_list first (tree-sitter nests type_identifier inside type_list)
        type_list = find_child_by_type(interfaces_node, 'type_list')
        if type_list:
            for child in type_list.children:
                if child.type == 'type_identifier':
                    implements.append(get_node_text(child, source))
        else:
            # Fallback to direct children
            for child in interfaces_node.children:
                if child.type == 'type_identifier':
                    implements.append(get_node_text(child, source))

    # Check if this is a protobuf enum (implements d4)
    is_protobuf_enum = 'd4' in implements

    return ClassInfo(
        name=name,
        qualified_name=qualified_name,
        parent_class=parent_qualified,
        extends=None,
        implements=implements,
        start_line=node.start_point[0] + 1,
        end_line=node.end_point[0] + 1,
        start_byte=node.start_byte,
        end_byte=node.end_byte,
        is_enum=True,
        is_message=False,
        is_builder=False,
    )


def parse_java_file(filepath: str, verbose: bool = False) -> Dict:
    """Parse Java file and extract structural information.

    Returns a dictionary with:
    - classes: List of ClassInfo dictionaries
    - total_classes: Total count
    - messages: Count of message classes (extends v3)
    - enums: Count of enum classes
    """

    # Initialize parser with Java language
    JAVA_LANGUAGE = Language(tsjava.language())
    parser = Parser(JAVA_LANGUAGE)

    # Read and parse source
    if verbose:
        print(f"Reading {filepath}...", file=sys.stderr)

    with open(filepath, 'rb') as f:
        source = f.read()

    if verbose:
        print(f"Parsing {len(source)} bytes...", file=sys.stderr)

    tree = parser.parse(source)

    classes: List[ClassInfo] = []

    def walk_tree(node, parent_qualified: Optional[str] = None, depth: int = 0):
        """Recursively walk tree to find class and enum declarations."""

        if node.type == 'class_declaration':
            class_info = extract_class_info(node, source, parent_qualified)
            classes.append(class_info)

            if verbose and class_info.is_message:
                print(f"  Found message: {class_info.name} (lines {class_info.start_line}-{class_info.end_line})", file=sys.stderr)

            # Process class body for nested classes
            class_body = find_child_by_type(node, 'class_body')
            if class_body:
                for child in class_body.children:
                    walk_tree(child, class_info.qualified_name, depth + 1)

        elif node.type == 'enum_declaration':
            enum_info = extract_enum_info(node, source, parent_qualified)
            classes.append(enum_info)

            if verbose and 'd4' in enum_info.implements:
                print(f"  Found enum: {enum_info.name}", file=sys.stderr)

            # Enums can have nested classes too
            enum_body = find_child_by_type(node, 'enum_body')
            if enum_body:
                for child in enum_body.children:
                    walk_tree(child, enum_info.qualified_name, depth + 1)

        else:
            # Continue walking for other node types
            for child in node.children:
                walk_tree(child, parent_qualified, depth)

    # Start walking from root
    walk_tree(tree.root_node)

    # Count statistics
    messages = [c for c in classes if c.is_message]
    enums = [c for c in classes if c.is_enum and 'd4' in c.implements]
    builders = [c for c in classes if c.is_builder]

    if verbose:
        print(f"\nExtracted:", file=sys.stderr)
        print(f"  Total classes/enums: {len(classes)}", file=sys.stderr)
        print(f"  Message classes (extends v3): {len(messages)}", file=sys.stderr)
        print(f"  Protobuf enums (implements d4): {len(enums)}", file=sys.stderr)
        print(f"  Builder classes (extends p3): {len(builders)}", file=sys.stderr)

    return {
        'classes': [asdict(c) for c in classes],
        'total_classes': len(classes),
        'message_count': len(messages),
        'enum_count': len(enums),
        'builder_count': len(builders),
        'source_bytes': len(source),
    }


def main():
    """CLI entry point."""
    import argparse

    parser = argparse.ArgumentParser(description='Parse Java file with tree-sitter')
    parser.add_argument('input', help='Input Java file')
    parser.add_argument('-o', '--output', help='Output JSON file (default: stdout)')
    parser.add_argument('-v', '--verbose', action='store_true', help='Verbose output')

    args = parser.parse_args()

    result = parse_java_file(args.input, verbose=args.verbose)

    output = json.dumps(result, indent=2)

    if args.output:
        with open(args.output, 'w') as f:
            f.write(output)
        print(f"Wrote {args.output}", file=sys.stderr)
    else:
        print(output)


if __name__ == '__main__':
    main()
