#!/usr/bin/env python3
"""Main orchestrator for the protobuf extraction pipeline.

Runs all phases in sequence:
  Phase 1: tree-sitter structural parsing
  Phase 2: regex pattern extraction
  Phase 3: type resolution
  Phase 4: binary validation
  Phase 5: proto generation
"""

import argparse
import json
import sys
from pathlib import Path

# Import phase modules
from tree_sitter_parser import parse_java_file
from pattern_extractor import extract_patterns
from type_resolver import resolve_types
from binary_validator import validate_binary
from proto_generator import generate_proto


def run_pipeline(java_path: str, binary_path: str = None,
                 output_dir: str = None, proto_output: str = None,
                 package: str = 'oura.ringeventparser',
                 verbose: bool = False) -> dict:
    """Run the complete extraction pipeline."""

    # Set up paths
    java_path = Path(java_path)
    if output_dir:
        output_dir = Path(output_dir)
        output_dir.mkdir(parents=True, exist_ok=True)
    else:
        output_dir = Path('intermediate')
        output_dir.mkdir(exist_ok=True)

    results = {
        'phases': {},
        'success': False,
    }

    # =========================================================================
    # Phase 1: tree-sitter structural parsing
    # =========================================================================
    print("\n" + "=" * 60, file=sys.stderr)
    print("PHASE 1: tree-sitter Structural Parsing", file=sys.stderr)
    print("=" * 60, file=sys.stderr)

    class_map_path = output_dir / 'class_map.json'
    try:
        class_map = parse_java_file(str(java_path), str(class_map_path), verbose=verbose)
        results['phases']['phase1'] = {
            'status': 'success',
            'output': str(class_map_path),
            'total_classes': class_map['total_classes'],
            'messages': class_map['summary']['messages'],
            'enums': class_map['summary']['enums'],
        }
        print(f"\nPhase 1 complete: {class_map['total_classes']} classes extracted", file=sys.stderr)
    except Exception as e:
        results['phases']['phase1'] = {'status': 'error', 'error': str(e)}
        print(f"Phase 1 FAILED: {e}", file=sys.stderr)
        return results

    # =========================================================================
    # Phase 2: Regex pattern extraction
    # =========================================================================
    print("\n" + "=" * 60, file=sys.stderr)
    print("PHASE 2: Regex Pattern Extraction", file=sys.stderr)
    print("=" * 60, file=sys.stderr)

    raw_schema_path = output_dir / 'raw_schema.json'
    try:
        raw_schema = extract_patterns(
            str(java_path),
            str(class_map_path),
            str(raw_schema_path),
            verbose=verbose
        )
        results['phases']['phase2'] = {
            'status': 'success',
            'output': str(raw_schema_path),
            'statistics': raw_schema['statistics'],
        }
        print(f"\nPhase 2 complete: {raw_schema['statistics']['total_fields']} fields extracted", file=sys.stderr)
    except Exception as e:
        results['phases']['phase2'] = {'status': 'error', 'error': str(e)}
        print(f"Phase 2 FAILED: {e}", file=sys.stderr)
        return results

    # =========================================================================
    # Phase 3: Type resolution
    # =========================================================================
    print("\n" + "=" * 60, file=sys.stderr)
    print("PHASE 3: Type Resolution", file=sys.stderr)
    print("=" * 60, file=sys.stderr)

    resolved_schema_path = output_dir / 'resolved_schema.json'
    try:
        resolved_schema = resolve_types(
            str(class_map_path),
            str(raw_schema_path),
            str(resolved_schema_path),
            verbose=verbose
        )
        results['phases']['phase3'] = {
            'status': 'success',
            'output': str(resolved_schema_path),
            'statistics': resolved_schema['statistics'],
        }
        print(f"\nPhase 3 complete: {resolved_schema['statistics']['messages']} messages resolved", file=sys.stderr)
    except Exception as e:
        results['phases']['phase3'] = {'status': 'error', 'error': str(e)}
        print(f"Phase 3 FAILED: {e}", file=sys.stderr)
        return results

    # =========================================================================
    # Phase 4: Binary validation (optional)
    # =========================================================================
    if binary_path:
        print("\n" + "=" * 60, file=sys.stderr)
        print("PHASE 4: Binary Validation", file=sys.stderr)
        print("=" * 60, file=sys.stderr)

        validation_path = output_dir / 'validation_report.json'
        try:
            validation = validate_binary(
                str(resolved_schema_path),
                str(binary_path),
                'RingData',
                str(validation_path),
                verbose=verbose
            )
            results['phases']['phase4'] = {
                'status': 'success',
                'output': str(validation_path),
                'valid_fields': len(validation.valid_fields),
                'type_mismatches': len(validation.type_mismatches),
                'passed': len(validation.type_mismatches) == 0,
            }
            if validation.type_mismatches:
                print(f"\nPhase 4 WARNING: {len(validation.type_mismatches)} type mismatches!", file=sys.stderr)
            else:
                print(f"\nPhase 4 complete: Validation PASSED", file=sys.stderr)
        except Exception as e:
            results['phases']['phase4'] = {'status': 'error', 'error': str(e)}
            print(f"Phase 4 FAILED: {e}", file=sys.stderr)
            # Continue anyway - validation is optional

    # =========================================================================
    # Phase 5: Proto generation
    # =========================================================================
    print("\n" + "=" * 60, file=sys.stderr)
    print("PHASE 5: Proto Generation", file=sys.stderr)
    print("=" * 60, file=sys.stderr)

    if proto_output:
        proto_path = Path(proto_output)
    else:
        proto_path = Path('ringeventparser.proto')

    try:
        proto_content = generate_proto(
            str(resolved_schema_path),
            str(proto_path),
            package=package,
            verbose=verbose
        )
        line_count = len(proto_content.split('\n'))
        results['phases']['phase5'] = {
            'status': 'success',
            'output': str(proto_path),
            'lines': line_count,
        }
        print(f"\nPhase 5 complete: Generated {line_count} lines of proto", file=sys.stderr)
    except Exception as e:
        results['phases']['phase5'] = {'status': 'error', 'error': str(e)}
        print(f"Phase 5 FAILED: {e}", file=sys.stderr)
        return results

    # =========================================================================
    # Summary
    # =========================================================================
    print("\n" + "=" * 60, file=sys.stderr)
    print("PIPELINE COMPLETE", file=sys.stderr)
    print("=" * 60, file=sys.stderr)

    results['success'] = True
    results['output'] = str(proto_path)

    print(f"\nGenerated: {proto_path}", file=sys.stderr)
    print(f"\nNext steps:", file=sys.stderr)
    print(f"  1. Compile with protoc:", file=sys.stderr)
    print(f"     protoc --python_out=. {proto_path}", file=sys.stderr)
    print(f"  2. Use in Python:", file=sys.stderr)
    print(f"     from ringeventparser_pb2 import RingData", file=sys.stderr)
    print(f"     data = RingData()", file=sys.stderr)
    print(f"     data.ParseFromString(open('ring_data.pb', 'rb').read())", file=sys.stderr)

    return results


def main():
    """CLI entry point."""
    parser = argparse.ArgumentParser(
        description='Extract protobuf schema from decompiled Java',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Example:
  python main.py \\
    --input Ringeventparser.java \\
    --binary ring_data.pb \\
    --output ringeventparser.proto

Phases:
  1. tree-sitter parsing   - Extract class structure
  2. Pattern extraction    - Find field numbers and types
  3. Type resolution       - Map Java types to proto types
  4. Binary validation     - Validate against actual data
  5. Proto generation      - Generate .proto file
        """
    )

    parser.add_argument(
        '--input', '-i',
        required=True,
        help='Input Java file (decompiled Ringeventparser.java)'
    )
    parser.add_argument(
        '--binary', '-b',
        help='Binary protobuf file for validation (optional)'
    )
    parser.add_argument(
        '--output', '-o',
        help='Output .proto file (default: ringeventparser.proto)'
    )
    parser.add_argument(
        '--intermediate-dir',
        default='intermediate',
        help='Directory for intermediate files (default: intermediate/)'
    )
    parser.add_argument(
        '--package',
        default='oura.ringeventparser',
        help='Proto package name (default: oura.ringeventparser)'
    )
    parser.add_argument(
        '--verbose', '-v',
        action='store_true',
        help='Verbose output'
    )
    parser.add_argument(
        '--json',
        action='store_true',
        help='Output results as JSON'
    )

    args = parser.parse_args()

    results = run_pipeline(
        java_path=args.input,
        binary_path=args.binary,
        output_dir=args.intermediate_dir,
        proto_output=args.output,
        package=args.package,
        verbose=args.verbose,
    )

    if args.json:
        print(json.dumps(results, indent=2))

    sys.exit(0 if results['success'] else 1)


if __name__ == '__main__':
    main()
