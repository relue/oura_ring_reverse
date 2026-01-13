# Protobuf schema extraction from decompiled Java
"""
Hybrid extraction pipeline:
1. tree-sitter for structural parsing
2. Regex for protobuf-specific patterns
3. Binary validation against ring_data.pb
4. Proto file generation
"""
