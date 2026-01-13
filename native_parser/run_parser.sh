#!/bin/bash
# Run the native parser bridge via QEMU user-mode emulation
#
# This script parses raw BLE events captured from the Oura Ring
# and outputs a protobuf file that can be decoded with Python.
#
# Usage: ./run_parser.sh <events.txt> [output.pb]
#
# Example:
#   ./run_parser.sh ../analysis_scripts/ring_events_20260112.txt ring_data.pb
#   python decode_ringdata.py ring_data.pb
#
# Requirements:
#   - qemu-aarch64 (QEMU user-mode emulator for ARM64)
#   - android_root/ directory with Android system libraries

set -e

# Script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# Arguments
EVENTS_FILE="${1:?Usage: $0 <events.txt> [output.pb]}"
OUTPUT_FILE="${2:-ring_data.pb}"

# Check input file exists
if [ ! -f "$EVENTS_FILE" ]; then
    echo "Error: Events file not found: $EVENTS_FILE" >&2
    exit 1
fi

# Check parser binary exists
if [ ! -f "$SCRIPT_DIR/parser_bridge_android" ]; then
    echo "Error: parser_bridge_android not found in $SCRIPT_DIR" >&2
    echo "Please compile it first with the Android NDK" >&2
    exit 1
fi

# Check android_root exists
if [ ! -d "$SCRIPT_DIR/android_root" ]; then
    echo "Error: android_root directory not found" >&2
    echo "This directory should contain the Android system libraries" >&2
    exit 1
fi

# Check QEMU is available
if ! command -v qemu-aarch64 &> /dev/null; then
    echo "Error: qemu-aarch64 not found" >&2
    echo "Install QEMU user-mode emulation:" >&2
    echo "  Arch: pacman -S qemu-user" >&2
    echo "  Ubuntu: apt install qemu-user" >&2
    exit 1
fi

# Set up environment for QEMU
# The binary expects /system/bin/linker64, so prefix should be android_root
export QEMU_LD_PREFIX="$SCRIPT_DIR/android_root"
# Clear library paths to avoid picking up host x86 libraries (e.g. NoMachine NX)
unset LD_LIBRARY_PATH
unset LD_PRELOAD

# Count events in input file
EVENT_COUNT=$(grep -c '^[^#]' "$EVENTS_FILE" 2>/dev/null || echo 0)
INPUT_SIZE=$(stat -c%s "$EVENTS_FILE")

echo "Input: $EVENTS_FILE ($EVENT_COUNT events, $INPUT_SIZE bytes)" >&2
echo "Output: $OUTPUT_FILE" >&2
echo "Running native parser via QEMU..." >&2

# Run parser through QEMU with clean environment
env -i PATH="/usr/bin:/bin" QEMU_LD_PREFIX="$QEMU_LD_PREFIX" \
    qemu-aarch64 ./parser_bridge_android "$EVENTS_FILE" > "$OUTPUT_FILE"

# Check output
if [ -f "$OUTPUT_FILE" ]; then
    OUTPUT_SIZE=$(stat -c%s "$OUTPUT_FILE")
    echo "" >&2
    echo "Success! Output: $OUTPUT_FILE ($OUTPUT_SIZE bytes)" >&2

    # Quick validation
    if [ "$OUTPUT_SIZE" -gt 100 ]; then
        echo "" >&2
        echo "Decode with:" >&2
        echo "  python decode_ringdata.py $OUTPUT_FILE" >&2
    else
        echo "Warning: Output file is small ($OUTPUT_SIZE bytes)" >&2
        echo "Check that the input events are in the correct format" >&2
    fi
else
    echo "Error: Output file not created" >&2
    exit 1
fi
