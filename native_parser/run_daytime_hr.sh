#!/bin/bash
#
# run_daytime_hr.sh - Run Oura's Daytime HR Processing via QEMU
#
# Usage:
#   ./run_daytime_hr.sh input.csv > output.csv
#   echo "ts,ibi,amp" | ./run_daytime_hr.sh > output.csv
#
# Input format (CSV, no header):
#   timestamp_ms,ibi_ms,amplitude
#
# Output format (CSV with header):
#   timestamp_ms,ibi_ms,hr_bpm,quality
#

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ANDROID_ROOT="$SCRIPT_DIR/android_root"
BRIDGE="$SCRIPT_DIR/daytime_hr_bridge"

# Check if bridge exists
if [ ! -f "$BRIDGE" ]; then
    echo "ERROR: Bridge not found: $BRIDGE" >&2
    echo "Please compile with:" >&2
    echo "  cd $SCRIPT_DIR" >&2
    echo "  aarch64-linux-android31-clang -O2 -fPIE -pie -o daytime_hr_bridge daytime_hr_bridge.c -ldl" >&2
    exit 1
fi

# Check if Android root exists
if [ ! -d "$ANDROID_ROOT" ]; then
    echo "ERROR: Android root not found: $ANDROID_ROOT" >&2
    exit 1
fi

# Run the bridge via QEMU
if [ -n "$1" ] && [ -f "$1" ]; then
    # Input from file
    exec env -i \
        LD_LIBRARY_PATH="$ANDROID_ROOT/system/lib64" \
        QEMU_LD_PREFIX="$ANDROID_ROOT" \
        qemu-aarch64 -L "$ANDROID_ROOT" "$BRIDGE" < "$1"
else
    # Input from stdin
    exec env -i \
        LD_LIBRARY_PATH="$ANDROID_ROOT/system/lib64" \
        QEMU_LD_PREFIX="$ANDROID_ROOT" \
        qemu-aarch64 -L "$ANDROID_ROOT" "$BRIDGE"
fi
