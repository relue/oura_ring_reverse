#!/bin/bash
#
# run_ibi_correction.sh - Run Oura's IBI correction via QEMU
#
# Usage:
#   ./run_ibi_correction.sh input.csv > output.csv
#   echo "ts,ibi,amp" | ./run_ibi_correction.sh > output.csv
#
# Input format (CSV, no header):
#   timestamp_ms,ibi_ms,amplitude
#
# Output format (CSV with header):
#   timestamp,ibi,amplitude,validity
#
# Validity values:
#   0 = Valid (RR_VALID)
#   1 = Invalid (RR_INVALID) - marked as questionable
#   2 = Interpolated (RR_INTERPOLATED) - filled in missing beat
#

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ANDROID_ROOT="$SCRIPT_DIR/android_root"
BRIDGE="$SCRIPT_DIR/ibi_correction_bridge_v9"

# Check if bridge exists
if [ ! -f "$BRIDGE" ]; then
    echo "ERROR: Bridge not found: $BRIDGE" >&2
    echo "Please compile with:" >&2
    echo "  cd $SCRIPT_DIR" >&2
    echo "  aarch64-linux-android31-clang -O2 -fPIE -pie -o ibi_correction_bridge_v9 ibi_correction_bridge_v9.c -ldl" >&2
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
