#!/bin/bash
# Continuous BLE monitor for Oura Ring advertisements
# Usage: ./oura_monitor.sh [hci_index]
#
# This script runs btmon and filters for Oura Ring advertisements.
# It will show when the ring is advertising.

HCI_INDEX="${1:-0}"
echo "=== Oura Ring BLE Monitor ==="
echo "Monitoring hci$HCI_INDEX for Oura Ring advertisements..."
echo "Put ring on charger to wake it up."
echo "Press Ctrl+C to stop."
echo "================================"
echo ""

# Ensure scanning is on
bluetoothctl scan on &>/dev/null &
SCAN_PID=$!

# Run btmon and filter for Oura (case insensitive)
sudo btmon -i "$HCI_INDEX" 2>&1 | grep -i --line-buffered -E "oura|A0:38:F8:43:4E:CB|ring" | while read line; do
    echo "[$(date '+%H:%M:%S')] $line"
done

# Cleanup
kill $SCAN_PID 2>/dev/null
bluetoothctl scan off &>/dev/null
