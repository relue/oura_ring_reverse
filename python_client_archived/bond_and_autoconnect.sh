#!/bin/bash
#
# Oura Ring Bond + Kernel Auto-Connect Setup
#
# This script must be run while the ring is in pairing mode!
# It will:
# 1. Scan and find the Oura Ring
# 2. Pair/bond with it
# 3. Immediately enable kernel auto-connect (btmgmt add-device -a 2)
# 4. Trust the device
# 5. Start monitoring for auto-connect
#
# Usage: sudo ./bond_and_autoconnect.sh
#

set -e

ADAPTER_INDEX=1
ADAPTER_ADDR="0C:EF:15:5E:0D:F1"
IDENTITY_ADDR=""

echo "=============================================="
echo "  Oura Ring Bond + Kernel Auto-Connect Setup"
echo "=============================================="
echo ""
echo "Make sure the ring is in PAIRING MODE!"
echo ""

# Step 1: Scan for Oura Ring
echo "[1/6] Scanning for Oura Ring..."
bluetoothctl scan on &
SCAN_PID=$!
sleep 5

# Find Oura address
OURA_RPA=$(bluetoothctl devices | grep -i "Oura" | awk '{print $2}' | head -1)

if [ -z "$OURA_RPA" ]; then
    echo "ERROR: Oura Ring not found! Make sure it's in pairing mode."
    kill $SCAN_PID 2>/dev/null
    exit 1
fi

echo "Found Oura Ring at RPA: $OURA_RPA"
kill $SCAN_PID 2>/dev/null
bluetoothctl scan off 2>/dev/null

# Step 2: Pair with the ring
echo ""
echo "[2/6] Pairing with $OURA_RPA..."
bluetoothctl pair "$OURA_RPA"

# Wait a moment for pairing to complete and identity to resolve
sleep 2

# Get the identity address (BlueZ resolves RPA to identity after pairing)
IDENTITY_ADDR=$(bluetoothctl devices | grep -i "Oura" | awk '{print $2}' | head -1)
echo "Identity address: $IDENTITY_ADDR"

# Step 3: Trust the device
echo ""
echo "[3/6] Trusting device..."
bluetoothctl trust "$IDENTITY_ADDR"

# Step 4: IMMEDIATELY enable kernel auto-connect
echo ""
echo "[4/6] Enabling kernel auto-connect (btmgmt add-device -a 2)..."
sudo btmgmt --index $ADAPTER_INDEX add-device -a 2 -t 1 "$IDENTITY_ADDR"

# Step 5: Verify bond exists
echo ""
echo "[5/6] Verifying bond..."
BOND_FILE="/var/lib/bluetooth/$ADAPTER_ADDR/$IDENTITY_ADDR/info"
if [ -f "$BOND_FILE" ]; then
    echo "Bond file exists: $BOND_FILE"
    echo "IRK: $(grep -A1 '\[IdentityResolvingKey\]' $BOND_FILE | grep Key= | cut -d= -f2)"
else
    echo "WARNING: Bond file not found!"
fi

# Step 6: Don't disconnect - let kernel maintain connection
echo ""
echo "[6/6] Setup complete!"
echo ""
echo "=============================================="
echo "  AUTO-CONNECT ENABLED"
echo "=============================================="
echo ""
echo "Identity Address: $IDENTITY_ADDR"
echo "Kernel Action: Auto-connect (0x02)"
echo ""
echo "The kernel will now automatically connect when"
echo "the ring advertises (with any RPA)."
echo ""
echo "To monitor: sudo btmon | grep -i 'Device Found\|Connected'"
echo ""

# Check if still connected
CONNECTED=$(bluetoothctl info "$IDENTITY_ADDR" 2>/dev/null | grep "Connected: yes" || true)
if [ -n "$CONNECTED" ]; then
    echo "STATUS: Currently CONNECTED"
    echo ""
    echo "You can now use the Python client:"
    echo "  python oura_client.py --heartbeat"
else
    echo "STATUS: Not connected (waiting for ring to advertise)"
    echo ""
    echo "Move the ring or wait for it to advertise."
fi
