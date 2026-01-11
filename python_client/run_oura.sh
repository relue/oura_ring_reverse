#!/bin/bash
# Wrapper script to run Oura BLE client via Windows Python from WSL

PYTHON_PATH="C:\\Users\\picke\\AppData\\Local\\Python\\bin\\python.exe"
SCRIPT_PATH="/home/picke/reverse_oura/oura_ble_client.py"

# Convert WSL path to Windows path
WIN_SCRIPT_PATH=$(wslpath -w "$SCRIPT_PATH")

echo "Running Oura BLE Client..."
echo "Python: $PYTHON_PATH"
echo "Script: $WIN_SCRIPT_PATH"
echo ""

cmd.exe /c "$PYTHON_PATH \"$WIN_SCRIPT_PATH\""
