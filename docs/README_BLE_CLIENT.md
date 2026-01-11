# Oura Ring Gen 3 BLE Client

Python-based Bluetooth Low Energy client for communicating directly with Oura Ring Gen 3 to monitor live heartbeat data.

## Overview

This client replicates the Oura app's BLE heartbeat monitoring functionality using the protocol reverse-engineered via Frida instrumentation. It connects directly to the ring, sends the initialization sequence, and displays real-time BPM readings.

## Requirements

- **Hardware:** Bluetooth adapter (built-in or USB dongle)
- **OS:** Windows (for Bluetooth access via Bleak)
- **Software:**
  - Python 3.12+ installed on Windows
  - Bleak library (`pip install bleak`)
- **Oura Ring:** Gen 3, paired with computer

## Installation

### 1. Python + Bleak (Already Installed)
```bash
# Verify installation
cmd.exe /c "C:\Users\picke\AppData\Local\Python\bin\python.exe --version"
# Should show: Python 3.14.0

# Verify Bleak
cmd.exe /c "C:\Users\picke\AppData\Local\Python\bin\python.exe -m pip list | findstr bleak"
# Should show: bleak 1.1.1
```

### 2. Pair Oura Ring with Computer
- Enable Bluetooth on Windows
- Put Oura Ring in pairing mode (if needed)
- Pair via Windows Settings → Bluetooth & devices

## Usage

### Option 1: Via Wrapper Script (Easiest)
```bash
cd /home/picke/reverse_oura
./run_oura.sh
```

### Option 2: Direct Execution
```bash
cd /home/picke/reverse_oura
cmd.exe /c "C:\Users\picke\AppData\Local\Python\bin\python.exe oura_ble_client.py"
```

### Option 3: From Windows
```cmd
cd %USERPROFILE%\reverse_oura
python oura_ble_client.py
```

## Output

When running successfully:
```
╔════════════════════════════════════════════════════════════╗
║           OURA RING GEN 3 HEARTBEAT MONITOR              ║
╚════════════════════════════════════════════════════════════╝

🔍 Scanning for Oura Ring (4B:DD:91:1C:33:61)...
✓ Found Oura Ring: Oura Ring (4B:DD:91:1C:33:61)

🔗 Connecting to 4B:DD:91:1C:33:61...
✓ Connected!

🔔 Subscribing to notifications...
✓ Subscribed!

🚀 Starting heartbeat monitoring...
📤 Sending Init command 1: 2f 02 20 02
📤 Sending Init command 2: 2f 03 22 02 03
📤 Sending Start streaming: 2f 03 26 02 02

✓ Heartbeat monitoring active! Press Ctrl+C to stop.

============================================================

┌──────────────────────────────────────────────────────────┐
│  💓 HEARTBEAT #1                                         │
├──────────────────────────────────────────────────────────┤
│  BPM:   67.9 BPM                                         │
│  IBI:    884 ms                                          │
│  Flag: 0x11                                              │
└──────────────────────────────────────────────────────────┘

┌──────────────────────────────────────────────────────────┐
│  💓 HEARTBEAT #2                                         │
├──────────────────────────────────────────────────────────┤
│  BPM:   64.9 BPM                                         │
│  IBI:    924 ms                                          │
│  Flag: 0x01                                              │
└──────────────────────────────────────────────────────────┘
```

Press `Ctrl+C` to stop monitoring.

## Protocol Details

Based on reverse engineering documented in:
- `/home/picke/reverse_oura/analysis/heartbeat_complete_flow.md`
- `/home/picke/reverse_oura/analysis/heartbeat_replication_guide.md`

### BLE Service & Characteristics
```
Service:     98ed0001-a541-11e4-b6a0-0002a5d5c51b
Write Char:  98ed0002-a541-11e4-b6a0-0002a5d5c51b
Notify Char: 98ed0003-a541-11e4-b6a0-0002a5d5c51b
```

### Initialization Sequence
```
1. Write: 2f 02 20 02        (Setup)
2. Write: 2f 03 22 02 03     (Enable heartbeat mode)
3. Write: 2f 03 26 02 02     (Start streaming)
```

### Heartbeat Packet Format
```
Offset:  0   1   2   3   4   5   6   7   8      9      10  11  12  13  14  15  16
Data:   2f  0f  28  02  XX  02  00  00 [IBI_L] [IBI_H] 00  00  00  00  YY  ZZ  7f

IBI Extraction: ibi_ms = ((byte[9] & 0x0F) << 8) | (byte[8] & 0xFF)
BPM Calculation: bpm = 60000 / ibi_ms
```

### Stop Command
```
Write: 2f 03 22 02 01
```

## Troubleshooting

### "Oura Ring not found"
- Ensure ring is charged and nearby
- Check ring is paired with computer (Windows Bluetooth settings)
- Try re-pairing the ring

### "Bluetooth error: Could not find..."
- Verify Bluetooth is enabled on Windows
- Check USB dongle is connected (if using one)
- Restart Bluetooth service: `Services → Bluetooth Support Service → Restart`

### "Permission denied" or "Access denied"
- Ring may be connected to phone - disconnect from Oura app first
- Only one device can connect at a time
- Try unpairing and re-pairing

### Import errors
- Ensure Bleak is installed: `pip install bleak`
- Verify Python path in `run_oura.sh` matches your installation

## Files

- `oura_ble_client.py` - Main Python BLE client
- `run_oura.sh` - Wrapper script to run from WSL
- `README_BLE_CLIENT.md` - This file
- `analysis/heartbeat_complete_flow.md` - Complete protocol documentation
- `analysis/heartbeat_replication_guide.md` - Replication guide

## Technical Notes

### Why Windows Python?
- WSL2 doesn't have native Bluetooth support
- Windows Bleak uses WinRT APIs for BLE access
- Script is in WSL for easy editing, but executes via Windows Python

### IBI vs BPM
- **IBI (Inter-Beat Interval):** Time between heartbeats in milliseconds
- **BPM (Beats Per Minute):** Heart rate
- Conversion: `BPM = 60,000 / IBI_ms`

### Comparison with Oura App
This client:
- ✅ Uses identical BLE protocol
- ✅ Calculates BPM the same way (verified via Frida hooks)
- ❌ Doesn't store historical data
- ❌ Doesn't sync to cloud
- ✅ Shows raw real-time heartbeat data

## References

- Bleak Documentation: https://bleak.readthedocs.io/
- Protocol reverse engineering: Frida instrumentation of Oura app v6.14.0
- Verification: Decompiled app source code analysis
