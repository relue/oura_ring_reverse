# Oura Ring BLE Pairing Analysis - Frida Gadget on Real Phone

**Date:** 2025-11-02
**Device:** Xiaomi M2102J20SG (Android 11, arm64-v8a)
**App:** Oura v6.14.0
**Tool:** Frida Gadget 17.4.4 (non-root)

---

## Executive Summary

Successfully deployed Frida Gadget on the Oura app running on a real Android phone (non-rooted) to trace Bluetooth Low Energy (BLE) pairing and communication with an Oura Ring. This setup enables real-time monitoring of BLE scanning, GATT connections, service discovery, and characteristic read/write operations during ring pairing.

---

## Setup Process

### 1. Environment
- **Host:** WSL2 on Windows
- **Phone:** Xiaomi M2102J20SG
  - Android Version: 11
  - Architecture: arm64-v8a
  - IP: 192.168.0.175
  - ADB Port: 39513 (wireless)

### 2. Frida Gadget Injection Workflow

#### Tools Required
- `apktool` v2.7.0
- `zipalign` (Android SDK)
- `apksigner` (Android SDK)
- `keytool` (JDK)
- `uber-apk-signer-1.3.0.jar`
- `frida-non-root` patcher (https://github.com/kiks7/frida-non-root)
- Frida Gadget 17.4.4 for arm64 (24MB .so file)

#### Step-by-Step Process

**Step 1: Extract Original APK**
```bash
# Pull base APK from phone
adb pull "/data/app/~~DMoQfBHikojQKWmUJdKo9g==/com.ouraring.oura-vKA2lOYDzw-qb96-e_rc3g==/base.apk" oura-base.apk

# App is split APK bundle (5 components):
# - base.apk (138MB)
# - config.arm64_v8a.apk (41MB)
# - config.xxxhdpi.apk (15MB)
# - core_resources.apk (18MB)
# - oura_models.apk (40MB)
```

**Step 2: Patch Base APK with Frida Gadget**
```bash
# Run frida-non-root patcher
cd frida-non-root
python3 frida-non-root.py \
  -i /home/picke/reverse_oura/patched/oura-base.apk \
  -o repacked.apk \
  -g res/frida-gadget-17.4.4-android- \
  -a arm64-v8a

# Result:
# - Injected libfrida-gadget.so into lib/arm64-v8a/
# - Modified com.ouraring.oura.launcher.LauncherActivity.onCreate()
# - Added: System.loadLibrary("frida-gadget")
# - Output: repacked.apk (110MB, zipaligned)
```

**Injection Point:**
```smali
# LauncherActivity.onCreate() - Line 3
const-string v0, "frida-gadget"
invoke-static {v0}, Ljava/lang/System;->loadLibrary(Ljava/lang/String;)V
```

**Step 3: Sign All APKs with Unified Certificate**
```bash
# Use uber-apk-signer to sign all 5 APKs with same certificate
java -jar uber-apk-signer-1.3.0.jar --allowResign \
  --apks unsigned/base.apk \
  /home/picke/reverse_oura/extracted/config.arm64_v8a.apk \
  /home/picke/reverse_oura/extracted/config.xxxhdpi.apk \
  /home/picke/reverse_oura/extracted/core_resources.apk \
  /home/picke/reverse_oura/extracted/oura_models.apk

# Certificate:
# - Subject: CN=Android Debug, O=Android, C=US
# - Signature: SHA256 1e08a903aef9c3a721510b64ec764d01d3d094eb954161b62544ea8f187b5953
# - Schemes: v1 (JAR), v2, v3
```

**Step 4: Install on Phone**
```bash
# Push all signed APKs to phone
adb push base-aligned-debugSigned.apk /sdcard/Download/
adb push config.arm64_v8a-aligned-debugSigned.apk /sdcard/Download/
adb push config.xxxhdpi-aligned-debugSigned.apk /sdcard/Download/
adb push core_resources-aligned-debugSigned.apk /sdcard/Download/
adb push oura_models-aligned-debugSigned.apk /sdcard/Download/

# Install using SAI (Split APKs Installer) app
# Note: Install all 5 APKs together as a bundle
```

**Step 5: Connect Frida to Gadget**
```bash
# Launch app (Gadget embedded, listening on port 27042)
adb shell am start -n com.ouraring.oura/com.ouraring.oura.launcher.LauncherActivity

# Get PID
PID=$(adb shell pidof com.ouraring.oura)

# Attach Frida
frida -U $PID -l trace-ble-comprehensive.js
```

---

## BLE Tracing Setup

### Frida Hooks Enabled

**Successfully Hooked:**
- ✅ `android.bluetooth.BluetoothAdapter` (enable, getBluetoothLeScanner)
- ✅ `android.bluetooth.le.BluetoothLeScanner` (startScan, stopScan)
- ✅ `android.bluetooth.le.ScanCallback` (onScanResult, onBatchScanResults, onScanFailed)
- ✅ `android.bluetooth.BluetoothGattCallback` (all lifecycle methods)
- ✅ `android.bluetooth.BluetoothDevice` (connectGatt)

**Partial Hook (overload issue):**
- ⚠️ `android.bluetooth.BluetoothGatt.connect()` - multiple overloads, needs signature specification

### Trace Script
Location: `/tmp/trace-ble-comprehensive.js`

Captures:
- BLE scan start/stop with filter details
- Device discoveries (name, MAC, RSSI)
- GATT connection state changes
- Service discovery results
- Characteristic read/write operations with hex values
- Notification/indication data

---

## Initial BLE Scan Analysis

### Scan Configuration

**Scan Mode:** `2` (SCAN_MODE_LOW_LATENCY)
- Most aggressive scan mode
- Fastest device discovery
- Higher battery consumption

**Callback Type:** `1` (CALLBACK_TYPE_ALL_MATCHES)
- Report all matching advertisements immediately
- No batching

### Service UUID Filters

The Oura app scans for devices advertising **2 specific service UUIDs**:

#### Filter 0: Primary Oura Ring Service
```
UUID: 98ed0001-a541-11e4-b6a0-0002a5d5c51b
Type: Primary GATT Service
```
**Confirmed:** This UUID matches the primary service discovered in emulator analysis.

#### Filter 1: Secondary Oura Service
```
UUID: 8bc5888f-c577-4f5d-857f-377354093f13
Type: Unknown (likely Oura-specific)
```
**New Discovery:** This UUID was not observed in emulator testing. Likely used for:
- Firmware update service
- Device information service
- Proprietary Oura protocol

### Scan Behavior Observed

```
[BT] Getting BLE Scanner
[BLE] ★★★ FILTERED BLE SCAN STARTED ★★★
[BLE] Filter count: 2
[BLE] Scan mode: 2
[BLE] Callback type: 1
[BLE] ▓▓▓ BLE SCAN STOPPED (callback) ▓▓▓
```

**Pattern:**
1. App requests BLE scanner multiple times
2. Starts filtered scan with 2 UUIDs
3. Stops and restarts scan periodically

**Likely Reason:**
- Implementing scan cycling to balance battery vs discovery speed
- Standard Android BLE best practice (scan for 10-30 seconds, pause, repeat)

---

## Key Findings

### 1. Service UUIDs Summary

| UUID | Type | Source | Purpose |
|------|------|--------|---------|
| `98ed0001-a541-11e4-b6a0-0002a5d5c51b` | Primary Service | Confirmed (emulator + real) | Main Oura Ring GATT service |
| `8bc5888f-c577-4f5d-857f-377354093f13` | Unknown Service | New (real phone only) | Secondary Oura service (TBD) |

### 2. Scan Strategy
- **Filter-based scanning:** Only Oura devices are discovered (efficient)
- **Low-latency mode:** Prioritizes fast discovery over battery
- **Periodic cycling:** Scan start/stop pattern observed

### 3. Gadget Behavior
- **Default mode:** "Wait" - app blocks at startup until Frida connects
- **Connection:** Gadget listens on port 27042 (TCP)
- **Stability:** No crashes observed, app fully functional with Gadget embedded

---

## Next Steps for Analysis

### Phase 1: Device Discovery
- [ ] Capture actual Oura Ring MAC address during scan
- [ ] Record RSSI values during discovery
- [ ] Identify advertised service data (if any)
- [ ] Check for manufacturer-specific data in advertisements

### Phase 2: GATT Connection
- [ ] Trace `BluetoothDevice.connectGatt()` call
- [ ] Monitor connection state changes
- [ ] Capture connection parameters (interval, latency, timeout)
- [ ] Log MTU negotiation

### Phase 3: Service Discovery
- [ ] Enumerate all services on the ring
- [ ] List all characteristics and their properties (read/write/notify)
- [ ] Identify descriptors (CCC for notifications)
- [ ] Map service UUIDs to functionality

### Phase 4: Pairing Protocol
- [ ] Capture initial handshake sequence
- [ ] Log all characteristic writes during pairing
- [ ] Monitor notification data from ring
- [ ] Identify encryption/authentication steps

### Phase 5: Data Protocol
- [ ] Decode characteristic value formats
- [ ] Identify command/response structure
- [ ] Map API calls to BLE operations
- [ ] Reverse engineer data encoding (health metrics, battery, etc.)

---

## Technical Challenges Encountered

### 1. Carrier Restriction on ADB Install
**Problem:** Phone requires SIM card to enable "Install via USB"
**Solution:** Push APKs to `/sdcard/Download/` and install via SAI app

### 2. Wireless ADB Instability
**Problem:** ADB connection drops periodically
**Solution:** Reconnect with `adb connect 192.168.0.175:<new_port>`
**Note:** USB ADB recommended for production use

### 3. App Hangs on Startup (Expected Behavior)
**Problem:** App hangs with white screen after installation
**Root Cause:** Frida Gadget in "wait" mode blocks execution
**Solution:** Attach Frida before app timeout (~10 seconds)

### 4. BluetoothGatt Hook Overload
**Problem:** `connect()` has multiple overloads, hook failed
**Status:** Partial - other GATT methods hooked successfully
**Impact:** Minimal - `BluetoothGattCallback.onConnectionStateChange()` captures connection events

---

## Files and Locations

### Analysis Files
- `/home/picke/reverse_oura/analysis/frida-gadget-ble-analysis.md` (this file)
- `/tmp/trace-ble-comprehensive.js` - Comprehensive BLE trace script
- `/tmp/trace-fragments.js` - Activity/Fragment trace script
- `/tmp/ssl-bypass.js` - OkHttp SSL pinning bypass

### APK Files
- `/home/picke/reverse_oura/patched/oura-base.apk` - Original base APK (138MB)
- `/home/picke/reverse_oura/tools/frida-non-root/repacked.apk` - Patched APK (110MB)
- `/home/picke/reverse_oura/tools/unsigned/base-aligned-debugSigned.apk` - Final signed base APK

### Gadget Files
- `/home/picke/reverse_oura/tools/frida-gadget-17.4.4-android-arm64.so` (24MB)
- Injected as: `lib/arm64-v8a/libfrida-gadget.so` in APK

---

## Known Service UUIDs (from previous analysis)

### From Emulator Testing (v6.14.0):
```
Primary Service: 98ed0001-a541-11e4-b6a0-0002a5d5c51b
├── Characteristic: 98ed0002-a541-11e4-b6a0-0002a5d5c51b (write, notify)
├── Characteristic: 98ed0003-a541-11e4-b6a0-0002a5d5c51b (read, write, notify)
└── Characteristic: 98ed0004-a541-11e4-b6a0-0002a5d5c51b (properties unknown)
```

### Additional Services to Investigate:
- `8bc5888f-c577-4f5d-857f-377354093f13` (new discovery from real phone)

---

## Command Reference

### Frida Commands
```bash
# Attach to running app
frida -U $(adb shell pidof com.ouraring.oura) -l trace.js

# List running processes
frida-ps -U

# Interactive REPL
frida -U com.ouraring.oura
```

### ADB Commands
```bash
# Connect wireless ADB
adb pair 192.168.0.175:39995  # Enter pairing code when prompted
adb connect 192.168.0.175:39513

# Launch Oura app
adb shell am start -n com.ouraring.oura/com.ouraring.oura.launcher.LauncherActivity

# Monitor logcat
adb logcat | grep -i "oura\|frida\|gadget"
```

---

## References

### Tools
- Frida: https://frida.re/
- frida-non-root: https://github.com/kiks7/frida-non-root
- uber-apk-signer: https://github.com/patrickfav/uber-apk-signer

### Bluetooth LE Documentation
- Android BLE Guide: https://developer.android.com/guide/topics/connectivity/bluetooth-le
- GATT Specifications: https://www.bluetooth.com/specifications/gatt/

---

## Appendix: Frida Trace Output Sample

```
[*] Starting comprehensive BLE trace for Oura Ring...

[+] BluetoothAdapter tracing enabled
[+] BluetoothLeScanner tracing enabled
[+] ScanCallback result tracing enabled
[+] BluetoothGattCallback tracing enabled
[+] BluetoothDevice tracing enabled

[*] BLE trace ready! Start ring search in the app.

[BT] Getting BLE Scanner

[BLE] ★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★
[BLE] ★★★ FILTERED BLE SCAN STARTED ★★★
[BLE] Filter count: 2
[BLE] Filter 0: BluetoothLeScanFilter [mUuid=98ed0001-a541-11e4-b6a0-0002a5d5c51b]
[BLE] Filter 1: BluetoothLeScanFilter [mUuid=8bc5888f-c577-4f5d-857f-377354093f13]
[BLE] Scan mode: 2
[BLE] Callback type: 1
[BLE] ★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★

[BLE] ▓▓▓ BLE SCAN STOPPED (callback) ▓▓▓
```

---

**Status:** Frida Gadget successfully deployed and tracing BLE operations. Ready for live ring pairing capture.
