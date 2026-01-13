# Frida Instrumentation for Oura Ring Analysis

**Last Updated:** 2026-01-12

---

## 1. Overview

Frida is a dynamic instrumentation toolkit used to analyze the Oura Ring Android application at runtime. This document covers the setup process for deploying Frida Gadget on non-rooted Android devices and the key scripts used for BLE communication analysis and factory reset tracing.

**Key Use Cases:**
- Real-time monitoring of BLE scanning, GATT connections, and characteristic read/write operations
- Capturing pairing and authentication protocols
- Tracing factory reset operations and auth key lifecycle
- Bypassing SSL pinning for network analysis

---

## 2. Frida Gadget Setup (Non-Root Method)

Frida Gadget enables Frida instrumentation on non-rooted Android devices by embedding the Frida library directly into the target APK.

### 2.1 Tools Required

- `apktool` v2.7.0 - APK decompilation/recompilation
- `zipalign` (Android SDK) - APK alignment
- `apksigner` (Android SDK) - APK signing
- `keytool` (JDK) - Certificate generation
- `uber-apk-signer-1.3.0.jar` - Unified APK signing tool
- `frida-non-root` patcher - https://github.com/kiks7/frida-non-root
- Frida Gadget `.so` file (e.g., `frida-gadget-17.4.4-android-arm64.so`, ~24MB)

### 2.2 APK Patching Process

#### Step 1: Extract Original APK

```bash
# Pull base APK from phone
adb pull "/data/app/~~DMoQfBHikojQKWmUJdKo9g==/com.ouraring.oura-vKA2lOYDzw-qb96-e_rc3g==/base.apk" oura-base.apk

# Note: Oura app is a split APK bundle with 5 components:
# - base.apk (138MB)
# - config.arm64_v8a.apk (41MB)
# - config.xxxhdpi.apk (15MB)
# - core_resources.apk (18MB)
# - oura_models.apk (40MB)
```

#### Step 2: Patch Base APK with Frida Gadget

```bash
# Run frida-non-root patcher
cd frida-non-root
python3 frida-non-root.py \
  -i /path/to/oura-base.apk \
  -o repacked.apk \
  -g res/frida-gadget-17.4.4-android- \
  -a arm64-v8a
```

**What the patcher does:**
- Injects `libfrida-gadget.so` into `lib/arm64-v8a/`
- Modifies `com.ouraring.oura.launcher.LauncherActivity.onCreate()` to load the gadget

**Injection Point (Smali):**
```smali
# LauncherActivity.onCreate() - Line 3
const-string v0, "frida-gadget"
invoke-static {v0}, Ljava/lang/System;->loadLibrary(Ljava/lang/String;)V
```

### 2.3 Lib Injection Details

The Frida Gadget library is placed at:
```
lib/arm64-v8a/libfrida-gadget.so
```

This library is loaded via `System.loadLibrary("frida-gadget")` at app startup, before any other application code executes.

### 2.4 Config.json Settings

By default, Frida Gadget operates in "wait" mode:
- App blocks at startup until Frida client connects
- Gadget listens on port 27042 (TCP)
- Timeout occurs after ~10 seconds if no connection

Optional: Create a `libfrida-gadget.config.so` file alongside the gadget for custom configuration:
```json
{
  "interaction": {
    "type": "listen",
    "address": "0.0.0.0",
    "port": 27042,
    "on_load": "wait"
  }
}
```

### 2.5 Signing and Installation

#### Step 3: Sign All APKs with Unified Certificate

```bash
# Use uber-apk-signer to sign all 5 APKs with the same certificate
java -jar uber-apk-signer-1.3.0.jar --allowResign \
  --apks unsigned/base.apk \
  /path/to/config.arm64_v8a.apk \
  /path/to/config.xxxhdpi.apk \
  /path/to/core_resources.apk \
  /path/to/oura_models.apk
```

#### Step 4: Install on Phone

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

#### Step 5: Connect Frida to Gadget

```bash
# Launch app (Gadget embedded, listening on port 27042)
adb shell am start -n com.ouraring.oura/com.ouraring.oura.launcher.LauncherActivity

# Get PID
PID=$(adb shell pidof com.ouraring.oura)

# Attach Frida
frida -U $PID -l trace-script.js
```

---

## 3. Key Frida Scripts and Their Purposes

The following scripts are available in the `frida_scripts/` folder:

| Script | Purpose |
|--------|---------|
| `trace-sweetblue-v3.js` | General BLE communication tracing via SweetBlue library |
| `trace-all-operations.js` | Traces Oura-specific operations including factory reset |
| `trace-with-backtrace.js` | BLE tracing with call stack backtraces |
| `trace_0x6a_processing.js` | Traces specific BLE command processing |
| `verify-bpm-calculation.js` | Validates heart rate calculation logic |
| `simple-heartbeat-monitor.js` | Basic heartbeat/connection monitoring |

### Scripts in `frida_scripts/tmp/`:

| Script | Purpose |
|--------|---------|
| `trace_complete_auth_flow.js` | Complete authentication flow tracing |
| `capture_auth_key.js` | Captures authentication key exchange |
| `trace_authkey_write.js` | Traces auth key write operations |
| `read_stored_auth_key.js` | Reads stored auth key from database |
| `comprehensive_connection_trace.js` | Full connection lifecycle tracing |
| `force_ble_factory_reset.js` | Forces BLE factory reset command |
| `detailed_auth_trace.js` | Detailed authentication protocol tracing |
| `complete_setup_trace.js` | Complete device setup tracing |
| `trace_auth_protocol_detailed.js` | Detailed auth protocol analysis |

---

## 4. BLE Analysis Hooks

### 4.1 Successfully Hooked Classes

**Android Bluetooth Stack:**
- `android.bluetooth.BluetoothAdapter` - enable, getBluetoothLeScanner
- `android.bluetooth.le.BluetoothLeScanner` - startScan, stopScan
- `android.bluetooth.le.ScanCallback` - onScanResult, onBatchScanResults, onScanFailed
- `android.bluetooth.BluetoothGattCallback` - all lifecycle methods
- `android.bluetooth.BluetoothDevice` - connectGatt

**SweetBlue Library (Oura's BLE wrapper):**
- `BleManager` - scan operations
- `DiscoveryListener` - device discovery
- `BleDevice` - connect, disconnect, read, write, notifications
- `DeviceListenerImpl` - low-level notifications
- `P_BleDeviceImpl` - high-level read/write events
- `DeviceConnectListener` - connection states
- `BondListener` - pairing events

### 4.2 Service UUIDs Discovered

| UUID | Type | Purpose |
|------|------|---------|
| `98ed0001-a541-11e4-b6a0-0002a5d5c51b` | Primary Service | Main Oura Ring GATT service |
| `8bc5888f-c577-4f5d-857f-377354093f13` | Secondary Service | Secondary Oura service (firmware/proprietary) |

**Primary Service Characteristics:**
```
Primary Service: 98ed0001-a541-11e4-b6a0-0002a5d5c51b
  - Characteristic: 98ed0002-a541-11e4-b6a0-0002a5d5c51b (write, notify)
  - Characteristic: 98ed0003-a541-11e4-b6a0-0002a5d5c51b (read, write, notify)
  - Characteristic: 98ed0004-a541-11e4-b6a0-0002a5d5c51b (properties unknown)
```

### 4.3 Scan Configuration Observed

- **Scan Mode:** `2` (SCAN_MODE_LOW_LATENCY) - Most aggressive, fastest discovery
- **Callback Type:** `1` (CALLBACK_TYPE_ALL_MATCHES) - Report all matches immediately
- **Filter Strategy:** Filter-based scanning for Oura service UUIDs only

### 4.4 Sample BLE Trace Output

```
[*] Starting comprehensive BLE trace for Oura Ring...

[+] BluetoothAdapter tracing enabled
[+] BluetoothLeScanner tracing enabled
[+] ScanCallback result tracing enabled
[+] BluetoothGattCallback tracing enabled
[+] BluetoothDevice tracing enabled

[*] BLE trace ready! Start ring search in the app.

[BT] Getting BLE Scanner

[BLE] *** FILTERED BLE SCAN STARTED ***
[BLE] Filter count: 2
[BLE] Filter 0: BluetoothLeScanFilter [mUuid=98ed0001-a541-11e4-b6a0-0002a5d5c51b]
[BLE] Filter 1: BluetoothLeScanFilter [mUuid=8bc5888f-c577-4f5d-857f-377354093f13]
[BLE] Scan mode: 2
[BLE] Callback type: 1
```

---

## 5. Factory Reset Tracing

### 5.1 Available Scripts Comparison

| Feature | trace-sweetblue-v3.js | trace-all-operations.js | trace_factory_reset_comprehensive.js |
|---------|----------------------|------------------------|-------------------------------------|
| BLE Communications | Comprehensive | Minimal | Targeted |
| Factory Reset Command (0x1a) | No | Yes | Yes |
| High-Level Factory Reset | No | Yes | Yes |
| Auth Key Deletion | No | No | Yes |
| Database Operations | No | No | Yes |
| Android Bond Removal | No | No | Yes |
| State Machine | No | Yes | Yes |
| Backtraces | No | Yes | Yes |
| Ring Responses | Yes | No | Yes |

### 5.2 Recommended Script: trace_factory_reset_comprehensive.js

This script provides complete visibility into all factory reset operations:

**Hooks Included:**

1. **High-Level App Logic:**
   - `RingModel.factoryReset()` - Entry point
   - State machine transitions (FACTORY_RESET state)

2. **BLE Commands:**
   - `ResetMemory` (0x1a) - Constructor, getRequest(), parseResponse()
   - Full command breakdown (tag, subcmd, payload)
   - Response parsing with status codes

3. **Database Operations:**
   - `DbRingConfiguration.setAuthKey()` - Captures auth key deletion (null)
   - `DbRingConfiguration.getAuthKey()` - Auth key reads
   - Realm transactions (begin, commit, cancel)

4. **Android Bluetooth:**
   - `BluetoothDevice.removeBond()` - Captures device unpairing

5. **Low-Level BLE:**
   - `BleDevice.write()` - Highlights factory reset commands
   - `DeviceListenerImpl.onCharacteristicChanged()` - Ring responses

### 5.3 Factory Reset Command Flow

```
1. [HIGH LEVEL] RingModel.factoryReset()
   - User triggers factory reset in app

2. [BLE COMMAND] ResetMemory constructor
   - bleFactoryReset flag set

3. [BLE COMMAND] ResetMemory.getRequest()
   - Command: 1a <subcmd> (2-3 bytes)

4. [BLE WRITE] Command sent to ring
   - Characteristic: 98ed0002

5. [NOTIFICATION] Ring response
   - Response: 1b <subcmd> <status>
   - Status 0x00 = SUCCESS

6. [DATABASE] DbRingConfiguration.setAuthKey(null)
   - Auth key cleared from database

7. [DATABASE] Realm.commitTransaction()
   - Changes persisted

8. [ANDROID BT] BluetoothDevice.removeBond() (optional)
   - Device unpaired from Android
```

### 5.4 Usage

```bash
frida -U Gadget -l /path/to/trace_factory_reset_comprehensive.js 2>&1 | tee factory_reset.log
```

Then perform factory reset in the Oura app and observe the complete trace.

---

## 6. Limitations and Troubleshooting

### 6.1 Known Limitations

**BluetoothGatt Hook Overload Issue:**
- `android.bluetooth.BluetoothGatt.connect()` has multiple overloads
- Hook may fail without explicit signature specification
- Workaround: Use `BluetoothGattCallback.onConnectionStateChange()` instead

**Gadget Wait Mode:**
- App hangs with white screen on startup (expected behavior)
- Must attach Frida within ~10 seconds before timeout
- App becomes unresponsive if Frida not attached in time

### 6.2 Troubleshooting

**Problem:** Carrier restriction on ADB install
**Solution:** Push APKs to `/sdcard/Download/` and install via SAI app

**Problem:** Wireless ADB connection drops
**Solution:** Reconnect with `adb connect <ip>:<new_port>`
**Recommendation:** Use USB ADB for stability

**Problem:** App hangs on startup
**Cause:** Frida Gadget in "wait" mode blocks execution
**Solution:** Attach Frida immediately after launching app

**Problem:** Hook not triggering
**Solutions:**
- Verify class/method name spelling
- Check for method overloads and specify signature
- Use `Java.enumerateMethods()` to discover exact signatures

### 6.3 Useful Commands

```bash
# Attach to running app
frida -U $(adb shell pidof com.ouraring.oura) -l trace.js

# List running processes
frida-ps -U

# Interactive REPL
frida -U com.ouraring.oura

# Connect wireless ADB
adb pair 192.168.0.175:39995  # Enter pairing code when prompted
adb connect 192.168.0.175:39513

# Launch Oura app
adb shell am start -n com.ouraring.oura/com.ouraring.oura.launcher.LauncherActivity

# Monitor logcat
adb logcat | grep -i "oura\|frida\|gadget"
```

---

## 7. References

### Scripts in frida_scripts/ Folder

**Main Scripts:**
- `frida_scripts/trace-sweetblue-v3.js` - BLE via SweetBlue
- `frida_scripts/trace-all-operations.js` - Oura operations tracing
- `frida_scripts/trace-with-backtrace.js` - BLE with backtraces
- `frida_scripts/trace_0x6a_processing.js` - Command processing
- `frida_scripts/verify-bpm-calculation.js` - Heart rate verification
- `frida_scripts/simple-heartbeat-monitor.js` - Basic monitoring

**Temporary/Development Scripts:**
- `frida_scripts/tmp/trace_complete_auth_flow.js`
- `frida_scripts/tmp/capture_auth_key.js`
- `frida_scripts/tmp/comprehensive_connection_trace.js`
- `frida_scripts/tmp/force_ble_factory_reset.js`
- `frida_scripts/tmp/trace_auth_protocol_detailed.js`

### External Resources

**Tools:**
- Frida: https://frida.re/
- frida-non-root: https://github.com/kiks7/frida-non-root
- uber-apk-signer: https://github.com/patrickfav/uber-apk-signer

**Documentation:**
- Android BLE Guide: https://developer.android.com/guide/topics/connectivity/bluetooth-le
- GATT Specifications: https://www.bluetooth.com/specifications/gatt/

---

*Merged from: frida-gadget-ble-analysis.md + FACTORY_RESET_TRACING_ANALYSIS.md*
