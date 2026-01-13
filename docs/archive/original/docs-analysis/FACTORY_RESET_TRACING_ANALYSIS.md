# Factory Reset Tracing Analysis

## Overview
This document analyzes the available Frida tracing scripts for capturing Oura Ring factory reset operations.

## Available Scripts

### 1. trace-sweetblue-v3.js
**Purpose:** General BLE communication tracing via SweetBlue library

**Hooks:**
- ✅ BleManager (scan operations)
- ✅ DiscoveryListener (device discovery)
- ✅ BleDevice (connect, disconnect, read, write, notifications)
- ✅ DeviceListenerImpl (low-level notifications)
- ✅ P_BleDeviceImpl (high-level read/write events)
- ✅ DeviceConnectListener (connection states)
- ✅ BondListener (pairing events)

**Strengths:**
- Comprehensive BLE layer coverage
- Captures all BLE reads/writes/notifications
- Shows connection state changes

**Limitations for Factory Reset:**
- ❌ No Oura-specific operation hooks
- ❌ No database/auth key hooks
- ❌ No high-level factory reset logic
- ❌ Won't capture auth key deletion from database

### 2. trace-all-operations.js
**Purpose:** Traces Oura-specific operations including factory reset

**Hooks:**
- ✅ ResetMemory (0x1a) - Factory reset BLE command
- ✅ RingModel.factoryReset() - High-level factory reset
- ✅ State machine transitions
- ✅ Base RingOperation.getRequest()
- ✅ SetFeatureMode, SetFeatureSubscription, GetFeatureStatus
- ✅ Minimal BLE write hook

**Strengths:**
- Captures factory reset BLE command (0x1a)
- Shows high-level factory reset flow
- Includes call stack backtraces

**Limitations for Factory Reset:**
- ❌ No database operations (auth key deletion)
- ❌ No Android bond removal hooks
- ❌ No comprehensive BLE notification capture
- ❌ Doesn't show what happens to stored auth key

### 3. trace_factory_reset_comprehensive.js (NEW)
**Purpose:** Complete factory reset tracing including ALL layers

**Hooks:**
1. **High-Level App Logic:**
   - ✅ RingModel.factoryReset()
   - ✅ State machine transitions (FACTORY_RESET)

2. **BLE Commands:**
   - ✅ ResetMemory (0x1a) - Constructor, getRequest(), parseResponse()
   - ✅ Full command breakdown (tag, subcmd, payload)
   - ✅ Response parsing with status codes

3. **Database Operations:**
   - ✅ DbRingConfiguration.setAuthKey() - Captures auth key deletion (null)
   - ✅ DbRingConfiguration.getAuthKey()
   - ✅ Realm transactions (begin, commit, cancel)

4. **Android Bluetooth:**
   - ✅ BluetoothDevice.removeBond() - Captures unpairing

5. **Low-Level BLE:**
   - ✅ BleDevice.write() - Highlights factory reset commands
   - ✅ DeviceListenerImpl.onCharacteristicChanged() - Ring responses

**Strengths:**
- ✅ Complete visibility into ALL factory reset operations
- ✅ Captures auth key deletion from database
- ✅ Shows Android bond removal
- ✅ Detailed command/response breakdown
- ✅ Backtraces for each critical operation
- ✅ Clear visual separation of different layers

**Best for:**
- Factory reset reverse engineering
- Understanding complete auth key lifecycle
- Replicating factory reset in custom app

## Comparison Matrix

| Feature | trace-sweetblue-v3.js | trace-all-operations.js | trace_factory_reset_comprehensive.js |
|---------|----------------------|------------------------|-------------------------------------|
| BLE Communications | ✅ Comprehensive | ⚠️ Minimal | ✅ Targeted |
| Factory Reset Command (0x1a) | ❌ | ✅ | ✅ |
| High-Level Factory Reset | ❌ | ✅ | ✅ |
| Auth Key Deletion | ❌ | ❌ | ✅ |
| Database Operations | ❌ | ❌ | ✅ |
| Android Bond Removal | ❌ | ❌ | ✅ |
| State Machine | ❌ | ✅ | ✅ |
| Backtraces | ❌ | ✅ | ✅ |
| Ring Responses | ✅ | ❌ | ✅ |

## Recommendation

### For Factory Reset Analysis: Use `trace_factory_reset_comprehensive.js`

**Why:**
1. ✅ Captures EVERYTHING related to factory reset
2. ✅ Shows auth key deletion from database
3. ✅ Shows Android bond removal
4. ✅ Complete BLE command/response flow
5. ✅ Clear output with visual markers

### Usage:
```bash
frida -U Gadget -l /tmp/trace_factory_reset_comprehensive.js 2>&1 | tee /home/picke/reverse_oura/analysis/factory_reset_complete.log
```

Then perform factory reset in the Oura app and observe:
1. High-level RingModel.factoryReset() call
2. ResetMemory BLE command (0x1a) being built
3. Command sent to ring
4. Ring response
5. Auth key set to NULL in database
6. Realm transaction commit
7. Possible Android bond removal

## Expected Factory Reset Flow

Based on hooks, expect this sequence:

```
1. [HIGH LEVEL] RingModel.factoryReset()
   └─ User triggers factory reset in app

2. [BLE COMMAND] ResetMemory constructor
   └─ bleFactoryReset flag set

3. [BLE COMMAND] ResetMemory.getRequest()
   └─ Command: 1a <subcmd> (2-3 bytes)

4. [BLE WRITE] Command sent to ring
   └─ Characteristic: 98ed0002

5. [NOTIFICATION] Ring response
   └─ Response: 1b <subcmd> <status>
   └─ Status 0x00 = SUCCESS

6. [DATABASE] DbRingConfiguration.setAuthKey(null)
   └─ Auth key cleared from database

7. [DATABASE] Realm.commitTransaction()
   └─ Changes persisted

8. [ANDROID BT] BluetoothDevice.removeBond() (maybe)
   └─ Device unpaired from Android
```

## What You'll Learn

After running factory reset with the comprehensive tracer:

1. **Exact BLE command format**
   - Complete byte sequence for factory reset
   - Any subcmd or parameters

2. **Ring response format**
   - Response tag (likely 0x1b)
   - Status codes

3. **Database operations**
   - Confirmation that auth key is deleted
   - Database transaction details

4. **Pairing behavior**
   - Whether ring is unpaired from Android
   - Whether this is required for factory reset

5. **Complete call chain**
   - Where factory reset is initiated
   - Full execution flow

## Next Steps

1. Run comprehensive tracer
2. Perform factory reset in Oura app
3. Analyze captured trace
4. Document exact command format
5. Implement factory reset in custom app:
   ```
   - Send 0x1a command to ring
   - Wait for 0x1b response with status 0x00
   - Clear local auth key storage
   - Optionally unpair device
   ```
