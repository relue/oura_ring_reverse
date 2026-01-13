# Oura Ring Full Automation Plan

## Goal
Full automation of Oura Ring 4 control from PC terminal via Android phone as BLE bridge, with ability to:
- Connect to ring autonomously
- Authenticate without manual intervention
- Start/stop heartbeat monitoring
- Retrieve ring data programmatically

## Current Status

### Working
- [x] ADB command interface (send commands from PC terminal)
- [x] BLE scanning finds ring (handles rotating MAC via name matching)
- [x] Factory reset command works
- [x] SetAuthKey command structure implemented
- [x] Raw hex command sending
- [x] Notification/response logging
- [x] **Authentication flow complete** (GetAuthNonce -> AES encrypt -> Authenticate)
- [x] **Real-time heartbeat monitoring** (IBI streaming at ~1Hz)
- [x] **Event data retrieval** (GetEvent with binary search pagination)
- [x] **Export command** (saves events to file for PC analysis)
- [x] **20 event types verified** (sleep, temp, motion, activity, HRV, etc.)
- [x] **Overnight sleep data capture** (9 hours, 4794 events)

### Blocked
- [ ] Autonomous pairing (pairing dialog requires UI interaction on some devices)

### Completed (2026-01-11)
- [x] Authentication (ring was factory reset, new auth key set and working)
- [x] Heartbeat monitoring (real-time IBI: 66 BPM verified)
- [x] Data retrieval (184 events captured from 13 event types)
- [x] Protocol documentation (protocolknowledge.md updated)

### Completed (2026-01-12)
- [x] Overnight sleep data capture (4794 events over 9 hours)
- [x] Sleep event parsing (0x6a SLEEP_PERIOD_INFO_2 fully decoded)
- [x] Sleep HR analysis: 51.5-70 BPM (avg 59 BPM)
- [x] Sleep temp analysis: ~35°C (7 sensors)
- [x] HRV event parsing (0x5d)
- [x] 17/20 event types fully verified with parsers
- [x] Protocol documentation complete (protocolknowledge.md)

## Implementation Steps

### Phase 1: Complete Pairing Automation
1. Detect which type of pairing UI appears (modal dialog vs notification)
2. Implement UI automation to click "Pair" button
3. Handle multiple pairing dialog types (MIUI notification, standard Android dialog)
4. Add retry logic for when ring stops advertising

```bash
# Proposed automation flow
adb shell am broadcast -a com.example.reverseoura.COMMAND --es cmd "connect"
# Wait for "Pairing initiated" in logs
# Poll UI with uiautomator dump
# Find and click "Pair" button
# Verify bond state becomes BOND_BONDED
```

### Phase 2: SetAuthKey and Authentication Flow
1. Once bonded, send SetAuthKey command to write auth key to ring
2. Save auth key to SharedPreferences
3. Implement GetAuthNonce -> AES encrypt -> Authenticate flow
4. Verify isAuthenticated becomes true

```bash
# Flow after pairing
adb shell am broadcast -a com.example.reverseoura.COMMAND --es cmd "setauth"
# Wait for SetAuthKey response (status 0x00 = success)
adb shell am broadcast -a com.example.reverseoura.COMMAND --es cmd "auth"
# Wait for isAuthenticated = true
```

### Phase 3: Heartbeat Monitoring
1. Start heartbeat capture via ADB command
2. Stream heartbeat data to logcat
3. Add parsing and data export
4. Implement stop command

```bash
# After authenticated
adb shell am broadcast -a com.example.reverseoura.COMMAND --es cmd "heartbeat"
# Monitor logcat for HB data
adb shell am broadcast -a com.example.reverseoura.COMMAND --es cmd "stop"
```

### Phase 4: Full Automation Script
Create a single bash script that:
1. Launches app
2. Connects and pairs (handling UI automation)
3. Sets auth key
4. Authenticates
5. Starts monitoring
6. Exports data to PC

## Technical Challenges

### BLE Privacy / RPA
The ring rotates its MAC address every ~15 minutes. Solution: match by device name containing "Oura".

### MIUI Pairing UI
On Xiaomi phones, pairing appears as notification, not modal dialog. Need to:
- Check `dumpsys notification` for Bluetooth pairing
- Expand notification shade
- Find and click "Pair & connect" action

### Ring Advertising Behavior
After factory reset, ring advertises for limited time. If pairing fails repeatedly, ring stops advertising. Solution:
- Place ring on charger to wake
- Reduce failed pairing attempts

### Connection Stability
Ring may disconnect during operations. Need:
- Auto-reconnect logic
- Retry failed commands
- State persistence

## Success Criteria

1. **Autonomous Connect**: `adb broadcast connect` results in connected state without manual intervention
2. **Autonomous Auth**: `adb broadcast auth` completes authentication
3. **Heartbeat Streaming**: Can start/stop heartbeat monitoring via ADB
4. **Data Export**: Can retrieve ring data to PC file system

## Next Actions

1. Wake up ring (put on charger)
2. Send connect command
3. When pairing dialog appears, identify UI elements
4. Implement UI automation for pairing
5. Complete SetAuthKey flow
6. Test full auth + heartbeat sequence
