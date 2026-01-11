# Oura Ring Gen 3 - Reverse Engineering Project

Complete reverse engineering of the Oura Ring Gen 3 Bluetooth Low Energy (BLE) protocol and working implementations.

## Project Overview

This project provides:
- **Complete BLE protocol documentation** for Oura Ring Gen 3
- **Python BLE client** for direct ring communication
- **Android app** with full ring integration
- **Protocol analysis and research findings**

## Quick Start

### Python BLE Client
```bash
cd python_client
python oura_ble_client.py
```

### Android App
1. Open `android_app/` in Android Studio
2. Build and run on Android device
3. Connect to your Oura Ring

## Project Structure

```
oura_ring_reverse/
├── docs/                      # Documentation
│   ├── ANALYSIS_REPORT.md    # Complete reverse engineering report
│   ├── protocol/              # Protocol specifications
│   │   ├── OURA_RING_COMMANDS.md
│   │   └── oura_ring_complete_protocol.md
│   └── BLUETOOTH_TROUBLESHOOTING.md
│
├── python_client/             # Python BLE implementation
│   ├── oura_ble_client.py    # Main client
│   └── scan_ble.py           # BLE scanner
│
├── android_app/               # Android Studio project
│   ├── app/src/main/java/com/example/reverseoura/
│   │   ├── MainActivity.kt   # Main app with BLE
│   │   └── RingEventParser.kt
│   └── build.gradle.kts
│
├── frida_scripts/             # Dynamic instrumentation
│
└── _large_files/              # NOT IN GIT (local only)
    ├── apks/                  # Original Oura APK (252MB)
    ├── decompiled/            # Decompiled sources (843MB)
    ├── native/                # Native libraries
    └── tools/                 # Build tools (4.4GB)
```

## Features

### Protocol Documentation
- 36+ BLE commands fully documented
- Authentication flow
- Real-time heartbeat streaming
- Sleep data retrieval
- Ring configuration

### Python Client
- Direct ring communication
- Real-time BPM monitoring
- Event data retrieval
- Authentication management

### Android App
- Full BLE connection
- Authentication with ring
- Live heartbeat monitoring
- Sleep data parsing
- Ring management (sync time, factory reset)
- Data browser UI

## BLE Protocol

**Service UUID:** `98ed0001-a541-11e4-b6a0-0002a5d5c51b`

**Key Commands:**
- `0x20` - GetFeatureStatus
- `0x22` - SetFeatureMode
- `0x24` - SetRealtimeMeasurements
- `0x10` - GetEvent
- `0x42` - Authenticate
- And 30+ more...

See `docs/protocol/` for complete specifications.

## Requirements

### Python Client
- Python 3.8+
- Bleak library
- Bluetooth 4.0+ adapter

### Android App
- Android Studio Koala or newer
- Android 12+ device (BLE permissions)
- Bluetooth 4.0+ hardware

## Moving to Another PC

### Files Tracked in Git (~50-100MB)
- Documentation
- Python client code
- Android app source code
- Frida scripts

### Large Files NOT in Git (5.6GB)
The `_large_files/` folder contains:
- Original Oura APK
- Decompiled sources
- Native libraries
- Build tools

**To transfer everything:**
1. Clone/pull git repo
2. Separately copy `_large_files/` folder if needed

## Security & Legal

This project is for **educational and research purposes only**.

- Decompiled code is for analysis only (not redistributed)
- No proprietary algorithms or trade secrets disclosed
- Protocol documentation derived from black-box analysis
- Respects Oura's intellectual property

## Credits

Reverse engineering and implementation by the community.

## License

Research findings and documentation: Educational use only
Original code implementations: MIT License (see individual files)
