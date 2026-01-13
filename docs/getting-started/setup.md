# Project Setup Guide

**Last Updated:** 2026-01-12

---

## Overview

This project provides complete reverse engineering of the Oura Ring Gen 3 Bluetooth Low Energy (BLE) protocol, including:
- **Complete BLE protocol documentation**
- **Python BLE client** for direct ring communication
- **Android app** with full ring integration
- **28 decrypted PyTorch ML models**
- **Protobuf schema** for ring event parsing

---

## Project Structure

```
oura_ring_reverse/
├── docs/                      # Documentation (you are here)
│   ├── getting-started/       # Setup and basics
│   ├── protocol/              # BLE protocol specs
│   ├── guides/                # Implementation guides
│   ├── reverse-engineering/   # RE methodology
│   ├── security/              # Security analysis
│   └── status/                # Project progress
│
├── python_client/             # Python BLE implementation
│   ├── oura_ble_client.py    # Main client
│   └── scan_ble.py           # BLE scanner
│
├── android_app/               # Android Studio project
│   └── app/src/main/java/...
│
├── native_parser/             # Native library tools
│   ├── ringeventparser.proto # Extracted protobuf schema
│   ├── decrypted_models/     # 28 PyTorch models
│   └── *.py                  # Parsing scripts
│
├── frida_scripts/             # Dynamic instrumentation
│
└── _large_files/              # NOT IN GIT (local only)
    ├── apks/                  # Original Oura APK (252MB)
    ├── decompiled/            # Decompiled sources (843MB)
    ├── models/                # Encrypted ML models
    └── tools/                 # Build tools (4.4GB)
```

---

## Quick Start

### Python BLE Client

```bash
cd python_client
pip install bleak
python oura_ble_client.py
```

### Android App

1. Open `android_app/` in Android Studio
2. Build and run on Android device (Android 12+)
3. Connect to your Oura Ring

---

## Requirements

### Python Client
- Python 3.8+
- Bleak library (`pip install bleak`)
- Bluetooth 4.0+ adapter

### Android App
- Android Studio Koala or newer
- Java 17+
- Android 12+ device (BLE permissions)
- Bluetooth 4.0+ hardware

### Native Parser
- Python 3.8+
- protobuf (`pip install protobuf`)
- pycryptodome (`pip install pycryptodome`) for model decryption

---

## Two-Part Structure

This project is organized into:
1. **Git-tracked files** (~32MB) - Code, docs, scripts
2. **Large local files** (5.6GB) - APKs, decompiled code, tools

### Git Repository (~32MB)
- All documentation
- Working Python client
- Android Studio project
- Frida scripts
- Native parser scripts

### _large_files/ Folder (5.6GB - NOT in git)
```
_large_files/
├── apks/
│   └── Oura_6.14.0_APKPure.xapk    # Original app (252MB)
├── decompiled/                      # Decompiled Java (843MB)
├── models/assets/                   # Encrypted .pt.enc files
└── tools/                           # Build tools (4.4GB)
```

---

## Transferring to Another PC

### Quick Transfer (Git Only)

If you only need working code and documentation:

```bash
# On new PC
git clone <repository-url>
cd oura_ring_reverse

# Run Python client
cd python_client
pip install bleak
python oura_ble_client.py

# Or open Android app
# Open android_app/ in Android Studio
```

**This gives you:**
- Working Android app
- Python BLE client
- Complete protocol documentation
- Frida scripts

### Complete Transfer (Everything)

To transfer ALL files including decompiled sources:

**On current PC:**
```bash
# 1. Push git repo
git push origin master

# 2. Create archive of large files
tar -czf oura_large_files.tar.gz _large_files/
# Creates ~1.5GB compressed file
```

**On new PC:**
```bash
# 1. Clone git repo
git clone <repository-url>
cd oura_ring_reverse

# 2. Extract large files
tar -xzf /path/to/oura_large_files.tar.gz
```

---

## File Sizes

| Component | Size | Transfer Method |
|-----------|------|-----------------|
| Git repo | 32MB | Git clone |
| APKs | 252MB | Archive |
| Decompiled code | 843MB | Archive |
| Tools | 4.4GB | Archive (optional) |
| **Total** | **5.6GB** | |

**Compressed:** ~1.5GB with tar.gz

---

## Verification After Setup

### Check Git Status
```bash
git status  # Should show clean working tree
```

### Check Python Client
```bash
cd python_client
python -c "import bleak; print('OK')"
```

### Check Android App
```bash
cd android_app
./gradlew assembleDebug  # Should build successfully
```

### Check Native Parser
```bash
cd native_parser
python -c "from ringeventparser_pb2 import *; print('OK')"
```

---

## Common Issues

### Python Dependencies Missing
```bash
pip install bleak protobuf pycryptodome
```

### Android Studio Can't Find Project
- Ensure you open the `android_app/` folder, not the root
- Check `android_app/build.gradle.kts` exists

### Bluetooth Permission Denied (Linux)
```bash
sudo setcap 'cap_net_raw,cap_net_admin+eip' $(readlink -f $(which python))
```

---

## Next Steps

1. Read [Protocol Overview](../protocol/overview.md) to understand BLE communication
2. Try [Heartbeat Monitoring](../guides/heartbeat-monitoring.md) for live HR
3. Explore [Sleep Data](../guides/sleep-data.md) for sleep analysis

---

*Merged from: README.md + TRANSFER_GUIDE.md*
