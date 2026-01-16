# Oura Ring Gen 3 - Reverse Engineering Project

Complete reverse engineering of the Oura Ring Gen 3 Bluetooth Low Energy (BLE) protocol and working implementations.

## Project Overview

This project provides:
- **Complete BLE protocol documentation** for Oura Ring Gen 3
- **Python BLE client** for direct ring communication
- **Android app** with full ring integration
- **Protocol analysis and research findings**

## Quick Start

### Web Dashboard + BLE Client (Recommended)

```bash
# Install uv (Python package manager)
curl -LsSf https://astral.sh/uv/install.sh | sh

# Install dependencies
uv sync

# Start Docker (parser + ML)
docker compose up -d --build

# Build frontend
cd native_parser/webapp/frontend && npm install && npm run build && cd ../..

# Start backend (from native_parser dir)
uv run uvicorn webapp.backend.main:app --host 0.0.0.0 --port 8000

# Open http://localhost:8000
```

### BLE Setup (Linux)
```bash
sudo apt install bluez                    # Debian/Ubuntu
sudo pacman -S bluez bluez-utils          # Arch/Manjaro
sudo systemctl enable --now bluetooth
sudo usermod -a -G bluetooth $USER        # Then logout/login
```

### Android App
1. Open `android_app/` in Android Studio
2. Build and run on Android device
3. Connect to your Oura Ring

## Project Structure

```
oura_ring_reverse/
├── docs/                      # Documentation
│   ├── README.md             # Documentation index & navigation
│   ├── getting-started/      # Setup, Python client, troubleshooting
│   ├── protocol/             # BLE protocol specs (overview, commands, events, auth)
│   ├── guides/               # Implementation guides (heartbeat, sleep data)
│   ├── reverse-engineering/  # RE methods (Frida, native libs, protobuf)
│   ├── security/             # Security analysis (keys, ML models)
│   └── archive/              # Original documentation preserved
│
├── python_client/             # Python BLE implementation
│   ├── oura_ble_client.py    # Main client
│   └── scan_ble.py           # BLE scanner
│
├── android_app/               # Android Studio project
│
├── native_parser/             # Protobuf & ML model tools
│   ├── ringeventparser.proto # Extracted schema (2070 lines)
│   ├── decrypted_models/     # 28 PyTorch models (decrypted)
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

See [docs/README.md](docs/README.md) for complete documentation index.

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
