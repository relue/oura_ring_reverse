# Oura Ring Reverse Engineering - Native Parser

Tools for parsing and analyzing Oura Ring data using reverse-engineered native binaries and ML models.

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                        HOST MACHINE                          │
│                                                              │
│  ┌──────────────────────┐    ┌──────────────────────────┐   │
│  │   React Frontend     │    │    Host Backend (8000)   │   │
│  │   (served by backend)│◄──►│    - REST API            │   │
│  │                      │    │    - BLE WebSocket       │   │
│  │   localhost:8000     │    │    - Calls Docker API    │   │
│  └──────────────────────┘    └───────────┬──────────────┘   │
│                                          │                   │
│                              ┌───────────▼──────────────┐   │
│                              │  Docker Container (8001) │   │
│                              │  - QEMU ARM64 Parser     │   │
│                              │  - SleepNet ML (PyTorch) │   │
│                              └──────────────────────────┘   │
└─────────────────────────────────────────────────────────────┘
```

## Requirements

- Docker
- Python 3.11+ with [uv](https://github.com/astral-sh/uv): `curl -LsSf https://astral.sh/uv/install.sh | sh`
- Node.js 18+
- Bluetooth 4.0+ adapter (for BLE)

### BLE Setup (Linux)

```bash
# Install BlueZ (Debian/Ubuntu)
sudo apt install bluez

# Arch/Manjaro
sudo pacman -S bluez bluez-utils

# Enable and start bluetooth service
sudo systemctl enable bluetooth
sudo systemctl start bluetooth

# Add user to bluetooth group (then logout/login)
sudo usermod -a -G bluetooth $USER

# If adapter is blocked
sudo rfkill unblock bluetooth
```

Verify BLE is working:
```bash
bluetoothctl show  # Should show "Powered: yes"
```

## Quick Start

```bash
# 1. Start Docker (parser + ML)
docker compose up -d --build

# 2. Install dependencies
uv sync

# 3. Build frontend
cd webapp/frontend && npm install && npm run build && cd ../..

# 4. Start backend
uv run uvicorn webapp.backend.main:app --host 0.0.0.0 --port 8000

# 5. Open http://localhost:8000
```

## Development

```bash
# Frontend dev mode (hot reload)
cd webapp/frontend && npm run dev

# Backend with auto-reload
uv run uvicorn webapp.backend.main:app --reload --port 8000

# Docker logs
docker compose logs -f
```

## License

Research/educational use only.
