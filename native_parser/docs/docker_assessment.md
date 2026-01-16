# Docker Assessment for Oura Ring Parser

## Components to Package

### 1. Native Parser (ARM64 via QEMU)
| Component | Size | Description |
|-----------|------|-------------|
| `parser_bridge_android` | 16KB | ARM64 binary, entry point |
| `android_root/` | 11MB | Android linker + system libs |
| `libs/` | 8MB | libringeventparser.so, protobuf, etc. |
| QEMU | ~50MB | qemu-aarch64 for ARM emulation |

### 2. ML Models
| Model | Size | Required |
|-------|------|----------|
| `sleepnet_moonstone_1_1_0.pt` | 40MB | Yes (sleep stage classification) |
| `dhrv_imputation_1_0_3.pt` | 1MB | Optional (HRV imputation) |

### 3. Python Dependencies
| Package | Size | Notes |
|---------|------|-------|
| PyTorch (CPU) | ~200MB | Required for ML inference |
| protobuf | ~5MB | Protobuf parsing |
| bleak | ~1MB | BLE client (needs bluetooth) |
| FastAPI/uvicorn | ~5MB | Backend API |

### 4. Frontend
| Component | Size | Notes |
|-----------|------|-------|
| Node.js build | ~50MB | Build-time only |
| Static dist | ~5MB | Production output |

## QEMU Integration

The key insight: **QEMU user-mode emulation works perfectly in Docker!**

```bash
# How QEMU is invoked:
qemu-aarch64 ./parser_bridge_android input.txt [ring_time] [utc_millis]

# With environment:
QEMU_LD_PREFIX=./android_root
```

**QEMU packages available:**
- Debian/Ubuntu: `qemu-user-static` or `qemu-user`
- Alpine: `qemu-aarch64`

## Estimated Docker Image Size

| Variant | Size | Features |
|---------|------|----------|
| Full (with ML) | ~600MB | Parser + SleepNet ML + Backend + Frontend |
| Minimal (no ML) | ~200MB | Parser + Backend only (raw stages) |
| With PyTorch GPU | ~3GB | Not recommended for this use case |

## Dockerfile Strategy

### Multi-stage Build (Recommended)

```dockerfile
# Stage 1: Build frontend
FROM node:20-slim AS frontend-builder
WORKDIR /app
COPY webapp/frontend/package*.json ./
RUN npm ci
COPY webapp/frontend/ ./
RUN npm run build

# Stage 2: Python + QEMU runtime
FROM python:3.11-slim

# Install QEMU for ARM64 emulation
RUN apt-get update && apt-get install -y \
    qemu-user-static \
    && rm -rf /var/lib/apt/lists/*

# Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy native parser components
COPY parser_bridge_android /app/
COPY android_root/ /app/android_root/
COPY libs/ /app/libs/

# Copy ML models
COPY decrypted_models/ /app/decrypted_models/

# Copy Python code
COPY oura/ /app/oura/
COPY ml_inference/ /app/ml_inference/
COPY ringeventparser_pb2.py /app/

# Copy backend
COPY webapp/backend/ /app/webapp/backend/

# Copy built frontend
COPY --from=frontend-builder /app/dist /app/webapp/frontend/dist

# Create data directory
RUN mkdir -p /app/input_data

WORKDIR /app
ENV PYTHONPATH=/app

EXPOSE 8000 5173
CMD ["python", "-m", "uvicorn", "webapp.backend.main:app", "--host", "0.0.0.0"]
```

## BLE/Bluetooth Considerations

### Option A: Backend-only (No BLE in container)
- Simplest approach
- User syncs data externally, mounts as volume
- `docker run -v /path/to/data:/app/input_data ...`

### Option B: Full BLE access (requires privileges)
```bash
# Run with bluetooth access
docker run --privileged \
  -v /var/run/dbus:/var/run/dbus \
  --net=host \
  oura-parser
```

**Recommendation:** Option A is cleaner. Use host BLE tools or mobile app for sync.

## Architecture Support

| Host Arch | QEMU | Status |
|-----------|------|--------|
| x86_64 | qemu-aarch64 | ✅ Works (tested) |
| aarch64 | Not needed | ✅ Native |
| ARM32 | qemu-aarch64 | ⚠️ Should work |

For multi-arch images, can build separate variants:
- `oura-parser:amd64` - Uses QEMU
- `oura-parser:arm64` - Native ARM64, no QEMU needed

## Volumes and Data

```bash
# Recommended volume mounts
docker run -d \
  -v /path/to/ring_events.txt:/app/input_data/ring_events.txt:ro \
  -v /path/to/output:/app/input_data/output \
  -p 8000:8000 \
  oura-parser
```

## Build Commands

```bash
# Build image
docker build -t oura-parser .

# Run with data volume
docker run -d \
  -v $(pwd)/input_data:/app/input_data \
  -p 8000:8000 \
  oura-parser

# Parse data manually
docker exec oura-parser python -m oura.native.parser

# Interactive shell
docker exec -it oura-parser bash
```

## Summary

| Aspect | Assessment |
|--------|------------|
| **Feasibility** | ✅ Fully feasible |
| **QEMU** | ✅ Works in Docker |
| **Image Size** | 600MB (reasonable) |
| **BLE** | ⚠️ Best to handle externally |
| **Complexity** | Medium (multi-stage build) |
| **Performance** | Good (QEMU overhead ~10-20%) |

**Verdict: Yes, we can package everything in Docker including QEMU!**
