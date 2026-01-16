# Oura Ring Parser Docker Image
# Native ARM64 parser via QEMU + ML models + FastAPI + React

# =============================================================================
# Stage 1: Build Frontend
# =============================================================================
FROM node:20-slim AS frontend-builder

WORKDIR /build
COPY webapp/frontend/package*.json ./
RUN npm ci --silent

COPY webapp/frontend/ ./
RUN npm run build

# =============================================================================
# Stage 2: Python Runtime with QEMU
# =============================================================================
FROM python:3.11-slim

LABEL maintainer="Oura Ring Reverse Engineering Project"
LABEL description="Native ring event parser with SleepNet ML and web dashboard"

# Install system dependencies (including curl for healthcheck)
RUN apt-get update && apt-get install -y --no-install-recommends \
    qemu-user-static \
    curl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Install Python dependencies first (better layer caching)
COPY requirements.docker.txt requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

# =============================================================================
# Copy Native Parser Components (ARM64 binaries + Android sysroot)
# =============================================================================

# ARM64 parser binary
COPY parser_bridge_android ./

# Android system root (linker, libc, etc.) - REQUIRED for QEMU
COPY android_root/ ./android_root/

# Native libraries
COPY libs/ ./libs/

# =============================================================================
# Copy ML Models (~41MB)
# =============================================================================
COPY decrypted_models/ ./decrypted_models/

# =============================================================================
# Copy Python Code
# =============================================================================
COPY ringeventparser_pb2.py ./
COPY complete_final_pb2.py ./
COPY oura_ecore.py ./
COPY oura/ ./oura/
COPY ml_inference/ ./ml_inference/

# =============================================================================
# Copy IBI Correction Bridges (for EcoreWrapper / SleepNet ML)
# =============================================================================
COPY ibi_correction_bridge_v7 ibi_correction_bridge_v8 ibi_correction_bridge_v9 ibi_correction_bridge_v10 ./
COPY ibi_correction_bridge_android ./

# =============================================================================
# Copy Backend + Frontend
# =============================================================================
COPY webapp/backend/ ./webapp/backend/
COPY --from=frontend-builder /build/dist ./webapp/frontend/dist

# =============================================================================
# Setup
# =============================================================================

# Create data directory for mounted volumes
RUN mkdir -p /app/input_data

# Environment variables
ENV PYTHONPATH=/app
ENV PYTHONUNBUFFERED=1
ENV QEMU_LD_PREFIX=/app/android_root

# Expose API port
EXPOSE 8000

# Healthcheck
HEALTHCHECK --interval=30s --timeout=10s --start-period=10s --retries=3 \
    CMD curl -f http://localhost:8000/health || exit 1

# Default: run FastAPI backend
CMD ["python", "-m", "uvicorn", "webapp.backend.main:app", "--host", "0.0.0.0", "--port", "8000"]
