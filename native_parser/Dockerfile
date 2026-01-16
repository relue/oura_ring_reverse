# Oura Ring Parser Docker Image
# Packages native ARM64 parser with QEMU emulation + ML models + web UI

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

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    qemu-user-static \
    && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /app

# Install Python dependencies first (better caching)
COPY requirements.docker.txt requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

# =============================================================================
# Copy Native Parser Components (ARM64 binaries + Android sysroot)
# =============================================================================

# ARM64 parser binary
COPY parser_bridge_android ./

# Android system root (linker, libc, etc.)
COPY android_root/ ./android_root/

# Native libraries (libringeventparser.so, libprotobuf-lite.so, etc.)
COPY libs/ ./libs/

# =============================================================================
# Copy ML Models
# =============================================================================
COPY decrypted_models/ ./decrypted_models/

# =============================================================================
# Copy Python Code
# =============================================================================

# Protobuf schema
COPY ringeventparser_pb2.py ./

# Main oura package
COPY oura/ ./oura/

# ML inference code
COPY ml_inference/ ./ml_inference/

# =============================================================================
# Copy Backend
# =============================================================================
COPY webapp/backend/ ./webapp/backend/

# =============================================================================
# Copy Built Frontend from Stage 1
# =============================================================================
COPY --from=frontend-builder /build/dist ./webapp/frontend/dist

# =============================================================================
# Setup
# =============================================================================

# Create data directory for input/output
RUN mkdir -p /app/input_data

# Environment
ENV PYTHONPATH=/app
ENV PYTHONUNBUFFERED=1

# Expose ports (backend API + optional frontend dev)
EXPOSE 8000

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8000/health || exit 1

# Default command: run backend server
CMD ["python", "-m", "uvicorn", "webapp.backend.main:app", "--host", "0.0.0.0", "--port", "8000"]
