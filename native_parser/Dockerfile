# Oura Ring Parser + ML API (Docker)
# Provides QEMU-based native parser and SleepNet ML inference
# UI and main backend run on host with BLE access

FROM python:3.11-slim

LABEL maintainer="Oura Ring Reverse Engineering Project"
LABEL description="Parser and ML inference API with QEMU ARM64 emulation"

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    qemu-user-static \
    curl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Install Python dependencies
COPY requirements.docker.txt requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

# =============================================================================
# Copy Native Parser Components (ARM64 binaries + Android sysroot)
# =============================================================================
COPY parser_bridge_android ./
COPY android_root/ ./android_root/
COPY libs/ ./libs/

# =============================================================================
# Copy IBI Correction Bridges (for EcoreWrapper / SleepNet ML)
# =============================================================================
COPY ibi_correction_bridge_v7 ibi_correction_bridge_v8 ibi_correction_bridge_v9 ibi_correction_bridge_v10 ./
COPY ibi_correction_bridge_android ./

# =============================================================================
# Copy Sleep Score Bridges (for native sleep score calculation)
# =============================================================================
COPY sleep_score_minutes_ndk ./
COPY readiness_score_bridge ./

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
# Copy Parser API
# =============================================================================
COPY parser_api.py ./

# =============================================================================
# Setup
# =============================================================================

# Create data directory for mounted volumes
RUN mkdir -p /app/input_data

# Environment variables
ENV PYTHONPATH=/app
ENV PYTHONUNBUFFERED=1
# Default timezone (can be overridden in docker-compose.yml)
ENV TZ=Europe/Berlin
ENV QEMU_LD_PREFIX=/app/android_root

# Expose Parser API port
EXPOSE 8001

# Healthcheck
HEALTHCHECK --interval=30s --timeout=10s --start-period=10s --retries=3 \
    CMD curl -f http://localhost:8001/health || exit 1

# Run Parser API
CMD ["python", "-m", "uvicorn", "parser_api:app", "--host", "0.0.0.0", "--port", "8001"]
