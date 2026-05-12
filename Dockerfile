# ===========================================================================
# mhr-cfw – Optimized & secure production Docker image
# Build:  docker build -t mhr-cfw .
# Run:    docker run -d --name mhr-cfw -p 8085:8085 -p 1080:1080 \
#             -v $(pwd)/config.json:/app/config.json:ro \
#             -v mhr-cfw-data:/app/data \
#             mhr-cfw
# ===========================================================================

# ── Stage 1: install Python dependencies ─────────────────────────────
FROM python:3.13-slim AS builder

WORKDIR /app

# Install build tools only if needed for compilation (none for current deps)
# RUN apt-get update && apt-get install -y --no-install-recommends gcc libc-dev && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --user --no-cache-dir -r requirements.txt

# ── Stage 2: final runtime image ─────────────────────────────────────
FROM python:3.13-slim

# Environment
ENV PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

# Install runtime dependencies
RUN apt-get update && \
    apt-get install -y --no-install-recommends ca-certificates && \
    rm -rf /var/lib/apt/lists/*

# Create non‑root user
RUN groupadd -r proxy && useradd -r -g proxy -d /app -s /sbin/nologin proxy

WORKDIR /app

# Copy installed Python packages from builder
COPY --from=builder /root/.local /home/proxy/.local

# Copy application code (exclude config.json – it will be mounted)
COPY src/ /app/src/
COPY main.py setup.py logging_utils.py constants.py cert_installer.py \
     lan_utils.py google_ip_scanner.py mitm.py proxy_server.py /app/
# Include any extra data files if needed (e.g., requirements.txt for reference)
COPY requirements.txt /app/

# Create writable directory for CA certificates and logs
RUN mkdir -p /app/ca /app/logs && chown -R proxy:proxy /app/ca /app/logs

# Switch to unprivileged user
USER proxy

# Ensure local bin is in PATH
ENV PATH="/home/proxy/.local/bin:${PATH}"

EXPOSE 8085 1080

# Health check – confirms HTTP proxy is listening
HEALTHCHECK --interval=30s --timeout=3s --start-period=20s --retries=3 \
    CMD python -c "import socket; s=socket.socket(); s.connect(('127.0.0.1',8085)); s.close()"

CMD ["python", "main.py"]