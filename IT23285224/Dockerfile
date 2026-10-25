# Multi-Stage Dockerfile for Lightweight Reconnaissance Detection Service
FROM python:3.11-slim as base

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONPATH=/app

WORKDIR /app

# Install system utilities
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

# Install python dependencies
COPY reconnaissance-ids/requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r /app/requirements.txt

# Copy source and configurations
COPY reconnaissance-ids/src /app/src
COPY reconnaissance-ids/configs /app/configs
COPY reconnaissance-ids/models /app/models
COPY reconnaissance-ids/README.md /app/README.md

# Default ports: 8000 (FastAPI), 8080 (Mock SDN Mitigation Receiver)
EXPOSE 8000 8080

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD curl -f http://localhost:8000/health || exit 1

CMD ["uvicorn", "src.api.app:app", "--host", "0.0.0.0", "--port", "8000"]
