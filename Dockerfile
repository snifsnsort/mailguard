# ── Stage 1: Build React frontend ────────────────────────────────────────────
FROM node:20-alpine AS frontend-builder
WORKDIR /app/frontend
COPY frontend/package*.json ./
RUN npm install
COPY frontend/ ./
RUN npm run build

# ── Stage 2: Build final image ────────────────────────────────────────────────
FROM python:3.12-slim-bookworm

# Install system deps + PowerShell 7
# Uses --tries=3 on wget and retries apt-get install up to 3 times.
# Microsoft's package repo occasionally returns transient errors (exit code 4)
# which cause the entire build to fail. The retry loop handles that.
RUN apt-get update \
    && apt-get install -y --no-install-recommends wget apt-transport-https ca-certificates curl \
    && wget -q --tries=3 --waitretry=5 \
           "https://packages.microsoft.com/config/debian/12/packages-microsoft-prod.deb" \
    && dpkg -i packages-microsoft-prod.deb \
    && rm packages-microsoft-prod.deb \
    && for i in 1 2 3; do \
           apt-get update \
           && apt-get install -y --no-install-recommends powershell \
           && break \
           || { echo "PowerShell apt attempt $i/3 failed — retrying in 10s"; sleep 10; }; \
       done \
    && rm -rf /var/lib/apt/lists/*

# Install ExchangeOnlineManagement PS module
RUN pwsh -Command "Install-Module ExchangeOnlineManagement -Force -AllowClobber -Scope AllUsers"

WORKDIR /app

# Python deps
COPY backend/requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

# Backend source
COPY backend/ ./backend/

# Frontend build output → served by FastAPI static files
COPY --from=frontend-builder /app/frontend/dist ./frontend/dist

WORKDIR /app/backend

# Persistent data directory — Azure File Share mounts here, never shadows source code
RUN mkdir -p /data

# Initialise DB and start
ENV PYTHONPATH=/app/backend
EXPOSE 8000
CMD ["python", "start.py"]
