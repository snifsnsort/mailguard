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
RUN apt-get update && apt-get install -y --no-install-recommends \
    wget apt-transport-https software-properties-common curl \
    && wget -q "https://packages.microsoft.com/config/debian/12/packages-microsoft-prod.deb" \
    && dpkg -i packages-microsoft-prod.deb \
    && apt-get update \
    && apt-get install -y --no-install-recommends powershell \
    && rm -rf /var/lib/apt/lists/* packages-microsoft-prod.deb

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

# Initialise DB and start
ENV PYTHONPATH=/app/backend
EXPOSE 8000
CMD ["python", "start.py"]
