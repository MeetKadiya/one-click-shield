# Multi-stage Dockerfile for 100% Free All-in-One Cloud Deployment
# (Compatible with Render, HuggingFace Spaces, Koyeb, Railway, Fly.io)

FROM node:18-alpine AS frontend-builder
WORKDIR /app/frontend
COPY frontend/package*.json ./
RUN npm install
COPY frontend/ ./
RUN npm run build

FROM python:3.11-slim
WORKDIR /app

# Install OpenSSL runtime tools for TLS socket probing
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    libssl-dev \
    dnsutils \
    && rm -rf /var/lib/apt/lists/*

# Install Python backend dependencies
COPY backend/requirements.txt ./backend/
RUN pip install --no-cache-dir -r ./backend/requirements.txt

# Copy application source code
COPY backend/ ./backend/
COPY --from=frontend-builder /app/frontend/dist /app/frontend/dist

ENV PORT=8000
EXPOSE 8000

WORKDIR /app/backend
CMD ["sh", "-c", "uvicorn main:app --host 0.0.0.0 --port ${PORT:-8000}"]
