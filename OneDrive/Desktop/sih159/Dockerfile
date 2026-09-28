# ---- Stage 1: Build Frontend (React + Vite) ----
FROM node:20-slim AS frontend
WORKDIR /app/frontend

COPY frontend/package*.json ./
RUN npm ci

COPY frontend/ ./
RUN npm run build

# ---- Stage 2: Backend & Runtime (Python + FastAPI) ----
FROM python:3.11-slim
WORKDIR /app

# System dependencies for WeasyPrint (PDF report export) and fonts
RUN apt-get update && apt-get install -y --no-install-recommends \
    libpango-1.0-0 \
    libpangoft2-1.0-0 \
    libharfbuzz0b \
    libgdk-pixbuf-2.0-0 \
    shared-mime-info \
    && rm -rf /var/lib/apt/lists/*

# Install Python requirements
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application source code
COPY . .

# Copy compiled frontend from build stage into frontend/dist
COPY --from=frontend /app/frontend/dist frontend/dist

# Ensure ML models are initialized
RUN python train.py

# Render assigns PORT dynamically; default to 8000 for local runs
ENV PORT=8000
EXPOSE 8000

CMD ["sh", "-c", "uvicorn backend.app.main:app --host 0.0.0.0 --port ${PORT}"]
