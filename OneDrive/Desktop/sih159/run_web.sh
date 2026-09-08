#!/usr/bin/env bash
# Launch the SecureMailScope web dashboard (API + frontend).
# Ensure Python deps are installed:  pip install -r requirements.txt
# Ensure frontend is built:         cd frontend && npm install && npm run build

set -e
PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$PROJECT_ROOT"

if [ ! -d ".venv" ]; then
  echo "[!] Creating virtual environment..."
  python3 -m venv .venv
  ./.venv/bin/pip install -r requirements.txt
fi

if [ ! -d "frontend/dist" ]; then
  echo "[!] Frontend not built. Building..."
  (cd frontend && npm install && npm run build)
fi

echo "[*] Starting SecureMailScope web dashboard at http://localhost:8000"
exec ./.venv/bin/python -m uvicorn backend.app.main:app --host 0.0.0.0 --port 8000
