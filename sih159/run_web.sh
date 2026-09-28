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

if [[ "$OSTYPE" == "darwin"* ]] && ls /dev/bpf* >/dev/null 2>&1; then
  if [ ! -r /dev/bpf0 ] || [ ! -w /dev/bpf0 ]; then
    echo "[*] Fixing /dev/bpf* permissions for packet capture..."
    if ! sudo -n chmod 666 /dev/bpf* 2>/dev/null; then
      echo "[!] Passwordless sudo not set up for this — you may be prompted for your password."
      sudo chmod 666 /dev/bpf* || echo "[!] Could not chmod /dev/bpf*; packet capture may fail without it."
    fi
  else
    echo "[✓] /dev/bpf* permissions already configured for packet capture."
  fi
fi

PORT="${PORT:-8000}"
echo "[*] Starting SecureMailScope web dashboard at http://localhost:$PORT"
exec ./.venv/bin/python -m uvicorn backend.app.main:app --host 0.0.0.0 --port "$PORT" "$@"
