#!/bin/bash

echo "[*] Initializing DevFlow APM..."

# 1. Check for root privileges (required for raw sockets)
if [ "$EUID" -ne 0 ]; then
  echo "[!] Error: DevFlow requires raw socket access."
  echo "    Please run this script with sudo: sudo ./start.sh"
  exit 1
fi

# 2. Ensure virtual environment exists
if [ ! -d "venv" ]; then
  echo "[*] Creating virtual environment..."
  python3 -m venv venv
fi

# 3. Install requirements silently if Flask isn't found
if ! ./venv/bin/python3 -c "import flask" &> /dev/null; then
  echo "[*] Installing dependencies from requirements.txt..."
  ./venv/bin/pip install -r requirements.txt > /dev/null 2>&1
fi

# 4. Clear old bytecode cache to prevent stale imports
rm -rf devflow/__pycache__ tests/__pycache__

# 5. Launch the APM Server
echo "[*] All checks passed. Starting DevFlow..."
./venv/bin/python3 app.py