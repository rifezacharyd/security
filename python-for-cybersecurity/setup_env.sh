#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "[*] Creating Python virtual environment..."
python3 -m venv "$SCRIPT_DIR/venv"

echo "[*] Activating virtual environment..."
source "$SCRIPT_DIR/venv/bin/activate"

echo "[*] Upgrading pip..."
pip install --upgrade pip

echo "[*] Installing security libraries..."
pip install -r "$SCRIPT_DIR/requirements.txt"

echo "[+] Environment ready. Activate with: source venv/bin/activate"
