#!/usr/bin/env sh
# Secret Scanner Pro — Linux/macOS launcher (opens TUI).
# Usage: ./start_tui.sh   (or: python3 main_optimized.py)
set -eu
cd "$(dirname "$0")"

echo ""
echo " Secret Scanner Pro - Operator TUI"
echo " Working dir: $(pwd)"
echo ""

if ! command -v python3 >/dev/null 2>&1; then
  echo "[ERROR] python3 not found in PATH"
  echo "Install Python 3.11+ and retry."
  exit 1
fi

if [ ! -f "config_local.py" ] && [ -f "config_local.py.example" ]; then
  echo "[WARN] config_local.py missing."
  echo "       cp config_local.py.example config_local.py and add GitHub tokens."
  echo "       Path: $(pwd)/config_local.py"
  echo ""
fi

exec python3 main_optimized.py "$@"
