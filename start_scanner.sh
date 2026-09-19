#!/usr/bin/env sh
# Secret Scanner Pro — Linux/macOS headless launcher (all sources).
# Usage: ./start_scanner.sh [--stats|--export ...]
set -eu
cd "$(dirname "$0")"

echo ""
echo " Secret Scanner Pro - Headless scanner (all sources)"
echo " Operator UI: ./start_tui.sh"
echo " Working dir: $(pwd)"
echo ""

if ! command -v python3 >/dev/null 2>&1; then
  echo "[ERROR] python3 not found in PATH"
  exit 1
fi

exec python3 main_optimized.py --all-sources "$@"
