#!/usr/bin/env bash
# Quadrama relay – local launcher.
# Runs the server from the directory of this script so relative paths
# (public/, package.json) always resolve correctly.

set -u

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR" || {
  echo "[start.sh] cannot cd into $SCRIPT_DIR" >&2
  exit 1
}

if [ ! -d node_modules ]; then
  echo "[start.sh] node_modules is missing."
  echo "[start.sh] Run \"npm install\" in this directory first, then re-run ./start.sh."
  exit 2
fi

if [ ! -f server.js ]; then
  echo "[start.sh] server.js not found in $SCRIPT_DIR" >&2
  exit 1
fi

PORT="${PORT:-8080}"
HOST="${HOST:-0.0.0.0}"

export PORT HOST

echo "[start.sh] Quadrama relay starting on http://127.0.0.1:${PORT}"
echo "[start.sh] (bound to ${HOST}:${PORT}; open the URL above in a browser)"
echo "[start.sh] Stop with Ctrl-C."
echo

exec node server.js
