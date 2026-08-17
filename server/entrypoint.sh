#!/usr/bin/env bash
set -euo pipefail

python3 -m uvicorn server.main:app --host 0.0.0.0 --port 8000 &
api_pid=$!
npm run start -- --host 0.0.0.0 --port 3000 &
web_pid=$!

shutdown() {
  kill "$api_pid" "$web_pid" 2>/dev/null || true
  wait "$api_pid" "$web_pid" 2>/dev/null || true
}

trap shutdown INT TERM EXIT
wait -n "$api_pid" "$web_pid"
