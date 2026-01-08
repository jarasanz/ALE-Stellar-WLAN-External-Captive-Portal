#!/usr/bin/env bash
set -euo pipefail

source .venv/bin/activate

mkdir -p data
python3 init_db.py

echo "[1/2] Starting RADIUS..."
sudo -E $(which python3) radius_server.py >data/radius_stdout.log 2>data/radius_stderr.log &
RADIUS_PID=$!

sleep 0.5
if ! ps -p "$RADIUS_PID" >/dev/null; then
  echo "RADIUS exited immediately. Logs:"
  echo "---- stderr ----"
  sed -n '1,200p' data/radius_stderr.log || true
  echo "---- stdout ----"
  sed -n '1,200p' data/radius_stdout.log || true
  exit 1
fi

echo "[2/2] Starting Portal..."
sudo -E $(which python3) app.py >data/portal_stdout.log 2>data/portal_stderr.log &
PORTAL_PID=$!

echo "PIDs: radius=$RADIUS_PID portal=$PORTAL_PID"
echo
echo "Listening UDP sockets:"
sudo ss -lunp | egrep ':(1812|1813)\b' || true
echo
echo "Press Ctrl+C to stop."

trap "sudo kill $PORTAL_PID 2>/dev/null || true; sudo kill $RADIUS_PID 2>/dev/null || true" INT TERM
wait

