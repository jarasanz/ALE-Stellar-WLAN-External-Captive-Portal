#!/usr/bin/env bash
set -euo pipefail

source .venv/bin/activate

mkdir -p data
python3 init_db.py

echo "[1/2] Starting RADIUS..."
sudo -E "$(which python3)" radius_server.py >data/radius_stdout.log 2>data/radius_stderr.log &
RADIUS_WRAPPER_PID=$!

sleep 0.5
if ! ps -p "$RADIUS_WRAPPER_PID" >/dev/null; then
  echo "RADIUS exited immediately. Logs:"
  echo "---- stderr ----"
  sed -n '1,200p' data/radius_stderr.log || true
  echo "---- stdout ----"
  sed -n '1,200p' data/radius_stdout.log || true
  exit 1
fi

echo "[2/2] Starting Portal..."
sudo -E "$(which python3)" app.py >data/portal_stdout.log 2>data/portal_stderr.log &
PORTAL_WRAPPER_PID=$!

# Wait briefly for sockets to appear (avoids race in ss output)
for i in {1..30}; do
  # RADIUS UDP ports
  if sudo ss -lun | egrep -q ':(1812|1813)\b'; then
    # Portal TCP ports
    if sudo ss -ltn | egrep -q ':(80|8080)\b'; then
      break
    fi
  fi
  sleep 0.1
done

# Get the real python PIDs (not the sudo wrapper PID)
RADIUS_PY_PID="$(pgrep -nf 'python3 .*radius_server\.py' || true)"
PORTAL_PY_PID="$(pgrep -nf 'python3 .*app\.py' || true)"

echo "PIDs: radius_sudo=$RADIUS_WRAPPER_PID radius_py=${RADIUS_PY_PID:-?} portal_sudo=$PORTAL_WRAPPER_PID portal_py=${PORTAL_PY_PID:-?}"
echo

echo "RADIUS (UDP 1812/1813):"
sudo ss -lunp | egrep ':(1812|1813)\b' || true
echo "RADIUS (python only):"
sudo ss -lunp | egrep ':(1812|1813)\b' | grep -i python || true

echo
echo "Captive Portal (TCP 80/8080):"
sudo ss -ltnp | egrep ':(80|8080)\b' || true
echo "Portal (python only):"
sudo ss -ltnp | egrep ':(80|8080)\b' | grep -i python || true

echo
echo "Press Ctrl+C to stop."

trap 'sudo kill '"$PORTAL_WRAPPER_PID"' 2>/dev/null || true; sudo kill '"$RADIUS_WRAPPER_PID"' 2>/dev/null || true' INT TERM
wait

