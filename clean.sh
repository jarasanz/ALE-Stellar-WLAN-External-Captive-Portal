#!/usr/bin/env bash
set -euo pipefail

echo "Stopping lab processes (best effort)..."
pkill -f radius_server.py || true
pkill -f "python3 app.py" || true
pkill -f "python3 init_db.py" || true

echo "Removing SQLite + logs..."
rm -f data/cp.db data/cp.db-wal data/cp.db-shm
rm -f data/portal_events.jsonl data/radius_events.jsonl

echo "Done. Environment reset."

