#!/usr/bin/env bash
# start.sh — Start all NIDS services
# Usage: ./start.sh

set -e
ROOT="$(cd "$(dirname "$0")" && pwd)"
PYTHON_CMD="python3"

if [ -x "$ROOT/.venv/bin/python" ]; then
  PYTHON_CMD="$ROOT/.venv/bin/python"
fi

echo ""
echo "🛡️  NIDS Startup Script"
echo "══════════════════════════════════════"
echo ""

# 1. Check models trained
if [ ! -f "$ROOT/ml-service/models/random_forest_model.pkl" ]; then
  echo "⚠  Models not found. Running training first…"
  cd "$ROOT/ml-service"
  "$PYTHON_CMD" train.py
fi

# 2. Start ML service
echo "[ 1/3 ] Starting ML service (port 8000)…"
cd "$ROOT/ml-service"
if ! "$PYTHON_CMD" -c "import uvicorn" >/dev/null 2>&1; then
  echo "Installing ML service dependencies..."
  "$PYTHON_CMD" -m pip install -r requirements.txt
fi
"$PYTHON_CMD" -m uvicorn main:app --port 8000 &
ML_PID=$!
sleep 2

# 3. Start Node backend
echo "[ 2/3 ] Starting Node.js backend (port 3001)…"
cd "$ROOT/server"
npm install --silent
node index.js &
NODE_PID=$!
sleep 1

# 4. Start React frontend
echo "[ 3/3 ] Starting React dashboard (port 5173)…"
cd "$ROOT/client"
npm install --silent
npm run dev &
REACT_PID=$!

echo ""
echo "✅  All services started!"
echo "   Dashboard  : http://localhost:5173"
echo "   Backend    : http://localhost:3001"
echo "   ML Service : http://localhost:8000"
echo ""
echo "   Run simulator: cd packet-capture && python capture.py --simulate"
echo ""
echo "   Press Ctrl+C to stop all services"
echo ""

# Cleanup on exit
cleanup() {
  echo ""
  echo "Stopping services…"
  kill $ML_PID $NODE_PID $REACT_PID 2>/dev/null
  exit 0
}
trap cleanup SIGINT SIGTERM

wait
