#!/usr/bin/env bash
# SecureDep v2 — deploy script
# Usage: bash start.sh
set -e

echo ""
echo "  ╔══════════════════════════════╗"
echo "  ║      SecureDep v2            ║"
echo "  ╚══════════════════════════════╝"
echo ""

# Check Python
if ! command -v python3 &>/dev/null; then
  echo "  ❌ Python 3 not found → https://python.org"; exit 1
fi
echo "  ✅ Python $(python3 --version 2>&1)"

# Install deps
echo "  📦 Installing backend dependencies…"
cd "$(dirname "$0")/backend"
pip install -q -r requirements.txt
echo "  ✅ Dependencies installed"

# Check optional tools
echo ""
echo "  🔍 Scanner availability:"
command -v osv-scanner &>/dev/null && echo "     ✅ osv-scanner" || echo "     ⚠️  osv-scanner missing (go install github.com/google/osv-scanner/cmd/osv-scanner@latest)"
command -v semgrep     &>/dev/null && echo "     ✅ semgrep"     || echo "     ⚠️  semgrep missing (pip install semgrep)"
command -v bandit      &>/dev/null && echo "     ✅ bandit"      || echo "     ⚠️  bandit missing (pip install bandit)"

echo ""
echo "  🚀 Starting API → http://localhost:8000"
echo "  📊 Open dashboard → http://127.0.0.1:8000"
echo "  📖 API docs → http://localhost:8000/docs"
echo ""
echo "  ⚡ The dashboard is served directly from the API."
echo "     Do NOT open frontend/index.html as a file — use the URL above."
echo ""
echo "  Press Ctrl+C to stop"
echo ""

uvicorn main:app --host 0.0.0.0 --port 8000 --reload
