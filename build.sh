#!/bin/bash
# QueryGuard — Build Script
# Builds the React dashboard and compiles Go binaries

set -e

GREEN='\033[0;32m'
CYAN='\033[0;36m'
RED='\033[0;31m'
NC='\033[0m'

BASE_DIR="$(cd "$(dirname "$0")" && pwd)"

echo -e "${CYAN}"
echo "╔══════════════════════════════════════════╗"
echo "║       QueryGuard — Build All             ║"
echo "╚══════════════════════════════════════════╝"
echo -e "${NC}"

# ── 1. Build React Dashboard ──
echo -e "${CYAN}[1/3] Building React dashboard...${NC}"
cd "$BASE_DIR/dashboard"

if ! command -v npm &> /dev/null; then
    echo -e "${RED}  ✗ npm not found — install Node.js first${NC}"
    exit 1
fi

npm install --silent 2>/dev/null
npm run build 2>/dev/null

if [ -d "dist" ]; then
    echo -e "${GREEN}  ✓ Dashboard built → dashboard/dist/${NC}"
else
    echo -e "${RED}  ✗ Dashboard build failed${NC}"
    exit 1
fi

# ── 2. Build Go Gateway ──
echo -e "${CYAN}[2/3] Building Go gateway...${NC}"
cd "$BASE_DIR/gateway"

if ! command -v go &> /dev/null; then
    echo -e "${RED}  ✗ Go not found — install Go first${NC}"
    exit 1
fi

CGO_ENABLED=1 go build -o gateway main.go 2>/dev/null

if [ -f "gateway" ]; then
    echo -e "${GREEN}  ✓ Gateway built → gateway/gateway${NC}"
else
    echo -e "${RED}  ✗ Gateway build failed${NC}"
    exit 1
fi

# ── 3. Build Go Agent ──
echo -e "${CYAN}[3/3] Building Go agent...${NC}"
cd "$BASE_DIR/agent"

go build -o agent main.go 2>/dev/null

if [ -f "agent" ]; then
    echo -e "${GREEN}  ✓ Agent built → agent/agent${NC}"
else
    echo -e "${RED}  ✗ Agent build failed${NC}"
    exit 1
fi

# ── Done ──
echo ""
echo -e "${GREEN}╔══════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║          Build Complete!                 ║${NC}"
echo -e "${GREEN}╠══════════════════════════════════════════╣${NC}"
echo -e "${GREEN}║  dashboard/dist/   — React build         ║${NC}"
echo -e "${GREEN}║  gateway/gateway   — Go gateway binary   ║${NC}"
echo -e "${GREEN}║  agent/agent       — Go agent binary     ║${NC}"
echo -e "${GREEN}║                                          ║${NC}"
echo -e "${GREEN}║  To run:  ./start.sh                     ║${NC}"
echo -e "${GREEN}║  Or:      ./start.sh simulate            ║${NC}"
echo -e "${GREEN}╚══════════════════════════════════════════╝${NC}"
