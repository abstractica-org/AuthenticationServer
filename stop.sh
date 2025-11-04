#!/bin/bash

# Authentication Server - Stop Script
# Stops the running application

# Color codes
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo -e "${BLUE}╔════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║  Authentication Server - Stopping     ║${NC}"
echo -e "${BLUE}╚════════════════════════════════════════╝${NC}"
echo ""

# Find and kill the process running on port 8080
PID=$(lsof -ti:8080 2>/dev/null)

if [ -z "$PID" ]; then
    echo -e "${YELLOW}[WARNING]${NC} No application found running on port 8080"
    exit 0
fi

echo -e "${BLUE}[INFO]${NC} Found application with PID: $PID"
echo -e "${BLUE}[INFO]${NC} Stopping application..."

kill -15 $PID 2>/dev/null

# Wait for graceful shutdown
sleep 2

# Check if process is still running
if kill -0 $PID 2>/dev/null; then
    echo -e "${YELLOW}[WARNING]${NC} Process didn't stop gracefully, forcing shutdown..."
    kill -9 $PID 2>/dev/null
fi

echo -e "${GREEN}[SUCCESS]${NC} Application stopped successfully"
