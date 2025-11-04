#!/bin/bash

# Authentication Server - Start Script
# Simple script to start the application

set -e

# Color codes
GREEN='\033[0;32m'
BLUE='\033[0;34m'
NC='\033[0m'

APP_PORT="8080"

echo -e "${BLUE}╔════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║  Authentication Server - Starting     ║${NC}"
echo -e "${BLUE}╚════════════════════════════════════════╝${NC}"
echo ""

# Check if PostgreSQL is running
if ! pg_isready -h localhost -p 5432 >/dev/null 2>&1; then
    echo -e "${BLUE}[INFO]${NC} PostgreSQL is not running. Please start PostgreSQL first."
    echo ""
    echo "Ubuntu/Debian: sudo systemctl start postgresql"
    echo "macOS: brew services start postgresql@14"
    exit 1
fi

echo -e "${GREEN}[SUCCESS]${NC} PostgreSQL is running"
echo ""
echo -e "${BLUE}[INFO]${NC} Starting Authentication Server on port $APP_PORT..."
echo -e "${BLUE}[INFO]${NC} Press Ctrl+C to stop the server"
echo ""
echo "Access points:"
echo "  - API: http://localhost:$APP_PORT"
echo "  - Swagger UI: http://localhost:$APP_PORT/swagger-ui.html"
echo "  - Health Check: http://localhost:$APP_PORT/actuator/health"
echo ""

# Start the application
mvn spring-boot:run
