#!/bin/bash

# Authentication Server - Uninstall Script
# Removes the database and cleans up

set -e

# Color codes
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

DB_NAME="auth_server"

echo -e "${RED}╔════════════════════════════════════════╗${NC}"
echo -e "${RED}║  Authentication Server - Uninstall    ║${NC}"
echo -e "${RED}╚════════════════════════════════════════╝${NC}"
echo ""

echo -e "${YELLOW}[WARNING]${NC} This will remove:"
echo "  - Database: $DB_NAME"
echo "  - Build artifacts (target/)"
echo "  - Generated keys (src/main/resources/keys/)"
echo "  - Log files (logs/)"
echo ""

read -p "Are you sure you want to continue? (y/N): " -n 1 -r
echo ""

if [[ ! $REPLY =~ ^[Yy]$ ]]; then
    echo -e "${BLUE}[INFO]${NC} Uninstall cancelled"
    exit 0
fi

# Stop application if running
echo -e "${BLUE}[INFO]${NC} Stopping application..."
./stop.sh 2>/dev/null || true

# Drop database
echo -e "${BLUE}[INFO]${NC} Dropping database '$DB_NAME'..."
sudo -u postgres psql -c "DROP DATABASE IF EXISTS $DB_NAME;" >/dev/null 2>&1
echo -e "${GREEN}[SUCCESS]${NC} Database dropped"

# Clean build artifacts
echo -e "${BLUE}[INFO]${NC} Cleaning build artifacts..."
mvn clean >/dev/null 2>&1 || true
echo -e "${GREEN}[SUCCESS]${NC} Build artifacts cleaned"

# Remove generated files
echo -e "${BLUE}[INFO]${NC} Removing generated files..."
rm -rf src/main/resources/keys
rm -rf logs
echo -e "${GREEN}[SUCCESS]${NC} Generated files removed"

echo ""
echo -e "${GREEN}[SUCCESS]${NC} Uninstall complete!"
echo ""
echo -e "${BLUE}[INFO]${NC} To reinstall, run: ./install.sh"
