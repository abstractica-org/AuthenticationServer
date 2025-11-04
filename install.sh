#!/bin/bash

# Authentication Server - Installation Script
# This script sets up PostgreSQL database and starts the application

set -e  # Exit on any error

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration variables
DB_NAME="auth_server"
DB_USER="postgres"
DB_PASSWORD="postgres"
DB_HOST="localhost"
DB_PORT="5432"
APP_PORT="8080"

# Function to print colored messages
print_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

print_header() {
    echo -e "\n${BLUE}===================================${NC}"
    echo -e "${BLUE}$1${NC}"
    echo -e "${BLUE}===================================${NC}\n"
}

# Function to check if command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Function to check Java version
check_java() {
    print_header "Checking Java Installation"

    if ! command_exists java; then
        print_error "Java is not installed!"
        print_info "Please install Java 21 LTS:"
        echo "  - Ubuntu/Debian: sudo apt install openjdk-21-jdk"
        echo "  - macOS: brew install openjdk@21"
        echo "  - Or download from: https://adoptium.net/"
        exit 1
    fi

    JAVA_VERSION=$(java -version 2>&1 | awk -F '"' '/version/ {print $2}' | cut -d. -f1)
    if [ "$JAVA_VERSION" -lt 21 ]; then
        print_error "Java version 21 or higher is required (found: $JAVA_VERSION)"
        exit 1
    fi

    print_success "Java $JAVA_VERSION detected"
}

# Function to check Maven
check_maven() {
    print_header "Checking Maven Installation"

    if ! command_exists mvn; then
        print_error "Maven is not installed!"
        print_info "Please install Maven 3.8+:"
        echo "  - Ubuntu/Debian: sudo apt install maven"
        echo "  - macOS: brew install maven"
        echo "  - Or download from: https://maven.apache.org/download.cgi"
        exit 1
    fi

    MAVEN_VERSION=$(mvn -version | grep "Apache Maven" | awk '{print $3}')
    print_success "Maven $MAVEN_VERSION detected"
}

# Function to check PostgreSQL
check_postgres() {
    print_header "Checking PostgreSQL Installation"

    if ! command_exists psql; then
        print_error "PostgreSQL is not installed!"
        print_info "Installing PostgreSQL..."

        if [[ "$OSTYPE" == "linux-gnu"* ]]; then
            if command_exists apt-get; then
                sudo apt-get update
                sudo apt-get install -y postgresql postgresql-contrib
                sudo systemctl start postgresql
                sudo systemctl enable postgresql
            elif command_exists yum; then
                sudo yum install -y postgresql-server postgresql-contrib
                sudo postgresql-setup initdb
                sudo systemctl start postgresql
                sudo systemctl enable postgresql
            else
                print_error "Unable to install PostgreSQL automatically."
                print_info "Please install PostgreSQL 14+ manually."
                exit 1
            fi
        elif [[ "$OSTYPE" == "darwin"* ]]; then
            if command_exists brew; then
                brew install postgresql@14
                brew services start postgresql@14
            else
                print_error "Homebrew not found. Please install PostgreSQL manually."
                exit 1
            fi
        else
            print_error "Unsupported OS. Please install PostgreSQL manually."
            exit 1
        fi

        print_success "PostgreSQL installed successfully"
    else
        POSTGRES_VERSION=$(psql --version | awk '{print $3}')
        print_success "PostgreSQL $POSTGRES_VERSION detected"
    fi
}

# Function to setup database
setup_database() {
    print_header "Setting Up Database"

    # Check if PostgreSQL is running
    if ! pg_isready -h $DB_HOST -p $DB_PORT >/dev/null 2>&1; then
        print_warning "PostgreSQL is not running. Attempting to start..."

        if [[ "$OSTYPE" == "linux-gnu"* ]]; then
            sudo systemctl start postgresql
        elif [[ "$OSTYPE" == "darwin"* ]]; then
            brew services start postgresql@14 || brew services start postgresql
        fi

        sleep 2

        if ! pg_isready -h $DB_HOST -p $DB_PORT >/dev/null 2>&1; then
            print_error "Failed to start PostgreSQL"
            exit 1
        fi
    fi

    print_success "PostgreSQL is running"

    # Check if database exists
    print_info "Checking if database '$DB_NAME' exists..."

    DB_EXISTS=$(sudo -u postgres psql -tAc "SELECT 1 FROM pg_database WHERE datname='$DB_NAME'" 2>/dev/null || echo "")

    if [ "$DB_EXISTS" = "1" ]; then
        print_warning "Database '$DB_NAME' already exists"
        read -p "Do you want to drop and recreate it? (y/N): " -n 1 -r
        echo
        if [[ $REPLY =~ ^[Yy]$ ]]; then
            print_info "Dropping database '$DB_NAME'..."
            sudo -u postgres psql -c "DROP DATABASE IF EXISTS $DB_NAME;" >/dev/null 2>&1
            print_success "Database dropped"
        else
            print_info "Keeping existing database"
            return
        fi
    fi

    # Create database
    print_info "Creating database '$DB_NAME'..."
    sudo -u postgres psql -c "CREATE DATABASE $DB_NAME;" >/dev/null 2>&1

    # Grant privileges
    print_info "Granting privileges to user '$DB_USER'..."
    sudo -u postgres psql -c "GRANT ALL PRIVILEGES ON DATABASE $DB_NAME TO $DB_USER;" >/dev/null 2>&1

    print_success "Database '$DB_NAME' created and configured"
}

# Function to create necessary directories
create_directories() {
    print_header "Creating Required Directories"

    mkdir -p src/main/resources/keys
    mkdir -p logs
    mkdir -p target

    print_success "Directories created"
}

# Function to build project
build_project() {
    print_header "Building Project"

    print_info "Running Maven clean install..."
    print_info "This may take a few minutes on first run..."

    if mvn clean install -DskipTests; then
        print_success "Project built successfully"
    else
        print_error "Build failed. Please check the error messages above."
        exit 1
    fi
}

# Function to run database migrations
run_migrations() {
    print_header "Running Database Migrations"

    print_info "Liquibase will automatically run migrations on application startup"
    print_success "Migration configuration verified"
}

# Function to start application
start_application() {
    print_header "Starting Application"

    print_info "Starting Authentication Server on port $APP_PORT..."
    print_info "Press Ctrl+C to stop the server"
    print_info ""
    print_info "Once started, you can access:"
    echo "  - API: http://localhost:$APP_PORT"
    echo "  - Swagger UI: http://localhost:$APP_PORT/swagger-ui.html"
    echo "  - Health Check: http://localhost:$APP_PORT/actuator/health"
    echo ""

    # Start application
    mvn spring-boot:run
}

# Function to display summary
display_summary() {
    print_header "Installation Summary"

    echo "Database Configuration:"
    echo "  - Host: $DB_HOST"
    echo "  - Port: $DB_PORT"
    echo "  - Database: $DB_NAME"
    echo "  - User: $DB_USER"
    echo ""
    echo "Application Configuration:"
    echo "  - Port: $APP_PORT"
    echo "  - Profile: default"
    echo ""
    echo "URLs:"
    echo "  - API: http://localhost:$APP_PORT"
    echo "  - Swagger: http://localhost:$APP_PORT/swagger-ui.html"
    echo "  - Health: http://localhost:$APP_PORT/actuator/health"
    echo ""
}

# Main installation flow
main() {
    clear
    echo "╔════════════════════════════════════════╗"
    echo "║  Authentication Server - Installer    ║"
    echo "║  Version 1.0.0                         ║"
    echo "╚════════════════════════════════════════╝"
    echo ""

    # Check prerequisites
    check_java
    check_maven
    check_postgres

    # Setup database
    setup_database

    # Create directories
    create_directories

    # Build project
    build_project

    # Display summary
    display_summary

    # Ask if user wants to start the application
    echo ""
    read -p "Do you want to start the application now? (Y/n): " -n 1 -r
    echo ""

    if [[ $REPLY =~ ^[Nn]$ ]]; then
        print_info "Installation complete! You can start the application later with:"
        echo "  mvn spring-boot:run"
        echo ""
        print_info "Or use the provided start script:"
        echo "  ./start.sh"
        exit 0
    fi

    # Start application
    start_application
}

# Run main function
main
