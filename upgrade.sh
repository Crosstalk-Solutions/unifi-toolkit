#!/bin/bash
#
# UI Toolkit - Upgrade Script
# Handles git pull, Docker rebuild, and database migrations
#

set -e

# Colors for output
RED=$'\033[0;31m'
GREEN=$'\033[0;32m'
YELLOW=$'\033[1;33m'
BLUE=$'\033[0;34m'
CYAN=$'\033[0;36m'
NC=$'\033[0m' # No Color
BOLD=$'\033[1m'

# Functions
print_banner() {
    echo ""
    printf "${BLUE}=================================================================${NC}\n"
    printf "${BLUE}             ${BOLD}UI Toolkit - Upgrade Script${NC}\n"
    printf "${BLUE}=================================================================${NC}\n"
    echo ""
}

print_success() {
    printf "${GREEN}✓${NC} %s\n" "$1"
}

print_error() {
    printf "${RED}✗${NC} %s\n" "$1"
}

print_warning() {
    printf "${YELLOW}⚠${NC} %s\n" "$1"
}

print_info() {
    printf "${CYAN}ℹ${NC} %s\n" "$1"
}

print_step() {
    echo ""
    printf "${BOLD}Step %s: %s${NC}\n" "$1" "$2"
    echo ""
}

# Detect deployment mode from .env file
detect_deployment_mode() {
    if [ -f ".env" ]; then
        DEPLOYMENT_TYPE=$(grep -E "^DEPLOYMENT_TYPE=" .env | cut -d'=' -f2 | tr -d '"' | tr -d "'")
    fi
    DEPLOYMENT_TYPE=${DEPLOYMENT_TYPE:-local}

    if [ "$DEPLOYMENT_TYPE" == "production" ]; then
        COMPOSE_CMD="docker compose --profile production"
    else
        COMPOSE_CMD="docker compose"
    fi
}

# Check if containers are running
check_containers() {
    if $COMPOSE_CMD ps --quiet 2>/dev/null | grep -q .; then
        return 0  # Containers are running
    else
        return 1  # No containers running
    fi
}

# Get current version from git
get_current_version() {
    if [ -f "pyproject.toml" ]; then
        grep -E "^version\s*=" pyproject.toml | head -1 | cut -d'"' -f2
    elif git describe --tags --abbrev=0 2>/dev/null; then
        git describe --tags --abbrev=0
    else
        echo "unknown"
    fi
}

# Run database migrations with smart error handling
run_migrations() {
    print_info "Running database migrations..."

    # First, try to run migrations normally
    if $COMPOSE_CMD exec -T unifi-toolkit alembic upgrade head 2>&1; then
        print_success "Migrations completed successfully"
        return 0
    fi

    # If that failed, check if it's a "table already exists" error
    MIGRATION_OUTPUT=$($COMPOSE_CMD exec -T unifi-toolkit alembic upgrade head 2>&1 || true)

    if echo "$MIGRATION_OUTPUT" | grep -q "already exists"; then
        print_warning "Tables already exist - stamping database to current version..."

        # Stamp the database to mark all migrations as applied
        if $COMPOSE_CMD exec -T unifi-toolkit alembic stamp head 2>&1; then
            print_success "Database stamped to current version"
            return 0
        else
            print_error "Failed to stamp database"
            return 1
        fi
    else
        # Some other error occurred
        print_error "Migration failed with error:"
        echo "$MIGRATION_OUTPUT"
        return 1
    fi
}

# Main upgrade flow
main() {
    print_banner

    # Check we're in the right directory
    if [ ! -f "docker-compose.yml" ] && [ ! -f "compose.yml" ]; then
        print_error "docker-compose.yml not found!"
        print_info "Please run this script from the unifi-toolkit directory."
        exit 1
    fi

    # Check for .env file
    if [ ! -f ".env" ]; then
        print_error ".env file not found!"
        print_info "Please run ./setup.sh first to configure the application."
        exit 1
    fi

    # Detect deployment mode
    detect_deployment_mode
    print_info "Deployment mode: ${BOLD}$DEPLOYMENT_TYPE${NC}"

    # Get current version before upgrade
    OLD_VERSION=$(get_current_version)
    print_info "Current version: $OLD_VERSION"
    echo ""

    # Confirm upgrade
    read -p "Continue with upgrade? [Y/n]: " confirm
    if [[ "$confirm" =~ ^[Nn]$ ]]; then
        print_info "Upgrade cancelled."
        exit 0
    fi

    # Step 1: Stop containers
    print_step "1" "Stopping containers"
    if check_containers; then
        $COMPOSE_CMD down
        print_success "Containers stopped"
    else
        print_info "No containers running"
    fi

    # Step 2: Pull latest code
    print_step "2" "Pulling latest code"
    if git pull; then
        print_success "Code updated"
    else
        print_error "Git pull failed"
        print_info "Please resolve any git conflicts and try again."
        exit 1
    fi

    # Get new version
    NEW_VERSION=$(get_current_version)
    if [ "$OLD_VERSION" != "$NEW_VERSION" ]; then
        print_success "Upgrading from $OLD_VERSION to $NEW_VERSION"
    fi

    # Step 3: Rebuild Docker image
    print_step "3" "Rebuilding Docker image"
    if $COMPOSE_CMD build --no-cache; then
        print_success "Docker image rebuilt"
    else
        print_error "Docker build failed"
        exit 1
    fi

    # Step 4: Start containers
    print_step "4" "Starting containers"
    if $COMPOSE_CMD up -d; then
        print_success "Containers started"
    else
        print_error "Failed to start containers"
        exit 1
    fi

    # Wait for app to be ready
    print_info "Waiting for application to start..."
    sleep 5

    # Step 5: Run database migrations
    print_step "5" "Database migrations"

    # Wait for container to be healthy
    RETRIES=0
    MAX_RETRIES=30
    while [ $RETRIES -lt $MAX_RETRIES ]; do
        if $COMPOSE_CMD exec -T unifi-toolkit python -c "print('ready')" 2>/dev/null; then
            break
        fi
        RETRIES=$((RETRIES + 1))
        sleep 2
    done

    if [ $RETRIES -eq $MAX_RETRIES ]; then
        print_error "Container failed to start properly"
        print_info "Check logs with: $COMPOSE_CMD logs unifi-toolkit"
        exit 1
    fi

    # Run migrations
    if run_migrations; then
        print_success "Database is up to date"
    else
        print_warning "Migration issues detected - check logs"
        print_info "The application may still work if tables were already created."
    fi

    # Step 6: Restart to ensure clean state
    print_step "6" "Final restart"
    $COMPOSE_CMD restart
    print_success "Application restarted"

    # Wait for health check
    sleep 5

    # Final status
    echo ""
    printf "${GREEN}=================================================================${NC}\n"
    printf "${GREEN}                   Upgrade Complete!${NC}\n"
    printf "${GREEN}=================================================================${NC}\n"
    echo ""

    if [ "$DEPLOYMENT_TYPE" == "production" ]; then
        DOMAIN=$(grep -E "^DOMAIN=" .env | cut -d'=' -f2 | tr -d '"' | tr -d "'")
        printf "  Access your toolkit at: ${CYAN}https://%s${NC}\n" "$DOMAIN"
    else
        printf "  Access your toolkit at: ${CYAN}http://localhost:8000${NC}\n"
    fi

    echo ""
    print_info "Version: $NEW_VERSION"
    echo ""

    # Show container status
    printf "${BOLD}Container Status:${NC}\n"
    $COMPOSE_CMD ps
    echo ""

    print_info "View logs with: $COMPOSE_CMD logs -f unifi-toolkit"
    echo ""
}

# Run main function
main "$@"
