#!/bin/bash
#
# UI Toolkit - Upgrade Script
# Handles git pull, Docker image updates, and database migrations
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

# Directories
BACKUP_DIR="./backups"
LOG_DIR="./logs"
UPGRADE_LOG="$LOG_DIR/upgrade.log"

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

# Log upgrade events
log_upgrade() {
    mkdir -p "$LOG_DIR"
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" >> "$UPGRADE_LOG"
}

# Pre-flight checks
run_preflight_checks() {
    print_step "0" "Pre-flight checks"
    PREFLIGHT_PASSED=true

    # Check Docker is running
    if ! docker info >/dev/null 2>&1; then
        print_error "Docker is not running"
        PREFLIGHT_PASSED=false
    else
        print_success "Docker is running"
    fi

    # Check docker compose is available
    if ! docker compose version >/dev/null 2>&1; then
        print_error "docker compose is not available"
        PREFLIGHT_PASSED=false
    else
        print_success "docker compose is available"
    fi

    # Check disk space (warn if less than 1GB free)
    if command -v df >/dev/null 2>&1; then
        # Get available space in KB, handle both Linux and macOS
        AVAILABLE_KB=$(df -k . 2>/dev/null | tail -1 | awk '{print $4}')
        if [ -n "$AVAILABLE_KB" ] && [ "$AVAILABLE_KB" -lt 1048576 ]; then
            print_warning "Low disk space: $(( AVAILABLE_KB / 1024 )) MB available"
        else
            print_success "Disk space OK"
        fi
    fi

    # Check git is available
    if ! command -v git >/dev/null 2>&1; then
        print_error "git is not installed"
        PREFLIGHT_PASSED=false
    else
        print_success "git is available"
    fi

    # Check curl is available (used for health verification)
    if ! command -v curl >/dev/null 2>&1; then
        print_error "curl is not installed (required for health verification)"
        PREFLIGHT_PASSED=false
    else
        print_success "curl is available"
    fi

    # Check we're in a git repo
    if ! git rev-parse --git-dir >/dev/null 2>&1; then
        print_error "Not in a git repository"
        PREFLIGHT_PASSED=false
    else
        print_success "Git repository detected"
    fi

    # Check for uncommitted changes
    if ! git diff --quiet 2>/dev/null || ! git diff --cached --quiet 2>/dev/null; then
        print_warning "You have uncommitted changes - they will be preserved"
    fi

    if [ "$PREFLIGHT_PASSED" = false ]; then
        print_error "Pre-flight checks failed. Please fix the issues above."
        exit 1
    fi

    print_success "All pre-flight checks passed"
}

# Backup database before migrations
backup_database() {
    print_info "Creating database backup..."

    mkdir -p "$BACKUP_DIR"
    TIMESTAMP=$(date +%Y%m%d_%H%M%S)
    BACKUP_FILE="$BACKUP_DIR/unifi_toolkit_${TIMESTAMP}.db"

    if [ -f "./data/unifi_toolkit.db" ]; then
        cp "./data/unifi_toolkit.db" "$BACKUP_FILE"

        # Get file size
        if command -v stat >/dev/null 2>&1; then
            # Try GNU stat first, then BSD stat
            SIZE=$(stat -c%s "$BACKUP_FILE" 2>/dev/null || stat -f%z "$BACKUP_FILE" 2>/dev/null || echo "unknown")
            if [ "$SIZE" != "unknown" ]; then
                SIZE_MB=$(echo "scale=2; $SIZE / 1048576" | bc 2>/dev/null || echo "$(( SIZE / 1048576 ))")
                print_success "Database backed up to $BACKUP_FILE (${SIZE_MB} MB)"
            else
                print_success "Database backed up to $BACKUP_FILE"
            fi
        else
            print_success "Database backed up to $BACKUP_FILE"
        fi

        log_upgrade "Database backed up to $BACKUP_FILE"

        # Clean up old backups (keep last 5)
        BACKUP_COUNT=$(ls -1 "$BACKUP_DIR"/unifi_toolkit_*.db 2>/dev/null | wc -l)
        if [ "$BACKUP_COUNT" -gt 5 ]; then
            print_info "Cleaning up old backups (keeping last 5)..."
            ls -1t "$BACKUP_DIR"/unifi_toolkit_*.db | tail -n +6 | xargs rm -f
        fi
    else
        print_info "No existing database found - skipping backup"
    fi
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

# Verify application health by hitting the /health endpoint
verify_health() {
    print_info "Verifying application health..."

    # Determine the URL based on deployment type
    if [ "$DEPLOYMENT_TYPE" == "production" ]; then
        DOMAIN=$(grep -E "^DOMAIN=" .env | cut -d'=' -f2 | tr -d '"' | tr -d "'")
        HEALTH_URL="https://${DOMAIN}/health"
    else
        HEALTH_URL="http://localhost:8000/health"
    fi

    RETRIES=0
    MAX_RETRIES=30

    while [ $RETRIES -lt $MAX_RETRIES ]; do
        # Use curl with timeout, follow redirects, and ignore SSL errors for self-signed certs
        HEALTH_RESPONSE=$(curl -s -k -m 5 "$HEALTH_URL" 2>/dev/null || echo "")

        if echo "$HEALTH_RESPONSE" | grep -q '"status".*"healthy"'; then
            print_success "Application is healthy"

            # Extract version from health response if available
            HEALTH_VERSION=$(echo "$HEALTH_RESPONSE" | grep -o '"version"[[:space:]]*:[[:space:]]*"[^"]*"' | cut -d'"' -f4 || echo "")
            if [ -n "$HEALTH_VERSION" ]; then
                print_info "Running version: $HEALTH_VERSION"
            fi
            return 0
        fi

        RETRIES=$((RETRIES + 1))
        sleep 2
    done

    print_warning "Could not verify application health"
    print_info "The application may still be starting up"
    print_info "Check manually at: $HEALTH_URL"
    return 1
}

# Run database migrations with smart error handling
run_migrations() {
    print_info "Running database migrations..."

    # Get current alembic revision for debugging
    CURRENT_REV=$($COMPOSE_CMD exec -T unifi-toolkit alembic current 2>/dev/null || echo "unknown")
    print_info "Current database revision: $CURRENT_REV"

    # First, try to run migrations normally
    MIGRATION_OUTPUT=$($COMPOSE_CMD exec -T unifi-toolkit alembic upgrade head 2>&1)
    MIGRATION_STATUS=$?

    if [ $MIGRATION_STATUS -eq 0 ]; then
        print_success "Migrations completed successfully"
        log_upgrade "Migrations completed successfully"
        return 0
    fi

    # Migration failed - check for common schema sync issues
    # These occur when the database schema was modified outside of alembic
    # or when upgrading from a version that had different migration history

    NEEDS_STAMP=false
    STAMP_REASON=""

    # Check for "already exists" errors (tables or columns)
    if echo "$MIGRATION_OUTPUT" | grep -qi "already exists"; then
        NEEDS_STAMP=true
        STAMP_REASON="Schema objects already exist"
    fi

    # Check for "duplicate column" errors
    if echo "$MIGRATION_OUTPUT" | grep -qi "duplicate column"; then
        NEEDS_STAMP=true
        STAMP_REASON="Duplicate column detected"
    fi

    # Check for "table .* already exists" (SQLite specific)
    if echo "$MIGRATION_OUTPUT" | grep -qi "table .* already exists"; then
        NEEDS_STAMP=true
        STAMP_REASON="Table already exists"
    fi

    # Check for UNIQUE constraint errors that indicate schema is ahead
    if echo "$MIGRATION_OUTPUT" | grep -qi "UNIQUE constraint failed"; then
        NEEDS_STAMP=true
        STAMP_REASON="Schema constraint conflict"
    fi

    if [ "$NEEDS_STAMP" = true ]; then
        print_warning "$STAMP_REASON - database schema is ahead of migration history"
        print_info "This is common when upgrading from older versions."
        print_info "Synchronizing migration history with current schema..."
        log_upgrade "Migration issue: $STAMP_REASON - auto-stamping"

        # Stamp the database to mark all migrations as applied
        if $COMPOSE_CMD exec -T unifi-toolkit alembic stamp head 2>&1; then
            print_success "Database synchronized to current version"
            log_upgrade "Database synchronized via alembic stamp head"

            # Verify the stamp worked
            NEW_REV=$($COMPOSE_CMD exec -T unifi-toolkit alembic current 2>/dev/null || echo "unknown")
            print_info "New database revision: $NEW_REV"
            return 0
        else
            print_error "Failed to synchronize database"
            print_info "You may need to manually run: docker compose exec unifi-toolkit alembic stamp head"
            log_upgrade "ERROR: Failed to synchronize database"
            return 1
        fi
    else
        # Some other error occurred
        print_error "Migration failed with unexpected error:"
        echo ""
        echo "$MIGRATION_OUTPUT"
        echo ""
        print_info "If this is a schema sync issue, try running:"
        print_info "  docker compose exec unifi-toolkit alembic stamp head"
        print_info ""
        print_info "Your database has been backed up to: $BACKUP_DIR/"
        log_upgrade "ERROR: Migration failed - $MIGRATION_OUTPUT"
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

    # Log upgrade start
    log_upgrade "========== Upgrade started =========="
    log_upgrade "Old version: $OLD_VERSION"

    # Step 0: Pre-flight checks
    run_preflight_checks

    # Step 1: Backup database
    print_step "1" "Backing up database"
    backup_database

    # Step 2: Stop containers
    print_step "2" "Stopping containers"
    if check_containers; then
        $COMPOSE_CMD down
        print_success "Containers stopped"
    else
        print_info "No containers running"
    fi

    # Step 3: Pull latest code
    print_step "3" "Pulling latest code"
    if git pull; then
        print_success "Code updated"
    else
        print_error "Git pull failed"
        print_info "Please resolve any git conflicts and try again."
        log_upgrade "ERROR: Git pull failed"
        exit 1
    fi

    # Get new version
    NEW_VERSION=$(get_current_version)
    if [ "$OLD_VERSION" != "$NEW_VERSION" ]; then
        print_success "Upgrading from $OLD_VERSION to $NEW_VERSION"
        log_upgrade "New version: $NEW_VERSION"
    else
        log_upgrade "Version unchanged: $NEW_VERSION"
    fi

    # Step 4: Pull latest Docker image
    print_step "4" "Pulling latest Docker image"
    if $COMPOSE_CMD pull; then
        print_success "Docker image updated"
    else
        print_error "Docker pull failed"
        log_upgrade "ERROR: Docker pull failed"
        exit 1
    fi

    # Step 5: Start containers
    print_step "5" "Starting containers"
    if $COMPOSE_CMD up -d; then
        print_success "Containers started"
    else
        print_error "Failed to start containers"
        log_upgrade "ERROR: Failed to start containers"
        exit 1
    fi

    # Wait for app to be ready
    print_info "Waiting for application to start..."
    sleep 5

    # Step 6: Run database migrations
    print_step "6" "Database migrations"

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
        log_upgrade "ERROR: Container failed to start"
        exit 1
    fi

    # Run migrations
    if run_migrations; then
        print_success "Database is up to date"
    else
        print_warning "Migration issues detected - check logs"
        print_info "The application may still work if tables were already created."
    fi

    # Step 7: Restart to ensure clean state
    print_step "7" "Final restart"
    $COMPOSE_CMD restart
    print_success "Application restarted"

    # Step 8: Verify health
    print_step "8" "Health verification"
    sleep 3
    verify_health

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

    print_info "Database backup: $BACKUP_DIR/"
    print_info "Upgrade log: $UPGRADE_LOG"
    print_info "View app logs: $COMPOSE_CMD logs -f unifi-toolkit"
    echo ""

    log_upgrade "Upgrade completed successfully"
    log_upgrade "========== Upgrade finished =========="
}

# Run main function
main "$@"
