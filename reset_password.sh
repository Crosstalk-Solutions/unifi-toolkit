#!/bin/bash
#
# UI Toolkit - Password Reset Utility
# Resets the admin password for production deployments
#

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color
BOLD='\033[1m'

print_success() {
    echo -e "${GREEN}✓${NC} $1"
}

print_error() {
    echo -e "${RED}✗${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}⚠${NC} $1"
}

print_info() {
    echo -e "${CYAN}ℹ${NC} $1"
}

# Check if Python 3 is available
check_python() {
    if command -v python3 &> /dev/null; then
        PYTHON_CMD="python3"
    elif command -v python &> /dev/null; then
        PYTHON_CMD="python"
    else
        print_error "Python 3 is required but not found!"
        exit 1
    fi
}

# Hash password with bcrypt
hash_password() {
    local password="$1"
    $PYTHON_CMD -c "import bcrypt; print(bcrypt.hashpw('$password'.encode(), bcrypt.gensalt()).decode())" 2>/dev/null || {
        print_error "Failed to hash password"
        print_info "Make sure bcrypt is installed: pip install bcrypt"
        exit 1
    }
}

# Validate password meets requirements
validate_password() {
    local password="$1"
    local errors=()

    # Check length
    if [ ${#password} -lt 12 ]; then
        errors+=("Password must be at least 12 characters long")
    fi

    # Check for lowercase
    if ! [[ "$password" =~ [a-z] ]]; then
        errors+=("Password must contain at least one lowercase letter")
    fi

    # Check for uppercase
    if ! [[ "$password" =~ [A-Z] ]]; then
        errors+=("Password must contain at least one uppercase letter")
    fi

    # Check for number
    if ! [[ "$password" =~ [0-9] ]]; then
        errors+=("Password must contain at least one number")
    fi

    if [ ${#errors[@]} -gt 0 ]; then
        echo ""
        print_error "Password does not meet requirements:"
        for error in "${errors[@]}"; do
            echo "  - $error"
        done
        return 1
    fi

    return 0
}

# Update password hash in .env file
update_env_file() {
    local new_hash="$1"

    if [ ! -f ".env" ]; then
        print_error ".env file not found!"
        print_info "Run setup.sh first to create the configuration."
        exit 1
    fi

    # Check if AUTH_PASSWORD_HASH exists in .env
    if grep -q "^AUTH_PASSWORD_HASH=" .env; then
        # Update existing line
        # Escape dollar signs for Docker Compose ($ -> $$)
        local escaped_hash="${new_hash//\$/\$\$}"
        # Use a different delimiter for sed since the hash contains $
        sed -i "s|^AUTH_PASSWORD_HASH=.*|AUTH_PASSWORD_HASH=$escaped_hash|" .env
    else
        # Add new line
        # Escape dollar signs for Docker Compose ($ -> $$)
        local escaped_hash="${new_hash//\$/\$\$}"
        echo "AUTH_PASSWORD_HASH=$escaped_hash" >> .env
    fi
}

# Main function
main() {
    echo ""
    echo -e "${BOLD}UI Toolkit - Password Reset${NC}"
    echo ""

    # Check prerequisites
    check_python

    # Check if .env exists
    if [ ! -f ".env" ]; then
        print_error ".env file not found!"
        print_info "Run setup.sh first to create the configuration."
        exit 1
    fi

    # Check if running in production mode
    DEPLOYMENT_TYPE=$(grep "^DEPLOYMENT_TYPE=" .env | cut -d'=' -f2 || echo "local")

    if [ "$DEPLOYMENT_TYPE" != "production" ]; then
        print_warning "This installation is configured for LOCAL mode."
        print_info "Authentication is not enabled in local mode."
        echo ""
        read -p "Do you still want to set a password? [y/N]: " confirm
        if [[ ! "$confirm" =~ ^[Yy]$ ]]; then
            exit 0
        fi
        echo ""
    fi

    # Get new password
    echo "Enter the new admin password."
    echo "Requirements: 12+ characters, uppercase, lowercase, and numbers"
    echo ""

    while true; do
        read -s -p "New password: " password
        echo ""

        if ! validate_password "$password"; then
            echo ""
            continue
        fi

        read -s -p "Confirm password: " password_confirm
        echo ""

        if [ "$password" != "$password_confirm" ]; then
            echo ""
            print_error "Passwords do not match. Please try again."
            echo ""
            continue
        fi

        break
    done

    echo ""
    print_info "Hashing password..."
    password_hash=$(hash_password "$password")

    print_info "Updating .env file..."
    update_env_file "$password_hash"

    print_success "Password updated successfully!"
    echo ""

    # Check if running in Docker
    if [ -f "docker-compose.yml" ] && command -v docker &> /dev/null; then
        echo "To apply the new password, restart the application:"
        echo ""
        if [ "$DEPLOYMENT_TYPE" == "production" ]; then
            echo -e "  ${CYAN}docker compose --profile production restart${NC}"
        else
            echo -e "  ${CYAN}docker compose restart${NC}"
        fi
    else
        echo "To apply the new password, restart the application:"
        echo ""
        echo -e "  ${CYAN}# Stop the running application (Ctrl+C)${NC}"
        echo -e "  ${CYAN}python run.py${NC}"
    fi

    echo ""
}

# Run main function
main
