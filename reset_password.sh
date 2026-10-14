#!/bin/bash
#
# UI Toolkit - Credential Reset Utility
# Resets the admin username and/or password for production deployments
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

# Messages go to stderr so they stay visible when called inside $(...)
print_error() {
    echo -e "${RED}✗${NC} $1" >&2
}

print_warning() {
    echo -e "${YELLOW}⚠${NC} $1" >&2
}

print_info() {
    echo -e "${CYAN}ℹ${NC} $1" >&2
}

# Show usage
show_usage() {
    echo ""
    echo -e "${BOLD}UI Toolkit - Credential Reset Utility${NC}"
    echo ""
    echo "Usage: $0 [OPTIONS]"
    echo ""
    echo "Options:"
    echo "  --show-username    Display current username and exit"
    echo "  --username-only    Change username only (skip password)"
    echo "  --password-only    Change password only (skip username)"
    echo "  -h, --help         Show this help message"
    echo ""
    echo "With no options, prompts to change both username and password."
    echo ""
}

# Check if Python 3 is available
check_python() {
    # The first interpreter that actually runs Python 3. `command -v` alone is
    # not enough: Windows ships a python3 stub that only opens the Store.
    PYTHON_CMD=""
    for cmd in python3 python; do
        if command -v "$cmd" &> /dev/null && \
                "$cmd" -c 'import sys; sys.exit(sys.version_info[0] != 3)' &> /dev/null; then
            PYTHON_CMD="$cmd"
            break
        fi
    done
    # None found is fine: hash_password falls back to htpasswd
}

# Hash password with bcrypt.
# Tries Python bcrypt first, then htpasswd (built into macOS; on Ubuntu:
# sudo apt install apache2-utils). The password is passed on stdin so it
# never appears in the process list.
hash_password() {
    local password="$1"
    local hash=""
    if [ -n "$PYTHON_CMD" ]; then
        hash=$(printf '%s\n' "$password" | $PYTHON_CMD -c "
import sys
import bcrypt
password = sys.stdin.readline().rstrip('\n')
print(bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode())
" 2>/dev/null || true)
    fi
    if [ -z "$hash" ] && command -v htpasswd &> /dev/null; then
        hash=$(printf '%s\n' "$password" | htpasswd -niBC 12 user 2>/dev/null | cut -d: -f2- | tr -d '\r\n' || true)
    fi
    if [[ ! "$hash" =~ ^\$2[aby]\$ ]]; then
        print_error "Failed to hash password"
        print_info "Install either the Python bcrypt package (pip install bcrypt)"
        print_info "or htpasswd (Ubuntu: sudo apt install apache2-utils) and try again."
        exit 1
    fi
    echo "$hash"
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

# Get current username from .env
get_current_username() {
    if [ ! -f ".env" ]; then
        echo "admin"
        return
    fi

    local username=$(grep "^AUTH_USERNAME=" .env | cut -d'=' -f2)
    if [ -z "$username" ]; then
        echo "admin"
    else
        echo "$username"
    fi
}

# Validate username
validate_username() {
    local username="$1"

    # Check length
    if [ ${#username} -lt 3 ]; then
        print_error "Username must be at least 3 characters long"
        return 1
    fi

    if [ ${#username} -gt 32 ]; then
        print_error "Username must be 32 characters or less"
        return 1
    fi

    # Check for valid characters (alphanumeric, underscore, hyphen)
    if ! [[ "$username" =~ ^[a-zA-Z][a-zA-Z0-9_-]*$ ]]; then
        print_error "Username must start with a letter and contain only letters, numbers, underscores, or hyphens"
        return 1
    fi

    return 0
}

# Update username in .env file
update_username() {
    local new_username="$1"

    if [ ! -f ".env" ]; then
        print_error ".env file not found!"
        print_info "Run setup.sh first to create the configuration."
        exit 1
    fi

    # Check if AUTH_USERNAME exists in .env
    if grep -q "^AUTH_USERNAME=" .env; then
        # Update existing line
        # -i.bak works with both GNU sed (Linux) and BSD sed (macOS)
        sed -i.bak "s|^AUTH_USERNAME=.*|AUTH_USERNAME=$new_username|" .env && rm -f .env.bak
    else
        # Add new line
        echo "AUTH_USERNAME=$new_username" >> .env
    fi
}

# Update password hash in .env file
update_password_hash() {
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
        sed -i.bak "s|^AUTH_PASSWORD_HASH=.*|AUTH_PASSWORD_HASH=$escaped_hash|" .env && rm -f .env.bak
    else
        # Add new line
        # Escape dollar signs for Docker Compose ($ -> $$)
        local escaped_hash="${new_hash//\$/\$\$}"
        echo "AUTH_PASSWORD_HASH=$escaped_hash" >> .env
    fi
}

# Prompt for username change
prompt_username_change() {
    local current_username=$(get_current_username)

    echo -e "Current username: ${CYAN}${current_username}${NC}"
    echo ""
    read -p "Enter new username (or press Enter to keep current): " new_username

    if [ -z "$new_username" ]; then
        echo ""
        print_info "Keeping current username: $current_username"
        return 1  # No change
    fi

    if [ "$new_username" == "$current_username" ]; then
        echo ""
        print_info "Username unchanged"
        return 1  # No change
    fi

    if ! validate_username "$new_username"; then
        echo ""
        return 2  # Invalid, retry
    fi

    update_username "$new_username"
    print_success "Username updated to: $new_username"
    return 0  # Changed
}

# Prompt for password change
prompt_password_change() {
    echo ""
    echo "Enter the new password."
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
    password_hash=$(hash_password "$password") || exit 1

    print_info "Updating .env file..."
    update_password_hash "$password_hash"

    print_success "Password updated successfully!"
    return 0
}

# Show restart instructions
show_restart_instructions() {
    local deployment_type="$1"

    echo ""
    if [ -f "docker-compose.yml" ] && command -v docker &> /dev/null; then
        echo "To apply the changes, restart the application:"
        echo ""
        if [ "$deployment_type" == "production" ]; then
            echo -e "  ${CYAN}docker compose --profile production restart${NC}"
        else
            echo -e "  ${CYAN}docker compose restart${NC}"
        fi
    else
        echo "To apply the changes, restart the application:"
        echo ""
        echo -e "  ${CYAN}# Stop the running application (Ctrl+C)${NC}"
        echo -e "  ${CYAN}python run.py${NC}"
    fi
    echo ""
}

# Main function
main() {
    local show_username_only=false
    local username_only=false
    local password_only=false

    # Parse arguments
    while [[ $# -gt 0 ]]; do
        case $1 in
            --show-username)
                show_username_only=true
                shift
                ;;
            --username-only)
                username_only=true
                shift
                ;;
            --password-only)
                password_only=true
                shift
                ;;
            -h|--help)
                show_usage
                exit 0
                ;;
            *)
                print_error "Unknown option: $1"
                show_usage
                exit 1
                ;;
        esac
    done

    # Check if .env exists (needed for all operations)
    if [ ! -f ".env" ]; then
        print_error ".env file not found!"
        print_info "Run setup.sh first to create the configuration."
        exit 1
    fi

    # Handle --show-username
    if [ "$show_username_only" = true ]; then
        local current_username=$(get_current_username)
        echo ""
        echo -e "Current username: ${CYAN}${current_username}${NC}"
        echo ""
        exit 0
    fi

    echo ""
    echo -e "${BOLD}UI Toolkit - Credential Reset${NC}"
    echo ""

    # Check prerequisites
    check_python

    # Check if running in production mode
    DEPLOYMENT_TYPE=$(grep "^DEPLOYMENT_TYPE=" .env | cut -d'=' -f2 || echo "local")

    if [ "$DEPLOYMENT_TYPE" != "production" ]; then
        print_warning "This installation is configured for LOCAL mode."
        print_info "Authentication is not enabled in local mode."
        echo ""
        read -p "Do you still want to update credentials? [y/N]: " confirm
        if [[ ! "$confirm" =~ ^[Yy]$ ]]; then
            exit 0
        fi
        echo ""
    fi

    local changes_made=false

    # Username change
    if [ "$password_only" != true ]; then
        while true; do
            prompt_username_change
            local result=$?
            if [ $result -eq 0 ]; then
                changes_made=true
                break
            elif [ $result -eq 1 ]; then
                break  # No change requested
            fi
            # result == 2 means invalid, loop again
        done
        echo ""
    fi

    # Password change
    if [ "$username_only" != true ]; then
        if [ "$password_only" = true ] || [ "$username_only" != true ]; then
            prompt_password_change
            changes_made=true
        fi
    fi

    # Show restart instructions if any changes were made
    if [ "$changes_made" = true ]; then
        show_restart_instructions "$DEPLOYMENT_TYPE"
    else
        echo ""
        print_info "No changes made."
        echo ""
    fi
}

# Run main function with all arguments
main "$@"
