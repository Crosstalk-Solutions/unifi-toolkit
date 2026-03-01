#!/usr/bin/env python3
"""
UI Toolkit - Application Entry Point

This script starts the UI Toolkit web application.
It checks for required environment variables and starts the FastAPI server.
"""
import os
import sys
from pathlib import Path


# ---------------------------------------------------------------------------
# Docker Swarm / orchestrator secrets support (_FILE env vars)
# ---------------------------------------------------------------------------
# For any supported var, setting VAR_FILE=/run/secrets/my_secret will read
# the file contents and inject them into the environment as VAR.
# If both VAR and VAR_FILE are set, _FILE takes precedence.
_FILE_SUPPORTED_VARS = [
    "ENCRYPTION_KEY",
    "AUTH_USERNAME",
    "AUTH_PASSWORD_HASH",
    "DATABASE_URL",
    "UNIFI_PASSWORD",
    "UNIFI_API_KEY",
]


def _resolve_file_env_vars():
    """Resolve VAR_FILE env vars into their corresponding VAR values."""
    for var in _FILE_SUPPORTED_VARS:
        file_var = f"{var}_FILE"
        file_path = os.getenv(file_var)
        if not file_path:
            continue

        path = Path(file_path)
        if not path.is_file():
            print(f"ERROR: {file_var}={file_path} but file does not exist or is not readable")
            sys.exit(1)

        try:
            value = path.read_text().strip()
        except Exception as e:
            print(f"ERROR: Failed to read {file_var}={file_path}: {e}")
            sys.exit(1)

        if os.getenv(var):
            print(f"WARNING: Both {var} and {file_var} are set — using {file_var}")

        os.environ[var] = value


_resolve_file_env_vars()

# Load environment variables from .env file if it exists
env_file = Path(__file__).parent / ".env"
if env_file.exists():
    try:
        from dotenv import load_dotenv
        load_dotenv(env_file)
    except ImportError:
        print("WARNING: python-dotenv not installed, .env file will not be loaded")
        print("Install it with: pip install python-dotenv")
elif not os.getenv("ENCRYPTION_KEY"):
    print("=" * 70)
    print("ERROR: No .env file found and ENCRYPTION_KEY not set!")
    print("=" * 70)
    print()
    print("Either create a .env file (cp .env.example .env)")
    print("or pass environment variables directly to the container.")
    print()
    print("=" * 70)
    sys.exit(1)

# Check for required environment variables
encryption_key = os.getenv("ENCRYPTION_KEY")
if not encryption_key:
    print("=" * 70)
    print("ERROR: ENCRYPTION_KEY not set in .env file!")
    print("=" * 70)
    print()
    print("The ENCRYPTION_KEY is required to encrypt sensitive data.")
    print("Generate a new key with:")
    print()
    print("  python -c \"from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())\"")
    print()
    print("Then add it to your .env file:")
    print()
    print("  ENCRYPTION_KEY=your_generated_key_here")
    print()
    print("=" * 70)
    sys.exit(1)

# Check that the data directory exists and is writable before doing anything else
def check_data_directory():
    """Verify the data directory is usable before starting."""
    db_url = os.getenv("DATABASE_URL", "sqlite+aiosqlite:///./data/unifi_toolkit.db")
    if not db_url.startswith("sqlite"):
        return  # Only relevant for SQLite

    db_path = Path(db_url.split("///")[-1])
    data_dir = db_path.parent

    # Try to create the directory if it doesn't exist
    try:
        data_dir.mkdir(parents=True, exist_ok=True)
    except PermissionError:
        print("=" * 70)
        print("ERROR: Cannot create data directory!")
        print("=" * 70)
        print()
        print(f"  Path: {data_dir.resolve()}")
        print()
        print("The data directory does not exist and cannot be created.")
        print("Fix this by creating it on the host before starting the container:")
        print()
        print("  mkdir -p ./data")
        print("  chown 1000:1000 ./data")
        print()
        print("=" * 70)
        sys.exit(1)

    # Check if the directory is writable
    test_file = data_dir / ".write_test"
    try:
        test_file.touch()
        test_file.unlink()
    except (PermissionError, OSError):
        print("=" * 70)
        print("ERROR: Data directory is not writable!")
        print("=" * 70)
        print()
        print(f"  Path: {data_dir.resolve()}")
        print()
        print("The application needs write access to store its database.")
        print("Fix this by updating permissions on the host:")
        print()
        print("  chown 1000:1000 ./data")
        print()
        print("Or if using a container manager (Portainer, Synology, TrueNAS, etc.),")
        print("make sure the volume mount for /app/data has write permissions for")
        print("UID 1000.")
        print()
        print("=" * 70)
        sys.exit(1)


check_data_directory()


# Run database migrations before starting the app
# This runs in a normal synchronous context, avoiding any async/uvicorn complications
def run_migrations():
    """Run Alembic migrations before uvicorn starts."""
    try:
        from alembic.config import Config
        from alembic import command

        print("Running database migrations...")
        alembic_cfg = Config("alembic.ini")
        command.upgrade(alembic_cfg, "head")
        print("Database migrations completed successfully")

    except Exception as e:
        error_msg = str(e).lower()

        # Check for common schema sync issues
        schema_sync_errors = [
            "already exists",
            "duplicate column",
            "table already exists",
            "unique constraint failed",
        ]

        is_schema_sync_issue = any(err in error_msg for err in schema_sync_errors)

        if is_schema_sync_issue:
            print(f"Migration detected schema sync issue: {e}")
            print("Attempting to synchronize migration history...")

            try:
                from alembic.config import Config
                from alembic import command

                alembic_cfg = Config("alembic.ini")
                command.stamp(alembic_cfg, "head")
                print("Migration history synchronized with current schema")
            except Exception as stamp_error:
                print(f"Failed to synchronize migration history: {stamp_error}")
        else:
            print(f"Migration warning: {e}")
            print("The application will continue, but some features may not work correctly.")

    # Always run schema repair after migrations to catch cases where
    # stamping to head skipped actual column additions
    _repair_schema()


def _repair_schema():
    """
    Check for and add missing columns that migrations may have skipped.

    This handles the case where init_db's create_all creates new tables,
    causing alembic to fail with 'already exists' and stamp to head,
    skipping ADD COLUMN operations on existing tables.
    """
    import sqlite3
    from pathlib import Path

    db_path = Path("./data/unifi_toolkit.db")
    if not db_path.exists():
        return  # No database yet, nothing to repair

    def _add_missing_columns(cursor, table, columns):
        """Check a table for missing columns and add them."""
        cursor.execute(f"PRAGMA table_info({table})")
        existing = {row[1] for row in cursor.fetchall()}
        if not existing:
            return  # Table doesn't exist yet
        for col_name, col_sql in columns.items():
            if col_name not in existing:
                print(f"Schema repair: adding missing column '{col_name}' to {table}")
                cursor.execute(f"ALTER TABLE {table} ADD COLUMN {col_sql}")

    try:
        conn = sqlite3.connect(str(db_path))
        cursor = conn.cursor()

        # threats_events — migrations #8 (ignore rules)
        _add_missing_columns(cursor, 'threats_events', {
            'ignored': "ignored BOOLEAN NOT NULL DEFAULT 0",
            'ignored_by_rule_id': "ignored_by_rule_id INTEGER",
        })

        # stalker_tracked_devices — migrations #2, #5, #9, #10
        _add_missing_columns(cursor, 'stalker_tracked_devices', {
            'is_blocked': "is_blocked BOOLEAN",
            'is_wired': "is_wired BOOLEAN",
            'current_switch_mac': "current_switch_mac VARCHAR",
            'current_switch_name': "current_switch_name VARCHAR",
            'current_switch_port': "current_switch_port INTEGER",
            'current_ssid': "current_ssid VARCHAR",
            'current_radio': "current_radio VARCHAR",
        })

        # stalker_connection_history — migrations #5, #9
        _add_missing_columns(cursor, 'stalker_connection_history', {
            'is_wired': "is_wired BOOLEAN",
            'switch_mac': "switch_mac VARCHAR",
            'switch_name': "switch_name VARCHAR",
            'switch_port': "switch_port INTEGER",
            'ssid': "ssid VARCHAR",
        })

        # stalker_webhook_config — migration #3
        _add_missing_columns(cursor, 'stalker_webhook_config', {
            'event_device_blocked': "event_device_blocked BOOLEAN",
            'event_device_unblocked': "event_device_unblocked BOOLEAN",
        })

        # unifi_config — migrations #4, #6
        _add_missing_columns(cursor, 'unifi_config', {
            'is_unifi_os': "is_unifi_os BOOLEAN",
            'api_key_encrypted': "api_key_encrypted BLOB",
        })

        conn.commit()
        conn.close()
    except Exception as e:
        print(f"Schema repair warning: {e}")


# Start the application
if __name__ == "__main__":
    import uvicorn
    from shared.config import get_settings
    from app import __version__ as app_version
    from tools.wifi_stalker import __version__ as stalker_version
    from tools.threat_watch import __version__ as threat_watch_version
    from tools.network_pulse import __version__ as pulse_version

    # Run migrations FIRST, before any uvicorn/async stuff
    run_migrations()

    settings = get_settings()

    print("=" * 70)
    print("Starting UI Toolkit...")
    print("=" * 70)
    print()
    print(f"Version: {app_version}")
    print(f"Log Level: {settings.log_level}")
    print(f"Database: {settings.database_url}")
    print()

    # Display deployment mode
    deployment_type = settings.deployment_type.upper()
    if deployment_type == "PRODUCTION":
        print(f"Deployment: PRODUCTION (authentication enabled)")
        if settings.domain:
            print(f"Domain: {settings.domain}")
    else:
        print(f"Deployment: LOCAL (authentication disabled)")
    print()

    print("Available tools:")
    print(f"  - Wi-Fi Stalker v{stalker_version}")
    print(f"  - Threat Watch v{threat_watch_version}")
    print(f"  - Network Pulse v{pulse_version}")
    print()

    if deployment_type == "PRODUCTION":
        print("Access via your configured domain with HTTPS")
    else:
        print(f"Access the dashboard at: http://localhost:{settings.app_port}")
        print(f"Wi-Fi Stalker at: http://localhost:{settings.app_port}/stalker/")
        print(f"Threat Watch at: http://localhost:{settings.app_port}/threats/")
        print(f"Network Pulse at: http://localhost:{settings.app_port}/pulse/")
    print()
    print("Press Ctrl+C to stop the server")
    print("=" * 70)
    print()

    # Configure logging level
    log_level = settings.log_level.lower()

    # Start uvicorn server
    uvicorn.run(
        "app.main:app",
        host="0.0.0.0",
        port=settings.app_port,
        reload=False,  # Set to True for development
        log_level=log_level,
        access_log=True
    )
