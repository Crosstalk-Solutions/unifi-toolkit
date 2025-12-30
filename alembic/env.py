"""
Alembic environment configuration for UI Toolkit

This file is responsible for:
1. Loading database URL from settings
2. Importing all SQLAlchemy models
3. Running migrations in online/offline mode

Note: Uses synchronous SQLAlchemy engine for migrations to avoid
issues with nested event loops when called from within FastAPI/uvicorn.
"""
from logging.config import fileConfig

from sqlalchemy import pool, create_engine

from alembic import context

# Import shared base and settings
from shared.models.base import Base
from shared.config import get_settings

# Import all models so Alembic can detect them
from shared.models.unifi_config import UniFiConfig
from tools.wifi_stalker.database import TrackedDevice, ConnectionHistory, WebhookConfig
from tools.threat_watch.database import ThreatEvent, ThreatWebhookConfig

# This is the Alembic Config object, which provides
# access to the values within the .ini file in use.
config = context.config

# Interpret the config file for Python logging.
# This line sets up loggers basically.
if config.config_file_name is not None:
    fileConfig(config.config_file_name)

# Set target metadata for autogenerate support
target_metadata = Base.metadata

# Get database URL from settings and convert to synchronous URL
# (aiosqlite -> sqlite for migrations)
settings = get_settings()
db_url = settings.database_url.replace("sqlite+aiosqlite", "sqlite")
config.set_main_option("sqlalchemy.url", db_url)


def run_migrations_offline() -> None:
    """
    Run migrations in 'offline' mode.

    This configures the context with just a URL
    and not an Engine, though an Engine is acceptable
    here as well. By skipping the Engine creation
    we don't even need a DBAPI to be available.

    Calls to context.execute() here emit the given string to the
    script output.
    """
    url = config.get_main_option("sqlalchemy.url")
    context.configure(
        url=url,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
        render_as_batch=True,  # Required for SQLite
    )

    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    """
    Run migrations in 'online' mode using synchronous engine.

    This avoids issues with asyncio.run() when called from within
    an already-running event loop (e.g., FastAPI/uvicorn).
    """
    url = config.get_main_option("sqlalchemy.url")

    connectable = create_engine(
        url,
        poolclass=pool.NullPool,
    )

    with connectable.connect() as connection:
        context.configure(
            connection=connection,
            target_metadata=target_metadata,
            render_as_batch=True,  # Required for SQLite
        )

        with context.begin_transaction():
            context.run_migrations()

    connectable.dispose()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
