"""add api_key_encrypted to unifi_config

Revision ID: 636983efcbf3
Revises: 9ded46fa11ea
Create Date: 2025-12-29 22:49:18.764323+00:00

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy import inspect


# revision identifiers, used by Alembic.
revision: str = '636983efcbf3'
down_revision: Union[str, None] = '9ded46fa11ea'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def column_exists(table_name: str, column_name: str) -> bool:
    """Check if a column exists in a table."""
    bind = op.get_bind()
    inspector = inspect(bind)
    columns = [col['name'] for col in inspector.get_columns(table_name)]
    return column_name in columns


def upgrade() -> None:
    # Add api_key_encrypted column for UniFi OS API key authentication
    # Column is nullable since existing installations use username/password
    # Check if column exists first (idempotent migration for stamped databases)
    if not column_exists('unifi_config', 'api_key_encrypted'):
        with op.batch_alter_table('unifi_config', schema=None) as batch_op:
            batch_op.add_column(sa.Column('api_key_encrypted', sa.LargeBinary(), nullable=True))


def downgrade() -> None:
    if column_exists('unifi_config', 'api_key_encrypted'):
        with op.batch_alter_table('unifi_config', schema=None) as batch_op:
            batch_op.drop_column('api_key_encrypted')
