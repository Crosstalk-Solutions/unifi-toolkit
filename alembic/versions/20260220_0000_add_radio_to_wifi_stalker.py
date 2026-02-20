"""Add radio band tracking to Wi-Fi Stalker

Revision ID: b5c9e2d7f1a3
Revises: a3f8d1c4e9b2
Create Date: 2026-02-20 00:00:00.000000+00:00

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'b5c9e2d7f1a3'
down_revision: Union[str, None] = 'a3f8d1c4e9b2'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    with op.batch_alter_table('stalker_tracked_devices', schema=None) as batch_op:
        batch_op.add_column(sa.Column('current_radio', sa.String(), nullable=True))


def downgrade() -> None:
    with op.batch_alter_table('stalker_tracked_devices', schema=None) as batch_op:
        batch_op.drop_column('current_radio')
