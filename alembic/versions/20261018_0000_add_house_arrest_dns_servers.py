"""Add House Arrest DNS servers table

Revision ID: c7e1a4f9d2b6
Revises: b5c9e2d7f1a3
Create Date: 2026-10-18 00:00:00.000000+00:00

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'c7e1a4f9d2b6'
down_revision: Union[str, None] = 'b5c9e2d7f1a3'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table('house_arrest_dns_servers',
        sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
        sa.Column('ip', sa.String(), nullable=False),
        sa.Column('name', sa.String(), nullable=False),
        sa.Column('kind', sa.String(), nullable=False, server_default='generic'),
        sa.Column('admin_url', sa.String(), nullable=True),
        sa.Column('created_at', sa.DateTime(), nullable=False),
        sa.PrimaryKeyConstraint('id')
    )
    with op.batch_alter_table('house_arrest_dns_servers', schema=None) as batch_op:
        batch_op.create_index(batch_op.f('ix_house_arrest_dns_servers_ip'), ['ip'], unique=True)


def downgrade() -> None:
    with op.batch_alter_table('house_arrest_dns_servers', schema=None) as batch_op:
        batch_op.drop_index(batch_op.f('ix_house_arrest_dns_servers_ip'))
    op.drop_table('house_arrest_dns_servers')
