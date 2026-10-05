"""add device to events

Revision ID: bc68c289e054
Revises: 52b22ef713e3
Create Date: 2026-10-04 11:26:03.492983

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'bc68c289e054'
down_revision: Union[str, Sequence[str], None] = '52b22ef713e3'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    # Nullable, no default: instant on the partitioned parent and every existing partition.
    op.add_column('events', sa.Column('device', sa.Text(), nullable=True))
    op.add_column('events', sa.Column('device_os', sa.Text(), nullable=True))


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_column('events', 'device_os')
    op.drop_column('events', 'device')
