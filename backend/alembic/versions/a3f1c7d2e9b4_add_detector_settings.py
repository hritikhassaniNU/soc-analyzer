"""add detector settings and per-upload disabled detectors

Revision ID: a3f1c7d2e9b4
Revises: bc68c289e054
Create Date: 2026-10-04 13:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision: str = 'a3f1c7d2e9b4'
down_revision: Union[str, Sequence[str], None] = 'bc68c289e054'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    op.create_table(
        'detector_settings',
        sa.Column('kind', sa.Text(), nullable=False),
        sa.Column('enabled', sa.Boolean(), nullable=False),
        sa.Column('changed_by', sa.Integer(), nullable=True),
        sa.Column('changed_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.ForeignKeyConstraint(['changed_by'], ['users.id'], name=op.f('fk_detector_settings_changed_by_users'),
                                ondelete='SET NULL'),
        sa.PrimaryKeyConstraint('kind', name=op.f('pk_detector_settings')),
    )
    # Existing uploads were scanned with every detector on: '{}' is the truth for them.
    op.add_column('uploads', sa.Column('disabled_detectors', postgresql.ARRAY(sa.Text()),
                                       server_default=sa.text("'{}'"), nullable=False))


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_column('uploads', 'disabled_detectors')
    op.drop_table('detector_settings')
