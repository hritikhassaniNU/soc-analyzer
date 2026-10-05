"""create user reviews

Revision ID: c5e8a1b3d7f2
Revises: a3f1c7d2e9b4
Create Date: 2026-10-04 15:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision: str = 'c5e8a1b3d7f2'
down_revision: Union[str, Sequence[str], None] = 'a3f1c7d2e9b4'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    op.create_table(
        'user_reviews',
        sa.Column('id', sa.Integer(), sa.Identity(always=False), nullable=False),
        sa.Column('username', sa.Text(), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.Column('created_by', sa.Integer(), nullable=True),
        sa.Column('source', sa.String(length=10), nullable=False),
        sa.Column('model', sa.Text(), nullable=True),
        sa.Column('summary', sa.Text(), nullable=False),
        sa.Column('fingerprint', sa.String(length=64), nullable=False),
        sa.Column('incident_count', sa.Integer(), nullable=False),
        sa.CheckConstraint("source IN ('ai', 'template')", name=op.f('ck_user_reviews_source')),
        sa.ForeignKeyConstraint(['created_by'], ['users.id'], name=op.f('fk_user_reviews_created_by_users'),
                                ondelete='SET NULL'),
        sa.PrimaryKeyConstraint('id', name=op.f('pk_user_reviews')),
    )
    op.create_index(op.f('ix_user_reviews_username'), 'user_reviews', ['username'], unique=False)


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_index(op.f('ix_user_reviews_username'), table_name='user_reviews')
    op.drop_table('user_reviews')
