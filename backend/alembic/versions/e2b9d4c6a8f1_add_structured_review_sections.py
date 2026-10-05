"""add structured sections to company and user reviews

Revision ID: e2b9d4c6a8f1
Revises: c5e8a1b3d7f2
Create Date: 2026-10-04 18:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision: str = 'e2b9d4c6a8f1'
down_revision: Union[str, Sequence[str], None] = 'c5e8a1b3d7f2'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

TABLES = ('company_reviews', 'user_reviews')


def upgrade() -> None:
    """Upgrade schema."""
    for table in TABLES:  # existing reviews: no sections (the UI shows their paragraph)
        op.add_column(table, sa.Column('headline', sa.Text(), nullable=True))
        op.add_column(table, sa.Column('key_findings', postgresql.JSONB(astext_type=sa.Text()),
                                       server_default=sa.text("'[]'"), nullable=False))
        op.add_column(table, sa.Column('actions', postgresql.JSONB(astext_type=sa.Text()),
                                       server_default=sa.text("'[]'"), nullable=False))


def downgrade() -> None:
    """Downgrade schema."""
    for table in TABLES:
        op.drop_column(table, 'actions')
        op.drop_column(table, 'key_findings')
        op.drop_column(table, 'headline')
