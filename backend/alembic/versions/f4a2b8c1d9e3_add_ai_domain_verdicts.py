"""add the AI domain classifier: domain_verdicts cache and the 'ai' finding source

Revision ID: f4a2b8c1d9e3
Revises: e2b9d4c6a8f1
Create Date: 2026-10-04 20:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision: str = 'f4a2b8c1d9e3'
down_revision: Union[str, Sequence[str], None] = 'e2b9d4c6a8f1'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    op.create_table(
        'domain_verdicts',
        sa.Column('host', sa.Text(), nullable=False),
        sa.Column('label', sa.String(length=30), nullable=False),
        sa.Column('confidence', sa.String(length=10), nullable=False),
        sa.Column('reason', sa.Text(), nullable=False),
        sa.Column('model', sa.Text(), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.CheckConstraint("label IN ('random_generated', 'brand_lookalike', 'anonymous_file_sharing', 'likely_benign')",
                           name=op.f('ck_domain_verdicts_label')),
        sa.CheckConstraint("confidence IN ('low', 'medium', 'high')", name=op.f('ck_domain_verdicts_confidence')),
        sa.PrimaryKeyConstraint('host', name=op.f('pk_domain_verdicts')),
    )
    # Findings may now come from the AI detector (source 'ai'). Swapping a CHECK is instant.
    op.drop_constraint(op.f('ck_anomalies_source'), 'anomalies', type_='check')
    op.create_check_constraint(op.f('ck_anomalies_source'), 'anomalies', "source IN ('rule', 'stat', 'ml', 'ai')")


def downgrade() -> None:
    """Downgrade schema."""
    op.execute("DELETE FROM anomalies WHERE source = 'ai'")
    op.drop_constraint(op.f('ck_anomalies_source'), 'anomalies', type_='check')
    op.create_check_constraint(op.f('ck_anomalies_source'), 'anomalies', "source IN ('rule', 'stat', 'ml')")
    op.drop_table('domain_verdicts')
