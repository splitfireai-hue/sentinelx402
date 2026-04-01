"""Initial schema

Revision ID: 001
Revises:
Create Date: 2026-04-01
"""

from alembic import op
import sqlalchemy as sa

revision = "001"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "threat_indicators",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("indicator_type", sa.String(50), nullable=False),
        sa.Column("value", sa.String(512), nullable=False),
        sa.Column("risk_score", sa.Float(), nullable=False),
        sa.Column("threat_type", sa.String(100), nullable=False),
        sa.Column("source", sa.String(100), server_default="sentinelx402", nullable=False),
        sa.Column("tags", sa.Text(), nullable=True),
        sa.Column("first_seen", sa.DateTime(), nullable=False),
        sa.Column("last_seen", sa.DateTime(), nullable=False),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("value"),
    )
    op.create_index("ix_threat_indicators_indicator_type", "threat_indicators", ["indicator_type"])
    op.create_index("ix_threat_indicators_value", "threat_indicators", ["value"])
    op.create_index("ix_threat_type_score", "threat_indicators", ["threat_type", "risk_score"])


def downgrade() -> None:
    op.drop_table("threat_indicators")
