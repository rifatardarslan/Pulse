"""V2 columns: FP fields on vulnerabilities, scanners_run on scans, webhook_url on projects, schedules table

Revision ID: 0002
Revises: 0001
Create Date: 2026-05-09 00:00:00.000000

For existing V1 installations that already have the base tables but not the V2 columns/tables.
Alembic uses 'CREATE TABLE IF NOT EXISTS' equivalent via checkfirst=True.
"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision: str = "0002"
down_revision: Union[str, None] = "0001"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def _column_exists(table: str, column: str) -> bool:
    bind = op.get_bind()
    result = bind.execute(sa.text(
        "SELECT 1 FROM information_schema.columns "
        "WHERE table_name=:t AND column_name=:c"
    ), {"t": table, "c": column})
    return result.fetchone() is not None


def _table_exists(table: str) -> bool:
    bind = op.get_bind()
    result = bind.execute(sa.text(
        "SELECT 1 FROM information_schema.tables WHERE table_name=:t"
    ), {"t": table})
    return result.fetchone() is not None


def upgrade() -> None:
    # --- vulnerabilities: V2 false positive columns ---
    if not _column_exists("vulnerabilities", "is_false_positive"):
        op.add_column("vulnerabilities", sa.Column("is_false_positive", sa.Boolean(), server_default="false", nullable=False))
    if not _column_exists("vulnerabilities", "false_positive_reason"):
        op.add_column("vulnerabilities", sa.Column("false_positive_reason", sa.Text(), nullable=True))
    if not _column_exists("vulnerabilities", "false_positive_marked_at"):
        op.add_column("vulnerabilities", sa.Column("false_positive_marked_at", sa.DateTime(timezone=True), nullable=True))

    # --- scans: V2 scanners_run JSONB column ---
    if not _column_exists("scans", "scanners_run"):
        op.add_column("scans", sa.Column("scanners_run", postgresql.JSONB(), nullable=True))

    # --- projects: V2 webhook_url column ---
    if not _column_exists("projects", "webhook_url"):
        op.add_column("projects", sa.Column("webhook_url", sa.String(2048), nullable=True))

    # --- schedules table (V2 new) ---
    if not _table_exists("schedules"):
        # create_type=False: we manage creation manually with checkfirst=True
        # to avoid SQLAlchemy re-issuing CREATE TYPE inside op.create_table
        schedulestatus_enum = postgresql.ENUM("ACTIVE", "PAUSED", "ERROR", name="schedulestatus", create_type=False)
        schedulestatus_enum.create(op.get_bind(), checkfirst=True)

        op.create_table(
            "schedules",
            sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
            sa.Column("project_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("projects.id", ondelete="CASCADE"), nullable=False),
            sa.Column("cron_expression", sa.String(100), nullable=False),
            sa.Column("status", schedulestatus_enum, server_default="ACTIVE", nullable=False),
            sa.Column("skip_ai", sa.Boolean(), server_default="false", nullable=False),
            sa.Column("last_run_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("last_scan_id", postgresql.UUID(as_uuid=True), nullable=True),
            sa.Column("next_run_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("run_count", sa.Integer(), server_default="0", nullable=False),
            sa.Column("error_count", sa.Integer(), server_default="0", nullable=False),
            sa.Column("last_error", sa.Text(), nullable=True),
            sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
            sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        )


def downgrade() -> None:
    if _table_exists("schedules"):
        op.drop_table("schedules")
    if _column_exists("projects", "webhook_url"):
        op.drop_column("projects", "webhook_url")
    if _column_exists("scans", "scanners_run"):
        op.drop_column("scans", "scanners_run")
    if _column_exists("vulnerabilities", "false_positive_marked_at"):
        op.drop_column("vulnerabilities", "false_positive_marked_at")
    if _column_exists("vulnerabilities", "false_positive_reason"):
        op.drop_column("vulnerabilities", "false_positive_reason")
    if _column_exists("vulnerabilities", "is_false_positive"):
        op.drop_column("vulnerabilities", "is_false_positive")
