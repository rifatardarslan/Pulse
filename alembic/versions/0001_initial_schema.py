"""Initial V1 schema — projects, scans, vulnerabilities, remediations

Revision ID: 0001
Revises:
Create Date: 2026-01-01 00:00:00.000000
"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision: str = "0001"
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "projects",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("name", sa.String(255), nullable=False),
        sa.Column("repo_url", sa.String(1024), nullable=False, unique=True),
        sa.Column("branch", sa.String(255), server_default="main"),
        sa.Column("is_active", sa.Boolean(), server_default="true"),
        sa.Column("webhook_url", sa.String(2048), nullable=True),
        sa.Column("last_scan_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )

    scanstatus_enum = postgresql.ENUM("PENDING", "RUNNING", "COMPLETED", "FAILED", name="scanstatus")
    scannertype_enum = postgresql.ENUM("GITLEAKS", "SEMGREP", name="scannertype")
    scanstatus_enum.create(op.get_bind(), checkfirst=True)
    scannertype_enum.create(op.get_bind(), checkfirst=True)

    op.create_table(
        "scans",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("project_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("projects.id", ondelete="CASCADE"), nullable=False),
        sa.Column("scanner_type", scannertype_enum, nullable=False),
        sa.Column("status", scanstatus_enum, server_default="PENDING", nullable=False),
        sa.Column("docker_container_id", sa.String(64), nullable=True),
        sa.Column("logs", sa.Text(), nullable=True),
        sa.Column("scanners_run", postgresql.JSONB(), nullable=True),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("finished_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )

    severity_enum = postgresql.ENUM("INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL", name="severity")
    severity_enum.create(op.get_bind(), checkfirst=True)

    op.create_table(
        "vulnerabilities",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("scan_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("scans.id", ondelete="CASCADE"), nullable=False),
        sa.Column("tool_vulnerability_id", sa.String(255), nullable=True),
        sa.Column("severity", severity_enum, server_default="INFO", nullable=False),
        sa.Column("vulnerability_type", sa.String(255), nullable=False),
        sa.Column("file_path", sa.String(1024), nullable=True),
        sa.Column("line_number", sa.Integer(), nullable=True),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("raw_evidence", postgresql.JSONB(), nullable=True),
        sa.Column("is_false_positive", sa.Boolean(), server_default="false", nullable=False),
        sa.Column("false_positive_reason", sa.Text(), nullable=True),
        sa.Column("false_positive_marked_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )

    op.create_table(
        "remediations",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("vulnerability_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("vulnerabilities.id", ondelete="CASCADE"), nullable=False),
        sa.Column("ai_model", sa.String(64), nullable=False),
        sa.Column("suggested_fix", sa.Text(), nullable=True),
        sa.Column("remediation_steps", sa.Text(), nullable=True),
        sa.Column("confidence_score", sa.Float(), nullable=True),
        sa.Column("is_reviewed", sa.Boolean(), server_default="false", nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )

    schedulestatus_enum = postgresql.ENUM("ACTIVE", "PAUSED", "ERROR", name="schedulestatus")
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
    op.drop_table("schedules")
    op.drop_table("remediations")
    op.drop_table("vulnerabilities")
    op.drop_table("scans")
    op.drop_table("projects")
    postgresql.ENUM(name="schedulestatus").drop(op.get_bind(), checkfirst=True)
    postgresql.ENUM(name="severity").drop(op.get_bind(), checkfirst=True)
    postgresql.ENUM(name="scannertype").drop(op.get_bind(), checkfirst=True)
    postgresql.ENUM(name="scanstatus").drop(op.get_bind(), checkfirst=True)
