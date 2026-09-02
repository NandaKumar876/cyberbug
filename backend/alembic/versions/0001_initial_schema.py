"""Initial CyberBug storage schema.

Revision ID: 0001_initial_schema
Revises:
Create Date: 2026-08-22
"""

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = "0001_initial_schema"
down_revision = None
branch_labels = None
depends_on = None

json_value = sa.JSON().with_variant(postgresql.JSONB, "postgresql")


def upgrade() -> None:
    op.create_table("identities", sa.Column("id", sa.String(80), primary_key=True), sa.Column("department", sa.String(120)), sa.Column("role", sa.String(120)), sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()))
    op.create_table("devices", sa.Column("id", sa.String(120), primary_key=True), sa.Column("trust_level", sa.String(30), nullable=False, server_default="UNKNOWN"), sa.Column("first_seen", sa.DateTime(timezone=True)), sa.Column("last_seen", sa.DateTime(timezone=True)))
    op.create_table("sessions", sa.Column("id", sa.String(120), primary_key=True), sa.Column("identity_id", sa.String(80), sa.ForeignKey("identities.id"), nullable=False), sa.Column("device_id", sa.String(120), sa.ForeignKey("devices.id"), nullable=False), sa.Column("started_at", sa.DateTime(timezone=True), nullable=False), sa.Column("last_seen", sa.DateTime(timezone=True), nullable=False), sa.Column("closed_at", sa.DateTime(timezone=True)), sa.Column("risk_score", sa.Integer(), nullable=False, server_default="0"), sa.Column("anomaly_score", sa.Integer(), nullable=False, server_default="0"), sa.Column("sequence_score", sa.Integer(), nullable=False, server_default="0"), sa.Column("intent", sa.String(40), nullable=False, server_default="NONE"), sa.Column("intent_confidence", sa.Float(), nullable=False, server_default="0"), sa.Column("status", sa.String(40), nullable=False, server_default="NORMAL"), sa.Column("is_contained", sa.Boolean(), nullable=False, server_default=sa.false()), sa.Column("approved_override", sa.Boolean(), nullable=False, server_default=sa.false()), sa.Column("features", json_value, nullable=False), sa.Column("evidence", json_value, nullable=False))
    op.create_table("events", sa.Column("id", sa.String(120), primary_key=True), sa.Column("timestamp", sa.DateTime(timezone=True), nullable=False), sa.Column("identity_id", sa.String(80), sa.ForeignKey("identities.id"), nullable=False), sa.Column("session_id", sa.String(120), sa.ForeignKey("sessions.id")), sa.Column("device_id", sa.String(120), sa.ForeignKey("devices.id"), nullable=False), sa.Column("event_type", sa.String(60), nullable=False), sa.Column("event_category", sa.String(60), nullable=False), sa.Column("source", sa.String(120), nullable=False), sa.Column("target", sa.String(200)), sa.Column("resource_type", sa.String(80)), sa.Column("resource_sensitivity", sa.Integer(), nullable=False, server_default="0"), sa.Column("action", sa.String(120), nullable=False), sa.Column("result", sa.String(40), nullable=False), sa.Column("metadata", json_value, nullable=False))
    op.create_table("baseline_profiles", sa.Column("id", sa.Integer(), primary_key=True), sa.Column("identity_id", sa.String(80), sa.ForeignKey("identities.id"), nullable=False, unique=True), sa.Column("profile", json_value, nullable=False), sa.Column("trusted_observations", sa.Integer(), nullable=False, server_default="0"), sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now()))
    op.create_table("peer_baselines", sa.Column("id", sa.Integer(), primary_key=True), sa.Column("department", sa.String(120), nullable=False), sa.Column("role", sa.String(120), nullable=False), sa.Column("profile", json_value, nullable=False), sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now()), sa.UniqueConstraint("department", "role", name="uq_peer_baselines_department_role"))
    op.create_table("risk_snapshots", sa.Column("id", sa.Integer(), primary_key=True), sa.Column("session_id", sa.String(120), sa.ForeignKey("sessions.id"), nullable=False), sa.Column("recorded_at", sa.DateTime(timezone=True), server_default=sa.func.now()), sa.Column("risk_score", sa.Integer(), nullable=False), sa.Column("components", json_value, nullable=False), sa.Column("explanation", json_value, nullable=False))
    op.create_table("intent_detections", sa.Column("id", sa.Integer(), primary_key=True), sa.Column("session_id", sa.String(120), sa.ForeignKey("sessions.id"), nullable=False), sa.Column("intent", sa.String(40), nullable=False), sa.Column("confidence", sa.Float(), nullable=False), sa.Column("evidence", json_value, nullable=False), sa.Column("detected_at", sa.DateTime(timezone=True), server_default=sa.func.now()))
    op.create_table("incidents", sa.Column("id", sa.String(120), primary_key=True), sa.Column("session_id", sa.String(120), sa.ForeignKey("sessions.id"), nullable=False), sa.Column("title", sa.String(255), nullable=False), sa.Column("severity", sa.String(30), nullable=False), sa.Column("status", sa.String(30), nullable=False, server_default="OPEN"), sa.Column("summary", sa.Text(), nullable=False), sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()))
    op.create_table("decoy_interactions", sa.Column("id", sa.Integer(), primary_key=True), sa.Column("session_id", sa.String(120), sa.ForeignKey("sessions.id"), nullable=False), sa.Column("resource", sa.String(255), nullable=False), sa.Column("action", sa.String(80), nullable=False), sa.Column("confidence_delta", sa.Integer(), nullable=False, server_default="0"), sa.Column("observed_at", sa.DateTime(timezone=True), server_default=sa.func.now()), sa.Column("metadata", json_value, nullable=False))
    op.create_table("response_actions", sa.Column("id", sa.Integer(), primary_key=True), sa.Column("session_id", sa.String(120), sa.ForeignKey("sessions.id"), nullable=False), sa.Column("action", sa.String(80), nullable=False), sa.Column("reason", sa.Text(), nullable=False), sa.Column("performed_at", sa.DateTime(timezone=True), server_default=sa.func.now()))
    op.create_table("approvals", sa.Column("id", sa.Integer(), primary_key=True), sa.Column("identity_id", sa.String(80), sa.ForeignKey("identities.id"), nullable=False), sa.Column("approval_type", sa.String(80), nullable=False), sa.Column("active", sa.Boolean(), nullable=False, server_default=sa.true()), sa.Column("expires_at", sa.DateTime(timezone=True)), sa.Column("reason", sa.Text(), nullable=False))
    for table, column in (("sessions", "identity_id"), ("sessions", "device_id"), ("sessions", "started_at"), ("sessions", "last_seen"), ("events", "timestamp"), ("events", "identity_id"), ("events", "session_id"), ("events", "device_id"), ("events", "event_type"), ("baseline_profiles", "identity_id"), ("peer_baselines", "department"), ("peer_baselines", "role"), ("risk_snapshots", "session_id"), ("intent_detections", "session_id"), ("incidents", "session_id"), ("decoy_interactions", "session_id"), ("response_actions", "session_id"), ("approvals", "identity_id")):
        op.create_index(f"ix_{table}_{column}", table, [column])


def downgrade() -> None:
    for table in ("approvals", "response_actions", "decoy_interactions", "incidents", "intent_detections", "risk_snapshots", "peer_baselines", "baseline_profiles", "events", "sessions", "devices", "identities"):
        op.drop_table(table)
