from datetime import datetime
from typing import Any

from sqlalchemy import Boolean, DateTime, Float, ForeignKey, Integer, JSON, String, Text, UniqueConstraint, func
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from app.db.session import Base

JSON_VALUE = JSON().with_variant(JSONB, "postgresql")


class IdentityRecord(Base):
    __tablename__ = "identities"
    id: Mapped[str] = mapped_column(String(80), primary_key=True)
    department: Mapped[str | None] = mapped_column(String(120))
    role: Mapped[str | None] = mapped_column(String(120))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class DeviceRecord(Base):
    __tablename__ = "devices"
    id: Mapped[str] = mapped_column(String(120), primary_key=True)
    trust_level: Mapped[str] = mapped_column(String(30), default="UNKNOWN")
    first_seen: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_seen: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class SessionRecord(Base):
    __tablename__ = "sessions"
    id: Mapped[str] = mapped_column(String(120), primary_key=True)
    identity_id: Mapped[str] = mapped_column(ForeignKey("identities.id"), index=True)
    device_id: Mapped[str] = mapped_column(ForeignKey("devices.id"), index=True)
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    closed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    risk_score: Mapped[int] = mapped_column(Integer, default=0)
    anomaly_score: Mapped[int] = mapped_column(Integer, default=0)
    sequence_score: Mapped[int] = mapped_column(Integer, default=0)
    intent: Mapped[str] = mapped_column(String(40), default="NONE")
    intent_confidence: Mapped[float] = mapped_column(Float, default=0)
    status: Mapped[str] = mapped_column(String(40), default="NORMAL")
    is_contained: Mapped[bool] = mapped_column(Boolean, default=False)
    approved_override: Mapped[bool] = mapped_column(Boolean, default=False)
    features: Mapped[dict[str, Any]] = mapped_column(JSON_VALUE, default=dict)
    evidence: Mapped[list[str]] = mapped_column(JSON_VALUE, default=list)


class EventRecord(Base):
    __tablename__ = "events"
    id: Mapped[str] = mapped_column(String(120), primary_key=True)
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    identity_id: Mapped[str] = mapped_column(ForeignKey("identities.id"), index=True)
    session_id: Mapped[str | None] = mapped_column(ForeignKey("sessions.id"), index=True)
    device_id: Mapped[str] = mapped_column(ForeignKey("devices.id"), index=True)
    event_type: Mapped[str] = mapped_column(String(60), index=True)
    event_category: Mapped[str] = mapped_column(String(60))
    source: Mapped[str] = mapped_column(String(120))
    target: Mapped[str | None] = mapped_column(String(200))
    resource_type: Mapped[str | None] = mapped_column(String(80))
    resource_sensitivity: Mapped[int] = mapped_column(Integer, default=0)
    action: Mapped[str] = mapped_column(String(120))
    result: Mapped[str] = mapped_column(String(40))
    metadata_json: Mapped[dict[str, Any]] = mapped_column("metadata", JSON_VALUE, default=dict)


class BaselineProfileRecord(Base):
    __tablename__ = "baseline_profiles"
    id: Mapped[int] = mapped_column(primary_key=True)
    identity_id: Mapped[str] = mapped_column(ForeignKey("identities.id"), unique=True, index=True)
    profile: Mapped[dict[str, Any]] = mapped_column(JSON_VALUE, default=dict)
    trusted_observations: Mapped[int] = mapped_column(Integer, default=0)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())


class PeerBaselineRecord(Base):
    __tablename__ = "peer_baselines"
    __table_args__ = (UniqueConstraint("department", "role", name="uq_peer_baselines_department_role"),)
    id: Mapped[int] = mapped_column(primary_key=True)
    department: Mapped[str] = mapped_column(String(120), index=True)
    role: Mapped[str] = mapped_column(String(120), index=True)
    profile: Mapped[dict[str, Any]] = mapped_column(JSON_VALUE, default=dict)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())


class RiskSnapshotRecord(Base):
    __tablename__ = "risk_snapshots"
    id: Mapped[int] = mapped_column(primary_key=True)
    session_id: Mapped[str] = mapped_column(ForeignKey("sessions.id"), index=True)
    recorded_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    risk_score: Mapped[int] = mapped_column(Integer)
    components: Mapped[dict[str, Any]] = mapped_column(JSON_VALUE, default=dict)
    explanation: Mapped[list[str]] = mapped_column(JSON_VALUE, default=list)


class IntentDetectionRecord(Base):
    __tablename__ = "intent_detections"
    id: Mapped[int] = mapped_column(primary_key=True)
    session_id: Mapped[str] = mapped_column(ForeignKey("sessions.id"), index=True)
    intent: Mapped[str] = mapped_column(String(40))
    confidence: Mapped[float] = mapped_column(Float)
    evidence: Mapped[list[str]] = mapped_column(JSON_VALUE, default=list)
    detected_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class IncidentRecord(Base):
    __tablename__ = "incidents"
    id: Mapped[str] = mapped_column(String(120), primary_key=True)
    session_id: Mapped[str] = mapped_column(ForeignKey("sessions.id"), index=True)
    title: Mapped[str] = mapped_column(String(255))
    severity: Mapped[str] = mapped_column(String(30))
    status: Mapped[str] = mapped_column(String(30), default="OPEN")
    summary: Mapped[str] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class DecoyInteractionRecord(Base):
    __tablename__ = "decoy_interactions"
    id: Mapped[int] = mapped_column(primary_key=True)
    session_id: Mapped[str] = mapped_column(ForeignKey("sessions.id"), index=True)
    resource: Mapped[str] = mapped_column(String(255))
    action: Mapped[str] = mapped_column(String(80))
    confidence_delta: Mapped[int] = mapped_column(Integer, default=0)
    observed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    metadata_json: Mapped[dict[str, Any]] = mapped_column("metadata", JSON_VALUE, default=dict)


class ResponseActionRecord(Base):
    __tablename__ = "response_actions"
    id: Mapped[int] = mapped_column(primary_key=True)
    session_id: Mapped[str] = mapped_column(ForeignKey("sessions.id"), index=True)
    action: Mapped[str] = mapped_column(String(80))
    reason: Mapped[str] = mapped_column(Text)
    performed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class ApprovalRecord(Base):
    __tablename__ = "approvals"
    id: Mapped[int] = mapped_column(primary_key=True)
    identity_id: Mapped[str] = mapped_column(ForeignKey("identities.id"), index=True)
    approval_type: Mapped[str] = mapped_column(String(80))
    active: Mapped[bool] = mapped_column(Boolean, default=True)
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    reason: Mapped[str] = mapped_column(Text)


# Passive network-flow entities.  These tables are intentionally separate from
# the retired identity/session prototype tables above so an existing local
# development database can be upgraded without destructive migration.
class NetworkFlowRecord(Base):
    __tablename__ = "network_flows"
    event_id: Mapped[str] = mapped_column(String(120), primary_key=True)
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    source_ip: Mapped[str] = mapped_column(String(45), index=True)
    destination_ip: Mapped[str] = mapped_column(String(45), index=True)
    source_port: Mapped[int] = mapped_column(Integer)
    destination_port: Mapped[int] = mapped_column(Integer, index=True)
    protocol: Mapped[str] = mapped_column(String(10))
    packet_count: Mapped[int] = mapped_column(Integer)
    byte_count: Mapped[int] = mapped_column(Integer)
    packet_rate: Mapped[float] = mapped_column(Float)
    byte_rate: Mapped[float] = mapped_column(Float)
    flow_duration: Mapped[float] = mapped_column(Float)
    inter_arrival_time: Mapped[float] = mapped_column(Float)
    tcp_flags: Mapped[str] = mapped_column(String(40), default="")
    dns_query: Mapped[str | None] = mapped_column(String(255))
    dns_query_length: Mapped[int] = mapped_column(Integer, default=0)
    dns_entropy: Mapped[float] = mapped_column(Float, default=0)
    domain_length: Mapped[int] = mapped_column(Integer, default=0)
    connection_interval: Mapped[float | None] = mapped_column(Float)
    session_id: Mapped[str] = mapped_column(String(160), index=True)
    host_id: Mapped[str] = mapped_column(String(120), index=True)
    scenario_id: Mapped[str] = mapped_column(String(160), index=True)
    traffic_label: Mapped[str] = mapped_column(String(40), default="NORMAL")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class FlowFeatureRecord(Base):
    __tablename__ = "flow_features"
    event_id: Mapped[str] = mapped_column(ForeignKey("network_flows.event_id"), primary_key=True)
    window_seconds: Mapped[int] = mapped_column(Integer)
    values: Mapped[dict[str, Any]] = mapped_column(JSON_VALUE, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class FlowDetectionRecord(Base):
    __tablename__ = "flow_detections"
    detection_id: Mapped[str] = mapped_column(String(120), primary_key=True)
    event_id: Mapped[str] = mapped_column(ForeignKey("network_flows.event_id"), unique=True, index=True)
    predicted_threat: Mapped[str] = mapped_column(String(40), index=True)
    confidence: Mapped[float] = mapped_column(Float)
    risk_score: Mapped[int] = mapped_column(Integer, index=True)
    severity: Mapped[str] = mapped_column(String(20))
    scores: Mapped[dict[str, Any]] = mapped_column(JSON_VALUE, default=dict)
    threat_dna: Mapped[dict[str, Any]] = mapped_column(JSON_VALUE, default=dict)
    supporting_evidence: Mapped[list[str]] = mapped_column(JSON_VALUE, default=list)
    counter_evidence: Mapped[list[str]] = mapped_column(JSON_VALUE, default=list)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class FlowAlertRecord(Base):
    __tablename__ = "flow_alerts"
    alert_id: Mapped[str] = mapped_column(String(120), primary_key=True)
    event_id: Mapped[str] = mapped_column(ForeignKey("network_flows.event_id"), index=True)
    detection_id: Mapped[str] = mapped_column(ForeignKey("flow_detections.detection_id"), unique=True, index=True)
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    title: Mapped[str] = mapped_column(String(255))
    threat: Mapped[str] = mapped_column(String(40), index=True)
    severity: Mapped[str] = mapped_column(String(20))
    confidence: Mapped[float] = mapped_column(Float)
    risk_score: Mapped[int] = mapped_column(Integer)
    status: Mapped[str] = mapped_column(String(30), default="OPEN")
    supporting_evidence: Mapped[list[str]] = mapped_column(JSON_VALUE, default=list)
    counter_evidence: Mapped[list[str]] = mapped_column(JSON_VALUE, default=list)


class FlowIncidentRecord(Base):
    __tablename__ = "flow_incidents"
    incident_id: Mapped[str] = mapped_column(String(120), primary_key=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())
    title: Mapped[str] = mapped_column(String(255))
    severity: Mapped[str] = mapped_column(String(20))
    risk_score: Mapped[int] = mapped_column(Integer, index=True)
    confidence: Mapped[float] = mapped_column(Float)
    affected_host: Mapped[str] = mapped_column(String(120), index=True)
    related_event_ids: Mapped[list[str]] = mapped_column(JSON_VALUE, default=list)
    related_alert_ids: Mapped[list[str]] = mapped_column(JSON_VALUE, default=list)
    status: Mapped[str] = mapped_column(String(30), default="OPEN")
    evidence: Mapped[list[str]] = mapped_column(JSON_VALUE, default=list)
    recommendations: Mapped[list[str]] = mapped_column(JSON_VALUE, default=list)
    analyst_verdict: Mapped[str | None] = mapped_column(String(30))
    analyst_feedback_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class NetworkBaselineRecord(Base):
    __tablename__ = "network_baselines"
    host_id: Mapped[str] = mapped_column(String(120), primary_key=True)
    profile: Mapped[dict[str, Any]] = mapped_column(JSON_VALUE, default=dict)
    trusted_observations: Mapped[int] = mapped_column(Integer, default=0)
    last_updated: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())


class AnalystFeedbackRecord(Base):
    __tablename__ = "analyst_feedback"
    feedback_id: Mapped[str] = mapped_column(String(120), primary_key=True)
    incident_id: Mapped[str] = mapped_column(ForeignKey("flow_incidents.incident_id"), index=True)
    verdict: Mapped[str] = mapped_column(String(30))
    note: Mapped[str] = mapped_column(Text, default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class SimulationRunRecord(Base):
    __tablename__ = "simulation_runs"
    run_id: Mapped[str] = mapped_column(String(120), primary_key=True)
    scenario: Mapped[str] = mapped_column(String(40), index=True)
    state: Mapped[str] = mapped_column(String(20), default="RUNNING")
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    stopped_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    events_generated: Mapped[int] = mapped_column(Integer, default=0)
    flows_analyzed: Mapped[int] = mapped_column(Integer, default=0)
    alerts_generated: Mapped[int] = mapped_column(Integer, default=0)
    incidents_created: Mapped[int] = mapped_column(Integer, default=0)
    average_detection_latency_ms: Mapped[float] = mapped_column(Float, default=0)
