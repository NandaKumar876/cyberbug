"""Typed contracts for passive, unidirectional network-flow analysis.

These models describe observations received by CyberBug.  They deliberately do
not contain probe, handshake, scan-command, or response-control fields.
"""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field, field_validator


class TrafficLabel(StrEnum):
    NORMAL = "NORMAL"
    DDOS = "DDOS"
    C2_BEACONING = "C2_BEACONING"
    DNS_TUNNELING = "DNS_TUNNELING"
    DGA = "DGA"
    SCANNING = "SCANNING"


class ScenarioKind(StrEnum):
    NORMAL = "normal"
    DDOS = "ddos"
    C2 = "c2"
    DNS = "dns"
    SCANNING = "scanning"
    MIXED = "mixed"
    FULL_STORY = "full_story"


class SimulationState(StrEnum):
    STOPPED = "STOPPED"
    RUNNING = "RUNNING"
    PAUSED = "PAUSED"


class IncidentStatus(StrEnum):
    OPEN = "OPEN"
    INVESTIGATING = "INVESTIGATING"
    CONFIRMED = "CONFIRMED"
    FALSE_POSITIVE = "FALSE_POSITIVE"
    RESOLVED = "RESOLVED"


class FlowRecord(BaseModel):
    """A NetFlow/IPFIX-style observation, not an active network operation."""

    event_id: str = Field(pattern=r"^EVT-[A-Z0-9-]+$")
    timestamp: datetime
    source_ip: str
    destination_ip: str
    source_port: int = Field(ge=1, le=65535)
    destination_port: int = Field(ge=1, le=65535)
    protocol: str = Field(pattern=r"^(TCP|UDP|ICMP)$")
    packet_count: int = Field(ge=1)
    byte_count: int = Field(ge=1)
    packet_rate: float = Field(ge=0)
    byte_rate: float = Field(ge=0)
    flow_duration: float = Field(gt=0)
    inter_arrival_time: float = Field(ge=0)
    tcp_flags: str = ""
    dns_query: str | None = None
    dns_query_length: int = Field(default=0, ge=0)
    dns_entropy: float = Field(default=0, ge=0)
    domain_length: int = Field(default=0, ge=0)
    connection_interval: float | None = Field(default=None, ge=0)
    session_id: str
    host_id: str
    scenario_id: str
    traffic_label: TrafficLabel

    @field_validator("source_ip", "destination_ip")
    @classmethod
    def private_demo_address_only(cls, value: str) -> str:
        """Keep the built-in demo and accepted flow API constrained to RFC1918 IPs."""
        if not (value.startswith("10.") or value.startswith("192.168.") or value.startswith("172.16.")):
            raise ValueError("CyberBug accepts only private demonstration addresses")
        return value


class FlowFeatures(BaseModel):
    event_id: str
    window_seconds: int
    packet_rate: float
    byte_rate: float
    flow_duration: float
    source_ip_count: int
    destination_ip_count: int
    port_diversity: int
    protocol_distribution: dict[str, float]
    tcp_flag_distribution: dict[str, float]
    inter_arrival_time: float
    connection_periodicity: float
    dns_query_length: int
    dns_entropy: float
    domain_frequency: int
    unique_domain_ratio: float
    destination_concentration: float
    syn_ratio: float
    successful_session_ratio: float
    host_behaviour_deviation: float = Field(ge=0, le=1)


class DetectorScores(BaseModel):
    rule_score: float = Field(ge=0, le=1)
    ml_probability: float = Field(ge=0, le=1)
    anomaly_score: float = Field(ge=0, le=1)
    baseline_deviation: float = Field(ge=0, le=1)
    model_inference_ms: float = Field(ge=0)


class ThreatDNA(BaseModel):
    high_traffic: float = Field(ge=0, le=1)
    source_diversity: float = Field(ge=0, le=1)
    periodicity: float = Field(ge=0, le=1)
    dns_entropy: float = Field(ge=0, le=1)
    port_diversity: float = Field(ge=0, le=1)
    baseline_deviation: float = Field(ge=0, le=1)


class DetectionResult(BaseModel):
    detection_id: str
    event_id: str
    predicted_threat: TrafficLabel
    confidence: float = Field(ge=0, le=1)
    risk_score: int = Field(ge=0, le=100)
    severity: str
    scores: DetectorScores
    threat_dna: ThreatDNA
    supporting_evidence: list[str]
    counter_evidence: list[str]
    created_at: datetime


class AlertResponse(BaseModel):
    alert_id: str
    event_id: str
    detection_id: str
    timestamp: datetime
    title: str
    threat: TrafficLabel
    severity: str
    confidence: float
    risk_score: int
    status: str
    supporting_evidence: list[str]
    counter_evidence: list[str]


class IncidentResponse(BaseModel):
    incident_id: str
    created_at: datetime
    updated_at: datetime
    title: str
    severity: str
    risk_score: int
    confidence: float
    affected_host: str
    related_event_ids: list[str]
    related_alert_ids: list[str]
    status: IncidentStatus
    evidence: list[str]
    recommendations: list[str]
    analyst_verdict: str | None = None
    analyst_feedback_at: datetime | None = None


class BaselineResponse(BaseModel):
    host_id: str
    normal_packet_rate: float
    normal_byte_rate: float
    known_destinations: list[str]
    typical_ports: list[int]
    communication_periodicity: float
    deviation: float
    status: str
    trusted_observations: int
    last_updated: datetime


class TelemetryResponse(BaseModel):
    event_id: str
    timestamp: datetime
    event_type: str
    source: str
    destination: str
    protocol: str
    session_id: str
    severity: str
    status: str
    risk_score: int


class AttackStoryEntry(BaseModel):
    story_id: str
    timestamp: datetime
    host_id: str
    event_id: str | None = None
    incident_id: str | None = None
    stage: str
    severity: str
    evidence: str


class SimulationControlRequest(BaseModel):
    scenario: ScenarioKind = ScenarioKind.NORMAL
    rate_per_second: int = Field(default=4, ge=1, le=30)


class AnalystFeedbackRequest(BaseModel):
    incident_id: str
    verdict: IncidentStatus
    note: str = Field(default="", max_length=1000)


class SimulationResponse(BaseModel):
    run_id: str | None
    state: SimulationState
    scenario: ScenarioKind | None
    message: str


class OverviewResponse(BaseModel):
    live_flows: int
    active_threats: int
    critical_incidents: int
    current_risk: int
    events_per_minute: int
    flow_rate: list[dict[str, Any]]
    risk_distribution: dict[str, int]
    top_sources: list[dict[str, Any]]
    top_destinations: list[dict[str, Any]]
    simulator_state: SimulationState
    simulator_scenario: ScenarioKind | None
    telemetry_connected: bool
    observability: dict[str, float | int | bool]

