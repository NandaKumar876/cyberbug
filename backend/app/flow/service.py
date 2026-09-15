"""Transactional passive-flow pipeline, alert correlation, and query services."""

from __future__ import annotations

from collections import Counter, deque
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from time import perf_counter
from uuid import uuid4

from sqlalchemy import delete, select
from sqlalchemy.orm import Session

from app.db.models import (
    AnalystFeedbackRecord, AttackStoryRecord, FlowAlertRecord, FlowDetectionRecord,
    FlowFeatureRecord, FlowIncidentRecord, NetworkBaselineRecord, NetworkFlowRecord,
    SimulationRunRecord,
)
from app.flow.baseline import deviation, profile_for, to_response, update
from app.flow.detection import fuse
from app.flow.features import extract_features
from app.flow.ml import load_models
from app.flow.schemas import (
    AlertResponse, AnalystFeedbackRequest, AttackStoryEntry, BaselineResponse,
    DetectionResult, FlowFeatures, FlowRecord, IncidentResponse, IncidentStatus,
    OverviewResponse, ScenarioKind, SimulationState, TelemetryResponse, TrafficLabel,
)


@dataclass
class PipelineMetrics:
    processed: int = 0
    alerts: int = 0
    incidents: int = 0
    errors: int = 0
    latencies_ms: deque[float] = field(default_factory=lambda: deque(maxlen=500))
    inference_ms: deque[float] = field(default_factory=lambda: deque(maxlen=500))
    started_at: float = field(default_factory=perf_counter)
    queue_depth: int = 0

    def snapshot(self) -> dict[str, float | int | bool]:
        elapsed = max(.001, perf_counter() - self.started_at)
        return {
            "events_per_second": round(self.processed / elapsed, 3),
            "flows_per_second": round(self.processed / elapsed, 3),
            "average_detection_latency_ms": round(sum(self.latencies_ms) / max(1, len(self.latencies_ms)), 3),
            "model_inference_ms": round(sum(self.inference_ms) / max(1, len(self.inference_ms)), 3),
            "errors": self.errors,
            "queue_depth": self.queue_depth,
        }


metrics = PipelineMetrics()


@dataclass(frozen=True)
class ProcessResult:
    flow: FlowRecord
    features: FlowFeatures
    detection: DetectionResult
    alert: AlertResponse | None
    incident: IncidentResponse | None
    story: AttackStoryEntry


def _flow_from_record(record: NetworkFlowRecord) -> FlowRecord:
    return FlowRecord(
        event_id=record.event_id, timestamp=record.timestamp, source_ip=record.source_ip,
        destination_ip=record.destination_ip, source_port=record.source_port,
        destination_port=record.destination_port, protocol=record.protocol,
        packet_count=record.packet_count, byte_count=record.byte_count,
        packet_rate=record.packet_rate, byte_rate=record.byte_rate, flow_duration=record.flow_duration,
        inter_arrival_time=record.inter_arrival_time, tcp_flags=record.tcp_flags,
        dns_query=record.dns_query, dns_query_length=record.dns_query_length,
        dns_entropy=record.dns_entropy, domain_length=record.domain_length,
        connection_interval=record.connection_interval, session_id=record.session_id,
        host_id=record.host_id, scenario_id=record.scenario_id,
        traffic_label=TrafficLabel(record.traffic_label),
    )


def _to_alert(record: FlowAlertRecord) -> AlertResponse:
    return AlertResponse(
        alert_id=record.alert_id, event_id=record.event_id, detection_id=record.detection_id,
        timestamp=record.timestamp, title=record.title, threat=TrafficLabel(record.threat),
        severity=record.severity, confidence=record.confidence, risk_score=record.risk_score,
        status=record.status, supporting_evidence=record.supporting_evidence,
        counter_evidence=record.counter_evidence,
    )


def _to_incident(record: FlowIncidentRecord) -> IncidentResponse:
    return IncidentResponse(
        incident_id=record.incident_id, created_at=record.created_at, updated_at=record.updated_at,
        title=record.title, severity=record.severity, risk_score=record.risk_score,
        confidence=record.confidence, affected_host=record.affected_host,
        related_event_ids=record.related_event_ids, related_alert_ids=record.related_alert_ids,
        status=IncidentStatus(record.status), evidence=record.evidence,
        recommendations=record.recommendations, analyst_verdict=record.analyst_verdict,
        analyst_feedback_at=record.analyst_feedback_at,
    )


def _story_stage(threat: TrafficLabel) -> str:
    return {
        TrafficLabel.NORMAL: "Normal traffic baseline observation",
        TrafficLabel.DGA: "DNS anomaly",
        TrafficLabel.DNS_TUNNELING: "DNS anomaly",
        TrafficLabel.C2_BEACONING: "C2-like periodic communication",
        TrafficLabel.SCANNING: "Reconnaissance activity",
        TrafficLabel.DDOS: "Traffic anomaly / possible protocol flood",
    }[threat]


def _incident_title(threat: TrafficLabel, flow: FlowRecord) -> str:
    if threat is TrafficLabel.DDOS:
        return f"Possible DDoS / protocol flood against {flow.destination_ip}"
    if threat is TrafficLabel.C2_BEACONING:
        return f"Possible compromised host: {flow.host_id}"
    if threat in {TrafficLabel.DGA, TrafficLabel.DNS_TUNNELING}:
        return f"Suspicious DNS behaviour on {flow.host_id}"
    return f"Possible reconnaissance activity from {flow.host_id}"


def _recommendations(threat: TrafficLabel) -> list[str]:
    base = ["Validate this passive finding with the responsible SOC analyst.", "Preserve the referenced flow metadata for investigation; CyberBug sends no traffic back through the ingest path."]
    if threat is TrafficLabel.DDOS:
        return ["Review the protected service's upstream capacity and rate-limit policy through the approved operations workflow.", *base]
    if threat is TrafficLabel.C2_BEACONING:
        return ["Review the host's approved destination allow-list and endpoint telemetry through the incident workflow.", *base]
    if threat in {TrafficLabel.DGA, TrafficLabel.DNS_TUNNELING}:
        return ["Review the DNS resolver logs and approved DNS policy through the incident workflow.", *base]
    return ["Review authorised asset-discovery or vulnerability-management windows before escalating.", *base]


class FlowPipeline:
    """Processes one observed flow transactionally; no function emits network traffic."""

    def process(self, db: Session, flow: FlowRecord, *, run_id: str | None = None) -> ProcessResult:
        started = perf_counter()
        if db.get(NetworkFlowRecord, flow.event_id) is not None:
            raise ValueError(f"Duplicate flow event_id: {flow.event_id}")
        try:
            cutoff = flow.timestamp - timedelta(seconds=60)
            recent_records = db.scalars(
                select(NetworkFlowRecord).where(NetworkFlowRecord.timestamp >= cutoff).order_by(NetworkFlowRecord.timestamp)
            ).all()
            recent = [_flow_from_record(item) for item in recent_records]
            baseline_record = db.get(NetworkBaselineRecord, flow.host_id)
            provisional = extract_features(flow, recent)
            baseline_deviation = deviation(baseline_record, flow, provisional)
            features = provisional.model_copy(update={"host_behaviour_deviation": baseline_deviation})
            profile = profile_for(baseline_record)
            packet_rates: list[float] = profile["packet_rates"]  # type: ignore[assignment]
            baseline_packet_rate = sum(packet_rates) / max(1, len(packet_rates))
            model = load_models()
            detection = fuse(
                flow, features, baseline_packet_rate=baseline_packet_rate,
                baseline_observations=baseline_record.trusted_observations if baseline_record else 0,
                model=model,
            )
            db.add(NetworkFlowRecord(**flow.model_dump()))
            db.add(FlowFeatureRecord(event_id=flow.event_id, window_seconds=features.window_seconds, values=features.model_dump(mode="json")))
            db.add(FlowDetectionRecord(
                detection_id=detection.detection_id, event_id=flow.event_id,
                predicted_threat=detection.predicted_threat.value, confidence=detection.confidence,
                risk_score=detection.risk_score, severity=detection.severity,
                scores=detection.scores.model_dump(), threat_dna=detection.threat_dna.model_dump(),
                supporting_evidence=detection.supporting_evidence, counter_evidence=detection.counter_evidence,
            ))
            # Ground-truth labels exist only for controlled synthetic generation.
            # A real submitted flow trains the baseline only when fusion regards it as low risk.
            if detection.predicted_threat is TrafficLabel.NORMAL and detection.risk_score < 30:
                trusted = update(baseline_record, flow, features)
                if baseline_record is None:
                    db.add(trusted)
            alert = self._create_alert(db, flow, detection)
            incident = self._correlate(db, flow, detection, alert) if alert else None
            story = self._record_story(db, flow, detection, incident)
            if run_id:
                run = db.get(SimulationRunRecord, run_id)
                if run:
                    run.events_generated += 1
                    run.flows_analyzed += 1
                    if alert:
                        run.alerts_generated += 1
                    if incident and incident.created_at == incident.updated_at:
                        run.incidents_created += 1
                    elapsed_ms = (perf_counter() - started) * 1_000
                    previous = run.average_detection_latency_ms * max(0, run.flows_analyzed - 1)
                    run.average_detection_latency_ms = round((previous + elapsed_ms) / run.flows_analyzed, 4)
            db.commit()
            metrics.processed += 1
            if alert:
                metrics.alerts += 1
            if incident:
                metrics.incidents += 1
            metrics.latencies_ms.append((perf_counter() - started) * 1_000)
            metrics.inference_ms.append(detection.scores.model_inference_ms)
            return ProcessResult(flow=flow, features=features, detection=detection, alert=alert, incident=incident, story=story)
        except Exception:
            db.rollback()
            metrics.errors += 1
            raise

    def _create_alert(self, db: Session, flow: FlowRecord, detection: DetectionResult) -> AlertResponse | None:
        if detection.predicted_threat is TrafficLabel.NORMAL or detection.risk_score < 30:
            return None
        record = FlowAlertRecord(
            alert_id=f"ALT-{flow.event_id.removeprefix('EVT-')}", event_id=flow.event_id,
            detection_id=detection.detection_id, timestamp=flow.timestamp,
            title=f"Possible {detection.predicted_threat.value.replace('_', ' ').title()} behaviour",
            threat=detection.predicted_threat.value, severity=detection.severity,
            confidence=detection.confidence, risk_score=detection.risk_score, status="OPEN",
            supporting_evidence=detection.supporting_evidence, counter_evidence=detection.counter_evidence,
        )
        db.add(record)
        db.flush()
        return _to_alert(record)

    def _correlate(self, db: Session, flow: FlowRecord, detection: DetectionResult, alert: AlertResponse) -> IncidentResponse | None:
        cutoff = flow.timestamp - timedelta(minutes=20)
        existing = db.scalars(
            select(FlowIncidentRecord).where(
                FlowIncidentRecord.affected_host == flow.host_id,
                FlowIncidentRecord.status.in_([IncidentStatus.OPEN.value, IncidentStatus.INVESTIGATING.value]),
                FlowIncidentRecord.updated_at >= cutoff,
            ).order_by(FlowIncidentRecord.updated_at.desc())
        ).first()
        related_alerts = db.scalars(
            select(FlowAlertRecord).join(NetworkFlowRecord, NetworkFlowRecord.event_id == FlowAlertRecord.event_id).where(
                NetworkFlowRecord.host_id == flow.host_id, FlowAlertRecord.timestamp >= cutoff,
            )
        ).all()
        if existing is None and len(related_alerts) < 2 and detection.risk_score < 80:
            return None
        if existing is None:
            existing = FlowIncidentRecord(
                incident_id=f"INC-{uuid4().hex[:8].upper()}", title=_incident_title(detection.predicted_threat, flow),
                severity=detection.severity, risk_score=detection.risk_score, confidence=detection.confidence,
                affected_host=flow.host_id, related_event_ids=[flow.event_id], related_alert_ids=[alert.alert_id],
                status=IncidentStatus.OPEN.value, evidence=detection.supporting_evidence,
                recommendations=_recommendations(detection.predicted_threat),
            )
            db.add(existing)
        else:
            existing.related_event_ids = [*existing.related_event_ids, flow.event_id][-100:]
            existing.related_alert_ids = [*existing.related_alert_ids, alert.alert_id][-100:]
            existing.risk_score = max(existing.risk_score, detection.risk_score)
            existing.confidence = max(existing.confidence, detection.confidence)
            if detection.severity == "CRITICAL":
                existing.severity = "CRITICAL"
            existing.evidence = [*existing.evidence, *detection.supporting_evidence][-20:]
        db.flush()
        return _to_incident(existing)

    def _record_story(self, db: Session, flow: FlowRecord, detection: DetectionResult, incident: IncidentResponse | None) -> AttackStoryEntry:
        evidence = detection.supporting_evidence[0] if detection.supporting_evidence else "Observed flow matched the current normal baseline."
        record = AttackStoryRecord(
            story_id=f"STORY-{flow.event_id.removeprefix('EVT-')}", timestamp=flow.timestamp,
            host_id=flow.host_id, event_id=flow.event_id, incident_id=incident.incident_id if incident else None,
            stage=_story_stage(detection.predicted_threat), severity=detection.severity, evidence=evidence,
        )
        db.add(record)
        return AttackStoryEntry(
            story_id=record.story_id, timestamp=record.timestamp, host_id=record.host_id,
            event_id=record.event_id, incident_id=record.incident_id, stage=record.stage,
            severity=record.severity, evidence=record.evidence,
        )


pipeline = FlowPipeline()


def list_flows(db: Session, limit: int = 100) -> list[FlowRecord]:
    return [_flow_from_record(item) for item in db.scalars(select(NetworkFlowRecord).order_by(NetworkFlowRecord.timestamp.desc()).limit(min(max(limit, 1), 500))).all()]


def list_alerts(db: Session, limit: int = 100) -> list[AlertResponse]:
    return [_to_alert(item) for item in db.scalars(select(FlowAlertRecord).order_by(FlowAlertRecord.timestamp.desc()).limit(min(max(limit, 1), 500))).all()]


def list_incidents(db: Session) -> list[IncidentResponse]:
    return [_to_incident(item) for item in db.scalars(select(FlowIncidentRecord).order_by(FlowIncidentRecord.updated_at.desc())).all()]


def list_baselines(db: Session) -> list[BaselineResponse]:
    return [to_response(item) for item in db.scalars(select(NetworkBaselineRecord).order_by(NetworkBaselineRecord.host_id)).all()]


def list_telemetry(db: Session, limit: int = 150) -> list[TelemetryResponse]:
    rows = db.execute(
        select(NetworkFlowRecord, FlowDetectionRecord).join(FlowDetectionRecord, FlowDetectionRecord.event_id == NetworkFlowRecord.event_id).order_by(NetworkFlowRecord.timestamp.desc()).limit(min(max(limit, 1), 500))
    ).all()
    return [TelemetryResponse(
        event_id=flow.event_id, timestamp=flow.timestamp, event_type=detection.predicted_threat,
        source=flow.source_ip, destination=flow.destination_ip, protocol=flow.protocol,
        session_id=flow.session_id, severity=detection.severity,
        status="ALERT" if detection.risk_score >= 30 else "OBSERVED", risk_score=detection.risk_score,
    ) for flow, detection in rows]


def list_story(db: Session, limit: int = 100) -> list[AttackStoryEntry]:
    return [AttackStoryEntry(
        story_id=item.story_id, timestamp=item.timestamp, host_id=item.host_id, event_id=item.event_id,
        incident_id=item.incident_id, stage=item.stage, severity=item.severity, evidence=item.evidence,
    ) for item in db.scalars(select(AttackStoryRecord).order_by(AttackStoryRecord.timestamp.desc()).limit(min(max(limit, 1), 500))).all()]


def overview(db: Session, state: SimulationState, scenario: ScenarioKind | None, websocket_connected: bool) -> OverviewResponse:
    flows = db.scalars(select(NetworkFlowRecord).order_by(NetworkFlowRecord.timestamp.desc()).limit(180)).all()
    alerts = db.scalars(select(FlowAlertRecord).order_by(FlowAlertRecord.timestamp.desc()).limit(180)).all()
    incidents = db.scalars(select(FlowIncidentRecord)).all()
    latest_time = flows[0].timestamp if flows else datetime.now(UTC)
    event_count = sum(flow.timestamp >= latest_time - timedelta(minutes=1) for flow in flows)
    flow_rate = [{"time": item.timestamp.isoformat(), "packet_rate": round(item.packet_rate, 2), "risk": next((alert.risk_score for alert in alerts if alert.event_id == item.event_id), 0)} for item in reversed(flows[:36])]
    top_sources = [{"label": value, "count": count} for value, count in Counter(item.source_ip for item in flows).most_common(5)]
    top_destinations = [{"label": value, "count": count} for value, count in Counter(item.destination_ip for item in flows).most_common(5)]
    distribution = {"low": sum(item.risk_score < 35 for item in alerts), "medium": sum(35 <= item.risk_score < 60 for item in alerts), "high": sum(60 <= item.risk_score < 80 for item in alerts), "critical": sum(item.risk_score >= 80 for item in alerts)}
    return OverviewResponse(
        live_flows=len(flows), active_threats=sum(item.status == "OPEN" for item in alerts),
        critical_incidents=sum(item.severity == "CRITICAL" and item.status in {"OPEN", "INVESTIGATING"} for item in incidents),
        current_risk=max([item.risk_score for item in alerts], default=0), events_per_minute=event_count,
        flow_rate=flow_rate, risk_distribution=distribution, top_sources=top_sources,
        top_destinations=top_destinations, simulator_state=state, simulator_scenario=scenario,
        telemetry_connected=websocket_connected, observability=metrics.snapshot(),
    )


def submit_feedback(db: Session, payload: AnalystFeedbackRequest) -> IncidentResponse:
    incident = db.get(FlowIncidentRecord, payload.incident_id)
    if incident is None:
        raise KeyError(payload.incident_id)
    if payload.verdict not in {IncidentStatus.CONFIRMED, IncidentStatus.FALSE_POSITIVE}:
        raise ValueError("Analyst feedback accepts CONFIRMED or FALSE_POSITIVE only")
    now = datetime.now(UTC)
    incident.status = payload.verdict.value
    incident.analyst_verdict = payload.verdict.value
    incident.analyst_feedback_at = now
    db.add(AnalystFeedbackRecord(feedback_id=f"FDB-{uuid4().hex[:10].upper()}", incident_id=incident.incident_id, verdict=payload.verdict.value, note=payload.note))
    db.commit()
    db.refresh(incident)
    return _to_incident(incident)


def safe_response_simulation(db: Session, incident_id: str) -> dict[str, object]:
    incident = db.get(FlowIncidentRecord, incident_id)
    if incident is None:
        raise KeyError(incident_id)
    after = round(incident.risk_score * .65)
    return {
        "label": "SIMULATION — NO REAL NETWORK ACTION",
        "incident_id": incident_id,
        "estimated_risk_before": incident.risk_score,
        "estimated_risk_after": after,
        "potentially_affected": ["Protected service dependency review", "Approved DNS or network operations workflow"],
        "potentially_contained": ["Suspicious communication exposure in the model only"],
    }


def reset_flow_data(db: Session) -> None:
    for model in (AttackStoryRecord, AnalystFeedbackRecord, FlowAlertRecord, FlowDetectionRecord, FlowFeatureRecord, NetworkFlowRecord, NetworkBaselineRecord, FlowIncidentRecord, SimulationRunRecord):
        db.execute(delete(model))
    db.commit()
    metrics.processed = metrics.alerts = metrics.incidents = metrics.errors = 0
    metrics.latencies_ms.clear()
    metrics.inference_ms.clear()
    metrics.started_at = perf_counter()
