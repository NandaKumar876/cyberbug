from contextlib import asynccontextmanager
from datetime import UTC, datetime, timedelta

from fastapi import Depends, FastAPI, Header, HTTPException, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.db.bootstrap import create_schema, seed_demo_if_empty
from app.db.dependencies import get_ready_db
from app.db.models import ApprovalRecord, BaselineProfileRecord, DecoyInteractionRecord, DeviceRecord, EventRecord, IdentityRecord, IncidentRecord, IntentDetectionRecord, PeerBaselineRecord, ResponseActionRecord, RiskSnapshotRecord, SessionRecord
from app.db.repository import contain, list_session_details, session_detail, session_summary
from app.db.session import SessionLocal
from app.schemas import ApprovalRequest, ContainmentResponse, OverviewResponse, Scenario, SessionDetail, SimulationRunRequest
from app.simulation.store import SCENARIOS
from app.ingestion import ingest_event
from app.normalization.event import NormalizedEvent
from app.realtime import hub
from app.simulation.runner import run_scenario
from app.corporate.router import router as corporate_router
from app.config import settings
from app.deception.decoy_data import DECOYS
from app.collector.health import all_collectors, heartbeat
from app.policy.overrides import refresh_identity_override


@asynccontextmanager
async def lifespan(_: FastAPI):
    if settings.auto_create_schema:
        create_schema()
    with SessionLocal() as db:
        if settings.seed_demo_data:
            seed_demo_if_empty(db)
    yield


app = FastAPI(title="CyberBug API", version="0.2.0", lifespan=lifespan)
app.add_middleware(
    CORSMiddleware,
    allow_origin_regex=".*",
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
app.include_router(corporate_router)


def get_session_or_404(db: Session, session_id: str) -> SessionDetail:
    detail = session_detail(db, session_id)
    if detail is None:
        raise HTTPException(status_code=404, detail="Session not found")
    return detail


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.get("/api/v1/collectors")
def collectors() -> list[dict[str, object]]:
    return all_collectors()


@app.post("/api/v1/collectors/heartbeat")
def collector_heartbeat(payload: dict[str, object], x_cyberbug_collector_token: str | None = Header(default=None)) -> dict[str, object]:
    if settings.collector_token and x_cyberbug_collector_token != settings.collector_token:
        raise HTTPException(status_code=401, detail="Valid collector token required")
    collector_id = str(payload.get("collector_id", "unknown"))
    source = str(payload.get("source", "security"))
    return heartbeat(collector_id, source=source, submitted=int(payload.get("submitted", 0)), skipped=int(payload.get("skipped", 0)))


@app.get("/api/v1/overview", response_model=OverviewResponse)
def overview(db: Session = Depends(get_ready_db)) -> OverviewResponse:
    details = list_session_details(db)
    attention = [detail for detail in details if detail.risk_score >= 51]
    active = db.scalar(select(func.count()).select_from(SessionRecord).where(SessionRecord.closed_at.is_(None))) or 0
    elevated = sum(31 <= detail.risk_score <= 74 for detail in details)
    critical = sum(detail.risk_score >= 75 for detail in details)
    now = datetime.now(UTC).replace(minute=0, second=0, microsecond=0)
    activity = [0] * 24
    snapshots = db.scalars(select(RiskSnapshotRecord).where(RiskSnapshotRecord.recorded_at >= now - timedelta(hours=23))).all()
    for snapshot in snapshots:
        recorded_at = snapshot.recorded_at.replace(tzinfo=UTC) if snapshot.recorded_at.tzinfo is None else snapshot.recorded_at.astimezone(UTC)
        offset = int((recorded_at.replace(minute=0, second=0, microsecond=0) - (now - timedelta(hours=23))).total_seconds() // 3600)
        if 0 <= offset < len(activity):
            activity[offset] = max(activity[offset], snapshot.risk_score)
    return OverviewResponse(active_sessions=active, elevated_sessions=elevated, critical_sessions=critical, risk_activity=activity, attention_sessions=[session_summary(db.get(SessionRecord, detail.id)) for detail in attention], generated_at=datetime.now(UTC))


@app.get("/api/v1/sessions", response_model=list[SessionDetail])
def list_sessions(db: Session = Depends(get_ready_db)) -> list[SessionDetail]:
    return list_session_details(db)


@app.get("/api/v1/sessions/{session_id}", response_model=SessionDetail)
def get_session(session_id: str, db: Session = Depends(get_ready_db)) -> SessionDetail:
    return get_session_or_404(db, session_id)


@app.get("/api/v1/sessions/{session_id}/timeline")
def session_timeline(session_id: str, db: Session = Depends(get_ready_db)):
    return get_session_or_404(db, session_id).timeline


@app.get("/api/v1/sessions/{session_id}/risk")
def session_risk(session_id: str, db: Session = Depends(get_ready_db)) -> dict[str, object]:
    detail = get_session_or_404(db, session_id)
    return {"session_id": session_id, "risk_score": detail.risk_score, "anomaly_score": detail.anomaly_score, "sequence_score": detail.sequence_score, "explanation": detail.reason_codes}


@app.get("/api/v1/sessions/{session_id}/features")
def session_features(session_id: str, db: Session = Depends(get_ready_db)) -> dict[str, object]:
    detail = get_session_or_404(db, session_id)
    record = db.get(SessionRecord, session_id)
    return {
        "session_id": session_id,
        "new_hosts": detail.new_hosts,
        "remote_access_ratio": detail.remote_access_ratio,
        "privilege_attempts": detail.privilege_attempts,
        "baseline_comparison": detail.baseline_comparison,
        "features": record.features if record else {},
    }


@app.post("/api/v1/sessions/{session_id}/contain", response_model=ContainmentResponse)
async def contain_session(session_id: str, db: Session = Depends(get_ready_db)) -> ContainmentResponse:
    summary = contain(db, session_id)
    if summary is None:
        raise HTTPException(status_code=404, detail="Session not found")
    response = ContainmentResponse(session=summary, action="REVOKE_APPLICATION_SESSION", message="The suspicious application session was contained. The identity remains active on other contexts.")
    await hub.publish("incidents", {"type": "SESSION_CONTAINED", "session_id": summary.id, "identity_id": summary.identity_id, "risk_score": summary.risk_score})
    return response


@app.get("/api/v1/events")
def events(limit: int = 100, db: Session = Depends(get_ready_db)) -> list[dict[str, object]]:
    records = db.scalars(select(EventRecord).order_by(EventRecord.timestamp.desc()).limit(min(max(limit, 1), 500))).all()
    return [{"event_id": record.id, "timestamp": record.timestamp, "identity_id": record.identity_id, "session_id": record.session_id, "device_id": record.device_id, "event_type": record.event_type, "source": record.source, "target": record.target, "action": record.action, "result": record.result} for record in records]


@app.get("/api/v1/devices")
def devices(db: Session = Depends(get_ready_db)) -> list[dict[str, object]]:
    rows = db.scalars(select(DeviceRecord).order_by(DeviceRecord.last_seen.desc())).all()
    return [{"device_id": row.id, "trust_level": row.trust_level, "first_seen": row.first_seen, "last_seen": row.last_seen} for row in rows]


@app.get("/api/v1/traffic")
def traffic(limit: int = 100, db: Session = Depends(get_ready_db)) -> list[dict[str, object]]:
    rows = db.scalars(select(EventRecord).where(EventRecord.target.is_not(None)).order_by(EventRecord.timestamp.desc()).limit(min(max(limit, 1), 500))).all()
    return [{"timestamp": row.timestamp, "source": row.source, "source_ip": row.metadata_json.get("source_ip"), "device_id": row.device_id, "target": row.target, "event_type": row.event_type, "action": row.action, "result": row.result} for row in rows]


@app.post("/api/v1/events", response_model=SessionDetail, status_code=201)
async def ingest_normalized_event(event: NormalizedEvent, x_cyberbug_collector_token: str | None = Header(default=None), x_cyberbug_source_ip: str | None = Header(default=None), db: Session = Depends(get_ready_db)) -> SessionDetail:
    """Ingestion boundary for real normalized Windows metadata and approved collectors."""
    if settings.collector_token and x_cyberbug_collector_token != settings.collector_token:
        raise HTTPException(status_code=401, detail="Valid collector token required")
    if x_cyberbug_source_ip:
        event = event.model_copy(update={"metadata": {**event.metadata, "source_ip": x_cyberbug_source_ip}})
    try:
        session = ingest_event(db, event)
    except ValueError as error:
        raise HTTPException(status_code=409, detail=str(error)) from error
    detail = session_detail(db, session.id)
    if detail is None:
        raise HTTPException(status_code=500, detail="Session was not available after ingestion")
    await hub.publish("events", {"type": "NORMALIZED_EVENT", "event_id": event.event_id, "timestamp": event.timestamp.isoformat(), "identity_id": event.identity_id, "session_id": detail.id, "device_id": event.device_id, "event_type": event.event_type.value, "target": event.target, "result": event.result})
    await hub.publish("risk", {"type": "SESSION_RISK_UPDATED", "session_id": detail.id, "identity_id": detail.identity_id, "risk_score": detail.risk_score, "anomaly_score": detail.anomaly_score, "sequence_score": detail.sequence_score, "intent": detail.intent.value, "status": detail.status.value})
    return detail


async def websocket_topic(websocket: WebSocket, topic: str) -> None:
    await hub.connect(topic, websocket)
    try:
        while True:
            # The stream is server-driven; receive keeps the connection alive.
            await websocket.receive_text()
    except WebSocketDisconnect:
        await hub.disconnect(topic, websocket)


@app.websocket("/ws/events")
async def events_stream(websocket: WebSocket) -> None:
    await websocket_topic(websocket, "events")


@app.websocket("/ws/risk")
async def risk_stream(websocket: WebSocket) -> None:
    await websocket_topic(websocket, "risk")


@app.websocket("/ws/incidents")
async def incident_stream(websocket: WebSocket) -> None:
    await websocket_topic(websocket, "incidents")


@app.get("/api/v1/identities")
def identities(db: Session = Depends(get_ready_db)) -> list[dict[str, object]]:
    records = db.scalars(select(IdentityRecord).order_by(IdentityRecord.id)).all()
    return [{"id": record.id, "department": record.department, "role": record.role, "sessions": [session_summary(item).model_dump() for item in db.scalars(select(SessionRecord).where(SessionRecord.identity_id == record.id)).all()]} for record in records]


@app.get("/api/v1/identities/{identity_id}")
def identity(identity_id: str, db: Session = Depends(get_ready_db)) -> dict[str, object]:
    record = db.get(IdentityRecord, identity_id)
    if record is None:
        raise HTTPException(status_code=404, detail="Identity not found")
    sessions = [session_summary(item).model_dump() for item in db.scalars(select(SessionRecord).where(SessionRecord.identity_id == identity_id).order_by(SessionRecord.last_seen.desc())).all()]
    return {"id": record.id, "department": record.department, "role": record.role, "sessions": sessions}


@app.get("/api/v1/identities/{identity_id}/baseline")
def identity_baseline(identity_id: str, db: Session = Depends(get_ready_db)) -> dict[str, object]:
    identity_record = db.get(IdentityRecord, identity_id)
    if identity_record is None:
        raise HTTPException(status_code=404, detail="Identity not found")
    personal = db.scalar(select(BaselineProfileRecord).where(BaselineProfileRecord.identity_id == identity_id))
    peer = db.scalar(select(PeerBaselineRecord).where(PeerBaselineRecord.department == identity_record.department, PeerBaselineRecord.role == identity_record.role))
    return {
        "identity_id": identity_id,
        "learning_policy": {"normal_below": 30, "reduced_through": 50, "frozen_above": 50},
        "personal": {"trusted_observations": personal.trusted_observations, "profile": personal.profile, "updated_at": personal.updated_at} if personal else None,
        "peer": {"department": peer.department, "role": peer.role, "profile": peer.profile, "updated_at": peer.updated_at} if peer else None,
    }


@app.get("/api/v1/identities/{identity_id}/sessions")
def identity_sessions(identity_id: str, db: Session = Depends(get_ready_db)) -> list[SessionDetail]:
    if db.get(IdentityRecord, identity_id) is None:
        raise HTTPException(status_code=404, detail="Identity not found")
    return [detail for detail in list_session_details(db) if detail.identity_id == identity_id]


@app.get("/api/v1/incidents")
def incidents(db: Session = Depends(get_ready_db)) -> list[dict[str, object]]:
    return [{"id": item.id, "session_id": item.session_id, "title": item.title, "severity": item.severity, "status": item.status, "summary": item.summary, "created_at": item.created_at} for item in db.scalars(select(IncidentRecord).order_by(IncidentRecord.created_at.desc())).all()]


@app.get("/api/v1/incidents/{incident_id}")
def incident(incident_id: str, db: Session = Depends(get_ready_db)) -> dict[str, object]:
    record = db.get(IncidentRecord, incident_id)
    if record is None:
        raise HTTPException(status_code=404, detail="Incident not found")
    detail = get_session_or_404(db, record.session_id)
    return {
        "id": record.id,
        "session_id": record.session_id,
        "title": record.title,
        "severity": record.severity,
        "status": record.status,
        "summary": record.summary,
        "created_at": record.created_at,
        "session": detail,
    }


@app.get("/api/v1/deception/sessions")
def deception_sessions(db: Session = Depends(get_ready_db)) -> list[dict[str, object]]:
    records = db.scalars(select(SessionRecord).where(SessionRecord.status.in_(["DECEPTION_ELIGIBLE", "DECEPTION", "CONTAINED"])).order_by(SessionRecord.risk_score.desc())).all()
    return [session_summary(record).model_dump() for record in records]


@app.get("/api/v1/deception/resources")
def deception_resources() -> list[dict[str, object]]:
    return [{"path": resource.path, "title": resource.title, "content_type": resource.content_type, "synthetic": resource.synthetic} for resource in DECOYS.values()]


@app.get("/api/v1/deception/interactions")
def decoy_interactions(db: Session = Depends(get_ready_db)) -> list[dict[str, object]]:
    return [{"session_id": item.session_id, "resource": item.resource, "action": item.action, "confidence_delta": item.confidence_delta, "observed_at": item.observed_at} for item in db.scalars(select(DecoyInteractionRecord).order_by(DecoyInteractionRecord.observed_at.desc())).all()]


@app.get("/api/v1/policies")
def policies() -> list[dict[str, object]]:
    return [
        {"id": "deception-eligibility", "name": "Deception eligibility", "scope": "Risk + eligible intent + confidence + no verified override", "state": "ENFORCED"},
        {"id": "session-containment", "name": "Application session containment", "scope": "Revoke only the suspicious application context", "state": "ENFORCED"},
        {"id": "legitimate-override", "name": "Legitimate operation override", "scope": "Suppress deception while monitoring continues", "state": "ENFORCED"},
    ]


@app.get("/api/v1/approvals")
def approvals(db: Session = Depends(get_ready_db)) -> list[dict[str, object]]:
    now = datetime.now(UTC)
    records = db.scalars(select(ApprovalRecord).order_by(ApprovalRecord.id.desc())).all()
    return [{"id": item.id, "identity_id": item.identity_id, "approval_type": item.approval_type, "active": item.active and (item.expires_at is None or (item.expires_at.replace(tzinfo=UTC) if item.expires_at.tzinfo is None else item.expires_at) > now), "expires_at": item.expires_at, "reason": item.reason} for item in records]


@app.post("/api/v1/approvals", status_code=201)
def create_approval(payload: ApprovalRequest, db: Session = Depends(get_ready_db)) -> dict[str, object]:
    if db.get(IdentityRecord, payload.identity_id) is None:
        raise HTTPException(status_code=404, detail="Identity not found")
    approval = ApprovalRecord(identity_id=payload.identity_id, approval_type=payload.approval_type, reason=payload.reason, expires_at=payload.expires_at)
    db.add(approval)
    db.flush()
    refresh_identity_override(db, payload.identity_id)
    db.commit()
    db.refresh(approval)
    return {"id": approval.id, "identity_id": approval.identity_id, "approval_type": approval.approval_type, "active": approval.active, "expires_at": approval.expires_at, "reason": approval.reason}


@app.post("/api/v1/approvals/{approval_id}/revoke")
def revoke_approval(approval_id: int, db: Session = Depends(get_ready_db)) -> dict[str, object]:
    approval = db.get(ApprovalRecord, approval_id)
    if approval is None:
        raise HTTPException(status_code=404, detail="Approval not found")
    approval.active = False
    db.flush()
    effective = refresh_identity_override(db, approval.identity_id)
    db.commit()
    return {"id": approval.id, "identity_id": approval.identity_id, "active": approval.active, "effective_override": effective}


@app.get("/api/v1/simulation/scenarios", response_model=list[Scenario])
def scenarios() -> list[Scenario]:
    return SCENARIOS


@app.post("/api/v1/simulation/reset")
def reset_simulation(db: Session = Depends(get_ready_db)) -> dict[str, str]:
    simulated_ids = list(db.scalars(select(SessionRecord.id).where(SessionRecord.id.like("SIM-%"))).all())
    if simulated_ids:
        for model in (RiskSnapshotRecord, IntentDetectionRecord, DecoyInteractionRecord, ResponseActionRecord):
            db.query(model).where(model.session_id.in_(simulated_ids)).delete(synchronize_session=False)
        db.query(EventRecord).where(EventRecord.session_id.in_(simulated_ids)).delete(synchronize_session=False)
        db.query(SessionRecord).where(SessionRecord.id.in_(simulated_ids)).delete(synchronize_session=False)
        db.query(BaselineProfileRecord).where(BaselineProfileRecord.identity_id.like("USR-DEMO-%")).delete(synchronize_session=False)
        db.query(IdentityRecord).where(IdentityRecord.id.like("USR-DEMO-%")).delete(synchronize_session=False)
    db.query(EventRecord).where(EventRecord.id.like("EVT-SES-%")).delete(synchronize_session=False)
    db.query(SessionRecord).where(SessionRecord.id.like("SES-%")).delete(synchronize_session=False)
    db.commit()
    seed_demo_if_empty(db)
    return {"status": "reset"}


@app.post("/api/v1/simulation/run")
async def simulation_run(payload: SimulationRunRequest, db: Session = Depends(get_ready_db)) -> dict[str, object]:
    if not any(scenario.id == payload.scenario_id for scenario in SCENARIOS):
        raise HTTPException(status_code=404, detail="Simulation scenario not found")
    try:
        session_ids = run_scenario(db, payload.scenario_id)
    except ValueError as error:
        raise HTTPException(status_code=400, detail=str(error)) from error
    sessions = [get_session_or_404(db, session_id) for session_id in session_ids]
    for session in sessions:
        await hub.publish("risk", {"type": "SESSION_RISK_UPDATED", "session_id": session.id, "identity_id": session.identity_id, "risk_score": session.risk_score, "anomaly_score": session.anomaly_score, "sequence_score": session.sequence_score, "intent": session.intent.value, "status": session.status.value})
    return {"scenario_id": payload.scenario_id, "session_ids": session_ids, "sessions": sessions, "generated": True}
