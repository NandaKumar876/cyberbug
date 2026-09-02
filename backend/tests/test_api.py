from datetime import UTC, datetime
from fastapi.testclient import TestClient
from uuid import uuid4

from app.db.bootstrap import create_schema
from app.db.models import ApprovalRecord, DecoyInteractionRecord, DeviceRecord, IdentityRecord, IncidentRecord, ResponseActionRecord, SessionRecord
from app.db.session import SessionLocal
from app.main import app
from app.policy.overrides import refresh_identity_override

client = TestClient(app)


def test_overview_returns_session_scoped_attention() -> None:
    response = client.get("/api/v1/overview")
    assert response.status_code == 200
    session = response.json()["attention_sessions"][0]
    assert session["id"] == "SES-A817"
    assert session["identity_id"] == "USR-A12"
    assert session["is_contained"] is True


def test_containment_does_not_change_identity_scope() -> None:
    response = client.post("/api/v1/sessions/SES-C441/contain")
    assert response.status_code == 200
    body = response.json()
    assert body["action"] == "REVOKE_APPLICATION_SESSION"
    assert body["session"]["id"] == "SES-C441"


def test_simulation_runs_through_persisted_ingestion() -> None:
    response = client.post("/api/v1/simulation/run", json={"scenario_id": "low-and-slow"})
    assert response.status_code == 200
    body = response.json()
    assert body["generated"] is True
    assert body["sessions"][0]["sequence_score"] == 100


def test_identity_baseline_endpoint_exposes_learning_policy() -> None:
    response = client.get("/api/v1/identities/USR-A12/baseline")
    assert response.status_code == 200
    assert response.json()["learning_policy"]["frozen_above"] == 50


def test_deception_resources_endpoint_is_available() -> None:
    response = client.get("/api/v1/deception/resources")
    assert response.status_code == 200
    assert any(item["synthetic"] is True for item in response.json())


def test_honey_attempt_contain_only_the_eligible_application_session() -> None:
    create_schema()
    suffix = uuid4().hex
    identity_id, device_id, session_id = f"USR-DECOY-{suffix}", f"DEV-DECOY-{suffix}", f"SES-DECOY-{suffix}"
    with SessionLocal() as db:
        db.add(IdentityRecord(id=identity_id, department="Test", role="Analyst"))
        db.add(DeviceRecord(id=device_id, trust_level="UNKNOWN"))
        db.add(SessionRecord(id=session_id, identity_id=identity_id, device_id=device_id, started_at=datetime.now(UTC), last_seen=datetime.now(UTC), risk_score=82, intent="CREDENTIAL_HUNTING", intent_confidence=.91, status="DECEPTION_ELIGIBLE", features={}, evidence=[]))
        db.commit()
    headers = {"X-CyberBug-Session": session_id}
    decoy = client.get("/admin/credentials", headers=headers)
    assert decoy.status_code == 200
    assert decoy.json()["route"] == "DECOY"
    attempt = client.post("/admin/credentials/attempt", headers=headers, json={"credential_id": "HP-DECOY-CRED-2026-01"})
    assert attempt.status_code == 200
    assert attempt.json()["contained"] is True
    with SessionLocal() as db:
        assert db.get(SessionRecord, session_id).is_contained is True
        assert db.query(IncidentRecord).filter_by(session_id=session_id).count() == 1
        db.query(DecoyInteractionRecord).where(DecoyInteractionRecord.session_id == session_id).delete()
        db.query(ResponseActionRecord).where(ResponseActionRecord.session_id == session_id).delete()
        db.query(IncidentRecord).where(IncidentRecord.session_id == session_id).delete()
        db.query(SessionRecord).where(SessionRecord.id == session_id).delete()
        db.query(IdentityRecord).where(IdentityRecord.id == identity_id).delete()
        db.query(DeviceRecord).where(DeviceRecord.id == device_id).delete()
        db.commit()


def test_revoked_approval_stops_session_override() -> None:
    with SessionLocal() as db:
        db.query(ApprovalRecord).where(ApprovalRecord.reason == "Test workflow approval").delete()
        refresh_identity_override(db, "USR-A12")
        db.commit()
    created = client.post("/api/v1/approvals", json={"identity_id": "USR-A12", "approval_type": "approved_bulk_operation", "reason": "Test workflow approval"})
    assert created.status_code == 201
    approval_id = created.json()["id"]
    assert client.get("/api/v1/sessions/SES-A102").json()["approved_override"] is True
    revoked = client.post(f"/api/v1/approvals/{approval_id}/revoke")
    assert revoked.status_code == 200
    assert revoked.json()["effective_override"] is False
    assert client.get("/api/v1/sessions/SES-A102").json()["approved_override"] is False
    with SessionLocal() as db:
        db.query(ApprovalRecord).where(ApprovalRecord.id == approval_id).delete()
        refresh_identity_override(db, "USR-A12")
        db.commit()
