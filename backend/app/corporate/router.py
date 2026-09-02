"""Protected corporate application routes; this is the only deception enforcement point."""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, Header, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app.db.dependencies import get_ready_db
from app.db.models import SessionRecord
from app.deception.decoy_data import DECOYS, decoy_payload
from app.deception.evidence import record_decoy_access, record_honey_credential_attempt, session_can_receive_decoy
from app.policy.overrides import refresh_identity_override

router = APIRouter(tags=["controlled-corporate-app"])
SessionHeader = Annotated[str | None, Header(alias="X-CyberBug-Session")]

REAL_RESOURCES: dict[str, dict[str, str]] = {
    "/dashboard": {"title": "Corporate dashboard", "classification": "INTERNAL"},
    "/reports": {"title": "Management reports", "classification": "INTERNAL"},
    "/finance": {"title": "Finance workspace", "classification": "CONFIDENTIAL"},
    "/database/customers": {"title": "Customer database", "classification": "RESTRICTED"},
    "/admin": {"title": "Administration", "classification": "RESTRICTED"},
    "/admin/users": {"title": "User administration", "classification": "RESTRICTED"},
    "/admin/credentials": {"title": "Credential management", "classification": "RESTRICTED"},
    "/files/confidential": {"title": "Confidential files", "classification": "RESTRICTED"},
    "/export": {"title": "Export center", "classification": "RESTRICTED"},
}


class HoneyCredentialAttempt(BaseModel):
    """Metadata-only endpoint: never submit, log, or retain a credential value."""

    credential_id: str = Field(pattern=r"^HP-DECOY-CRED-2026-01$")


def _session_or_401(db: Session, session_id: str | None) -> SessionRecord:
    if not session_id:
        raise HTTPException(status_code=401, detail="X-CyberBug-Session is required for controlled application access.")
    session = db.get(SessionRecord, session_id)
    if session is None:
        raise HTTPException(status_code=404, detail="Application session not found")
    if session.is_contained:
        raise HTTPException(status_code=403, detail="This application session has been contained.")
    return session


def _resource_response(path: str, session_header: str | None, db: Session) -> dict[str, object]:
    session = _session_or_401(db, session_header)
    if path not in REAL_RESOURCES and path not in DECOYS:
        raise HTTPException(status_code=404, detail="Protected resource not found")
    refresh_identity_override(db, session.identity_id)
    allow_decoy, reason = session_can_receive_decoy(session)
    if allow_decoy and path in DECOYS:
        resource = DECOYS[path]
        record_decoy_access(db, session=session, resource=resource.path)
        return {"route": "DECOY", "policy_reason": reason, "payload": decoy_payload(resource)}
    return {"route": "REAL", "policy_reason": reason, "resource": REAL_RESOURCES.get(path, {"title": path}), "content_exposed": False}


@router.get("/dashboard")
def dashboard(session_header: SessionHeader = None, db: Session = Depends(get_ready_db)) -> dict[str, object]:
    return _resource_response("/dashboard", session_header, db)


@router.get("/reports")
def reports(session_header: SessionHeader = None, db: Session = Depends(get_ready_db)) -> dict[str, object]:
    return _resource_response("/reports", session_header, db)


@router.get("/finance")
def finance(session_header: SessionHeader = None, db: Session = Depends(get_ready_db)) -> dict[str, object]:
    return _resource_response("/finance", session_header, db)


@router.get("/database/customers")
def customers(session_header: SessionHeader = None, db: Session = Depends(get_ready_db)) -> dict[str, object]:
    return _resource_response("/database/customers", session_header, db)


@router.get("/admin")
def admin(session_header: SessionHeader = None, db: Session = Depends(get_ready_db)) -> dict[str, object]:
    return _resource_response("/admin", session_header, db)


@router.get("/admin/users")
def admin_users(session_header: SessionHeader = None, db: Session = Depends(get_ready_db)) -> dict[str, object]:
    return _resource_response("/admin/users", session_header, db)


@router.get("/admin/credentials")
def admin_credentials(session_header: SessionHeader = None, db: Session = Depends(get_ready_db)) -> dict[str, object]:
    return _resource_response("/admin/credentials", session_header, db)


@router.post("/admin/credentials/attempt")
def credential_attempt(payload: HoneyCredentialAttempt, session_header: SessionHeader = None, db: Session = Depends(get_ready_db)) -> dict[str, object]:
    session = _session_or_401(db, session_header)
    refresh_identity_override(db, session.identity_id)
    try:
        contained = record_honey_credential_attempt(db, session=session, credential_id=payload.credential_id)
    except PermissionError as error:
        raise HTTPException(status_code=403, detail=str(error)) from error
    return {"route": "DECOY", "contained": True, "session_id": contained.id, "risk_score": contained.risk_score, "message": "Synthetic honey credential evidence contained this application session only."}


@router.get("/files/{path:path}")
def files(path: str, session_header: SessionHeader = None, db: Session = Depends(get_ready_db)) -> dict[str, object]:
    resource_path = f"/files/{path}".rstrip("/")
    return _resource_response(resource_path if resource_path in DECOYS else "/files/confidential", session_header, db)


@router.get("/export")
def export(session_header: SessionHeader = None, db: Session = Depends(get_ready_db)) -> dict[str, object]:
    return _resource_response("/export", session_header, db)
