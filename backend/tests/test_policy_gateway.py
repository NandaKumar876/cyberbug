from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)


def test_contained_session_cannot_access_controlled_application() -> None:
    response = client.get("/admin/credentials", headers={"X-CyberBug-Session": "SES-A817"})
    assert response.status_code == 403


def test_legitimate_override_never_receives_decoy() -> None:
    response = client.get("/admin/credentials", headers={"X-CyberBug-Session": "SES-B208"})
    assert response.status_code == 200
    assert response.json()["route"] == "REAL"
