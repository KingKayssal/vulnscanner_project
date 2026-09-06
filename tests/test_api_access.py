import os
from types import SimpleNamespace
from unittest.mock import patch

from fastapi.testclient import TestClient

from api.main import app


def test_unauthenticated_access_is_denied():
    with TestClient(app) as client:
        response = client.get("/scans/missing")
    assert response.status_code == 401


def test_cross_org_scan_is_not_found(monkeypatch):
    monkeypatch.setenv("SCANNER_API_KEY", "test-key")
    with patch("api.main.get_session") as get_session:
        session = get_session.return_value
        session.query.return_value.filter_by.return_value.first.side_effect = [
            SimpleNamespace(id="org-a"),
            None,
        ]
        with TestClient(app) as client:
            response = client.get(
                "/scans/scan-b",
                headers={"X-API-Key": "test-key", "X-Organization": "Org A"},
            )
    assert response.status_code == 404


def test_valid_org_scan_access_succeeds(monkeypatch):
    monkeypatch.setenv("SCANNER_API_KEY", "test-key")
    scan = SimpleNamespace(id="scan-a", status="completed", started_at=None, completed_at=None)
    with patch("api.main.get_session") as get_session:
        session = get_session.return_value
        session.query.return_value.filter_by.return_value.first.side_effect = [
            SimpleNamespace(id="org-a"), scan,
        ]
        session.query.return_value.filter_by.return_value.all.return_value = []
        with TestClient(app) as client:
            response = client.get(
                "/scans/scan-a",
                headers={"X-API-Key": "test-key", "X-Organization": "Org A"},
            )
    assert response.status_code == 200
    assert response.json()["id"] == "scan-a"