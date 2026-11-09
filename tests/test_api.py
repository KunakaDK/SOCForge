import json
from fastapi.testclient import TestClient

from socforge.api import create_app
from socforge.security import sign_payload


def signed_post(client, path, payload, secret):
    raw = json.dumps(payload, separators=(",", ":")).encode()
    return client.post(path, content=raw, headers={"Content-Type": "application/json", "X-SOCForge-Signature": sign_payload(raw, secret)})


def test_api_ingests_events_creates_alert_and_tracks_case(tmp_path):
    secret = "test-secret"
    app = create_app(str(tmp_path / "api.db"), secret, True)
    client = TestClient(app)
    for n in range(5):
        payload = {
            "event_type": "authentication_failure", "source": "test", "severity": "low",
            "src_ip": "192.0.2.99", "username": "lab.user", "message": "synthetic failed login"
        }
        response = signed_post(client, "/api/events", payload, secret)
        assert response.status_code == 200
    alerts = client.get("/api/alerts").json()
    assert len(alerts) == 1
    alert_id = alerts[0]["id"]
    acknowledged = client.post(f"/api/alerts/{alert_id}/acknowledge", json={"actor": "tester", "note": "Reviewed in test."})
    assert acknowledged.status_code == 200
    incident = client.post("/api/incidents", json={"title": "Test incident", "severity": "high", "description": "Synthetic test case", "alert_ids": [alert_id]})
    assert incident.status_code == 200
    assert client.get("/api/audit/verify").json()["valid"] is True


def test_api_rejects_unsigned_event(tmp_path):
    app = create_app(str(tmp_path / "api.db"), "test-secret", True)
    client = TestClient(app)
    response = client.post("/api/events", json={"event_type": "authentication_success"})
    assert response.status_code == 401


def test_wazuh_adapter_normalizes_and_ingests(tmp_path):
    secret = "adapter-secret"
    app = create_app(str(tmp_path / "wazuh.db"), secret, True)
    client = TestClient(app)
    payload = {
        "timestamp": "2026-11-09T10:15:00Z",
        "rule": {"id": "5710", "level": 10, "description": "Synthetic failed authentication", "groups": ["authentication_failed"]},
        "agent": {"id": "007", "name": "demo-linux-01"},
        "data": {"srcip": "192.0.2.44", "srcuser": "training.user", "event_type": "authentication_failure"},
    }
    response = signed_post(client, "/api/adapters/wazuh", payload, secret)
    assert response.status_code == 200
    events = client.get("/api/events").json()
    assert events[0]["source"] == "wazuh"
    assert events[0]["host"] == "demo-linux-01"


def test_vulnerability_workflow_uses_cvss_band_and_audit(tmp_path):
    app = create_app(str(tmp_path / "vuln.db"), "unused", False)
    client = TestClient(app)
    response = client.post("/api/vulnerabilities", json={
        "asset": "demo-web", "cve": "CVE-2099-0001", "title": "Synthetic dependency finding",
        "cvss": 9.1, "package": "demo-package", "remediation": "Upgrade the test package."
    })
    assert response.status_code == 200
    finding = response.json()
    assert finding["severity"] == "critical"
    updated = client.post(f"/api/vulnerabilities/{finding['id']}/status", json={"status": "remediated", "note": "Verified in synthetic test."})
    assert updated.status_code == 200
    assert updated.json()["status"] == "remediated"
    assert client.get("/api/audit/verify").json()["valid"] is True


def test_suricata_and_sysmon_adapters(tmp_path):
    secret = "multi-adapter-secret"
    app = create_app(str(tmp_path / "multi.db"), secret, True)
    client = TestClient(app)
    suricata = {
        "timestamp": "2026-11-09T10:20:00Z", "event_type": "alert", "src_ip": "198.51.100.18",
        "dest_ip": "192.0.2.80", "proto": "TCP", "alert": {"signature_id": 900001, "signature": "Synthetic lab alert", "severity": 2}
    }
    sysmon = {
        "UtcTime": "2026-11-09T10:25:00Z", "EventID": 11, "Computer": "demo-windows-01",
        "EventData": {"TargetFilename": "C:\\Training\\config.ini", "Image": "notepad.exe", "User": "LAB\\training.user"}
    }
    r1 = signed_post(client, "/api/adapters/suricata", suricata, secret)
    r2 = signed_post(client, "/api/adapters/sysmon", sysmon, secret)
    assert r1.status_code == 200
    assert r2.status_code == 200
    sources = {e["source"] for e in client.get("/api/events").json()}
    assert {"suricata", "sysmon"}.issubset(sources)
    assert len(client.get("/api/alerts").json()) >= 2
