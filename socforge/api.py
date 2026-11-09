from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from fastapi import FastAPI, Header, HTTPException, Query, Request
from fastapi.responses import HTMLResponse
from pydantic import ValidationError

from .audit import verify_audit_chain
from .config import settings
from .db import connect, init_db
from .detections import RULES
from .normalizer import normalize_suricata, normalize_sysmon, normalize_wazuh
from .schemas import AlertAction, EventIn, IncidentCreate, IncidentStatusUpdate, VulnerabilityIn, VulnerabilityStatusUpdate
from .security import verify_payload
from .service import (create_incident, create_vulnerability, ingest_event, list_alerts, list_incidents,
                      list_vulnerabilities, summary, update_alert, update_incident, update_vulnerability)


def create_app(db_path: str | None = None, hmac_secret: str | None = None, require_signatures: bool | None = None) -> FastAPI:
    resolved_db = db_path or settings.db_path
    secret = hmac_secret or settings.hmac_secret
    require_sig = settings.require_signatures if require_signatures is None else require_signatures
    init_db(resolved_db)
    app = FastAPI(title="SOCForge API", version="1.0.0", description="Defensive SOC lab for telemetry, transparent detections, alert triage and incident tracking.")
    app.state.db_path = resolved_db

    def check_signature(raw: bytes, signature: str | None) -> bool:
        valid = verify_payload(raw, signature, secret)
        if require_sig and not valid:
            raise HTTPException(status_code=401, detail="Missing or invalid X-SOCForge-Signature. Sign the exact request body with HMAC-SHA256.")
        return valid

    @app.get("/", response_class=HTMLResponse)
    def root() -> str:
        return "<h2>SOCForge API</h2><p>Open <a href='/dashboard'>/dashboard</a> or <a href='/docs'>/docs</a>.</p>"

    @app.get("/dashboard", response_class=HTMLResponse)
    def dashboard() -> str:
        path = Path(__file__).with_name("dashboard.html")
        return path.read_text(encoding="utf-8")

    @app.get("/api/health")
    def health() -> dict[str, str]:
        return {"status": "ok", "service": "socforge", "version": "1.0.0"}

    @app.get("/api/rules")
    def rules() -> list[dict[str, Any]]:
        return RULES

    @app.get("/api/summary")
    def get_summary() -> dict[str, Any]:
        return summary(resolved_db)

    @app.post("/api/events")
    async def post_event(request: Request, x_socforge_signature: str | None = Header(default=None)) -> dict[str, Any]:
        raw = await request.body()
        signature_valid = check_signature(raw, x_socforge_signature)
        try:
            payload = EventIn.model_validate_json(raw)
        except ValidationError as exc:
            raise HTTPException(status_code=422, detail=exc.errors()) from exc
        return ingest_event(payload, signature_valid, resolved_db)

    @app.post("/api/adapters/wazuh")
    async def wazuh_adapter(request: Request, x_socforge_signature: str | None = Header(default=None)) -> dict[str, Any]:
        raw = await request.body()
        signature_valid = check_signature(raw, x_socforge_signature)
        try:
            normal = normalize_wazuh(json.loads(raw))
            payload = EventIn.model_validate(normal)
        except (ValueError, TypeError, ValidationError) as exc:
            raise HTTPException(status_code=422, detail=f"Invalid Wazuh JSON: {exc}") from exc
        return ingest_event(payload, signature_valid, resolved_db)

    @app.post("/api/adapters/suricata")
    async def suricata_adapter(request: Request, x_socforge_signature: str | None = Header(default=None)) -> dict[str, Any]:
        raw = await request.body()
        signature_valid = check_signature(raw, x_socforge_signature)
        try:
            normal = normalize_suricata(json.loads(raw))
            payload = EventIn.model_validate(normal)
        except (ValueError, TypeError, ValidationError) as exc:
            raise HTTPException(status_code=422, detail=f"Invalid Suricata JSON: {exc}") from exc
        return ingest_event(payload, signature_valid, resolved_db)

    @app.post("/api/adapters/sysmon")
    async def sysmon_adapter(request: Request, x_socforge_signature: str | None = Header(default=None)) -> dict[str, Any]:
        raw = await request.body()
        signature_valid = check_signature(raw, x_socforge_signature)
        try:
            normal = normalize_sysmon(json.loads(raw))
            payload = EventIn.model_validate(normal)
        except (ValueError, TypeError, ValidationError) as exc:
            raise HTTPException(status_code=422, detail=f"Invalid Sysmon JSON: {exc}") from exc
        return ingest_event(payload, signature_valid, resolved_db)

    @app.get("/api/events")
    def get_events(limit: int = Query(100, ge=1, le=500)) -> list[dict[str, Any]]:
        conn = connect(resolved_db)
        try:
            rows = conn.execute("SELECT * FROM events ORDER BY event_time DESC LIMIT ?", (limit,)).fetchall()
            result = []
            for row in rows:
                item = dict(row)
                item["attributes"] = json.loads(item.pop("attributes_json") or "{}")
                item["signature_valid"] = bool(item["signature_valid"])
                result.append(item)
            return result
        finally:
            conn.close()

    @app.get("/api/alerts")
    def get_alerts(status: str | None = None, limit: int = Query(100, ge=1, le=500)) -> list[dict[str, Any]]:
        return list_alerts(resolved_db, status, limit)

    @app.post("/api/alerts/{alert_id}/acknowledge")
    def acknowledge_alert(alert_id: int, payload: AlertAction) -> dict[str, Any]:
        result = update_alert(alert_id, "acknowledged", payload.actor, payload.note, resolved_db)
        if result is None:
            raise HTTPException(status_code=404, detail="Alert not found")
        return result

    @app.post("/api/alerts/{alert_id}/investigate")
    def investigate_alert(alert_id: int, payload: AlertAction) -> dict[str, Any]:
        result = update_alert(alert_id, "investigating", payload.actor, payload.note, resolved_db)
        if result is None:
            raise HTTPException(status_code=404, detail="Alert not found")
        return result

    @app.post("/api/alerts/{alert_id}/resolve")
    def resolve_alert(alert_id: int, payload: AlertAction) -> dict[str, Any]:
        if not payload.note.strip():
            raise HTTPException(status_code=400, detail="A resolution note is required for auditability.")
        result = update_alert(alert_id, "resolved", payload.actor, payload.note, resolved_db)
        if result is None:
            raise HTTPException(status_code=404, detail="Alert not found")
        return result

    @app.get("/api/incidents")
    def get_incidents(limit: int = Query(100, ge=1, le=500)) -> list[dict[str, Any]]:
        return list_incidents(resolved_db, limit)

    @app.post("/api/incidents")
    def post_incident(payload: IncidentCreate) -> dict[str, Any]:
        return create_incident(payload.model_dump(), resolved_db)

    @app.post("/api/incidents/{incident_id}/status")
    def set_incident_status(incident_id: int, payload: IncidentStatusUpdate) -> dict[str, Any]:
        result = update_incident(incident_id, payload.status, payload.actor, payload.note, resolved_db)
        if result is None:
            raise HTTPException(status_code=404, detail="Incident not found")
        return result

    @app.get("/api/vulnerabilities")
    def get_vulnerabilities(limit: int = Query(100, ge=1, le=500)) -> list[dict[str, Any]]:
        return list_vulnerabilities(resolved_db, limit)

    @app.post("/api/vulnerabilities")
    def post_vulnerability(payload: VulnerabilityIn) -> dict[str, Any]:
        return create_vulnerability(payload.model_dump(), resolved_db)

    @app.post("/api/vulnerabilities/{vulnerability_id}/status")
    def set_vulnerability_status(vulnerability_id: int, payload: VulnerabilityStatusUpdate) -> dict[str, Any]:
        result = update_vulnerability(vulnerability_id, payload.status, payload.actor, payload.note, resolved_db)
        if result is None:
            raise HTTPException(status_code=404, detail="Vulnerability not found")
        return result

    @app.get("/api/audit/verify")
    def audit_verify() -> dict[str, Any]:
        return verify_audit_chain(resolved_db)

    return app


app = create_app()
