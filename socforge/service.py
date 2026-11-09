from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from typing import Any

from .audit import append_audit
from .db import connect
from .detections import evaluate_event
from .schemas import EventIn


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), default=str)


def ingest_event(event: EventIn, signature_valid: bool, db_path: str) -> dict[str, Any]:
    event_time = event.timestamp.astimezone(timezone.utc).isoformat()
    conn = connect(db_path)
    try:
        cur = conn.execute(
            """INSERT INTO events(external_id,event_time,ingested_at,source,event_type,severity,host,src_ip,dst_ip,username,process,message,cvss,attributes_json,signature_valid)
               VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (event.external_id, event_time, _now(), event.source, event.event_type, event.severity, event.host, event.src_ip, event.dst_ip,
             event.username, event.process, event.message, event.cvss, _json(event.attributes), int(signature_valid)),
        )
        event_id = cur.lastrowid
        current = {
            "id": event_id, "event_time": event_time, "source": event.source, "event_type": event.event_type,
            "severity": event.severity, "host": event.host, "src_ip": event.src_ip, "dst_ip": event.dst_ip,
            "username": event.username, "process": event.process, "message": event.message, "cvss": event.cvss,
        }
        recent: list[dict[str, Any]] = [current]
        if event.event_type.lower() in {"authentication_failure", "failed_auth", "login_failure"}:
            cutoff = (event.timestamp.astimezone(timezone.utc) - timedelta(minutes=10)).isoformat()
            rows = conn.execute(
                "SELECT id,event_time,event_type,src_ip,username,message FROM events WHERE event_time>=? AND src_ip IS ? AND event_type IN ('authentication_failure','failed_auth','login_failure') ORDER BY event_time DESC LIMIT 100",
                (cutoff, event.src_ip),
            ).fetchall()
            recent = [dict(r) for r in rows]
        candidates = evaluate_event(current, recent)
        created_alerts = []
        for candidate in candidates:
            entity_key = _json(candidate["entities"])
            # Suppress repeated open alerts for the same rule and entity for 15 minutes.
            existing = conn.execute(
                "SELECT id,entities_json,created_at FROM alerts WHERE rule_id=? AND status IN ('open','acknowledged','investigating') ORDER BY id DESC LIMIT 20",
                (candidate["rule_id"],),
            ).fetchall()
            duplicate = False
            for row in existing:
                try:
                    same_entities = json.loads(row["entities_json"]) == candidate["entities"]
                    created = datetime.fromisoformat(row["created_at"])
                    age = datetime.now(timezone.utc) - created.astimezone(timezone.utc)
                    if same_entities and age <= timedelta(minutes=15):
                        duplicate = True
                        break
                except (ValueError, TypeError):
                    continue
            if duplicate:
                continue
            timestamp = _now()
            alert_cur = conn.execute(
                """INSERT INTO alerts(rule_id,title,severity,status,summary,created_at,updated_at,event_ids_json,entities_json,mitre_tactic,mitre_technique,confidence,notes)
                   VALUES(?,?,?,'open',?,?,?,?,?,?,?,?, '')""",
                (candidate["rule_id"], candidate["title"], candidate["severity"], candidate["summary"], timestamp, timestamp,
                 _json(candidate["event_ids"]), entity_key, candidate["mitre_tactic"], candidate["mitre_technique"], candidate["confidence"]),
            )
            created_alerts.append({"id": alert_cur.lastrowid, **candidate, "status": "open", "created_at": timestamp})
        conn.commit()
    finally:
        conn.close()

    append_audit("telemetry-ingestor", "event.ingested", "event", str(event_id), {"source": event.source, "event_type": event.event_type, "signature_valid": signature_valid}, db_path)
    for alert in created_alerts:
        append_audit("detection-engine", "alert.created", "alert", str(alert["id"]), {"rule_id": alert["rule_id"], "severity": alert["severity"]}, db_path)
    return {"event_id": event_id, "signature_valid": signature_valid, "alerts_created": created_alerts}


def _row_alert(row: Any) -> dict[str, Any]:
    item = dict(row)
    item["event_ids"] = json.loads(item.pop("event_ids_json") or "[]")
    item["entities"] = json.loads(item.pop("entities_json") or "{}")
    return item


def list_alerts(db_path: str, status: str | None = None, limit: int = 100) -> list[dict[str, Any]]:
    conn = connect(db_path)
    try:
        if status:
            rows = conn.execute("SELECT * FROM alerts WHERE status=? ORDER BY created_at DESC LIMIT ?", (status, limit)).fetchall()
        else:
            rows = conn.execute("SELECT * FROM alerts ORDER BY created_at DESC LIMIT ?", (limit,)).fetchall()
        return [_row_alert(r) for r in rows]
    finally:
        conn.close()


def update_alert(alert_id: int, status: str, actor: str, note: str, db_path: str) -> dict[str, Any] | None:
    allowed = {"acknowledged", "investigating", "resolved"}
    if status not in allowed:
        raise ValueError("Unsupported alert status")
    conn = connect(db_path)
    try:
        row = conn.execute("SELECT * FROM alerts WHERE id=?", (alert_id,)).fetchone()
        if not row:
            return None
        old_notes = row["notes"] or ""
        note_entry = f"[{_now()}] {actor}: {note}".strip()
        new_notes = (old_notes + "\n" + note_entry).strip()
        conn.execute("UPDATE alerts SET status=?,updated_at=?,notes=? WHERE id=?", (status, _now(), new_notes, alert_id))
        conn.commit()
        updated = conn.execute("SELECT * FROM alerts WHERE id=?", (alert_id,)).fetchone()
        result = _row_alert(updated)
    finally:
        conn.close()
    append_audit(actor, f"alert.{status}", "alert", str(alert_id), {"note": note}, db_path)
    return result


def create_incident(payload: dict[str, Any], db_path: str) -> dict[str, Any]:
    timestamp = _now()
    conn = connect(db_path)
    try:
        cur = conn.execute(
            "INSERT INTO incidents(title,severity,status,description,owner,created_at,updated_at,alert_ids_json) VALUES(?,?, 'open',?,?,?,?,?)",
            (payload["title"], payload["severity"], payload["description"], payload["owner"], timestamp, timestamp, _json(payload["alert_ids"])),
        )
        incident_id = cur.lastrowid
        row = conn.execute("SELECT * FROM incidents WHERE id=?", (incident_id,)).fetchone()
        result = dict(row)
        result["alert_ids"] = json.loads(result.pop("alert_ids_json"))
    finally:
        conn.close()
    append_audit(payload.get("actor", "soc-analyst"), "incident.created", "incident", str(incident_id), {"alert_ids": payload["alert_ids"]}, db_path)
    return result


def list_incidents(db_path: str, limit: int = 100) -> list[dict[str, Any]]:
    conn = connect(db_path)
    try:
        rows = conn.execute("SELECT * FROM incidents ORDER BY created_at DESC LIMIT ?", (limit,)).fetchall()
        result = []
        for row in rows:
            item = dict(row)
            item["alert_ids"] = json.loads(item.pop("alert_ids_json") or "[]")
            result.append(item)
        return result
    finally:
        conn.close()


def update_incident(incident_id: int, status: str, actor: str, note: str, db_path: str) -> dict[str, Any] | None:
    conn = connect(db_path)
    try:
        row = conn.execute("SELECT * FROM incidents WHERE id=?", (incident_id,)).fetchone()
        if not row:
            return None
        description = row["description"]
        if note:
            description = (description + f"\n\n[{_now()}] {actor}: {note}").strip()
        conn.execute("UPDATE incidents SET status=?,description=?,updated_at=? WHERE id=?", (status, description, _now(), incident_id))
        conn.commit()
        updated = dict(conn.execute("SELECT * FROM incidents WHERE id=?", (incident_id,)).fetchone())
        updated["alert_ids"] = json.loads(updated.pop("alert_ids_json") or "[]")
    finally:
        conn.close()
    append_audit(actor, f"incident.{status}", "incident", str(incident_id), {"note": note}, db_path)
    return updated


def create_vulnerability(payload: dict[str, Any], db_path: str) -> dict[str, Any]:
    cvss = payload["cvss"]
    severity = "critical" if cvss >= 9 else "high" if cvss >= 7 else "medium" if cvss >= 4 else "low"
    timestamp = _now()
    conn = connect(db_path)
    try:
        cur = conn.execute(
            "INSERT INTO vulnerabilities(asset,cve,title,cvss,severity,package,status,remediation,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?)",
            (payload["asset"], payload.get("cve"), payload["title"], cvss, severity, payload.get("package"), payload["status"], payload["remediation"], timestamp, timestamp),
        )
        vuln_id = cur.lastrowid
        row = dict(conn.execute("SELECT * FROM vulnerabilities WHERE id=?", (vuln_id,)).fetchone())
        conn.commit()
    finally:
        conn.close()
    append_audit(payload.get("actor", "vulnerability-analyst"), "vulnerability.created", "vulnerability", str(vuln_id), {"asset": payload["asset"], "cvss": cvss}, db_path)
    return row


def list_vulnerabilities(db_path: str, limit: int = 100) -> list[dict[str, Any]]:
    conn = connect(db_path)
    try:
        return [dict(r) for r in conn.execute("SELECT * FROM vulnerabilities ORDER BY cvss DESC,created_at DESC LIMIT ?", (limit,)).fetchall()]
    finally:
        conn.close()


def update_vulnerability(vuln_id: int, status: str, actor: str, note: str, db_path: str) -> dict[str, Any] | None:
    conn = connect(db_path)
    try:
        row = conn.execute("SELECT * FROM vulnerabilities WHERE id=?", (vuln_id,)).fetchone()
        if not row:
            return None
        remediation = row["remediation"]
        if note:
            remediation = (remediation + f"\n[{_now()}] {actor}: {note}").strip()
        conn.execute("UPDATE vulnerabilities SET status=?,remediation=?,updated_at=? WHERE id=?", (status, remediation, _now(), vuln_id))
        conn.commit()
        result = dict(conn.execute("SELECT * FROM vulnerabilities WHERE id=?", (vuln_id,)).fetchone())
    finally:
        conn.close()
    append_audit(actor, f"vulnerability.{status}", "vulnerability", str(vuln_id), {"note": note}, db_path)
    return result


def summary(db_path: str) -> dict[str, Any]:
    conn = connect(db_path)
    try:
        def scalar(sql: str) -> int:
            return int(conn.execute(sql).fetchone()[0])
        alert_counts = {r["severity"]: r["n"] for r in conn.execute("SELECT severity,COUNT(*) AS n FROM alerts WHERE status!='resolved' GROUP BY severity").fetchall()}
        return {
            "events_total": scalar("SELECT COUNT(*) FROM events"),
            "alerts_open": scalar("SELECT COUNT(*) FROM alerts WHERE status IN ('open','acknowledged','investigating')"),
            "incidents_open": scalar("SELECT COUNT(*) FROM incidents WHERE status NOT IN ('resolved','closed')"),
            "vulnerabilities_open": scalar("SELECT COUNT(*) FROM vulnerabilities WHERE status IN ('open','in_progress')"),
            "alerts_by_severity": alert_counts,
        }
    finally:
        conn.close()
