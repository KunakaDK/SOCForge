from __future__ import annotations

from collections import defaultdict
from datetime import datetime, timedelta, timezone
from typing import Any

RULES = [
    {"id": "SF-AUTH-001", "name": "Repeated authentication failures", "severity": "high", "description": "Five or more failed authentication events from the same source within ten minutes.", "mitre_tactic": "Credential Access", "mitre_technique": "T1110", "confidence": 0.85},
    {"id": "SF-NET-001", "name": "High-severity network IDS alert", "severity": "high", "description": "A high or critical network IDS event requires analyst review.", "mitre_tactic": "Command and Control / Discovery", "mitre_technique": "T1046", "confidence": 0.75},
    {"id": "SF-END-001", "name": "Endpoint protection disabled", "severity": "high", "description": "Endpoint protection health telemetry reports a disabled or unhealthy sensor.", "mitre_tactic": "Defense Evasion", "mitre_technique": "T1562", "confidence": 0.9},
    {"id": "SF-PRIV-001", "name": "Privileged account change", "severity": "medium", "description": "A privileged group or role membership change requires validation.", "mitre_tactic": "Privilege Escalation", "mitre_technique": "T1098", "confidence": 0.7},
    {"id": "SF-FIM-001", "name": "File integrity change", "severity": "medium", "description": "A monitored file integrity change was reported.", "mitre_tactic": "Defense Evasion", "mitre_technique": "T1565", "confidence": 0.65},
    {"id": "SF-VULN-001", "name": "Critical vulnerability finding", "severity": "critical", "description": "A vulnerability with CVSS 9.0 or higher requires prioritised assessment.", "mitre_tactic": "Initial Access", "mitre_technique": "T1190", "confidence": 0.95},
]


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def evaluate_event(event: dict[str, Any], recent_events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Evaluate one normalized event. Rules are intentionally transparent and defensive."""
    event_type = (event.get("event_type") or "").lower()
    emitted: list[dict[str, Any]] = []

    if event_type in {"authentication_failure", "failed_auth", "login_failure"}:
        src_ip = event.get("src_ip") or "unknown-source"
        timestamp = datetime.fromisoformat(event["event_time"].replace("Z", "+00:00")) if event.get("event_time") else _utc_now()
        cutoff = timestamp - timedelta(minutes=10)
        matching = []
        for candidate in recent_events:
            if (candidate.get("event_type") or "").lower() not in {"authentication_failure", "failed_auth", "login_failure"}:
                continue
            if (candidate.get("src_ip") or "unknown-source") != src_ip:
                continue
            t = datetime.fromisoformat(candidate["event_time"].replace("Z", "+00:00"))
            if cutoff <= t <= timestamp:
                matching.append(candidate)
        if len(matching) >= 5:
            rule = RULES[0]
            emitted.append(_alert(rule, f"Repeated authentication failures from {src_ip}", f"Observed {len(matching)} failed authentication events from {src_ip} in a ten-minute window.", [x["id"] for x in matching], {"src_ip": src_ip, "username": event.get("username")}))

    if event_type in {"network_alert", "suricata_alert", "ids_alert"} and event.get("severity") in {"high", "critical"}:
        rule = RULES[1]
        emitted.append(_alert(rule, "High-severity network IDS alert", event.get("message") or "A network IDS event requires analyst review.", [event["id"]], {"src_ip": event.get("src_ip"), "dst_ip": event.get("dst_ip"), "host": event.get("host")}))

    if event_type in {"edr_health", "endpoint_protection_status"} and any(x in (event.get("message") or "").lower() for x in ("disabled", "stopped", "unhealthy", "not running")):
        rule = RULES[2]
        emitted.append(_alert(rule, "Endpoint protection health issue", event.get("message") or "Endpoint protection requires review.", [event["id"]], {"host": event.get("host")}))

    if event_type in {"privilege_change", "privileged_group_change", "role_membership_change"}:
        rule = RULES[3]
        emitted.append(_alert(rule, "Privileged account or role change", event.get("message") or "A privileged access change requires validation.", [event["id"]], {"host": event.get("host"), "username": event.get("username")}))

    if event_type in {"file_integrity_change", "fim_change"}:
        rule = RULES[4]
        emitted.append(_alert(rule, "Monitored file integrity change", event.get("message") or "A monitored file changed.", [event["id"]], {"host": event.get("host"), "process": event.get("process")}))

    if event_type in {"vulnerability", "vulnerability_finding"} and (event.get("cvss") or 0) >= 9.0:
        rule = RULES[5]
        emitted.append(_alert(rule, "Critical vulnerability finding", event.get("message") or f"Critical vulnerability on {event.get('host') or 'an asset'}.", [event["id"]], {"host": event.get("host"), "cvss": event.get("cvss")}))

    return emitted


def _alert(rule: dict[str, Any], title: str, summary: str, event_ids: list[int], entities: dict[str, Any]) -> dict[str, Any]:
    return {
        "rule_id": rule["id"],
        "title": title,
        "severity": rule["severity"],
        "summary": summary,
        "event_ids": sorted(set(event_ids)),
        "entities": {k: v for k, v in entities.items() if v is not None},
        "mitre_tactic": rule["mitre_tactic"],
        "mitre_technique": rule["mitre_technique"],
        "confidence": rule["confidence"],
    }
