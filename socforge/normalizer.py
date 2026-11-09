from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

SEVERITY_MAP = {"1": "critical", "2": "high", "3": "medium", "4": "low", "5": "info"}


def _to_iso(value: Any) -> str:
    if not value:
        return datetime.now(timezone.utc).isoformat()
    if isinstance(value, (int, float)):
        return datetime.fromtimestamp(value, timezone.utc).isoformat()
    text = str(value)
    try:
        dt = datetime.fromisoformat(text.replace("Z", "+00:00"))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.isoformat()
    except ValueError:
        return datetime.now(timezone.utc).isoformat()


def normalize_wazuh(raw: dict[str, Any]) -> dict[str, Any]:
    rule = raw.get("rule") or {}
    agent = raw.get("agent") or {}
    data = raw.get("data") or {}
    level = rule.get("level", 3)
    severity = "critical" if int(level or 0) >= 14 else "high" if int(level or 0) >= 10 else "medium" if int(level or 0) >= 7 else "low" if int(level or 0) >= 4 else "info"
    return {
        "timestamp": _to_iso(raw.get("timestamp")),
        "source": "wazuh",
        "event_type": data.get("event_type") or "wazuh_alert",
        "severity": severity,
        "host": (agent.get("name") or raw.get("location")),
        "src_ip": data.get("srcip") or data.get("src_ip"),
        "dst_ip": data.get("dstip") or data.get("dst_ip"),
        "username": data.get("srcuser") or data.get("user") or data.get("dstuser"),
        "process": data.get("process") or data.get("win", {}).get("eventdata", {}).get("image"),
        "message": rule.get("description") or "Wazuh security alert",
        "attributes": {"rule_id": rule.get("id"), "rule_level": level, "groups": rule.get("groups", []), "mitre": rule.get("mitre", {})},
    }


def normalize_suricata(raw: dict[str, Any]) -> dict[str, Any]:
    alert = raw.get("alert") or {}
    event_type = raw.get("event_type") or "unknown"
    if event_type == "alert":
        severity = SEVERITY_MAP.get(str(alert.get("severity", "3")), "medium")
        normalized_type = "network_alert"
    else:
        severity = "info"
        normalized_type = f"suricata_{event_type}"
    return {
        "timestamp": _to_iso(raw.get("timestamp")),
        "source": "suricata",
        "event_type": normalized_type,
        "severity": severity,
        "host": raw.get("host") or raw.get("in_iface"),
        "src_ip": raw.get("src_ip"),
        "dst_ip": raw.get("dest_ip"),
        "username": None,
        "process": None,
        "message": alert.get("signature") or f"Suricata {event_type} event",
        "attributes": {"signature_id": alert.get("signature_id"), "category": alert.get("category"), "flow_id": raw.get("flow_id"), "proto": raw.get("proto")},
    }


def normalize_sysmon(raw: dict[str, Any]) -> dict[str, Any]:
    event_id = str(raw.get("EventID") or raw.get("event_id") or "")
    eventdata = raw.get("EventData") or raw.get("eventdata") or {}
    mapping = {1: "process_start", 3: "network_connection", 11: "file_integrity_change", 13: "registry_change"}
    return {
        "timestamp": _to_iso(raw.get("UtcTime") or raw.get("timestamp")),
        "source": "sysmon",
        "event_type": mapping.get(int(event_id), "sysmon_event") if event_id.isdigit() else "sysmon_event",
        "severity": "info",
        "host": raw.get("Computer") or raw.get("host"),
        "src_ip": eventdata.get("SourceIp") or eventdata.get("SourceAddress"),
        "dst_ip": eventdata.get("DestinationIp") or eventdata.get("DestinationIp"),
        "username": eventdata.get("User"),
        "process": eventdata.get("Image") or eventdata.get("TargetFilename"),
        "message": raw.get("Message") or f"Sysmon event {event_id}",
        "attributes": {"event_id": event_id, "event_data": eventdata},
    }
