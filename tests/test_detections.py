from datetime import datetime, timedelta, timezone

from socforge.detections import evaluate_event


def make_event(i, event_type="authentication_failure", src_ip="192.0.2.44"):
    return {
        "id": i,
        "event_time": (datetime.now(timezone.utc) - timedelta(seconds=(6-i)*30)).isoformat(),
        "event_type": event_type,
        "severity": "low",
        "src_ip": src_ip,
        "username": "demo.user",
        "message": "synthetic test event",
    }


def test_repeated_auth_failures_trigger_rule():
    events = [make_event(i) for i in range(1, 6)]
    result = evaluate_event(events[-1], events)
    assert len(result) == 1
    assert result[0]["rule_id"] == "SF-AUTH-001"
    assert result[0]["mitre_technique"] == "T1110"


def test_low_severity_network_event_does_not_trigger_high_alert():
    event = make_event(1, "network_alert")
    event["severity"] = "low"
    assert evaluate_event(event, [event]) == []


def test_critical_vulnerability_triggers_alert():
    event = make_event(1, "vulnerability")
    event["cvss"] = 9.2
    event["host"] = "demo-web"
    result = evaluate_event(event, [event])
    assert result[0]["rule_id"] == "SF-VULN-001"
    assert result[0]["severity"] == "critical"
