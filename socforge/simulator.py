from __future__ import annotations

import random
from datetime import datetime, timedelta, timezone
from typing import Any

ASSETS = ["soc-win-01", "soc-linux-02", "web-demo-01", "db-demo-01", "workstation-07"]
USERS = ["analyst.demo", "service.reader", "operator.demo", "admin.demo"]
IPS = ["192.0.2.10", "192.0.2.25", "198.51.100.18", "203.0.113.7"]  # RFC 5737 documentation ranges


def generate_demo_events(seed: int = 41) -> list[dict[str, Any]]:
    """Generate benign, clearly labelled training events; no real attack traffic is created."""
    rng = random.Random(seed)
    now = datetime.now(timezone.utc)
    events: list[dict[str, Any]] = []

    for index in range(12):
        events.append({
            "timestamp": (now - timedelta(minutes=12 - index)).isoformat(),
            "source": "socforge-simulator", "event_type": "authentication_success", "severity": "info",
            "host": rng.choice(ASSETS), "src_ip": rng.choice(IPS), "username": rng.choice(USERS),
            "message": "Synthetic successful authentication event.", "attributes": {"simulation": True, "label": "benign"},
        })

    # A controlled sequence of synthetic failed-authentication events for one lab identity.
    for index in range(6):
        events.append({
            "timestamp": (now - timedelta(minutes=4) + timedelta(seconds=index * 20)).isoformat(),
            "source": "socforge-simulator", "event_type": "authentication_failure", "severity": "low",
            "host": "soc-win-01", "src_ip": "192.0.2.44", "username": "demo.user",
            "message": "Synthetic failed authentication event for threshold validation.",
            "attributes": {"simulation": True, "label": "controlled-test-case"},
        })

    events.extend([
        {"timestamp": now.isoformat(), "source": "socforge-simulator", "event_type": "network_alert", "severity": "high", "host": "edge-sensor-01", "src_ip": "198.51.100.18", "dst_ip": "192.0.2.80", "message": "Synthetic IDS alert: lab policy test signature matched.", "attributes": {"simulation": True, "label": "controlled-test-case"}},
        {"timestamp": now.isoformat(), "source": "socforge-simulator", "event_type": "edr_health", "severity": "high", "host": "workstation-07", "message": "Synthetic endpoint agent health status: service stopped in test fixture.", "attributes": {"simulation": True, "label": "controlled-test-case"}},
        {"timestamp": now.isoformat(), "source": "socforge-simulator", "event_type": "privilege_change", "severity": "medium", "host": "soc-linux-02", "username": "demo.admin", "message": "Synthetic privileged group membership change for review.", "attributes": {"simulation": True, "label": "controlled-test-case"}},
        {"timestamp": now.isoformat(), "source": "socforge-simulator", "event_type": "file_integrity_change", "severity": "medium", "host": "db-demo-01", "process": "/usr/bin/package-manager", "message": "Synthetic monitored configuration file change.", "attributes": {"simulation": True, "label": "controlled-test-case"}},
        {"timestamp": now.isoformat(), "source": "socforge-simulator", "event_type": "vulnerability", "severity": "critical", "host": "web-demo-01", "cvss": 9.1, "message": "Synthetic critical vulnerability fixture; not an actual CVE or scan result.", "attributes": {"simulation": True, "label": "controlled-test-case"}},
    ])
    return events
