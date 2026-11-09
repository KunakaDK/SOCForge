#!/usr/bin/env python3
"""Send a JSONL sample file to a SOCForge adapter using the configured HMAC secret."""
from __future__ import annotations

import argparse
import json
import os
import sys
import urllib.error
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from socforge.config import settings  # noqa: E402
from socforge.security import sign_payload  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("input", help="Path to a JSONL file")
    parser.add_argument("--adapter", choices=["canonical", "wazuh", "suricata", "sysmon"], default="canonical")
    parser.add_argument("--api-url", default="http://127.0.0.1:8000")
    args = parser.parse_args()
    endpoint = {"canonical": "/api/events", "wazuh": "/api/adapters/wazuh", "suricata": "/api/adapters/suricata", "sysmon": "/api/adapters/sysmon"}[args.adapter]
    sent = 0
    for line_number, line in enumerate(Path(args.input).read_text(encoding="utf-8").splitlines(), start=1):
        if not line.strip():
            continue
        try:
            payload = json.loads(line)
        except json.JSONDecodeError as exc:
            raise SystemExit(f"Invalid JSON on line {line_number}: {exc}")
        raw = json.dumps(payload, separators=(",", ":")).encode("utf-8")
        signature = sign_payload(raw, settings.hmac_secret)
        request = urllib.request.Request(
            args.api_url.rstrip("/") + endpoint,
            data=raw,
            headers={"Content-Type": "application/json", "X-SOCForge-Signature": signature},
            method="POST",
        )
        try:
            with urllib.request.urlopen(request, timeout=10) as response:
                response.read()
            sent += 1
        except urllib.error.HTTPError as exc:
            raise SystemExit(f"API rejected line {line_number} (HTTP {exc.code}): {exc.read().decode(errors='replace')}")
        except urllib.error.URLError as exc:
            raise SystemExit(f"Could not reach API: {exc.reason}")
    print(f"Successfully submitted {sent} events using the {args.adapter} adapter.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
