from __future__ import annotations

import argparse
import json
import math
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

from .config import settings
from .security import sign_payload
from .simulator import generate_demo_events


def _post(url: str, payload: dict, secret: str) -> dict:
    raw = json.dumps(payload, separators=(",", ":")).encode("utf-8")
    request = urllib.request.Request(url, data=raw, headers={
        "Content-Type": "application/json",
        "X-SOCForge-Signature": sign_payload(raw, secret),
    }, method="POST")
    try:
        with urllib.request.urlopen(request, timeout=10) as response:
            return json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        body = exc.read().decode("utf-8", errors="replace")
        raise RuntimeError(f"API returned HTTP {exc.code}: {body}") from exc
    except urllib.error.URLError as exc:
        raise RuntimeError(f"Could not reach SOCForge API: {exc.reason}") from exc


def cmd_simulate(args: argparse.Namespace) -> int:
    posted = 0
    alerts = 0
    iterations = 0
    interrupted = False
    try:
        while args.loop or iterations < args.iterations:
            cycle_posted = 0
            cycle_alerts = 0
            for event in generate_demo_events(args.seed + iterations):
                result = _post(f"{args.api_url.rstrip('/')}/api/events", event, settings.hmac_secret)
                cycle_posted += 1
                cycle_alerts += len(result.get("alerts_created", []))
                posted += 1
                alerts += len(result.get("alerts_created", []))
            iterations += 1

            if args.loop or args.iterations > 1:
                print(json.dumps({
                    "iteration": iterations,
                    "events_posted": cycle_posted,
                    "alerts_created": cycle_alerts,
                }), flush=True)

            if args.loop or iterations < args.iterations:
                time.sleep(args.interval)
    except KeyboardInterrupt:
        interrupted = True

    summary = {
        "events_posted": posted,
        "alerts_created": alerts,
        "label": "synthetic training telemetry",
    }
    if args.loop or args.iterations > 1:
        summary["iterations_completed"] = iterations
        if interrupted:
            summary["interrupted"] = True
    print(json.dumps(summary, indent=2))
    return 0


def cmd_export_sample(args: argparse.Namespace) -> int:
    target = Path(args.output)
    target.parent.mkdir(parents=True, exist_ok=True)
    with target.open("w", encoding="utf-8") as handle:
        for event in generate_demo_events(args.seed):
            handle.write(json.dumps(event, separators=(",", ":")) + "\n")
    print(f"Wrote {target}")
    return 0


def main() -> None:
    parser = argparse.ArgumentParser(prog="socforge", description="SOCForge defensive SOC lab utility")
    sub = parser.add_subparsers(required=True)
    simulate = sub.add_parser("simulate", help="send synthetic telemetry to a running SOCForge API")
    simulate.add_argument("--api-url", default="http://127.0.0.1:8000")
    simulate.add_argument("--seed", type=int, default=41)
    simulate.add_argument("--loop", action="store_true", help="repeat continuously until interrupted")
    simulate.add_argument("--iterations", type=int, default=1, help="number of batches to send (default: 1)")
    simulate.add_argument("--interval", type=float, default=5.0, help="seconds between batches (default: 5)")
    simulate.set_defaults(func=cmd_simulate)
    export = sub.add_parser("export-sample", help="write synthetic events to a JSONL file")
    export.add_argument("--output", default="samples/synthetic_events.jsonl")
    export.add_argument("--seed", type=int, default=41)
    export.set_defaults(func=cmd_export_sample)
    args = parser.parse_args()
    if args.func is cmd_simulate:
        if args.iterations < 1:
            parser.error("--iterations must be at least 1")
        if not math.isfinite(args.interval) or args.interval < 0:
            parser.error("--interval must be a finite non-negative number")
    try:
        raise SystemExit(args.func(args))
    except RuntimeError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        raise SystemExit(2)


if __name__ == "__main__":
    main()
