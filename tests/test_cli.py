import argparse
import json

from socforge import cli


def test_simulate_repeats_batches_and_reports_event_totals(monkeypatch, capsys):
    posted_events = []
    sleeps = []

    monkeypatch.setattr(cli, "generate_demo_events", lambda seed: [{"seed": seed}, {"seed": seed}])

    def fake_post(url, event, secret):
        posted_events.append((url, event, secret))
        return {"alerts_created": [1] if event["seed"] == 42 else []}

    monkeypatch.setattr(cli, "_post", fake_post)
    monkeypatch.setattr(cli.time, "sleep", sleeps.append)
    args = argparse.Namespace(
        api_url="http://127.0.0.1:8000/",
        seed=41,
        loop=False,
        iterations=2,
        interval=3,
    )

    assert cli.cmd_simulate(args) == 0

    output = [json.loads(line) for line in capsys.readouterr().out.splitlines()]
    assert [event["seed"] for _, event, _ in posted_events] == [41, 41, 42, 42]
    assert [url for url, _, _ in posted_events] == ["http://127.0.0.1:8000/api/events"] * 4
    assert sleeps == [3]
    assert output[-1] == {
        "events_posted": 4,
        "alerts_created": 2,
        "label": "synthetic training telemetry",
        "iterations_completed": 2,
    }
