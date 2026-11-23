import json
import pathlib

from harness.events import from_evtx_json, load_jsonl

SAMPLE = next(pathlib.Path("rules/sigma/regression_data/rules/windows/process_creation").rglob("*.json"))


def test_flatten_regression_sample():
    ev = from_evtx_json(json.loads(SAMPLE.read_text(encoding="utf-8")), "r-1")
    assert ev["event_id"] == "r-1"
    assert ev["EventID"] == 1
    assert ev["Provider_Name"] == "Microsoft-Windows-Sysmon"
    assert "Image" in ev and "CommandLine" in ev
    assert ev["@timestamp"].startswith("20")


def test_smoke_events_load():
    evs = load_jsonl("conformance/smoke/events.jsonl")
    assert [e["event_id"] for e in evs] == ["smoke-1", "smoke-2", "smoke-3"]
