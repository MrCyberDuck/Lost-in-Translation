"""Canonical events.

Every event the harness handles is a flat dict:
- `event_id`: unique string id, used to compare match sets across engines;
- `@timestamp`: ISO-8601 UTC time;
- every other key is a Sigma field name (for example `Image`, `CommandLine`, `EventID`).

Engines receive exactly these dicts; each engine adapter decides how to store them,
and that decision is recorded in the run manifest (ingestion is a study variable).
"""
from __future__ import annotations

import json
import pathlib
from typing import Any, Iterable, Iterator

Event = dict[str, Any]


def load_jsonl(path: str | pathlib.Path) -> list[Event]:
    """Load canonical events from a JSON Lines file."""
    events = []
    with open(path, encoding="utf-8") as fh:
        for n, line in enumerate(fh, 1):
            line = line.strip()
            if not line:
                continue
            ev = json.loads(line)
            if "event_id" not in ev or "@timestamp" not in ev:
                raise ValueError(f"{path}:{n}: event needs 'event_id' and '@timestamp'")
            events.append(ev)
    ids = [e["event_id"] for e in events]
    if len(ids) != len(set(ids)):
        raise ValueError(f"{path}: duplicate event_id values")
    return events


def from_evtx_json(record: dict, event_id: str) -> Event:
    """Flatten one EVTX record (as dumped by evtx_dump / SigmaHQ regression_data) to Sigma fields.

    Follows the Sigma spec field-usage rules: `<EventData><Data Name="X">` becomes `X`,
    System header attributes become `Tag_Attribute` (for example `Provider_Name`).
    """
    ev = record.get("Event", record)
    system = ev.get("System", {})
    out: Event = {"event_id": event_id}
    for key, val in system.items():
        if isinstance(val, dict):
            attrs = val.get("#attributes", {})
            for ak, av in attrs.items():
                out[f"{key}_{ak}"] = av
            if "#text" in val:
                out[key] = val["#text"]
        else:
            out[key] = val
    ts = out.pop("TimeCreated_SystemTime", None)
    out["@timestamp"] = ts or "1970-01-01T00:00:00Z"
    data = ev.get("EventData") or ev.get("UserData") or {}
    if isinstance(data, dict):
        for key, val in data.items():
            if key == "#attributes":
                continue
            out[key] = val
    return out


def field_names(events: Iterable[Event]) -> list[str]:
    """All field names over a set of events, in first-seen order."""
    seen: dict[str, None] = {}
    for ev in events:
        for k in ev:
            seen.setdefault(k, None)
    return list(seen)


def chunks(items: list, size: int) -> Iterator[list]:
    for i in range(0, len(items), size):
        yield items[i:i + size]
