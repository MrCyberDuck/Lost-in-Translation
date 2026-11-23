"""Grafana Loki: events are pushed as JSON log lines; LogQL parses them with `| json`."""
from __future__ import annotations

import json
import re
import time
from datetime import datetime, timezone

from ..events import Event, chunks
from .base import Engine, local_session, safe_name


def _ns(ts: str) -> int:
    dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return int(dt.timestamp() * 1_000_000_000)


class LokiEngine(Engine):
    name = "loki"
    targets = ("loki",)

    def __init__(self, url: str):
        self.url = url.rstrip("/")
        self.http = local_session()
        self._range: dict[str, tuple[int, int]] = {}

    def health(self) -> dict:
        r = self.http.get(f"{self.url}/loki/api/v1/status/buildinfo", timeout=10)
        r.raise_for_status()
        return {"version": r.json().get("version")}

    def load(self, dataset: str, events: list[Event]) -> None:
        # Loki cannot delete a stream cheaply, so each dataset gets its own label value; reuse of a
        # dataset name requires a fresh Loki volume.
        label = safe_name(dataset)
        stamps = []
        for part in chunks(events, 500):
            values = []
            for ev in part:
                ts = _ns(ev["@timestamp"])
                stamps.append(ts)
                values.append([str(ts), json.dumps(ev, ensure_ascii=False)])
            r = self.http.post(f"{self.url}/loki/api/v1/push", timeout=60, json={
                "streams": [{"stream": {"lit_dataset": label}, "values": values}]})
            if r.status_code >= 300:
                raise RuntimeError(f"loki push failed {r.status_code}: {r.text[:300]}")
        self._range[label] = (min(stamps) - 1_000_000_000, max(stamps) + 1_000_000_000)
        # wait until all lines are queryable
        want = len(events)
        for _ in range(60):
            if len(self._select(label, '{lit_dataset="%s"}' % label)) >= want:
                return
            time.sleep(1)
        raise RuntimeError("loki: events not queryable after 60 s")

    def _select(self, label: str, logql: str) -> set[str]:
        start, end = self._range[label]
        r = self.http.get(f"{self.url}/loki/api/v1/query_range", timeout=60, params={
            "query": logql, "start": start, "end": end, "limit": 5000, "direction": "forward"})
        if r.status_code >= 300:
            raise RuntimeError(f"loki query failed {r.status_code}: {r.text[:300]}")
        ids = set()
        for stream in r.json()["data"]["result"]:
            for _, line in stream["values"]:
                ids.add(json.loads(line)["event_id"])
        return ids

    def query(self, dataset: str, target: str, query: str) -> set[str]:
        label = safe_name(dataset)
        # The backend emits a stream selector for Windows log jobs; replace it with the dataset's.
        q = re.sub(r"^\{[^}]*\}", '{lit_dataset="%s"}' % label, query.strip(), count=1)
        return self._select(label, q)

    def storage_notes(self) -> dict:
        return {"line_format": "JSON object per event", "labels": ["lit_dataset"],
                "timestamp": "event @timestamp"}
