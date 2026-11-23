"""Splunk Enterprise: events sent to HTTP Event Collector as `_json`, searched via the REST export API."""
from __future__ import annotations

import json
import time
from datetime import datetime, timezone

from ..events import Event, chunks
from .base import Engine, local_session, safe_name

SOURCETYPE = "_json"   # Splunk's built-in JSON sourcetype: fields extracted at search time


def _epoch(ts: str) -> float:
    dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.timestamp()


class SplunkEngine(Engine):
    name = "splunk"
    targets = ("splunk",)

    def __init__(self, url: str, hec_url: str, user: str, password: str):
        self.url = url.rstrip("/")
        self.hec_url = hec_url.rstrip("/")
        self.http = local_session()
        self.http.verify = False          # the container uses a self-signed certificate
        self.http.auth = (user, password)
        self._tokens: dict[str, str] = {}
        import urllib3
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    def _rest(self, method: str, path: str, **kw):
        kw.setdefault("timeout", 60)
        r = self.http.request(method, f"{self.url}{path}", **kw)
        return r

    def health(self) -> dict:
        r = self._rest("GET", "/services/server/info", params={"output_mode": "json"})
        r.raise_for_status()
        c = r.json()["entry"][0]["content"]
        return {"version": c.get("version"), "license": c.get("activeLicenseGroup")}

    def _ensure_index_and_token(self, index: str) -> str:
        if index in self._tokens:
            return self._tokens[index]
        r = self._rest("POST", "/services/data/indexes", data={"name": index, "output_mode": "json"})
        if r.status_code not in (200, 201, 409):
            raise RuntimeError(f"splunk: cannot create index {index}: {r.status_code} {r.text[:300]}")
        base = "/servicesNS/nobody/splunk_httpinput/data/inputs/http"
        r = self._rest("GET", f"{base}/{index}", params={"output_mode": "json"})
        if r.status_code == 404:
            r = self._rest("POST", base, data={"name": index, "index": index, "indexes": index,
                                               "sourcetype": SOURCETYPE, "output_mode": "json"})
        r.raise_for_status()
        token = r.json()["entry"][0]["content"]["token"]
        # make sure HEC itself is enabled
        self._rest("POST", f"{base}/http/enable", data={"output_mode": "json"})
        self._tokens[index] = token
        return token

    def _index(self, dataset: str) -> str:
        return f"lit_{safe_name(dataset)}"

    def load(self, dataset: str, events: list[Event]) -> None:
        index = self._index(dataset)
        token = self._ensure_index_and_token(index)
        # Splunk cannot drop an index's events without restart or the `delete` capability, so a
        # dataset name must not be loaded twice; the smoke test uses a fresh run-scoped name.
        hec = local_session()
        hec.verify = False
        for part in chunks(events, 500):
            body = "".join(json.dumps({"time": _epoch(ev["@timestamp"]), "index": index,
                                       "sourcetype": SOURCETYPE, "event": ev}) for ev in part)
            r = hec.post(f"{self.hec_url}/services/collector/event", data=body.encode(), timeout=60,
                         headers={"Authorization": f"Splunk {token}"})
            if r.status_code >= 300:
                raise RuntimeError(f"splunk HEC failed {r.status_code}: {r.text[:300]}")
        want = len(events)
        for _ in range(90):
            got = self._search(f"search index={index} | stats count")
            if got and int(got[0].get("count", 0)) >= want:
                return
            time.sleep(1)
        raise RuntimeError("splunk: events not searchable after 90 s")

    def _search(self, spl: str) -> list[dict]:
        r = self._rest("POST", "/services/search/jobs/export", timeout=300, data={
            "search": spl, "output_mode": "json", "earliest_time": "0", "latest_time": "+10y"})
        if r.status_code >= 300:
            raise RuntimeError(f"splunk search failed {r.status_code}: {r.text[:300]}")
        rows = []
        for line in r.text.splitlines():
            if not line.strip():
                continue
            obj = json.loads(line)
            if "result" in obj:
                rows.append(obj["result"])
            elif obj.get("messages") and any(m.get("type") == "FATAL" for m in obj["messages"]):
                raise RuntimeError(f"splunk search error: {obj['messages']}")
        return rows

    def query(self, dataset: str, target: str, query: str) -> set[str]:
        index = self._index(dataset)
        q = query.strip()
        spl = f"search index={index} {q} | fields event_id" if not q.startswith("|") else q
        return {str(r["event_id"]) for r in self._search(spl) if "event_id" in r}

    def storage_notes(self) -> dict:
        return {"ingest": "HEC /services/collector/event", "sourcetype": SOURCETYPE,
                "field_extraction": "search-time JSON (KV_MODE=json via _json sourcetype)"}
