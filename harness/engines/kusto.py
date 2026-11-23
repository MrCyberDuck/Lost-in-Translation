"""Azure Data Explorer Kusto emulator: one table per dataset, ingested inline as CSV."""
from __future__ import annotations

import csv
import io

from ..events import Event, chunks, field_names
from .base import Engine, local_session, safe_name

DB = "NetDefaultDB"


def _kusto_type(values) -> str:
    vals = [v for v in values if v is not None]
    if vals and all(isinstance(v, bool) for v in vals):
        return "bool"
    if vals and all(isinstance(v, int) and not isinstance(v, bool) for v in vals):
        return "long"
    if vals and all(isinstance(v, (int, float)) and not isinstance(v, bool) for v in vals):
        return "real"
    return "string"


def _col(name: str) -> str:
    return "['" + name.replace("'", "\\'") + "']"


class KustoEngine(Engine):
    name = "kusto"
    targets = ("kusto",)

    def __init__(self, url: str):
        self.url = url.rstrip("/")
        self.http = local_session()
        self._schemas: dict[str, dict[str, str]] = {}

    def _mgmt(self, csl: str) -> dict:
        r = self.http.post(f"{self.url}/v1/rest/mgmt", timeout=120, json={"db": DB, "csl": csl})
        if r.status_code >= 300:
            raise RuntimeError(f"kusto mgmt failed {r.status_code}: {r.text[:500]}")
        return r.json()

    def _query(self, csl: str) -> list[list]:
        r = self.http.post(f"{self.url}/v1/rest/query", timeout=120, json={"db": DB, "csl": csl})
        if r.status_code >= 300:
            raise RuntimeError(f"kusto query failed {r.status_code}: {r.text[:500]}")
        return r.json()["Tables"][0]["Rows"]

    def health(self) -> dict:
        rows = self._mgmt(".show version")["Tables"][0]["Rows"]
        return {"version": rows[0][1] if rows and len(rows[0]) > 1 else str(rows)}

    def load(self, dataset: str, events: list[Event]) -> None:
        table = safe_name(dataset)
        cols = [c for c in field_names(events) if c != "@timestamp"]
        types = {c: _kusto_type([ev.get(c) for ev in events]) for c in cols}
        schema = ", ".join(f"{_col(c)}:{t}" for c, t in types.items())
        self._mgmt(f".drop table {table} ifexists")
        self._mgmt(f".create table {table} (TimeGenerated:datetime, {schema})")
        order = ["TimeGenerated"] + cols
        for part in chunks(events, 200):
            buf = io.StringIO()
            w = csv.writer(buf, lineterminator="\n")
            for ev in part:
                row = [ev["@timestamp"]]
                for c in cols:
                    v = ev.get(c)
                    row.append("" if v is None else (str(v).lower() if isinstance(v, bool) else v))
                w.writerow(row)
            self._mgmt(f".ingest inline into table {table} <|\n{buf.getvalue()}")
        self._schemas[table] = {"TimeGenerated": "datetime", **types}
        n = self._query(f"{table} | count")[0][0]
        if n != len(events):
            raise RuntimeError(f"kusto: expected {len(events)} rows, found {n}")
        _ = order

    def query(self, dataset: str, target: str, query: str) -> set[str]:
        table = safe_name(dataset)
        rows = self._query(f"{table}\n| where {query}\n| project event_id")
        return {str(r[0]) for r in rows}

    def storage_notes(self) -> dict:
        return {"ingest": "inline CSV", "types": "long/real/bool when all values are, else string",
                "missing_field": "empty string (Kusto strings cannot be null)",
                "schemas": self._schemas}
