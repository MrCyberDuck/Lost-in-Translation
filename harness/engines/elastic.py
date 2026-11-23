"""Elasticsearch and OpenSearch: Lucene query_string, ES|QL and EQL."""
from __future__ import annotations

import json
import re

from ..events import Event, chunks
from .base import Engine, local_session, safe_name

# Neutral mapping: every string is a `keyword` (exact, case-sensitive term) with no length cut-off,
# numbers keep their JSON type. This is the "raw-keyword" template of the plan; the "ecs-like"
# template (wildcard / text fields) is a later variant.
NEUTRAL_MAPPING = {
    "dynamic_templates": [
        {"strings_as_keyword": {"match_mapping_type": "string",
                                "mapping": {"type": "keyword", "ignore_above": 32766}}}
    ],
    "properties": {"@timestamp": {"type": "date"}, "event_id": {"type": "keyword"}},
}


def _check(r, what: str) -> None:
    if r.status_code >= 300:
        raise RuntimeError(f"{what} failed {r.status_code}: {r.text[:500]}")


class ElasticEngine(Engine):
    def __init__(self, flavor: str, url: str):
        self.name = flavor
        self.flavor = flavor
        self.url = url.rstrip("/")
        self.http = local_session()
        self.targets = ("lucene", "esql", "eql") if flavor == "elasticsearch" else ("opensearch_lucene",)

    def _index(self, dataset: str) -> str:
        return f"lit-{safe_name(dataset)}".replace("_", "-")

    def health(self) -> dict:
        r = self.http.get(self.url, timeout=10)
        r.raise_for_status()
        v = r.json()["version"]
        return {"distribution": v.get("distribution", "elasticsearch"), "version": v["number"]}

    def load(self, dataset: str, events: list[Event]) -> None:
        index = self._index(dataset)
        self.http.delete(f"{self.url}/{index}", timeout=30)
        r = self.http.put(f"{self.url}/{index}", timeout=30, json={
            "settings": {"number_of_shards": 1, "number_of_replicas": 0},
            "mappings": NEUTRAL_MAPPING,
        })
        r.raise_for_status()
        for part in chunks(events, 500):
            body = "".join(json.dumps({"index": {"_index": index, "_id": ev["event_id"]}}) + "\n"
                           + json.dumps(ev) + "\n" for ev in part)
            r = self.http.post(f"{self.url}/_bulk?refresh=wait_for", data=body.encode(), timeout=120,
                               headers={"Content-Type": "application/x-ndjson"})
            r.raise_for_status()
            if r.json().get("errors"):
                bad = [i for i in r.json()["items"] if i["index"].get("error")][:3]
                raise RuntimeError(f"{self.name}: bulk errors: {bad}")

    def query(self, dataset: str, target: str, query: str) -> set[str]:
        index = self._index(dataset)
        if target in ("lucene", "opensearch_lucene"):
            r = self.http.post(f"{self.url}/{index}/_search", timeout=60, json={
                "size": 10000, "_source": ["event_id"],
                "query": {"query_string": {"query": query}},
            })
            _check(r, "query_string search")
            return {h["_source"]["event_id"] for h in r.json()["hits"]["hits"]}
        if target == "esql":
            # The backend emits `from * metadata ...`; point it at the dataset index only.
            q = re.sub(r"^from\s+\S+(\s+metadata\s+[^|]*)?", f"from {index} ", query.strip(), count=1)
            q += " | keep event_id | limit 10000"
            r = self.http.post(f"{self.url}/_query", timeout=60, json={"query": q})
            _check(r, "ES|QL query")
            return {row[0] for row in r.json()["values"]}
        if target == "eql":
            r = self.http.post(f"{self.url}/{index}/_eql/search", timeout=60, json={
                "query": query, "size": 10000, "timestamp_field": "@timestamp",
            })
            _check(r, "EQL search")
            return {e["_source"]["event_id"] for e in r.json()["hits"].get("events", [])}
        raise ValueError(f"{self.name} does not run target {target}")

    def storage_notes(self) -> dict:
        return {"index_template": "raw-keyword", "mapping": NEUTRAL_MAPPING}
