"""Engine adapters. Each adapter stores canonical events and runs converted queries."""
from __future__ import annotations

from .base import Engine
from .elastic import ElasticEngine
from .kusto import KustoEngine
from .loki import LokiEngine
from .splunk import SplunkEngine
from .sqlite import SqliteEngine

# target id -> engine key
TARGET_ENGINE = {
    "splunk": "splunk",
    "lucene": "elasticsearch",
    "esql": "elasticsearch",
    "eql": "elasticsearch",
    "opensearch_lucene": "opensearch",
    "kusto": "kusto",
    "loki": "loki",
    "sqlite": "sqlite",
}

WAVES = {
    "a": ["elasticsearch", "opensearch", "loki", "sqlite"],
    "b": ["splunk", "kusto", "sqlite"],
}


def make_engines(cfg) -> dict[str, Engine]:
    return {
        "elasticsearch": ElasticEngine("elasticsearch", cfg.es_url),
        "opensearch": ElasticEngine("opensearch", cfg.os_url),
        "loki": LokiEngine(cfg.loki_url),
        "sqlite": SqliteEngine(cfg.sqlite_dir),
        "splunk": SplunkEngine(cfg.splunk_url, cfg.splunk_hec_url, cfg.splunk_user, cfg.splunk_password),
        "kusto": KustoEngine(cfg.kusto_url),
    }


__all__ = ["Engine", "TARGET_ENGINE", "WAVES", "make_engines"]
