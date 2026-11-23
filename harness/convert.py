"""Rule conversion with pySigma backends.

Two configurations are studied (see the plan, "Ingestion normalisation"):
- `neutral`: no processing pipeline, so queries use Sigma field names and events are stored
  with Sigma field names. This isolates converter and engine behaviour.
- `production`: the backend's stock pipeline (added in Phase 4).
"""
from __future__ import annotations

from dataclasses import dataclass
from functools import lru_cache

from sigma.collection import SigmaCollection
from sigma.plugins import InstalledSigmaPlugins

# The 8 query targets of the core set, keyed by sigma-cli target id.
TARGETS = ["splunk", "lucene", "esql", "eql", "opensearch_lucene", "kusto", "loki", "sqlite"]


@dataclass
class Conversion:
    target: str
    queries: list[str]
    error: str | None = None


@lru_cache(maxsize=1)
def _plugins() -> InstalledSigmaPlugins:
    return InstalledSigmaPlugins.autodiscover()


def convert(rule_yaml: str, target: str, config: str = "neutral") -> Conversion:
    """Convert one rule (YAML text) for one target. Conversion errors are returned, not raised."""
    if config != "neutral":
        raise NotImplementedError("only the neutral config exists in Phase 1")
    backend_cls = _plugins().backends[target]
    try:
        backend = backend_cls()
        collection = SigmaCollection.from_yaml(rule_yaml)
        queries = backend.convert(collection)
        return Conversion(target, [str(q) for q in queries])
    except Exception as exc:  # noqa: BLE001 - a refused conversion is a result, not a crash
        return Conversion(target, [], f"{type(exc).__name__}: {exc}")
