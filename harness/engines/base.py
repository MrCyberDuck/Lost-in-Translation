from __future__ import annotations

import abc
import re

import requests

from ..events import Event


def local_session() -> requests.Session:
    """HTTP session for engines on localhost: never route through a corporate or cloud proxy."""
    s = requests.Session()
    s.trust_env = False
    return s


def safe_name(dataset: str) -> str:
    """Dataset name usable as an index / table / label name on every engine."""
    name = re.sub(r"[^a-z0-9_]", "_", dataset.lower())
    if not re.match(r"^[a-z]", name):
        name = "d_" + name
    return name


class Engine(abc.ABC):
    """One storage and query engine. `targets` are the query languages it executes."""

    name: str
    targets: tuple[str, ...]

    @abc.abstractmethod
    def health(self) -> dict:
        """Return version information; raise if the engine is not reachable."""

    @abc.abstractmethod
    def load(self, dataset: str, events: list[Event]) -> None:
        """(Re)create the dataset and store the events. Must return only when they are searchable."""

    @abc.abstractmethod
    def query(self, dataset: str, target: str, query: str) -> set[str]:
        """Run a converted query against the dataset and return the matching event_ids."""

    def storage_notes(self) -> dict:
        """How events are stored (mapping, types, sourcetype...). Goes into the run manifest."""
        return {}
