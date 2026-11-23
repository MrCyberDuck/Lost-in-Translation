"""SQLite, as used by Zircolite: one wide table `logs`, Python `re.search` as REGEXP."""
from __future__ import annotations

import pathlib
import re
import sqlite3

from ..events import Event, field_names
from .base import Engine, safe_name


def _regexp(pattern: str, value) -> bool:
    # Zircolite registers a Python-`re` REGEXP function; we do the same so SQLite behaves as the
    # most common offline Sigma scanner does. Note this makes the regex dialect Python `re`.
    if value is None:
        return False
    return re.search(pattern, str(value)) is not None


class SqliteEngine(Engine):
    name = "sqlite"
    targets = ("sqlite",)

    def __init__(self, folder: str):
        self.folder = pathlib.Path(folder)

    def _db(self, dataset: str) -> pathlib.Path:
        return self.folder / f"{safe_name(dataset)}.db"

    def health(self) -> dict:
        return {"sqlite_version": sqlite3.sqlite_version}

    def _connect(self, dataset: str) -> sqlite3.Connection:
        con = sqlite3.connect(self._db(dataset))
        con.create_function("REGEXP", 2, _regexp, deterministic=True)
        return con

    def load(self, dataset: str, events: list[Event]) -> None:
        self.folder.mkdir(parents=True, exist_ok=True)
        db = self._db(dataset)
        if db.exists():
            db.unlink()
        cols = field_names(events)
        con = self._connect(dataset)
        quoted = ", ".join(f'"{c}"' for c in cols)
        # No declared types: SQLite stores each value with its JSON type (TEXT / INTEGER / REAL / NULL).
        con.execute(f"CREATE TABLE logs ({quoted})")
        marks = ", ".join("?" for _ in cols)
        con.executemany(f"INSERT INTO logs ({quoted}) VALUES ({marks})",
                        [tuple(ev.get(c) for c in cols) for ev in events])
        con.commit()
        con.close()

    def query(self, dataset: str, target: str, query: str) -> set[str]:
        sql = re.sub(r"^SELECT \* FROM logs", 'SELECT "event_id" FROM logs', query.strip(), count=1)
        con = self._connect(dataset)
        try:
            return {str(r[0]) for r in con.execute(sql)}
        finally:
            con.close()

    def storage_notes(self) -> dict:
        return {"table": "logs", "column_types": "none (dynamic typing)", "missing_field": "NULL",
                "regexp": "python re.search, as Zircolite"}
