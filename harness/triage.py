"""Verdict labels for disagreements, with the spec-gap rule built in.

Clause statuses are parsed from docs/spec-clauses.md, the single source of truth. Any verdict that
depends on an ambiguous or contradictory clause is a `spec-gap`, never a `backend-bug`.
See docs/triage-labels.md.
"""
from __future__ import annotations

import functools
import pathlib
import re
from typing import Iterable

SPEC_CLAUSES = pathlib.Path(__file__).resolve().parent.parent / "docs" / "spec-clauses.md"

VERDICTS = ("oracle-bug", "rule-out-of-spec", "spec-gap", "config", "backend-bug")
CAUSES = ("converter", "engine", "ingest")

_ROW = re.compile(r"^\|\s*(S\d+)\s*\|(.*)$")


@functools.lru_cache(maxsize=1)
def clause_status(path: str | None = None) -> dict[str, str]:
    """Map clause id -> 'clear' | 'ambiguous' | 'contradictory', read from spec-clauses.md.

    A clause counts as ambiguous if its status cell mentions 'ambiguous' at all (for example
    'clear for ASCII; ambiguous for non-ASCII'): if any part of it is open, the clause is open.
    """
    text = pathlib.Path(path or SPEC_CLAUSES).read_text(encoding="utf-8")
    out: dict[str, str] = {}
    for line in text.splitlines():
        m = _ROW.match(line)
        if not m:
            continue
        cells = [c.strip() for c in re.split(r"(?<!\\)\|", m.group(2))]
        # columns after the id: Clause | Spec source | Status | ...
        status_cell = cells[2].lower() if len(cells) > 2 else ""
        if "contradictory" in status_cell:
            out[m.group(1)] = "contradictory"
        elif "ambiguous" in status_cell:
            out[m.group(1)] = "ambiguous"
        elif "clear" in status_cell:
            out[m.group(1)] = "clear"
        else:
            raise ValueError(f"{m.group(1)}: cannot read status cell {status_cell!r}")
    return out


def open_clauses(depends_on: Iterable[str]) -> list[str]:
    """The clauses in `depends_on` that are ambiguous or contradictory."""
    status = clause_status()
    unknown = [c for c in depends_on if c not in status]
    if unknown:
        raise KeyError(f"unknown clause ids: {unknown}")
    return [c for c in depends_on if status[c] != "clear"]


def classify(depends_on: Iterable[str], *, oracle_wrong: bool = False,
             rule_out_of_spec: bool = False, production_only: bool = False,
             cause: str | None = None) -> dict:
    """Label one disagreement. `depends_on` lists the clause ids the expected verdict relies on."""
    deps = list(depends_on)
    if not deps:
        raise ValueError("a disagreement must name the spec clauses its expected verdict depends on")
    if oracle_wrong:
        return {"verdict": "oracle-bug"}
    if rule_out_of_spec:
        return {"verdict": "rule-out-of-spec"}
    gaps = open_clauses(deps)
    if gaps:
        return {"verdict": "spec-gap", "open_clauses": gaps}
    if production_only:
        return {"verdict": "config"}
    if cause not in CAUSES:
        raise ValueError(f"a backend-bug needs a cause, one of {CAUSES}")
    return {"verdict": "backend-bug", "cause": cause}
