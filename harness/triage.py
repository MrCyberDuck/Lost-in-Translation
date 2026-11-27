"""Verdict labels for disagreements, with the spec-gap rule built in.

Clause statuses and the readings of every open clause are parsed from docs/spec-clauses.md, the
single source of truth. A disagreement is a `spec-gap`, never a `backend-bug`, when the target's
result is right under at least one reading of an ambiguous or contradictory clause it depends on.
Only a result that is wrong under every reading of every such clause (`wrong_under`) can be a
`backend-bug`. See docs/triage-labels.md.
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
_READING = re.compile(r"^\|\s*(S\d+)\.([a-z])\s*\|([^|]*)\|\s*(yes)?\s*\|\s*$")


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


@functools.lru_cache(maxsize=1)
def clause_readings(path: str | None = None) -> dict[str, list[str]]:
    """Map open clause id -> its reading ids (`S34.a`, `S34.b`), from the table "Readings of the open
    clauses" in spec-clauses.md. Every open clause has at least two readings and at most one marked
    as the working one; a clear clause has none."""
    text = pathlib.Path(path or SPEC_CLAUSES).read_text(encoding="utf-8")
    out: dict[str, list[str]] = {}
    for line in text.splitlines():
        m = _READING.match(line)
        if m:
            out.setdefault(m.group(1), []).append(f"{m.group(1)}.{m.group(2)}")
    return out


def working_reading(clause: str, path: str | None = None) -> str | None:
    """The reading the evaluator follows, or None when none is chosen yet."""
    text = pathlib.Path(path or SPEC_CLAUSES).read_text(encoding="utf-8")
    for line in text.splitlines():
        m = _READING.match(line)
        if m and m.group(1) == clause and m.group(4):
            return f"{m.group(1)}.{m.group(2)}"
    return None


def every_reading(depends_on: Iterable[str]) -> dict[str, list[str]]:
    """`wrong_under` for a result that is wrong whatever the readings, such as a crash."""
    readings = clause_readings()
    return {c: list(readings[c]) for c in open_clauses(depends_on)}


def open_clauses(depends_on: Iterable[str]) -> list[str]:
    """The clauses in `depends_on` that are ambiguous or contradictory."""
    status = clause_status()
    unknown = [c for c in depends_on if c not in status]
    if unknown:
        raise KeyError(f"unknown clause ids: {unknown}")
    return [c for c in depends_on if status[c] != "clear"]


def classify(depends_on: Iterable[str], *, oracle_wrong: bool = False,
             rule_out_of_spec: bool = False, production_only: bool = False,
             cause: str | None = None, wrong_under: dict[str, Iterable[str]] | None = None) -> dict:
    """Label one disagreement of one target.

    `depends_on` lists every clause the case relies on, open ones included. `wrong_under` maps an open
    clause to the readings under which the target's result is wrong; an open clause excuses the
    result unless it is wrong under all of that clause's readings (decision of 27 Nov 2026)."""
    deps = list(depends_on)
    if not deps:
        raise ValueError("a disagreement must name the spec clauses its expected verdict depends on")
    if oracle_wrong:
        return {"verdict": "oracle-bug"}
    if rule_out_of_spec:
        return {"verdict": "rule-out-of-spec"}
    gaps = open_clauses(deps)
    wrong = {c: sorted(set(r)) for c, r in (wrong_under or {}).items()}
    readings = clause_readings()
    for c, rs in wrong.items():
        if c not in gaps:
            raise ValueError(f"wrong_under names {c}, which is not an open clause the case depends on")
        unknown = [r for r in rs if r not in readings[c]]
        if unknown:
            raise ValueError(f"{c} has no readings {unknown}; its readings are {readings[c]}")
    excusing = [c for c in gaps if set(wrong.get(c, ())) != set(readings[c])]
    if excusing:
        return {"verdict": "spec-gap", "open_clauses": excusing}
    record = {"wrong_under": {c: wrong[c] for c in gaps}} if gaps else {}
    if production_only:
        return {"verdict": "config", **record}
    if cause not in CAUSES:
        raise ValueError(f"a backend-bug needs a cause, one of {CAUSES}")
    return {"verdict": "backend-bug", "cause": cause, **record}
