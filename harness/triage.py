"""Verdict labels for disagreements, with the spec-gap rule built in.

Clause statuses and the readings of every open clause are parsed from docs/spec-clauses.md, the
single source of truth. A clause is clear, ambiguous or contradictory (the spec has text on its
question, and each reading of it quotes that text) or silent (the spec has no text on it). A
disagreement on a case that depends on an open clause is a `spec-gap` unless the target's mechanism
breaks a clear clause, or an ambiguous or contradictory clause under every one of its readings
(`breaks`). A silent clause can never be broken. See docs/triage-labels.md.
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
_READING = re.compile(r"^\|\s*(S\d+)\.([a-z])\s*\|([^|]*)\|([^|]*)\|\s*(yes)?\s*\|\s*$")


@functools.lru_cache(maxsize=1)
def clause_status(path: str | None = None) -> dict[str, str]:
    """Map clause id -> 'clear' | 'ambiguous' | 'contradictory' | 'silent', read from spec-clauses.md.

    A clause counts as open if its status cell mentions 'contradictory', 'silent' or 'ambiguous' at all
    (for example 'clear for ASCII; ambiguous for non-ASCII'): if any part of it is open, the clause is
    open. 'silent' wins over 'ambiguous' and loses to 'contradictory'.
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
        elif "silent" in status_cell:
            out[m.group(1)] = "silent"
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
    clauses" in spec-clauses.md. Every ambiguous or contradictory clause has at least two readings, one
    of them marked as the working one; a clear or silent clause has none."""
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
        if m and m.group(1) == clause and m.group(5):
            return f"{m.group(1)}.{m.group(2)}"
    return None


def open_clauses(depends_on: Iterable[str]) -> list[str]:
    """The clauses in `depends_on` that are ambiguous, contradictory or silent."""
    status = clause_status()
    unknown = [c for c in depends_on if c not in status]
    if unknown:
        raise KeyError(f"unknown clause ids: {unknown}")
    return [c for c in depends_on if status[c] != "clear"]


def classify(depends_on: Iterable[str], *, oracle_wrong: bool = False,
             rule_out_of_spec: bool = False, production_only: bool = False,
             cause: str | None = None, breaks: dict[str, object] | None = None,
             crashed: bool = False) -> dict:
    """Label one disagreement of one target (rule of 28 Nov 2026, docs/triage-labels.md).

    `depends_on` lists every clause the case relies on, open ones included. `breaks` names what the
    target's mechanism breaks, judged by the mechanism and not by the outcome: a clear clause maps to
    "clear"; an ambiguous or contradictory clause maps to the readings under which the result is wrong.
    A silent clause cannot be named. If the case depends on an open clause, the result is a candidate
    only when it breaks a clear clause, or an open clause under all of its readings, or crashed;
    otherwise it is a `spec-gap`."""
    deps = list(depends_on)
    if not deps:
        raise ValueError("a disagreement must name the spec clauses its expected verdict depends on")
    if oracle_wrong:
        return {"verdict": "oracle-bug"}
    if rule_out_of_spec:
        return {"verdict": "rule-out-of-spec"}
    gaps = open_clauses(deps)
    status, readings = clause_status(), clause_readings()
    broken: dict[str, object] = {}
    for c, v in (breaks or {}).items():
        if c not in deps:
            raise ValueError(f"breaks names {c}, which the case does not depend on")
        if status[c] == "silent":
            raise ValueError(f"{c} is silent: the spec has no text on it, so no result can break it")
        if status[c] == "clear":
            if v != "clear":
                raise ValueError(f"{c} is clear: name it with 'clear', not readings")
            broken[c] = "clear"
            continue
        rs = sorted(set(v))  # type: ignore[arg-type]
        unknown = [r for r in rs if r not in readings[c]]
        if unknown or not rs:
            raise ValueError(f"{c} has no readings {unknown or rs}; its readings are {readings[c]}")
        broken[c] = rs
    decisive = {c: v for c, v in broken.items() if v == "clear" or set(v) == set(readings[c])}  # type: ignore[arg-type]
    if gaps and not decisive and not crashed:
        return {"verdict": "spec-gap", "open_clauses": gaps}
    record: dict = {}
    if decisive:
        record["breaks"] = decisive
    if crashed:
        record["crashed"] = True
    if production_only:
        return {"verdict": "config", **record}
    if cause not in CAUSES:
        raise ValueError(f"a backend-bug needs a cause, one of {CAUSES}")
    return {"verdict": "backend-bug", "cause": cause, **record}
