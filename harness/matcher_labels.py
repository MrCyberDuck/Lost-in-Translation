"""Triage labels for the matcher cross-check mechanisms M1 to M7 (results/phase3/matcher_crosscheck/README.md).

Each mechanism lists the clauses its expected verdict relies on and, for every open clause, the readings
under which sigma.matching's result is wrong (docs/spec-clauses.md, "Readings of the open clauses").
harness.triage.classify turns that into the label:

    python -m harness.matcher_labels
"""
from __future__ import annotations

import json

from harness.triage import classify

MECHANISMS: dict[str, tuple[list[str], dict[str, list[str]]]] = {
    "M1": (["S25"], {}),
    "M2": (["S85"], {}),
    # Both fields are missing, so no question of case arises: wrong under both readings of S20.
    "M3": (["S20", "S25"], {"S20": ["S20.a", "S20.b"]}),
    "M4": (["S23", "S25"], {}),
    "M5": (["S5"], {}),
    # Right under S11.c (an integer matches only an integer-typed value), so a spec gap.
    "M6": (["S11"], {}),
    # The value C:\x has one backslash; the rule asks for two (S5). No element, no joined string and no
    # positional field holds two; only the JSON text of the list does.
    "M7": (["S5", "S44", "S87"], {"S44": ["S44.a", "S44.b", "S44.c"], "S87": ["S87.a", "S87.b", "S87.c"]}),
}


def labels() -> dict[str, dict]:
    return {key: classify(deps, cause="engine", wrong_under=wrong) for key, (deps, wrong) in MECHANISMS.items()}


if __name__ == "__main__":
    print(json.dumps(labels(), indent=1))
