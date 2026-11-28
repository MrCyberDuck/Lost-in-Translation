"""Triage labels for the matcher cross-check mechanisms M1 to M7 (results/phase3/matcher_crosscheck/README.md).

Each mechanism lists the clauses its expected verdict relies on and what it breaks: a clear clause
("clear") or an open clause with the readings under which sigma.matching's result is wrong
(docs/spec-clauses.md, "Readings of the open clauses"; docs/triage-labels.md).
harness.triage.classify turns that into the label:

    python -m harness.matcher_labels
"""
from __future__ import annotations

import json

from harness.triage import classify

MECHANISMS: dict[str, tuple[list[str], dict[str, object]]] = {
    "M1": (["S25"], {}),
    "M2": (["S85"], {}),
    "M3": (["S20", "S25"], {}),
    "M4": (["S23", "S25"], {}),
    "M5": (["S5"], {}),
    # An integer in the rule does not match the same number as a string in the event; S11 is clear.
    "M6": (["S11"], {}),
    # The value C:\x has one backslash; the rule asks for two (S5). The matcher matches the JSON text of
    # the list, which escapes it, so it breaks S5 whatever a multi-valued field is (S44, S87 are silent).
    "M7": (["S5", "S44", "S87"], {"S5": "clear"}),
}


def labels() -> dict[str, dict]:
    return {key: classify(deps, cause="engine", breaks=brk) for key, (deps, brk) in MECHANISMS.items()}


if __name__ == "__main__":
    print(json.dumps(labels(), indent=1))
