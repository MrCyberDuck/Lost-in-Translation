"""Cross-check the reference evaluator against pySigma 2.x's built-in matcher (sigma.matching).

Runs in the pySigma 2.x environment (requirements-2x.lock), on the Phase 2 events and rules:

    python -m harness.matcher_crosscheck regression
    python -m harness.matcher_crosscheck evtx-attack-samples

Neutral config only: logsource is not applied, so each rule is matched against every event, as the
evaluator's neutral run did. Writes results/phase3/matcher_crosscheck/<dataset>/summary.json and
disagreements.json (one row per rule whose match set differs from the evaluator's, with counts
and up to 20 event ids per side).
"""
from __future__ import annotations

import argparse
import collections
import datetime
import json
import pathlib
import sys
import time
import warnings

from sigma.collection import SigmaCollection
from sigma.matching import Event, EventLogSource
from sigma.matching.compiler import MatchCompiler
from sigma.rule import SigmaRule

SIGMA = pathlib.Path("rules/sigma")
PHASE2 = pathlib.Path("results/phase2")
OUT = pathlib.Path("results/phase3/matcher_crosscheck")
HARNESS_KEYS = ("event_id", "@timestamp")  # added by the harness, not part of the event
SAMPLE = 20  # event ids kept per rule and side in disagreements.json; the counts are complete


def rule_set() -> dict[str, pathlib.Path]:
    """The Phase 2 rule set: the in-scope rules plus every rule with SigmaHQ regression data."""
    rules: dict[str, pathlib.Path] = {}
    for line in open("results/phase0/inscope_rules.jsonl", encoding="utf-8"):
        r = json.loads(line)
        rules[r["id"]] = SIGMA / r["path"]
    for c in json.loads((PHASE2 / "regression_cases.json").read_text(encoding="utf-8")):
        rules.setdefault(c["rule_id"], SIGMA / c["rule_path"])
    return rules


def load_events(dataset: str) -> list[tuple[str, Event]]:
    stamp = datetime.datetime(2026, 1, 1, tzinfo=datetime.timezone.utc)
    out = []
    for line in open(PHASE2 / f"{dataset}_events.jsonl", encoding="utf-8"):
        e = json.loads(line)
        data = {k: v for k, v in e.items() if k not in HARNESS_KEYS}
        out.append((e["event_id"], Event(timestamp=stamp, logsource=EventLogSource(), data=data)))
    return out


def evaluator_hits(dataset: str) -> dict[str, set[str]]:
    hits = json.loads((PHASE2 / dataset / "hits.json").read_text(encoding="utf-8"))["evaluator"]["neutral"]
    out: dict[str, set[str]] = collections.defaultdict(set)
    for h in hits:
        out[h["rule_id"]].add(h["event_id"])
    return out


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("dataset", choices=("regression", "evtx-attack-samples"))
    args = ap.parse_args(argv)
    warnings.filterwarnings("ignore")
    t0 = time.time()
    rules, events = rule_set(), load_events(args.dataset)
    ev_errors = json.loads((PHASE2 / args.dataset / "rule_errors.json").read_text(encoding="utf-8"))
    ev_errors = set(ev_errors.get("evaluator", ev_errors) if isinstance(ev_errors, dict) else ev_errors)
    expected = evaluator_hits(args.dataset)
    compiler = MatchCompiler()
    errors: dict[str, str] = {}
    rows, agree, differ = [], 0, 0
    for rid, path in sorted(rules.items()):
        try:
            rule = next(r for r in SigmaCollection.from_yaml(path.read_text(encoding="utf-8")).rules
                        if isinstance(r, SigmaRule))
            matcher = compiler.compile_rule(rule)
        except Exception as exc:  # noqa: BLE001 - every failure is recorded, none is fatal
            errors[rid] = f"{type(exc).__name__}: {exc}"
            continue
        if rid in ev_errors:
            continue
        got = set()
        for eid, ev in events:
            try:
                if matcher(ev.data, ev.get_raw()):
                    got.add(eid)
            except Exception as exc:  # noqa: BLE001
                errors[rid] = f"match {type(exc).__name__}: {exc}"
                break
        if rid in errors:
            continue
        exp = expected.get(rid, set())
        if got == exp:
            agree += 1
        else:
            differ += 1
            only_e, only_m = sorted(exp - got), sorted(got - exp)
            rows.append({"rule_id": rid, "path": str(path),
                         "only_evaluator_count": len(only_e), "only_evaluator": only_e[:SAMPLE],
                         "only_matcher_count": len(only_m), "only_matcher": only_m[:SAMPLE]})
    summary = {"dataset": args.dataset, "events": len(events), "rules": len(rules),
               "evaluator_rule_errors": len(ev_errors), "matcher_rule_errors": len(errors),
               "rules_compared": agree + differ, "rules_agree": agree, "rules_differ": differ,
               "pairs_only_evaluator": sum(r["only_evaluator_count"] for r in rows),
               "pairs_only_matcher": sum(r["only_matcher_count"] for r in rows),
               "seconds": round(time.time() - t0, 1)}
    out = OUT / args.dataset
    out.mkdir(parents=True, exist_ok=True)
    (out / "summary.json").write_text(json.dumps(summary, indent=1) + "\n", encoding="utf-8")
    (out / "disagreements.json").write_text(json.dumps(rows, indent=1) + "\n", encoding="utf-8")
    (out / "matcher_errors.json").write_text(json.dumps(errors, indent=1, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(summary, indent=1))
    return 0


if __name__ == "__main__":
    sys.exit(main())
