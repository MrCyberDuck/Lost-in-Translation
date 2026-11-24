"""Phase 2: run the reference evaluator, Chainsaw and Hayabusa on real EVTX and compare.

    python -m harness.phase2 regression
    python -m harness.phase2 evtx-attack-samples --scan-dir DIR

Rule set: the 2,247 in-scope rules plus every rule that has SigmaHQ regression data.
Each run writes results/phase2/<dataset>/: hits.json (every engine's (rule, event) matches
per config), rule_errors.json, summary.json and disagreements.json (one row per rule whose
match sets differ, for triage).
"""
from __future__ import annotations

import argparse
import collections
import json
import pathlib
import sys
import time

import yaml

from . import manifest, native
from .evaluator import RuleError, compile_rule, evaluate
from .events import load_jsonl

SIGMA = pathlib.Path("rules/sigma")
OUT = pathlib.Path("results/phase2")
ENGINES = ("evaluator", "chainsaw", "hayabusa")


def rule_set() -> dict[str, dict]:
    rules: dict[str, dict] = {}
    for line in open("results/phase0/inscope_rules.jsonl", encoding="utf-8"):
        r = json.loads(line)
        rules[r["id"]] = {"path": SIGMA / r["path"], "in_scope": True}
    for c in json.loads((OUT / "regression_cases.json").read_text(encoding="utf-8")):
        rules.setdefault(c["rule_id"], {"path": SIGMA / c["rule_path"], "in_scope": False})
    return rules


def run_evaluator(rules: dict[str, dict], events: list[dict]) -> tuple[dict, dict, dict]:
    hits = {"neutral": [], "production": []}
    errors: dict[str, str] = {}
    meta: dict[str, dict] = {}
    for rid, info in rules.items():
        try:
            comp = compile_rule(info["path"].read_text(encoding="utf-8"))
        except RuleError as exc:
            errors[rid] = str(exc)
            continue
        meta[rid] = {"out_of_spec": comp.out_of_spec, "clauses": sorted(comp.clauses),
                     "logsource_error": comp.logsource_error}
        for e in evaluate(comp, events, "neutral"):
            hits["neutral"].append({"rule_id": rid, "event_id": e})
        if comp.logsource_error is None:
            for e in evaluate(comp, events, "production"):
                hits["production"].append({"rule_id": rid, "event_id": e})
    return hits, errors, meta


def run_native(rules: dict[str, dict], scan_dir: pathlib.Path, root: pathlib.Path, work: pathlib.Path):
    paths = [info["path"] for info in rules.values()]
    chainsaw = {c: native.run_chainsaw(paths, scan_dir, root, c, work) for c in ("neutral", "production")}
    original = [(info["path"], rid, "original") for rid, info in rules.items()]
    conv = native.converted_rules({rid: info["path"] for rid, info in rules.items()})
    converted = [(p, rid, variant) for rid, items in conv.items() for p, variant in items]
    hayabusa = {
        "neutral": native.run_hayabusa(original, scan_dir, root, "neutral", work),
        "production": native.run_hayabusa(converted, scan_dir, root, "production", work),
    }
    return chainsaw, hayabusa, conv


def _sets(hits: list[dict], variant: str | None = None) -> dict[str, set[str]]:
    out: dict[str, set[str]] = collections.defaultdict(set)
    for h in hits:
        if variant is None or h.get("variant") == variant:
            out[h["rule_id"]].add(h["event_id"])
    return out


def compare(rules, hits_by_engine, eval_errors, conv, config, unloadable=None) -> tuple[dict, list[dict]]:
    """Rule-level agreement for one config.

    A pair of engines is compared only on rules both can run: the evaluator's rule errors,
    rules Chainsaw cannot load (`unloadable`), and in production rules Hayabusa has no
    converted version for are left out of the pairs that involve that engine.
    """
    cannot = {"evaluator": set(eval_errors), "chainsaw": set(unloadable or ()),
              "hayabusa": set() if config == "neutral" else {r for r in rules if r not in conv}}
    sets = {eng: _sets(hits_by_engine[eng][config]) for eng in ENGINES}
    if config == "production":
        # Hayabusa production: like-for-like is the sysmon variant where one exists, else the
        # builtin one (service rules); builtin variants next to a sysmon one are an extra log
        # source (Security 4688 etc.), reported separately as config.
        hb = hits_by_engine["hayabusa"][config]
        sysmon, builtin_all = _sets(hb, "sysmon"), _sets(hb, "builtin")
        variants = {rid: {v for _, v in conv.get(rid, [])} for rid in rules}
        sets["hayabusa"] = {rid: (sysmon.get(rid, set()) if "sysmon" in variants[rid] else builtin_all.get(rid, set()))
                            for rid in rules}
        builtin = {rid: builtin_all.get(rid, set()) for rid in rules if "sysmon" in variants[rid]}
    else:
        builtin = {}
    comparable = [rid for rid in rules if rid not in eval_errors]
    pairs = {f"{a}-{b}": {"rules_agree": 0, "rules_differ": 0, "pairs_both": 0, "pairs_only_a": 0, "pairs_only_b": 0}
             for a, b in (("evaluator", "chainsaw"), ("evaluator", "hayabusa"), ("chainsaw", "hayabusa"))}
    rows = []
    for rid in comparable:
        able = [eng for eng in ENGINES if rid not in cannot[eng]]
        s = {eng: sets[eng].get(rid, set()) for eng in able}
        for key, st in pairs.items():
            a, b = key.split("-")
            if a not in s or b not in s:
                st["rules_not_runnable"] = st.get("rules_not_runnable", 0) + 1
                continue
            sa, sb = s[a], s[b]
            st["rules_agree" if sa == sb else "rules_differ"] += 1
            st["pairs_both"] += len(sa & sb)
            st["pairs_only_a"] += len(sa - sb)
            st["pairs_only_b"] += len(sb - sa)
        if len({frozenset(v) for v in s.values()}) > 1:
            union = set().union(*s.values())
            rows.append({
                "rule_id": rid, "rule_path": rules[rid]["path"].relative_to(SIGMA).as_posix(),
                "in_scope": rules[rid]["in_scope"], "config": config, "engines": able,
                "events": {e: [eng for eng in able if e in s[eng]] for e in sorted(union)},
                "hayabusa_builtin_extra": sorted(builtin.get(rid, set())),
            })
    summary = {"rules_compared": len(comparable), "rules_all_agree": len(comparable) - len(rows),
               "rules_not_runnable": {eng: len(c) for eng, c in cannot.items()},
               "matches": {eng: sum(len(sets[eng].get(r, ())) for r in comparable if r not in cannot[eng])
                           for eng in ENGINES},
               "pairs": pairs}
    return summary, rows


def regression_positive(cases, hits_by_engine) -> dict:
    """SigmaHQ's own test: each rule must fire on at least one event of its EVTX."""
    out = {}
    for config in ("neutral", "production"):
        per = {}
        for eng in ENGINES:
            hits = hits_by_engine[eng][config]
            fired = {(h["rule_id"], h["event_id"].split("#")[0]) for h in hits}
            per[eng] = {c["rule_id"] + "|" + c["evtx"]: (c["rule_id"], c["evtx"]) in fired for c in cases}
        out[config] = per
    return out


def main(argv: list[str]) -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("dataset")
    ap.add_argument("--scan-dir", help="folder of EVTX files (default: SigmaHQ regression_data)")
    ap.add_argument("--root", help="event ids are relative to this folder (default: rules/sigma)")
    ap.add_argument("--reuse-hits", action="store_true", help="only recompute the comparison from hits.json")
    args = ap.parse_args(argv)
    scan_dir = pathlib.Path(args.scan_dir) if args.scan_dir else SIGMA / "regression_data"
    root = pathlib.Path(args.root) if args.root else (scan_dir if args.scan_dir else SIGMA)
    out = OUT / args.dataset
    work = (out / "work").resolve()
    work.mkdir(parents=True, exist_ok=True)

    rules = rule_set()
    events = load_jsonl(OUT / f"{args.dataset}_events.jsonl")
    t0 = time.time()
    if args.reuse_hits:  # recompute the comparison only, from a previous run's hits
        hits = json.loads((out / "hits.json").read_text(encoding="utf-8"))
        ev_errors = json.loads((out / "rule_errors.json").read_text(encoding="utf-8"))
        ev_meta = json.loads((out / "rule_meta.json").read_text(encoding="utf-8"))
        conv = native.converted_rules({rid: info["path"] for rid, info in rules.items()})
        t1 = t2 = time.time()
    else:
        ev_hits, ev_errors, ev_meta = run_evaluator(rules, events)
        t1 = time.time()
        cs_hits, hb_hits, conv = run_native(rules, scan_dir, root, work)
        t2 = time.time()
        hits = {"evaluator": ev_hits, "chainsaw": cs_hits, "hayabusa": hb_hits}
    unloadable = native.chainsaw_unloadable({rid: info["path"] for rid, info in rules.items()})

    summary = {"dataset": args.dataset, "events": len(events), "rules": len(rules),
               "rules_in_scope": sum(r["in_scope"] for r in rules.values()),
               "evaluator_rule_errors": len(ev_errors),
               "hayabusa_converted_rules": len(conv),
               "chainsaw_unloadable": unloadable,
               "seconds": (json.loads((out / "summary.json").read_text(encoding="utf-8"))["seconds"] if args.reuse_hits
                           else {"evaluator": round(t1 - t0, 1), "native": round(t2 - t1, 1)}),
               "versions": native.versions(), "manifest": manifest.collect() if hasattr(manifest, "collect") else None}
    rows = []
    for config in ("neutral", "production"):
        summary[config], r = compare(rules, hits, ev_errors, conv, config, unloadable)
        rows += r
    if args.dataset == "regression":
        cases = json.loads((OUT / "regression_cases.json").read_text(encoding="utf-8"))
        pos = regression_positive(cases, hits)
        summary["regression_positive"] = {
            cfg: {eng: sum(v.values()) for eng, v in per.items()} | {"cases": len(cases)} for cfg, per in pos.items()}
        (out / "regression_positive.json").write_text(json.dumps(pos, indent=1) + "\n", encoding="utf-8")
    (out / "hits.json").write_text(json.dumps(hits, indent=0) + "\n", encoding="utf-8")
    (out / "rule_errors.json").write_text(json.dumps(ev_errors, indent=1, sort_keys=True) + "\n", encoding="utf-8")
    (out / "rule_meta.json").write_text(json.dumps(ev_meta, indent=0, sort_keys=True) + "\n", encoding="utf-8")
    (out / "disagreements.json").write_text(json.dumps(rows, indent=1) + "\n", encoding="utf-8")
    (out / "summary.json").write_text(json.dumps(summary, indent=1, default=str) + "\n", encoding="utf-8")
    print(json.dumps({k: v for k, v in summary.items() if k != "manifest"}, indent=1, default=str))


if __name__ == "__main__":
    main(sys.argv[1:])
