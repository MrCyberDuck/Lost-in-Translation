"""Explain every evaluator-vs-native disagreement by emulating the native engine's behaviour.

    python -m harness.explain regression
    python -m harness.explain evtx-attack-samples

Each native engine differs from the spec in a few specific ways ("mechanisms"), found by
reading its documentation and mapping files and by probe rules (docs/phase2.md, section 3).
This module re-runs the reference evaluator with those mechanisms switched on and checks:

1. **Completeness:** with all of an engine's mechanisms on, does the emulated evaluator give
   exactly the engine's match set? Pairs it still gets wrong are the *residual*, which must be
   triaged by hand (or point at an evaluator bug).
2. **Attribution:** for each disagreeing (rule, event) pair, which single mechanisms flip the
   spec answer to the engine's answer. The pair's triage label comes from the clauses those
   mechanisms touch (harness/triage.py), so ambiguous clauses always give `spec-gap`.

Output: results/phase2/<dataset>/explained.json.
"""
from __future__ import annotations

import collections
import json
import pathlib
import sys
from dataclasses import dataclass, field
from typing import Callable

import yaml

from . import native
from .evaluator.core import HARNESS_FIELDS, RuleError, Semantics, compile_rule, normalise_fields
from .events import load_jsonl
from .phase2 import OUT, SIGMA, rule_set
from .triage import classify, open_clauses

Event = dict


@dataclass
class Mechanism:
    key: str
    engine: str
    description: str
    clauses: list[str]               # spec clauses the engine departs from
    kind: str                        # "semantics" (engine logic) or "config" (mapping/ingest)
    sem: dict = field(default_factory=dict)         # Semantics flags
    view: Callable[[Event], Event] | None = None    # event transformation
    production_only: bool = False


# ---------------------------------------------------------------- Chainsaw


def _chainsaw_fields() -> set[str]:
    doc = yaml.safe_load(native.CHAINSAW_MAPPING.read_text(encoding="utf-8"))
    names = set()
    for group in doc.get("groups", []):
        for f in group.get("fields", []):
            if "from" in f:
                names.add(f["from"])
    # System fields are reached as Event.System.X; Provider_Name is mapped as Provider.
    return names | {"EventID", "Channel", "Computer", "EventRecordID", "Provider_Name"}


def _only_fields(allowed: set[str]) -> Callable[[Event], Event]:
    return lambda e: {k: v for k, v in e.items() if k in allowed or k in HARNESS_FIELDS}


def _no_userdata(e: Event) -> Event:
    drop = set(e.get("@userdata") or [])
    return {k: v for k, v in e.items() if k not in drop} if drop else e


def chainsaw_preconditions() -> tuple[dict, set[str]]:
    """Logsource -> list of (provider, event ids) filters, and excluded rule titles."""
    doc = yaml.safe_load(native.CHAINSAW_MAPPING.read_text(encoding="utf-8"))
    out: dict[tuple[str, str], list[tuple[str | None, set[int] | None]]] = {}
    for pre in (doc.get("extensions") or {}).get("preconditions") or []:
        (key, val), = pre["for"].items()
        filters = pre["filter"] if isinstance(pre["filter"], list) else [pre["filter"]]
        parsed = []
        for f in filters:
            ids = f.get("int(EventID)")
            if ids is not None:
                ids = {int(i) for i in (ids if isinstance(ids, list) else [ids])}
            parsed.append((f.get("Provider"), ids))
        out[(key.split(".")[-1], str(val))] = parsed  # logsource.category / logsource.service / id
    return out, set(doc.get("exclusions") or [])


def chainsaw_logsource(rule, pre) -> Callable[[Event], bool] | None:
    ls = rule.logsource
    filters = pre.get(("id", str(rule.id)))
    if filters is None and ls.category:
        filters = pre.get(("category", ls.category))
    if filters is None and ls.service:
        filters = pre.get(("service", ls.service))
    if filters is None:
        return None  # no precondition: the rule runs on every event

    def ok(e: Event) -> bool:
        for provider, ids in filters:
            if provider is not None and e.get("Provider_Name") != provider:
                continue
            if ids is not None and e.get("EventID") not in ids:
                continue
            return True
        return False

    return ok


def chainsaw_mechanisms() -> list[Mechanism]:
    return [
        Mechanism("C1", "chainsaw", "only fields listed in the mapping file are reachable", [], "config",
                  view=_only_fields(_chainsaw_fields())),
        Mechanism("C2", "chainsaw", "event field names with spaces are not stripped", ["S85"], "config"),
        Mechanism("C3", "chainsaw", "UserData fields are not reachable (mapping points at EventData)", ["S86"], "config",
                  view=_no_userdata),
        Mechanism("C4", "chainsaw", "a test on a missing field is unknown; NOT of unknown stays unknown, so "
                  "`sel and not filter` fails when the filter's field is missing", ["S25"], "semantics",
                  sem={"three_valued_missing": True}),
        Mechanism("C5", "chainsaw", "`field: null` matches only a present JSON null, not a missing field", ["S24"],
                  "semantics", sem={"null_explicit_only": True}),
        Mechanism("C6", "chainsaw", "a string in the rule ('true') does not match a boolean event value", ["S11", "S39"],
                  "semantics", sem={"strict_bool": True}),
        Mechanism("C8", "chainsaw", "a number in the rule (3389) does not match a string event value ('3389')",
                  ["S11"], "semantics", sem={"strict_number": True}),
        Mechanism("C7", "chainsaw", "logsource preconditions by Provider/EventID (process_creation also 4688; "
                  "unlisted categories and services run on every event)", ["S37"], "config",
                  production_only=True),
        Mechanism("C9", "chainsaw", "rules listed by title under `exclusions` in the mapping file never run",
                  [], "config", production_only=True),
    ]


# ---------------------------------------------------------------- Hayabusa


def _strip_values(e: Event) -> Event:
    return {k: (v.strip() if isinstance(v, str) and k not in HARNESS_FIELDS else v) for k, v in e.items()}


def _ps_classic_fields(e: Event) -> Event:
    """Port of Hayabusa 4.4.0 src/detections/field_extract.rs: for channel "Windows PowerShell",
    event ids 400/403/600/800, split Data[1] (800) or Data[2] (others) into Key=Value fields."""
    if e.get("Channel") != "Windows PowerShell" or str(e.get("EventID")) not in ("400", "403", "600", "800"):
        return e
    data = e.get("Data")
    idx = 1 if str(e.get("EventID")) == "800" else 2
    if not isinstance(data, list) or len(data) <= idx or not isinstance(data[idx], str):
        return e
    out = dict(e)
    for line in data[idx].strip().split("\n\t"):
        line = line.removesuffix("\r\n").removesuffix("\r")
        if "=" in line:
            k, v = line.split("=", 1)
            out[k] = v
    return out


def hayabusa_mechanisms() -> list[Mechanism]:
    return [
        Mechanism("H1", "hayabusa", "leading/trailing spaces in event values are trimmed before matching",
                  ["S3", "S45"], "semantics", view=_strip_values),
        Mechanism("H2", "hayabusa", "events without a Channel are not evaluated", ["S36"], "config",
                  view=lambda e: e if e.get("Channel") else {}),
        Mechanism("H3", "hayabusa", "raw SigmaHQ rules: field names with spaces are not stripped "
                  "(the converter adds the renames)", ["S85"], "config"),
        Mechanism("H4", "hayabusa", "PowerShell classic (400/600/800) `Data` text is split into fields "
                  "such as CommandLine and HostApplication", ["S87"], "config", view=_ps_classic_fields),
    ]


# ---------------------------------------------------------------- emulation


def _run(comp_cache, rid, events, mechs: list[Mechanism], config: str, cs_pre=None) -> set[str]:
    sem = Semantics(**{k: v for m in mechs for k, v in m.sem.items()})
    key = (rid, sem)
    if key not in comp_cache:
        comp_cache[key] = compile_rule(comp_cache[("src", rid)], sem)
    comp = comp_cache[key]
    keys = {m.key for m in mechs}
    out = set()
    lsf = None
    if config == "production":
        if "C9" in keys and comp.rule.title in cs_pre[1]:
            return set()
        if "C7" in keys:
            lsf = chainsaw_logsource(comp.rule, cs_pre[0])
        elif comp.logsource_error is None:
            lsf = comp.logsource_filter
    for e in events:
        if not ({"C2", "H3"} & keys):
            e = normalise_fields(e)
        for m in mechs:
            if m.view:
                e = m.view(e)
        if not e:
            continue
        if lsf is not None and not lsf(e):
            continue
        if comp.predicate(e):
            out.add(e["event_id"])
    return out


def explain(dataset: str) -> dict:
    out_dir = OUT / dataset
    hits = json.loads((out_dir / "hits.json").read_text(encoding="utf-8"))
    rules = rule_set()
    events = load_jsonl(OUT / f"{dataset}_events.jsonl")
    by_id = {e["event_id"]: e for e in events}
    cs_pre = chainsaw_preconditions()
    result = {"dataset": dataset, "mechanisms": {}, "engines": {}}
    comp_cache: dict = {}
    for rid, info in rules.items():
        comp_cache[("src", rid)] = info["path"].read_text(encoding="utf-8")

    conv = native.converted_rules({rid: info["path"] for rid, info in rules.items()})
    variants = {rid: {v for _, v in conv.get(rid, [])} for rid in rules}
    for engine, mechs in (("chainsaw", chainsaw_mechanisms()), ("hayabusa", hayabusa_mechanisms())):
        for m in mechs:
            result["mechanisms"][m.key] = {"engine": engine, "description": m.description, "clauses": m.clauses,
                                           "kind": m.kind}
        eng_res = {}
        for config in ("neutral", "production"):
            ev_sets = collections.defaultdict(set)
            for h in hits["evaluator"][config]:
                ev_sets[h["rule_id"]].add(h["event_id"])
            nat_hits = hits[engine][config]
            if engine == "hayabusa" and config == "production":
                nat_hits = [h for h in nat_hits
                            if h["variant"] == ("sysmon" if "sysmon" in variants.get(h["rule_id"], ()) else "builtin")]
            nat_sets = collections.defaultdict(set)
            for h in nat_hits:
                nat_sets[h["rule_id"]].add(h["event_id"])
            active = [m for m in mechs if config == "production" or not m.production_only]
            if engine == "hayabusa" and config == "production":
                active = [m for m in active if m.key == "H1"]  # converted rules: H2 to H4 do not apply
            pairs, residual = [], []
            # same rule sets as harness/phase2.py
            skip = set(json.loads((OUT / "chainsaw_unloadable.json").read_text(encoding="utf-8"))) \
                if engine == "chainsaw" else set()
            if engine == "hayabusa" and config == "production":
                skip = {r for r in rules if r not in conv}
            for rid in [r for r in rules if r not in skip]:
                spec, nat = ev_sets.get(rid, set()), nat_sets.get(rid, set())
                if spec == nat:
                    continue
                touched = spec ^ nat
                try:
                    emul_all = _run(comp_cache, rid, [by_id[e] for e in touched], active, config, cs_pre)
                except RuleError:
                    continue
                for ev in sorted(touched):
                    engine_says = ev in nat
                    flips = []
                    for m in active:
                        try:
                            got = ev in _run(comp_cache, rid, [by_id[ev]], [m], config, cs_pre)
                        except RuleError:
                            continue
                        if got == engine_says:
                            flips.append(m.key)
                    if not flips:  # no single mechanism: look for a pair that is needed together
                        for i, a in enumerate(active):
                            for b in active[i + 1:]:
                                if (ev in _run(comp_cache, rid, [by_id[ev]], [a, b], config, cs_pre)) == engine_says:
                                    flips.append(f"{a.key}&{b.key}")
                    explained = (ev in emul_all) == engine_says
                    row = {"rule_id": rid, "rule_path": info_path(rules, rid), "event_id": ev,
                           "spec": ev in spec, engine: engine_says, "mechanisms": flips,
                           "explained_by_all": explained}
                    row["label"] = label(row, result["mechanisms"], config)
                    (pairs if explained or flips else residual).append(row)
            eng_res[config] = {"disagreeing_pairs": len(pairs) + len(residual), "explained": len(pairs),
                               "residual": residual, "pairs": pairs,
                               "by_mechanism": dict(collections.Counter("+".join(p["mechanisms"]) or "combination"
                                                                       for p in pairs)),
                               "by_label": dict(collections.Counter(p["label"] for p in pairs))}
        result["engines"][engine] = eng_res
    (out_dir / "explained.json").write_text(json.dumps(result, indent=1) + "\n", encoding="utf-8")
    return result


def info_path(rules, rid) -> str:
    return rules[rid]["path"].relative_to(SIGMA).as_posix()


def label(row: dict, mechanisms: dict, config: str) -> str:
    """Triage label for one explained pair.

    `mechanisms` lists alternatives: each entry alone (or `A&B` together) reproduces the
    engine's answer. Conservative rule (decision of 23 Nov 2026): if any explaining mechanism
    touches an ambiguous or contradictory clause, the pair is a `spec-gap`. Otherwise, if every
    mechanism involved is the engine's configuration (mapping, field list, logsource), it is
    `config`; otherwise it is a `backend-bug` with cause `engine`.
    """
    keys = [k for entry in row["mechanisms"] for k in entry.split("&")]
    if not keys:
        return "unexplained"
    clauses = sorted({c for k in keys for c in mechanisms[k]["clauses"]})
    if open_clauses(clauses):
        return "spec-gap"
    needed = [set(entry.split("&")) for entry in row["mechanisms"]]
    if any(all(mechanisms[k]["kind"] == "config" for k in alt) for alt in needed):
        return "config"
    return classify(clauses, cause="engine")["verdict"]


def main(argv: list[str]) -> None:
    res = explain(argv[0])
    for engine, by_cfg in res["engines"].items():
        for cfg, r in by_cfg.items():
            print(engine, cfg, {k: v for k, v in r.items() if k not in ("pairs", "residual")}, "residual:", len(r["residual"]))


if __name__ == "__main__":
    main(sys.argv[1:])
