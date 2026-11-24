"""Real-event datasets for Phase 2: EVTX files turned into canonical events.

EVTX is parsed once with `chainsaw dump --json` (the Rust `evtx` crate, which Hayabusa also
uses), so the evaluator and both native engines read the same records. Each record becomes a
flat canonical event (harness/events.py) with `event_id = "<evtx path>#<EventRecordID>"`.

    python -m harness.datasets regression     # SigmaHQ regression_data -> results/phase2/
    python -m harness.datasets evtx DIR NAME  # any folder of .evtx files
"""
from __future__ import annotations

import argparse
import json
import pathlib
import subprocess
import sys
from typing import Any

import yaml

from .native import CHAINSAW

SIGMA = pathlib.Path("rules/sigma")
OUT = pathlib.Path("results/phase2")


def flatten(record: dict, event_id: str) -> dict[str, Any]:
    """Flatten one `chainsaw dump --json` record to Sigma field names.

    System: `X_attributes: {A: v}` becomes `X_A` (Provider_Name, Execution_ProcessID, ...),
    TimeCreated_SystemTime becomes `@timestamp`. EventData `Name=value` pairs become fields;
    unnamed `<Data>` elements become the multi-valued field `Data` (S87, S44).
    UserData has one wrapper element; its children become fields (S86).
    """
    ev = record["Event"]
    out: dict[str, Any] = {"event_id": event_id}
    for key, val in (ev.get("System") or {}).items():
        if key.endswith("_attributes") and isinstance(val, dict):
            base = key[: -len("_attributes")]
            for ak, av in val.items():
                out[f"{base}_{ak}"] = av
        elif isinstance(val, dict) and "#text" in val:
            out[key] = val["#text"]
        else:
            out[key] = val
    out["@timestamp"] = out.pop("TimeCreated_SystemTime", None) or "1970-01-01T00:00:00Z"
    data = ev.get("EventData")
    if isinstance(data, dict):
        for key, val in data.items():
            if key.endswith("_attributes"):
                continue
            if isinstance(val, dict) and "#text" in val:  # unnamed <Data> elements (S87)
                val = val["#text"]
            out.setdefault(key, val)
    user = ev.get("UserData")
    if isinstance(user, dict):
        from_user = []
        for key, val in user.items():
            if key.endswith("_attributes"):
                continue
            items = val.items() if isinstance(val, dict) else [(key, val)]
            for k2, v2 in items:
                if not k2.endswith("_attributes") and k2 not in out:
                    out[k2] = v2
                    from_user.append(k2)
        if from_user:
            out["@userdata"] = from_user  # provenance for harness/explain.py; not log content
    return out


def dump_evtx(path: pathlib.Path) -> list[dict]:
    res = subprocess.run([str(CHAINSAW), "dump", str(path), "--json", "-q"],
                         capture_output=True, text=True, check=True)
    return json.loads(res.stdout or "[]")


def events_from_evtx(paths: list[pathlib.Path], root: pathlib.Path) -> list[dict]:
    events = []
    for path in paths:
        rel = path.relative_to(root).as_posix()
        for rec in dump_evtx(path):
            rid = rec["Event"]["System"].get("EventRecordID")
            events.append(flatten(rec, f"{rel}#{rid}"))
    ids = [e["event_id"] for e in events]
    if len(ids) != len(set(ids)):
        raise ValueError("duplicate event ids")
    return events


def rule_index(sigma: pathlib.Path = SIGMA) -> dict[str, pathlib.Path]:
    """Rule id -> rule file, over every rule folder of the SigmaHQ checkout."""
    index = {}
    for path in sigma.rglob("*.yml"):
        if "regression_data" in path.parts or ".github" in path.parts:
            continue
        try:
            doc = yaml.safe_load(path.read_text(encoding="utf-8"))
        except yaml.YAMLError:
            continue
        if isinstance(doc, dict) and doc.get("id") and "detection" in doc:
            index[str(doc["id"])] = path
    return index


def regression_cases(sigma: pathlib.Path = SIGMA) -> list[dict]:
    """One case per (rule, evtx) pair listed in a regression_data info.yml."""
    in_scope = {json.loads(l)["id"] for l in open("results/phase0/inscope_rules.jsonl", encoding="utf-8")}
    index = rule_index(sigma)
    cases = []
    for info in sorted((sigma / "regression_data").rglob("info.yml")):
        doc = yaml.safe_load(info.read_text(encoding="utf-8"))
        for meta in doc.get("rule_metadata", []):
            rid = str(meta["id"])
            for test in doc.get("regression_tests_info", []):
                if test.get("type") != "evtx":
                    continue
                evtx = info.parent / pathlib.Path(test["path"]).name
                cases.append({
                    "rule_id": rid,
                    "rule_path": index[rid].relative_to(sigma).as_posix() if rid in index else None,
                    "evtx": evtx.relative_to(sigma).as_posix(),
                    "test": test.get("name"),
                    "in_scope": rid in in_scope,
                })
    return cases


def main(argv: list[str]) -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("regression")
    p = sub.add_parser("evtx")
    p.add_argument("folder")
    p.add_argument("name")
    args = ap.parse_args(argv)
    OUT.mkdir(parents=True, exist_ok=True)
    if args.cmd == "regression":
        cases = regression_cases()
        (OUT / "regression_cases.json").write_text(json.dumps(cases, indent=1) + "\n", encoding="utf-8")
        paths = sorted({SIGMA / c["evtx"] for c in cases})
        events = events_from_evtx(paths, SIGMA)
        name = "regression"
    else:
        root = pathlib.Path(args.folder)
        events = events_from_evtx(sorted(root.rglob("*.evtx")), root)
        name = args.name
    with open(OUT / f"{name}_events.jsonl", "w", encoding="utf-8") as fh:
        for e in events:
            fh.write(json.dumps(e, ensure_ascii=False, sort_keys=True) + "\n")
    print(f"{len(events)} events -> {OUT / f'{name}_events.jsonl'}")


if __name__ == "__main__":
    main(sys.argv[1:])
