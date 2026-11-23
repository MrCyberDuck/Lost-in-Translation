"""Phase 1 smoke test: ingest 3 known events into each engine, run 1 converted rule, expect 1 hit.

With --case it runs any single conformance case folder the same way.

Usage:
    python -m harness.smoke --wave a      # Elasticsearch, OpenSearch, Loki, SQLite
    python -m harness.smoke --wave b      # Splunk, Kusto emulator, SQLite
    python -m harness.smoke --wave all

Exit code 0 only if every target of the selected wave returns exactly the expected event ids.
Results and a run manifest are written to results/runs/<run_id>/.
"""
from __future__ import annotations

import argparse
import datetime as dt
import json
import pathlib
import sys
import traceback

from . import manifest
from .config import Config
from .convert import convert
from .engines import TARGET_ENGINE, WAVES, make_engines
from .events import load_jsonl

SMOKE = pathlib.Path("conformance/smoke")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--wave", choices=["a", "b", "all"], default="all")
    ap.add_argument("--case", default=str(SMOKE),
                    help="folder with rule.yml, events.jsonl, expected.json (default: the smoke case)")
    args = ap.parse_args()
    case = pathlib.Path(args.case)

    run_id = case.name.replace("-", "_") + "_" + dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dt%H%M%S")
    engine_keys = sorted(set(WAVES["a"] + WAVES["b"])) if args.wave == "all" else WAVES[args.wave]
    engines = make_engines(Config())
    rule = (case / "rule.yml").read_text(encoding="utf-8")
    events = load_jsonl(case / "events.jsonl")
    expected = set(json.loads((case / "expected.json").read_text()))

    results, engine_info, ok = [], {}, True
    for key in engine_keys:
        eng = engines[key]
        info = {"targets": list(eng.targets)}
        try:
            info["health"] = eng.health()
            eng.load(run_id, events)
            info["storage"] = eng.storage_notes()
        except Exception as exc:  # noqa: BLE001
            info["error"] = f"{type(exc).__name__}: {exc}"
            engine_info[key] = info
            ok = False
            print(f"[FAIL] {key:13s} engine not ready: {info['error']}")
            for t in eng.targets:
                results.append({"target": t, "engine": key, "status": "engine_error"})
            continue
        engine_info[key] = info
        for target in eng.targets:
            assert TARGET_ENGINE[target] == key
            conv = convert(rule, target)
            row = {"target": target, "engine": key, "queries": conv.queries}
            if conv.error:
                row.update(status="conversion_error", error=conv.error)
                ok = False
            else:
                try:
                    got: set[str] = set()
                    for q in conv.queries:
                        got |= eng.query(run_id, target, q)
                    row.update(matched=sorted(got),
                               status="pass" if got == expected else "fail")
                    ok &= got == expected
                except Exception as exc:  # noqa: BLE001
                    row.update(status="query_error", error=f"{type(exc).__name__}: {exc}",
                               trace=traceback.format_exc(limit=3))
                    ok = False
            results.append(row)
            mark = "PASS" if row["status"] == "pass" else "FAIL"
            detail = row.get("matched", row.get("error", ""))
            print(f"[{mark}] {target:17s} on {key:13s} -> {detail}")

    out = pathlib.Path("results/runs") / run_id
    manifest.write(out / "manifest.json", manifest.build(run_id, engine_info, {"wave": args.wave, "case": str(case)}))
    (out / "results.json").write_text(json.dumps(results, indent=2), encoding="utf-8")
    print(f"\n{'ALL PASS' if ok else 'FAILURES'}; results in {out}/")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
