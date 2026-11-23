"""Select the in-scope SigmaHQ rules (Phase 0) and write the list plus counts.

In scope for the first paper (decision of 23 Nov 2026):
- rules from the main `rules/` folder of the pinned SigmaHQ release,
- logsource product `windows`,
- status `stable` or `test`,
- rules that pySigma can parse.

Usage:
    python -m harness.select_rules [--sigma rules/sigma] [--out results/phase0]
"""
from __future__ import annotations

import argparse
import collections
import json
import pathlib

from sigma.collection import SigmaCollection
from sigma.rule import SigmaRule

IN_SCOPE_STATUS = {"stable", "test"}


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--sigma", default="rules/sigma", help="path to the SigmaHQ checkout")
    ap.add_argument("--out", default="results/phase0", help="output folder")
    args = ap.parse_args()

    root = pathlib.Path(args.sigma)
    out = pathlib.Path(args.out)
    out.mkdir(parents=True, exist_ok=True)

    paths = sorted((root / "rules").rglob("*.yml"))
    counts: collections.Counter[str] = collections.Counter()
    by_category: collections.Counter[str] = collections.Counter()
    by_status: collections.Counter[str] = collections.Counter()
    selected: list[dict] = []
    parse_errors: list[dict] = []

    for p in paths:
        counts["files"] += 1
        try:
            coll = SigmaCollection.from_yaml(p.read_text(encoding="utf-8"), collect_errors=True)
        except Exception as exc:  # noqa: BLE001 - we record every failure
            parse_errors.append({"path": str(p.relative_to(root)), "error": repr(exc)})
            continue
        for rule in coll.rules:
            if rule.errors:
                parse_errors.append({"path": str(p.relative_to(root)),
                                     "error": "; ".join(repr(e) for e in rule.errors)})
                continue
            if not isinstance(rule, SigmaRule):
                counts["non_detection_rules"] += 1
                continue
            status = rule.status.name.lower() if rule.status else "none"
            product = (rule.logsource.product or "").lower()
            by_status[status] += 1
            if product != "windows":
                counts["other_product"] += 1
                continue
            counts["windows"] += 1
            if status not in IN_SCOPE_STATUS:
                counts["windows_out_of_status"] += 1
                continue
            cat = rule.logsource.category or f"service:{rule.logsource.service}"
            by_category[cat] += 1
            selected.append({
                "id": str(rule.id),
                "title": rule.title,
                "status": status,
                "category": rule.logsource.category,
                "service": rule.logsource.service,
                "path": str(p.relative_to(root)),
            })

    counts["selected"] = len(selected)
    counts["parse_errors"] = len(parse_errors)

    (out / "inscope_rules.jsonl").write_text(
        "".join(json.dumps(r, ensure_ascii=False) + "\n" for r in selected), encoding="utf-8")
    (out / "parse_errors.json").write_text(json.dumps(parse_errors, indent=2), encoding="utf-8")
    summary = {
        "counts": dict(counts),
        "status_all_products": dict(by_status.most_common()),
        "selected_by_logsource": dict(by_category.most_common()),
    }
    (out / "rule_counts.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()
