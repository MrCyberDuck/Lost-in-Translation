"""Build taxonomy_windows.json from the Sigma taxonomy appendix (Windows Folder tables).

    python -m harness.evaluator.build_taxonomy path/to/sigma-appendix-taxonomy.md

The appendix is read at spec commit ba9251aa834b11a70dbf80836b453dba99c5159e (docs/spec-clauses.md).
Categories mapped to an ETW provider instead of a channel (file_access, file_rename) get no
channels, so the production config reports them as unsupported.
"""
from __future__ import annotations

import json
import pathlib
import re
import sys

OUT = pathlib.Path(__file__).with_name("taxonomy_windows.json")


def _cells(line: str) -> list[str]:
    return [c.strip() for c in line.strip().strip("|").split("|")]


def _list_after(label: str, text: str) -> list[str]:
    """Values after `EventID:`/`EventIDs:`/`Channel:`; inline value or `<br> - x` items."""
    m = re.search(rf"{label}s?:\s*(.*?)(?=(?:<br>)?(?:EventIDs?|Channel|ETW Provider):|$)", text)
    if not m:
        return []
    body = m.group(1)
    items = [i.strip() for i in re.split(r"<br>\s*-\s*", body)]
    return [i.removesuffix("<br>").strip() for i in items if i.removesuffix("<br>").strip()]


def build(md: str) -> dict:
    section = md.split("### Windows Folder", 1)[1].split("## Network Events", 1)[0]
    out: dict[str, dict] = {"category": {}, "service": {}}
    for line in section.splitlines():
        if not line.startswith("| windows"):
            continue
        _, logsource, desc = _cells(line)[:3]
        m = re.search(r"(category|service):\s*([\w\-]+)", logsource)
        if not m:
            continue
        kind, name = m.groups()
        entry = {"channels": _list_after("Channel", desc)}
        if kind == "category":
            entry["event_ids"] = [int(x) for x in _list_after("EventID", desc)]
        out[kind][name] = entry
    return out


def main(argv: list[str]) -> None:
    data = build(pathlib.Path(argv[0]).read_text(encoding="utf-8"))
    OUT.write_text(json.dumps(data, indent=1, sort_keys=True) + "\n", encoding="utf-8")
    print(f"{len(data['category'])} categories, {len(data['service'])} services -> {OUT}")


if __name__ == "__main__":
    main(sys.argv[1:])
