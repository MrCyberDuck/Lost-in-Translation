"""Every spec clause in docs/spec-clauses.md has exactly one primary area in docs/taxonomy.md."""
import collections
import pathlib
import re

DOCS = pathlib.Path(__file__).resolve().parent.parent / "docs"


def _clauses():
    text = (DOCS / "spec-clauses.md").read_text(encoding="utf-8")
    return sorted({int(m) for m in re.findall(r"^\| S(\d+) \|", text, re.M)})


def _coverage():
    text = (DOCS / "taxonomy.md").read_text(encoding="utf-8")
    section = text.split("## 6. Clause coverage", 1)[1].split("\n## ", 1)[0]
    rows = re.findall(r"^\| S(\d+) \| (T\d+) \|([^|]*)\|", section, re.M)
    return section, [(int(s), p, [x.strip() for x in sec.split(",") if x.strip()]) for s, p, sec in rows]


def _areas():
    text = (DOCS / "taxonomy.md").read_text(encoding="utf-8")
    return set(re.findall(r"^### (T\d+)\. ", text, re.M))


def test_every_clause_has_one_primary_area():
    _, rows = _coverage()
    counts = collections.Counter(s for s, _, _ in rows)
    assert sorted(counts) == _clauses()
    assert all(n == 1 for n in counts.values()), [s for s, n in counts.items() if n > 1]


def test_areas_exist():
    _, rows = _coverage()
    areas = _areas()
    for s, primary, secondary in rows:
        assert primary in areas, (s, primary)
        assert all(a in areas for a in secondary), (s, secondary)


def test_per_area_counts_match_table():
    section, rows = _coverage()
    counts = collections.Counter(p for _, p, _ in rows)
    line = re.search(r"Clauses per primary area: (.*)\.", section).group(1)
    stated = {a: int(n) for a, n in re.findall(r"(T\d+) (\d+)", line)}
    assert stated == dict(counts)


def test_layer_table_matches_area_table():
    text = (DOCS / "taxonomy.md").read_text(encoding="utf-8")
    glance = text.split("## 4. Areas at a glance", 1)[1].split("\n## ", 1)[0]
    from_areas = collections.defaultdict(set)
    for area, layers in re.findall(r"^\| (T\d+) \| [^|]+ \| [^|]+ \| ([^|]+) \|", glance, re.M):
        for layer in layers.split(","):
            from_areas[layer.strip()].add(area)
    table = text.split("### 3.1 Layer", 1)[1].split("\n### ", 1)[0]
    from_layers = {l: set(re.findall(r"T\d+", areas))
                   for l, areas in re.findall(r"^\| (L[1-7]) \| [^|]+ \| [^|]+ \| ([^|]+) \|", table, re.M)}
    assert set(from_layers) == {f"L{i}" for i in range(1, 8)}
    assert all(from_layers.values())
    assert from_layers == dict(from_areas)
