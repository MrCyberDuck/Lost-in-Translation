"""Count which Sigma constructs the in-scope rules use (Phase 0, spec-clause audit).

For every spec clause we want to know how many in-scope rules can be affected by it, so the
conformance suite and the full-corpus run can be prioritised.

Usage:
    python -m harness.construct_census [--sigma rules/sigma] [--scope results/phase0/inscope_rules.jsonl]
"""
from __future__ import annotations

import argparse
import collections
import json
import pathlib
import re

import yaml

RE_UNSUPPORTED = {
    # metacharacters outside the spec's PCRE subset (modifiers appendix, `re`)
    "shorthand_class": re.compile(r"\\[dDwWsSbB]"),
    "lookaround": re.compile(r"\(\?[=!<]"),
    "non_capturing_group": re.compile(r"\(\?:"),
    "inline_flags": re.compile(r"\(\?[imsx]+\)"),
    "lazy_quantifier": re.compile(r"[*+?}]\?"),
    "backreference": re.compile(r"\\[1-9]"),
    "escape_hex_or_unicode": re.compile(r"\\[xu]"),
}


def walk_values(node):
    """Yield (field_with_modifiers or None for keywords, value) for every detection value."""
    if isinstance(node, dict):
        for key, val in node.items():
            vals = val if isinstance(val, list) else [val]
            for v in vals:
                if isinstance(v, (dict, list)):
                    yield from walk_values(v)
                else:
                    yield key, v
    elif isinstance(node, list):
        for item in node:
            if isinstance(item, (dict, list)):
                yield from walk_values(item)
            else:
                yield None, item


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--sigma", default="rules/sigma")
    ap.add_argument("--scope", default="results/phase0/inscope_rules.jsonl")
    ap.add_argument("--out", default="results/phase0/construct_census.json")
    args = ap.parse_args()

    root = pathlib.Path(args.sigma)
    scope = [json.loads(line) for line in open(args.scope, encoding="utf-8")]
    rules_with: dict[str, set[str]] = collections.defaultdict(set)
    modifier_chains: collections.Counter[str] = collections.Counter()

    for r in scope:
        doc = yaml.safe_load((root / r["path"]).read_text(encoding="utf-8"))
        rid = r["id"]
        det = doc["detection"]
        cond = det.get("condition")
        conds = cond if isinstance(cond, list) else [cond]
        for c in conds:
            c = str(c)
            if re.search(r"\bnot\b", c):
                rules_with["condition:not"].add(rid)
            if re.search(r"\b1 of them\b|\ball of them\b", c):
                rules_with["condition:x_of_them"].add(rid)
            if re.search(r"\b(1|all) of \w*\*", c):
                rules_with["condition:x_of_pattern"].add(rid)
            if "(" in c:
                rules_with["condition:brackets"].add(rid)
            if re.search(r"\bor\b", c) and re.search(r"\band\b", c):
                rules_with["condition:mixed_and_or"].add(rid)
        if isinstance(cond, list):
            rules_with["condition:list"].add(rid)
        for ident, body in det.items():
            if ident == "condition":
                continue
            if ident.startswith("_"):
                rules_with["identifier:underscore"].add(rid)
            if isinstance(body, list) and body and all(isinstance(x, dict) for x in body):
                rules_with["selection:list_of_maps"].add(rid)
            for key, val in walk_values(body):
                field, *mods = (key.split("|") if key is not None else [None])
                chain = "|".join(mods)
                if mods:
                    modifier_chains[chain] += 1
                for m in mods:
                    rules_with[f"modifier:{m}"].add(rid)
                if key is None or field == "":
                    rules_with["keywords"].add(rid)
                if val is None:
                    rules_with["value:null"].add(rid)
                    continue
                if isinstance(val, bool):
                    rules_with["value:bool"].add(rid)
                    continue
                if isinstance(val, int):
                    rules_with["value:integer"].add(rid)
                    continue
                if isinstance(val, float):
                    rules_with["value:float"].add(rid)
                    continue
                s = str(val)
                if s == "":
                    rules_with["value:empty_string"].add(rid)
                if "re" in mods:
                    for name, pat in RE_UNSUPPORTED.items():
                        if pat.search(s):
                            rules_with[f"regex:{name}"].add(rid)
                    if s.startswith("^") or s.endswith("$"):
                        rules_with["regex:anchored"].add(rid)
                    else:
                        rules_with["regex:unanchored"].add(rid)
                    continue
                if re.search(r"(?<!\\)\?", s):
                    rules_with["value:question_mark_wildcard"].add(rid)
                if re.search(r"(?<!\\)\*", s.strip("*")):
                    rules_with["value:inner_star_wildcard"].add(rid)
                if re.search(r"\\[*?]", s):
                    rules_with["value:escaped_wildcard"].add(rid)
                if "\\\\" in s:
                    rules_with["value:double_backslash"].add(rid)
                if "\\" in s:
                    rules_with["value:backslash"].add(rid)
                if s.endswith("\\"):
                    rules_with["value:trailing_backslash"].add(rid)
                if any(ord(ch) > 127 for ch in s):
                    rules_with["value:non_ascii"].add(rid)
                if s != s.strip():
                    rules_with["value:leading_or_trailing_space"].add(rid)
                if "  " in s or "\t" in s:
                    rules_with["value:double_space_or_tab"].add(rid)
                if '"' in s or "'" in s:
                    rules_with["value:quote_char"].add(rid)
                if "_" in s or "%" in s:
                    rules_with["value:sql_like_metachar"].add(rid)
                if re.fullmatch(r"0x[0-9a-fA-F]+", s):
                    rules_with["value:hex_string"].add(rid)
                if re.fullmatch(r"\d+", s):
                    rules_with["value:numeric_string"].add(rid)
                if len(s) > 256:
                    rules_with["value:longer_than_256"].add(rid)
                if field and field.lower() in ("hashes", "hash"):
                    rules_with["field:hashes"].add(rid)

    counts = {k: len(v) for k, v in sorted(rules_with.items(), key=lambda kv: -len(kv[1]))}
    out = {"in_scope_rules": len(scope), "rules_using": counts,
           "modifier_chains": dict(modifier_chains.most_common())}
    pathlib.Path(args.out).write_text(json.dumps(out, indent=2), encoding="utf-8")
    print(json.dumps(out, indent=2))


if __name__ == "__main__":
    main()
