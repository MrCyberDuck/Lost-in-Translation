"""The three-valued emulation of Chainsaw (harness/explain.py, mechanism C4) must reproduce
the probe rules run against Chainsaw 2.18.0 on 23 Nov 2026 (docs/phase2.md, section 3).

sel = a field that matches, nomatch = a field that does not match, miss/miss2 = missing fields. (The probes named it `no`; PyYAML reads an
unquoted `no:` key as the boolean false, so it is renamed here.)
"""
import pytest

from harness.evaluator import compile_rule
from harness.evaluator.core import Semantics

RULE = """title: probe
id: 22222222-2222-2222-2222-222222222222
status: test
logsource:
    product: windows
detection:
    sel:
        Image|endswith: '\\\\bitsadmin.exe'
    nomatch:
        Image|endswith: '\\\\nothing.exe'
    miss:
        NoSuchField: 'x'
    miss2:
        OtherMissing: 'y'
    condition: {}
"""
EVENT = {"event_id": "e", "@timestamp": "t", "Image": "C:\\Windows\\System32\\bitsadmin.exe"}

CHAINSAW_PROBES = [  # condition, matches in Chainsaw
    ("sel or miss", True),
    ("sel and not (miss or nomatch)", True),
    ("not miss", False),
    ("not (miss and sel)", False),
    ("not (nomatch and miss)", True),
    ("sel and not (miss or sel)", False),
    ("not not sel", True),
    ("sel and not (miss or miss2)", False),
    ("sel and not (nomatch or miss)", True),
    ("sel and not (miss and nomatch)", False),
    ("sel and not (sel and miss)", False),
    ("(miss or sel) and not nomatch", True),
    ("sel and not miss and not nomatch", False),
    ("sel and (not miss or sel)", True),
    ("sel and (not miss or not nomatch)", True),
]


@pytest.mark.parametrize("cond,chainsaw", CHAINSAW_PROBES)
def test_emulation_matches_chainsaw_probes(cond, chainsaw):
    comp = compile_rule(RULE.format(cond), Semantics(three_valued_missing=True))
    assert comp.predicate(EVENT) is chainsaw


@pytest.mark.parametrize("cond", ["not miss", "sel and not (miss or miss2)", "sel and not miss and not nomatch"])
def test_spec_disagrees_with_chainsaw_on_negated_missing_fields(cond):
    assert compile_rule(RULE.format(cond)).matches(EVENT) is True  # S25


CHAINSAW_RULE = """title: probe
id: 33333333-3333-3333-3333-{n:012d}
status: test
description: probe
author: lit
date: 2026-11-23
logsource:
    product: windows
    category: process_creation
detection:
    sel:
        Image|endswith: '\\\\bitsadmin.exe'
    nomatch:
        Image|endswith: '\\\\nothing.exe'
    miss:
        NoSuchField: 'x'
    miss2:
        OtherMissing: 'y'
    condition: {cond}
level: low
"""


def test_probes_still_hold_on_installed_chainsaw(tmp_path):
    """Re-runs the probes on the real binary, so a Chainsaw upgrade that changes behaviour is noticed."""
    import json
    import pathlib
    import subprocess

    from harness import native
    evtx = pathlib.Path("rules/sigma/regression_data/rules/windows/process_creation/"
                        "proc_creation_win_bitsadmin_download")
    if not native.CHAINSAW.exists() or not evtx.exists():
        pytest.skip("Chainsaw binary or SigmaHQ submodule not installed")
    mapping = native.neutral_mapping(tmp_path / "neutral.yml")
    for n, (cond, expected) in enumerate(CHAINSAW_PROBES):
        rule = tmp_path / f"probe{n}.yml"
        rule.write_text(CHAINSAW_RULE.format(n=n, cond=cond), encoding="utf-8")
        res = subprocess.run([str(native.CHAINSAW), "hunt", str(evtx), "-s", str(rule), "--mapping", str(mapping),
                              "--json", "-q"], capture_output=True, text=True, check=True)
        got = len(json.loads(res.stdout)) > 0 if res.stdout.strip() else False
        assert got is expected, cond
