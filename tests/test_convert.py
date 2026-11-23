import pathlib

import pytest

from harness.convert import TARGETS, convert

RULE = pathlib.Path("conformance/smoke/rule.yml").read_text(encoding="utf-8")


@pytest.mark.parametrize("target", TARGETS)
def test_smoke_rule_converts_for_every_target(target):
    conv = convert(RULE, target)
    assert conv.error is None
    assert len(conv.queries) == 1
