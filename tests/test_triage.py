import pytest

from harness.triage import classify, clause_status


def test_all_84_clauses_parsed():
    status = clause_status()
    assert len(status) == 84
    assert status["S27"] == "clear"
    assert status["S24"] == "ambiguous"
    assert status["S1"] == "ambiguous"      # "clear for ASCII; ambiguous for non-ASCII" counts as open
    assert status["S70"] == "contradictory"


def test_ambiguous_clause_always_wins_over_backend_bug():
    # Even with a cause given, a dependency on S24 (null) makes it a spec gap.
    out = classify(["S8", "S24"], cause="converter")
    assert out == {"verdict": "spec-gap", "open_clauses": ["S24"]}


def test_clear_clauses_give_backend_bug_with_cause():
    assert classify(["S27", "S9"], cause="converter") == {"verdict": "backend-bug", "cause": "converter"}


def test_out_of_spec_rule_beats_spec_gap():
    assert classify(["S15", "S60"], rule_out_of_spec=True) == {"verdict": "rule-out-of-spec"}


def test_backend_bug_needs_cause_and_dependencies():
    with pytest.raises(ValueError):
        classify(["S27"])
    with pytest.raises(ValueError):
        classify([], cause="engine")
