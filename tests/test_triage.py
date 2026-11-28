import pytest

import re

from harness.triage import SPEC_CLAUSES, classify, clause_readings, clause_status, working_reading


def test_all_99_clauses_parsed():
    status = clause_status()
    assert len(status) == 99
    assert status["S27"] == "clear"
    assert status["S24"] == "ambiguous"
    assert status["S1"] == "ambiguous"      # "clear for ASCII; ambiguous for non-ASCII" counts as open
    assert status["S70"] == "contradictory"
    assert status["S88"] == "clear"
    assert status["S92"] == "contradictory"
    assert status["S34"] == "contradictory"
    assert status["S93"] == "silent"
    assert status["S98"] == "silent"
    assert status["S99"] == "silent"
    assert status["S94"] == "silent"        # "silent on ...; clear that ..." counts as open
    assert status["S15"] == "clear"
    assert status["S20"] == "clear"
    assert status["S37"] == "clear"


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


@pytest.mark.parametrize("clause", ["S10", "S11", "S24", "S33", "S35"])
def test_closed_questions_still_give_spec_gap(clause):
    # Nik, 23 Nov 2026: working interpretations kept, findings on these are spec gaps.
    result = classify([clause, "S27"], cause="converter")
    assert result["verdict"] == "spec-gap"


def test_open_clauses_with_spec_text_list_their_readings():
    # Safeguard 1 (Nik, 27 Nov 2026), revised 28 Nov 2026: an ambiguous or contradictory clause lists the
    # readings its spec text allows; a silent clause lists none.
    status, readings = clause_status(), clause_readings()
    with_text = {c for c, s in status.items() if s in ("ambiguous", "contradictory")}
    assert set(readings) == with_text
    for c in with_text:
        assert len(readings[c]) >= 2, c
        assert len(set(readings[c])) == len(readings[c]), c
        assert working_reading(c) is not None, c
    assert working_reading("S34") == "S34.a"


def test_every_reading_quotes_the_spec():
    # Nik, 28 Nov 2026: where the spec has text, readings come from it, never from an engine or from us.
    rows = [line for line in SPEC_CLAUSES.read_text(encoding="utf-8").splitlines()
            if re.match(r"^\|\s*S\d+\.[a-z]\s*\|", line)]
    assert rows
    for row in rows:
        source = row.split("|")[3].strip()
        assert source.startswith("spec"), row


def test_open_reading_not_broken_under_all_is_a_spec_gap():
    out = classify(["S27", "S73"], cause="engine", breaks={"S73": ["S73.a"]})
    assert out == {"verdict": "spec-gap", "open_clauses": ["S73"]}


def test_breaking_every_reading_gives_backend_bug_with_record():
    out = classify(["S31", "S73"], cause="engine", breaks={"S73": ["S73.b", "S73.a"]})
    assert out == {"verdict": "backend-bug", "cause": "engine", "breaks": {"S73": ["S73.a", "S73.b"]}}


def test_breaking_a_clear_clause_wins_over_open_ones():
    # Judged by the mechanism: a chain that never fires breaks S76 whatever S94 and S33 say.
    out = classify(["S76", "S94", "S33"], cause="engine", breaks={"S76": "clear"})
    assert out == {"verdict": "backend-bug", "cause": "engine", "breaks": {"S76": "clear"}}


def test_silent_clause_cannot_be_broken():
    assert classify(["S35"], cause="engine")["verdict"] == "spec-gap"
    with pytest.raises(ValueError):
        classify(["S35"], cause="engine", breaks={"S35": ["S35.a"]})


def test_breaks_is_checked():
    with pytest.raises(ValueError):
        classify(["S34"], cause="engine", breaks={"S34": ["S34.a", "S34.z"]})
    with pytest.raises(ValueError):
        classify(["S34"], cause="engine", breaks={"S73": ["S73.a"]})
    with pytest.raises(ValueError):
        classify(["S27"], cause="engine", breaks={"S27": ["S27.a"]})
    with pytest.raises(ValueError):
        classify(["S34"], cause="engine", breaks={"S34": "clear"})


def test_a_crash_is_a_candidate():
    out = classify(["S31", "S73"], cause="engine", crashed=True)
    assert out == {"verdict": "backend-bug", "cause": "engine", "crashed": True}


def test_matcher_mechanism_labels():
    from harness.matcher_labels import labels
    out = labels()
    assert out["M6"] == {"verdict": "spec-gap", "open_clauses": ["S11"]}
    assert {k for k, v in out.items() if v["verdict"] == "backend-bug"} == {"M1", "M2", "M3", "M4", "M5", "M7"}
    assert out["M7"]["breaks"] == {"S5": "clear"}
