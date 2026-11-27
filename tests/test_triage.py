import pytest

from harness.triage import classify, clause_readings, clause_status, every_reading, working_reading


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
    assert status["S93"] == "ambiguous"
    assert status["S98"] == "ambiguous"
    assert status["S99"] == "ambiguous"


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


@pytest.mark.parametrize("clause", ["S10", "S11", "S24", "S33"])
def test_closed_questions_still_give_spec_gap(clause):
    # Nik, 23 Nov 2026: working interpretations kept, findings on these are spec gaps.
    result = classify([clause, "S27"], cause="converter")
    assert result["verdict"] == "spec-gap"


def test_every_open_clause_lists_its_readings():
    # Safeguard 1 (Nik, 27 Nov 2026): readings are fixed in spec-clauses.md before labels use them.
    status, readings = clause_status(), clause_readings()
    open_ids = {c for c, s in status.items() if s != "clear"}
    assert set(readings) == open_ids
    for c in open_ids:
        assert len(readings[c]) >= 2, c
        assert len(set(readings[c])) == len(readings[c]), c
    # every open clause but S22 (time modifiers, not implemented yet) names the evaluator's reading
    assert {c for c in open_ids if working_reading(c) is None} == {"S22"}
    assert working_reading("S34") == "S34.a"


def test_open_clause_excuses_a_result_right_under_one_reading():
    out = classify(["S27", "S73"], cause="engine", wrong_under={"S73": ["S73.a", "S73.b"]})
    assert out == {"verdict": "spec-gap", "open_clauses": ["S73"]}


def test_wrong_under_every_reading_gives_backend_bug_with_record():
    out = classify(["S31", "S73"], cause="engine", wrong_under={"S73": ["S73.c", "S73.a", "S73.b"]})
    assert out == {"verdict": "backend-bug", "cause": "engine",
                   "wrong_under": {"S73": ["S73.a", "S73.b", "S73.c"]}}


def test_every_open_clause_must_be_covered():
    # S33 is listed but no reading is recorded for it, so it still excuses the result.
    out = classify(["S34", "S33"], cause="engine", wrong_under={"S34": ["S34.a", "S34.b"]})
    assert out == {"verdict": "spec-gap", "open_clauses": ["S33"]}


def test_wrong_under_is_checked_against_the_lists():
    with pytest.raises(ValueError):
        classify(["S34"], cause="engine", wrong_under={"S34": ["S34.a", "S34.z"]})
    with pytest.raises(ValueError):
        classify(["S34"], cause="engine", wrong_under={"S73": ["S73.a"]})
    with pytest.raises(ValueError):
        classify(["S27"], cause="engine", wrong_under={"S27": []})


def test_every_reading_for_a_crash():
    assert every_reading(["S31", "S73"]) == {"S73": ["S73.a", "S73.b", "S73.c"]}
    out = classify(["S31", "S73"], cause="engine", wrong_under=every_reading(["S31", "S73"]))
    assert out["verdict"] == "backend-bug"


def test_matcher_mechanism_labels():
    from harness.matcher_labels import labels
    out = labels()
    assert out["M6"] == {"verdict": "spec-gap", "open_clauses": ["S11"]}
    assert {k for k, v in out.items() if v["verdict"] == "backend-bug"} == {"M1", "M2", "M3", "M4", "M5", "M7"}
    assert out["M7"]["wrong_under"] == {"S44": ["S44.a", "S44.b", "S44.c"], "S87": ["S87.a", "S87.b", "S87.c"]}
