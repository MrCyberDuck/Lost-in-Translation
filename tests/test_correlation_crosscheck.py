"""The evaluator's results on the correlation cross-check cases are the ones recorded in
results/phase3/correlation_crosscheck/evaluator.json, so the README tables stay true."""
import json
import pathlib

from harness.correlation_crosscheck import CASES, run_evaluator

RECORDED = pathlib.Path(__file__).resolve().parent.parent / "results/phase3/correlation_crosscheck/evaluator.json"


def test_evaluator_results_match_the_recorded_run():
    recorded = json.loads(RECORDED.read_text(encoding="utf-8"))["cases"]
    got = json.loads(json.dumps({c.id: run_evaluator(c) for c in CASES}))
    assert got == recorded


def test_case_ids_are_unique_and_every_case_names_a_clause():
    ids = [c.id for c in CASES]
    assert len(ids) == len(set(ids)) == 31
    assert all(c.clauses for c in CASES)
