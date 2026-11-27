# Triage labels

Every disagreement between a target and the reference evaluator gets exactly one **verdict** label. Only `backend-bug` also gets a **cause** label. The rules are enforced in `harness/triage.py`, which reads clause statuses and the readings of every open clause straight from [spec-clauses.md](spec-clauses.md), so the two cannot drift apart.

## Verdict labels, checked in this order

| Order | Label | When | Reported as |
| --- | --- | --- | --- |
| 1 | `oracle-bug` | The reference evaluator is wrong (found by review or by the native engines all agreeing against it) | Fixed in the evaluator; not a finding |
| 2 | `rule-out-of-spec` | The rule itself uses something the spec forbids (for example `\d` in a regex, clause S60) | Separate table: SigmaHQ rules that are outside the spec |
| 3 | `spec-gap` | The case depends on a clause whose status is `ambiguous` or `contradictory`, and the target's result is right under **at least one** of that clause's readings | Proposed clarifications to the Sigma specification, collected in [spec-clarifications.md](spec-clarifications.md). **Never** filed against a backend, whatever the backend does |
| 4 | `config` | Only the production configuration differs: a processing pipeline, field mapping or ingestion choice | Configuration findings, separate from language findings |
| 5 | `backend-bug` | The target disagrees, and every open clause the case depends on was ruled out: the result is wrong under **every** one of its readings | Converter or engine bugs, candidates for upstream reports |

The order matters: a result that is right under any reading of an open clause is a `spec-gap` even if it also looks like a backend mistake (decision of 23 Nov 2026).

**What "depends on" means (decision of 27 Nov 2026).** A case depends on every clause its expected verdict relies on, open ones included. An open clause excuses a result only if the result is right under at least one of its readings. A result that is wrong under all of them, such as a crash, or Hayabusa applying only one bound of a range when S34 allows either refusing the rule or applying both, is not excused, and it is labelled as if the clause were clear. Three safeguards keep this from turning spec gaps into bugs:

1. The readings of every open clause are fixed in advance, in the table "Readings of the open clauses" in [spec-clauses.md](spec-clauses.md). A reading is added, never removed, and only with a note in the review log; adding one can turn a candidate back into a `spec-gap`, never the reverse. A test checks that every open clause has at least two readings.
2. Every `backend-bug` (and `config`) label that rests on an open clause records the readings it is wrong under (`wrong_under`), and `classify` checks them against the table: a label is only given when every reading of every open clause is listed.
3. The very-critical review at Phase 3 step 6 checks the reading lists and every recorded `wrong_under`: whether a reading is missing that would make the target right, and whether the target is really wrong under each listed one.

The same judgement is made for each target separately: S34 excuses pySigma's refusal of a range (right under S34.b) but not Hayabusa's single bound (wrong under both).

## Cause labels (only for `backend-bug`)

| Label | Meaning |
| --- | --- |
| `converter` | The pySigma backend emits a query that does not mean what the rule means (for example missing brackets) |
| `engine` | The query is faithful but the engine evaluates it differently from its own documentation |
| `ingest` | The difference comes from how the engine stored the event (mapping, truncation, typing) in a configuration that claims to be neutral |

## What each case must record

- the clause ids its expected verdict depends on (`depends_on`, for example `["S1", "S6"]`), open ones included,
- for a `backend-bug` or `config` label that rests on an open clause, the readings the target is wrong under (`wrong_under`, for example `{"S34": ["S34.a", "S34.b"]}`),
- the matched sets per target,
- the label and, for `backend-bug`, the cause,
- a minimal reproducer (the conformance case folder).

## Reporting upstream

No bug is filed upstream before Phase 3 (decision of 23 Nov 2026). In Phase 3 every `backend-bug` is re-verified, then all findings are reported together.
