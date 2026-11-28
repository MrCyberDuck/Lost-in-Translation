# Triage labels

Every disagreement between a target and the reference evaluator gets exactly one **verdict** label. Only `backend-bug` also gets a **cause** label. The rules are enforced in `harness/triage.py`, which reads clause statuses and the readings of every `ambiguous` or `contradictory` clause straight from [spec-clauses.md](spec-clauses.md), so the two cannot drift apart.

## Verdict labels, checked in this order

| Order | Label | When | Reported as |
| --- | --- | --- | --- |
| 1 | `oracle-bug` | The reference evaluator is wrong (found by review or by the native engines all agreeing against it) | Fixed in the evaluator; not a finding |
| 2 | `rule-out-of-spec` | The rule itself uses something the spec forbids (for example `\d` in a regex, clause S60) | Separate table: SigmaHQ rules that are outside the spec |
| 3 | `spec-gap` | The case depends on an open clause (`ambiguous`, `contradictory` or `silent`), and the target's mechanism breaks neither a `clear` clause nor an open clause under **every** one of its readings | Proposed clarifications to the Sigma specification, collected in [spec-clarifications.md](spec-clarifications.md). **Never** filed against a backend, whatever the backend does |
| 4 | `config` | Only the production configuration differs: a processing pipeline, field mapping or ingestion choice | Configuration findings, separate from language findings |
| 5 | `backend-bug` | The target disagrees, and either the case depends on `clear` clauses only, or the target's mechanism breaks a `clear` clause or an `ambiguous` or `contradictory` clause under **every** one of its readings, or the target crashed | Converter or engine bugs, candidates for upstream reports |

The order matters: a result that a reading of an open clause allows is a `spec-gap` even if it also looks like a backend mistake (decision of 23 Nov 2026).

**What "depends on" and "breaks" mean (decisions of 27 and 28 Nov 2026).** A case depends on every clause its expected verdict relies on, open ones included. A label is judged by the target's **mechanism**, the behaviour traced in its source or reproduced by the harness, not by whether its outcome happens to match some reading:

- A mechanism that breaks a `clear` clause gives a candidate, whatever open clauses the case also depends on. sigma.matching never passes a correlation's matches on to another correlation, so no chain fires (S76), whatever a chain counts.
- A mechanism on an `ambiguous` or `contradictory` clause gives a candidate only if it is wrong under every reading of that clause. Hayabusa applies only the first bound of a range, which is wrong whether S34 allows a range (both bounds) or not (refuse the rule).
- A `silent` clause can never be broken. The spec has no text on its question, so there is no right answer to measure against, and agreement among backends is not one either. A difference that turns on a silent point is a `spec-gap`.
- A crash is a candidate.

Three safeguards keep this from turning spec gaps into bugs or bugs into spec gaps:

1. The readings of every `ambiguous` or `contradictory` clause are fixed in advance, in the table "Readings of the open clauses" in [spec-clauses.md](spec-clauses.md). Each one quotes the spec's text, an example or the schema. A reading that only an engine follows, or that only we came up with, is not a reading (Nik, 28 Nov 2026). A reading is added only with its quote and a note in the review log. Tests check that every such clause has at least two readings and that every reading cites the spec.
2. Every `backend-bug` (and `config`) label that rests on a broken clause records it (`breaks`), with the readings for an open clause. `classify` checks the record against the table, and refuses a `silent` clause.
3. The very-critical review at Phase 3 step 6 checks the reading lists and every recorded `breaks`: whether a quoted reading is missing that would make the target right, whether the mechanism really is wrong under each listed one, and whether a difference marked as breaking a clear clause really does not turn on a silent point.

The same judgement is made for each target separately: S34 excuses pySigma's refusal of a range (it follows S34.b) but not Hayabusa's single bound (wrong under both).

## Cause labels (only for `backend-bug`)

| Label | Meaning |
| --- | --- |
| `converter` | The pySigma backend emits a query that does not mean what the rule means (for example missing brackets) |
| `engine` | The query is faithful but the engine evaluates it differently from its own documentation |
| `ingest` | The difference comes from how the engine stored the event (mapping, truncation, typing) in a configuration that claims to be neutral |

## What each case must record

- the clause ids its expected verdict depends on (`depends_on`, for example `["S1", "S6"]`), open ones included,
- for a `backend-bug` or `config` label, what the target's mechanism breaks (`breaks`: `{"S76": "clear"}`, or for an open clause the readings it is wrong under, `{"S34": ["S34.a", "S34.b"]}`),
- the matched sets per target,
- the label and, for `backend-bug`, the cause,
- a minimal reproducer (the conformance case folder).

## Reporting upstream

No bug is filed upstream before Phase 3 (decision of 23 Nov 2026). In Phase 3 every `backend-bug` is re-verified, then all findings are reported together.
