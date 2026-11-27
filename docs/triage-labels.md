# Triage labels

Every disagreement between a target and the reference evaluator gets exactly one **verdict** label. Only `backend-bug` also gets a **cause** label. The rules are enforced in `harness/triage.py`, which reads clause statuses straight from [spec-clauses.md](spec-clauses.md), so the two cannot drift apart.

## Verdict labels, checked in this order

| Order | Label | When | Reported as |
| --- | --- | --- | --- |
| 1 | `oracle-bug` | The reference evaluator is wrong (found by review or by the native engines all agreeing against it) | Fixed in the evaluator; not a finding |
| 2 | `rule-out-of-spec` | The rule itself uses something the spec forbids (for example `\d` in a regex, clause S60) | Separate table: SigmaHQ rules that are outside the spec |
| 3 | `spec-gap` | The expected verdict depends on **any** clause whose status is `ambiguous` or `contradictory` | Proposed clarifications to the Sigma specification, collected in [spec-clarifications.md](spec-clarifications.md). **Never** filed against a backend, whatever the backend does |
| 4 | `config` | Only the production configuration differs: a processing pipeline, field mapping or ingestion choice | Configuration findings, separate from language findings |
| 5 | `backend-bug` | Every clause the verdict depends on is `clear`, and the target still disagrees | Converter or engine bugs, candidates for upstream reports |

The order matters: a case that touches an ambiguous clause is a `spec-gap` even if it also looks like a backend mistake. This was decided on 23 Nov 2026.

## Cause labels (only for `backend-bug`)

| Label | Meaning |
| --- | --- |
| `converter` | The pySigma backend emits a query that does not mean what the rule means (for example missing brackets) |
| `engine` | The query is faithful but the engine evaluates it differently from its own documentation |
| `ingest` | The difference comes from how the engine stored the event (mapping, truncation, typing) in a configuration that claims to be neutral |

## What each case must record

- the clause ids its expected verdict depends on (`depends_on`, for example `["S1", "S6"]`),
- the matched sets per target,
- the label and, for `backend-bug`, the cause,
- a minimal reproducer (the conformance case folder).

## Reporting upstream

No bug is filed upstream before Phase 3 (decision of 23 Nov 2026). In Phase 3 every `backend-bug` is re-verified, then all findings are reported together.
