# Evaluator correlations and filters vs three implementations (Phase 3 step 2, 26 Nov 2026)

The evaluator gained global filters and correlation rules in step 2 (`harness/evaluator/collection.py`, clauses S31 to S35, S70 to S83 and S89 to S93 in [spec-clauses.md](../../../docs/spec-clauses.md)). SigmaHQ r2026-07-01 has no correlation rules or filters in scope, so there is no real data to cross-check them on, as Phase 2 did for detection rules. This run checks them instead on 31 small synthetic cases, one or two per clause, against three implementations written independently of the evaluator:

| Target | Version | How it runs |
| --- | --- | --- |
| `matcher` | pySigma 2.1.2 `sigma.matching.SigmaMatcher` | in process, events in file order |
| `zircolite` | Zircolite 4.8.0, correlation plans from pySigma-backend-sqlite 2.2.0 | `zircolite.py -j --no-event-filter --timefield SystemTime` |
| `hayabusa` | Hayabusa 4.4.0 | `dfir-timeline -J` on the same events as JSON lines |

Chainsaw 2.18.0 is left out: it ignores correlation rules without an error ([correlation_native](../correlation_native/README.md)).

    python -m harness.correlation_crosscheck evaluator      # pySigma 1.x environment
    python -m harness.correlation_crosscheck matcher        # pySigma 2.x environment
    python -m harness.correlation_crosscheck zircolite      # pySigma 2.x environment
    python -m harness.correlation_crosscheck hayabusa
    python -m harness.correlation_crosscheck compare        # writes summary.json

Versions: [frozen_versions.json](../frozen_versions.json). Run in the cloud container at the frozen versions.

## Method

Every target gets the same YAML file and the same events. Base rules match on `EventID` only, so the detection layer cannot differ and only correlation and filter semantics are compared. Events carry `@timestamp` (evaluator, Hayabusa) and the same value in `SystemTime` (Zircolite). The unit of comparison is the set of groups a correlation fires for, case-folded (S93): targets raise different numbers of alerts for one burst, so alert counts are recorded but not compared. Filter cases compare the base rule's matches. A target that rejects the rule counts as `error`: under S78 a refusal is conformant, and it goes to the conversion-failure rate, not to the disagreements. Hayabusa reports a rule it cannot parse as "Rule parsing errors: N" and exits 0; that counts as a refusal.

## Result

| Target | Agree | Differ | Refused | Not applicable |
| --- | --- | --- | --- | --- |
| matcher | 16 | 12 | 2 | 1 |
| zircolite | 26 | 3 | 2 | 0 |
| hayabusa | 13 | 9 | 9 | 0 |

Zircolite agrees with the evaluator on every case except three behaviours of pySigma's own rule parser and filter handling (P1 to P3 below), which Zircolite inherits. That includes the evaluator's working interpretations of S32, S72, S73, S90 and S91, which Zircolite's SQL implements the same way. No case has all three targets against the evaluator, and every difference is traced to a mechanism in a target. The cross-check therefore supports the evaluator and turns up no evaluator bug.

Groups each correlation fires for (bold: differs from the evaluator):

| Case | Clauses | What | Evaluator | matcher | zircolite | hayabusa |
| --- | --- | --- | --- | --- | --- | --- |
| C01 | S31 | event_count: 3 failures for bob, 2 for eve, within 5 minutes | (bob) | (bob) | (bob) | (bob) |
| C02 | S33 | event_count: a burst at 04:00, 05:00, 06:00 straddles a 5-minute boundary | (bob) | (bob) | (bob) | (bob) |
| C03 | S91 | event_count: first and last event exactly 5 minutes apart | (bob) | (bob) | (bob) | (bob) |
| C04 | S33 | event_count: first and last event 5 minutes and 1 second apart | none | none | none | none |
| C05 | S32 | event_count: the third event has no User field | none | none | none | none |
| C06 | S90 | event_count: User is Bob, BOB and bob | (bob) | **none** | (bob) | **none** |
| C07 | S71 | event_count without group-by: 3 events of 3 users | (all) | (all) | (all) | **refused** |
| C08 | S34 | event_count range gt 1, lte 2: bob has 2 events, eve 3 at the same second | (bob) | **refused** | **refused** | **(bob), (eve)** |
| C09 | S34 | event_count neq 1: bob has 2 events at one second, eve 1 | (bob) | (bob) | (bob) | **refused** |
| C10 | S72, S90 | value_count of User per Host, gte 3: Admin, admin, root | none | **(h)** | none | **(h)** |
| C11 | S72 | value_count of User per Host, gte 2: one event has no User | none | none | none | **(h)** |
| C12 | S73 | value_count of [User, Src], gte 3: 2 users, 2 sources, 3 pairs | (h) | **crash** | (h) | (h) |
| C13 | S31 | temporal: bob has a failure and a success, eve only failures | (bob) | (bob) | (bob) | (bob) |
| C14 | S35 | temporal_ordered failed then success: eve in order, bob reversed | (eve) | (eve) | (eve) | (eve) |
| C15 | S35 | temporal_ordered failed then success at the same second | none | **(bob)** | none | **(bob)** |
| C16 | S92 | temporal over 3 rules without a condition: bob has 2 of them, eve all 3 | (eve) | (eve) | (eve) | (eve) |
| C17 | S31 | temporal over 3 rules with gte 2: bob has 2 kinds, eve 2 events of one kind | (bob) | **none** | (bob) | **none** |
| C18 | S76 | event_count referencing the base rule by id | (bob) | **none** | (bob) | (bob) |
| C19 | S76 | chain: inner gte 2 in 5m per User, outer gte 2 inner alerts in 1h; bob has 2 bursts, eve 1 | (bob) | **none** | (bob) | **refused** |
| C20 | S75 | temporal with aliases: ip is DestIp in conn_in and SrcIp in conn_out | (10.0.0.1) | **(none)** | (10.0.0.1) | **(null)** |
| C21 | S70 | value_sum of Bytes per Host, gte 25: 10 + 10 + 10 | (h) | (h) | (h) | **refused** |
| C22 | S70 | value_avg of Bytes per Host: gte 9 fires for h (avg 10), not for g (avg 5) | (h) | (h) | (h) | **refused** |
| C23 | S74 | value_percentile of Image per Host, lte 10: one rare image among 11 events | (h) | **none** | **refused** | **refused** |
| C24 | S81 | filter `User\|startswith: adm_`, `condition: sel`; events adm_bob (e1) and alice (e2) | e2 | **e1** | **e1** | **refused** |
| C25 | S89 | filter on the base rule of an event_count without group-by, gte 3: one of 3 events is filtered | none | none | none | **refused** |
| C26 | S80 | timespan 5M (upper-case unit) | refused | **(bob)** | **(bob)** | refused |
| C27 | S93 | event_count gte 3: 6 events in 6 seconds, then 3 more 20 minutes later | (bob) | (bob) | (bob) | (bob) |
| C28 | S77 | base rule referenced without generate: are its matches emitted | not emitted | n/a | not emitted | not emitted |
| C29 | S81, S89 | as C25 with gte 2: 2 events are left after the filter, 1 if the filter is ANDed in | (all) | **none** | **none** | **refused** |
| C30 | S32 | event_count gte 3: three events, none with the User field | none | **(none)** | none | **(null)** |
| C31 | S33 | temporal over 3 rules, 5m: success at 00:00, failed at 05:00, other at 10:00 | none | none | none | **(bob)** |

In C27 the evaluator raises 2 alerts (one per burst), the matcher and Zircolite 5 (one per event once the count is reached) and Hayabusa 2. The groups agree.

## Mechanisms

Each difference above is one of these. IDs continue the existing series: P for pySigma's rule parser and collection handling, shared by every pySigma backend; M for `sigma.matching` (M1 to M7 are in [matcher_crosscheck](../matcher_crosscheck/README.md)); H for Hayabusa (H1 to H4 are from Phase 2).

| ID | Target | What it does | Cases | Clause | Label |
| --- | --- | --- | --- | --- | --- |
| P1 | pySigma 2.1.2 (matcher, Zircolite) | Rejects a condition with two operators: "Sigma correlation condition must have exactly one condition item". The spec says "a map of exactly one condition criterion" and then shows a range with two | C08 | S34 (clear) | refusal |
| P2 | pySigma 2.1.2 (matcher, Zircolite) | Accepts `timespan: 5M` (and `w`, `y`), which the spec does not allow | C26 | S80 (clear) | `backend-bug` candidate |
| P3 | pySigma 2.1.2 (matcher, Zircolite) | ANDs the filter's condition into the rule, so the filter keeps the events it should suppress (T23.1) | C24, C29 | S81 (ambiguous) | `spec-gap` |
| M8 | matcher | Group-by values and counted values are case-sensitive | C06, C10 | S90, S72 (ambiguous) | `spec-gap` |
| M9 | matcher | Events without a group-by field form a group of their own | C30 | S32 (ambiguous) | `spec-gap` |
| M10 | matcher | `value_count` over two fields raises `TypeError: unhashable type: 'list'` while matching | C12 | S73 (ambiguous), but no reading gives a crash | `backend-bug` candidate |
| M11 | matcher | `temporal_ordered` accepts two events at the same timestamp as ordered | C15 | S35 (ambiguous) | `spec-gap` |
| M12 | matcher | `temporal` ignores the condition and needs every referenced rule | C17 | S31 (clear) | `backend-bug` candidate |
| M13 | matcher | A reference by `id` is never routed to the correlation, silently | C18 | S76 (clear) | `backend-bug` candidate |
| M14 | matcher | A correlation over a correlation never fires, silently | C19 | S76, S78 (clear) | `backend-bug` candidate |
| M15 | matcher | `aliases` are not applied: the group key is empty, so unrelated events correlate | C20 | S75 (clear) | `backend-bug` candidate |
| M16 | matcher | `value_percentile` does not fire on a value seen in 1 of 11 events | C23 | S74 (ambiguous) | `spec-gap` |
| H5 | Hayabusa | Group-by values and counted values are case-sensitive | C06, C10 | S90, S72 (ambiguous) | `spec-gap` |
| H6 | Hayabusa | Events without a group-by field form a `null` group | C30 | S32 (ambiguous) | `spec-gap` |
| H7 | Hayabusa | A range uses only its first operator (`gt: 1` of `gt: 1, lte: 2`), silently | C08 | S34 (clear) | `backend-bug` candidate |
| H8 | Hayabusa | `value_count` counts a missing field as a value | C11 | S72 (ambiguous) | `spec-gap` |
| H9 | Hayabusa | `temporal_ordered` accepts equal timestamps as ordered | C15 | S35 (ambiguous) | `spec-gap` |
| H10 | Hayabusa | `temporal` ignores the condition and needs every referenced rule | C17 | S31 (clear) | `backend-bug` candidate |
| H11 | Hayabusa | `aliases` are not applied: the group is `null`, so unrelated events correlate | C20 | S75 (clear) | `backend-bug` candidate |
| H12 | Hayabusa | `temporal` looks `timespan` before and after the first rule's event, so the events can span twice the timespan | C31 | S33 (ambiguous), but no reading allows 10 minutes for a 5-minute timespan | `backend-bug` candidate |

Refusals, which are conformant under S78 and count toward the conversion-failure rate: P1 (C08); the SQLite backend does not convert `value_percentile` (C23); Hayabusa does not parse correlations without `group-by` (C07, S71 is contradictory), `neq` (C09), chains (C19), `value_sum`, `value_avg` and `value_percentile` (C21 to C23, S70 is contradictory), global filters (C24, C25, C29; it then runs the base rule without the filter) or `timespan: 5M` (C26).

The source code confirms H7 (`process_condition_pairs` returns the first operator), H8 (`unwrap_or_default` turns a missing field into the empty string, which `FieldStrategy` counts as a value), H9 and H10 (`detect_within_timeframe` checks `time >= order_floor` and requires every rule) and H12 (the `base.start_datetime - timeframe` to `+ timeframe` test) in Hayabusa 4.4.0. In pySigma 2.1.2 `sigma/matching`, `_eval_temporal` checks that every rule name fired and never reads the condition (M12); `SigmaMatcher` routes a match to correlations by rule `name` only (M13) and never routes correlation matches onward (M14); `_resolve_alias` falls back to the alias name itself when the rule object does not match, a field no event has (M15).

None of these is reported yet. Like every finding, they first have to meet the reporting bar in Phase 3 step 7.
