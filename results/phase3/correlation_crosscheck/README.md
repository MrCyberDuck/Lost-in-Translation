# Evaluator correlations and filters vs three implementations (Phase 3 step 2, 26 Nov 2026)

The evaluator gained global filters and correlation rules in step 2 (`harness/evaluator/collection.py`, clauses S31 to S35, S70 to S83 and S89 to S99 in [spec-clauses.md](../../../docs/spec-clauses.md)). SigmaHQ r2026-07-01 has no correlation rules or filters in scope, so there is no real data to cross-check them on, as Phase 2 did for detection rules. This run checks them instead on 45 small synthetic cases against three implementations written independently of the evaluator:

| Target | Version | How it runs |
| --- | --- | --- |
| `matcher` | pySigma 2.1.2 `sigma.matching.SigmaMatcher` | in process, events in time order, ties in file order |
| `zircolite` | Zircolite 4.8.0, correlation plans from pySigma-backend-sqlite 2.2.0 | `zircolite.py -j --no-event-filter --timefield SystemTime` |
| `hayabusa` | Hayabusa 4.4.0 | `dfir-timeline -J` on the same events as JSON lines |

Chainsaw 2.18.0 is left out: it ignores correlation rules without an error ([correlation_native](../correlation_native/README.md)).

    python -m harness.correlation_crosscheck evaluator      # pySigma 1.x environment
    python -m harness.correlation_crosscheck matcher        # pySigma 2.x environment
    python -m harness.correlation_crosscheck zircolite      # pySigma 2.x environment
    python -m harness.correlation_crosscheck hayabusa
    python -m harness.correlation_crosscheck compare        # writes summary.json

Versions: [frozen_versions.json](../frozen_versions.json). Run in the cloud container at the frozen versions; two runs gave byte-identical results.

## Method

Every target gets the same YAML file and the same events. Base rules match on `EventID` only, so the detection layer cannot differ and only correlation and filter semantics are compared. Every event carries its time in both `@timestamp` (read by the evaluator and Hayabusa) and `SystemTime` (read by Zircolite).

The unit of comparison is the set of groups a correlation fires for, case-folded (S93): targets raise different numbers of alerts for one burst, so alert counts are recorded but not compared. Filter cases compare the base rule's matches. `<missing>` is a group the target reports with no value; Hayabusa writes such a value as the string `null`.

Each run has one outcome:

- `agree` or `differ`;
- `refused`: the target rejects the rule loudly. Under S78 that is conformant, and it goes to the conversion-failure rate, not to the disagreements. Hayabusa reports a rule it cannot parse as "Rule parsing errors: N" and exits 0; a second run without the filter documents tells whether it skipped the correlation (`refused`) or only the filter;
- `degraded`: Hayabusa skipped the filter and ran the rest without it;
- `crash`: the target fails while matching;
- `n/a`: the case does not apply (sigma.matching is a library and always returns base-rule matches, so `generate` cannot be checked on it).

Each case lists the clauses its expected verdict depends on, open ones included. A target's difference is labelled by its mechanism (decisions of 27 and 28 Nov 2026, [triage-labels.md](../../../docs/triage-labels.md)): it is a `backend-bug` candidate if the mechanism breaks a clear clause, or an ambiguous or contradictory clause under every one of its readings, which quote the spec ([spec-clauses.md](../../../docs/spec-clauses.md#readings-of-the-open-clauses)); a crash is a candidate too. A difference that turns on a silent clause, one the spec has no text on, is a `spec-gap`. Each candidate records what it breaks for that target (`breaks`, with the reason next to it in `harness/correlation_crosscheck.py`). The label of every difference, crash and degraded run is computed by `harness.triage.classify` and written to summary.json.

## Result

| Target | Agree | Differ | Degraded | Refused | Crash | n/a |
| --- | --- | --- | --- | --- | --- | --- |
| matcher | 21 | 19 | 0 | 1 | 2 | 2 |
| zircolite | 37 | 6 | 0 | 2 | 0 | 0 |
| hayabusa | 16 | 15 | 5 | 9 | 0 | 0 |

What the cross-check shows, and what it does not:

- **It found two evaluator bugs, both fixed before this run.** The first review of step 2 showed that a correlation over a correlation saw only the rising edges of the inner one, with only the inner group-by values, so the spec's own brute-force example could not fire (now C34 to C36, clause S94). It also showed that an event matched by two referenced rules was counted twice (now C37, C38, clause S95). Timestamps also lost their last three digits; they are now compared in nanoseconds (C45).
- **Zircolite agrees with the evaluator on 37 of 45 cases.** It differs only through pySigma's own rule parsing and filter handling (P1 to P5 below, which every pySigma backend shares), its refusal of `value_percentile` in the spec's form (P6) and its millisecond timestamps (Z1). On the open clauses S32, S72, S73, S90, S91, S94 and S95 it makes the same choices as the evaluator. That shows the two readings are implementable and consistent, not that the spec requires them.
- **sigma.matching and Zircolite are not independent of each other**: both parse rules with pySigma 2.1.2.
- **No target supports the evaluator on S74, S81, S82 or S89.** sigma.matching and Zircolite AND the filter into the rule (P3) and apply it across logsources (P4); Hayabusa does not parse filters; no target computes `value_percentile` the evaluator's way. These verdicts rest on the evaluator's working interpretations alone, and they are all `spec-gap`.
- Every difference is traced to a mechanism in a target, with one exception: the Hayabusa chain results C34 and C36 are observed, and their cause in the source is a guess (H14).

Groups each correlation fires for (bold: differs from the evaluator, crashes, or degraded):

| Case | Depends on | What | Evaluator | matcher | zircolite | hayabusa |
| --- | --- | --- | --- | --- | --- | --- |
| C01 | S31 | event_count: 3 failures for bob, 2 for eve, within 5 minutes | (bob) | (bob) | (bob) | (bob) |
| C02 | S33 | event_count: a burst at 04:00, 05:00, 06:00 straddles a 5-minute boundary | (bob) | (bob) | (bob) | (bob) |
| C03 | S91 | event_count: first and last event exactly 5 minutes apart | (bob) | (bob) | (bob) | (bob) |
| C04 | S31, S33 | event_count: first and last event 5 minutes and 1 second apart | none | none | none | none |
| C05 | S31, S32 | event_count: the third event has no User field | none | none | none | none |
| C06 | S90 | event_count: User is Bob, BOB and bob | (bob) | **none** | (bob) | **none** |
| C07 | S71 | event_count without group-by: 3 events of 3 users | (all) | (all) | (all) | refused |
| C08 | S34, S33, S96 | event_count range gt 1, lte 2: bob has 2 events, eve 3 at the same second | (bob) | refused | refused | **(bob), (eve)** |
| C09 | S34 | event_count neq 1: bob has 2 events at one second, eve 1 | (bob) | (bob) | (bob) | refused |
| C10 | S72, S90 | value_count of User per Host, gte 3: Admin, admin, root | none | **(h)** | none | **(h)** |
| C11 | S72 | value_count of User per Host, gte 2: one event has no User | none | none | none | **(h)** |
| C12 | S73, S33 | value_count of [User, Src], gte 3: 2 users, 2 sources, 3 pairs | (h) | **crash** | (h) | (h) |
| C13 | S31 | temporal: bob has a failure and a success, eve only failures | (bob) | (bob) | (bob) | (bob) |
| C14 | S35 | temporal_ordered failed then success: eve in order, bob reversed | (eve) | (eve) | (eve) | (eve) |
| C15 | S35 | temporal_ordered failed then success at the same second, failed first in the file | none | **(bob)** | none | **(bob)** |
| C16 | S92 | temporal over 3 rules without a condition: bob has 2 of them, eve all 3 | (eve) | (eve) | (eve) | (eve) |
| C17 | S92 | temporal over 3 rules with gte 2: bob has 2 kinds, eve 2 events of one kind | (bob) | **none** | (bob) | **none** |
| C18 | S76, S33 | event_count referencing the base rule by id | (bob) | **none** | (bob) | (bob) |
| C19 | S76, S94, S33 | chain: inner gte 2 in 5m per User, outer gte 2 inner matches in 1h; bob has 2 bursts of 2, eve 1 | (bob) | **none** | (bob) | refused |
| C20 | S75, S92, S33, S32 | temporal with aliases: ip is DestIp in conn_in and SrcIp in conn_out | (10.0.0.1) | **(\<missing\>)** | (10.0.0.1) | **(null)** |
| C21 | S70 | value_sum of Bytes per Host, gte 25: 10 + 10 + 10 | (h) | (h) | (h) | refused |
| C22 | S70 | value_avg of Bytes per Host: gte 9 fires for h (avg 10), not for g (avg 5) | (h) | (h) | (h) | refused |
| C23 | S74 | value_percentile of Image per Host, lte 10, as in the spec example: one rare image among 11 events | (h) | **none** | refused | refused |
| C24 | S81, S98 | filter `User\|startswith: adm_`, `condition: selection`; events adm_bob (e1), alice (e2) | e2 | **e1** | **e1** | **degraded: e1, e2** |
| C25 | S89, S98 | filter on the base rule of an event_count per Host, gte 3: one of 3 events is filtered | none | none | none | **degraded: (h)** |
| C26 | S80 | timespan 5M (upper-case unit), events at 00:00, 30:00 and 59:00 | refused | **(bob)** | **(bob)** | refused |
| C27 | S31, S93 | event_count gte 3: 6 events in 6 seconds, then 3 more 20 minutes later | (bob) | (bob) | (bob) | (bob) |
| C28 | S77 | base rule referenced without generate: are its matches emitted | not emitted | n/a | not emitted | not emitted |
| C29 | S81, S89, S98 | as C25 with gte 2: 2 events are left after the filter, 1 if the filter is ANDed in | (h) | **none** | **none** | **degraded: (h)** |
| C30 | S32 | event_count gte 3: three events, none with the User field | none | **(\<missing\>)** | none | **(null)** |
| C31 | S31, S33, S91, S92 | temporal over 3 rules, 5m: success at 00:00, failed at 05:00, other at 10:00 | none | none | none | **(bob)** |
| C32 | S35 | as C15 with success first in the file | none | none | none | **(bob)** |
| C33 | S31, S73, S33 | value_count of [User, Src], gte 3: 3 events with the same pair | none | **crash** | none | **(h)** |
| C34 | S94, S76 | chain of the spec's shape: inner event_count per Host gte 2, outer temporal_ordered [inner, success] per User | (bob) | **none** | (bob) | **none** |
| C35 | S94, S76 | chain: inner gte 2 per User, outer gte 2 inner matches; eve has one burst of 3 | (eve) | **none** | (eve) | refused |
| C36 | S94, S76 | brute force then success: failures every 2 minutes 00:00 to 14:00, success at 15:00, outer timespan 2m | (bob) | **none** | (bob) | **none** |
| C37 | S95 | event_count over [failed, failed2] gte 2: one event matches both rules | none | **(bob)** | none | none |
| C38 | S95 | value_sum over [failed, failed2] gte 20: one event with Bytes 10 matches both rules | none | **(h)** | none | refused |
| C39 | S96 | event_count eq 2: bob has 3 events at 00:00, 01:00, 02:00 | (bob) | (bob) | (bob) | (bob) |
| C40 | S96 | value_avg lt 100: Bytes 1000 at 00:00, 10 at 04:00 (a window with only the 10 exists) | none | none | none | refused |
| C41 | S97, S75 | aliases list only conn_in; conn_out events have a field named ip | (10.0.0.1) | **none** | (10.0.0.1) | **none** |
| C42 | S82, S98 | filter with logsource product: windows only, on a product: windows, service: security rule | e1, e2 | **e1** | **e1** | **degraded: e1, e2** |
| C43 | S83, S98 | filter referencing a rule that does not exist | e1, e2 | e1, e2 | e1, e2 | degraded: e1, e2 |
| C44 | S77 | generate: true at the top level of the correlation rule, as the JSON schema has it | emitted | n/a | **not emitted** | **not emitted** |
| C45 | S35, S99 | temporal_ordered failed then success 800 nanoseconds apart | (bob) | (bob) | **none** | (bob) |

C27 cannot fail on groups; it records alert granularity: the evaluator raises 2 alerts (one per burst), sigma.matching and Zircolite 5 (one per event once the count is reached), Hayabusa 2. C39 and C40 record S96: all targets that run them test windows that end at events, as the evaluator does, while pySigma's fixed-bucket conversions (SPL, ES|QL) will not. C43 is `degraded` with the evaluator's result, so it is not a difference.

## Mechanisms

IDs continue the existing series: P for pySigma's rule parser and collection handling, shared by every pySigma backend; M for `sigma.matching` (M1 to M7 are in [matcher_crosscheck](../matcher_crosscheck/README.md)); H for Hayabusa (H1 to H4 are from Phase 2); Z for Zircolite. The label is the one `classify` gives on the case's dependencies.

| ID | Target | What it does | Cases | Label |
| --- | --- | --- | --- | --- |
| P1 | pySigma 2.1.2 | Rejects a condition with two operators in its rule parser (`SigmaCorrelationCondition.from_dict`): "Sigma correlation condition must have exactly one condition item". Every pySigma backend therefore refuses the rule with an error before converting it; pySigma 1.5.1 has the same check. It follows the spec's "a map of exactly one condition criterion", against the range example a few lines later (S34 is contradictory) | C08 | refusal |
| P2 | pySigma 2.1.2 | Accepts the timespan units `w`, `M` and `y` on purpose (`SigmaCorrelationTimespan`, `[smhdwMy]`); `5M` is 5 months, so events 59 minutes apart correlate | C26 | `backend-bug` candidate (S80) |
| P3 | pySigma 2.1.2 | ANDs the filter's condition into the rule, so the filter keeps the events it should suppress (T23.1) | C24, C29 | `spec-gap` (S81, S89): follows S81.b |
| P4 | pySigma 2.1.2 | Applies a filter whose logsource is a subset of the rule's (T23.2) | C42 | `spec-gap` (S82 is silent) |
| P5 | pySigma 2.1.2 | Reads `generate` only inside the `correlation` map, so a top-level `generate: true`, as in the JSON schema, is ignored | C44 | `backend-bug` candidate (S77) |
| P6 | pySigma 2.1.2 and pySigma-backend-sqlite 2.2.0 | `value_percentile` needs a `percentile` key in the condition, which the spec does not have; the backend refuses the spec's form: "needs a percentile between 0 and 100" | C23 | refusal |
| Z1 | Zircolite | Rounds timestamps to milliseconds in its SQL, so two events 800 ns apart tie | C45 | `spec-gap` (S99 is silent on the resolution) |
| M8 | matcher | Group-by values and counted values are case-sensitive | C06, C10 | `spec-gap` (S90 and S72 are silent on case) |
| M9 | matcher | Events without a group-by field form a group of their own | C30 | `spec-gap` (S32 is silent) |
| M10 | matcher | `value_count` over two fields raises `TypeError: unhashable type: 'list'` (`e.data.get` with a list) | C12, C33 | crash, `backend-bug` candidate |
| M11 | matcher | `temporal_ordered` breaks ties by arrival order: failed then success at one second fires, success then failed does not | C15, C32 | `spec-gap` (S35 is silent on equal timestamps) |
| M12 | matcher | `temporal` checks that every rule fired and never reads the condition (`_eval_temporal`) | C17 | `spec-gap` (S92): follows S92.b |
| M13 | matcher | Routes a match to correlations by rule `name` only, so a reference by `id` never fires | C18 | `backend-bug` candidate: breaks S76 |
| M14 | matcher | Never routes correlation matches onward, so a correlation over a correlation never fires, silently | C19, C34 to C36 | `backend-bug` candidate: breaks S76, whatever a chain counts |
| M15 | matcher | Never resolves the rule references in `aliases` (`SigmaCorrelationRule.resolve_rule_references` resolves `rules` only), so the group key is empty | C20, C41 | `backend-bug` candidate: breaks S75 |
| M16 | matcher | `value_percentile` computes the Nth percentile (default 95) of the values that convert to float and skips the rest, so a text field never fires | C23 | `spec-gap` (S74): follows S74.b |
| M17 | matcher | Counts an event once per referenced rule that matches it | C37, C38 | `spec-gap` (S95 is silent) |
| H5 | Hayabusa | Group-by values and counted values are case-sensitive | C06, C10 | `spec-gap` (S90 and S72 are silent on case) |
| H6 | Hayabusa | Events without a group-by field form a `null` group | C30 | `spec-gap` (S32 is silent) |
| H7 | Hayabusa | A range uses only its first operator (`process_condition_pairs`), silently | C08 | `backend-bug` candidate: breaks S34 under S34.a and S34.b |
| H8 | Hayabusa | `value_count` counts a missing field as a value (`unwrap_or_default` gives the empty string) | C11 | `spec-gap` (S72 is silent) |
| H9 | Hayabusa | `temporal_ordered` accepts equal timestamps in either order (`time >= order_floor`) | C15, C32 | `spec-gap` (S35 is silent on equal timestamps) |
| H10 | Hayabusa | `temporal` requires every rule and never reads the condition | C17 | `spec-gap` (S92): follows S92.b |
| H11 | Hayabusa | `aliases` are not applied: the group is `null`, so unrelated events correlate | C20, C41 | `backend-bug` candidate: breaks S75 |
| H12 | Hayabusa | `temporal` accepts events up to `timespan` before and after the first rule's event (`base.start_datetime ± timeframe`), so they can span twice the timespan | C31 | `backend-bug` candidate: breaks S33 under S33.a and S33.b |
| H13 | Hayabusa | A list in `field` is read as no field (`value.as_str()` is `None`), so `value_count` counts events instead of values; C12 agrees only by accident | C33 | `backend-bug` candidate: breaks S73 under S73.a and S73.b |
| H14 | Hayabusa | A temporal correlation over a correlation does not fire when the inner rule groups by another field (C34) or when the inner condition last held minutes before (C36). Guess, not traced: `detect_within_timeframe` compares group keys across rules and uses the start of each inner window, and inner windows do not overlap | C34, C36 | C34 `backend-bug` candidate: breaks S76, whatever a chain counts, though the cause is a guess; C36 `spec-gap`: it turns on the silent part of S94 (if an inner match is only its rising edge, nothing falls within 2 minutes of the success) |
| H15 | Hayabusa | Does not parse global filters and runs the rules without them | C24, C25, C29, C42, C43 | degraded; `spec-gap` where the result differs, since it reports the skipped filter and the spec does not say whether a tool may run the rules without it (S98 is silent) |
| H16 | Hayabusa | Reads `generate` only inside the `correlation` map (`rule.yaml["correlation"]["generate"]`), like P5 | C44 | `backend-bug` candidate (S77) |

Refusals: P1 (C08) and P6 (C23); Hayabusa does not parse correlations without `group-by` (C07, S71 is contradictory), `neq` (C09), an `event_count` or `value_sum` over a correlation or over two rules (C19, C35, C38), `value_sum`, `value_avg` and `value_percentile` (C21 to C23, C40, S70 is contradictory) or `timespan: 5M` (C26, where it agrees with the evaluator). After refusing a correlation Hayabusa still emits the matches of its base rules as alerts in C07, C21 to C23, C38 and C40; whether that breaks S77 depends on whether a refused correlation still counts as referencing them.

Under the rule of 28 Nov 2026, a `backend-bug` candidate is judged by its mechanism: it must break a clear clause, or an ambiguous or contradictory clause under every reading the spec's text allows, and the case records what it breaks. H7 is the case the rule was first made for: S34 is contradictory, but under one reading Hayabusa should refuse the range and under the other it should apply both bounds, and it does neither. M14, M15 and H11 show why the mechanism decides and not the outcome: before 28 Nov, C34 to C36 and C41 looked right under readings that were ours (S94.b) or answers to a silent clause (S97), though the mechanisms behind them ignore chains and aliases altogether. None of these findings is reported yet. Like every finding, they first have to meet the reporting bar in Phase 3 step 7.
