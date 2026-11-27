# Phase 3 review log

Every checkpoint review of Phase 3, per the review tiers in the Phase 3 plan. Reviewers start from a fresh context and see only the artifacts. Claude verifies every point a reviewer raises; contested points go to Nik.

## Step 2: evaluator filters and correlations (critical tier, 26 Nov 2026)

Reviewed commit 1f4463d: `harness/evaluator/collection.py`, its unit tests, clauses S89 to S93, and the first cross-check (31 cases).

| Reviewer | Model | Brief | Points |
| --- | --- | --- | --- |
| Method and oracle | Opus 5.5, extra effort | implementation against the clauses, correlation semantics, clause statuses, cross-check design and adapters | 18 |
| Findings and claims | Sonnet 5.5, high effort | re-run every target, check every table cell, mechanism, label and summary claim | 12 |

Both reviewers re-ran the targets on copies of the repository. Sonnet found the results byte-identical to the committed ones.

### Verified and applied

| Point | Raised by | What was wrong | Change |
| --- | --- | --- | --- |
| Chains | Opus 1 | A correlation over a correlation saw only the rising edges of the inner one and only the inner group-by values; the spec's brute-force example could not fire | New clause S94; chain items are every window where the inner condition holds, with the fields of the event that ends it; cases C34 to C36 |
| Double counting | Opus 2 | An event matched by two referenced rules was counted twice; a rule referenced twice was allowed | New clause S95; events counted once; a repeated reference is a rule error (S76, JSON schema `uniqueItems`); cases C37, C38 |
| Temporal condition | Opus 3, Sonnet 1 | M12 and H10 were labelled `backend-bug` under S31, but the verdict depends on S92 | S92 widened to the condition of `temporal`; M12, H10 now `spec-gap` |
| Labels by hand | Opus 5 | Labels bypassed `harness.triage.classify`; H12 and M10 cited open clauses | Every case lists the clauses its verdict depends on; `classify` computes the label; the reading of "depends on" is open with Nik (below) |
| Non-monotone conditions | Opus 6 | `eq`, `lt` and `value_avg` are tested on windows that end at events, which no clause said | New clause S96; cases C39, C40 |
| Hayabusa refusals | Opus 7, Sonnet 5 | A skipped filter with the rule still running was counted as a refusal; leaked base-rule alerts were not reported | New outcome `degraded`; a second Hayabusa run without filters tells which document was skipped; leaks listed; C25 and C29 now have a group-by so the filter is tested on its own |
| Crash vs refusal | Opus 7, Sonnet 6 | The matcher's TypeError was counted as a refusal | New outcome `crash` |
| Event order | Opus 8, Sonnet 7 | sigma.matching got events in file order; M11 depended on it | Events in time order; case C32 swaps the tie; M11 restated as arrival order |
| Overclaims | Opus 9, Sonnet 3, 4 | "supports the evaluator", "no case has all three against it", "three behaviours" | Result section rewritten: what is and is not supported, shared pySigma parsing, the four clauses with no support |
| Hayabusa chains | Opus 10 | "Hayabusa refuses chains" was too general | T11.9 and H14 corrected |
| Partial aliases | Opus 12 | S75 "clear" did not cover an alias that lists only some rules | New clause S97 (fall back to the field of that name); case C41 |
| Timestamps | Opus 13 | Fractions cut to microseconds; dropped events silent | Nanosecond comparison; dropped events reported in `warnings`; case C45 |
| `generate` | Opus 14 | `generate: 'false'` read as true; placement undocumented | Must be a boolean; top level first, as in the JSON schema; S77 row; case C44 |
| Docs vs code | Opus 15, Sonnet 11 | S33, S74, S76, S32, value_sum and S89 marking differed between docstring, docs and code; changed interpretations of accepted clauses were not flagged | Docstring, rows S32, S33, S70, S72, S74, S76, S77, S92 aligned; all changed interpretations listed as waiting for Nik |
| Filter syntax | Opus 16 | Cases used `sel`; the filters spec requires `selection` | Cases fixed; the evaluator now requires `selection` and `condition` |
| Group display | Opus 17, Sonnet 12 | Python `None` showed as "none", like "no groups" | Shown as `<missing>` |
| S82 example | Opus 18 | The spec's example filter also lists a logon rule | Noted in the S82 row; cases C42, C43 for S82 and S83 |
| Percentile mechanisms | Sonnet 2, Opus 11 | Zircolite's C23 refusal and M16 were described wrongly | P6 (the `percentile` key) and M16 (numeric percentile, text skipped) |
| Alias mechanism | Sonnet 8 | M15's cause was wrong; C20 also depended on S32 | M15 restated (alias references never resolved); C20 without the extra events |
| Hidden deviation | Sonnet 9 | Hayabusa agreed on C12 by accident (a list `field` is read as none) | H13; case C33 |
| `5M` | Sonnet 10 | P2 was shown without consequence | C26 spreads events over 59 minutes; P2 says `M` is a month in pySigma |
| Case coverage wording | Sonnet 11 | "one or two per clause" was not true | Wording dropped; S82 and S83 now have cases; S78 and S79 are backend obligations, checked in the conformance runs |
| `SystemTime` | Sonnet 12 | README said only Zircolite's events had it | Fixed |

### Not applied

| Point | Raised by | Why |
| --- | --- | --- |
| Hayabusa `lte` may fire on partial windows (V13) | Sonnet 12 | Not reproduced as a mechanism here; it falls under S96 and goes to the step 4 cases |
| Tie-free variants of C08 and C09 | Opus 6 | C39 covers an upper bound on the way up; C08 keeps its ties so it tests the range alone |

### Decided by Nik

| Point | Decision | Change |
| --- | --- | --- |
| S34 was `clear`, but the spec says "a map of exactly one condition criterion" and then shows a range with two operators; both reviewers read this as contradictory | `contradictory` (27 Nov 2026) | S34 row; proposed clarifications SC1 and SC2 (the JSON schema checks no condition) in [spec-clarifications.md](spec-clarifications.md) |
| The reading of "depends on" in triage-labels.md | A clause excuses a result only if the result is right under one of its readings; three safeguards (27 Nov 2026) | Readings of all 51 open clauses in spec-clauses.md; `classify` takes `wrong_under` and checks it; cases list every open clause they touch; M3, M7, M10, H7, H12, H13 and the clear-clause candidates C18 to C20 record their readings; H7 is a `backend-bug` candidate again. In Phase 2, C7 and H4 are wrong under every reading of S37 and S87 and become `config`. Two clauses the audit found missing: S98 (a tool that cannot apply a filter, SC3) and S99 (timestamp resolution, SC4) |

### Open with Nik

1. The working interpretations of S89 to S99, and the changed interpretations of S32, S33, S70, S72, S74, S76, S77 and S92. S74 in particular: the evaluator reads `value_percentile` as a value's share of the events, as the spec's example title suggests; pySigma reads it as a numeric percentile, as the hint "median is a percentile 50" suggests. The reading lists of the open clauses, written on 27 Nov 2026, are checked by the step 6 review.
