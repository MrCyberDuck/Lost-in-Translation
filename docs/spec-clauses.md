# Sigma spec clauses for the reference evaluator (Phase 0)

The reference evaluator is the oracle: it decides what each rule *should* match according to the Sigma specification. Each clause below is something the evaluator must implement, with a unit test per clause in Phase 2.

Source: [SigmaHQ/sigma-specification](https://github.com/SigmaHQ/sigma-specification) at commit `ba9251aa834b11a70dbf80836b453dba99c5159e` (9 Jun 2026). Rules specification v2.1.0, modifiers appendix v2.1.0, correlation specification as of that commit.

**Status column:** `clear` means the spec text decides the behaviour. `ambiguous` means the spec leaves it open or says it "depends on the target SIEM". For ambiguous clauses the evaluator follows the **working interpretation** given, and every disagreement that hinges on it is reported as a *spec gap*, never as a backend bug. Working interpretations need sign-off from Nik and the co-author.

## Values and matching

| ID | Clause | Spec source | Status | Evaluator behaviour / working interpretation |
| --- | --- | --- | --- | --- |
| S1 | All values are compared as case-insensitive strings | Rules spec, Detection > General | clear for ASCII; ambiguous for non-ASCII | Case-fold with Unicode full case folding (`str.casefold()`). Non-ASCII folding is not specified; report non-ASCII cases separately (taxonomy T1). |
| S2 | `cased` makes matching case-sensitive | Modifiers > Generic | clear | Exact code-point comparison. |
| S3 | Plain value (no modifier, no wildcard) matches the whole field value | Rules spec, Maps | clear | Full-string equality after S1. |
| S4 | `*` matches any sequence (including empty); `?` matches exactly one character | Rules spec, String Wildcard | clear | Translate to an anchored pattern over the whole value. "Character" = one Unicode code point (working interpretation). |
| S5 | Escaping: `\*` and `\?` are literal; `\\*` is a literal backslash followed by a wildcard; `\\\*` is a literal backslash and a literal star; a backslash not followed by a wildcard is literal; `\\\\` (or three) is a literal `\\` | Rules spec, Escape Character | clear, but the 3-backslash rule is unusual | Implement exactly as listed; follow pySigma's `SigmaString` parsing and test every row of the spec list. |
| S6 | `contains`, `startswith`, `endswith` add `*` around/after/before the value | Modifiers > Generic | clear | Applied before wildcard translation, so inner wildcards still work. |
| S7 | Lists of values under one field are OR; `all` makes them AND | Rules spec, Lists; Modifiers > `all` | clear | |
| S8 | A map's keys are AND | Rules spec, Maps | clear | |
| S9 | A list of maps is OR | Rules spec, Lists | clear | |
| S10 | Keyword lists (no field) search the "full log message" | Rules spec, Keywords search | ambiguous | Working interpretation: substring match (case-insensitive, wildcards honoured) against **any string field value** of the event, not token matching. T12 tests rely on this. |
| S11 | Integers in rules are compared with the field value | Rules spec, Maps (`EventID: 4769`) | ambiguous | Working interpretation: compare as strings ("all values are treated as strings"), so `4688` matches int 4688 and string "4688", and `0x10` does **not** match `16`. |
| S12 | Modifiers apply left to right in the order written | Rules spec, Value Modifiers | clear | |
| S13 | Transformation modifiers expand values (`base64`, `base64offset`, `utf16le`/`wide`, `utf16be`, `utf16`, `windash`) | Modifiers > String | clear | Reuse pySigma's modifier implementations so expansion is identical to what backends receive; the oracle differs only in matching. |
| S14 | `windash` permutes `-`, `/`, en dash, em dash, horizontal bar | Modifiers > String | clear | Five characters, all permutations. |
| S15 | `re` uses a restricted PCRE subset; case-sensitive by default; sub-modifiers `i`, `m`, `s` | Modifiers > Regular Expression | clear on syntax; ambiguous on anchoring | Working interpretation: **unanchored search** (`re.search`), as PCRE does. Rules using unsupported metacharacters are tagged `out_of_spec_regex` and reported separately. |
| S16 | Numeric modifiers `lt`, `lte`, `gt`, `gte`, `neq` | Modifiers > Numeric | ambiguous for string-typed fields | Working interpretation: parse the field value as an integer; if it does not parse, the comparison is false. |
| S17 | `cidr` matches IPv4 and IPv6 networks | Modifiers > IP | ambiguous for IPv4-mapped IPv6 | Use Python `ipaddress`; IPv4-mapped IPv6 (`::ffff:a.b.c.d`) does **not** match an IPv4 network (working interpretation). Unparseable value = no match. |
| S18 | `exists: true/false` checks only presence of the field, not its value | Modifiers > Generic | clear | Present-but-empty and present-but-null both count as existing. |
| S19 | `neq` on strings: field is different from the value | Modifiers > Generic | ambiguous for missing fields | Working interpretation: a missing field does not satisfy `neq`. |
| S20 | `fieldref` compares one field with another field of the same event | Modifiers > Specific | ambiguous on case | Case-insensitive (S1) unless `cased` is chained. |
| S21 | `expand` placeholders must be resolved or the rule rejected | Rules spec, Placeholders | clear | Rules with `expand` are excluded from the main run (they live in `rules-placeholder`, not in scope). |
| S22 | Time modifiers (`minute`, `hour`, `day`, `week`, `month`, `year`) | Modifiers > Time | clear on range, ambiguous on time zone | Not used by in-scope rules (to verify in Phase 2); out of scope unless found. |

## Null, empty and missing

| ID | Clause | Spec source | Status | Evaluator behaviour / working interpretation |
| --- | --- | --- | --- | --- |
| S23 | `''` is an empty value | Rules spec, Special Field Values | clear | Matches a present field whose value is the empty string. |
| S24 | `null` is a null value; "the application depends on the target SIEM" | Rules spec, Special Field Values | **ambiguous by design** | Working interpretation: `field: null` matches when the field is absent **or** present with JSON null; it does not match `''`. Every T4 disagreement is a spec gap. |
| S25 | A field missing from the event never matches a value condition | implied | clear | So `not sel` is true when `sel`'s field is missing. |

## Conditions

| ID | Clause | Spec source | Status | Evaluator behaviour / working interpretation |
| --- | --- | --- | --- | --- |
| S26 | Operators `and`, `or`, `not`, brackets | Rules spec, Condition | clear | |
| S27 | Precedence from loosest to tightest: `or`, `and`, `not`, `x of`, brackets | Rules spec, Condition | clear | Use pySigma's condition parser, which implements this. |
| S28 | `1 of them` / `all of them` exclude identifiers that start with `_` | Rules spec, Condition | clear | |
| S29 | `1 of pattern` / `all of pattern` with `*` wildcards in the pattern | Rules spec, Condition | clear | `all of` over zero matching identifiers: working interpretation is a rule error (pySigma raises). |
| S30 | A condition given as a list is an OR of its items | Rules spec, Condition | clear | |

## Correlation rules

SigmaHQ r2026-07-01 contains **no** correlation rules in its rule folders, so correlation is tested only with synthetic cases in the conformance suite (taxonomy T11).

| ID | Clause | Spec source | Status | Evaluator behaviour / working interpretation |
| --- | --- | --- | --- | --- |
| S31 | `event_count`, `value_count`, `temporal`, `temporal_ordered` (plus `value_sum`, `value_avg`, `value_percentile`) | Correlation spec, Correlation Types | clear on meaning | |
| S32 | `group-by` fields are ANDed into one grouping key | Correlation spec, Grouping | ambiguous for missing group fields | Working interpretation: events with a missing group-by field are not grouped (excluded). |
| S33 | `timespan` is a period in which the correlation applies; "should not be restricted to boundaries if this is not required by the given backend" | Correlation spec, Time Selection, Temporal | **ambiguous** | Working interpretation: a **sliding** window. Tumbling-window backends will disagree on boundary cases; that is reported as a spec gap plus the backend's choice. |
| S34 | Condition operators `gt`, `gte`, `lt`, `lte`, `eq`, `neq`, combinable as a range | Correlation spec, Condition | clear | |
| S35 | `temporal_ordered`: events appear in the order of the `rules` list | Correlation spec | ambiguous on equal timestamps | Working interpretation: equal timestamps do not count as ordered. |

## Open questions for the co-author

1. S10 keywords: substring in any field (current choice) or a full-text match on the raw message?
2. S11 integers: string comparison (current choice) or numeric comparison when both sides parse?
3. S24 null: absent-or-null (current choice), or absent only?
4. S33 correlation windows: sliding (current choice) or tumbling?
