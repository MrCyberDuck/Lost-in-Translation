# Sigma spec clauses for the reference evaluator

The reference evaluator is the oracle: it decides what each rule *should* match according to the Sigma specification. Each clause below is something the evaluator must implement, with a unit test per clause (`tests/test_evaluator.py`, and `tests/test_collection.py` for correlations and filters), and each clause is a place where a converter or engine can disagree with the spec.

Source: [SigmaHQ/sigma-specification](https://github.com/SigmaHQ/sigma-specification) at commit `ba9251aa834b11a70dbf80836b453dba99c5159e` (9 Jun 2026): rules specification v2.1.0, modifiers appendix v2.1.0, filters specification v2.1.0, correlation specification and taxonomy appendix as of that commit.

## How to read this list

**Status** is one of:

- `clear`: the spec text decides the behaviour.
- `ambiguous`: the spec is silent, leaves it to the target SIEM, or can be read two ways.
- `contradictory`: two parts of the spec disagree with each other.

For every `ambiguous` or `contradictory` clause the evaluator follows the **working interpretation** given. The working interpretations of S1 to S88 were accepted by Nik on 23 and 24 Nov 2026, including the four questions that were open (see the end of this file). Those of S89 to S99, and the changes to the interpretations of S32, S33, S70, S72, S74, S76, S77 and S92, were written on 26 and 27 Nov 2026, when the evaluator gained correlations and filters in Phase 3 step 2, and wait for Nik's acceptance. S34 was listed as `clear` until Nik marked it `contradictory` on 27 Nov 2026; its interpretation did not change. Accepting an interpretation does not make a clause clear: its status stays `ambiguous`, and the clause keeps all its readings (see [Readings of the open clauses](#readings-of-the-open-clauses)).

**Spec-gap rule (decisions of 23 and 27 Nov 2026).** A disagreement is labelled `spec-gap`, never `backend-bug`, when the target's result is right under at least one reading of an `ambiguous` or `contradictory` clause the case depends on. Only a result that is wrong under every reading of every such clause can be a `backend-bug` candidate, and the case records those readings. A `spec-gap` is reported as a proposed clarification to the Sigma specification ([spec-clarifications.md](spec-clarifications.md)), not filed against a backend. The full label set is in [triage-labels.md](triage-labels.md) and is enforced in `harness/triage.py`.

**Rules** is how many of the 2,247 in-scope rules use the construct, from `results/phase0/construct_census.json` (`python -m harness.construct_census`). A dash means it is not counted automatically.

## Audit of the first version (35 clauses)

The first version was **not exhaustive**. It covered value matching, modifiers, null handling, conditions and the four main correlation types, but it skipped or under-specified the following. All of them are added below as S36 to S84.

| Missed area | Why it matters for mismatches | New clauses |
| --- | --- | --- |
| Logsource scoping and the taxonomy appendix | Without a pipeline, every backend drops the logsource, so a rule can match events of the wrong type. With a pipeline, each backend adds its own EventID/Channel filter. | S36 to S38 |
| YAML typing of rule values | Unquoted `true`, `0x10`, `010` become booleans and integers before Sigma ever sees them. | S39, S40 |
| Backslash pairs not followed by a wildcard | `\\` means one backslash, not two; 63 rules use it. | S41 |
| Field names: case, dots, multi-valued fields | Engines differ on case-sensitive field names (SQLite is not), on dotted names and on arrays. | S42 to S44 |
| Whitespace, newlines, Unicode normalisation | 532 rules have leading or trailing spaces in values; PowerShell script blocks are multi-line, and `*` across a newline differs by engine. | S45 to S48 |
| Detection structure edge cases | Empty lists, `null` inside lists, keyword lists with `all`, undefined identifiers. | S49 to S54 |
| Condition parsing details | Keyword case, `_` identifiers with explicit patterns, `and`/`or` mixing (61 rules). | S55 to S57 |
| Modifier details | `neq` with lists, `cidr` notations, regex outside the spec subset (42+ rules), `base64offset` edges, `windash` scope, `expand` rejection, unknown modifiers. | S58 to S69 |
| Correlation details and spec inconsistencies | The spec lists 4 allowed types but defines 7; `group-by` is both mandatory and optional; distinct-value case; chaining; aliases; must-error rules. | S70 to S80 |
| Global filters (meta-filters) | A third rule kind the first version ignored. | S81 to S83 |
| Field value formats from the taxonomy | `Hashes` packs several hashes into one string (46 rules). | S84 |

What is still out of scope, on purpose: rule metadata that converters do not use (title, author, tags, level, references, dates, `fields`, `falsepositives`), file naming, and pySigma processing pipelines themselves, which are a pySigma feature rather than part of the Sigma spec (they are tested through the production configuration, taxonomy area T10).

## Values and matching

| ID | Clause | Spec source | Status | Rules | Evaluator behaviour / working interpretation |
| --- | --- | --- | --- | --- | --- |
| S1 | All values are compared as case-insensitive strings | Rules spec, Detection > General | clear for ASCII; ambiguous for non-ASCII | all | Case-fold with Unicode full case folding (`str.casefold()`). Non-ASCII folding is not specified; non-ASCII cases are a spec gap (taxonomy T1). |
| S2 | `cased` makes matching case-sensitive | Modifiers > Generic | clear | 0 | Exact code-point comparison. |
| S3 | A plain value (no modifier, no wildcard) matches the whole field value | Rules spec, Maps | clear | — | Full-string equality after S1. |
| S4 | `*` matches any sequence (including empty); `?` matches exactly one character | Rules spec, String Wildcard | clear; ambiguous on what a "character" is | 19 inner `*`, 11 `?` | Anchored pattern over the whole value. One character = one Unicode code point (working interpretation). |
| S5 | Escaping: `\*` and `\?` are literal; `\\*` is a literal backslash followed by a wildcard; `\\\*` is a literal backslash and a literal star; three or four backslashes are a literal `\\` | Rules spec, Escape Character | clear | 30 escaped wildcards | Implement every row of the spec list; follow pySigma's `SigmaString` parsing. |
| S6 | `contains`, `startswith`, `endswith` add `*` around/after/before the value | Modifiers > Generic | clear | 1,617 / 225 / 1,385 | Applied before wildcard translation, so inner wildcards still work. |
| S7 | Lists of values under one field are OR; `all` makes them AND | Rules spec, Lists; Modifiers > `all` | clear | 550 use `all` | |
| S8 | A map's keys are AND | Rules spec, Maps | clear | all | |
| S9 | A list of maps is OR | Rules spec, Lists | clear | 690 | |
| S10 | Keyword lists (no field) search the "full log message" | Rules spec, Keywords search | ambiguous | 12 | Substring match (case-insensitive, wildcards honoured) against **any string field value** of the event, not token matching. |
| S11 | Integers in rules are compared with the field value | Rules spec, Maps | ambiguous | 330 | Compare as strings ("all values are treated as strings"): `4688` matches int 4688 and string "4688"; `0x10` does **not** match `16`. |
| S12 | Modifiers apply left to right in the order written | Rules spec, Value Modifiers | clear | — | |
| S13 | Transformation modifiers expand values (`base64`, `base64offset`, `utf16le`/`wide`, `utf16be`, `utf16`, `windash`) | Modifiers > String | clear | 7 `base64offset`, 71 `windash` | Reuse pySigma's modifier implementations so expansion is identical to what backends receive; the oracle differs only in matching. |
| S14 | `windash` permutes `-`, `/`, en dash, em dash, horizontal bar | Modifiers > String | clear | 71 | Five characters, all permutations. |
| S15 | `re` uses a restricted PCRE subset; case-sensitive by default; sub-modifiers `i`, `m`, `s` | Modifiers > Regular Expression | clear on syntax; ambiguous on anchoring | 68 | **Unanchored search** (`re.search`), as PCRE does. Rules using metacharacters outside the subset: see S60. |
| S16 | Numeric modifiers `lt`, `lte`, `gt`, `gte`, `neq` | Modifiers > Numeric | ambiguous for string-typed fields | 0 | Parse the field value as a number; if it does not parse, the comparison is false. |
| S17 | `cidr` matches IPv4 and IPv6 networks | Modifiers > IP | ambiguous for IPv4-mapped IPv6 | 16 | Python `ipaddress`; `::ffff:a.b.c.d` does **not** match an IPv4 network. Unparseable value = no match. |
| S18 | `exists: true/false` checks only presence of the field, not its value | Modifiers > Generic | clear | 0 | Present-but-empty and present-but-null both count as existing. |
| S19 | `neq` on strings: field is different from the value | Modifiers > Generic | ambiguous for missing fields | 0 | A missing field does not satisfy `neq`. |
| S20 | `fieldref` compares one field with another field of the same event | Modifiers > Specific | ambiguous on case | 1 | Case-insensitive (S1) unless `cased` is chained. |
| S21 | `expand` placeholders must be resolved or the rule rejected | Rules spec, Placeholders | clear | 0 | Not in the main run; see S67 for the rejection test. |
| S22 | Time modifiers (`minute`, `hour`, `day`, `week`, `month`, `year`) | Modifiers > Time | clear on range, ambiguous on time zone | 0 | Conformance cases only. |

## Null, empty and missing

| ID | Clause | Spec source | Status | Rules | Evaluator behaviour / working interpretation |
| --- | --- | --- | --- | --- | --- |
| S23 | `''` is an empty value | Rules spec, Special Field Values | clear | 31 | Matches a present field whose value is the empty string. |
| S24 | `null` is a null value; "the application depends on the target SIEM" | Rules spec, Special Field Values | **ambiguous by design** | 65 | `field: null` matches when the field is absent **or** present with JSON null; it does not match `''`. |
| S25 | A field missing from the event never matches a value condition | implied by two-valued `not` (Conditions) | clear (confirmed by Nik, 2026-11-23) | all | So `not sel` is true when `sel`'s field is missing. |

## Conditions

| ID | Clause | Spec source | Status | Rules | Evaluator behaviour / working interpretation |
| --- | --- | --- | --- | --- | --- |
| S26 | Operators `and`, `or`, `not`, brackets | Rules spec, Condition | clear | 596 use `not` | |
| S27 | Precedence from loosest to tightest: `or`, `and`, `not`, `x of`, brackets | Rules spec, Condition | clear | 61 mix `and`/`or` | pySigma's condition parser. Missing brackets in output are converter bugs (seen in Loki, case T9-001). |
| S28 | `1 of them` / `all of them` exclude identifiers that start with `_` | Rules spec, Condition | clear | 0 use `them` | |
| S29 | `1 of pattern` / `all of pattern` with `*` wildcards in the pattern | Rules spec, Condition | clear | 1,125 | `all of` over zero matching identifiers is a rule error (pySigma raises). |
| S30 | A condition given as a list is an OR of its items | Rules spec, Condition | clear | 0 | |

## Correlation rules (original clauses)

SigmaHQ r2026-07-01 contains **no** correlation rules in its rule folders, so every correlation clause is tested only with synthetic cases in the conformance suite (taxonomy T11).

| ID | Clause | Spec source | Status | Evaluator behaviour / working interpretation |
| --- | --- | --- | --- | --- |
| S31 | `event_count`, `value_count`, `temporal`, `temporal_ordered` (plus `value_sum`, `value_avg`, `value_percentile`) | Correlation spec, Correlation Types | clear on meaning | |
| S32 | `group-by` fields are ANDed into one grouping key | Correlation spec, Grouping | ambiguous for missing group fields | Events with a missing group-by field, or with a list or map in it, are not grouped (excluded). |
| S33 | `timespan` is a period in which the correlation applies; "should not be restricted to boundaries if this is not required by the given backend" | Correlation spec, Time Selection, Temporal | **ambiguous** | A **sliding** window: the windows are the spans of `timespan` that end at an event of the group (S91 for the bounds, S96 for conditions that are not monotone). |
| S34 | Condition operators `gt`, `gte`, `lt`, `lte`, `eq`, `neq`, combinable as a range | Correlation spec, Condition; JSON schema | **contradictory** | The Condition section says "It is a map of exactly one condition criterion" and, a few lines later, "To define a range, you can use the conjunction 'AND' in the mapping", with the example `gt: 100`, `lte: 200`. The JSON schema does not settle it: it gives the condition `maxItems: 3`, which JSON Schema applies only to arrays, so the schema accepts any condition. Every operator given must hold, so two operators form a range. pySigma 1.5.1 and 2.1.2 follow the first sentence and reject a range in their rule parser, so every pySigma backend refuses such a rule with an error. |
| S35 | `temporal_ordered`: events appear in the order of the `rules` list | Correlation spec | ambiguous on equal timestamps | Equal timestamps do not count as ordered. |

## New: logsource and taxonomy

| ID | Clause | Spec source | Status | Rules | Evaluator behaviour / working interpretation |
| --- | --- | --- | --- | --- | --- |
| S36 | `logsource` (category, product, service) selects which events a rule applies to | Rules spec, LogSource | clear on intent; implementation left to converters | all | **Neutral config:** every event in a dataset belongs to the rule's logsource, so logsource is not evaluated. **Production config:** apply S37. A converter that silently drops the logsource while claiming a pipeline is applied is a `backend-bug`. |
| S37 | The taxonomy appendix maps Windows categories to EventID + Channel (for example `process_creation` = Sysmon EventID 1, `ps_script` = EventID 4104 on two PowerShell channels) | Taxonomy appendix, Windows Folder | clear for Sysmon-based categories; ambiguous where other sources (Security 4688) also provide the category | 2,247 | Use the appendix table as the logsource filter in production-config runs. A pipeline that also accepts Security 4688 for `process_creation` is recorded as a `config` difference. |
| S38 | `definition` in logsource is not evaluated by converters | Rules spec, LogSource | clear | — | Ignored. |

## New: YAML and value typing

| ID | Clause | Spec source | Status | Rules | Evaluator behaviour / working interpretation |
| --- | --- | --- | --- | --- | --- |
| S39 | Rules are YAML; unquoted scalars are typed by the YAML loader (`true` is a boolean, `0x10` is the integer 16, `010` is the integer 8 in YAML 1.1) | Rules spec, Yaml File; General ("treated as strings") | **contradictory**: YAML typing vs "all values are strings" | 1 boolean in scope; 3 `true` values in Windows rules overall | Use pySigma's loader (it keeps booleans as booleans). Compare a boolean `true` case-insensitively with the strings `true`/`True`. Any mismatch on typed values is a spec gap. |
| S40 | Quoting: only the YAML quote character needs escaping in values | Rules spec, Detection > General | clear | 95 | Escaping of quotes in the target query is the converter's job; a broken query is a `backend-bug`. |
| S41 | A backslash not followed by a wildcard may be written single or double: `\\` means one backslash | Rules spec, Escape Character | clear (but surprising) | 63 | `C:\\Windows` means `C:\Windows`. A backend that searches for two backslashes is a `backend-bug`. UNC paths therefore need `\\\\` in the rule. |

## New: field names and field values

| ID | Clause | Spec source | Status | Rules | Evaluator behaviour / working interpretation |
| --- | --- | --- | --- | --- | --- |
| S42 | Field names are given as they appear in the log source; whether they are case-sensitive is not stated | Rules spec, Field Usage | ambiguous | all | Field names are case-sensitive (exact). SQLite column names are case-insensitive, so `image` and `Image` collide there; such cases are a spec gap. |
| S43 | Windows XML attributes become `Tag_Attribute` names (`Provider_Name`); dotted names (`event.category`) are allowed in other taxonomies | Rules spec, Field Usage | clear for underscores; ambiguous for dots (flat key or nested object) | — | Dotted names are flat keys in the neutral config. |
| S44 | A field holding several values (an array) | not covered | ambiguous | — | The field matches if **any** element matches. |
| S45 | Leading and trailing spaces inside a value are part of the value | Rules spec, Maps (implied) | clear | 532 | No trimming, on either side. |
| S46 | Whether `*` and `?` match a newline | not covered | ambiguous | 158 `ps_script` rules match multi-line script blocks | `*` matches any character including newline. Matters for Loki and regex-based translations. |
| S47 | Unicode normalisation (composed vs decomposed characters) | not covered | ambiguous | 23 non-ASCII values | No normalisation; compare code points. |
| S48 | Repeated spaces and tabs inside values are literal | implied by S3 | clear | 7 | No whitespace collapsing. |

## New: detection structure

| ID | Clause | Spec source | Status | Rules | Evaluator behaviour / working interpretation |
| --- | --- | --- | --- | --- | --- |
| S49 | `null` cannot be part of a list of values and must be its own selection | Rules spec, Special Field Values | clear | 0 violations | The evaluator rejects such rules. A backend that converts them silently is noted, not counted. |
| S50 | Keyword lists with `'\|all':` mean every keyword must appear | Rules spec, Keywords search | ambiguous: in one field or each in any field | — | Each keyword may appear in a different field. |
| S51 | An empty list of values or an empty selection | not covered | ambiguous | 0 | Rule error. |
| S52 | A condition that names an identifier which is not defined | Rules spec, Condition (implied) | clear | 0 | Rule error. A backend that converts it is a `backend-bug`. |
| S53 | Identifiers defined but not used in the condition are ignored | Rules spec, Condition (implied) | clear | — | |
| S54 | Several fields in one map, one of them missing from the event | S8 + S25 | clear | — | The selection is false. |

## New: condition parsing

| ID | Clause | Spec source | Status | Rules | Evaluator behaviour / working interpretation |
| --- | --- | --- | --- | --- | --- |
| S55 | Case of the condition keywords (`and` vs `AND`) | Rules spec, Condition (examples are lower case) | ambiguous | — | Accept what pySigma accepts. |
| S56 | `1 of _filter*`: an explicit pattern that matches identifiers starting with `_` | Rules spec, Condition (the `_` exclusion is stated only for `them`) | ambiguous | 0 | Explicit patterns **include** `_` identifiers. |
| S57 | `not` applied to `1 of` / `all of` (`not 1 of filter_*`) | Rules spec, Condition (precedence list) | clear | part of 596 | `not` binds looser than `x of`. |

## New: modifier details

| ID | Clause | Spec source | Status | Rules | Evaluator behaviour / working interpretation |
| --- | --- | --- | --- | --- | --- |
| S58 | `neq` with a list of values | Modifiers > Generic | ambiguous: different from all (AND) or from any (OR) | 0 | Different from **all** listed values. |
| S59 | `cidr` value notations: compressed IPv6, zone IDs (`fe80::1%eth0`), IPv4 with leading zeros (`010.0.0.1`) | Modifiers > IP | ambiguous | 16 | Zone IDs and leading-zero IPv4 do not parse, so no match. |
| S60 | `re` metacharacters outside the spec subset (`\d`, `\w`, `\s`, `(?:`, inline flags, lazy quantifiers, lookaround, backreferences) "are unsupported and can not be used" | Modifiers > Regular Expression | clear | 42 shorthand classes, 19 `(?:`, 10 inline flags, 9 lazy | Rules that use them are **outside the spec**: label `rule-out-of-spec`, reported separately, never as a backend bug or spec gap. The evaluator still runs them with Python `re` for information. |
| S61 | `re\|i`, `re\|m`, `re\|s` sub-modifiers | Modifiers > Regular Expression | clear | 1 | Map to the regex flags. |
| S62 | `re` values do not get Sigma wildcard or escape processing | Modifiers > Regular Expression (implied) | clear | 68 | `*` is a regex quantifier, `\` is a regex escape. |
| S63 | `base64offset` must sit next to `contains` to make sense | Modifiers > Encoding | clear in practice | 7 | Use pySigma's three offset variants. |
| S64 | `windash` also permutes a `/` that is already in the value, and every dash in the value | Modifiers > String | clear | 71 | All occurrences, all five characters. |
| S65 | `cased` combined with `contains`, `startswith`, `endswith` and wildcards | Modifiers > Generic | clear | 0 | Wildcards still apply; only case folding is off. |
| S66 | `exists` takes a boolean, not a string | Modifiers > Generic | clear | 0 | `exists: 'true'` is a rule error. |
| S67 | A tool that cannot resolve a placeholder (`expand`) must reject the rule | Rules spec, Placeholders | clear | 0 in scope; 17 in `rules-placeholder` | Conformance case: every backend without a placeholder pipeline must refuse to convert. Emitting the literal `%name%` is a `backend-bug`. |
| S68 | Unknown or misspelled modifiers | not covered | ambiguous | 0 | Rule error. |
| S69 | Numeric modifiers with float or negative values, or with numbers quoted as strings in the rule | Modifiers > Numeric | ambiguous | 0 | Parse both sides as numbers; quoted numbers are accepted. |

## New: correlation details

| ID | Clause | Spec source | Status | Evaluator behaviour / working interpretation |
| --- | --- | --- | --- | --- |
| S70 | Allowed correlation types are listed as 4, but `value_sum`, `value_avg` and `value_percentile` are defined later | Correlation spec, Correlation type vs Correlation Types | **contradictory** | Accept all 7. A backend that rejects the last 3 is not a bug. `value_sum` and `value_avg` use the events whose field parses as a number (S16) and ignore the others. |
| S71 | `group-by` is "Use: mandatory" but the text says it "optionally defines" fields | Correlation spec, Grouping | **contradictory** | A correlation without `group-by` groups all events together. |
| S72 | `value_count` counts distinct values; whether `Admin` and `admin` are distinct is not stated | Correlation spec, Value Count + S1 | ambiguous | Distinct after case folding (S1). An event without the field adds no value. |
| S73 | `value_count` with several `field` values links them with AND | Correlation spec, Value Count | ambiguous (counted as tuples or separately) | Count distinct tuples. |
| S74 | `value_percentile` semantics ("check when a certain percentage of observed values occur") | Correlation spec, Value Percentile | ambiguous | The condition holds when some value of `field` has a share, in percent, of the window's events that have the field, that meets the condition (`lte: 1` fires on a value seen in at most 1% of them). Spec gap on every disagreement. |
| S75 | `aliases` map one group-by name to different fields per referenced rule | Correlation spec, Field Name Aliases | clear | |
| S76 | Referenced rules may be given by `id` or `name`; correlations may reference correlations (chains) | Correlation spec, Related rules | clear | The same rule referenced twice, for example by name and by id, is a rule error: the JSON schema gives `rules` `uniqueItems`. What a chained correlation sees is S94. |
| S77 | `generate`: by default only the correlation query is produced, not the referenced rules | Correlation spec, Generate; JSON schema | clear | A backend that emits the base rules as alerts by default is a `backend-bug`. `generate` is a top-level boolean, as in the JSON schema; the evaluator reads `correlation.generate`, where pySigma expects it, only when the top-level key is absent. Any other value is a rule error. |
| S78 | A backend must raise an error rather than convert a feature it cannot support where the spec says "must" (counting by group, applying the condition) | Correlation spec, Compatibility | clear | A silent conversion that drops grouping or the condition is a `backend-bug`. |
| S79 | A backend should warn when it can only approximate a "should" feature (ordering, sliding windows) | Correlation spec, Compatibility | clear | A tumbling window **with** a warning is a spec gap (S33); **without** a warning it is a `backend-bug` against this clause. |
| S80 | `timespan` format is a number plus `s`, `m`, `h` or `d` in lower case | Correlation spec, Time Selection | clear | Other formats are rule errors. pySigma 1.5.1 also accepts `w`, `M` and `y`. |
| S90 | Whether `group-by` values that differ only in case form one group | not covered; S1 makes value comparison case-insensitive | ambiguous | One group: values are case-folded as in S1, so `Bob` and `bob` are counted together. |
| S91 | Whether an event exactly `timespan` before the last event is inside the window | Correlation spec, Time Selection, does not say | ambiguous | Inside: the window ending at an event at time t is `[t - timespan, t]`, both ends included. |
| S92 | `condition` is "Use: mandatory" and for `temporal` "specified the count of different event types", but Temporal Proximity says "All events defined by the rules referred by the rule field must occur in the time frame", its Requires list and the JSON schema have no condition, and its examples have none | Correlation spec, Condition vs Temporal Proximity; JSON schema | **contradictory** | Without a condition, every referenced rule must match in the window, which is also pySigma's default (`gte` the number of rules). With a condition, `temporal` counts the referenced rules that matched in the window, and `temporal_ordered` the length of the longest prefix of `rules` seen in order. |
| S93 | What one correlation match is: how many alerts a burst gives and when | not covered | ambiguous | One alert per group each time the condition becomes true, at the event that ends the first window where it holds; it fires again only after the condition has been false. Results are compared with backends by the set of groups that fire, not by alert counts. For chains, S94. |
| S94 | What a correlation that references a correlation counts | Correlation spec, Related rules and the brute-force example ("the correlation rule only uses its own group-by") | ambiguous | One item for every window where the inner condition holds, not only for the rising edges of S93, at the time of the event that ends the window and with that event's fields, so the outer correlation groups by its own fields. |
| S95 | An event matched by several rules of one correlation | not covered; event_count "counts events" | ambiguous | One event: `event_count` and the value types count it once. `temporal` counts each rule it matches. |
| S96 | Which windows a condition is tested on when it is not monotone (`lt`, `lte`, `eq`, `neq`, `value_avg`, `value_percentile`) | not covered | ambiguous | Every window that ends at an event (S33), so `eq: 2` fires on the way to 3 events, and a window that starts after an event is never tested. |
| S97 | A group-by alias that lists only some of the referenced rules | Correlation spec, Field Name Aliases | ambiguous | For a rule the alias does not list, the group-by name is read as a field name. |
| S99 | The resolution at which timestamps are compared for windows and order | not covered | ambiguous | The full resolution of the event's timestamp, down to nanoseconds, so two events 800 ns apart are in order. Many SIEMs store milliseconds. |

## New: global filters (meta-filters)

No global filters are shipped in the in-scope folder, so these are conformance cases only.

| ID | Clause | Spec source | Status | Evaluator behaviour / working interpretation |
| --- | --- | --- | --- | --- |
| S81 | A filter applies its selection to the rules listed in `filter.rules` to suppress their matches | Filters spec, Global Filter | ambiguous: the spec says "suppress" but does not give the boolean form | `rule condition and not filter condition`. |
| S82 | The filter's logsource versus the rule's logsource | Filters spec, Log source | ambiguous | The filter applies only when the logsources are equal. The spec's own example is a `process_creation` filter that also lists a rule titled "Login on jump host", which suggests filters may be meant to reach other logsources too. |
| S83 | A filter that references a rule id that does not exist | not covered | ambiguous | Ignored with a warning. |
| S89 | Whether a filter applies to a rule's matches before a correlation that references the rule counts them | not covered | ambiguous | Yes: a correlation counts only the matches left after the filters. |
| S98 | A tool that cannot apply a global filter: whether it must refuse the rules the filter names or may run them without it | not covered; the correlation spec's Compatibility section (S78, S79) has no counterpart for filters | ambiguous | Not evaluated by the evaluator, which applies every filter. A target may run the rules without the filter if it reports that the filter was not applied, as Hayabusa does ("Rule parsing errors"). |

## New: field value formats

| ID | Clause | Spec source | Status | Rules | Evaluator behaviour / working interpretation |
| --- | --- | --- | --- | --- | --- |
| S84 | `Hashes` holds several hashes in one string (`SHA1=...,MD5=...,SHA256=...,IMPHASH=...`), as Sysmon writes it | Taxonomy appendix, Fields | clear for the neutral config; the production mapping to per-hash fields is a pipeline choice | 46 | Neutral config: plain string matching. Production config: differences are `config`, not bugs. |

## New in Phase 2: found by the native-engine cross-check

| ID | Clause | Spec source | Status | Rules | Evaluator behaviour / working interpretation |
| --- | --- | --- | --- | --- | --- |
| S85 | Field names in rules are the log source's names "with all spaces stripped" (`New Value` is written `NewValue`) | Rules spec, Field Usage, point 2 | clear | 1 in the regression data (Defender `Source Name`, `Threat Name`, `Process Name`) | A rule field matches an event field whose name equals it once spaces are removed; an exact name wins. Missed in the 84-clause audit and found in Phase 2 because the evaluator missed a regression test that Hayabusa (through its rule converter) passed. |
| S86 | Windows events that carry their payload in `<UserData>` instead of `<EventData>` (WMI-Activity 5858, some Task Scheduler and AppLocker events) | Rules spec, Field Usage, point 3 covers `<EventData>` `Data Name` only | ambiguous | 1 in the regression data | The children of the single `<UserData>` wrapper element are fields under their own names (`harness/datasets.py`). Chainsaw's mapping only reaches `EventData`, Hayabusa reaches both. |
| S87 | Unnamed `<Data>` elements in `<EventData>` (classic Application-log providers such as ESENT, MsiInstaller, MSSQL, and PowerShell classic 400/600/800) | not covered (point 3 assumes every `Data` has a `Name`) | ambiguous | SigmaHQ rules address them as `Data` | They form one multi-valued field `Data`; a value matches if any element matches (S44). Hayabusa does the same. |

## New with the taxonomy (24 Nov 2026)

Added by Nik's decision of 24 Nov 2026 while reviewing [taxonomy.md](taxonomy.md) (area T9.5).

| ID | Clause | Spec source | Status | Rules | Evaluator behaviour / working interpretation |
| --- | --- | --- | --- | --- | --- |
| S88 | `all` on a single value is not allowed: "Single item values are not allowed to have an `all` modifier as some back-ends cannot support it" | Modifiers > Generic, `all` | clear | 0 of the 2,729 Windows rule files | The rule is outside the spec: label `rule-out-of-spec`, as for S60. The evaluator flags it and still matches it as the single value. pySigma 1.5.1 and 2.1.1 accept it silently on all 8 targets. |

## Readings of the open clauses

Every `ambiguous` or `contradictory` clause lists the readings that a careful implementer could take, fixed here before any result is labelled. **Source** says where each reading comes from: `spec` (a sentence, example or schema of the spec, quoted with its line, and how the reading takes it), `spec, inferred` (the premise is quoted, the step after it is ours), `spec delegates` (the spec leaves the choice to the tool), `observed` (only an implementation does it) or `own` (ours). `(silent clause)` marks a clause on whose question the spec has no text at all. Line numbers refer to the spec commit above. **Working** marks the reading the evaluator follows. A disagreement is a `backend-bug` candidate only if the target's result is wrong under **every** reading of every open clause it depends on, and the case then records those readings ([triage-labels.md](triage-labels.md)). A reading is added here, never removed, and only with a note in the Phase 3 review log; adding one can turn a candidate back into a `spec-gap`, never the reverse. `harness/triage.py` reads this table.

| Reading | What it says | Source | Working |
| --- | --- | --- | --- |
| S1.a | Non-ASCII letters are compared after Unicode full case folding (`ß` equals `ss`) | spec: "All values are treated as case-insensitive strings" (rules spec, line 361), read as Unicode full case folding | yes |
| S1.b | Non-ASCII letters are compared after simple per-character lower-casing (`ß` does not equal `ss`) | spec: the same sentence, read as Unicode simple case folding | |
| S1.c | Only ASCII letters are folded; non-ASCII letters are compared exactly | observed: SQLite `LIKE` folds ASCII letters only (SQLite documentation) | |
| S4.a | `?` matches one Unicode code point | spec: "`?` to replace a single mandatory character" (rules spec, line 371), a character read as a code point | yes |
| S4.b | `?` matches one UTF-16 code unit, so a character outside the Basic Multilingual Plane needs `??` | own | |
| S4.c | `?` matches one byte of the UTF-8 encoding | own | |
| S10.a | A keyword matches as a substring of any string field value of the event, case-insensitively, wildcards honoured | spec: "searching for keywords across an entire event" (rules spec, line 613) | yes |
| S10.b | A keyword matches as a substring of the whole raw event text | spec: "strings that are applied to the full log message" (rules spec, line 401) | |
| S10.c | A keyword matches whole tokens of an indexed message (full-text search) | observed: full-text term search in Splunk and Lucene (their documentation) | |
| S11.a | Integers are compared as strings: `4688` matches the integer and the string, `0x10` does not match `16` | spec: "All values are treated as case-insensitive strings" (rules spec, line 361) | yes |
| S11.b | Integers are compared as numbers: a numeric string in the event is parsed first | spec, inferred: "the value is a string or integer value" (rules spec, line 426); that an integer is compared as a number is inferred | |
| S11.c | An integer matches only an integer-typed field value | spec, inferred: the same sentence; that an integer matches only an integer is inferred; observed: Chainsaw C8, sigma.matching M6 | |
| S15.a | `re` searches anywhere in the value (unanchored) | spec: "The supported flavor is PCRE" (modifiers appendix, line 56); PCRE searches unanchored | yes |
| S15.b | `re` must match the whole value (anchored) | observed: Lucene, "the regular expression must match the entire string" (its documentation) | |
| S16.a | The field value is parsed as a number; if it does not parse, the comparison is false | spec: "can only be applied to numeric values" (modifiers appendix, line 85), read as values that denote a number | yes |
| S16.b | Only numerically typed field values are compared; string-typed values never match | spec: the same sentence, read as values of a numeric type | |
| S16.c | A string-typed value is compared as a string (lexicographically) | observed: string comparison in SQL and in SPL `where` (their documentation) | |
| S17.a | An IPv4-mapped IPv6 address does not match an IPv4 network | own (silent clause); Python `ipaddress` | yes |
| S17.b | An IPv4-mapped IPv6 address matches the IPv4 network of its embedded address | own (silent clause); RFC 4291 mapped addresses | |
| S19.a | A missing field does not satisfy `neq` | spec: "The field is different from the specified values" (modifiers appendix, line 44), read as needing the field; observed: `!=` in Elasticsearch ES-QL | yes |
| S19.b | A missing field satisfies `neq`, since it is different from the value | spec: the same sentence, read as true when there is no field | |
| S20.a | `fieldref` compares case-insensitively unless `cased` is chained | spec: "All values are treated as case-insensitive strings" (rules spec, line 361); `fieldref` itself (modifiers appendix, line 121) does not mention case | yes |
| S20.b | `fieldref` compares case-sensitively | observed: the Elasticsearch ES-QL, SQLite and SPL conversions (taxonomy T8.5) | |
| S22.a | Time modifiers read the timestamp in UTC | own | |
| S22.b | Time modifiers read the timestamp in the offset written in the event | spec: "It is not designed to handle timezone or format conversions" (modifiers appendix, line 98), read as the time as written | |
| S22.c | Time modifiers read the timestamp in the time zone configured in the SIEM | own | |
| S24.a | `null` matches a missing field and a field holding JSON null, not `''` | spec delegates: "The application of these values depends on the target SIEM system" (rules spec, line 497); our choice | yes |
| S24.b | `null` matches only a field present with JSON null | spec delegates (the same sentence); observed: Chainsaw C5 | |
| S24.c | `null` matches only a missing field | spec delegates (the same sentence) | |
| S24.d | `null` matches a missing field, JSON null and `''` | spec delegates (the same sentence) | |
| S32.a | An event whose group-by field is missing, a list or a map is not grouped | own (silent clause) | yes |
| S32.b | Such an event forms a group of its own (a null group) | own (silent clause); observed: sigma.matching M9, Hayabusa H6 | |
| S32.c | A missing group-by field is read as the empty string, so such events group together with events that have `''` | own (silent clause) | |
| S33.a | Sliding windows: the spans of `timespan` that end at an event of the group | spec: "The time frame should not be restricted to boundaries" (correlation spec, line 450) | yes |
| S33.b | Fixed (tumbling) windows aligned to clock boundaries | spec: "... if this is not required by the given backend" (the same sentence) | |
| S33.c | Windows that start at the first event of the group and restart after they expire | own | |
| S34.a | A range: every criterion given must hold | spec: "To define a range, you can use the conjunction 'AND' in the mapping" (correlation spec, line 343) | yes |
| S34.b | Exactly one criterion: a condition with more than one is a rule error and must be refused | spec: "It is a map of exactly one condition criterion" (line 327) | |
| S35.a | Events with equal timestamps are not in order | own (silent clause) | yes |
| S35.b | Events with equal timestamps are in order, whichever arrived first | own (silent clause); observed: Hayabusa H9 | |
| S35.c | Events with equal timestamps are in order only in their arrival order | own (silent clause); observed: sigma.matching M11 | |
| S37.a | `process_creation` and the other Windows categories are only the sources in the appendix table | spec: the Windows table of the taxonomy appendix | yes |
| S37.b | A category also covers other sources that provide it (Security 4688 for `process_creation`) | observed: Chainsaw C7 and Windows pipelines that add Security 4688 | |
| S39.a | Values are typed by the YAML loader; a boolean `true` matches the strings `true` and `True` | spec, inferred: rules are YAML and "Numeric values don't use any quotes" (rules spec, line 102); comparing a typed value as a string is inferred; observed: pySigma's loader | yes |
| S39.b | All values are strings, whether quoted or not | spec: "All values are treated as case-insensitive strings" (rules spec, line 361) | |
| S39.c | Typed values match only values of the same type in the event | spec, inferred: the same YAML typing; that a typed value matches only the same type is inferred; observed: Chainsaw C6 | |
| S42.a | Field names are case-sensitive | own (silent clause) | yes |
| S42.b | Field names are case-insensitive | own (silent clause); observed: SQLite column names | |
| S43.a | A dotted name is one flat key | own (silent clause) | yes |
| S43.b | A dotted name is a path into nested objects | own (silent clause); observed: Elasticsearch objects | |
| S43.c | A dotted name matches a flat key or a nested path | own (silent clause) | |
| S44.a | A multi-valued field matches if any element matches | own (silent clause); observed: Hayabusa, Splunk multivalue fields | yes |
| S44.b | A multi-valued field matches only if every element matches | own (silent clause) | |
| S44.c | A multi-valued field is matched as one string, its elements joined | own (silent clause) | |
| S46.a | `*` and `?` match a newline | own (silent clause) | yes |
| S46.b | `*` and `?` do not match a newline | own (silent clause); observed: regex `.` in LogQL translations | |
| S47.a | No Unicode normalisation: code points are compared as written | own (silent clause) | yes |
| S47.b | Both sides are normalised to NFC first | own (silent clause) | |
| S47.c | Both sides are normalised to NFKC first | own (silent clause) | |
| S50.a | Keywords with `all` may each appear in a different field | spec: "across an entire event" (rules spec, line 613) | yes |
| S50.b | Keywords with `all` must all appear in the same field | spec: "applied to the full log message" (rules spec, line 401), one message | |
| S51.a | An empty list of values or an empty selection is a rule error | own (silent clause) | yes |
| S51.b | It matches nothing | own (silent clause) | |
| S51.c | It tests that the field is missing or empty | own (silent clause); observed: every backend converts `[]` to a null test (taxonomy T9.5) | |
| S55.a | Condition keywords are lower case only (`AND` is a rule error), as pySigma accepts | own (silent clause); every condition example is lower case; observed: pySigma | yes |
| S55.b | Condition keywords are case-insensitive | own (silent clause) | |
| S56.a | An explicit pattern such as `1 of _filter*` includes identifiers that start with `_` | spec: "restricted to matching search identifiers" (rules spec, line 665) | yes |
| S56.b | Identifiers that start with `_` are excluded from every pattern, as from `them` | spec: "Same as 1/all of them" (line 665), which excludes `_` identifiers (line 655) | |
| S58.a | `neq` with a list: the value is different from all listed values | spec: "The field is different from the specified values" (modifiers appendix, line 44) | yes |
| S58.b | `neq` with a list: the value is different from at least one listed value (OR, as for other lists) | spec: "Normally, lists of values are linked with OR" (modifiers appendix, line 26) | |
| S59.a | Zone IDs and leading-zero IPv4 values do not parse, so they do not match | own (silent clause); Python `ipaddress` | yes |
| S59.b | A zone ID is dropped and leading zeros are read as decimal before matching | own (silent clause) | |
| S59.c | Leading zeros are read as octal, as `inet_aton` does | own (silent clause); observed: `inet_aton` | |
| S68.a | An unknown or misspelled modifier is a rule error | own (silent clause) | yes |
| S68.b | An unknown modifier is ignored and the value is matched without it | own (silent clause) | |
| S69.a | Both sides are parsed as numbers; floats, negatives and quoted numbers are accepted | spec: "can only be applied to numeric values" (modifiers appendix, line 85) for floats and negatives; own for quoted numbers | yes |
| S69.b | Only unquoted integers are allowed; other values are rule errors | spec, inferred: "Numeric values don't use any quotes" (rules spec, line 102); integers only is own | |
| S70.a | All seven correlation types are allowed | spec: the seven types defined under Correlation Types (correlation spec) | yes |
| S70.b | Only the four listed types are allowed; the other three are rule errors | spec: the four types listed under Correlation type (the same spec) | |
| S71.a | `group-by` is optional; without it all events form one group | spec: "optionally defines one or multiple fields" (correlation spec, line 282) | yes |
| S71.b | `group-by` is mandatory; a correlation without it is a rule error | spec: "Use: mandatory" (the same section) | |
| S72.a | Distinct values are counted after case folding; an event without the field adds no value | own (silent clause), by analogy with S1 | yes |
| S72.b | Distinct values are case-sensitive; an event without the field adds no value | own (silent clause); observed: sigma.matching M8, Hayabusa H5 | |
| S72.c | An event without the field adds one value (empty or null) | own (silent clause); observed: Hayabusa H8 | |
| S73.a | Several fields are counted as distinct tuples | spec: "When you use multiple values in `field` they are linked by an **AND**" (correlation spec, line 418), read as one combined value | yes |
| S73.b | Each field is counted on its own, and the condition must hold for every field | spec: the same sentence, read as a condition on each field | |
| S73.c | The values of all fields are pooled and counted together | own | |
| S74.a | The condition is tested on the share, in percent, of the window's events with the field that hold one value | spec: "Check when a certain percentage of observed values occur" (correlation spec, line 559) | yes |
| S74.b | The condition is tested on a numeric percentile of the field's values | spec: "Hint: median is a percentile 50" (line 560); observed: pySigma | |
| S81.a | A filter suppresses matches: `rule condition and not filter condition` | spec: "with the goal to suppress matches of multiple rules" (filters spec, line 35) | yes |
| S81.b | The filter's condition says what to keep: `rule condition and filter condition` | spec: "refers to one or multiple Sigma rules where to add the filter" (filters spec, line 153), and the example's `condition: selection` (line 187); observed: pySigma P3 | |
| S82.a | A filter applies only to a rule with the same logsource | own (silent clause): the filter's `logsource` is mandatory, but no sentence says what it does | yes |
| S82.b | A filter applies to a rule whose logsource includes the filter's | own (silent clause); observed: pySigma P4 | |
| S82.c | A filter applies to every listed rule, whatever the logsources | own (silent clause); the example also lists rule df0841c0, "Login on jump host" (line 184), which suggests another logsource, but that id is not in SigmaHQ at commit 552f3fee4 | |
| S83.a | A reference to a rule that does not exist is ignored, with a warning | own (silent clause) | yes |
| S83.b | It is ignored without a warning | own (silent clause); observed: pySigma (taxonomy T23.3) | |
| S83.c | It makes the filter a rule error | own (silent clause) | |
| S86.a | The children of the `<UserData>` wrapper are fields under their own names | own (silent clause); observed: Hayabusa | yes |
| S86.b | `<UserData>` content is not a field | own (silent clause); observed: Chainsaw C3 | |
| S86.c | The children are fields under names that include the wrapper element | own (silent clause) | |
| S87.a | Unnamed `<Data>` elements form one multi-valued field `Data` | own (silent clause); observed: Hayabusa | yes |
| S87.b | They are fields named by position (`Data_1`, `Data_2`, ...) | own (silent clause) | |
| S87.c | They form one string field `Data`, the elements joined | own (silent clause) | |
| S89.a | A correlation counts a rule's matches after the filters | own (silent clause) | yes |
| S89.b | A correlation counts a rule's matches before the filters; filters apply only to the rule's own alerts | own (silent clause); observed: Hayabusa runs correlations without filters (H15) | |
| S90.a | Group-by values that differ only in case form one group | own (silent clause), by analogy with S1 | yes |
| S90.b | They form separate groups | own (silent clause); observed: sigma.matching M8, Hayabusa H5 | |
| S91.a | Both ends of the window are inside: `[t - timespan, t]` | own (silent clause); observed: all three cross-check targets | yes |
| S91.b | An event exactly `timespan` earlier is outside: `(t - timespan, t]` | own (silent clause) | |
| S92.a | Without a condition every referenced rule must match in the window; with one, `temporal` counts the referenced rules that matched and `temporal_ordered` the longest prefix seen in order | spec: condition "Use: mandatory" and "the count of different event types" (correlation spec, line 324) | yes |
| S92.b | Every referenced rule must match in the window, and a condition is ignored | spec: "All events defined by the rules referred by the rule field must occur in the time frame" (line 447); observed: sigma.matching M12, Hayabusa H10 | |
| S92.c | A condition is mandatory; a `temporal` correlation without one is a rule error | spec: condition "Use: mandatory" (Condition) | |
| S93.a | One alert per group each time the condition becomes true | own (silent clause) | yes |
| S93.b | One alert for every event that ends a window where the condition holds | own (silent clause); observed: sigma.matching, Zircolite (C27) | |
| S93.c | One alert per fixed window where the condition holds | own (silent clause) | |
| S94.a | An outer correlation counts every window where the inner condition holds, with the fields of the event that ends it | spec: "the correlation rule only uses its own `group-by`" (correlation spec, line 498) | yes |
| S94.b | It counts only the rising edges of the inner correlation (S93), with the inner group-by values | own: the evaluator's first version, which line 498 rules out | |
| S94.c | It counts the base events that made the inner correlation match | own | |
| S95.a | An event matched by several referenced rules counts once in `event_count` and the value types; `temporal` counts each rule it matches | own (silent clause) | yes |
| S95.b | The event counts once for each referenced rule that matches it | own (silent clause); observed: sigma.matching M17 | |
| S96.a | A condition that is not monotone is tested on every window that ends at an event | own (silent clause) | yes |
| S96.b | It is tested on every window at any point in time, including windows that end between events | own (silent clause) | |
| S96.c | It is tested only on fixed windows (as S33.b) | own (silent clause), as S33.b | |
| S97.a | For a referenced rule the alias does not list, the group-by name is read as a field name | own (silent clause) | yes |
| S97.b | Events of an unlisted rule are not grouped | own (silent clause) | |
| S97.c | An alias that does not list every referenced rule is a rule error | own (silent clause) | |
| S98.a | A tool that cannot apply a filter must refuse the rules the filter names | own (silent clause), by analogy with S78 | |
| S98.b | It may run them without the filter if it reports that the filter was not applied | own (silent clause); observed: Hayabusa H15 | yes |
| S98.c | It may run them without the filter, silently | own (silent clause) | |
| S99.a | Timestamps are compared at their full resolution | own (silent clause) | yes |
| S99.b | Timestamps are compared at millisecond resolution | own (silent clause); observed: Zircolite Z1 | |
| S99.c | Timestamps are compared at second resolution | own (silent clause) | |

## Questions closed on 23 Nov 2026

These four were open for the co-author. Nik decided on 23 Nov 2026 to keep the working interpretation for each. The clauses stay `ambiguous` and keep all their readings, so a finding that is right under any of those readings is a `spec-gap`.

1. S10 keywords: substring in any string field (kept), not a full-text match on the raw message.
2. S11 integers: string comparison (kept), not numeric comparison.
3. S24 null: absent or JSON null (kept), not absent only.
4. S33 correlation windows: sliding (kept), not tumbling.
