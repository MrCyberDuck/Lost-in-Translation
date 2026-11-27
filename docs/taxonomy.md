# Taxonomy of translation divergence

This file lists every area where a Sigma rule can end up detecting different events on different targets, and why. It is the reference for the conformance suite (Phase 3), for the area label on each finding (Phase 5), and for the per-area results in the paper (Phase 6).

Status: draft of 24 Nov 2026, reviewed once by an independent agent (section 9). It replaces the seed list T1 to T14 in the testbed plan. T1 to T14 keep their IDs; T15 to T26 are new.

## 1. Why a new taxonomy

The plan started from 14 areas (T1 to T14) taken from experience with Sigma conversion. That list was a seed, not a result: nobody checked it against the spec clauses, the converter source, the engines or the findings from Phases 1 and 2. When we did, three kinds of gap showed up.

- **Whole areas were missing.** Field names (spaces, dots, hyphens, quoting), logsource selection, multi-valued fields, YAML typing, query structure, limits, unsupported features, time, Sigma filters, storage schema and event representation had no area, although several Phase 2 mechanisms (C1, C2, C3, C7, H2, H4) and spec clauses (S36 to S44, S84 to S87) sit there.
- **Some areas hid more than one mechanism.** T4 "null/empty/missing" mixes three questions (what null means, whether empty equals missing, how `not` treats a missing field). T14 "whitespace and quotes" left out the characters that are special to each query language.
- **Nothing tied the areas to evidence.** No area said which clauses it covers, which layer causes it, which targets are at risk, or how an attacker would use it.

## 2. Method

We examined the question from nine perspectives, then had the draft reviewed by an independent agent that re-ran the probes and checked vendor documentation (section 9).

| # | Perspective | What we did | What it found |
| --- | --- | --- | --- |
| P1 | Spec clauses | Mapped each of S1 to S99 ([spec-clauses.md](spec-clauses.md)) onto an area | 17 clauses have their primary home outside T1 to T14 (S22, S36 to S40, S42 to S44, S81 to S87, S89) |
| P2 | Processing layers | Followed one rule from YAML file to engine verdict and asked at each step what can change the meaning (section 3) | Rule loading (T18), query structure (T19), storage schema (T25), event representation (T26) |
| P3 | Target languages | For each query language (Lucene, ES\|QL, EQL, KQL, SPL, LogQL, SQL), listed the semantics that differ from Sigma: case, anchoring, tokenisation, null handling, typing, quoting | Literal escaping per language (T3, T14), anchoring (T2, T7), bare-string keywords (T12), three-valued logic outside Chainsaw (T4) |
| P4 | Backend source and options | Read the class attributes and constructor options of each pySigma backend (precedence, escaping, wildcard tokens, quoting patterns, null and exists expressions, `convert_or_as_in`, deferred parts) | Field-name quoting (T15), `?` mapped to `*` (T2), case lost in value lists (T1), deferred parts (T19), backend options (sub-area T10.6) |
| P5 | Conversion probes | Converted 66 one-feature rules with all 8 pySigma targets ([harness/probe_conversion.py](../harness/probe_conversion.py), output [results/taxonomy/conversion_probe.json](../results/taxonomy/conversion_probe.json)), plus correlation and filter probes ([probe_correlation.py](../harness/probe_correlation.py), [probe_filters.py](../harness/probe_filters.py), outputs in [results/taxonomy/](../results/taxonomy/)) | The conversion evidence quoted in section 5 |
| P6 | Our own findings | Placed every measured deviation (D1 to D3 from the demo, C1 to C9 and H1 to H4 from Phase 2) in an area | Section 7 |
| P7 | Event source and ingest | Asked how the same Windows event reaches each engine: XML to JSON, rendered vs raw values, index mappings, field types, size limits | T13, T25, T26 |
| P8 | Attacker | Asked which fields an attacker controls and which cheap changes of those fields (case, padding, separators, encoding, ordering) flip a verdict on one target only | Attacker column in section 4 |
| P9 | Prior work | Checked the closest papers and reports (see the novelty doc) for mechanisms they found | Lucene case and `\b` (Maiorano), PPL dropping the correlation window (Security Data Works), rejected Elastic conversions (opentide sweep) all fall into existing areas |

**What "exhaustive" means here.** A taxonomy of an open system cannot be proven complete. We use four closure checks instead; the repository tests the first two.

1. Every spec clause S1 to S99 has exactly one primary area (section 6, `tests/test_taxonomy_coverage.py`).
2. Every layer L1 to L7 has at least one area (L8 is covered by section 8), and the layer table in section 3.1 agrees with section 4 (same test).
3. Every measured deviation so far has an area (section 7).
4. Every backend class attribute that changes matching semantics maps to an area. Backend options and pipeline transformation types are listed in T10.6 and T10.2 as far as we have read them; that list is **not yet complete**, so check 4 is partial.

A new mechanism that fits no area gets a new ID (T27 and up). IDs are never reused or renumbered.

**What counts as a divergence.** A divergence is a rule that matches different events on different targets, or on a target and the reference evaluator, because meaning was lost or changed somewhere between the rule file and the engine's verdict. Two things are out of scope. Evasions that work the same on every target (for example inserting `^` into a `cmd` command line) are rule-quality issues, not translation divergence; they are studied elsewhere (SPECTRA). Performance and query cost are out of scope too, also because the Kusto emulator licence forbids benchmarks.

**IDs.** `T1` to `T26` are areas; `Tn.m` is sub-area *m* of area *Tn* (for example `T10.6`, backend options), defined in section 5.

**Evidence labels.** Each claim about a target carries one label.

- **conv**: seen in the converted query from a probe (P5). It shows what the converter emits, not what the engine does with it.
- **run**: measured on the engine in our runs (demo of 23 Nov 2026 or Phase 2).
- **doc**: stated in the vendor's documentation (link given), not yet run on our engines.
- **hyp**: a hypothesis about engine behaviour. **strong** means the converter output plus the docs make it very likely.

Every **doc** and **hyp** claim becomes a Phase 3 case: documentation is evidence, not a measurement.

Versions: pySigma 1.5.1 for Lucene, ES\|QL, EQL (elasticsearch backend 2.1.1), OpenSearch Lucene (2.0.3) and KQL (kusto 1.0.1); pySigma 2.1.1 for SPL (splunk 3.0.1), LogQL (loki 0.16.0) and SQLite (2.2.0). Neutral config, no pipeline.

Documentation sources used below (fetched 24 Nov 2026):
[ES\|QL WHERE](https://www.elastic.co/docs/reference/query-languages/esql/commands/where),
[Lucene regexp syntax](https://www.elastic.co/docs/reference/query-languages/query-dsl/regexp-syntax),
[EQL syntax](https://www.elastic.co/docs/reference/query-languages/eql/eql-syntax),
[ES ignore_above](https://www.elastic.co/docs/reference/elasticsearch/mapping-reference/ignore-above),
[KQL string operators](https://learn.microsoft.com/en-us/kusto/query/datatypes-string-operators),
[KQL entity names](https://learn.microsoft.com/kusto/query/schema-entities/entity-names),
[KQL ipv4_is_in_range](https://learn.microsoft.com/en-us/kusto/query/ipv4-is-in-range-function),
[KQL null values](https://learn.microsoft.com/en-us/kusto/query/scalar-data-types/null-values),
[LogQL log queries](https://grafana.com/docs/loki/latest/query/log_queries/),
[SPL search syntax](https://docs.splunk.com/Documentation/Splunk/latest/Search/Aboutsearchlanguagesyntax).

## 3. Dimensions

Each area is described along four dimensions. The area says *what* differs; the dimensions say *where* it happens, *how it shows* and *under which setup*.

### 3.1 Layer (where the meaning changes)

| Layer | Name | Example of a change at this layer | Areas |
| --- | --- | --- | --- |
| L1 | Rule loading | YAML turns `0x10` into 16 and `yes` (YAML 1.1) into `true` | T3, T5, T18, T23, T24 |
| L2 | pySigma core | Modifier expansion (`windash`, `base64offset`), placeholders, regex validation, filters | T3, T6, T7, T8, T9, T21, T23 |
| L3 | Processing pipeline | Field renames, logsource conditions, dropped detection items | T10, T16, T23 |
| L4 | Backend code generation | Escaping, wildcard emulation, operator choice, precedence, quoting | T1, T2, T3, T4, T5, T6, T7, T8, T9, T10, T11, T12, T14, T15, T19, T21 |
| L5 | Engine evaluation | Case folding, regex dialect, three-valued logic, tokenisation, windows | T1, T2, T3, T4, T5, T6, T7, T9, T11, T12, T13, T14, T15, T16, T17, T19, T20, T22, T24 |
| L6 | Ingest, storage and schema | Index mapping (keyword vs text), field types, value length limits | T4, T5, T6, T12, T13, T17, T22, T25 |
| L7 | Event source representation | Rendered vs raw values, `UserData`, unnamed `Data`, hex vs decimal | T13, T15, T17, T26 |
| L8 | Harness and deployment | How the query is sent and results are collected | Section 8 (not a taxonomy area) |

### 3.2 Outcome (how the divergence shows)

- **Silent under-match**: the target misses events the spec says match. This is the evasion case.
- **Silent over-match**: the target matches events the spec says do not match. This is the false-positive case.
- **Loud rejection**: the converter or engine refuses the rule or errors. Reported separately as the conversion failure rate (plan, "Metrics"); not a triage label.
- **Warned approximation**: the converter emits an approximation and says so (S79 asks for this for correlations).

### 3.3 Config and version

Each case runs in the **neutral** config (no pipeline, logsource ignored) and, from Phase 4, the **production** config (stock pipelines and logsource tables). T10, T16, T25 and T26 mostly show in production. Each case also runs on both pySigma majors where a backend exists for both (decision 8): a divergence that a 2.x release fixes is still a finding for the 1.x backends people run.

### 3.4 Attacker relevance

- **High**: the area acts on fields the attacker writes (command line, file and registry paths, script text, service and task names) and a cheap change of those fields flips the verdict on some targets.
- **Medium**: the attacker can influence the value only indirectly (source address format, logon type through the choice of tool), or the divergence needs a specific but common rule construct.
- **Low**: the value is written by the system, or the divergence needs a rare rule construct.

## 4. Areas at a glance

| ID | Area | What can diverge | Layers | Clauses (primary) | Attacker | When tested |
| --- | --- | --- | --- | --- | --- | --- |
| T1 | Case | Case-insensitive default, `cased` (also in lists), non-ASCII folding | L4, L5 | S1, S2, S65 | High | Phase 3 |
| T2 | Wildcards and anchoring | `*`, `?`, whole-value match, contains/startswith/endswith, newlines | L4, L5 | S3, S4, S6, S46 | High | Phase 3 |
| T3 | Backslashes and escaping | Sigma escape rules, escaped wildcards, escaping across nested literal layers | L1, L2, L4, L5 | S5, S41 | High | Phase 3 |
| T4 | Null, empty and missing | `null`, `''`, `exists`, `neq` and `not` over a missing field, unknown fields | L4, L5, L6 | S18, S19, S23, S24, S25, S49, S54, S66 | Medium | Phase 3 |
| T5 | Types and numbers | Numeric compare on strings, failed conversions, leading zeros, hex, booleans | L1, L4, L5, L6 | S11, S16, S69 | Low | Phase 3 |
| T6 | CIDR and IP addresses | IPv6, IPv4-mapped IPv6, prefix expansion, ip-typed fields | L2, L4, L5, L6 | S17, S59 | Medium | Phase 3 |
| T7 | Regex dialect | Flavour, anchoring, inline flags, unsupported syntax | L2, L4, L5 | S15, S60, S61, S62 | High | Phase 3 |
| T8 | Value modifiers | `base64offset`, `utf16*`, `windash`, `fieldref`, `expand`, chaining | L2, L4 | S12, S13, S14, S20, S21, S63, S64, S67, S68 | High | Phase 3 |
| T9 | Lists and boolean logic | Precedence, grouping of expansions, `x of`, `them`, list and condition edge cases | L2, L4, L5 | S7, S8, S9, S26 to S30, S51 to S53, S55 to S58, S88 | Medium | Phase 3 |
| T10 | Field mapping, pipelines and options | Renames, value transforms, dropped items, pipeline versions, backend options | L3, L4 | none | Low | Phase 4 |
| T11 | Correlation | Support, window type, grouping, distinct counting, ordering, alert granularity, conditions, references | L4, L5 | S31 to S35, S70 to S80, S90 to S97 | Medium | Phase 3 (Q2) |
| T12 | Keywords and full-text search | What "the full log message" is, tokens vs substrings | L4, L5, L6 | S10, S50 | High | Phase 3 |
| T13 | Value length and encoding | Truncation of long values, non-ASCII, Unicode normalisation, NUL | L5, L6, L7 | S47 | High | Phase 3 |
| T14 | Whitespace, quotes and special characters | Spaces, tabs, newlines in queries, quotes, characters special to the language | L4, L5 | S45, S48 | High | Phase 3 |
| T15 | Field names and field access | Spaces, dots, hyphens, case of names, quoting of names | L4, L5, L7 | S42, S43, S85, S86 | Low | Phase 3 |
| T16 | Logsource selection | Which events a rule applies to, per target | L3, L5 | S36, S37, S38 | Medium | Phase 4 |
| T17 | Multi-valued and nested fields | Arrays, repeated `Data`, composite strings like `Hashes` | L5, L6, L7 | S44, S84, S87 | Medium | Phase 3 |
| T18 | Rule loading and value typing | YAML 1.1 typing, quoting, rule validity | L1 | S39, S40 | Low | Phase 3 |
| T19 | Query structure and deferred parts | Post-filter pipes, several queries per rule, `not` around a deferred part | L4, L5 | none | Medium | Phase 3 |
| T20 | Query and engine limits | Clause counts, query length, regex size, result caps, timeouts | L5 | none | Low | Phase 3 and 4 |
| T21 | Unsupported features and lossy emulation | Loud error vs silent drop vs approximation, across all areas | L2, L4 | none | Medium | Phase 3 |
| T22 | Time and ordering | Time modifiers, event vs ingest time, time zones, ties, timestamp resolution | L5, L6 | S22, S99 | Low | Phase 3 (with T11) |
| T23 | Sigma filters and meta-rules | How a global filter is combined with the rule, logsource, references, correlations | L1, L2, L3 | S81, S82, S83, S89, S98 | Low | Phase 3 (conversion), Phase 4 |
| T24 | Rule-authoring quirks | Rules whose literal text only works on some targets | L1, L5 | none | Medium | Phase 4 |
| T25 | Storage schema and field types | Keyword vs text, typed fields, dynamic mapping | L6 | none | Medium | Phase 4 |
| T26 | Event value representation | Rendered vs raw, hex vs decimal, `%%` codes, path forms | L7 | none | Medium | Phase 4 |

Areas with no primary clause (T10, T19, T20, T21, T24, T25, T26) have no spec verdict of their own. A divergence there is judged against the clause it ends up breaking (a dropped detection item in T10 changes a T9 verdict; `?` emulated as `*` in T21 breaks S4), or it is labelled `config` when it comes only from setup. T21 is a cross-cutting view: its cases keep the area of the feature they lose (T1, T2, T6...) as primary.

## 5. Areas in detail

Each area gives the Sigma intent, its sub-areas with evidence per target, and an example case. A sub-area ID has the form `Tn.m`: sub-area *m* of area *Tn*. For example, `T10.6` is the sixth sub-area of T10 ("Backend options"). The other sections refer to sub-areas by these IDs, and findings are labelled with them. Target names: Lucene, OpenSearch (OpenSearch Lucene), ES\|QL, EQL, KQL (Kusto), SPL (Splunk), LogQL (Loki), SQLite, Chainsaw, Hayabusa.

### T1. Case

**Intent.** Values match case-insensitively (S1, which is also where non-ASCII folding sits); `cased` makes them case-sensitive (S2), including with `contains`, `startswith`, `endswith` and wildcards (S65). `re` is case-sensitive unless `i` is given (S15, in T7).

- **T1.1 Default case-insensitivity on the engine.** Lucene, OpenSearch and ES\|QL miss `whoami /ALL` on keyword fields (**run**, D1): the converter emits a plain term and the engine compares case-sensitively. ES\|QL `LIKE` "is case-sensitive and must match the exact string indexed" (**doc**, ES\|QL WHERE).
- **T1.2 `cased` on single values.** Lucene, OpenSearch, ES\|QL, KQL and SPL reject `cased` (**conv**, loud). EQL emits `==`, LogQL drops `(?i)`, SQLite emits `GLOB` (**conv**).
- **T1.3 `cased` on value lists (silent).** A list goes through the `convert_or_as_in` path and loses `cased` without an error: `CommandLine|cased: [A, B]` becomes Lucene `CommandLine:(A OR B)`, ES\|QL `in ("A", "B")`, EQL `like~ ("A", "B")`, KQL `in~ ("A", "B")`, SPL `IN ("A", "B")` (**conv**). `in~` and `like~` are case-insensitive by definition, so this is a silent loss of case-sensitivity on targets that reject the same modifier on a single value. `windash|cased|contains` on Lucene and EQL also comes out case-insensitive (review probe, **conv**).
- **T1.4 `cased` with wildcards.** EQL turns `cased|contains: 'a[b]'` into `CommandLine == "*a[b]*"` and `cased|startswith` into `== "Mimi*"` (**conv**). EQL: "The == and != operators do not expand wildcard characters" (**doc**), so both never match: a silent under-match. SQLite escapes `[` as `[[]` in `GLOB` (**conv**, correct).
- **T1.5 Non-ASCII case folding** (S1). `café` vs `CAFÉ`, Turkish dotted I, `ß`: SQLite `LIKE` folds ASCII only; others unknown (**hyp**).
- **T1.6 Case in emulated regexes.** LogQL emulates case-insensitive matching by adding `(?i)` to every non-regex match (**conv**). Whether that flag reaches the engine is T7.3.
- **Backend attributes.** `case_sensitive_match_expression` is `None` for all but EQL (`{field} == {value}`) and SQLite (`GLOB`); `convert_or_as_in` (T1.3).

Example case: `CommandLine|contains: 'whoami /all'`, events `whoami /ALL` (match) and `whoami /alx` (no match); `CommandLine|cased: [Mimi, Kat]` against `mimi`.

### T2. Wildcards and anchoring

**Intent.** A plain value matches the whole field (S3). `*` matches any sequence including empty, `?` exactly one character (S4). `contains`, `startswith`, `endswith` add `*` (S6). Whether `*` and `?` match a newline is not stated (S46, ambiguous).

- **T2.1 `?` emulation.** SPL maps `?` to `*` (`Image="C:\\a*c.exe"`, **conv**): over-match, since `*` accepts zero or many characters. SQLite maps it to `_`, LogQL to `.` inside an anchored `(?i)^...$` (**conv**).
- **T2.2 KQL wildcard emulation.** The kusto backend has three paths, all lossy:
  - a single value with an inner wildcard becomes `matches regex`: `Image: 'a*b.exe'` gives `Image matches regex "a.*b\\.exe"`, `C:\a?c.exe` gives `"C:\\\\a.c\\.exe"` (**conv**). `matches regex` means "LHS contains a match for RHS" and is case-sensitive (**doc**, KQL string operators): unanchored (over-match on `xa1b.exey`) and case-sensitive (under-match on `A1B.EXE`).
  - a list of values with inner wildcards becomes an AND of `contains` fragments: `[a?.exe, b*c.exe]` gives `(Image contains "a" and Image contains ".exe") or (...)` (**conv**). Order, anchoring and the `?` are lost (over-match).
  - plain values under `|all` become `has_all ("a", "b")` (**conv**), a term match (**doc**), not whole-value equality (over-match; see T12.2).
- **T2.3 Value `*` alone.** `CommandLine: '*'` becomes `CommandLine:*` (Lucene), `starts_with(CommandLine, "")` (ES\|QL), `CommandLine startswith ""` (KQL), `CommandLine="*"` (SPL), `LIKE '%'` (SQLite) (**conv**). On an empty value and on a missing field these can disagree (**hyp**). Overlaps T4.
- **T2.4 Wildcards and newlines** (S46). A value containing a newline passes through as a raw newline in Lucene, ES\|QL, KQL, SPL and SQLite, and as `\` plus newline in EQL and LogQL (**conv**). Whether `*`, `LIKE '%'` and `.*` cross a newline differs by engine (`.` without `s` does not cross it in RE2) (**hyp**). Results are `spec-gap`.
- **T2.5 Leading wildcards and analysed fields.** `contains` and `endswith` need a leading wildcard. Lucene `query_string` can disable them (`allow_leading_wildcard`), and a wildcard on an analysed `text` field matches tokens, not the value (**hyp**, T25).
- **Backend attributes.** `wildcard_single` is `*` for SPL and KQL (no single-character wildcard), `_` for SQLite, `?` elsewhere.

Example case: `Image: 'C:\a?c.exe'`, events `C:\abc.exe` (match), `C:\abbc.exe` (no), `C:\ABC.exe` (match), `xC:\abc.exey` (no).

### T3. Backslashes and escaping

**Intent.** `\*` and `\?` are a literal star and question mark; `\\*` is one literal backslash then a wildcard; three or four backslashes are a literal `\\` (S5). A backslash not before a wildcard may be single or double (S41).

- **T3.1 Sigma escape decoding (core).** The pySigma 2.x release notes list a backslash round-trip fix in the core; we have not yet measured its effect on the corpus (to check in Phase 3 step 1).
- **T3.2 Layers of escaping.** Each value passes through up to four escaping layers: YAML, Sigma, the query language's string literal, and the engine's pattern syntax (wildcard, `LIKE` or regex). One escape too few or too many at any layer shifts the meaning. `endswith: '\\*'` becomes `*\\*` in Lucene and SPL, `LIKE '%\\%' ESCAPE '\'` in SQLite and `.*\\.*` in LogQL (**conv**).
- **T3.3 ES\|QL `LIKE` and backslashes (strong).** In ES\|QL `LIKE` "the escape character is backslash" and "to match a literal backslash in the data, write \\ in the pattern" (**doc**). Inside a double-quoted ES\|QL string that is four backslashes. The backend emits `Image like "*\\AppData\\*"` (**conv**), which the string literal turns into the pattern `*\AppData\*`: `\A` reads as `A` and `\*` as a literal star (**hyp**, strong). This hits every `contains`, `startswith` and `endswith` with a backslash, which is most Windows path rules.
- **T3.4 Escaped wildcards `\*` and `\?`.**
  - LogQL turns `contains: 'a\*b'` into `.*a\\.*b.*` and `'a\?b'` into `^a\\.b$` (**conv**): the literal star becomes a literal backslash plus a wildcard, so the rule matches neither `a*b` nor what was intended. The core parses the value correctly, so this is the backend.
  - SPL emits `"*a\*b*"`, but in SPL "asterisks cannot be searched for using a backslash to escape the character" (**doc**): over-match.
  - KQL emits `contains "a*b"` (correct, since `contains` has no wildcards); Lucene, ES\|QL and EQL keep `\*` (**conv**; ES\|QL see T3.3).
- **T3.5 Trailing backslash.** `Path: 'C:\dir\'` becomes `C\:\\dir\\` (Lucene) and `"C:\\dir\\"` (KQL, SPL, EQL) (**conv**). A trailing single backslash can escape the closing quote in some literal syntaxes (**hyp**).
- **T3.6 Backslash in keyword search.** In LogQL the keyword filter runs over the JSON line, where each backslash is doubled by JSON encoding (**hyp**, T12.3).

Example case: `Image|contains: '\AppData\'` against `C:\Users\x\AppData\Local\a.exe` (match on all targets).

### T4. Null, empty and missing

**Intent.** `''` is an empty value (S23). `null` is "a null value", and what that means "depends on the target SIEM" (S24, ambiguous). `exists` checks presence only (S18) and takes a boolean (S66). A missing field never matches a value condition, and `not` is two-valued (S25, clear by decision 7). `null` must be its own selection (S49).

- **T4.1 What `null` means.** Lucene and OpenSearch emit `NOT _exists_:f`, ES\|QL `f is null`, EQL `?f == null`, KQL `isnull(f)`, SPL `NOT f=*`, SQLite `IS NULL`, LogQL ``f=`` `` (empty string) (**conv**). LogQL therefore treats null as empty. In KQL "the string data type doesn't support null values" (**doc**, KQL null values), and the harness ingests missing string fields as `""` (`harness/engines/kusto.py`), so `isnull(f)` never matches a string field (**hyp**, strong). Chainsaw matches only an explicit JSON null (**run**, C5).
- **T4.2 Empty vs missing.** `exists: true` is `isnotempty(f)` in KQL and `f!=""` in LogQL; `exists: false` is `isempty(f)` and `f=""` (**conv**). Both treat an empty value as missing, against S18. EQL rejects `exists` (**conv**, loud).
- **T4.3 Negation over a missing field (three-valued logic).**
  - Chainsaw: `selection and not filter` fails when the filter's field is absent; it missed 16 LSASS dumps (**run**, C4, `backend-bug`).
  - ES\|QL: `WHERE field != "value"` "will be interpreted as `WHERE field != "value" AND field IS NOT NULL`" (**doc**). The backend writes negations as `not f==v` and `not f rlike ...` (**conv**), so ES\|QL is expected to drop events without the field, the same pattern as C4 (**hyp**, strong).
  - KQL: for numeric columns, `where` drops rows whose predicate is null (**doc**, KQL null values).
  - SQLite wraps negations in `NOT COALESCE((...), 0)` to stay two-valued (**conv**). Lucene `NOT f:v` and SPL `NOT f=v` are expected to include events without `f` (**hyp**).
- **T4.4 `neq` over a missing field.** Every backend writes `neq` as a negation (**conv**), so on two-valued targets a missing field satisfies `neq`, and on three-valued targets (T4.3) it does not. S19 does not say which is intended (ambiguous).
- **T4.5 Several fields, one missing** (S54). A map with two fields where the event has only one must not match on any target.
- **T4.6 A field unknown to the schema.** If no stored event has the field, some engines raise an error instead of treating it as missing: EQL needs `?field` to get null "instead of returning an error" (**doc**); ES\|QL (unknown column), KQL (unresolved name) and SQLite (no such column) are expected to behave the same (**hyp**). A rule whose negated filter names an absent field then fails as a whole.

Example case: `selection: {Image|endswith: '\rundll32.exe'}`, `filter: {CommandLine|contains: 'x'}`, `condition: selection and not filter`, event without `CommandLine` (match).

### T5. Types and numbers

**Intent.** Integers in rules are compared with the field value (S11, ambiguous on string vs number). Numeric modifiers `lt`, `lte`, `gt`, `gte` (S16); floats, negatives and quoted numbers (S69, ambiguous).

- **T5.1 Number vs string representation.** Rule `3389` vs event `'3389'` fails on Chainsaw (**run**, C8). EQL rejects numeric `EventID:4720` with `:` (**run**, demo, loud). KQL writes integer lists as strings: `EventID in~ ("4624", "4625")`, while a single value stays `Flags == 16` (**conv**); on an integer column the string list may not match (**hyp**). EQL writes integer lists as `like~ (4624, 4625)` (**conv**, **hyp** that `like~` on numbers fails).
- **T5.2 Numbers written as strings in the rule.** `DestinationPort: '0443'` stays the string `0443` everywhere (**conv**); an engine that stores the port as a number never matches it, one that coerces does (**hyp**).
- **T5.3 Numeric compare on string fields.** `LogonType|lt: 5` becomes `LogonType<5` everywhere except SQLite, which wraps it in a type check (`CASE WHEN typeof(...)`) (**conv**). On a string-typed field, `<` may compare lexically (`"10" < "5"`) (**hyp**, T25).
- **T5.4 Failed numeric conversion in LogQL (strong).** In a LogQL label filter, "if the conversion of the label value fails, the log line is not filtered and an `__error__` label is added" (**doc**). The backend emits numeric filters such as `EventID=4720`, `LogonType<5` and `x!=1` without an `__error__=""` guard (**conv**), so lines where the field is missing or not numeric pass the filter (**hyp**, strong over-match).
- **T5.5 Booleans.** Rule string `'true'` vs event boolean `true` fails on Chainsaw (**run**, C6). LogQL rejects booleans (**conv**, loud). SQLite emits `('true' OR 1)`, KQL `=~ true` (**conv**).
- **T5.6 Floats and negatives.** `gte: 1.5` and `lt: -1` pass through unchanged (**conv**); how Lucene parses `:<-1` is untested (**hyp**).

Example case: `DestinationPort: 443` against events with `443` as integer, `"443"` and `"0443"`, and an event without `DestinationPort`.

### T6. CIDR and IP addresses

**Intent.** `cidr` matches IPv4 and IPv6 networks (S17; ambiguous for IPv4-mapped IPv6, working interpretation: `::ffff:a.b.c.d` does not match an IPv4 network). Compressed IPv6, zone IDs and leading zeros are S59 (ambiguous).

- **T6.1 IPv6 through an IPv4 function.** KQL emits `ipv4_is_in_range(IpAddress, "fe80::/10")` for an IPv6 network (**conv**). The function returns null "if conversion for one of the two IPv4 strings wasn't successful" (**doc**); the docs do not mention IPv6 input, so "never matches" is **hyp**, strong.
- **T6.2 Field type.** Lucene and OpenSearch emit an escaped term `IpAddress:fe80\:\:\/10` (**conv**); this is a CIDR query only on an `ip`-typed field (**hyp**, T25). SPL emits `IpAddress="10.0.16.0/20"` and relies on SPL's own CIDR matching in `field=value` (**hyp**).
- **T6.3 Prefix expansion.** SQLite expands the network into `LIKE` prefixes in the pySigma core (`'10.0.16.%' OR '10.0.17.%' ...`, `'fe8_:%' ...`) (**conv**). Text prefixes miss uncompressed or zero-padded IPv6 forms. pySigma changed the IPv6 expansion between majors: `::1/128` gives one `LIKE` alternative in 1.5.1 and two in 2.1.1, and 16 corpus rules convert differently for SQLite for this reason (**conv**, version comparison of 24 Nov 2026).
- **T6.4 IPv4-mapped IPv6.** Windows writes many source addresses as `::ffff:192.168.1.5` (4624, 5156). Under the S17 working interpretation `cidr: 192.168.0.0/16` does not match it; engines may differ (**hyp**). Results are `spec-gap`.

Example case: `IpAddress|cidr: '10.0.16.0/20'`, events `10.0.31.255` (match), `10.0.32.0` (no), `::ffff:10.0.16.1` (no, by S17), and `fe80::1` with `cidr: 'fe80::/10'` (match).

### T7. Regex dialect

**Intent.** `re` uses a restricted PCRE subset, case-sensitive by default, with sub-modifiers `i`, `m`, `s` (S15, S61). Other syntax is "unsupported and can not be used" (S60). Regex values get no Sigma wildcard or escape processing (S62). S15 is ambiguous on anchoring; the working interpretation is an unanchored search, as PCRE does.

- **T7.1 Flavour.** Operators emitted (**conv**): Lucene and OpenSearch `/.../` (Lucene regexp syntax), EQL `regex~`, ES\|QL `rlike`, KQL `matches regex` (RE2), SPL `| regex` (PCRE), LogQL `=~` (RE2), SQLite `REGEXP` (the function the harness registers). EQL's `regex` uses the Lucene regexp syntax: the EQL page sends readers to "Regular expression syntax", which is the Lucene page (**doc**). The ES\|QL `rlike` dialect is not verified.
- **T7.2 Anchoring (strong).** Lucene regexp: "the regular expression must match the entire string" (**doc**), so on Lucene, OpenSearch and EQL an unanchored Sigma regex such as `[0-9]{3}` matches only a value that is exactly three digits. LogQL label matchers are fully anchored too (the LogQL page says so for `=~` in stream selectors and says label filters behave like them) (**doc**, label-filter part **hyp**); the backend emits `CommandLine=~`[0-9]{3}`` without `.*` padding (**conv**). KQL "contains a match" (**doc**), SPL and SQLite search (**hyp**). This turns most regex rules into under-matches on four targets.
- **T7.3 Anchors and inline flags (strong).** "Lucene's regular expression engine does not support anchor operators, such as ^ or $" and has no inline flag syntax; case-insensitivity is a query option (**doc**). The backends emit `CommandLine:/(?i)^cmd\.exe \/c/` (**conv**), which is expected never to match on Lucene, OpenSearch and EQL (**hyp**, strong).
- **T7.4 Unsupported syntax** (S60). pySigma 2.x validates regexes with RE2 and rejects lookahead `a(?=b)` for SPL, LogQL and SQLite; pySigma 1.x passes it to Lucene, ES\|QL, EQL and KQL (**conv**). The engine then errors (KQL, RE2), or reads it some other way (**hyp**). Shorthand classes `\d`, `\w`, `\s` are in the same position and are labelled `rule-out-of-spec` when a rule uses them.
- **T7.5 Escaping inside regex.** `/` is escaped for Lucene and EQL, `"` for ES\|QL, KQL and SPL (**conv**, `re_escape` attribute). A regex with `/` in a path is the case to test.

Example case: `CommandLine|re: '[0-9]{3}'`, events `abc123def` (match), `123` (match), `ABC` (no).

### T8. Value modifiers

**Intent.** Modifiers apply left to right (S12). Transformations `base64`, `base64offset`, `utf16le`/`wide`, `utf16be`, `utf16`, `windash` (S13, S14, S64). `fieldref` compares two fields (S20). `expand` placeholders must be resolved or the rule rejected (S21, S67). Unknown modifiers are not covered (S68).

- **T8.1 `base64offset`.** Three shifted encodings joined by OR (`*SUVY*`, `*lFW*`, `*JRV*`) on every target (**conv**). pySigma 2.x changed the handling of non-ASCII input (version comparison, **conv**). Base64 is case-sensitive by nature, but every case-insensitive backend matches it case-insensitively, which over-matches (**hyp**, T1).
- **T8.2 UTF-16 then base64.** `wide|base64offset` gives the same three strings on all targets (**conv**). pySigma 2.x changed the BOM handling of `utf16`.
- **T8.3 `utf16le` is unknown.** The spec lists `utf16le` (S13), but both pySigma 1.5.1 and 2.1.1 reject it: "Unknown modifier 'utf16le'" (**conv**, loud). SigmaHQ rules use `wide`, so the corpus is not affected; a rule from another source would be.
- **T8.4 `windash`.** Five variants (`-`, `/`, en dash, em dash, horizontal bar) on all targets (**conv**). For a value with four dashes, pySigma 1.5.1 expands every combination while 2.1.1 refuses: "windash modifier expands at most three dash occurrences in one value" (**conv**, loud on 2.x).
- **T8.5 `fieldref`.** Lucene, OpenSearch, EQL and KQL reject it (**conv**, loud; EQL's error text names the "ES Lucene backend"). ES\|QL `User==TargetUser`, SQLite `User=TargetUser`, SPL `where 'User'='TargetUser'`, LogQL a `label_format` template with `eq` (**conv**). All are expected to compare case-sensitively, against S1 (**hyp**).
- **T8.6 `expand` placeholders** (S21, S67, clear). An unhandled `%admins%` raises `SigmaPlaceholderError` on seven targets, but LogQL converts it to the literal `User=~`(?i)^%admins%$`` (**conv**): a `backend-bug` candidate against a clear clause. In production, pipelines can replace placeholders with a wildcard (`wildcard_placeholders`), which turns a narrow rule into a catch-all (**hyp**).
- **T8.7 Chaining and unknown modifiers.** Order matters (`wide|base64` vs `base64|wide`). Unknown modifiers are rejected by pySigma (**conv**, loud); native engines may differ (S68).

Example case: `CommandLine|windash|contains: ' -enc '` against ` /enc `, ` –enc ` (en dash) and ` -Enc `.

### T9. Lists and boolean logic

**Intent.** Lists under one field are OR, `all` makes them AND (S7); map keys are AND (S8); a list of maps is OR (S9). Operators and precedence `or` < `and` < `not` < `x of` < brackets (S26, S27). `them` skips identifiers starting with `_` (S28). Patterns (S29), condition lists (S30), empty lists (S51), undefined (S52) and unused identifiers (S53), keyword case (S55), explicit `_` patterns (S56), `not 1 of` (S57), `neq` with a list (S58).

- **T9.1 Grouping of modifier expansions in LogQL (open).** pySigma expands `windash`, `base64offset` and value lists into an OR group. In LogQL the backend does not bracket that group when it sits inside an AND: `Image|endswith` plus `CommandLine|windash|contains` gives `Image=~... and CommandLine=~A or CommandLine=~B or ...` in both backend 0.15.1 and 0.16.0 (**conv**). LogQL evaluates predicates "left to right" (**doc**), so the result is `(Image and A) or B or ...`: an over-match. This is D2 from the demo (**run**, rule c248c896 uses `windash`), still open in 0.16.0. Other targets bracket the group (**conv**).
- **T9.2 Precedence of explicit conditions.** `a and (b or c)` is bracketed by every backend (**conv**). `a or b and c` is emitted as `x=1 or y=2 and z=3` by LogQL (**conv**); with left-to-right evaluation that means `(a or b) and c`, not Sigma's `a or (b and c)` (**hyp**, strong). Lucene, OpenSearch and EQL list their precedence tuple as (NOT, OR, AND), the reverse of Sigma, but still bracketed every mixed group in our probes (**conv**). The LogQL tuple has no NOT at all.
- **T9.3 Negated groups.** `sel and not 1 of filter_*` becomes `NOT (x:1 OR y:2)` on most targets and De Morgan's `x!=1 and y!=2` on LogQL (**conv**). Equivalent in two-valued logic, not under T5.4's conversion-failure rule (**hyp**).
- **T9.4 `neq` with a list** (S58). OR of `neq` values is always true for two distinct values; AND is the likely intent. The spec does not say (ambiguous).
- **T9.5 Edge conditions are mostly silent.** All eight targets convert these without an error (**conv**): an empty list `Details: []` becomes a null test (`NOT _exists_:Details`, `isnull(Details)`, ...); `null` inside a list becomes `x OR null-test` (against S49); `|all` on a single value is accepted although the modifiers appendix forbids it (S88, clear; such a rule is labelled `rule-out-of-spec`, and no SigmaHQ Windows rule does it). Only upper-case `AND` (S55), unknown modifiers and `exists: 'true'` (S66) are rejected.

Example cases: `condition: a or b and c` with an event matching only `a`; `Image|endswith` plus `CommandLine|windash|contains` with an event matching only the second dash variant.

### T10. Field mapping, pipelines and backend options

**Intent.** Not in the Sigma spec. Pipelines adapt a rule to a target schema; backend options change how it is rendered.

- **T10.1 Renames.** ECS (`ecs_windows`, 70 items), Splunk (`splunk_windows`, 40 items in backend 2.1.0 vs 50 in 3.0.1), Splunk CIM, Microsoft XDR and 365 Defender, Sentinel ASIM, Azure Monitor (711 items), Loki promtail Sysmon. A field with no mapping passes through unchanged or makes the rule fail, depending on the pipeline.
- **T10.2 Value transformations.** `SplitDomainUser`, `ParentImageValue`, hash splitting, `SetValue`, `ConvertType`, `AddFieldnamePrefix`, `AddFieldnameSuffix`, `CaseTransformation` and `ReplaceStringTransformation` change values or names. The XDR, ASIM and Azure Monitor pipelines use `ReplaceString` with an anchored pattern (`^HKLM`) to rewrite registry hives, so a `contains` value, which starts with a wildcard, is not rewritten (**hyp**). A transformation that normalises only the rule side breaks matches.
- **T10.3 Dropped detection items.** `DropDetectionItem` removes a condition. Dropping it from a positive selection widens the rule; dropping it from a negated filter narrows it. Both are silent.
- **T10.4 Pipeline version drift.** The same pipeline name maps fields differently between releases (T10.1 Splunk example).
- **T10.5 Engine-native mapping.** Chainsaw reaches only fields listed in its mapping file (**run**, C1, `config`).
- **T10.6 Backend options.** Constructor options that change semantics: Loki `case_sensitive` and `add_line_filters`; SQLite `collate_nocase`, `cidr_mode`, `text_mode`, `modifier_mode`; Splunk `min_time` (default `-30d`) and tstats `fillnull_value="null"`. Phase 3 runs defaults only and records the options used; this list is partial (closure check 4).

Example: a rule on `ParentImage` through the Microsoft XDR pipeline, compared with the neutral result.

### T11. Correlation

**Intent.** Types `event_count`, `value_count`, `temporal`, `temporal_ordered` and `value_sum`, `value_avg`, `value_percentile` (S31, S70 contradictory on the list). `group-by` ANDed (S32, S71 contradictory on optional), with values that differ only in case not covered (S90). `timespan` should not be bound to fixed boundaries unless the backend needs it (S33); whether the window includes its start is not covered (S91). Condition operators, with a single criterion and a range example that contradict each other (S34 contradictory), and whether `temporal` needs one (S92 contradictory). Order (S35). How many alerts one burst gives is not covered (S93). Distinct counting and case (S72), several fields (S73), percentile semantics (S74), aliases (S75), references and chains (S76), `generate` (S77), errors where "must" features are unsupported (S78), warnings for approximations (S79), timespan format (S80).

- **T11.1 Support.** SPL (`bin _time span=5m | stats`), ES\|QL (`stats` by `date_trunc`), EQL (`sequence ... with maxspan`), LogQL (`count_over_time`) and SQLite convert `event_count` and `value_count`; Lucene, OpenSearch and KQL reject correlations (**conv**, loud). ES\|QL and LogQL reject `temporal_ordered` (**conv**, loud) ([correlation_probe.txt](../results/taxonomy/correlation_probe.txt)).
- **T11.2 Window type.** SPL and ES\|QL use fixed buckets, which miss bursts that straddle a boundary (S33); LogQL slides (**conv** for the query shape, **hyp** for counts). Neither SPL nor ES\|QL warns (S79). Security Data Works reported a backend dropping the window entirely (prior work). sigma.matching, Zircolite and Hayabusa slide, with windows that end at events (**run**) ([correlation_crosscheck](../results/phase3/correlation_crosscheck/README.md)). Hayabusa's `temporal` accepts events up to `timespan` before and after the first rule's event, so three events 10 minutes apart correlate under a 5-minute timespan (**run**, H12). Conditions that are not monotone (`eq`, `lt`, `value_avg`) are tested on every window that ends at an event, so `eq: 2` fires on the way to 3 events (S96, **run** on all three; fixed buckets will differ, **hyp**).
- **T11.3 EQL emulation.** `value_count` becomes `sequence by IpAddress with maxspan=5m [any where ...] by TargetUserName with runs=5` (**conv**): the inner `by` forces all five events to share the same `TargetUserName`, the opposite of counting distinct values. `temporal_ordered` and a correlation without `group-by` produce `by  with runs=2` and `sequence  with maxspan`, which look malformed (**conv**, **hyp** that EQL rejects them).
- **T11.4 Grouping with missing values.** Events where a `group-by` field is missing form a null group on some engines and are dropped on others (S32). sigma.matching and Hayabusa form the null group, Zircolite drops them (**run**, M9, H6); SPL's `stats ... by` drops them (**hyp**). Unapplied `aliases` put every event in the null group, so unrelated events correlate (**run**, M15, H11); an alias that lists only some rules is not covered (S97).
- **T11.5 Distinct counting and case** (S72, S73, S90, S95). `Admin` and `admin` counted as one or two values, or as one or two groups: sigma.matching and Hayabusa count two, Zircolite one (**run**, M8, H5). Hayabusa counts a missing field as a value (H8) and reads a list in `field` as no field, so it counts events (H13); sigma.matching crashes on a list (M10) and counts an event once per referenced rule that matches it (M17) (**run**).
- **T11.6 Ordering and ties.** `temporal_ordered` with two events at the same timestamp: Hayabusa accepts them in either order, sigma.matching in arrival order, Zircolite never (**run**, H9, M11, T22). Zircolite rounds timestamps to milliseconds, so events 800 ns apart tie (**run**, Z1; the spec does not give a resolution, S99). An event exactly `timespan` before the last one is inside the window on all three (S91, **run**).
- **T11.7 Alert granularity** (S93). SPL and ES\|QL give one row per group and bucket, LogQL one sample per evaluation step, the evaluator one alert per rising edge, so alert counts are not comparable across targets and cases compare the groups that fire (**hyp**). sigma.matching and Zircolite raise one alert per event once the count is reached, Hayabusa one per window (**run**).
- **T11.8 Conditions and timespan.** The spec both limits a condition to "exactly one condition criterion" and shows a range with two (S34, contradictory). pySigma follows the first sentence and rejects a range in its rule parser, so every pySigma backend refuses the rule with an error (**run**, P1, loud); Hayabusa keeps only the first operator (**run**, H7, silent). pySigma accepts `timespan: 5M` as 5 months (S80, **run**, P2). sigma.matching and Hayabusa ignore the condition of `temporal` and need every rule (S92, **run**, M12, H10). pySigma reads `value_percentile` as a numeric percentile with a `percentile` key the spec does not have (S74, **run**, M16, P6). pySigma and Hayabusa read `generate` only inside `correlation`, not at the top level where the JSON schema has it (S77, **run**, P5, H16).
- **T11.9 References and chains** (S76, S94). sigma.matching ignores a reference by `id` (M13) and never fires a correlation over a correlation (M14), both silently. Hayabusa refuses an `event_count` over a correlation and runs a `temporal` one, which does not fire when the inner rule groups by another field or held minutes earlier (H14). What a chained correlation counts is not covered (S94) (**run**).

Example case: `event_count` of failed logons per `TargetUserName`, `gte: 5`, `timespan: 5m`, with 5 events spread across a five-minute boundary.

### T12. Keywords and full-text search

**Intent.** A keyword list searches "the full log message" (S10, ambiguous). `'|all'` means every keyword must appear (S50).

- **T12.1 What is searched.** Lucene `*mimikatz*` searches the default field(s); SPL `"mimikatz"` searches the raw event; EQL emits `any where "mimikatz"`; KQL emits a bare `"mimikatz"`, which the harness wraps as `T | where "mimikatz"`, a non-boolean predicate that is expected to error (**conv**, **hyp** for the engines). ES\|QL and SQLite reject keywords (**conv**, loud; SQLite needs a full-text column).
- **T12.2 Tokens vs substrings.** The S10 working interpretation is a substring match against any string field value, not token matching, so a target that matches whole tokens only diverges as `spec-gap`. SPL matches indexed terms, so `mimikatz` may not match `xmimikatzx`, while Lucene `*mimikatz*` and LogQL `|~` do (**hyp**). KQL `has` and `has_all` (T2.2) are term matches (**doc**).
- **T12.3 JSON line in LogQL.** `|~ (?i)mimikatz` runs over the whole stored JSON line, so it also matches field names and sees JSON escapes (`\\` for each backslash, `\"` for quotes) (**conv**, **hyp** for effect).
- **T12.4 `|all`.** Converted as AND on all targets that support keywords (**conv**).

Example case: keyword `mimikatz` against an event with `Image: 'C:\tools\mimikatz.exe'`, against `xmimikatzx`, and against an event that has `mimikatz` only in a field name.

### T13. Value length and encoding

**Intent.** Not covered by the spec except Unicode normalisation (S47, not covered).

- **T13.1 Truncation at index time.** Elasticsearch and OpenSearch do not index a keyword longer than `ignore_above`; a keyword query then cannot match it. Our harness template sets `ignore_above: 32766` (`results/runs/*/manifest.json`), so stock defaults do not apply to our runs, but "the value for ignore_above is the character count, but Lucene counts bytes" (**doc**): a long value with multi-byte UTF-8 characters can still exceed Lucene's 32,766-byte term limit (**hyp**). Production setups with smaller limits are a Phase 4 question. SPL truncates events at `TRUNCATE` and LogQL rejects lines above its size limit (**hyp**). Attacker: pad the command line past the limit.
- **T13.2 Truncation at the source.** Windows truncates some fields itself (4688 command lines; 4104 script blocks are split into parts) (**hyp**, T26).
- **T13.3 Non-ASCII and normalisation.** Composed vs decomposed characters (S47), homoglyphs, right-to-left marks: the same on all targets unless an engine normalises (**hyp**).
- **T13.4 NUL and control characters.** SQLite's numeric check uses `instr(x, char(0))`; values with NUL may be cut by some engines (**hyp**).

Example case: `CommandLine|contains: 'sekurlsa'` on a 300-character, a 20,000-character and a 12,000-character non-ASCII command line.

### T14. Whitespace, quotes and special characters

**Intent.** Spaces inside a value are part of it (S45); repeated spaces and tabs are literal (S48). Only the YAML quote character needs escaping in a rule (S40, in T18).

- **T14.1 Leading and trailing spaces.** Hayabusa trims event values, so rule `NtLmSsp` matches event `NtLmSsp ` (**run**, H1, `backend-bug`). All converters keep the trailing space in the rule value (**conv**). On Lucene a quoted phrase on a `text` field loses it during analysis (**hyp**, T25).
- **T14.2 Tabs and newlines inside Lucene queries.** The Lucene backend escapes spaces but not tabs or newlines (`add_escaped` has no `\t` or `\n`), so `contains: "a\tb"` becomes `CommandLine:*a<TAB>b*` (**conv**). The classic query parser treats whitespace as a separator, so the query becomes two clauses (**hyp**, strong).
- **T14.3 Tabs and repeated spaces elsewhere.** Passed through as raw characters (**conv**). Analysed fields collapse them (**hyp**). Attacker: `cmd  /c` or a tab instead of a space.
- **T14.4 Quotes in values.** `say "hi" it's` is escaped correctly by all targets in the probe (**conv**).
- **T14.5 Characters special to the query language.** Lucene escapes `+-=&|!(){}[]<>^"~*?:\/` and space (**conv**). LogQL switches from backtick to double-quoted strings when the value contains a backtick (``CommandLine=~"(?i).*a`b.*"``), which changes how backslashes inside it must be escaped (**conv**, **hyp** for a backtick plus backslash). SQLite escapes `%` and `_` in `LIKE` (**conv**). `|`, `$` and `${...}` pass through (**conv**).

Example case: `AuthenticationPackageName: 'NtLmSsp'` against `NtLmSsp ` and `NtLmSsp`; `CommandLine|contains: "a\tb"` on Lucene.

### T15. Field names and field access

**Intent.** Field names are written as in the log source (S42, case-sensitivity not stated); Windows attributes become `Tag_Attribute` and dotted names are allowed (S43); spaces are stripped (S85); `<UserData>` is not covered (S86, ambiguous).

- **T15.1 Quoting of unusual names (strong).** KQL quotes names that are not `\w+` with single quotes: `'Source Name' =~ "x"`, `'event.code' =~ "1"`, `'a-b' =~ "1"` (**conv**). KQL references such names as `['entity-name']` (**doc**, KQL entity names); a bare `'...'` is a string literal, so the condition compares two constants (**hyp**, strong). EQL leaves `a-b:"1"` unquoted (**conv**), though EQL requires backticks around field names that "contain a hyphen" (**doc**).
- **T15.2 Sanitised names.** LogQL replaces `.`, `-` and space with `_` (`Source_Name`, `event_code`, `a_b`) (**conv**). This matches the `json` stage's own sanitising, but two different names can collide (`a-b` and `a_b`) (**hyp**).
- **T15.3 Case of names.** SQLite column names are case-insensitive; most others are case-sensitive (S42) (**hyp**).
- **T15.4 Spaces in names.** Chainsaw does not strip spaces (**run**, C2), nor do Hayabusa's raw rules (H3); both `config`.
- **T15.5 `UserData` and nested access.** Chainsaw cannot reach `<UserData>` fields (**run**, C3, `spec-gap`).

Example case: `'event.code': '1'` on a JSON event `{"event": {"code": "1"}}` and on `{"event.code": "1"}`.

### T16. Logsource selection

**Intent.** `logsource` selects which events a rule applies to (S36). The taxonomy appendix maps Windows categories to EventID and Channel (S37, ambiguous for non-Sysmon sources). `definition` is not evaluated (S38).

- **T16.1 Neutral config.** Every backend drops the logsource, so a rule can match events of the wrong type. Hayabusa still skips events with no `Channel` (**run**, H2).
- **T16.2 Engine tables.** Chainsaw requires provider Security-Auditing for `service: security`, so 1102 "audit log cleared", written by provider Eventlog, never fires (**run**, C7, `config`: no reading of S37 involves the provider). Chainsaw also excludes rules by title (**run**, C9, `config`).
- **T16.3 Pipeline conditions.** Each pipeline adds its own EventID, Channel or index condition; they need not agree (**hyp**, Phase 4).
- **T16.4 Unknown logsources.** A logsource a pipeline does not know is either dropped (the rule runs on everything) or rejected (**hyp**).

### T17. Multi-valued and nested fields

**Intent.** Arrays are not covered (S44). `Hashes` holds several hashes in one string (S84). Unnamed `<Data>` elements are not covered (S87, ambiguous).

- **T17.1 Arrays.** LogQL's `json` parser skips arrays: "Arrays are skipped" (**doc**). ES\|QL functions return null on multi-valued fields (**doc**, per the review; not re-checked). Lucene matches any element (**hyp**). Negation over an array (no element vs not every element) is the evasion case.
- **T17.2 Composite strings.** `Hashes: 'SHA1=...,MD5=...'`: rules use `contains`; pipelines may split it (T10.2).
- **T17.3 Unnamed `Data`.** Hayabusa splits PowerShell classic `Data` text into fields (**run**, H4, `config`: no reading of S87 gives those fields).

### T18. Rule loading and value typing

**Intent.** Rules are YAML; unquoted scalars are typed by the loader (S39, contradictory with "treated as strings"). Only the YAML quote character needs escaping (S40).

- **T18.1 YAML 1.1 vs 1.2.** `Flags: 0x10` becomes 16 for every target (**conv**), so an event value `0x10` does not match. `yes`, `on`, `010` and `1e3` differ between YAML 1.1 and 1.2 loaders; native engines with their own loaders (Chainsaw and Hayabusa, in Rust) may type them differently from pySigma (**hyp**). `Enabled: 'yes'` stays a string (**conv**).
- **T18.2 Rule validity.** What each tool does with a rule pySigma accepts and a native engine rejects, or the reverse (T9.5 lists what pySigma accepts silently). Counted as conversion failure.

### T19. Query structure and deferred parts

**Intent.** Not in the spec. Some backends split a rule into a main search and post-filters.

- **T19.1 Deferred regex.** SPL puts regexes in a `| regex` post-filter (`*\n| regex CommandLine="\\d{3}"`) and turns a negated regex into `| regex CommandLine!="x.y"` (**conv**). For events without the field, `regex !=` may keep or drop them (**hyp**, T4). Between splunk backend 2.1.0 and 3.0.1 one corpus rule (`regedit_import_keys`) moved the regex of a negated filter into a positive `| regex` post-filter (**conv**, version comparison).
- **T19.2 Several queries per rule.** A converter can emit more than one query for one rule; the harness counts the rule as matching if any query matches.
- **T19.3 Correlation queries.** Only the correlation query is generated by default (S77, in T11).
- **Backend attributes.** `deferred_start` is set for SPL and KQL.

### T20. Query and engine limits

**Intent.** Not in the spec.

- **T20.1 Clause counts.** Elasticsearch limits boolean clauses (`indices.query.bool.max_clause_count`); long value lists and `windash` or `base64offset` expansions grow fast (T8.4: four dashes give hundreds of clauses on 1.x) (**hyp**).
- **T20.2 Regex size.** Elasticsearch `index.max_regex_length` and Lucene's automaton state limit reject large regexes (**hyp**).
- **T20.3 Query length.** URL and request length limits for SPL and LogQL (**hyp**).
- **T20.4 Result caps and timeouts.** A search that returns at most N events, or times out, under-reports matches (harness, section 8).

### T21. Unsupported features and lossy emulation

**Intent.** Cross-cutting. The correlation spec asks for an error where a "must" feature cannot be supported (S78) and a warning for approximations (S79); for detection features the spec only implies that the meaning must be kept. Each case keeps the area of the feature as primary.

- **T21.1 Loud.** `cased` on single values (5 targets), `fieldref` (4), `exists` (EQL), booleans (LogQL), keywords (ES\|QL, SQLite), correlations (3 targets, plus `temporal_ordered` on 2), `utf16le` (all), four-dash `windash` (2.x) (**conv**).
- **T21.2 Silent loss.** None of these warns (**conv**):
  - `cased` dropped in value lists (T1.3) and turned into wildcard-free `==` in EQL (T1.4);
  - `?` as `*` in SPL (T2.1); KQL wildcards as unanchored case-sensitive regex or unordered `contains` fragments (T2.2);
  - escaped `\*` and `\?` in LogQL and SPL (T3.4);
  - IPv6 CIDR as `ipv4_is_in_range` in KQL (T6.1);
  - unbracketed expansions in LogQL (T9.1);
  - empty lists, `null` in lists and `|all` on one value (T9.5);
  - unresolved placeholders in LogQL (T8.6);
  - Sigma filters combined the wrong way (T23.1).
  These are the converter findings most worth reporting.
- **T21.3 Dropped parts.** Pipelines dropping detection items (T10.3).

### T22. Time and ordering

**Intent.** Time modifiers `minute` to `year` (S22). The resolution at which timestamps are compared is not covered (S99).

- **T22.1 Time modifiers.** Which time zone the engine uses for `hour`, `day`, `week` (**hyp**).
- **T22.2 Event time vs ingest time.** Engines that window by ingest time disagree with event time, mostly for correlation (**hyp**, T11).
- **T22.3 Search time range.** Old events fall outside a default search range: Loki needed `/flush` for events older than about 3 h (section 8), and the Splunk backend's `min_time` defaults to `-30d` (T10.6).

### T23. Sigma filters and meta-rules

**Intent.** A global filter suppresses matches of the rules it lists (S81, ambiguous; working interpretation `rule condition and not filter condition`). It applies only when the logsources are equal (S82, ambiguous). A reference to a missing rule is not covered (S83), nor is the order of filters and correlations (S89), nor what a tool that cannot apply a filter must do (S98). Probes: [filters_probe.txt](../results/taxonomy/filters_probe.txt).

- **T23.1 Combination.** pySigma ANDs the filter's condition into the rule: rule `Image|endswith: '\cmd.exe'` with a filter on `User: admin` and `condition: selection` gives `Image="*\\cmd.exe" User="admin"` on SPL and the same shape on every target (**conv**). Under S81's interpretation that is inverted: the spec's own example (`User|startswith: 'adm_'`, `condition: selection`) would keep only the admin events it was written to suppress. pySigma expects the filter author to write `not`; the spec example does not. `spec-gap` (S81 ambiguous), but worth a clarification to both.
- **T23.2 Logsource.** A filter with `{product: windows}` is applied to a `process_creation` rule (subset match), while S82's interpretation requires equal logsources; a filter with another product is not applied (**conv**).
- **T23.3 Missing references.** A filter that names a rule id that does not exist is silently ignored (**conv**, S83).
- **T23.4 Native engines.** Hayabusa reports a global filter as a rule parsing error and runs the rules without it (**run**, H15), which the spec neither allows nor forbids (S98); Chainsaw may not support them at all (**hyp**). sigma.matching and Zircolite inherit T23.1 and T23.2 from pySigma (**run**, P3, P4).
- **T23.5 Filters and correlations.** A filter on a rule that a correlation counts removes events before counting (S89); a converter may filter the base query, the correlation, or neither (**hyp**).

### T24. Rule-authoring quirks

**Intent.** Not in the spec. A rule whose literal text depends on a target's quirk to work.

- **T24.1 Trimmed values.** A rule written for a value with a trailing space, or without one, works on Hayabusa either way because it trims (H1).
- **T24.2 Unescaped wildcards meant literally.** `*` or `?` in a path or URL that the author meant as a character.
- **T24.3 Values that only match one representation.** A rule written for a rendered value (T26).

### T25. Storage schema and field types

**Intent.** Not in the spec. How the engine stores the field decides how a query behaves.

- **T25.1 Keyword vs text.** Default Elasticsearch and OpenSearch dynamic mapping stores strings as `text` with a `keyword` sub-field; a Lucene query on the analysed field matched nothing for our demo rule (**run**, D3).
- **T25.2 Typed fields.** `ip` type for CIDR (T6.2), numeric types for `lt`/`gt` (T5.3), the `wildcard` type in ECS templates.
- **T25.3 Engine typing.** Splunk indexed vs search-time fields, Kusto typed columns (strings cannot be null, T4.1), Loki labels vs JSON fields, SQLite type affinity.

### T26. Event value representation

**Intent.** Not in the spec. The same Windows event can carry different values depending on how it was collected.

- **T26.1 Rendered vs raw values.** Message codes such as `%%1936` vs `TokenElevationTypeDefault (1)` (4688).
- **T26.2 Number formats.** Process IDs in hex (`0x1a2c`, Security log) vs decimal (Sysmon).
- **T26.3 Path forms.** `\Device\HarddiskVolume3\...` vs `C:\...`, short 8.3 names, `\\?\` prefixes.
- **T26.4 Identifiers.** GUIDs with and without braces, SIDs vs names.
- **T26.5 Payload location.** `<UserData>` vs `<EventData>` (S86), unnamed `Data` (S87).

All T26 sub-areas are **hyp** for our corpus; Phase 4's production runs show which ones occur.

## 6. Clause coverage

Every clause has one primary area; secondary areas list where else it matters. `tests/test_taxonomy_coverage.py` fails if a clause in [spec-clauses.md](spec-clauses.md) is missing here or listed twice.

| Clause | Primary | Secondary |
| --- | --- | --- |
| S1 | T1 | T13 |
| S2 | T1 | T21 |
| S3 | T2 | T14 |
| S4 | T2 | |
| S5 | T3 | |
| S6 | T2 | T8 |
| S7 | T9 | T2 |
| S8 | T9 | |
| S9 | T9 | |
| S10 | T12 | |
| S11 | T5 | T18 |
| S12 | T8 | |
| S13 | T8 | T13 |
| S14 | T8 | |
| S15 | T7 | T1 |
| S16 | T5 | |
| S17 | T6 | |
| S18 | T4 | |
| S19 | T4 | T5 |
| S20 | T8 | T21 |
| S21 | T8 | T10 |
| S22 | T22 | |
| S23 | T4 | |
| S24 | T4 | |
| S25 | T4 | T9 |
| S26 | T9 | |
| S27 | T9 | |
| S28 | T9 | |
| S29 | T9 | |
| S30 | T9 | |
| S31 | T11 | |
| S32 | T11 | |
| S33 | T11 | T22 |
| S34 | T11 | |
| S35 | T11 | T22 |
| S36 | T16 | |
| S37 | T16 | T10 |
| S38 | T16 | |
| S39 | T18 | T5 |
| S40 | T18 | T14 |
| S41 | T3 | |
| S42 | T15 | |
| S43 | T15 | |
| S44 | T17 | |
| S45 | T14 | |
| S46 | T2 | T14 |
| S47 | T13 | |
| S48 | T14 | |
| S49 | T4 | T9 |
| S50 | T12 | |
| S51 | T9 | T21 |
| S52 | T9 | |
| S53 | T9 | |
| S54 | T4 | T9 |
| S55 | T9 | |
| S56 | T9 | |
| S57 | T9 | |
| S58 | T9 | T4 |
| S59 | T6 | |
| S60 | T7 | T21 |
| S61 | T7 | |
| S62 | T7 | T3 |
| S63 | T8 | |
| S64 | T8 | |
| S65 | T1 | T2 |
| S66 | T4 | T18 |
| S67 | T8 | T21 |
| S68 | T8 | T21 |
| S69 | T5 | |
| S70 | T11 | |
| S71 | T11 | |
| S72 | T11 | T1 |
| S73 | T11 | |
| S74 | T11 | |
| S75 | T11 | T15 |
| S76 | T11 | |
| S77 | T11 | T19 |
| S78 | T11 | T21 |
| S79 | T11 | T21 |
| S80 | T11 | T22 |
| S81 | T23 | |
| S82 | T23 | T16 |
| S83 | T23 | |
| S84 | T17 | T26 |
| S85 | T15 | |
| S86 | T15 | T26 |
| S87 | T17 | T15 |
| S88 | T9 | T18 |
| S89 | T23 | T11 |
| S90 | T11 | T1 |
| S91 | T11 | T22 |
| S92 | T11 | |
| S93 | T11 | |
| S94 | T11 | |
| S95 | T11 | |
| S96 | T11 | T22 |
| S97 | T11 | T15 |
| S98 | T23 | T21 |
| S99 | T22 | T11 |

The line below counts how many of the 99 clauses have each area as their primary home (it sums to 99). Areas not listed have none: the spec says nothing about them, so they have no spec verdict of their own (section 4). A low count also marks where the spec is thin, and spec gaps are likely there.

Clauses per primary area: T1 3, T2 4, T3 2, T4 8, T5 3, T6 2, T7 4, T8 9, T9 16, T11 24, T12 2, T13 1, T14 2, T15 4, T16 3, T17 3, T18 2, T22 2, T23 5.

## 7. Measured deviations by area

| Finding | Target | Area | Label or outcome |
| --- | --- | --- | --- |
| D1 case on keyword fields | Lucene, OpenSearch, ES\|QL | T1.1 | `backend-bug` candidate |
| D2 OR group not bracketed inside AND | LogQL | T9.1 | `backend-bug` candidate, still open in backend 0.16.0 |
| D3 dynamic mapping, no matches | Lucene | T25.1 | `config` |
| EQL rejects numeric `:` | EQL | T5.1 | loud (conversion failure, not triaged) |
| C1 unmapped fields | Chainsaw | T10.5 | `config` |
| C2 spaces in names | Chainsaw | T15.4 | `config` |
| C3 `UserData` | Chainsaw | T15.5 | `spec-gap` |
| C4 three-valued `not` | Chainsaw | T4.3 | `backend-bug` |
| C5 null = explicit null | Chainsaw | T4.1 | `spec-gap` |
| C6 string `'true'` vs boolean | Chainsaw | T5.5 | `spec-gap` |
| C7 logsource preconditions | Chainsaw | T16.2 | `config` |
| C8 number vs string | Chainsaw | T5.1 | `spec-gap` |
| C9 title exclusions | Chainsaw | T16.2 | `config` |
| C1&C4 unmapped field in a negated filter | Chainsaw | T10.5, T4.3 | `backend-bug` |
| C1+C2 `Source Name` neither mapped nor stripped | Chainsaw | T10.5, T15.4 | `config` |
| C1+C3 WMI rule on a `UserData` field | Chainsaw | T10.5, T15.5 | `spec-gap` |
| H1 value trimming | Hayabusa | T14.1 | `backend-bug` |
| H2 no `Channel` | Hayabusa | T16.1 | `config` |
| H3 spaces in names (raw rules) | Hayabusa | T15.4 | `config` |
| H4 classic `Data` split | Hayabusa | T17.3 | `config` |
| M1 `*` matches a missing field | sigma.matching | T4.2 | `backend-bug` candidate |
| M2 spaces in names not stripped | sigma.matching | T15.4 | `backend-bug` candidate |
| M3 `fieldref` with both fields missing matches | sigma.matching | T4.2 | `backend-bug` candidate |
| M4 `''` matches a missing field | sigma.matching | T4.2 | `backend-bug` candidate |
| M5 escaped `\*` and `\?` not literal | sigma.matching | T3.4 | `backend-bug` candidate |
| M6 rule integer vs event string | sigma.matching | T5.1 | `spec-gap` |
| M7 list field matched as JSON text | sigma.matching | T17.1 | `backend-bug` candidate |
| P1 range condition rejected | pySigma (all backends) | T11.8 | loud (conversion failure, not triaged) |
| P2 `timespan: 5M` accepted as 5 months | pySigma (all backends) | T11.8 | `backend-bug` candidate |
| P3 filter ANDed into the rule | pySigma (all backends) | T23.1 | `spec-gap` |
| P4 filter applied to a rule with a wider logsource | pySigma (all backends) | T23.2 | `spec-gap` |
| P5, H16 top-level `generate` ignored | pySigma (all backends), Hayabusa | T11.8 | `backend-bug` candidate |
| P6 `value_percentile` needs a `percentile` key | pySigma, SQLite backend | T11.8 | loud (conversion failure, not triaged) |
| Z1 timestamps rounded to milliseconds | Zircolite | T11.6 | `spec-gap` |
| M8, H5 case-sensitive groups and values | sigma.matching, Hayabusa | T11.5 | `spec-gap` |
| M9, H6 null group for a missing group-by field | sigma.matching, Hayabusa | T11.4 | `spec-gap` |
| M10 `value_count` over two fields crashes | sigma.matching | T11.5 | `backend-bug` candidate |
| M11, H9 ties in `temporal_ordered` | sigma.matching, Hayabusa | T11.6 | `spec-gap` |
| M12, H10 `temporal` ignores its condition | sigma.matching, Hayabusa | T11.8 | `spec-gap` |
| M13 reference by `id` ignored | sigma.matching | T11.9 | `backend-bug` candidate |
| M14 chain never fires | sigma.matching | T11.9 | `backend-bug` candidate (C19), `spec-gap` (S94 cases) |
| M15, H11 `aliases` not applied | sigma.matching, Hayabusa | T11.4 | `backend-bug` candidate (full alias), `spec-gap` (partial, S97) |
| M16 `value_percentile` as a numeric percentile | sigma.matching | T11.8 | `spec-gap` |
| M17 an event counted once per matching rule | sigma.matching | T11.5 | `spec-gap` |
| H7 range keeps its first operator | Hayabusa | T11.8 | `backend-bug` candidate |
| H8 missing field counted as a value | Hayabusa | T11.5 | `spec-gap` |
| H12 `temporal` spans twice the timespan | Hayabusa | T11.2 | `backend-bug` candidate |
| H13 list in `field` read as no field | Hayabusa | T11.5 | `backend-bug` candidate |
| H14 temporal over a correlation | Hayabusa | T11.9 | `spec-gap` |
| H15 global filters not parsed, rules run without them | Hayabusa | T23.4 | `spec-gap` |

Version comparisons (converter output only, **conv**): splunk 2.1.0 vs 3.0.1 (T19.1), SQLite IPv6 expansion (T6.3), `windash` limit (T8.4).

## 8. Harness threats (not taxonomy areas)

These change results without any Sigma meaning being lost. They are checked and fixed in the harness, never reported as divergences.

- **Ingest completeness.** Loki needed `POST /flush` after push for old events (fixed in PR #4; cause not established). Every run checks the stored event count per target before querying.
- **Result caps and pagination.** A target that returns the first N hits only. The harness must page or count.
- **Event identity.** Matching a returned hit back to the input event (ids survive ingest on every target).
- **Query transport.** URL encoding and API escaping on top of the query text (the backtick, tab and pipe cases in T14 run end to end for this reason).
- **Harness wrapping.** The harness adds its own syntax around some queries (KQL `T | where <query>`, T12.1). A divergence caused by the wrapper is a harness bug, not a finding.
- **Emulator vs product.** The Kusto emulator and default ES/Splunk settings may differ from managed services; Phase 5 samples ADX and Sentinel.
- **Version freeze.** All versions frozen at one date (decision 8); a change of any converter, pipeline or engine image is a new run.
- **Search time range and clocks.** Old timestamps need explicit time ranges (T22.3).

## 9. Review log

An independent agent reviewed the first draft on 24 Nov 2026. It re-ran the probes, wrote new ones (now in the probe scripts), and checked vendor documentation; a second agent fetched the cited documentation pages to confirm the quotes. Changes made as a result:

- **Corrected.** D2 is not fixed in LogQL 0.16.0 (T9.1); LogQL evaluates left to right, not `and` first (T9.2); `cased` is silently lost in value lists (T1.3); regex anchoring on LogQL and EQL (T7.1, T7.2); C6 direction (T5.5); KQL keyword search goes through the harness wrapper (T12.1); edge conditions are mostly silent, not loud (T9.5); the `windash` limit is loud on 2.x (T8.4); version comparisons are **conv**, not **run**; S78 and S79 moved from T21 to T11; the proposed new clauses were dropped: four already existed, keyword token matching is decided by S10's working interpretation, and `all` on a single value became S88 (Nik, 24 Nov 2026); the out-of-scope note moved to section 2 and the plan notes moved to the Phase 3 plan; the T7 example now uses `[0-9]{3}` instead of out-of-spec `\d{3}`; the layer table is now checked against section 4.
- **Added.** ES\|QL `LIKE` backslashes (T3.3), escaped wildcards (T3.4), LogQL numeric conversion failures (T5.4), three-valued logic on ES\|QL and KQL (T4.3, T4.1), unknown fields as errors (T4.6), the KQL list path (T2.2), EQL correlation emulation (T11.3), filter combination (T23), Lucene tabs and newlines (T14.2), LogQL placeholders (T8.6), `utf16le` (T8.3), backend options (T10.6), more pipeline transformations (T10.2), and **doc** citations for the strong hypotheses.
- **Not verified yet.** Engine behaviour for T4.6 and T14.2, the ES\|QL `rlike` dialect, and the ES\|QL multi-valued-field quote in T17.1.
