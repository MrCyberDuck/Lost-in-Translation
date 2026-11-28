# Phase 2: reference evaluator

**Gate (from the plan):** above 99% agreement with the native engines on SigmaHQ regression data, with every remaining disagreement explained.

**Result: gate passed.** On the regression data with logsource applied (production config), the evaluator agrees with Hayabusa on 2,279 of 2,279 rules (100%) and with Chainsaw on 2,263 of 2,266 rules Chainsaw can load (99.87%). The evaluator passes 197 of 197 SigmaHQ regression tests (Hayabusa 197, Chainsaw 195). On a second, larger real dataset (37,364 events) agreement is 99.96% with Hayabusa and 99.38% with Chainsaw. **Every** remaining disagreement, 343 (rule, event) pairs over both datasets and both configs, is reproduced exactly by switching on a specific, documented behaviour of the engine in the evaluator (section 3); none is left unexplained.

The cross-check found two evaluator bugs, both fixed, and both turned out to be gaps in the clause list: S85 (field names with spaces) and S87 (unnamed `Data` elements). It also made S86 (UserData) explicit. The clause list now has 88 clauses.

## 1. Design

### What the evaluator must do

It is the oracle: for a rule and an event, it says whether the event should match according to the Sigma specification and the working interpretations in [spec-clauses.md](spec-clauses.md). It must be:

- **faithful** to every clause, including the working interpretations for ambiguous ones, so a disagreement with a backend can be pinned on a clause;
- **independent** of the backends under test, as far as possible, so a shared mistake does not hide a disagreement;
- **checkable**: unit tests per clause, and agreement with native Sigma engines on real logs;
- **fast enough** for the full corpus (2,247 rules times tens of thousands of events) on a laptop.

### Architecture

```text
rule YAML ──► pySigma parser ──► SigmaRule (detections, modified values, condition text)
                                      │
                          harness/evaluator/core.py
                                      │
     ┌────────────────────────────────┼─────────────────────────────────┐
     │ own condition resolution       │ own value matching              │ logsource filter
     │ (identifiers, 1 of / all of,   │ (case folding, wildcards, re,   │ (taxonomy appendix,
     │  them, _ rule, and/or/not)     │  cidr, numbers, null, exists,   │  production config only)
     │                                │  fieldref, keywords, neq ...)   │
     └────────────────────────────────┴─────────────────────────────────┘
                                      │
                      CompiledRule.matches(event) -> bool
```

**Parsing is pySigma's; everything after parsing is ours.** This split is deliberate:

- *Shared with backends:* YAML loading, modifier application (`contains`, `windash`, `base64offset`, `wide`, ...) and wildcard/escape parsing into `SigmaString`. Re-implementing these would mostly re-create pySigma, and if the evaluator expanded a modifier differently from pySigma, every backend would "disagree" for a reason that is not a backend fault. The spec-clauses list already decided this (S5, S13, S27, S55).
- *Our own:* the evaluator does not use pySigma's lowered condition tree. It parses the condition without pySigma's post-processing, resolves identifiers and `x of` selectors itself, and compiles each detection item to a Python predicate. This matters because pySigma's lowering loses information that the spec cares about: `neq` becomes a plain `not`, which makes a missing field match (against S19), `1 of *` drops `_` identifiers (against S56), and `[value, null]` lists are accepted (against S49).
- *The risk this leaves:* a pySigma parsing bug would be shared by the evaluator and every pySigma backend, so it would not show up as a disagreement. That is why the native engines matter: Chainsaw and Hayabusa have their own parsers (Rust), so a pySigma parsing bug would show up as evaluator-vs-native disagreement. None did.

**Matching rules** follow spec-clauses.md, one function per value type:

| Value type | Behaviour | Clauses |
| --- | --- | --- |
| string | anchored regex built from `SigmaString`; case-folded with `str.casefold()` unless `cased`; `*` matches newlines; no trimming | S1 to S6, S41, S45 to S48, S65 |
| number, boolean | compared as strings (`4688` = `"4688"`, `true` = `"True"`) | S11, S39 |
| `re` | Python `re.search` (unanchored), flags from `i`/`m`/`s`; constructs outside the spec subset are flagged | S15, S60 to S62 |
| `cidr` | Python `ipaddress`; zone ids, leading zeros and the other address family never match | S17, S59 |
| `lt`/`lte`/`gt`/`gte` | field parsed as int or float; not a number = no match | S16, S69 |
| `null`, `''`, `exists` | null = absent or JSON null; `''` = present and empty; exists = present | S18, S23, S24 |
| `neq` | field present and different from every listed value | S19, S58 |
| `fieldref` | case-insensitive comparison with another field | S20 |
| keywords | case-insensitive substring in any string field (harness fields excluded) | S10, S50 |
| arrays | any element matches | S44 |
| field names | exact and case-sensitive; spaces in event field names are stripped | S42, S43, S85 |
| EVTX payload | `<EventData>` `Data Name` pairs, children of `<UserData>`, unnamed `<Data>` as the multi-valued field `Data` (in `harness/datasets.py`) | S43, S86, S87 |

**Rule errors** (`RuleError`): unresolved placeholders (S21, S67), null inside a value list (S49), empty selections (S51), undefined identifiers (S52), `x of` patterns that match nothing (S29), regexes that do not compile, and anything pySigma rejects.

**Two configurations**, as in the plan:

- `neutral`: logsource ignored; every event is in scope. This isolates detection logic.
- `production`: logsource applied through `harness/evaluator/taxonomy_windows.json`, built from the Sigma spec's taxonomy appendix by `python -m harness.evaluator.build_taxonomy`. Categories without a channel mapping (`file_access`, `file_rename`: ETW only) raise `UnsupportedLogsource`.

**Not in Phase 2:** correlation rules (S31 to S35, S70 to S80) and global filters (S81 to S83). SigmaHQ r2026-07-01 has no correlation rules or filters in scope, so they cannot be cross-checked on real data; they come with the Phase 3 synthetic cases (taxonomy areas T11 and T23).

### Usage

```python
from harness.evaluator import compile_rule, evaluate
rule = compile_rule(open("rules/sigma/rules/windows/.../rule.yml").read())
evaluate(rule, events, config="production")   # -> matching event_id values
```

Tests: `pytest tests/` runs 108 tests: `test_evaluator.py` (67, at least one per implemented clause), `test_datasets.py` (EVTX flattening), `test_chainsaw_semantics.py` (the Chainsaw emulation, checked against the real binary when it is installed) and `test_triage.py`.

## 2. Cross-check against native engines

### Setup

| Component | Version | Notes |
| --- | --- | --- |
| Chainsaw | 2.18.0 (built from source) | its own Sigma engine (tau); mapping `sigma-event-logs-all.yml` |
| Hayabusa | 4.4.0 (built from source, Rust 1.99) | its own Sigma engine; rules config from `hayabusa-rules` |
| sigma-to-hayabusa-converter | commit `e33d20e` | converts the pinned SigmaHQ rules to Hayabusa's production form (Channel/EventID added, built-in-log variants) |
| EVTX parsing | `chainsaw dump --json` | the same Rust `evtx` parser both engines use, so all three see identical records |

Two configurations for the native engines, matching the evaluator's:

- **neutral**: Chainsaw with its mapping minus the logsource preconditions; Hayabusa with the original SigmaHQ rules and its channel filter off (`-A -a`).
- **production**: Chainsaw with its shipped mapping; Hayabusa with the converted rules. Where the converter makes both a Sysmon and a built-in variant, the Sysmon one is compared (it matches the taxonomy appendix) and the built-in one is reported separately.

Run it:

```bash
python -m harness.datasets regression                 # EVTX -> results/phase2/regression_events.jsonl
python -m harness.phase2 regression                   # about 45 seconds
python -m harness.explain regression                  # attribution, about 10 seconds
python -m harness.datasets evtx ~/datasets/EVTX-ATTACK-SAMPLES evtx-attack-samples
python -m harness.phase2 evtx-attack-samples --scan-dir ~/datasets/EVTX-ATTACK-SAMPLES   # about 10 minutes
python -m harness.explain evtx-attack-samples
```

Results are in `results/phase2/<dataset>/`. The attack-samples event file (31 MB) is not committed; regenerate it with the command above.

On another machine (for example Windows), point the harness at the native tools with environment variables. `LIT_NATIVE` sets a base folder; `LIT_CHAINSAW`, `LIT_CHAINSAW_MAPPING`, `LIT_HAYABUSA`, `LIT_HAYABUSA_CONFIG` and `LIT_HAYABUSA_CONVERTED` override single paths. When `LIT_CHAINSAW_MAPPING` is unset, the mapping is looked up next to the Chainsaw binary (release zip) and then two levels up (cargo build). `harness/explain.py` and production Hayabusa runs also need the rules converted by sigma-to-hayabusa-converter in `LIT_HAYABUSA_CONVERTED`.

### Data

- **SigmaHQ regression data** (pinned tag): 197 EVTX files, 233 events, one test per (rule, EVTX) pair, 197 tests, 149 of them for in-scope rules.
- **EVTX-ATTACK-SAMPLES** (sbousseaden, commit `4ceed2f`): 278 EVTX files, 37,364 events. Not a test set (no expected answers), but it gives many more rule-event pairs.

Rules: the 2,247 in-scope rules plus the 48 out-of-scope rules that have regression data, 2,295 in total. The evaluator rejects none of them.

### Results on SigmaHQ regression data

| Config | Pair | Rules compared | Rules agree | Agreement | Matches in both | Only first | Only second |
| --- | --- | --- | --- | --- | --- | --- | --- |
| production | evaluator vs Hayabusa | 2,279 | 2,279 | 100% | 310 | 0 | 0 |
| production | evaluator vs Chainsaw | 2,266 | 2,263 | 99.87% | 307 | 3 | 0 |
| neutral | evaluator vs Hayabusa | 2,295 | 2,294 | 99.96% | 388 | 1 | 0 |
| neutral | evaluator vs Chainsaw | 2,266 | 2,261 | 99.78% | 378 | 11 | 2 |

SigmaHQ's own regression tests (the rule must fire on its EVTX): evaluator 197/197 in both configs, Hayabusa 196/197 neutral and 197/197 production, Chainsaw 195/197 in both.

"Rules compared" leaves out rules an engine cannot run: Chainsaw cannot load 29 rules (16 use `cidr`, 12 are keyword rules, 1 uses `fieldref`; `results/phase2/chainsaw_unloadable.json`), and the converter produced no Hayabusa version for 16 rules. The evaluator rejects none of the 2,295.

### Results on EVTX-ATTACK-SAMPLES

| Config | Pair | Rules compared | Rules agree | Agreement | Matches in both | Only first | Only second |
| --- | --- | --- | --- | --- | --- | --- | --- |
| production | evaluator vs Hayabusa | 2,279 | 2,278 | 99.96% | 1,174 | 0 | 2 |
| production | evaluator vs Chainsaw | 2,266 | 2,252 | 99.38% | 1,104 | 82 | 0 |
| neutral | evaluator vs Hayabusa | 2,295 | 2,292 | 99.87% | 1,795 | 2 | 6 |
| neutral | evaluator vs Chainsaw | 2,266 | 2,247 | 99.16% | 1,665 | 116 | 118 |

Run time on the 4-core cloud machine: evaluator 495 s for 2,295 rules times 37,364 events (pure Python, no indexing), both native engines together 65 s.

## 3. Every disagreement, explained

### Method: explain by emulation

A disagreement is only explained if we can say *which* behaviour causes it and show that this behaviour reproduces the engine's answer. `harness/explain.py` does this. Each engine's departures from the spec ("mechanisms", below) were found from its documentation, its mapping and config files, its source code and probe rules. Each mechanism is implemented as an option of the evaluator (a `Semantics` flag or an event transformation). Then, for every disagreeing (rule, event) pair:

1. With all of the engine's mechanisms on, the evaluator must give the engine's answer. **It does for all 343 pairs: the residual is zero.**
2. Each mechanism is tried alone (then in pairs) to find which one flips the spec answer to the engine's answer. The triage label follows from the clauses that mechanism touches (`harness/triage.py`): an ambiguous clause under one of whose readings the engine is right gives `spec-gap`; mapping or config alone gives `config`; otherwise `backend-bug` with cause `engine`.

Every mechanism is explained with a real example in [section 5](#5-mechanism-reference).

The Chainsaw negation logic (C4) is not documented anywhere, so it was pinned down with 15 probe rules run against the real binary. `tests/test_chainsaw_semantics.py` keeps those probes and re-runs them on the installed Chainsaw, so an upgrade that changes the behaviour is caught.

### Evaluator bugs (`oracle-bug`), all fixed

| Bug | Found by | Fix |
| --- | --- | --- |
| Rule field `SourceName` did not match event field `Source Name` (Defender events) | Regression test for the RedSun rule: evaluator missed it, Hayabusa (through its converter) passed it | New clause **S85**: the spec says rule field names are log field names "with all spaces stripped". Evaluator adds space-stripped aliases. |
| Unnamed `<Data>` elements (ESENT, MsiInstaller, MSSQL, PowerShell classic) became `{"#text": [...]}` and never matched `Data\|contains` | EVTX-ATTACK-SAMPLES: Hayabusa matched 12 events the evaluator missed | New clause **S87**: they form the multi-valued field `Data`. Fixed in `harness/datasets.py`. |

There was also one bug in the comparison harness (not the evaluator): converted Hayabusa rules were first linked to SigmaHQ rules by their `related: derived` id alone, which SigmaHQ also uses between its own rules, so a few converted rules were attributed to the wrong original. Fixed by matching file name plus link.

Pair counts below are (rule, event) pairs, given as regression neutral / production, then attack samples neutral / production. `A+B` means either mechanism alone explains the pair; `A&B` means both are needed.

### Chainsaw 2.18.0

| Mechanism | What Chainsaw does | Clauses | Regression | Attack samples | Label |
| --- | --- | --- | --- | --- | --- |
| C4 | A test on a missing field is "unknown", and `not unknown` stays unknown, so `selection and not filter` **fails** when the filter's field is absent. AND returns the first non-true value left to right; OR is true if any branch is true, else false if any is false, else unknown. | S25 | 8 / 0 | 88 / 16 | `backend-bug` (engine); S25 confirmed `clear` (Nik, 2026-11-23) |
| C5 | `field: null` matches only an explicit JSON null, not a missing field | S24 | 2 / 0 | 118 / 0 | `spec-gap` |
| C6 | Rule string `'true'` does not match a boolean event value | S11, S39 | 0 / 0 | 10 / 10 | `spec-gap` |
| C8 | Rule number `3389` does not match string event value `'3389'` | S11 | 0 / 0 | 4 / 4 | `spec-gap` |
| C1 | Only fields listed in the mapping file are reachable (`SourceUser`, `IpPort`, `FilterOrigin` and others are missing) | (config) | 0 / 0 | 13 / 13 | `config` |
| C1&C4 | An unmapped field inside a negated filter (LSASS-dump rule in regression, Kerberos relay over LDAP in attack samples) | S25 | 1 / 1 | 1 / 1 | `backend-bug` |
| C1+C2 | RedSun rule: field `Source Name` is neither mapped nor space-stripped | S85 | 1 / 1 | 0 / 0 | `config` |
| C1+C3 | WMI rule on a `<UserData>` field, which is neither mapped nor reachable | S86 | 1 / 1 | 0 / 0 | `spec-gap` |
| C7 | Production logsource preconditions by Provider and EventID: `service: security` requires provider Security-Auditing, so 1102 "audit log cleared" (written by provider Eventlog) never fires | S37 | 0 / 0 | 0 / 24 | `config` |
| C9 | Production: rules listed by title under `exclusions` in the mapping never run ("WMI Event Subscription") | (config) | 0 / 0 | 0 / 14 | `config` |
| (load) | Rules with `cidr`, `fieldref` or keyword lists are rejected at load time | S10, S17, S20 | 29 rules | 29 rules | not compared |

C5 is large in the neutral config only: 114 of its 118 pairs are the unsigned-DLL image-load rule firing on Sysmon process, registry and file events, which have no `Signed` field. With logsource applied, those events are out of scope for the rule and the pairs disappear. C4 is the one that survives logsource: 16 LSASS-dump detections (`proc_access_win_lsass_memdump`) that Chainsaw misses on real attack data.

### Hayabusa 4.4.0

| Mechanism | What Hayabusa does | Clauses | Regression | Attack samples | Label |
| --- | --- | --- | --- | --- | --- |
| H1 | Trims leading and trailing spaces from event values: `LogonProcessName: 'NtLmSsp '` (as Windows writes it, with a trailing space) matches the rule value `NtLmSsp` | S3, S45 | 0 / 0 | 2 / 2 | `backend-bug` (engine) |
| H2 | Events without a Channel (ETW-sourced EVTX) are not evaluated | S36 | 0 / 0 | 2 / 0 | `config` |
| H3 | Raw SigmaHQ rules: field names with spaces are not stripped; the converter adds the renames | S85 | 1 / 0 | 0 / 0 | `config` |
| H4 | PowerShell classic 400/403/600/800: the Key=Value text in `Data` is split into fields (`CommandLine`, `HostApplication`, ...); ported from `src/detections/field_extract.rs` | S87 | 0 / 0 | 4 / 0 | `spec-gap` |

In production, Hayabusa differs from the evaluator on exactly 2 pairs, both H1.

Full per-pair tables: `results/phase2/<dataset>/explained.json`; per-rule match sets: `disagreements.json`.

## 4. What this means for the study

1. **The oracle is trustworthy for Phase 3.** Two independent Sigma engines with their own parsers agree with it on 99.4% to 100% of rules on real attack data, and every difference is a known, reproducible engine behaviour. A pySigma parsing bug would have shown up as evaluator-vs-native disagreement; none did.
2. **The clause list was still incomplete, and the cross-check is how it gets completed.** S85 to S87 came from real data, not from reading the spec. Expect more of these when Phase 3 adds synthetic events.
3. **Missing-field negation is the biggest real-world gap so far.** Chainsaw drops true positives whenever a filter field is absent: 16 LSASS-dump detections (`proc_access_win_lsass_memdump`) on the attack samples in production config. ES|QL documents the same pattern: `field != "value"` also excludes events where the field is null ([ES|QL WHERE](https://www.elastic.co/docs/reference/query-languages/esql/commands/where)). This makes it a priority area for Phase 3 (taxonomy T4.3, negation over a missing field).
4. **`null` versus missing (S24) and string-versus-typed values (S11, S39) are the largest spec gaps** in volume (118 and 14 pairs in the neutral config). They are reported as spec clarifications, not bugs, as decided.
5. **A spec-faithful engine can miss what the rule author meant.** The Pass-the-Hash rule expects `NtLmSsp`, but Windows writes `NtLmSsp ` with a trailing space. Hayabusa matches only because it trims values (H1, against the spec); the evaluator and Chainsaw miss it. This is a rule-quality finding for SigmaHQ as well as an engine deviation.

### Decision: S25 stays `clear` (Nik, 2026-11-23)

The spec never says in words what a missing field means (S25's source is "implied"), so Chainsaw's C4 behaviour could have been read as a spec gap. It stays a `backend-bug` because the spec defines the condition language only as "Logical AND/OR" and "Negation with 'not'", with no third truth value. Under two-valued logic, `not X` is the complement of `X`. Chainsaw breaks that: on the Mimikatz event (`sysmon_3_10_Invoke-Mimikatz_hosted_Github.evtx#10273`, no `SourceUser`), probe rules show that both `filter` and `not filter` are false. The spec also treats optional fields as normal (Field Existence section), and its own example of the pattern is `selection and not filter`. Expected in Phase 3: SQL-style backends may show the same behaviour; this is a guess until measured.

### Limits

- Correlation rules and global filters are not implemented yet (no in-scope SigmaHQ rules use them). They come with the Phase 3 synthetic cases.
- Both datasets are mostly Sysmon and Security logs from lab machines; categories with few events (for example `ps_classic_*`, `dns_query`) are lightly tested.
- The native engines' behaviour was emulated from probes and source reading; the emulation is checked against the engines' real output pair by pair, but it is not a full model of either engine.

## 5. Mechanism reference

### What a mechanism is

A **mechanism** is one specific, repeatable way a native engine behaves differently from the reference evaluator. Example: "Chainsaw only reads fields listed in its mapping file". Each one has a code (C for Chainsaw, H for Hayabusa), and each one is written as a switch in `harness/explain.py`. Turned on, the switch makes the evaluator behave the way the engine does on that point, and nowhere else.

### Why we need them

Counting disagreements isn't enough. For a paper and for upstream reports, every disagreement needs a cause and a verdict. Mechanisms give us three things:

1. **Evidence of the cause.** A mechanism explains a disagreement only if switching it on in the evaluator reproduces the engine's exact answer for that (rule, event) pair. It isn't enough that the cause looks plausible. With all mechanisms on, the evaluator reproduces both engines on every one of the 343 pairs.
2. **A check on the oracle.** A disagreement that no mechanism can reproduce points to a bug in the evaluator itself. That's how the two `oracle-bug`s in section 3 were found.
3. **The label.** Each mechanism names the spec clause(s) the engine departs from. The clause's status and readings in [spec-clauses.md](spec-clauses.md) then set the label, using the rule Nik signed off (decision 5 in `docs/plan.md`, made precise on 27 and 28 Nov 2026):

| The mechanism departs from... | Label | Meaning |
| --- | --- | --- |
| a `silent` clause | `spec-gap` | The spec has no text on the question, so nothing makes the engine wrong. Reported as a proposed spec clarification. |
| an `ambiguous` or `contradictory` clause, and the engine follows one of its readings | `spec-gap` | The spec's text allows more than one reading. Reported as a proposed spec clarification, not as an engine bug. |
| an `ambiguous` or `contradictory` clause, but the engine is wrong under every reading | `config` or `backend-bug`, as for a clear clause | The open clause does not excuse the result. The mechanism records what it breaks (`breaks`). |
| a `clear` clause, through engine logic | `backend-bug` | The engine gets a clearly specified behaviour wrong. |
| no clause: only the engine's mapping, config or ingest | `config` | The setup that ships with the engine, not the matching logic. It can usually be fixed by configuration. |

The rules are applied in this order, which is the cautious one (`label()` in `harness/explain.py`). If any mechanism that explains the pair depends on an open clause and breaks neither a clear clause nor every reading of an open one, the pair is a `spec-gap`. Otherwise, if one explanation uses only config mechanisms, it is `config`. Otherwise it is a `backend-bug`. `A&B` means both mechanisms are needed together; `A+B` means either one alone explains the pair. For example, `C1&C4` is a `backend-bug` (C4 is engine logic against a clear clause), and `C1+C3` is a `spec-gap` (C3 turns on the silent S86).

The taxonomy area of each mechanism is listed in [taxonomy.md](taxonomy.md), section 7.

### Summary table

| Code | Engine | One-line behaviour | Spec clause(s) | Clause status | Label |
| --- | --- | --- | --- | --- | --- |
| C1 | Chainsaw | Only fields listed in the mapping file can be matched | none | | `config` |
| C2 | Chainsaw | Spaces in event field names are not stripped | S85 | clear | `config` (the mapping can rename) |
| C3 | Chainsaw | `<UserData>` fields can't be reached | S86 | silent | `spec-gap` |
| C4 | Chainsaw | A missing field makes `not` "unknown", so the rule fails | S25 | clear | `backend-bug` |
| C5 | Chainsaw | `field: null` matches only an explicit null, not a missing field | S24 | ambiguous, left to the SIEM; follows S24.b | `spec-gap` |
| C6 | Chainsaw | Rule string `'true'` doesn't match boolean `true` | S11, S39 | ambiguous, contradictory; right under S39.c | `spec-gap` |
| C7 | Chainsaw | Its own logsource-to-event table (production only) | S37 | clear; breaks it | `config` |
| C8 | Chainsaw | Rule number `3389` doesn't match string `'3389'` | S11 | ambiguous; right under S11.c | `spec-gap` |
| C9 | Chainsaw | Rules excluded by title in the mapping file (production only) | none | | `config` |
| H1 | Hayabusa | Trims spaces from event values | S3, S45 | clear | `backend-bug` |
| H2 | Hayabusa | Skips events without a `Channel` | S36 | (neutral config only) | `config` |
| H3 | Hayabusa | Raw SigmaHQ rules: spaces in field names not stripped | S85 | clear | `config` (its converter fixes it) |
| H4 | Hayabusa | Splits PowerShell classic `Data` text into fields | S87 | silent | `spec-gap` |

### Each mechanism, with a real example

Each example is a (rule, event) pair from our results. "Spec" is the evaluator's answer.

#### C1: only mapped fields are reachable (`config`)

- **What Chainsaw does:** it reads an event field only if the mapping file `sigma-event-logs-all.yml` lists it. A rule condition on any other field behaves as if the field were missing.
- **Spec:** no clause covers this. Field access is part of how the engine is deployed.
- **Example:** `win_esent_ntdsutil_abuse` (`Provider_Name: ESENT`, `EventID: 326`, `Data|contains: 'ntds.dit'`) on `dc_applog_ntdsutil_dfir_325_326_327.evtx#1969`, an ESENT event whose `Data` contains `...\Windows\NTDS\ntds.dit`. Spec: match. Chainsaw: no match, because `Data` isn't in the mapping. Other unmapped fields seen: `SourceUser`, `IpPort`, `FilterOrigin`, `Operation`, `SourceName`.
- **Pairs:** 13 on the attack samples, plus 4 in combination with other mechanisms.

#### C2: field names with spaces (`config`)

- **What Chainsaw does:** event field names are used as written. Defender writes `Source Name`, but the rule says `SourceName`.
- **Spec:** S85 (clear). Rule field names are the log's names "with all spaces stripped".
- **Example:** `win_defender_exploit_redsun_tiering_engine_detected_as_eicar` on the Defender 1119 event in its regression test. Spec: match. Chainsaw: no match. This pair is `C1+C2`: the field is also unmapped, and either cause alone explains it.
- **Label reason:** a mapping entry `Source Name → SourceName` fixes it, so it's a deployment fix, not a logic bug.

#### C3: `<UserData>` is not reachable (`spec-gap`)

- **What Chainsaw does:** its mapping points every field at `Event.EventData.*`. Events that carry their payload in `<UserData>` (WMI-Activity 5858, some Task Scheduler and AppLocker events) have no reachable fields.
- **Spec:** S86 (ambiguous). The spec only describes `<EventData>` `Data Name` fields.
- **Example:** `win_wmi_activity_nteventlogfile_cleareventlog` (`EventID: 5858`, `Operation|contains|all: Win32_NTEventlogFile, cleareventlog`) on its regression event, where `Operation` is `...Win32_NTEventlogFile...::cleareventlog` inside `<UserData>`. Spec: match. Chainsaw: no match. This is Chainsaw's only failed regression test besides RedSun.

#### C4: three-valued negation over a missing field (`backend-bug`)

- **What Chainsaw does:** a test on a missing field is "unknown" rather than false, and `not unknown` stays unknown. So `selection and not filter` fails whenever the filter's field is missing. AND returns the first non-true value, left to right. OR is true if any branch is true, else false if any is false, else unknown. A top-level unknown means no match. This was pinned down with 15 probe rules (`tests/test_chainsaw_semantics.py`).
- **Spec:** S25 (clear, confirmed by Nik on 2026-11-23). A missing field never matches, so `not filter` is true.
- **Example:** `proc_access_win_lsass_memdump` on `sysmon_3_10_Invoke-Mimikatz_hosted_Github.evtx#10273`, where `powershell.exe` opens `lsass.exe` with `0x143a` and the event has no `SourceUser`. Spec and Hayabusa: match. Chainsaw: no match, on all 16 LSASS dumps in the attack samples. The full case is in section 4.
- **Second example (neutral config):** `proc_creation_win_powershell_non_interactive_execution` on a Sysmon registry event from `powershell.exe`. The event has no `ParentImage`, so the filters can't match. Spec: match, because logsource isn't checked in the neutral config. Chainsaw: no match.

#### C5: `null` means explicit null only (`spec-gap`)

- **What Chainsaw does:** `field: null` matches only when the field is present with a JSON null value. A missing field doesn't count.
- **Spec:** S24 (ambiguous by design). The spec says null handling "depends on the target SIEM". Our working reading is "absent or JSON null".
- **Example:** `registry_set_taskcache_entry` has `filter_main_null: Details: null`, run on a Sysmon 12 `DeleteValue` event under `...\Schedule\TaskCache\Tree\MaliciousTask\Index`, which has no `Details` field. Spec: the null filter matches, so no alert. Chainsaw: the filter doesn't match, so it alerts. Note the direction: here Chainsaw fires and the spec doesn't.
- **Volume note:** 114 of the 118 attack-sample pairs are `image_load_susp_unsigned_dll` firing on non-image-load events, which have no `Signed` field. They disappear once logsource is applied.

#### C6: string `'true'` vs boolean `true` (`spec-gap`)

- **What Chainsaw does:** compares by type. The rule's string `'true'` doesn't equal the event's boolean `true`.
- **Spec:** S11 (ambiguous) and S39 (contradictory). YAML types the value, but the spec also says "all values are treated as strings". Our reading compares as strings.
- **Example:** `net_connection_win_certutil_initiated_connection` (`Initiated: 'true'`) on `panache_sysmon_vs_EDRTestingScript.evtx#4981`, where `certutil.exe` connects to port 443 with `Initiated: true` (boolean). Spec: match. Chainsaw: no match.

#### C7: Chainsaw's own logsource table (`config`, production only)

- **What Chainsaw does:** in production, a rule only runs on events that pass Chainsaw's preconditions for its logsource. `service: security` requires provider `Microsoft-Windows-Security-Auditing`, and categories it doesn't list run on every event.
- **Spec:** S37 (clear). The taxonomy appendix maps categories and services to Channel and EventID, not to a Provider, so Chainsaw's provider precondition breaks it, and the label is `config`: the precondition is in Chainsaw's mapping file. Its other part, accepting Security 4688 for `process_creation`, goes beyond the appendix table too, but it explains no pair here.
- **Example:** `win_security_audit_log_cleared` (`EventID: 1102`, `Provider_Name: Microsoft-Windows-Eventlog`) on `DE_RDP_Tunnel_5156.evtx#227693`, a real 1102 "audit log cleared" event in the Security channel. Windows writes 1102 under provider `Microsoft-Windows-Eventlog`, so Chainsaw's precondition (`Security-Auditing`) never lets it through. Spec: match. Chainsaw: no match, on all 24 such events. The rule itself names the right provider, so Chainsaw's table is stricter than the rule.

#### C8: number vs numeric string (`spec-gap`)

- **What Chainsaw does:** the rule's integer `3389` doesn't equal the event's string `"3389"`.
- **Spec:** S11 (ambiguous). Our reading compares as strings.
- **Example:** `win_security_rdp_reverse_tunnel` (`DestPort: 3389`, `SourceAddress: '127.*'`) on `DE_RDP_Tunnel_5156.evtx#227727`, where `plink.exe` connects from 127.0.0.1 to 127.0.0.2:3389. Security 5156 writes ports as strings. Spec: match. Chainsaw: no match.

#### C9: rules excluded by title (`config`, production only)

- **What Chainsaw does:** the mapping file's `exclusions` list disables rules by title. Presumably that's for noise, but this is a guess, because the file gives no reason.
- **Spec:** no clause. It's the shipped configuration.
- **Example:** `sysmon_wmi_event_subscription` ("WMI Event Subscription") never runs in Chainsaw's production config. That accounts for 14 attack-sample events.

#### H1: values are trimmed (`backend-bug`)

- **What Hayabusa does:** strips leading and trailing spaces from event values before matching.
- **Spec:** S3 and S45 (clear). A plain value must equal the whole field, and spaces are part of the value.
- **Example:** `win_security_pass_the_hash_2` (`LogonProcessName: 'NtLmSsp'`) on `ImpersonateUser-via local Pass The Hash Sysmon and Security.evtx#321446`. Windows writes `LogonProcessName: "NtLmSsp "` with a trailing space. Spec and Chainsaw: no match. Hayabusa: match. The engine deviates from the spec, but the outcome is the one the rule author intended, so this is also a rule-quality finding for SigmaHQ.

#### H2: events without a Channel are skipped (`config`, neutral only)

- **What Hayabusa does:** ignores events that have no `Channel`. These come from ETW-sourced EVTX files.
- **Spec:** S36. In the neutral config every event is in scope.
- **Example:** `sysmon_config_modification` (`EventID: 16`) on `CA_PetiPotam_etw_rpc_efsr_5_6.evtx#22545`, an RPC ETW event with EventID 16 and no Channel. Spec (neutral): match. Hayabusa: not evaluated. With logsource applied, the spec agrees with Hayabusa.

#### H3: raw rules and spaces in field names (`config`, neutral only)

- **What Hayabusa does:** the same as C2 when it runs raw SigmaHQ rules. Hayabusa's own rule converter adds the renames, so production (converted) rules are fine.
- **Example:** the RedSun rule on its regression event. Neutral: no match. Production: match.

#### H4: PowerShell classic `Data` is split into fields (`spec-gap`, neutral only)

- **What Hayabusa does:** for PowerShell classic events 400, 403, 600 and 800, it splits the `Key=Value` lines inside the unnamed `Data` text into fields such as `CommandLine` and `HostApplication`. This is ported from Hayabusa's `src/detections/field_extract.rs`.
- **Spec:** S87 (silent). The spec doesn't describe unnamed `<Data>` at all. Our reference choice makes it one multi-valued field `Data` and doesn't parse its contents; Hayabusa's parsing of the `Key=Value` lines is another answer to the same open question. Nothing in the spec makes either one wrong, so the label is `spec-gap`. It shows only in the neutral config, where a `process_creation` rule also runs on PowerShell events.
- **Example:** `proc_creation_win_powershell_token_obfuscation` (`CommandLine|re: ...`) on `exec_emotet_ps_800_get-item.evtx#789`, an Emotet PowerShell 800 event with an obfuscated command line inside `Data`. Spec: no `CommandLine` field, so no match. Hayabusa: match, on the extracted `CommandLine`.
