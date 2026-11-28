# Proposed clarifications to the Sigma specification

Every `spec-gap` finding ends here: a clause the spec leaves open or contradicts, what the implementations we test do with it, and the wording we would propose. These are material for the reports after Phase 3 and for the paper. Nothing here has been sent. Nik decides what goes to the Sigma maintainers and does all communication with them.

Spec text is quoted from [SigmaHQ/sigma-specification](https://github.com/SigmaHQ/sigma-specification) at commit `ba9251aa834b11a70dbf80836b453dba99c5159e`, the version the clause list uses ([spec-clauses.md](spec-clauses.md)). Tool versions are the frozen ones in `results/phase3/frozen_versions.json`.

## SC1. Range conditions in correlation rules (S34)

**Status:** contradictory (Nik, 27 Nov 2026). Draft, not sent.

**What the spec says.** The Condition section of the correlation specification says two things that cannot both hold.

- Line 327: "It is a map of exactly one condition criterion:", followed by the six operators `gt`, `gte`, `lt`, `lte`, `eq` and `neq`.
- Lines 343 to 351: "To define a range, you can use the conjunction 'AND' in the mapping.", with the example "101 to 200": `gt: 100` and `lte: 200`, a map with two criteria.

The JSON schema (`sigma-correlation-rules-schema.json`) does not settle it. Its `maxItems: 3` on the condition suggests that two operators plus `field` were meant, but the keyword has no effect, and the schema accepts any condition at all (SC2).

**What the implementations do.** Case C08 in the [correlation cross-check](../results/phase3/correlation_crosscheck/README.md) uses `event_count` with `gt: 1` and `lte: 2`. In it, bob has 2 events and eve has 3.

| Implementation | Reading | Result on C08 | Mechanism |
| --- | --- | --- | --- |
| Reference evaluator | Range: every criterion must hold | fires for bob | S34 working interpretation |
| pySigma 1.5.1 and 2.1.2 | Exactly one criterion | refuses the rule with an error | P1 |
| sigma.matching (pySigma 2.1.2) | Exactly one criterion, through pySigma | refuses the rule with an error | P1 |
| Zircolite 4.8.0 (pySigma-backend-sqlite 2.2.0) | Exactly one criterion, through pySigma | refuses the rule with an error | P1 |
| Hayabusa 4.4.0 | Neither: keeps the first operator it finds | fires for bob and eve, silently | H7 |

Two details matter for the proposal.

1. **pySigma fails in its rule parser, not in a backend.** `SigmaCorrelationCondition.from_dict` in `sigma/correlations.py` counts the operator keys and raises `SigmaCorrelationConditionError` when there is not exactly one (pySigma 2.1.2 lines 119 to 123; the same check is at line 121 in 1.5.1). Every pySigma backend parses rules through this code, so every one of them (Splunk, Elasticsearch, the SQLite backend behind Zircolite, sigma.matching, and the rest) refuses a range rule before converting anything. The behaviour is the same across the whole pySigma ecosystem, and it is pySigma's, not each backend's.
2. **The refusal is loud.** pySigma produces no query and raises "Sigma correlation condition must have exactly one condition item". The user knows the rule did not convert. That is allowed: the Compatibility section requires an error, not a silent conversion, for a feature a tool cannot support (S78). Hayabusa is the opposite case. It accepts the rule without a warning and keeps only `gt: 1` (`process_condition_pairs` in `src/detections/rule/correlation_parser.rs` returns on the first operator), so it fires for eve's 3 events, which is wrong under both readings of the spec.

**Impact.** A rule author who follows the spec's own range example gets a loud refusal on every pySigma backend and a silent over-match on Hayabusa. The SigmaHQ rule repository has no correlation rules at all at the commit we use (`552f3fee4`, 9 Jul 2026), so the impact today is on custom rules and on correlation rules SigmaHQ adds later.

**Proposed clarification.** We propose keeping ranges, because the spec already shows one, the schema's `maxItems: 3` suggests it was meant, and a range is hard to express otherwise (the alternative is chaining two correlations).

- Replace "It is a map of exactly one condition criterion:" with "It is a map of one or more condition criteria. All of them must hold:".
- Keep the "101 to 200" example.
- Add: "A tool that cannot apply every criterion must raise an error rather than apply only some of them", in line with the Compatibility section.
- Fix the JSON schema's `condition` so that it enforces this (SC2).

The other way to resolve it is to forbid ranges: delete the range paragraph and its example, and set `maxProperties` to 1, or 2 for `value_count` with `field`. That matches pySigma today, but it removes a feature the spec documents.

**Reproduce.**

- pySigma refusal, one command, either virtual environment:

  ```
  python -c "from sigma.collection import SigmaCollection; SigmaCollection.from_yaml(open('results/phase3/spec_clarifications/S34_range.yml').read())"
  ```

  Expected: `sigma.exceptions.SigmaCorrelationConditionError: Sigma correlation condition must have exactly one condition item`. Checked on pySigma 1.5.1 and 2.1.2, 27 Nov 2026.
- All targets: `python -m harness.correlation_crosscheck <target>` for `evaluator`, `matcher`, `zircolite` and `hayabusa`, then `python -m harness.correlation_crosscheck compare`, and read case C08 in `results/phase3/correlation_crosscheck/summary.json`.

## SC2. The correlation JSON schema does not check `condition` or `aliases`

**Status:** schema defect, not an open clause: the prose of the spec decides these points (except S34, see SC1), but the schema meant to check them accepts anything. Draft, not sent.

**What the schema says.** `json-schema/sigma-correlation-rules-schema.json` (draft 2020-12) has three faults. Each uses JSON Schema keywords in a place where they have no effect, so a validator ignores them without any warning.

1. **`condition`** is declared `type: object` with `minItems: 1`, `maxItems: 3` and `uniqueItems: true`. These three keywords apply only to arrays. Its `anyOf` lists entries such as `{"gt": {"type": "integer"}}`, but `gt` is not a JSON Schema keyword, so each entry is an empty schema that accepts everything. Operator names belong under `properties`.
2. **The `field` requirement** for `value_count`, `value_sum`, `value_avg` and `value_percentile` is written as `then: {condition: {...}, required: [...]}`. `condition` is not a keyword there either, so only `required` takes effect and `field` is never required. That block also types `field` as a string, while the main `field` definition and the spec (S73) allow a list.
3. **`aliases`** values are declared `type: object` with `items: {type: string}`. `items` applies only to arrays, so alias values are not checked.

**Effect.** Validated with `jsonschema` 4.23.0, the schema accepts each of these correlations: condition `{}`, `{foo: bar}`, `{gt: "x"}`, all six operators at once, a `value_count` without `field`, and an alias whose value is the number 123. A rule author or tool that relies on the schema gets no error for any of them. SigmaHQ's own CI (`.github/workflows/sigma-validation.yml`) validates rules only against the detection rule schema, so this schema is not enforced on SigmaHQ rules today; the rule repository has no correlation rules yet.

**Proposed fix.**

- `condition`: `properties` for `gt`, `gte`, `lt`, `lte`, `eq` and `neq` (integers) and `field` (a string or a list of strings), `additionalProperties: false` and `minProperties: 1`. A limit on the number of operators follows from the decision in SC1.
- The four `then` blocks: `then: {properties: {condition: {required: ["field"]}}, required: [...]}`, with no separate type for `field`.
- `aliases`: values as `type: object` with `additionalProperties: {type: string}`.

**Reproduce.** With `jsonschema` 4.23.0 installed:

```
python results/phase3/spec_clarifications/SC2_schema_check.py <sigma-specification>/json-schema/sigma-correlation-rules-schema.json
```

Expected: all six lines print `valid`. Checked 27 Nov 2026 at specification commit `ba9251a`.

## SC3. What a tool that cannot apply a global filter must do (S98)

**Status:** silent: the spec has no text on it. Working interpretation written 27 Nov 2026, waiting for Nik. Draft, not sent.

**What the spec says.** Nothing. The filters specification says that filters exist "to suppress matches of multiple rules" (line 35), but it has no compatibility rule. The correlation specification has one (S78: a backend must raise an error rather than convert a "must" feature it cannot support; S79: it should warn when it approximates a "should" feature), and the filters specification has no counterpart.

**What the implementations do.** Hayabusa 4.4.0 does not parse filter documents. It counts each one as a rule it could not parse ("Rule parsing errors: 1"), exits 0, and runs the rules the filter names without it (H15 in the [correlation cross-check](../results/phase3/correlation_crosscheck/README.md), cases C24, C25, C29, C42 and C43). The rules then match the events the filter should suppress: in C24, Hayabusa reports `adm_bob`, whom the filter excludes. pySigma and its backends do parse filters (with their own way of combining them, P3 and P4).

**Impact.** A team that tunes false positives with global filters and runs them on a tool without filter support gets the false positives back. The only sign is a parsing-error count among the start-up messages.

**Proposed clarification.** Add a compatibility rule to the filters specification, in line with S78: "A tool that cannot apply a filter must not apply the rules it names without it, or must at least warn that it did not apply the filter, naming the filter and the rules."

**Reproduce.** `python -m harness.correlation_crosscheck hayabusa`, then `compare`, and read cases C24 and C25 in `results/phase3/correlation_crosscheck/summary.json` (outcome `degraded`).

## SC4. The resolution at which timestamps are compared (S99)

**Status:** silent: the spec has no text on it. Working interpretation written 27 Nov 2026, waiting for Nik. Draft, not sent.

**What the spec says.** Nothing. The correlation specification defines `timespan` (number plus `s`, `m`, `h` or `d`) and the order of events in `temporal_ordered`, but not the resolution at which event times are compared. Windows and order both depend on it.

**What the implementations do.** Case C45 has a failure and a success 800 ns apart, in that order, for `temporal_ordered`. The evaluator compares nanoseconds and fires. sigma.matching and Hayabusa fire too. Zircolite 4.8.0 rounds timestamps to milliseconds in its SQL, so the two events tie, and under S35's working interpretation (equal timestamps are not in order) it does not fire (Z1).

**Impact.** Small for most data: Windows event times are 100 ns ticks, and sub-millisecond gaps matter mainly for events written by one process in quick succession, such as a process creation and its first network connection. It decides `temporal_ordered` results and window edges whenever two events fall in the same millisecond or second.

**Proposed clarification.** Add to Time Selection: "Event times are compared at the full resolution of the event's timestamp. A tool that compares at a coarser resolution should warn, as for other approximations." Alternatively, the spec could fix a resolution, such as milliseconds, which is what many SIEMs store.

**Reproduce.** `python -m harness.correlation_crosscheck zircolite`, then `compare`, and read case C45 in `results/phase3/correlation_crosscheck/summary.json`.

## SC5. Which string an unquoted YAML scalar becomes (S39)

**Status:** ambiguous. Narrowed by Nik on 28 Nov 2026. Draft, not sent.

**What the spec says.** Rule files "are written in yaml format", linking YAML 1.2.2 (rules specification, line 94), whose core schema types unquoted scalars: `0x10` and `010` are the integers 16 and 10, `true` is a boolean, `yes` is a string. A value may be "a string or integer value" (line 426), and "All values are treated as case-insensitive strings" (line 361). The spec does not say which string a typed scalar becomes when it is matched: its source text (`0x10`) or its value (`16`).

**What the implementations do.** pySigma, and so every pySigma backend, and the reference evaluator use the value: `Flags: 0x10` matches the event value `16`, not `0x10`. pySigma also loads rules with PyYAML, which reads YAML 1.1 rather than the 1.2.2 the spec names, so `010` becomes 8 and `yes` and `on` become `true` (checked with pySigma 1.5.1's own loader, 28 Nov 2026). Chainsaw and Hayabusa load rules with their own Rust YAML parsers; how they type these scalars is not checked yet.

**Impact.** None on SigmaHQ rules today: at commit `552f3fee4` the 976 unquoted integer values in detections are all plain decimal, and the only unquoted booleans are 4 `true`. It matters for custom rules that write hex flags, leading zeros or `yes`/`no` unquoted.

**Proposed clarification.** Add to Yaml File: "An unquoted value is matched as the string of its YAML 1.2.2 value, so `0x10` matches `16`. Quote a value to match it as written." Optionally, add the YAML version explicitly ("YAML 1.2.2, core schema") so that tools on YAML 1.1 loaders know they differ.

**Reproduce.** `python -m pytest tests/test_evaluator.py -k s39` for the evaluator, and for pySigma's loader: `python -c "import yaml; from sigma.rule.base import SigmaYAMLLoader as L; print(yaml.load('a: [010, 0x10, yes, on]', L))"`, which prints `{'a': [8, 16, True, True]}`.
