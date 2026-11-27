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
