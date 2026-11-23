# Phase 0: scoping (done 23 Nov 2026)

## Pins

| Item | Pinned to |
| --- | --- |
| SigmaHQ rules | tag `r2026-07-01`, commit `552f3fee420ef232a8e5790c4fae591847e32347`, as the git submodule `rules/sigma` |
| Sigma specification | `SigmaHQ/sigma-specification` commit `ba9251aa834b11a70dbf80836b453dba99c5159e` (rules spec v2.1.0, modifiers appendix v2.1.0) |
| pySigma and backends | `requirements.lock`: pySigma 1.5.1, sigma-cli 3.1.0, splunk 2.1.0, elasticsearch 2.1.1, opensearch 2.0.3, kusto 1.0.1, loki 0.15.1, sqlite 2.0.0 |
| Engine images | see `compose/`: Elasticsearch 9.5.5, OpenSearch 3.10.0, Loki 3.6.22, Splunk 10.6.2, Kusto emulator `latest` (its image id is recorded per run) |

`r2026-07-01` was the newest SigmaHQ release tag on 23 Nov 2026.

## In-scope rules

`python -m harness.select_rules` writes `results/phase0/inscope_rules.jsonl` and `results/phase0/rule_counts.json`.

| Count | Rules |
| --- | --- |
| Rule files in `rules/` | 3,142 |
| Windows rules | 2,403 |
| Windows rules with status `stable` or `test` (**in scope**) | **2,247** |
| Parse errors | 0 |

Largest logsource groups in scope: `process_creation` 1,095, `registry_set` 190, `ps_script` 158, `file_event` 151, Security log 140, `image_load` 91.

## Findings from scoping that change the plan

1. **SigmaHQ ships no correlation rules** at this tag. Correlation (taxonomy T11) is therefore tested only with synthetic cases in the conformance suite, and the headline rule-level numbers cover single-event rules only.
2. **Regression data comes as EVTX and JSON.** `rules/sigma/regression_data` holds 197 EVTX files, each with a JSON dump and an `info.yml` stating the expected match count. The JSON can be flattened directly (`harness/events.py: from_evtx_json`), so no EVTX parser is needed for Phase 2's cross-check.
3. **Five pySigma targets require a processing pipeline by default** (`lucene`, `esql`, `eql`, `opensearch_lucene`, `splunk`). The neutral configuration calls the backends without one, which `sigma convert --without-pipeline` also allows.

## Spec clauses

See [spec-clauses.md](spec-clauses.md): 35 clauses, of which 13 are ambiguous and carry a working interpretation. Four of them (keywords, integer comparison, null, correlation windows) need agreement with the co-author before Phase 2 ends.
