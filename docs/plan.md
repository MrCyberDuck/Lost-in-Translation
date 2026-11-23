# Research plan

The living plan is kept as a Claude Doc: "Sigma Backend Differential Testing: Testbed & Test Plan" (https://claude.ai/artifact/RZuxYLmZjDmLhBMzFfNeEV). A Markdown snapshot will be added here once the plan is signed off.

## Decisions (23 Nov 2026)

1. **Headline:** no single SIEM pair. Compare as many free backends as budget allows and report every deviation. The Microsoft Sentinel trial is a final validation step only.
2. **Scope:** Windows rules only for the first paper.
3. **QRadar CE:** later, run separately at the end against the same frozen rules, events and reference verdicts.
4. **Storage:** all scripts, data manifests and findings live in this repository.
5. **Spec gaps are not backend bugs.** Any disagreement whose expected verdict depends on an ambiguous or contradictory spec clause is labelled `spec-gap` and reported as a proposed clarification to the Sigma specification, never as a backend bug. The working interpretations in `docs/spec-clauses.md` are accepted. Enforced by `harness/triage.py`; labels in `docs/triage-labels.md`.
6. **No upstream bug reports before Phase 3.** Findings are collected until Phase 3, re-verified there in more detail, and reported upstream all at once.

## Core targets

| Engine | Query language(s) | Converter |
| --- | --- | --- |
| Splunk Enterprise (trial, then Free) | SPL | pySigma splunk |
| Elasticsearch (Basic) | Lucene, ES\|QL, EQL | pySigma elasticsearch |
| OpenSearch | Lucene | pySigma opensearch |
| Kusto emulator + Azure Data Explorer free cluster | KQL | pySigma kusto |
| Grafana Loki | LogQL | pySigma loki |
| SQLite / Zircolite | SQL | pySigma sqlite |
| Hayabusa, Chainsaw | native Sigma | own parsers |
| Reference evaluator (this repo) | Sigma spec v2 | oracle |

## Timeline

Start 30 Nov 2026, finish around 2 May 2027, slack to mid-May 2027.
