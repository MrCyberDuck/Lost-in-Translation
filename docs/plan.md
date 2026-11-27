# Research plan

The living plan is kept as a Claude Doc: "Sigma Backend Differential Testing: Testbed & Test Plan" (https://claude.ai/artifact/RZuxYLmZjDmLhBMzFfNeEV). A Markdown snapshot will be added here once the plan is signed off.

## Decisions (23 Nov 2026)

1. **Headline:** no single SIEM pair. Compare as many free backends as budget allows and report every deviation. The Microsoft Sentinel trial is a final validation step only.
2. **Scope:** Windows rules only for the first paper.
3. **QRadar CE:** later, run separately at the end against the same frozen rules, events and reference verdicts.
4. **Storage:** all scripts, data manifests and findings live in this repository.
5. **Spec gaps are not backend bugs.** A disagreement where the target is right under at least one reading of an ambiguous or contradictory spec clause it depends on is labelled `spec-gap` and reported as a proposed clarification to the Sigma specification, never as a backend bug. Only a result that is wrong under every reading of every such clause can be a backend bug, and it records those readings (made precise on 27 Nov 2026; readings fixed in `docs/spec-clauses.md`, safeguards in `docs/triage-labels.md`). The working interpretations in `docs/spec-clauses.md` are accepted. Enforced by `harness/triage.py`; labels in `docs/triage-labels.md`.
6. **Upstream reports in two batches, sent only by Nik.** Findings are reported after Phase 3 and again after Phase 5, and only once each is re-tested on the frozen versions, explained down to the mechanism, reproducible with one command and written up with step-by-step reproduction instructions. Claude drafts the reports and recommends whom to contact; all communication with maintainers is Nik's.
7. **S25 stays clear.** A missing field never matches, so `not sel` is true; Chainsaw's three-valued negation is a `backend-bug` (Phase 2, `docs/phase2.md`).
8. **Every backend at its latest release, even across pySigma majors.** The unit under test is each converter as released (backend plus its pySigma core). Until the Elasticsearch, OpenSearch and Kusto backends support pySigma 2.x, Phase 3 uses two environments: pySigma 1.5.x for those three, pySigma 2.x for Splunk, Loki, SQLite and Zircolite. All versions are frozen on one date and recorded per run. Control: the last 1.x release of each moved backend also runs, so differences caused by the pySigma core are attributed to pySigma, not to the backend. The evaluator keeps pySigma 1.5.1 parsing; pySigma 2.x's built-in matcher (`sigma.matching`) is added as an extra cross-check.

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
