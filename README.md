# Lost in Translation

Differential testing of Sigma rule backends: does the same SigmaHQ rule detect the same events on every SIEM it is converted for?

Sigma rules are converted by pySigma backends (and native Sigma engines) into SPL, Lucene, ES|QL, EQL, KQL, LogQL, SQL and more. Each converter and engine makes its own choices about case, wildcards, backslashes, nulls, CIDR, regex dialect, list logic, field mapping and correlation windows. This project measures how often those choices make one rule match different events on different engines, classifies why, and turns the cases into a reusable conformance suite.

## Status

Planning. The full research plan (backends, testbed, datasets, taxonomy, seed test cases, timeline) is in [docs/plan.md](docs/plan.md).

## Repository layout (planned)

| Path | Contents |
| --- | --- |
| `docs/` | Plan, decisions, spec-clause list, write-up drafts |
| `compose/` | Docker Compose files for the local engines (wave A and wave B) |
| `rules/` | SigmaHQ rules, pinned to a release tag (git submodule) |
| `events/` | Event manifests and generated events (large public datasets are fetched, not committed) |
| `harness/` | Converters, ingest adapters, query runners, reference evaluator, comparator |
| `conformance/` | Conformance suite: small rules, events and expected verdicts per taxonomy area (T1 to T14) |
| `results/` | Run manifests (versions, image digests) and result tables |
| `findings/` | One file per confirmed deviation, with a minimal reproducer and upstream issue link |
