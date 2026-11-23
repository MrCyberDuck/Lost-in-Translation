# Phase 1: testbed (gate passed 23 Nov 2026)

**Gate:** all 8 targets return exactly the expected event on the 3-event smoke test, and the run manifest records versions. Passed on a 4-core, 15 GB Linux cloud machine: wave A in run `smoke_20261123t104456`, wave B in run `smoke_20261123t104552` (folders under `results/runs/`).

## Run it

```bash
python -m venv .venv && . .venv/bin/activate        # Windows: .venv\Scripts\activate
pip install -r requirements.lock
git submodule update --init rules/sigma

docker compose -f compose/wave-a.yml up -d           # Elasticsearch, OpenSearch, Loki
python -m harness.smoke --wave a
docker compose -f compose/wave-a.yml down -v

docker compose -f compose/wave-b.yml up -d           # Splunk, Kusto emulator (Splunk needs ~1 min)
python -m harness.smoke --wave b
docker compose -f compose/wave-b.yml down -v
```

`python -m harness.smoke --case <folder>` runs any single conformance case (a folder with `rule.yml`, `events.jsonl`, `expected.json`) on the same engines.

## Measured memory (idle after the smoke test)

| Container | Limit | Used |
| --- | --- | --- |
| Elasticsearch 9.5.5 | 2 GB | 1.44 GB |
| OpenSearch 3.10.0 | 1.5 GB | 1.16 GB |
| Loki 3.6.22 | 0.5 GB | 0.08 GB |
| Splunk 10.6.2 | 2.5 GB | 1.74 GB |
| Kusto emulator | 3 GB | 0.58 GB |

Total with all five running: about 5 GB, so on a 16 GB laptop both waves can run together for small cases. Keep the two-wave split for full-corpus runs. On Windows, cap WSL2 in `%UserProfile%\.wslconfig`:

```ini
[wsl2]
memory=11GB
processors=6
swap=4GB
```

## How each engine stores events (neutral configuration)

| Engine | Storage | Notable choice |
| --- | --- | --- |
| Elasticsearch / OpenSearch | one index per dataset, every string a `keyword` (no length cut-off) | `keyword` is exact and case-sensitive |
| Splunk | one index per dataset, HEC, sourcetype `_json` | fields extracted at search time |
| Kusto | one table per dataset, typed columns, inline CSV ingest | missing fields become empty strings |
| Loki | one JSON log line per event, label `lit_dataset` | backend stream selector replaced by the dataset label |
| SQLite | one `logs` table per dataset, untyped | REGEXP = Python `re.search`, as Zircolite |

Each run writes these notes into its `manifest.json`.

## Problems met

- Docker Hub rate-limits anonymous pulls from shared cloud IPs (HTTP 429). Pull through `mirror.gcr.io/...` or `public.ecr.aws/...` and retag, or `docker login` first.
- `docker.elastic.co` was blocked by this cloud machine's network policy; the same image is published on Docker Hub as `elasticsearch:9.5.5`, which the compose file uses.
- The EQL search API rejects a JSON `null` for `filter_path`; fixed in the adapter.

## First deviation seen (preliminary)

Case `conformance/T1-case/T1-001-upper-image`: the smoke rule against upper-case and mixed-case versions of the same event. Sigma says values are case-insensitive, so all 3 events should match.

| Target | Matched |
| --- | --- |
| splunk, eql, kusto, loki, sqlite | 3 of 3 |
| lucene, esql, opensearch_lucene | 1 of 3 (only the lower-case event) |

This is with the neutral `keyword` mapping and no pipeline, so it is not yet attributed: the cause may be the converter (no case-insensitive query), the mapping (no lower-case normaliser), or both. Attribution is Phase 3 and Phase 5 work. Run: `results/runs/T1_001_upper_image_20261123t104642/`.

## Two more seed cases from real SigmaHQ rules (preliminary)

Both were first spotted in the explainer demo (`/mnt/project-files/demo-2026-11-23/`) and reproduced here with the testbed.

| Case | Expected | Deviating targets | Observation |
| --- | --- | --- | --- |
| `T9-logic/T9-001-whoami-all` (SigmaHQ `c248c896`) | w1, w2, w3 | lucene, esql, opensearch_lucene: miss `whoami /ALL` (w2). loki: also matches `cmd.exe /c dir /all` (w5) | Loki output has no brackets around the `Image`/`OriginalFileName` OR group, so `and` binds first. A converter bug candidate. |
| `T5-types/T5-001-eventid-integer` (SigmaHQ `66b6be3d`) | u1 | eql: query rejected (HTTP 400) | EQL's `:` operator only accepts strings; `EventID` is a long. Any integer field rule fails in the neutral config. |

Runs: `results/runs/T9_001_whoami_all_20261123t110035/`, `results/runs/T5_001_eventid_integer_20261123t110055/`.
