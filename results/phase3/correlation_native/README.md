# Correlation support of the native engines (Phase 3 step 1, 26 Nov 2026)

Checks the two open entries in the Phase 3 plan's correlation column. Versions: results/phase3/frozen_versions.json.

## Zircolite 4.8.0: converts and runs correlation

`zircolite_rule.yml` is an `event_count` rule (3 or more failed logons per `TargetUserName` in 5 minutes) over a base rule. `zircolite_events.jsonl` has 3 events for `bob` and 2 for `eve`.

    python zircolite.py -e zircolite_events.jsonl -j -r zircolite_rule.yml -o out.json --no-event-filter

Result: one correlation alert, for `bob`, with `event_count` 3 and a window of 5 minutes ending at the last event. `eve` gets none.

## Chainsaw 2.18.0: ignores correlation without an error

`chainsaw_base.yml` (EventID 4625) and `chainsaw_correlation.yml` (`event_count` of it per `TargetUserName`, `gte: 1`) were run with the neutral mapping (`harness.native.neutral_mapping`) on `EVTX-ATTACK-SAMPLES/Credential Access/CA_4624_4625_LogonType2_LogonProc_chrome.evtx`, which has one 4625 event.

    chainsaw lint --kind sigma chainsaw_correlation.yml            # "Validated 1 detection rules out of 1"
    chainsaw hunt <evtx> -s chainsaw_base.yml --mapping neutral.yml --json -q          # 1 hit
    chainsaw hunt <evtx> -s chainsaw_correlation.yml --mapping neutral.yml --json -q   # no output, exit 0

Chainsaw validates the correlation rule and then never fires it. The Chainsaw 2.18.0 source has no reference to correlation. Spec clause S78 requires an error for a rule a backend cannot support, so this silent drop is a T11 candidate for the conformance cases.
