# Evaluator vs pySigma's built-in matcher (Phase 3 step 1, 26 Nov 2026)

pySigma 2.x ships its own matcher, `sigma.matching`, which evaluates Sigma rules on events without converting them. It is a cross-check on the reference evaluator (decision 8), not a target. This run compares the two on the Phase 2 data: the same 2,295 rules (2,247 in scope plus the rules with SigmaHQ regression data), neutral config, logsource not applied.

    python -m harness.matcher_crosscheck regression            # pySigma 2.x environment
    python -m harness.matcher_crosscheck evtx-attack-samples
    python harness/probe_matcher.py                           # minimal probes for M1 to M7

Versions: results/phase3/frozen_versions.json (pySigma 2.1.2).

## Result

| Dataset | Events | Rules compared | Agree | Differ | Pairs only evaluator | Pairs only matcher |
| --- | --- | --- | --- | --- | --- | --- |
| regression | 233 | 2,295 | 2,291 | 4 | 1 | 241 |
| EVTX-ATTACK-SAMPLES | 37,364 | 2,295 | 2,286 | 9 | 21 | 72,100 |

Neither side failed to load any rule. Every differing rule is explained by one of seven matcher mechanisms below, each reproduced by a one-line probe in `harness/probe_matcher.py`, where the evaluator gives the result the clause requires. On these rules the evaluator also agrees with Chainsaw and Hayabusa (Phase 2), so the cross-check supports the evaluator and turns up no new evaluator bug.

## Mechanisms

| ID | What sigma.matching does | Clause | Evaluator | Rules affected |
| --- | --- | --- | --- | --- |
| M1 | `*` alone (`A: '*'`, `A\|contains: '*'`) matches when the field is missing | S25 (clear) | no match | posh_pm_alternate_powershell_hosts (every event) |
| M2 | Spaces in event field names are not stripped, so `SourceName` misses `Source Name` | S85 (clear) | match | win_defender_exploit_redsun_tiering_engine_detected_as_eicar |
| M3 | `fieldref` matches when both fields are missing | S25 (clear); S20 (ambiguous on case), wrong under S20.a and S20.b | no match | file_delete_win_delete_own_image |
| M4 | `''` matches a missing field | S23, S25 (clear) | no match | create_remote_thread_win_susp_password_dumper_lsass |
| M5 | Escaped wildcards `\*` and `\?` do not match the literal character | S5 (clear) | match | proc_creation_win_susp_file_characteristics, win_security_lm_namedpipe, win_security_susp_psexec, win_security_dce_rpc_smb_spoolss_named_pipe |
| M6 | An integer in the rule does not match the same number as a string in the event (the reverse does match) | S11 (ambiguous), right under S11.c | match | win_security_rdp_reverse_tunnel |
| M7 | A list-valued field is matched against its JSON text, so `\\` in the rule matches one backslash in the value | S5 (clear); S44 and S87 (ambiguous), wrong under S44.a to S44.c and S87.a to S87.c | no match | win_msi_install_from_susp_locations |

## Labels

The labels come from `python -m harness.matcher_labels`, which applies `harness.triage.classify` to each mechanism's clauses and recorded readings. M6 is right under one reading of S11 (S11.c: an integer matches only an integer-typed value), so it is `spec-gap`. M1, M2, M4 and M5 contradict clear clauses. M3 and M7 also touch open clauses, but they are wrong under every reading of them (S20 for M3; S44 and S87 for M7). These six are `backend-bug` candidates against pySigma's `sigma.matching`. They are not reported yet: like every finding, they first have to meet the reporting bar in Phase 3 step 7.

Separately, pySigma 2.1.1 and 2.1.2 import `typing_extensions` in `sigma.matching` without declaring it as a dependency, so `import sigma.matching` fails in a clean environment. `requirements-2x.lock` pins it by hand.
