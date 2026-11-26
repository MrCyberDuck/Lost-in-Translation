"""Cross-check the evaluator's correlations and filters against three independent implementations.

Small synthetic cases, one or two per clause, run on:

* `evaluator`: harness/evaluator/collection.py (pySigma 1.x environment, requirements.lock)
* `matcher`: pySigma 2.x's built-in matcher, sigma.matching.SigmaMatcher (requirements-2x.lock)
* `zircolite`: Zircolite 4.8.0, which runs pySigma's SQLite backend correlation plans (2.x environment)
* `hayabusa`: Hayabusa 4.4.0 on the same events as JSON lines (`-J`)

    python -m harness.correlation_crosscheck evaluator      # 1.x environment
    python -m harness.correlation_crosscheck matcher        # 2.x environment
    python -m harness.correlation_crosscheck zircolite      # 2.x environment
    python -m harness.correlation_crosscheck hayabusa
    python -m harness.correlation_crosscheck compare

Each target writes results/phase3/correlation_crosscheck/<target>.json: per case, the groups each
correlation fires for (case-folded, sorted; S93 makes groups the unit of comparison), the number of
alerts, the base-rule matches after filters for rule cases, or the error. `compare` writes
summary.json and README tables are written by hand from it.

Every case uses the same rule text and the same events on every target. Base rules match on EventID
only, so the detection layer cannot differ; only correlation and filter semantics are tested.
"""
from __future__ import annotations

import argparse
import datetime as dt
import json
import os
import pathlib
import shutil
import subprocess
import sys
import tempfile
import textwrap
from dataclasses import dataclass, field

OUT = pathlib.Path("results/phase3/correlation_crosscheck")
TARGETS = ("evaluator", "matcher", "zircolite", "hayabusa")
R = {n: f"00000000-0000-4000-8000-{i:012d}" for i, n in enumerate(("failed", "success", "other", "conn_in", "conn_out"), 1)}
EID = {"failed": 4625, "success": 4624, "other": 4688, "conn_in": 5156, "conn_out": 5158}


def base(name: str) -> str:
    return textwrap.dedent(f"""\
        title: {name}
        id: {R[name]}
        name: {name}
        status: test
        author: lost-in-translation
        date: 2026-11-26
        description: base rule for the correlation cross-check
        logsource:
            product: windows
            service: security
        detection:
            sel:
                EventID: {EID[name]}
            condition: sel
        level: low
        """)


def corr(body: str, cid: str = "c1", name: str | None = None) -> str:
    head = (f"title: correlation {cid}\nid: 00000000-0000-4000-9000-{int(cid[1:]):012d}\n"
            + (f"name: {name}\n" if name else "")
            + "status: test\nauthor: lost-in-translation\ndate: 2026-11-26\ndescription: cross-check\n"
            "correlation:\n")
    return head + textwrap.indent(textwrap.dedent(body), "    ") + "level: high\n"


def cid_id(cid: str) -> str:
    return f"00000000-0000-4000-9000-{int(cid[1:]):012d}"


FILTER = textwrap.dedent("""\
    title: filter admins
    id: 00000000-0000-4000-a000-000000000001
    status: test
    author: lost-in-translation
    date: 2026-11-26
    description: global filter
    logsource:
        product: windows
        service: security
    filter:
        rules: [failed]
        sel:
            User|startswith: adm_
        condition: sel
    """)


def count(group="[User]", cond="gte: 3", span="5m", rules="[failed]", ctype="event_count", extra="") -> str:
    g = f"group-by: {group}\n" if group else ""
    c = "condition:\n" + textwrap.indent(cond, "    ") + "\n" if cond else ""
    return f"type: {ctype}\nrules: {rules}\n{g}timespan: {span}\n{c}{extra}"


@dataclass
class Case:
    id: str
    clauses: list[str]
    what: str
    docs: list[str]
    events: list[tuple]                 # (mm:ss, rule name of the EventID, {fields})
    kind: str = "corr"                  # corr: compare correlation groups; rule: compare base-rule matches
    compare: list[str] = field(default_factory=lambda: ["c1"])

    def text(self) -> str:
        return "\n---\n".join(d.rstrip("\n") for d in self.docs) + "\n"


def E(t, name="failed", **fields):
    return (t, name, fields)


def burst(user, *times, name="failed", **extra):
    return [E(t, name, User=user, **extra) for t in times]


CASES = [
    Case("C01", ["S31"], "event_count: 3 failures for bob, 2 for eve, within 5 minutes",
         [base("failed"), corr(count())], burst("bob", "00:00", "01:00", "02:00") + burst("eve", "00:00", "01:00")),
    Case("C02", ["S33"], "event_count: a burst at 04:00, 05:00, 06:00 straddles a 5-minute boundary",
         [base("failed"), corr(count())], burst("bob", "04:00", "05:00", "06:00")),
    Case("C03", ["S91"], "event_count: first and last event exactly 5 minutes apart",
         [base("failed"), corr(count())], burst("bob", "00:00", "03:00", "05:00")),
    Case("C04", ["S33"], "event_count: first and last event 5 minutes and 1 second apart",
         [base("failed"), corr(count())], burst("bob", "00:00", "03:00", "05:01")),
    Case("C05", ["S32"], "event_count: the third event has no User field",
         [base("failed"), corr(count())], burst("bob", "00:00", "01:00") + [E("02:00")]),
    Case("C30", ["S32"], "event_count gte 3: three events, none with the User field",
         [base("failed"), corr(count())], [E("00:00"), E("01:00"), E("02:00")]),
    Case("C31", ["S33"], "temporal over 3 rules, 5m: success at 00:00, failed at 05:00, other at 10:00 (10 minutes end to end)",
         [base("failed"), base("success"), base("other"),
          corr(count(rules="[failed, success, other]", ctype="temporal", cond=None))],
         [E("00:00", "success", User="bob"), E("05:00", User="bob"), E("10:00", "other", User="bob")]),
    Case("C06", ["S90"], "event_count: User is Bob, BOB and bob",
         [base("failed"), corr(count())], [E("00:00", User="Bob"), E("01:00", User="BOB"), E("02:00", User="bob")]),
    Case("C07", ["S71"], "event_count without group-by: 3 events of 3 users",
         [base("failed"), corr(count(group=None))], [E("00:00", User="a"), E("01:00", User="b"), E("02:00", User="c")]),
    Case("C08", ["S34"], "event_count range gt 1, lte 2: bob has 2 events, eve 3 at the same second",
         [base("failed"), corr(count(cond="gt: 1\nlte: 2"))], burst("bob", "00:00", "01:00") + burst("eve", "02:00", "02:00", "02:00")),
    Case("C09", ["S34"], "event_count neq 1: bob has 2 events at one second, eve 1",
         [base("failed"), corr(count(cond="neq: 1"))], burst("bob", "00:00", "00:00") + burst("eve", "00:00")),
    Case("C10", ["S72", "S90"], "value_count of User per Host, gte 3: Admin, admin, root",
         [base("failed"), corr(count(group="[Host]", ctype="value_count", cond="field: User\ngte: 3"))],
         [E("00:00", Host="h", User="Admin"), E("01:00", Host="h", User="admin"), E("02:00", Host="h", User="root")]),
    Case("C11", ["S72"], "value_count of User per Host, gte 2: one event has no User",
         [base("failed"), corr(count(group="[Host]", ctype="value_count", cond="field: User\ngte: 2"))],
         [E("00:00", Host="h", User="a"), E("01:00", Host="h")]),
    Case("C12", ["S73"], "value_count of [User, Src], gte 3: 2 users, 2 sources, 3 pairs",
         [base("failed"), corr(count(group="[Host]", ctype="value_count", cond="field: [User, Src]\ngte: 3"))],
         [E("00:00", Host="h", User="a", Src="x"), E("01:00", Host="h", User="a", Src="y"),
          E("02:00", Host="h", User="b", Src="x")]),
    Case("C13", ["S31"], "temporal: bob has a failure and a success, eve only failures",
         [base("failed"), base("success"), corr(count(rules="[failed, success]", ctype="temporal", cond=None))],
         [E("00:00", "success", User="bob"), E("01:00", User="bob"), E("00:00", User="eve"), E("01:00", User="eve")]),
    Case("C14", ["S35"], "temporal_ordered failed then success: eve in order, bob reversed",
         [base("failed"), base("success"), corr(count(rules="[failed, success]", ctype="temporal_ordered", cond=None))],
         [E("00:00", User="eve"), E("01:00", "success", User="eve"), E("00:00", "success", User="bob"), E("01:00", User="bob")]),
    Case("C15", ["S35"], "temporal_ordered failed then success at the same second",
         [base("failed"), base("success"), corr(count(rules="[failed, success]", ctype="temporal_ordered", cond=None))],
         [E("01:00", User="bob"), E("01:00", "success", User="bob")]),
    Case("C16", ["S92"], "temporal over 3 rules without a condition: bob has 2 of them, eve all 3",
         [base("failed"), base("success"), base("other"),
          corr(count(rules="[failed, success, other]", ctype="temporal", cond=None))],
         [E("00:00", User="bob"), E("01:00", "success", User="bob"),
          E("00:00", User="eve"), E("01:00", "success", User="eve"), E("02:00", "other", User="eve")]),
    Case("C17", ["S31"], "temporal over 3 rules with gte 2: bob has 2 kinds, eve 2 events of one kind",
         [base("failed"), base("success"), base("other"),
          corr(count(rules="[failed, success, other]", ctype="temporal", cond="gte: 2"))],
         [E("00:00", User="bob"), E("01:00", "success", User="bob"), E("00:00", User="eve"), E("01:00", User="eve")]),
    Case("C18", ["S76"], "event_count referencing the base rule by id",
         [base("failed"), corr(count(rules=f"[{R['failed']}]"))], burst("bob", "00:00", "01:00", "02:00")),
    Case("C19", ["S76"], "chain: inner gte 2 in 5m per User, outer gte 2 inner alerts in 1h; bob has 2 bursts, eve 1",
         [base("failed"), corr(count(cond="gte: 2"), "c1", "burst"),
          corr(count(rules="[burst]", cond="gte: 2", span="1h"), "c2", "bursts")],
         burst("bob", "00:00", "01:00", "20:00", "21:00") + burst("eve", "00:00", "01:00"), compare=["c2"]),
    Case("C20", ["S75"], "temporal with aliases: ip is DestIp in conn_in and SrcIp in conn_out",
         [base("conn_in"), base("conn_out"),
          corr("type: temporal\nrules: [conn_in, conn_out]\naliases:\n    ip:\n        conn_in: DestIp\n"
               "        conn_out: SrcIp\ngroup-by: [ip]\ntimespan: 5m\n")],
         [E("00:00", "conn_in", DestIp="10.0.0.1"), E("01:00", "conn_out", SrcIp="10.0.0.1"),
          E("00:00", "conn_in", SrcIp="10.0.0.2"), E("01:00", "conn_out", DestIp="10.0.0.2")]),
    Case("C21", ["S70"], "value_sum of Bytes per Host, gte 25: 10 + 10 + 10",
         [base("failed"), corr(count(group="[Host]", ctype="value_sum", cond="field: Bytes\ngte: 25"))],
         [E(f"0{i}:00", Host="h", Bytes=10) for i in range(3)]),
    Case("C22", ["S70"], "value_avg of Bytes per Host: gte 9 fires for h (avg 10), not for g (avg 5)",
         [base("failed"), corr(count(group="[Host]", ctype="value_avg", cond="field: Bytes\ngte: 9"))],
         [E(f"0{i}:00", Host="h", Bytes=10) for i in range(3)] + [E(f"0{i}:00", Host="g", Bytes=5) for i in range(3)]),
    Case("C23", ["S74"], "value_percentile of Image per Host, lte 10: one rare image among 11 events",
         [base("failed"), corr(count(group="[Host]", ctype="value_percentile", span="1h", cond="field: Image\nlte: 10"))],
         [E(f"{i:02d}:00", Host="h", Image="svchost.exe") for i in range(10)] + [E("10:00", Host="h", Image="evil.exe")]),
    Case("C24", ["S81"], "filter User|startswith adm_ with condition: sel on the base rule",
         [base("failed"), FILTER], [E("00:00", User="adm_bob"), E("01:00", User="alice")], kind="rule"),
    Case("C25", ["S89"], "filter on the base rule of an event_count without group-by, gte 3: one of 3 events is filtered",
         [base("failed"), FILTER, corr(count(group=None))],
         [E("00:00", User="adm_a"), E("01:00", User="b"), E("02:00", User="c")]),
    Case("C29", ["S81", "S89"], "same as C25 with gte 2: 2 events are left after the filter, 1 if the filter is ANDed in",
         [base("failed"), FILTER, corr(count(group=None, cond="gte: 2"))],
         [E("00:00", User="adm_a"), E("01:00", User="b"), E("02:00", User="c")]),
    Case("C26", ["S80"], "timespan 5M (upper-case unit)",
         [base("failed"), corr(count(span="5M"))], burst("bob", "00:00", "01:00", "02:00")),
    Case("C27", ["S93"], "event_count gte 3: 6 events in 6 seconds, then 3 more 20 minutes later",
         [base("failed"), corr(count())],
         burst("bob", *[f"00:0{i}" for i in range(6)]) + burst("bob", "20:00", "20:01", "20:02")),
    Case("C28", ["S77"], "base rule referenced without generate: are its matches emitted",
         [base("failed"), corr(count())], burst("bob", "00:00", "01:00", "02:00"), kind="emitted"),
]

CASES.sort(key=lambda c: c.id)


def events(case: Case) -> list[dict]:
    """The same events for every target. Times are minutes:seconds after 2026-01-01T00:00:00Z."""
    out = []
    for i, (t, name, fields) in enumerate(case.events, 1):
        minute, second = t.split(":")
        stamp = f"2026-01-01T00:{int(minute):02d}:{int(second):02d}.000Z"
        if int(minute) >= 60:
            stamp = f"2026-01-01T01:{int(minute) - 60:02d}:{int(second):02d}.000Z"
        out.append({"event_id": f"{case.id}-e{i}", "@timestamp": stamp, "SystemTime": stamp, "EventRecordID": i,
                    "Channel": "Security", "Computer": "host", "EventID": EID[name], **fields})
    return out


def _fold_groups(groups) -> list:
    return sorted({tuple(str(v).casefold() for v in g) for g in groups})


# --------------------------------------------------------------------------- targets


def run_evaluator(case: Case) -> dict:
    from harness.evaluator import RuleError, compile_collection, evaluate_collection
    try:
        coll = compile_collection(case.text())
    except RuleError as exc:
        return {"error": str(exc)}
    res = evaluate_collection(coll, events(case))
    if case.kind == "rule":
        return {"rule_matches": sorted(res.rules[R["failed"]])}
    if case.kind == "emitted":
        return {"base_emitted": R["failed"] in res.emitted}
    out = {}
    for c in case.compare:
        alerts = res.alerts[cid_id(c)]
        out[c] = {"groups": _fold_groups(a.group for a in alerts), "alerts": len(alerts)}
    return out


def run_matcher(case: Case) -> dict:
    from sigma.collection import SigmaCollection
    from sigma.correlations import SigmaCorrelationRule
    from sigma.matching import Event, EventLogSource, SigmaMatcher
    try:
        coll = SigmaCollection.from_yaml(case.text())
        matcher = SigmaMatcher(coll, max_events_per_match=None)
    except Exception as exc:  # noqa: BLE001 - a refusal is a result
        return {"error": f"{type(exc).__name__}: {exc}"}
    matches = []
    for e in events(case):
        t = dt.datetime.fromisoformat(e["@timestamp"].replace("Z", "+00:00"))
        data = {k: v for k, v in e.items() if k != "@timestamp"}
        ev = Event(timestamp=t, logsource=EventLogSource(product="windows", service="security"), data=data)
        try:
            matches += matcher.match(ev)
        except Exception as exc:  # noqa: BLE001
            return {"error": f"match {type(exc).__name__}: {exc}"}
    if case.kind == "rule":
        return {"rule_matches": sorted(m.events[0].data["event_id"] for m in matches
                                       if not isinstance(m.rule, SigmaCorrelationRule) and str(m.rule.id) == R["failed"])}
    if case.kind == "emitted":
        return {"base_emitted": None, "note": "library API: base-rule matches are always returned"}
    out = {}
    for c in case.compare:
        alerts = [m for m in matches if isinstance(m.rule, SigmaCorrelationRule) and str(m.rule.id) == cid_id(c)]
        gb = list(next((r.group_by for r in coll.rules if str(r.id) == cid_id(c)), []) or [])
        groups = [tuple((m.group_values or {}).get(g) for g in gb) for m in alerts]
        out[c] = {"groups": _fold_groups(groups), "alerts": len(alerts)}
    return out


def _write_inputs(case: Case, work: pathlib.Path) -> tuple[pathlib.Path, pathlib.Path]:
    rules = work / "rules" / f"{case.id}.yml"
    rules.parent.mkdir(parents=True, exist_ok=True)
    rules.write_text(case.text(), encoding="utf-8")
    ev = work / "events" / f"{case.id}.jsonl"
    ev.parent.mkdir(parents=True, exist_ok=True)
    with ev.open("w", encoding="utf-8") as f:
        for e in events(case):
            f.write(json.dumps({k: v for k, v in e.items() if k != "event_id"}) + "\n")
    return rules, ev


def _by_record(case: Case) -> dict[int, str]:
    return {e["EventRecordID"]: e["event_id"] for e in events(case)}


def run_zircolite(case: Case, work: pathlib.Path) -> dict:
    from harness.native import ZIRCOLITE
    rules, ev = _write_inputs(case, work)
    out = work / f"{case.id}_zircolite.json"
    out.unlink(missing_ok=True)
    cmd = [sys.executable, str(ZIRCOLITE), "-e", str(ev), "-j", "-r", str(rules), "-o", str(out),
           "--no-event-filter", "--timefield", "SystemTime"]
    proc = subprocess.run(cmd, capture_output=True, text=True, cwd=ZIRCOLITE.parent)
    if not out.exists():
        import re
        log = re.sub(r"\x1b\[[0-9;]*m", "", proc.stdout + proc.stderr).replace(str(work), "<work>")
        lines = [" ".join(line.split()) for line in log.splitlines()
                 if re.search(r"cannot load|must|failed|error", line, re.I)]
        return {"error": f"exit {proc.returncode}, no output: {' '.join(lines[:3])}"}
    results = json.loads(out.read_text(encoding="utf-8") or "[]")
    records = _by_record(case)

    def rows_for(rid):
        return [m for r in results if r.get("id") == rid for m in r.get("matches", [])]

    if case.kind == "rule":
        return {"rule_matches": sorted(records[m["EventRecordID"]] for m in rows_for(R["failed"]))}
    if case.kind == "emitted":
        return {"base_emitted": bool(rows_for(R["failed"]))}
    res = {}
    loaded = {r.get("id") for r in results}
    for c in case.compare:
        alerts = rows_for(cid_id(c))
        gb = _group_by(case, c)
        groups = [tuple((m.get("group_keys") or {}).get(g) for g in gb) for m in alerts]
        res[c] = {"groups": _fold_groups(groups), "alerts": len(alerts)}
    skipped = [line.strip() for line in (proc.stdout + proc.stderr).splitlines()
               if "skip" in line.lower() or "error" in line.lower() or "unsupported" in line.lower()]
    if skipped and not loaded:
        res["log"] = skipped[-3:]
    return res


def _group_by(case: Case, c: str) -> list[str]:
    import yaml
    for d in yaml.safe_load_all(case.text()):
        if d and str(d.get("id")) == cid_id(c):
            g = d["correlation"].get("group-by") or []
            return [str(x) for x in (g if isinstance(g, list) else [g])]
    return []


def run_hayabusa(case: Case, work: pathlib.Path) -> dict:
    from harness.native import HAYABUSA, _hayabusa_config
    rules, ev = _write_inputs(case, work)
    rdir = work / "hayabusa_rules" / case.id
    shutil.rmtree(rdir, ignore_errors=True)
    rdir.mkdir(parents=True)
    shutil.copyfile(rules, rdir / rules.name)
    cfg = work / "hayabusa_config"
    if not cfg.exists():
        _hayabusa_config(work)
    out = work / f"{case.id}_hayabusa.jsonl"
    out.unlink(missing_ok=True)
    cmd = [str(HAYABUSA), "dfir-timeline", "-J", "-f", str(ev), "-r", str(rdir), "-c", str(cfg),
           "-w", "-K", "-N", "-C", "-U", "-O", "-D", "-u", "-n", "-p", "verbose", "-t", "jsonl",
           "-o", str(out)]
    with tempfile.TemporaryDirectory() as cwd:  # Hayabusa resolves ./rules/config from the cwd
        (pathlib.Path(cwd) / "rules").mkdir()
        os.symlink(cfg.resolve(), pathlib.Path(cwd) / "rules" / "config")
        proc = subprocess.run(cmd, capture_output=True, text=True, cwd=cwd)
    if proc.returncode != 0:
        return {"error": f"exit {proc.returncode}: {(proc.stdout + proc.stderr).strip().splitlines()[-1:]}"}
    dets = [json.loads(line) for line in out.read_text(encoding="utf-8").splitlines() if line.strip()] if out.exists() else []
    loaded, parse_errors = _hayabusa_counts(proc.stdout + proc.stderr)
    res: dict = {}
    if case.kind == "rule":
        res = {"rule_matches": sorted(_by_record(case)[(d.get("Details") or {}).get("EventRecordID")]
                                      for d in dets if d.get("RuleID") == R["failed"])}
    elif case.kind == "emitted":
        res = {"base_emitted": any(d.get("RuleID") == R["failed"] for d in dets)}
    for c in case.compare if case.kind == "corr" else []:
        alerts = [d for d in dets if d.get("RuleID") == cid_id(c)]
        gb = _group_by(case, c)
        groups = [tuple((d.get("Details") or {}).get(g) for g in gb) for d in alerts]
        res[c] = {"groups": _fold_groups(groups), "alerts": len(alerts)}
    if parse_errors:
        # Hayabusa skips a rule it cannot parse, prints the count and exits 0: a refusal (S78)
        return {"error": f"Hayabusa: {parse_errors} rule parsing error(s), {loaded} rules loaded", "partial": res}
    return res


def _hayabusa_counts(log: str) -> tuple[int | None, int]:
    import re
    log = re.sub(r"\x1b\[[0-9;]*m", "", log)
    total = re.search(r"Total detection rules: *([0-9]+)", log)
    errors = re.search(r"Rule parsing errors: *([0-9]+)", log)
    return (int(total.group(1)) if total else None), (int(errors.group(1)) if errors else 0)


# --------------------------------------------------------------------------- main


def _versions(target: str) -> dict:
    if target == "evaluator":
        from importlib.metadata import version
        return {"pySigma": version("pysigma")}
    if target in ("matcher", "zircolite"):
        from importlib.metadata import version
        return {"pySigma": version("pysigma"), "pySigma-backend-sqlite": version("pysigma-backend-sqlite")}
    from harness.native import versions
    return {"hayabusa": versions()["hayabusa"]}


def run(target: str) -> dict:
    work = pathlib.Path(tempfile.mkdtemp(prefix=f"corrx_{target}_"))
    out = {"target": target, "versions": _versions(target), "cases": {}}
    for case in CASES:
        if target == "evaluator":
            out["cases"][case.id] = run_evaluator(case)
        elif target == "matcher":
            out["cases"][case.id] = run_matcher(case)
        elif target == "zircolite":
            out["cases"][case.id] = run_zircolite(case, work)
        elif target == "hayabusa":
            out["cases"][case.id] = run_hayabusa(case, work)
    shutil.rmtree(work, ignore_errors=True)
    return out


def verdict(expected: dict, got: dict, case: Case) -> str:
    if "error" in expected:
        return "agree" if "error" in got else "differ"
    if "error" in got:
        return "error"
    if case.kind == "rule":
        return "agree" if got["rule_matches"] == expected["rule_matches"] else "differ"
    if case.kind == "emitted":
        if got.get("base_emitted") is None:
            return "n/a"
        return "agree" if got["base_emitted"] == expected["base_emitted"] else "differ"
    return "agree" if all(got[c]["groups"] == expected[c]["groups"] for c in case.compare) else "differ"


def compare() -> dict:
    res = {t: json.loads((OUT / f"{t}.json").read_text(encoding="utf-8")) for t in TARGETS if (OUT / f"{t}.json").exists()}
    rows = []
    for case in CASES:
        exp = res["evaluator"]["cases"][case.id]
        row = {"case": case.id, "clauses": case.clauses, "what": case.what, "evaluator": exp}
        for t in TARGETS[1:]:
            if t in res:
                got = res[t]["cases"][case.id]
                row[t] = {"verdict": verdict(exp, got, case), "result": got}
        rows.append(row)
    summary = {t: {v: sum(1 for r in rows if r.get(t, {}).get("verdict") == v) for v in ("agree", "differ", "error", "n/a")}
               for t in TARGETS[1:] if t in res}
    return {"summary": summary, "cases": rows}


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("target", choices=TARGETS + ("compare",))
    args = ap.parse_args(argv)
    OUT.mkdir(parents=True, exist_ok=True)
    if args.target == "compare":
        data = compare()
        (OUT / "summary.json").write_text(json.dumps(data, indent=1) + "\n", encoding="utf-8")
        print(json.dumps(data["summary"], indent=1))
        return 0
    data = run(args.target)
    (OUT / f"{args.target}.json").write_text(json.dumps(data, indent=1) + "\n", encoding="utf-8")
    print(json.dumps(data["cases"], indent=0)[:4000])
    return 0


if __name__ == "__main__":
    sys.exit(main())
