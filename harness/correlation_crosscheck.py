"""Cross-check the evaluator's correlations and filters against three independent implementations.

Small synthetic cases, written for the clauses in docs/spec-clauses.md, run on:

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
alerts, the base-rule matches after filters for rule cases, or the refusal. `compare` writes
summary.json with an outcome and, for each difference, the label from harness.triage.classify on the
case's `depends` list.

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
R = {n: f"00000000-0000-4000-8000-{i:012d}" for i, n in
     enumerate(("failed", "success", "other", "conn_in", "conn_out", "failed2"), 1)}
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
        selection:
            User|startswith: adm_
        condition: selection
    """)


def count(group="[User]", cond="gte: 3", span="5m", rules="[failed]", ctype="event_count", extra="") -> str:
    g = f"group-by: {group}\n" if group else ""
    c = "condition:\n" + textwrap.indent(cond, "    ") + "\n" if cond else ""
    return f"type: {ctype}\nrules: {rules}\n{g}timespan: {span}\n{c}{extra}"


@dataclass
class Case:
    """`clauses`: what the case tests. `depends`: every clause the expected verdict relies on, open ones
    included, the input to triage.classify. `breaks`: per target, what the target's mechanism breaks, a
    clear clause ("clear") or an open clause with the readings under which the result is wrong
    (docs/spec-clauses.md, "Readings of the open clauses"). A target is a `backend-bug` candidate only
    if it breaks a clear clause or an open clause under all of its readings; a silent clause cannot be
    broken (docs/triage-labels.md)."""
    id: str
    clauses: list[str]
    depends: list[str]
    what: str
    docs: list[str]
    events: list[tuple]                 # (mm:ss[.fraction], rule name of the EventID, {fields})
    kind: str = "corr"                  # corr: correlation groups; rule: base-rule matches; emitted: S77
    compare: list[str] = field(default_factory=lambda: ["c1"])
    breaks: dict[str, dict[str, object]] = field(default_factory=dict)

    def text(self) -> str:
        return "\n---\n".join(d.rstrip("\n") for d in self.docs) + "\n"


def rd(clause: str, letters: str) -> list[str]:
    """Readings of an open clause, by letter: rd("S34", "ab") is S34.a and S34.b."""
    return [f"{clause}.{x}" for x in letters]


def E(t, name="failed", **fields):
    return (t, name, fields)


def burst(user, *times, name="failed", **extra):
    return [E(t, name, User=user, **extra) for t in times]


def base2(name: str, eid: int, rid: str) -> str:
    """A second base rule on the same EventID as `failed` (S95)."""
    return base("failed").replace("title: failed", f"title: {name}").replace(f"name: failed", f"name: {name}") \
        .replace(R["failed"], rid).replace("EventID: 4625", f"EventID: {eid}")


FILTER_SUBSET = FILTER.replace("    service: security\n", "")
FILTER_UNKNOWN = FILTER.replace("rules: [failed]", "rules: [no-such-rule]")
H = {"Host": "h"}
ORD = count(rules="[failed, success]", ctype="temporal_ordered", cond=None)
T3 = [base("failed"), base("success"), base("other")]

CASES = [
    Case("C01", ["S31"], ["S31"], "event_count: 3 failures for bob, 2 for eve, within 5 minutes",
         [base("failed"), corr(count())], burst("bob", "00:00", "01:00", "02:00") + burst("eve", "00:00", "01:00")),
    Case("C02", ["S33"], ["S33"], "event_count: a burst at 04:00, 05:00, 06:00 straddles a 5-minute boundary",
         [base("failed"), corr(count())], burst("bob", "04:00", "05:00", "06:00")),
    Case("C03", ["S91"], ["S91"], "event_count: first and last event exactly 5 minutes apart",
         [base("failed"), corr(count())], burst("bob", "00:00", "03:00", "05:00")),
    Case("C04", ["S33"], ["S31", "S33"], "event_count: first and last event 5 minutes and 1 second apart",
         [base("failed"), corr(count())], burst("bob", "00:00", "03:00", "05:01")),
    Case("C05", ["S32"], ["S31", "S32"], "event_count: the third event has no User field",
         [base("failed"), corr(count())], burst("bob", "00:00", "01:00") + [E("02:00")]),
    Case("C06", ["S90"], ["S90"], "event_count: User is Bob, BOB and bob",
         [base("failed"), corr(count())], [E("00:00", User="Bob"), E("01:00", User="BOB"), E("02:00", User="bob")]),
    Case("C07", ["S71"], ["S71"], "event_count without group-by: 3 events of 3 users",
         [base("failed"), corr(count(group=None))], [E("00:00", User="a"), E("01:00", User="b"), E("02:00", User="c")]),
    Case("C08", ["S34"], ["S34", "S33", "S96"], "event_count range gt 1, lte 2: bob has 2 events, eve 3 at the same second",
         [base("failed"), corr(count(cond="gt: 1\nlte: 2"))], burst("bob", "00:00", "01:00") + burst("eve", "02:00", "02:00", "02:00"),
         # H7: Hayabusa keeps only `gt: 1` and fires for eve's 3 events. A range (S34.a) excludes 3; one
         # criterion (S34.b) means refusing the rule. Every window holds all three simultaneous events or none.
         breaks={"hayabusa": {"S34": rd("S34", "ab")}}),
    Case("C09", ["S34"], ["S34"], "event_count neq 1: bob has 2 events at one second, eve 1",
         [base("failed"), corr(count(cond="neq: 1"))], burst("bob", "00:00", "00:00") + burst("eve", "00:00")),
    Case("C10", ["S72", "S90"], ["S72", "S90"], "value_count of User per Host, gte 3: Admin, admin, root",
         [base("failed"), corr(count(group="[Host]", ctype="value_count", cond="field: User\ngte: 3"))],
         [E("00:00", Host="h", User="Admin"), E("01:00", Host="h", User="admin"), E("02:00", Host="h", User="root")]),
    Case("C11", ["S72"], ["S72"], "value_count of User per Host, gte 2: one event has no User",
         [base("failed"), corr(count(group="[Host]", ctype="value_count", cond="field: User\ngte: 2"))],
         [E("00:00", Host="h", User="a"), E("01:00", Host="h")]),
    Case("C12", ["S73"], ["S73", "S33"], "value_count of [User, Src], gte 3: 2 users, 2 sources, 3 pairs",
         [base("failed"), corr(count(group="[Host]", ctype="value_count", cond="field: [User, Src]\ngte: 3"))],
         [E("00:00", Host="h", User="a", Src="x"), E("01:00", Host="h", User="a", Src="y"),
          E("02:00", Host="h", User="b", Src="x")]),
    Case("C13", ["S31"], ["S31"], "temporal: bob has a failure and a success, eve only failures",
         [base("failed"), base("success"), corr(count(rules="[failed, success]", ctype="temporal", cond=None))],
         [E("00:00", "success", User="bob"), E("01:00", User="bob"), E("00:00", User="eve"), E("01:00", User="eve")]),
    Case("C14", ["S35"], ["S35"], "temporal_ordered failed then success: eve in order, bob reversed",
         [base("failed"), base("success"), corr(ORD)],
         [E("00:00", User="eve"), E("01:00", "success", User="eve"), E("00:00", "success", User="bob"), E("01:00", User="bob")]),
    Case("C15", ["S35"], ["S35"], "temporal_ordered failed then success at the same second, failed first in the file",
         [base("failed"), base("success"), corr(ORD)], [E("01:00", User="bob"), E("01:00", "success", User="bob")]),
    Case("C16", ["S92"], ["S92"], "temporal over 3 rules without a condition: bob has 2 of them, eve all 3",
         T3 + [corr(count(rules="[failed, success, other]", ctype="temporal", cond=None))],
         [E("00:00", User="bob"), E("01:00", "success", User="bob"),
          E("00:00", User="eve"), E("01:00", "success", User="eve"), E("02:00", "other", User="eve")]),
    Case("C17", ["S31", "S92"], ["S92"], "temporal over 3 rules with gte 2: bob has 2 kinds, eve 2 events of one kind",
         T3 + [corr(count(rules="[failed, success, other]", ctype="temporal", cond="gte: 2"))],
         [E("00:00", User="bob"), E("01:00", "success", User="bob"), E("00:00", User="eve"), E("01:00", User="eve")]),
    Case("C18", ["S76"], ["S76", "S33"], "event_count referencing the base rule by id",
         [base("failed"), corr(count(rules=f"[{R['failed']}]"))], burst("bob", "00:00", "01:00", "02:00"),
         # M13: the matcher routes matches by rule name only, so a reference by id (S76) never fires.
         breaks={"matcher": {"S76": "clear"}}),
    Case("C19", ["S76"], ["S76", "S94", "S33"], "chain: inner gte 2 in 5m per User, outer gte 2 inner matches in 1h; bob has 2 bursts of 2, eve 1",
         [base("failed"), corr(count(cond="gte: 2"), "c1", "burst"),
          corr(count(rules="[burst]", cond="gte: 2", span="1h"), "c2", "bursts")],
         burst("bob", "00:00", "01:00", "20:00", "21:00") + burst("eve", "00:00", "01:00"), compare=["c2"],
         # M14: the matcher never routes a correlation's matches to another correlation, so no chain (S76)
         # fires, whatever one inner match is.
         breaks={"matcher": {"S76": "clear"}}),
    Case("C20", ["S75"], ["S75", "S92", "S33", "S32"], "temporal with aliases: ip is DestIp in conn_in and SrcIp in conn_out",
         [base("conn_in"), base("conn_out"),
          corr("type: temporal\nrules: [conn_in, conn_out]\naliases:\n    ip:\n        conn_in: DestIp\n"
               "        conn_out: SrcIp\ngroup-by: [ip]\ntimespan: 5m\n")],
         [E("00:00", "conn_in", DestIp="10.0.0.1"), E("01:00", "conn_out", SrcIp="10.0.0.1")],
         # M15 and H11: neither applies `aliases` (S75), so the group key is empty instead of the IP.
         breaks={t: {"S75": "clear"} for t in ("matcher", "hayabusa")}),
    Case("C21", ["S70"], ["S70"], "value_sum of Bytes per Host, gte 25: 10 + 10 + 10",
         [base("failed"), corr(count(group="[Host]", ctype="value_sum", cond="field: Bytes\ngte: 25"))],
         [E(f"0{i}:00", Host="h", Bytes=10) for i in range(3)]),
    Case("C22", ["S70"], ["S70"], "value_avg of Bytes per Host: gte 9 fires for h (avg 10), not for g (avg 5)",
         [base("failed"), corr(count(group="[Host]", ctype="value_avg", cond="field: Bytes\ngte: 9"))],
         [E(f"0{i}:00", Host="h", Bytes=10) for i in range(3)] + [E(f"0{i}:00", Host="g", Bytes=5) for i in range(3)]),
    Case("C23", ["S74"], ["S74"], "value_percentile of Image per Host, lte 10, as in the spec example: one rare image among 11 events",
         [base("failed"), corr(count(group="[Host]", ctype="value_percentile", span="1h", cond="field: Image\nlte: 10"))],
         [E(f"{i:02d}:00", Host="h", Image="svchost.exe") for i in range(10)] + [E("10:00", Host="h", Image="evil.exe")]),
    Case("C24", ["S81"], ["S81", "S98"], "filter `User|startswith: adm_`, `condition: selection`; events adm_bob (e1), alice (e2)",
         [base("failed"), FILTER], [E("00:00", User="adm_bob"), E("01:00", User="alice")], kind="rule"),
    Case("C25", ["S89"], ["S89", "S98"], "filter on the base rule of an event_count per Host, gte 3: one of 3 events is filtered",
         [base("failed"), FILTER, corr(count(group="[Host]"))],
         [E("00:00", User="adm_a", **H), E("01:00", User="b", **H), E("02:00", User="c", **H)]),
    Case("C26", ["S80"], ["S80"], "timespan 5M (upper-case unit), events at 00:00, 30:00 and 59:00",
         [base("failed"), corr(count(span="5M"))], burst("bob", "00:00", "30:00", "59:00")),
    Case("C27", ["S93"], ["S31", "S93"], "event_count gte 3: 6 events in 6 seconds, then 3 more 20 minutes later",
         [base("failed"), corr(count())],
         burst("bob", *[f"00:0{i}" for i in range(6)]) + burst("bob", "20:00", "20:01", "20:02")),
    Case("C28", ["S77"], ["S77"], "base rule referenced without generate: are its matches emitted",
         [base("failed"), corr(count())], burst("bob", "00:00", "01:00", "02:00"), kind="emitted"),
    Case("C29", ["S81", "S89"], ["S81", "S89", "S98"], "as C25 with gte 2: 2 events are left after the filter, 1 if the filter is ANDed in",
         [base("failed"), FILTER, corr(count(group="[Host]", cond="gte: 2"))],
         [E("00:00", User="adm_a", **H), E("01:00", User="b", **H), E("02:00", User="c", **H)]),
    Case("C30", ["S32"], ["S32"], "event_count gte 3: three events, none with the User field",
         [base("failed"), corr(count())], [E("00:00"), E("01:00"), E("02:00")]),
    Case("C31", ["S33"], ["S31", "S33", "S91", "S92"], "temporal over 3 rules, 5m: success at 00:00, failed at 05:00, other at 10:00",
         T3 + [corr(count(rules="[failed, success, other]", ctype="temporal", cond=None))],
         [E("00:00", "success", User="bob"), E("05:00", User="bob"), E("10:00", "other", User="bob")],
         # H12: Hayabusa accepts events up to `timespan` before and after the first rule's event. The three
         # events span 10 minutes, so no 5-minute window holds them all, sliding (S33.a) or fixed (S33.b).
         breaks={"hayabusa": {"S33": rd("S33", "ab")}}),
    Case("C32", ["S35"], ["S35"], "as C15 with success first in the file",
         [base("failed"), base("success"), corr(ORD)], [E("01:00", "success", User="bob"), E("01:00", User="bob")]),
    Case("C33", ["S73"], ["S31", "S73", "S33"], "value_count of [User, Src], gte 3: 3 events with the same pair",
         [base("failed"), corr(count(group="[Host]", ctype="value_count", cond="field: [User, Src]\ngte: 3"))],
         [E(f"0{i}:00", Host="h", User="a", Src="x") for i in range(3)],
         # H13: Hayabusa reads a list in `field` as no field and counts the 3 events. One distinct pair is 1
         # tuple (S73.a) and 1 value per field (S73.b), below 3 either way.
         breaks={"hayabusa": {"S73": rd("S73", "ab")}}),
    Case("C34", ["S94"], ["S94", "S76"], "chain of the spec's shape: inner event_count per Host gte 2, outer temporal_ordered [inner, success] per User",
         [base("failed"), base("success"), corr(count(group="[Host]", cond="gte: 2"), "c1", "burst"),
          corr("type: temporal_ordered\nrules: [burst, success]\ngroup-by: [User]\ntimespan: 10m\n", "c2", "outer")],
         [E("00:00", User="bob", **H), E("01:00", User="bob", **H), E("02:00", "success", User="bob")], compare=["c2"],
         # The inner correlation holds at 01:00 and rises there, so whatever one inner match is (S94 is silent
         # on it), there is one at 01:00 that carries bob's fields (line 498), before the success at 02:00.
         # M14 never routes inner matches. Hayabusa does not fire either; its cause is not traced (H14).
         breaks={"matcher": {"S76": "clear"}, "hayabusa": {"S76": "clear"}}),
    Case("C35", ["S94"], ["S94", "S76"], "chain: inner gte 2 per User, outer gte 2 inner matches; eve has one burst of 3",
         [base("failed"), corr(count(cond="gte: 2"), "c1", "burst"),
          corr(count(rules="[burst]", cond="gte: 2"), "c2", "bursts")],
         burst("eve", "00:00", "01:00", "02:00"), compare=["c2"],
         breaks={"matcher": {"S76": "clear"}}),  # M14, as in C19
    Case("C36", ["S94"], ["S94", "S76"], "brute force then success: failures every 2 minutes 00:00 to 14:00, success at 15:00, outer timespan 2m",
         [base("failed"), base("success"), corr(count(), "c1", "many_failed"),
          corr("type: temporal_ordered\nrules: [many_failed, success]\ngroup-by: [User]\ntimespan: 2m\n", "c2", "outer")],
         burst("bob", *[f"{2 * i:02d}:00" for i in range(8)]) + [E("15:00", "success", User="bob")], compare=["c2"],
         # M14 as in C19. Hayabusa's result turns on the silent part of S94: if an inner match is only the
         # rising edge at 04:00, nothing is within 2 minutes of the success, so it is not marked as breaking.
         breaks={"matcher": {"S76": "clear"}}),
    Case("C37", ["S95"], ["S95"], "event_count over [failed, failed2] gte 2: one event matches both rules",
         [base("failed"), base2("failed2", 4625, R["failed2"]), corr(count(rules="[failed, failed2]", cond="gte: 2"))],
         [E("00:00", User="bob")]),
    Case("C38", ["S95"], ["S95"], "value_sum over [failed, failed2] gte 20: one event with Bytes 10 matches both rules",
         [base("failed"), base2("failed2", 4625, R["failed2"]),
          corr(count(group="[Host]", rules="[failed, failed2]", ctype="value_sum", cond="field: Bytes\ngte: 20"))],
         [E("00:00", Host="h", Bytes=10)]),
    Case("C39", ["S96"], ["S96"], "event_count eq 2: bob has 3 events at 00:00, 01:00, 02:00",
         [base("failed"), corr(count(cond="eq: 2"))], burst("bob", "00:00", "01:00", "02:00")),
    Case("C40", ["S96"], ["S96"], "value_avg lt 100: Bytes 1000 at 00:00, 10 at 04:00 (a window with only the 10 exists)",
         [base("failed"), corr(count(group="[Host]", ctype="value_avg", cond="field: Bytes\nlt: 100"))],
         [E("00:00", Host="h", Bytes=1000), E("04:00", Host="h", Bytes=10)]),
    Case("C41", ["S97"], ["S97", "S75"], "aliases list only conn_in; conn_out events have a field named ip",
         [base("conn_in"), base("conn_out"),
          corr("type: temporal\nrules: [conn_in, conn_out]\naliases:\n    ip:\n        conn_in: DestIp\n"
               "group-by: [ip]\ntimespan: 5m\n")],
         [E("00:00", "conn_in", DestIp="10.0.0.1"), E("01:00", "conn_out", ip="10.0.0.1")],
         # M15 and H11 never apply `aliases` (S75), as in C20; their result here does not come from an answer
         # to S97.
         breaks={t: {"S75": "clear"} for t in ("matcher", "hayabusa")}),
    Case("C42", ["S82"], ["S82", "S98"], "filter with logsource product: windows only, on a product: windows, service: security rule",
         [base("failed"), FILTER_SUBSET], [E("00:00", User="adm_bob"), E("01:00", User="alice")], kind="rule"),
    Case("C43", ["S83"], ["S83", "S98"], "filter referencing a rule that does not exist",
         [base("failed"), FILTER_UNKNOWN], [E("00:00", User="adm_bob"), E("01:00", User="alice")], kind="rule"),
    Case("C44", ["S77"], ["S77"], "generate: true at the top level of the correlation rule, as the JSON schema has it",
         [base("failed"), corr(count()) + "generate: true\n"], burst("bob", "00:00", "01:00", "02:00"), kind="emitted"),
    Case("C45", ["S35"], ["S35", "S99"], "temporal_ordered failed then success 800 nanoseconds apart",
         [base("failed"), base("success"), corr(ORD)],
         [E("01:00.000000100", User="bob"), E("01:00.000000900", "success", User="bob")]),
]
CASES.sort(key=lambda c: c.id)


def events(case: Case) -> list[dict]:
    """The same events for every target. Times are minutes:seconds after 2026-01-01T00:00:00Z."""
    out = []
    for i, (t, name, fields) in enumerate(case.events, 1):
        mmss, _, frac = t.partition(".")
        minute, second = (int(x) for x in mmss.split(":"))
        stamp = f"2026-01-01T{minute // 60:02d}:{minute % 60:02d}:{second:02d}.{(frac or '000')}Z"
        out.append({"event_id": f"{case.id}-e{i}", "@timestamp": stamp, "SystemTime": stamp, "EventRecordID": i,
                    "Channel": "Security", "Computer": "host", "EventID": EID[name], **fields})
    return out


MISSING = "<missing>"  # a group value the target reports as absent (Python None); Hayabusa writes "null"


def _fold_groups(groups) -> list:
    return sorted({tuple(MISSING if v is None else str(v).casefold() for v in g) for g in groups})


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
    # a streaming matcher: events in time order, ties in file order (C15 and C32 swap the tie)
    for e in sorted(events(case), key=lambda e: e["@timestamp"]):
        t = dt.datetime.fromisoformat(e["@timestamp"].replace("Z", "+00:00"))
        data = {k: v for k, v in e.items() if k != "@timestamp"}
        ev = Event(timestamp=t, logsource=EventLogSource(product="windows", service="security"), data=data)
        try:
            matches += matcher.match(ev)
        except Exception as exc:  # noqa: BLE001
            return {"crash": f"{type(exc).__name__}: {exc}"}
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


def _hayabusa_run(case: Case, text: str, work: pathlib.Path, tag: str) -> tuple[list[dict], int | None, int]:
    from harness.native import HAYABUSA, _hayabusa_config
    _, ev = _write_inputs(case, work)
    rdir = work / "hayabusa_rules" / f"{case.id}{tag}"
    shutil.rmtree(rdir, ignore_errors=True)
    rdir.mkdir(parents=True)
    (rdir / f"{case.id}.yml").write_text(text, encoding="utf-8")
    cfg = work / "hayabusa_config"
    if not cfg.exists():
        _hayabusa_config(work)
    out = work / f"{case.id}{tag}_hayabusa.jsonl"
    out.unlink(missing_ok=True)
    cmd = [str(HAYABUSA), "dfir-timeline", "-J", "-f", str(ev), "-r", str(rdir), "-c", str(cfg),
           "-w", "-K", "-N", "-C", "-U", "-O", "-D", "-u", "-n", "-p", "verbose", "-t", "jsonl",
           "-o", str(out)]
    with tempfile.TemporaryDirectory() as cwd:  # Hayabusa resolves ./rules/config from the cwd
        (pathlib.Path(cwd) / "rules").mkdir()
        os.symlink(cfg.resolve(), pathlib.Path(cwd) / "rules" / "config")
        proc = subprocess.run(cmd, capture_output=True, text=True, cwd=cwd)
    if proc.returncode != 0:
        raise RuntimeError(f"exit {proc.returncode}: {(proc.stdout + proc.stderr).strip().splitlines()[-1:]}")
    dets = [json.loads(line) for line in out.read_text(encoding="utf-8").splitlines() if line.strip()] if out.exists() else []
    loaded, errors = _hayabusa_counts(proc.stdout + proc.stderr)
    return dets, loaded, errors


def run_hayabusa(case: Case, work: pathlib.Path) -> dict:
    """Hayabusa skips a rule it cannot parse, prints "Rule parsing errors: N" and exits 0. A second run
    without the filter documents tells which document it skipped: a skipped correlation is a refusal
    (S78); a skipped filter with the rest running is `degraded`."""
    try:
        dets, loaded, errors = _hayabusa_run(case, case.text(), work, "")
        no_filter = "\n---\n".join(d.rstrip("\n") for d in case.docs if "\nfilter:" not in d) + "\n"
        errors_without_filters = _hayabusa_run(case, no_filter, work, "_nf")[2] if errors else 0
    except RuntimeError as exc:
        return {"error": str(exc)}
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
    if errors_without_filters:
        leaked = sorted({d.get("RuleTitle") for d in dets if d.get("RuleID") in R.values()})
        return {"error": f"Hayabusa: {errors_without_filters} correlation rule(s) not parsed, {loaded} rules loaded",
                "leaked_base_alerts": leaked}
    if errors:
        return {"degraded": f"Hayabusa: the filter is not parsed and the rules run without it", **res}
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


def _same(expected: dict, got: dict, case: Case) -> bool:
    if case.kind == "rule":
        return got["rule_matches"] == expected["rule_matches"]
    if case.kind == "emitted":
        return got["base_emitted"] == expected["base_emitted"]
    return all(got[c]["groups"] == expected[c]["groups"] for c in case.compare)


def verdict(expected: dict, got: dict, case: Case) -> str:
    """agree | differ | refused | degraded | crash | n/a. A refusal is conformant (S78) and goes to the
    conversion-failure rate; `degraded` is a partial refusal with the rest of the file still running."""
    if "crash" in got:
        return "crash"
    if "error" in expected:
        return "agree" if "error" in got else "differ"
    if "error" in got:
        return "refused"
    if case.kind == "emitted" and got.get("base_emitted") is None:
        return "n/a"
    if "degraded" in got:
        return "degraded"
    return "agree" if _same(expected, got, case) else "differ"


CAUSE = {"matcher": "engine", "zircolite": "converter", "hayabusa": "engine"}


def label(case: Case, target: str, v: str, expected: dict, got: dict) -> dict | None:
    """triage.classify on the case's dependencies, for a difference, a crash or a degraded run whose
    result differs."""
    from harness.triage import classify
    if v in ("agree", "refused", "n/a") or (v == "degraded" and _same(expected, got, case)):
        return None
    if v == "crash":  # a crash is no reading's result
        return classify(case.depends, cause=CAUSE[target], crashed=True)
    return classify(case.depends, cause=CAUSE[target], breaks=case.breaks.get(target, {}))


def compare() -> dict:
    res = {t: json.loads((OUT / f"{t}.json").read_text(encoding="utf-8")) for t in TARGETS if (OUT / f"{t}.json").exists()}
    rows = []
    for case in CASES:
        exp = res["evaluator"]["cases"][case.id]
        row = {"case": case.id, "clauses": case.clauses, "depends": case.depends, "what": case.what, "evaluator": exp}
        for t in TARGETS[1:]:
            if t in res:
                got = res[t]["cases"][case.id]
                v = verdict(exp, got, case)
                row[t] = {"verdict": v, "label": label(case, t, v, exp, got), "result": got}
        rows.append(row)
    outcomes = ("agree", "differ", "degraded", "refused", "crash", "n/a")
    summary = {t: {v: sum(1 for r in rows if r.get(t, {}).get("verdict") == v) for v in outcomes}
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
