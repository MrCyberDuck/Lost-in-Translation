"""One or more tests per clause for global filters (S81 to S83, S89) and correlation rules (S31 to S35,
S70 to S77, S80, S90 to S97) in the reference evaluator (harness/evaluator/collection.py).

S78 and S79 are obligations of a conversion backend (error or warn when it cannot express a feature),
not of the oracle, so they are checked against the backends in the conformance runs, not here.
"""
import textwrap

import pytest

from harness.evaluator import RuleError, compile_collection, evaluate_collection

BASE = """\
title: failed logon
id: {id}
name: {name}
status: test
logsource:
    product: windows
    service: security
detection:
    sel:
        EventID: {eid}
    condition: sel
"""


R1, R2, R3 = (f"00000000-0000-4000-8000-00000000000{i}" for i in (1, 2, 3))


def base(rid=R1, name="failed", eid=4625) -> str:
    return BASE.format(id=rid, name=name, eid=eid)


def corr(body: str, rid="c1", name="corr") -> str:
    return f"title: correlation\nid: {rid}\nname: {name}\nstatus: test\ncorrelation:\n" + textwrap.indent(
        textwrap.dedent(body), "    ")


def docs(*parts: str) -> str:
    return "\n---\n".join(p.rstrip("\n") for p in parts) + "\n"


def ev(i, minute, second=0, eid=4625, **fields) -> dict:
    return {"event_id": f"e{i}", "@timestamp": f"2026-01-01T00:{minute:02d}:{second:02d}Z", "EventID": eid, **fields}


def run(text: str, events: list[dict]):
    return evaluate_collection(compile_collection(text), events)


def groups(text: str, events: list[dict], cid="c1") -> list[tuple]:
    return [a.group for a in run(text, events).alerts[cid]]


COUNT3 = """\
type: event_count
rules: [failed]
group-by: [User]
timespan: 5m
condition:
    gte: 3
"""


# ---------------------------------------------------------------- filters


FILTER = """\
title: filter admins
id: f1
logsource:
    product: windows
    service: security
filter:
    rules: [{ref}]
    selection:
        User|startswith: adm_
    condition: selection
"""


def test_s81_filter_suppresses_matches_it_selects():
    # The spec's own example: `condition: selection` suppresses the admin events (rule and not filter).
    text = docs(base(), FILTER.format(ref=R1))
    out = run(text, [ev(1, 0, User="adm_bob"), ev(2, 0, User="alice")])
    assert out.rules[R1] == ["e2"]


def test_s81_filter_with_not_keeps_only_the_selected_events():
    text = docs(base(), FILTER.format(ref=R1).replace("condition: selection", "condition: not selection"))
    assert run(text, [ev(1, 0, User="adm_bob"), ev(2, 0, User="alice")]).rules[R1] == ["e1"]


def test_s76_filter_reference_by_name():
    text = docs(base(), FILTER.format(ref="failed"))
    assert run(text, [ev(1, 0, User="adm_bob")]).rules[R1] == []


def test_s81_filter_only_touches_listed_rules():
    text = docs(base(), base(R2, "other"), FILTER.format(ref=R1))
    out = run(text, [ev(1, 0, User="adm_bob")])
    assert out.rules == {R1: [], R2: ["e1"]}


def test_s82_filter_needs_equal_logsource():
    other = FILTER.format(ref=R1).replace("service: security", "service: system")
    assert run(docs(base(), other), [ev(1, 0, User="adm_bob")]).rules[R1] == ["e1"]
    subset = FILTER.format(ref=R1).replace("    service: security\n", "")
    assert run(docs(base(), subset), [ev(1, 0, User="adm_bob")]).rules[R1] == ["e1"]


def test_s83_unknown_reference_is_ignored_with_a_warning():
    coll = compile_collection(docs(base(), FILTER.format(ref="no-such-rule")))
    assert any("S83" in w for w in coll.warnings)
    assert evaluate_collection(coll, [ev(1, 0, User="adm_bob")]).rules[R1] == ["e1"]


def test_s89_filter_applies_before_correlation_counts():
    text = docs(base(), FILTER.format(ref=R1), corr(COUNT3.replace("group-by: [User]\n", "")))
    events = [ev(1, 0, User="adm_a"), ev(2, 1, User="b"), ev(3, 2, User="c")]
    assert run(text, events).alerts["c1"] == []
    events.append(ev(4, 3, User="d"))
    assert len(run(text, events).alerts["c1"]) == 1


# ---------------------------------------------------------------- correlation types


def test_s31_event_count():
    text = docs(base(), corr(COUNT3))
    assert groups(text, [ev(i, i, User="bob") for i in range(3)]) == [("bob",)]
    assert groups(text, [ev(i, i, User="bob") for i in range(2)]) == []


def test_s31_value_count():
    text = docs(base(), corr("""\
        type: value_count
        rules: [failed]
        group-by: [Host]
        timespan: 5m
        condition:
            field: User
            gte: 3
        """))
    same = [ev(i, i, Host="h", User="bob") for i in range(4)]
    assert groups(text, same) == []
    diff = [ev(i, i, Host="h", User=u) for i, u in enumerate(["a", "b", "c"])]
    assert groups(text, diff) == [("h",)]


def test_s31_temporal_any_order():
    text = docs(base(), base(R2, "success", 4624), corr("""\
        type: temporal
        rules: [failed, success]
        group-by: [User]
        timespan: 5m
        """))
    assert groups(text, [ev(1, 0, eid=4624, User="bob"), ev(2, 1, eid=4625, User="bob")]) == [("bob",)]
    assert groups(text, [ev(1, 0, eid=4624, User="bob"), ev(2, 1, eid=4625, User="eve")]) == []


def test_s31_value_sum_and_avg():
    for ctype, thr, expect in (("value_sum", 25, [("h",)]), ("value_avg", 9, [("h",)]), ("value_avg", 11, [])):
        text = docs(base(), corr(f"""\
            type: {ctype}
            rules: [failed]
            group-by: [Host]
            timespan: 5m
            condition:
                field: Bytes
                gte: {thr}
            """))
        assert groups(text, [ev(i, i, Host="h", Bytes=b) for i, b in enumerate([10, "10", 10])]) == expect


def test_s31_type_outside_the_spec_is_an_error():
    with pytest.raises(RuleError, match="S31"):
        compile_collection(docs(base(), corr(COUNT3.replace("event_count", "value_median"))))


def test_s70_all_seven_types_accepted():
    for ctype in ("value_sum", "value_avg", "value_percentile"):
        coll = compile_collection(docs(base(), corr(COUNT3.replace("event_count", ctype).replace(
            "gte: 3", "field: Bytes\n    gte: 3"))))
        assert "S70" in coll.clauses


def test_s31_value_types_need_a_field():
    with pytest.raises(RuleError, match="field"):
        compile_collection(docs(base(), corr(COUNT3.replace("event_count", "value_count"))))


# ---------------------------------------------------------------- grouping


def test_s32_event_without_group_field_is_not_counted():
    text = docs(base(), corr(COUNT3))
    assert groups(text, [ev(1, 0, User="bob"), ev(2, 1, User="bob"), ev(3, 2)]) == []


def test_s32_several_group_fields_form_one_key():
    text = docs(base(), corr(COUNT3.replace("[User]", "[User, Host]")))
    events = [ev(1, 0, User="bob", Host="a"), ev(2, 1, User="bob", Host="a"), ev(3, 2, User="bob", Host="b")]
    assert groups(text, events) == []
    events.append(ev(4, 3, User="bob", Host="a"))
    assert groups(text, events) == [("bob", "a")]


def test_s71_no_group_by_is_one_group():
    text = docs(base(), corr(COUNT3.replace("group-by: [User]\n", "")))
    assert groups(text, [ev(1, 0, User="a"), ev(2, 1, User="b"), ev(3, 2)]) == [()]


def test_s90_group_values_are_case_folded():
    text = docs(base(), corr(COUNT3))
    assert groups(text, [ev(1, 0, User="Bob"), ev(2, 1, User="BOB"), ev(3, 2, User="bob")]) == [("bob",)]


def test_s75_aliases_map_one_group_name_to_fields_per_rule():
    text = docs(base(R1, "conn_in"), base(R2, "conn_out", 4624), corr("""\
        type: temporal
        rules: [conn_in, conn_out]
        aliases:
            ip:
                conn_in: DestinationIp
                conn_out: SourceIp
        group-by: [ip]
        timespan: 5m
        """))
    good = [ev(1, 0, eid=4625, DestinationIp="10.0.0.1"), ev(2, 1, eid=4624, SourceIp="10.0.0.1")]
    assert groups(text, good) == [("10.0.0.1",)]
    swapped = [ev(1, 0, eid=4625, SourceIp="10.0.0.1"), ev(2, 1, eid=4624, DestinationIp="10.0.0.1")]
    assert groups(text, swapped) == []


# ---------------------------------------------------------------- windows and time


def test_s33_sliding_window_catches_a_burst_across_a_boundary():
    # 00:04, 00:05, 00:06 fall in two fixed 5-minute buckets but in one sliding 5-minute window.
    text = docs(base(), corr(COUNT3))
    assert groups(text, [ev(1, 4, User="bob"), ev(2, 5, User="bob"), ev(3, 6, User="bob")]) == [("bob",)]


def test_s33_events_further_apart_than_the_timespan_do_not_correlate():
    text = docs(base(), corr(COUNT3))
    assert groups(text, [ev(1, 0, User="bob"), ev(2, 3, User="bob"), ev(3, 5, 1, User="bob")]) == []


def test_s91_both_window_ends_are_included():
    text = docs(base(), corr(COUNT3))
    assert groups(text, [ev(1, 0, User="bob"), ev(2, 3, User="bob"), ev(3, 5, User="bob")]) == [("bob",)]


def test_s80_timespan_format():
    for good in ("30s", "5m", "2h", "1d"):
        compile_collection(docs(base(), corr(COUNT3.replace("5m", good))))
    for bad in ("5M", "1w", "1y", "5", "5 m", "1h30m", "300"):
        with pytest.raises(RuleError, match="S80"):
            compile_collection(docs(base(), corr(COUNT3.replace("5m", bad))))


def test_events_without_timestamp_are_not_counted():
    text = docs(base(), corr(COUNT3))
    events = [ev(1, 0, User="bob"), ev(2, 1, User="bob"), {**ev(3, 2, User="bob"), "@timestamp": None}]
    assert groups(text, events) == []


# ---------------------------------------------------------------- conditions


def test_s34_every_operator():
    cases = {"gt: 2": 3, "gte: 3": 3, "lt: 2": 1, "lte: 1": 1, "eq: 2": 2, "neq: 1": 2}
    for cond, n in cases.items():
        text = docs(base(), corr(COUNT3.replace("gte: 3", cond)))
        assert groups(text, [ev(i, i, User="bob") for i in range(n)]) == [("bob",)], cond


def test_s34_range_is_an_and():
    text = docs(base(), corr(COUNT3.replace("gte: 3", "gt: 1\n    lte: 2")))
    assert groups(text, [ev(1, 0, User="a")]) == []
    assert groups(text, [ev(1, 0, User="a"), ev(2, 1, User="a")]) == [("a",)]


def test_s34_extended_condition_is_out_of_spec():
    with pytest.raises(RuleError, match="S34"):
        compile_collection(docs(base(), corr(COUNT3.replace("condition:\n    gte: 3", "condition: failed and success"))))


def test_s34_unknown_operator_is_an_error():
    with pytest.raises(RuleError, match="S34"):
        compile_collection(docs(base(), corr(COUNT3.replace("gte", "ge"))))


# ---------------------------------------------------------------- ordering


ORDERED = """\
type: temporal_ordered
rules: [failed, success]
group-by: [User]
timespan: 5m
"""


def test_s35_temporal_ordered_needs_the_list_order():
    text = docs(base(), base(R2, "success", 4624), corr(ORDERED))
    assert groups(text, [ev(1, 0, eid=4625, User="bob"), ev(2, 1, eid=4624, User="bob")]) == [("bob",)]
    assert groups(text, [ev(1, 0, eid=4624, User="bob"), ev(2, 1, eid=4625, User="bob")]) == []


def test_s35_equal_timestamps_are_not_ordered():
    text = docs(base(), base(R2, "success", 4624), corr(ORDERED))
    assert groups(text, [ev(1, 1, eid=4625, User="bob"), ev(2, 1, eid=4624, User="bob")]) == []


def test_s92_temporal_without_condition_needs_every_rule():
    text = docs(base(), base(R2, "success", 4624), base(R3, "other", 4688), corr("""\
        type: temporal
        rules: [failed, success, other]
        group-by: [User]
        timespan: 5m
        """))
    two = [ev(1, 0, eid=4625, User="bob"), ev(2, 1, eid=4624, User="bob")]
    assert groups(text, two) == []
    assert groups(text, two + [ev(3, 2, eid=4688, User="bob")]) == [("bob",)]
    assert "S92" in compile_collection(text).clauses


def test_s31_temporal_condition_counts_rule_types():
    text = docs(base(), base(R2, "success", 4624), base(R3, "other", 4688), corr("""\
        type: temporal
        rules: [failed, success, other]
        group-by: [User]
        timespan: 5m
        condition:
            gte: 2
        """))
    assert groups(text, [ev(1, 0, eid=4625, User="bob"), ev(2, 1, eid=4625, User="bob")]) == []
    assert groups(text, [ev(1, 0, eid=4625, User="bob"), ev(2, 1, eid=4624, User="bob")]) == [("bob",)]


# ---------------------------------------------------------------- distinct values and percentile


def test_s72_distinct_values_are_case_folded():
    text = docs(base(), corr("""\
        type: value_count
        rules: [failed]
        group-by: [Host]
        timespan: 5m
        condition:
            field: User
            gte: 2
        """))
    assert groups(text, [ev(1, 0, Host="h", User="Admin"), ev(2, 1, Host="h", User="admin")]) == []
    assert groups(text, [ev(1, 0, Host="h", User="admin"), ev(2, 1, Host="h", User="root")]) == [("h",)]


def test_s72_events_without_the_field_add_no_value():
    text = docs(base(), corr("""\
        type: value_count
        rules: [failed]
        group-by: [Host]
        timespan: 5m
        condition:
            field: User
            gte: 2
        """))
    assert groups(text, [ev(1, 0, Host="h", User="a"), ev(2, 1, Host="h")]) == []


def test_s73_several_fields_count_tuples():
    text = docs(base(), corr("""\
        type: value_count
        rules: [failed]
        group-by: [Host]
        timespan: 5m
        condition:
            field: [User, Src]
            gte: 3
        """))
    # 2 distinct users and 2 distinct sources, but 3 distinct (User, Src) pairs
    events = [ev(1, 0, Host="h", User="a", Src="x"), ev(2, 1, Host="h", User="a", Src="y"),
              ev(3, 2, Host="h", User="b", Src="x")]
    assert groups(text, events) == [("h",)]
    assert "S73" in compile_collection(text).clauses


def test_s74_value_percentile_rare_value():
    text = docs(base(), corr("""\
        type: value_percentile
        rules: [failed]
        group-by: [Host]
        timespan: 1h
        condition:
            field: Image
            lte: 10
        """))
    common = [ev(i, i, Host="h", Image="svchost.exe") for i in range(10)]
    assert groups(text, common) == []
    assert groups(text, common + [ev(10, 10, Host="h", Image="evil.exe")]) == [("h",)]


# ---------------------------------------------------------------- references, chains, generate


def test_s76_reference_by_id():
    text = docs(base(), corr(COUNT3.replace("[failed]", f"[{R1}]")))
    assert groups(text, [ev(i, i, User="bob") for i in range(3)]) == [("bob",)]


def test_s76_unknown_reference_is_an_error():
    with pytest.raises(RuleError, match="S76"):
        compile_collection(docs(base(), corr(COUNT3.replace("[failed]", "[nope]"))))


def test_s76_chain_counts_inner_alerts():
    inner = corr(COUNT3.replace("gte: 3", "gte: 2"), "c1", "burst")
    outer = corr("""\
        type: event_count
        rules: [burst]
        group-by: [User]
        timespan: 1h
        condition:
            gte: 2
        """, "c2", "bursts")
    text = docs(outer, base(), inner)  # document order does not matter
    one_burst = [ev(1, 0, User="bob"), ev(2, 1, User="bob")]
    assert run(text, one_burst).alerts["c2"] == []
    two = one_burst + [ev(3, 20, User="bob"), ev(4, 21, User="bob")]
    out = run(text, two)
    assert [a.group for a in out.alerts["c2"]] == [("bob",)]
    assert out.alerts["c2"][0].events == ["e1", "e2", "e3", "e4"]
    assert "S76" in compile_collection(text).clauses


def test_s76_chain_loop_is_an_error():
    a = corr(COUNT3.replace("[failed]", "[cb]"), "ca", "ca")
    b = corr(COUNT3.replace("[failed]", "[ca]"), "cb", "cb")
    with pytest.raises(RuleError, match="loop"):
        compile_collection(docs(base(), a, b))


def test_s77_referenced_rules_are_not_emitted_by_default():
    text = docs(base(), base(R2, "other", 4688), corr(COUNT3))
    assert run(text, []).emitted == [R2, "c1"]
    gen = docs(base(), base(R2, "other", 4688), corr(COUNT3 + "generate: true\n"))
    assert run(gen, []).emitted == [R1, R2, "c1"]


def test_s93_one_burst_gives_one_alert():
    text = docs(base(), corr(COUNT3))
    burst = [ev(i, 0, i, User="bob") for i in range(6)]
    alerts = run(text, burst).alerts["c1"]
    assert len(alerts) == 1 and alerts[0].value == 3
    later = burst + [ev(10 + i, 20, i, User="bob") for i in range(3)]
    assert len(run(text, later).alerts["c1"]) == 2


def test_alert_carries_window_events_and_time():
    text = docs(base(), corr(COUNT3))
    a = run(text, [ev(1, 0, User="bob"), ev(2, 1, User="bob"), ev(3, 2, User="bob")]).alerts["c1"][0]
    assert a.events == ["e1", "e2", "e3"]
    assert a.time.isoformat() == "2026-01-01T00:02:00+00:00"


def test_filter_needs_selection_and_condition():
    with pytest.raises(RuleError, match="selection"):
        compile_collection(docs(base(), FILTER.format(ref=R1).replace("selection:", "sel:")))


# ---------------------------------------------------------------- found by the step 2 review


def test_s94_chain_groups_by_its_own_field():
    # The spec's example: the inner rule groups by Host, the outer correlation by User.
    inner = corr(COUNT3.replace("[User]", "[Host]").replace("gte: 3", "gte: 2"), "c1", "burst")
    outer = corr("""\
        type: temporal_ordered
        rules: [burst, success]
        group-by: [User]
        timespan: 10m
        """, "c2", "outer")
    text = docs(base(), base(R2, "success", 4624), inner, outer)
    events = [ev(1, 0, Host="h", User="bob"), ev(2, 1, Host="h", User="bob"), ev(3, 2, eid=4624, User="bob")]
    assert [a.group for a in run(text, events).alerts["c2"]] == [("bob",)]


def test_s94_chain_sees_every_window_where_the_inner_condition_holds():
    # One burst of 3 events with inner gte 2 holds at the 2nd and the 3rd event: 2 inner matches.
    inner = corr(COUNT3.replace("gte: 3", "gte: 2"), "c1", "burst")
    outer = corr(COUNT3.replace("[failed]", "[burst]").replace("gte: 3", "gte: 2"), "c2", "bursts")
    text = docs(base(), inner, outer)
    assert [a.group for a in run(text, [ev(i, i, User="eve") for i in range(3)]).alerts["c2"]] == [("eve",)]


def test_s94_brute_force_then_success():
    # Failures every 2 minutes for 14 minutes, then a success: the inner condition still holds at 14:00.
    inner = corr(COUNT3, "c1", "many_failed")
    outer = corr("""\
        type: temporal_ordered
        rules: [many_failed, success]
        group-by: [User]
        timespan: 2m
        """, "c2", "outer")
    text = docs(base(), base(R2, "success", 4624), inner, outer)
    events = [ev(i, 2 * i, User="bob") for i in range(8)] + [ev(9, 15, eid=4624, User="bob")]
    assert [a.group for a in run(text, events).alerts["c2"]] == [("bob",)]


def test_s95_event_matched_by_two_rules_counts_once():
    text = docs(base(), base(R2, "failed2"), corr(COUNT3.replace("[failed]", "[failed, failed2]").replace("gte: 3", "gte: 2")))
    assert groups(text, [ev(1, 0, User="bob")]) == []
    assert groups(text, [ev(1, 0, User="bob"), ev(2, 1, User="bob")]) == [("bob",)]


def test_s95_value_sum_counts_an_event_once():
    text = docs(base(), base(R2, "failed2"), corr("""\
        type: value_sum
        rules: [failed, failed2]
        group-by: [Host]
        timespan: 5m
        condition:
            field: Bytes
            gte: 20
        """))
    assert groups(text, [ev(1, 0, Host="h", Bytes=10)]) == []


def test_s76_same_rule_twice_is_an_error():
    with pytest.raises(RuleError, match="twice"):
        compile_collection(docs(base(), corr(COUNT3.replace("[failed]", f"[failed, {R1}]"))))


def test_s96_upper_bound_holds_on_the_way_up():
    text = docs(base(), corr(COUNT3.replace("gte: 3", "lt: 3")))
    assert groups(text, [ev(i, i, User="bob") for i in range(5)]) == [("bob",)]


def test_s97_alias_falls_back_to_the_field_for_unlisted_rules():
    text = docs(base(R1, "conn_in"), base(R2, "conn_out", 4624), corr("""\
        type: temporal
        rules: [conn_in, conn_out]
        aliases:
            ip:
                conn_in: DestinationIp
        group-by: [ip]
        timespan: 5m
        """))
    events = [ev(1, 0, DestinationIp="10.0.0.1"), ev(2, 1, eid=4624, ip="10.0.0.1")]
    assert groups(text, events) == [("10.0.0.1",)]
    assert "S97" in compile_collection(text).clauses


def test_timestamps_keep_nanoseconds():
    text = docs(base(), base(R2, "success", 4624), corr(ORDERED))
    events = [{**ev(1, 0, User="bob"), "@timestamp": "2026-01-01T00:00:00.000000100Z"},
              {**ev(2, 0, eid=4624, User="bob"), "@timestamp": "2026-01-01T00:00:00.000000900Z"}]
    assert groups(text, events) == [("bob",)]


def test_dropped_events_are_reported():
    text = docs(base(), corr(COUNT3))
    out = run(text, [ev(1, 0, User="bob"), {**ev(2, 1, User="bob"), "@timestamp": "yesterday"}])
    assert any("1 match(es)" in w for w in out.warnings)


def test_s77_generate_must_be_boolean_and_top_level_wins():
    with pytest.raises(RuleError, match="boolean"):
        compile_collection(docs(base(), corr(COUNT3 + "generate: 'false'\n")))
    top = docs(base(), corr(COUNT3).replace("level: high", "") + "generate: true\n")
    assert R1 in run(top, []).emitted
