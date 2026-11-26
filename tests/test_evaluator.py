"""One or more tests per spec clause (docs/spec-clauses.md) for the reference evaluator.

Correlation and global filters are tested in tests/test_collection.py.
"""
import textwrap

import pytest

from harness.evaluator import RuleError, compile_rule, evaluate


def rule(detection: str, logsource: str = "product: windows\n    category: process_creation") -> str:
    return textwrap.dedent("""\
        title: test
        id: 11111111-1111-1111-1111-111111111111
        status: test
        logsource:
            {logsource}
        detection:
        {detection}
        level: low
        """).format(logsource=logsource, detection=textwrap.indent(textwrap.dedent(detection), "    "))


def hit(detection: str, event: dict, config: str = "neutral", **kw) -> bool:
    ev = {"event_id": "e", "@timestamp": "2026-01-01T00:00:00Z", **event}
    return evaluate(compile_rule(rule(detection, **kw)), [ev], config) == ["e"]


SEL = "sel:\n    {}\ncondition: sel"


def one(item: str, event: dict, **kw) -> bool:
    return hit(SEL.format(item), event, **kw)


# ---------------------------------------------------------------- values and matching


def test_s1_case_insensitive_ascii():
    assert one("Image: 'C:\\Windows\\cmd.exe'", {"Image": "c:\\WINDOWS\\CMD.EXE"})


def test_s1_non_ascii_casefold():
    assert one("User: 'STRASSE'", {"User": "straße"})  # casefold ß -> ss (working interpretation)


def test_s2_cased():
    assert one("Image|cased: 'Cmd.exe'", {"Image": "Cmd.exe"})
    assert not one("Image|cased: 'Cmd.exe'", {"Image": "cmd.exe"})


def test_s3_plain_value_is_whole_field():
    assert not one("Image: 'cmd.exe'", {"Image": "C:\\cmd.exe"})


def test_s4_wildcards():
    assert one("Image: '*\\cmd.exe'", {"Image": "C:\\x\\cmd.exe"})
    assert one("Image: 'cm?.exe'", {"Image": "cmd.exe"})
    assert not one("Image: 'cm?.exe'", {"Image": "cm.exe"})
    assert one("Image: 'a*'", {"Image": "a"})  # * matches empty


def test_s4_single_char_is_one_code_point():
    assert one("Image: 'a?b'", {"Image": "aéb"})


def test_s5_escaped_wildcards_are_literal():
    assert one("CommandLine: 'a\\*b'", {"CommandLine": "a*b"})
    assert not one("CommandLine: 'a\\*b'", {"CommandLine": "axxb"})
    assert one("CommandLine: 'a\\?b'", {"CommandLine": "a?b"})


def test_s5_backslash_before_wildcard():
    # \\* = literal backslash then wildcard
    assert one("CommandLine: 'C:\\\\*'", {"CommandLine": "C:\\anything"})
    # \\\* = literal backslash and literal star
    assert one("CommandLine: 'C:\\\\\\*'", {"CommandLine": "C:\\*"})
    assert not one("CommandLine: 'C:\\\\\\*'", {"CommandLine": "C:\\x"})


def test_s6_contains_startswith_endswith():
    assert one("CommandLine|contains: 'whoami'", {"CommandLine": "cmd /c whoami /all"})
    assert one("CommandLine|startswith: 'cmd'", {"CommandLine": "cmd /c x"})
    assert not one("CommandLine|startswith: 'cmd'", {"CommandLine": "x cmd"})
    assert one("CommandLine|endswith: '/all'", {"CommandLine": "whoami /all"})


def test_s6_inner_wildcards_still_work():
    assert one("CommandLine|contains: 'a*c'", {"CommandLine": "xxabbbcxx"})


def test_s7_list_or_and_all():
    assert one("CommandLine|contains: ['a', 'zzz']", {"CommandLine": "a"})
    assert not one("CommandLine|contains|all: ['a', 'zzz']", {"CommandLine": "a"})
    assert one("CommandLine|contains|all: ['a', 'b']", {"CommandLine": "ba"})


def test_s8_map_keys_and():
    det = "sel:\n    Image: 'a'\n    User: 'b'\ncondition: sel"
    assert hit(det, {"Image": "a", "User": "b"})
    assert not hit(det, {"Image": "a", "User": "c"})


def test_s9_list_of_maps_or():
    det = "sel:\n    - Image: 'a'\n    - User: 'b'\ncondition: sel"
    assert hit(det, {"Image": "x", "User": "b"})


def test_s10_keywords_substring_any_string_field():
    det = "kw:\n    - 'mimikatz'\ncondition: kw"
    assert hit(det, {"CommandLine": "run MIMIKATZ.exe now"})
    assert not hit(det, {"Count": 5})


def test_s10_keywords_ignore_harness_fields():
    det = "kw:\n    - 'needle'\ncondition: kw"
    ev = {"event_id": "needle", "@timestamp": "2026-01-01T00:00:00Z", "A": "x"}
    assert evaluate(compile_rule(rule(det)), [ev]) == []


def test_s11_integers_compared_as_strings():
    assert one("EventID: 4688", {"EventID": 4688})
    assert one("EventID: 4688", {"EventID": "4688"})
    assert not one("EventID: 4688", {"EventID": "04688"})


def test_s12_modifiers_left_to_right():
    # base64 of 'ab' then contains: matches the encoded value, not the plain one
    assert one("Payload|base64|contains: 'ab'", {"Payload": "xxYWI=xx"})
    assert not one("Payload|base64|contains: 'ab'", {"Payload": "ab"})


def test_s13_utf16le_base64offset():
    import base64
    enc = base64.b64encode("Invoke-Mimikatz".encode("utf-16le")).decode()
    assert one("ScriptBlockText|wide|base64offset|contains: 'Invoke-Mimikatz'", {"ScriptBlockText": f"x{enc}x"})


@pytest.mark.parametrize("dash", ["-", "/", "\u2013", "\u2014", "\u2015"])
def test_s14_s64_windash(dash):
    assert one("CommandLine|windash|contains: ' -enc '", {"CommandLine": f"powershell {dash}enc AAA"})


def test_s15_regex_unanchored_case_sensitive():
    assert one("CommandLine|re: 'who.mi'", {"CommandLine": "x whoami x"})
    assert not one("CommandLine|re: 'WHOAMI'", {"CommandLine": "whoami"})


def test_s16_s69_numeric():
    assert one("Size|gt: 10", {"Size": 11})
    assert one("Size|gte: 10", {"Size": "10"})
    assert not one("Size|lt: 10", {"Size": "ten"})
    assert one("Size|lte: -1", {"Size": -2.5})


def test_s17_cidr():
    assert one("Ip|cidr: '10.0.0.0/8'", {"Ip": "10.1.2.3"})
    assert not one("Ip|cidr: '10.0.0.0/8'", {"Ip": "11.1.2.3"})
    assert one("Ip|cidr: 'fe80::/10'", {"Ip": "fe80::1"})
    assert not one("Ip|cidr: '10.0.0.0/8'", {"Ip": "::ffff:10.1.2.3"})  # IPv4-mapped IPv6 does not match


def test_s18_exists():
    assert one("PasswordLastSet|exists: true", {"PasswordLastSet": ""})
    assert one("PasswordLastSet|exists: true", {"PasswordLastSet": None})
    assert not one("PasswordLastSet|exists: true", {"Other": 1})
    assert one("PasswordLastSet|exists: false", {"Other": 1})


def test_s19_neq_missing_field_does_not_satisfy():
    assert one("User|neq: 'admin'", {"User": "bob"})
    assert not one("User|neq: 'admin'", {"User": "ADMIN"})
    assert not one("User|neq: 'admin'", {"Other": "x"})


def test_s20_fieldref():
    assert one("TargetUser|fieldref: SourceUser", {"TargetUser": "Bob", "SourceUser": "bob"})
    assert not one("TargetUser|fieldref: SourceUser", {"TargetUser": "Bob"})


def test_s21_s67_placeholder_rejected():
    with pytest.raises(RuleError):
        compile_rule(rule("sel:\n    User|expand: '%admins%'\ncondition: sel"))


# ---------------------------------------------------------------- null, empty, missing


def test_s23_empty_string():
    assert one("User: ''", {"User": ""})
    assert not one("User: ''", {"Other": "x"})
    assert not one("User: ''", {"User": None})


def test_s24_null_absent_or_json_null():
    assert one("User: null", {"Other": "x"})
    assert one("User: null", {"User": None})
    assert not one("User: null", {"User": ""})


def test_s25_missing_field_never_matches_so_not_is_true():
    det = "sel:\n    Image: 'a'\nf:\n    ParentImage: 'b'\ncondition: sel and not f"
    assert hit(det, {"Image": "a"})


# ---------------------------------------------------------------- conditions


def test_s26_s27_precedence():
    det = "a:\n    A: 1\nb:\n    B: 1\nc:\n    C: 1\ncondition: a or b and c"
    assert hit(det, {"A": 1})  # a or (b and c)
    assert not hit(det, {"B": 1})


def test_s27_not_binds_tighter_than_and():
    det = "a:\n    A: 1\nb:\n    B: 1\ncondition: not a and b"
    assert hit(det, {"B": 1})
    assert not hit(det, {"A": 1, "B": 1})


def test_s28_them_excludes_underscore():
    det = "a:\n    A: 1\n_b:\n    B: 1\ncondition: 1 of them"
    assert not hit(det, {"B": 1})


def test_s29_x_of_pattern():
    det = "sel_a:\n    A: 1\nsel_b:\n    B: 1\ncondition: all of sel_*"
    assert hit(det, {"A": 1, "B": 1})
    assert not hit(det, {"A": 1})
    assert hit("sel_a:\n    A: 1\nsel_b:\n    B: 1\ncondition: 1 of sel_*", {"B": 1})


def test_s29_pattern_matching_nothing_is_an_error():
    with pytest.raises(RuleError):
        compile_rule(rule("sel:\n    A: 1\ncondition: 1 of zzz*"))


def test_s30_condition_list_is_or():
    det = "a:\n    A: 1\nb:\n    B: 1\ncondition:\n    - a\n    - b"
    assert hit(det, {"B": 1})


# ---------------------------------------------------------------- logsource


def test_s36_neutral_ignores_logsource():
    assert one("Image: 'a'", {"Image": "a", "Channel": "Security", "EventID": 4688})


def test_s37_production_applies_taxonomy():
    sysmon = {"Image": "a", "Channel": "Microsoft-Windows-Sysmon/Operational", "EventID": 1}
    security = {"Image": "a", "Channel": "Security", "EventID": 4688}
    assert one("Image: 'a'", sysmon, config="production")
    assert not one("Image: 'a'", security, config="production")


def test_s37_service_mapping():
    ls = "product: windows\n    service: security"
    assert one("EventID: 1102", {"EventID": 1102, "Channel": "Security"}, config="production", logsource=ls)
    assert not one("EventID: 1102", {"EventID": 1102, "Channel": "System"}, config="production", logsource=ls)


def test_s37_unmapped_category_is_reported():
    from harness.evaluator import UnsupportedLogsource
    ls = "product: windows\n    category: file_access"
    with pytest.raises(UnsupportedLogsource):
        one("FileName: 'a'", {"FileName": "a"}, config="production", logsource=ls)


# ---------------------------------------------------------------- YAML typing, field names and values


def test_s39_boolean_value():
    assert one("Enabled: true", {"Enabled": "True"})
    assert one("Enabled: true", {"Enabled": True})


def test_s41_double_backslash_is_one():
    assert one("Image: 'C:\\\\Windows\\\\cmd.exe'", {"Image": "C:\\Windows\\cmd.exe"})


def test_s42_field_names_case_sensitive():
    assert not one("Image: 'a'", {"image": "a"})


def test_s43_dotted_names_flat():
    assert one("event.category: 'process'", {"event.category": "process"})


def test_s44_array_any_element():
    assert one("Tags: 'b'", {"Tags": ["a", "b"]})


def test_s45_spaces_kept():
    assert not one("CommandLine: 'a '", {"CommandLine": "a"})
    assert one("CommandLine|contains: ' -x '", {"CommandLine": "a -x b"})


def test_s46_wildcard_matches_newline():
    assert one("ScriptBlockText|contains: 'a*b'", {"ScriptBlockText": "a\nb"})


def test_s47_no_unicode_normalisation():
    assert not one("Name: 'caf\u00e9'", {"Name": "cafe\u0301"})


def test_s48_repeated_spaces_literal():
    assert not one("CommandLine: 'a  b'", {"CommandLine": "a b"})


def test_s49_null_in_list_rejected():
    with pytest.raises(RuleError):
        compile_rule(rule("sel:\n    User:\n        - 'a'\n        - null\ncondition: sel"))


def test_s50_keywords_all_in_different_fields():
    det = "kw:\n    '|all':\n        - 'aaa'\n        - 'bbb'\ncondition: kw"
    assert hit(det, {"A": "xaaax", "B": "bbb"})


def test_s52_undefined_identifier_rejected():
    with pytest.raises(RuleError):
        compile_rule(rule("sel:\n    A: 1\ncondition: sel and nothere"))


def test_s53_unused_identifier_ignored():
    det = "sel:\n    A: 1\nunused:\n    B: 1\ncondition: sel"
    assert hit(det, {"A": 1})


def test_s54_map_with_missing_field_is_false():
    det = "sel:\n    A: 1\n    B: 2\ncondition: sel"
    assert not hit(det, {"A": 1})


def test_s56_explicit_pattern_includes_underscore():
    det = "sel:\n    A: 1\n_filter_x:\n    B: 1\ncondition: sel and not 1 of _filter*"
    assert not hit(det, {"A": 1, "B": 1})


def test_s57_not_over_x_of():
    det = "sel:\n    A: 1\nfilter_a:\n    B: 1\nfilter_b:\n    C: 1\ncondition: sel and not 1 of filter_*"
    assert hit(det, {"A": 1})
    assert not hit(det, {"A": 1, "C": 1})


def test_s58_neq_list_differs_from_all():
    assert one("User|neq: ['a', 'b']", {"User": "c"})
    assert not one("User|neq: ['a', 'b']", {"User": "b"})


def test_s59_zone_id_and_leading_zero_do_not_match():
    assert not one("Ip|cidr: 'fe80::/10'", {"Ip": "fe80::1%eth0"})
    assert not one("Ip|cidr: '10.0.0.0/8'", {"Ip": "010.0.0.1"})


def test_s60_out_of_spec_regex_flagged():
    comp = compile_rule(rule("sel:\n    CommandLine|re: '\\d+'\ncondition: sel"))
    assert comp.out_of_spec


def test_s88_all_on_single_value_flagged_but_matches():
    comp = compile_rule(rule("sel:\n    CommandLine|contains|all: 'a'\ncondition: sel"))
    assert comp.out_of_spec and "S88" in comp.clauses
    assert one("CommandLine|contains|all: 'a'", {"CommandLine": "xay"})
    assert not compile_rule(rule("sel:\n    CommandLine|contains|all: ['a', 'b']\ncondition: sel")).out_of_spec


def test_s61_regex_flags():
    assert one("CommandLine|re|i: 'WHOAMI'", {"CommandLine": "whoami"})
    assert one("CommandLine|re|s: 'a.b'", {"CommandLine": "a\nb"})
    assert not one("CommandLine|re: 'a.b'", {"CommandLine": "a\nb"})


def test_s62_regex_no_wildcard_processing():
    assert one("CommandLine|re: 'ab*c'", {"CommandLine": "ac"})


def test_s65_cased_with_contains():
    assert one("CommandLine|cased|contains: 'Ab'", {"CommandLine": "xAbx"})
    assert not one("CommandLine|cased|contains: 'Ab'", {"CommandLine": "xabx"})


def test_s84_hashes_string_match():
    assert one("Hashes|contains: 'IMPHASH=ABC'", {"Hashes": "SHA1=1,MD5=2,IMPHASH=abc"})


def test_s85_field_names_with_spaces_stripped():
    assert one("SourceName: 'Real-Time Protection'", {"Source Name": "Real-Time Protection"})
    assert one("SourceName: 'x'", {"Source Name": "y", "SourceName": "x"})  # exact name wins
