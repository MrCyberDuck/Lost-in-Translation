"""Probe how each pySigma backend converts one feature at a time (taxonomy evidence, docs/taxonomy.md).

Run once per pySigma environment:  python harness/probe_conversion.py splunk loki sqlite > out.json
Output: {target: {probe: "Q: <query>" | "ERR: <error>"}}. Conversion output only; no engine is queried.
"""
import sys, json, warnings
warnings.filterwarnings("ignore")
from sigma.collection import SigmaCollection
from sigma.plugins import InstalledSigmaPlugins
probes = {
 "cased": "CommandLine|cased: 'Mimi'",
 "qmark": "Image: 'C:\\\\a?c.exe'",
 "fieldref": "User|fieldref: TargetUser",
 "cidr6": "IpAddress|cidr: 'fe80::/10'",
 "cidr20": "IpAddress|cidr: '10.0.16.0/20'",
 "re_i": "CommandLine|re|i: '^cmd\\.exe /c'",
 "null": "Details: null",
 "exists": "Details|exists: true",
 "empty": "Details: ''",
 "lt": "LogonType|lt: 5",
 "neq": "LogonType|neq: 3",
 "bool": "Initiated: true",
 "space_field": "'Source Name': 'x'",
 "dot_field": "'event.code': '1'",
 "hyphen_field": "'a-b': '1'",
 "quote_val": "CommandLine|contains: 'say \"hi\" it''s'",
 "bs_wild": "TargetFilename|endswith: '\\\\*'",
 "trailing_bs": "Path: 'C:\\\\dir\\\\'",
 "newline": "CommandLine|contains: \"a\\nb\"",
 "base64off": "CommandLine|base64offset|contains: 'IEX'",
 "windash": "CommandLine|windash|contains: ' -enc '",
 "num_str": "DestinationPort: '0443'",
 "re_digit": "CommandLine|re: '\\d{3}'",
 "re_newline_dot": "CommandLine|re|s: 'a.b'",
 "float_gte": "Score|gte: 1.5",
 "neg_lt": "Delta|lt: -1",
 "exists_false": "Details|exists: false",
 "utf16_b64": "CommandLine|wide|base64offset|contains: 'ping'",
 "contains_all": "CommandLine|contains|all:\n      - 'a'\n      - 'b'",
 "list_wild": "Image|endswith:\n      - '\\\\a.exe'\n      - '\\\\b.exe'",
 "unicode": "CommandLine|contains: 'caf\u00e9'",
 "lead_space": "AuthenticationPackageName: 'NtLmSsp '",
 "star_only": "CommandLine: '*'",
 "yaml_bool_str": "Enabled: 'yes'",
 "yaml_hex": "Flags: 0x10",
 "int_list": "EventID:\n      - 4624\n      - 4625",
 "backtick": "CommandLine|contains: 'a`b'",
 "pipe_val": "CommandLine|contains: 'a | b'",
 "tab": "CommandLine|contains: \"a\\tb\"",
 "lucene_reserved": "CommandLine|contains: 'a && (b) ~c:d'",
 "like_meta": "CommandLine|contains: '50%_x'",
 "cased_glob_meta": "CommandLine|cased|contains: 'a[b]'",
 "cased_startswith": "CommandLine|cased|startswith: 'Mimi'",
 "cidr_mapped": "IpAddress|cidr: '10.0.0.0/8'",
 "re_lookahead": "CommandLine|re: 'a(?=b)'",
 "dollar": "CommandLine|contains: '${env:x}'",
 "cased_list": "CommandLine|cased:\n      - 'A'\n      - 'B'",
 "windash_and": "Image|endswith: '\\\\a.exe'\n    CommandLine|windash|contains: ' -x '",
 "empty_list": "Details: []",
 "null_in_list": "Details:\n      - 'x'\n      - null",
 "all_single": "CommandLine|contains|all: 'a'",
 "all_plain_list": "CommandLine|all:\n      - 'a'\n      - 'b'",
 "esc_star": "CommandLine|contains: 'a\\*b'",
 "esc_qmark": "CommandLine: 'a\\?b'",
 "placeholder": "User|expand: '%admins%'",
 "utf16le": "CommandLine|utf16le|base64offset|contains: 'ping'",
 "windash_4": "CommandLine|windash|contains: '-a -b -c -d'",
 "bs_contains": "Image|contains: '\\\\AppData\\\\'",
 "list_inner_wild": "Image:\n      - 'a?.exe'\n      - 'b*c.exe'",
 "inner_star": "Image: 'a*b.exe'",
}
conditions = {
 "not_and": "a:\n    x: 1\n  b:\n    y: 2\n  condition: not a and b",
 "not_1of": "filter_a:\n    x: 1\n  filter_b:\n    y: 2\n  sel:\n    z: 3\n  condition: sel and not 1 of filter_*",
 "or_and": "a:\n    x: 1\n  b:\n    y: 2\n  c:\n    z: 3\n  condition: a or b and c",
 "keyword_all": "keywords:\n    '|all':\n      - 'foo'\n      - 'bar'\n  condition: keywords",
 "not_re": "sel:\n    a: 1\n  filter:\n    CommandLine|re: 'x.y'\n  condition: sel and not filter",
}
keyword = "keywords:\n    - 'mimikatz'\n  condition: keywords"
pl = InstalledSigmaPlugins.autodiscover()
res = {}
for t in sys.argv[1:]:
    res[t] = {}
    items = [(n, "sel:\n    " + i + "\n  condition: sel") for n, i in probes.items()]
    items += [("keyword", keyword)] + list(conditions.items())
    for name, det in items:
        y = f"title: p\nid: 33333333-3333-3333-3333-333333333333\nlogsource: {{product: windows}}\ndetection:\n  {det}\n"
        try:
            q = pl.backends[t]().convert(SigmaCollection.from_yaml(y))
            res[t][name] = "Q: " + " ;; ".join(str(x) for x in q)
        except Exception as e:
            res[t][name] = "ERR: " + type(e).__name__ + ": " + str(e).split("\n")[0][:200]
print(json.dumps(res, ensure_ascii=False))
