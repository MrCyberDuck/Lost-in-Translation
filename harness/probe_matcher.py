"""Minimal probes behind the matcher cross-check mechanisms M1 to M7 (results/phase3/matcher_crosscheck/README.md).

Runs in the pySigma 2.x environment:  python harness/probe_matcher.py
Each line: the rule item, the event, and whether sigma.matching (pySigma 2.x) matches it.
"""
import warnings, json; warnings.filterwarnings("ignore")
from sigma.collection import SigmaCollection
from sigma.matching.compiler import MatchCompiler
def m(item, ev):
    r=SigmaCollection.from_yaml("title: t\nlogsource: {product: windows}\ndetection:\n  s:\n    "+item+"\n  condition: s").rules[0]
    return MatchCompiler().compile_rule(r)(ev, json.dumps(ev))
PROBES = [  # mechanism, rule item, event, what the spec reading (the evaluator) expects
    ("M1", "A|contains: '*'", {"B": "x"}, False),
    ("M1", "A: '*'", {"B": "x"}, False),
    ("M2", "SourceName: 'x'", {"Source Name": "x"}, True),
    ("M3", "A|fieldref: B", {"C": "x"}, False),
    ("M4", "A: ''", {"C": "x"}, False),
    ("M5", r"A: '\?'", {"A": "?"}, True),
    ("M5", r"A: 'a\*b'", {"A": "a*b"}, True),
    ("M6", "A: 3389", {"A": "3389"}, True),
    ("M6", "A: '3389'", {"A": 3389}, True),
    ("M7", r"A|contains: '\\\\'", {"A": ["C:\\x"]}, False),
    ("M7", r"A|contains: '\\\\'", {"A": "C:\\x"}, False),
]
if __name__ == "__main__":
    for mech, item, ev, expected in PROBES:
        got = m(item, ev)
        print(f"{mech}  {item:28} {json.dumps(ev):24} matcher={got!s:5} evaluator_reading={expected!s:5} {'' if got == expected else 'DIFFERS'}")

