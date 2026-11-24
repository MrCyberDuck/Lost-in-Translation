"""Probe how pySigma backends convert correlation rules (taxonomy T11, docs/taxonomy.md).

Run per pySigma env: python harness/probe_correlation.py eql esql splunk ...
"""
import sys, warnings
warnings.filterwarnings("ignore")
from sigma.collection import SigmaCollection
from sigma.plugins import InstalledSigmaPlugins
pl = InstalledSigmaPlugins.autodiscover()
base = """title: base
id: 11111111-1111-1111-1111-111111111111
name: base
logsource: {product: windows}
detection:
  sel:
    EventID: 4625
  condition: sel
---
title: base2
id: 22222222-2222-2222-2222-222222222222
name: base2
logsource: {product: windows}
detection:
  sel:
    EventID: 4624
  condition: sel
---
"""
corrs = {
 "event_count": "title: c\nid: 33333333-3333-3333-3333-333333333333\ncorrelation:\n  type: event_count\n  rules: [base]\n  group-by: [TargetUserName]\n  timespan: 5m\n  condition: {gte: 5}\n",
 "value_count": "title: c\nid: 33333333-3333-3333-3333-333333333333\ncorrelation:\n  type: value_count\n  rules: [base]\n  group-by: [IpAddress]\n  timespan: 5m\n  condition: {gte: 5, field: TargetUserName}\n",
 "temporal_ordered": "title: c\nid: 33333333-3333-3333-3333-333333333333\ncorrelation:\n  type: temporal_ordered\n  rules: [base, base2]\n  group-by: [TargetUserName]\n  timespan: 5m\n",
 "no_groupby": "title: c\nid: 33333333-3333-3333-3333-333333333333\ncorrelation:\n  type: event_count\n  rules: [base]\n  timespan: 5m\n  condition: {gte: 5}\n",
}
for n, c in corrs.items():
    print("=====", n)
    for t in sys.argv[1:]:
        try:
            q = pl.backends[t]().convert(SigmaCollection.from_yaml(base + c))
            r = "Q: " + " ;; ".join(str(x) for x in q)
        except Exception as e:
            r = "ERR: " + type(e).__name__ + ": " + str(e).split("\n")[0][:160]
        print(f"  {t:8s} {r[:420]!r}")
