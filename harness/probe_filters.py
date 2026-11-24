"""Probe how pySigma applies Sigma global filters (taxonomy T23, docs/taxonomy.md).

Run per pySigma env: python harness/probe_filters.py splunk lucene ...
"""
import sys, warnings
warnings.filterwarnings("ignore")
from sigma.collection import SigmaCollection
from sigma.plugins import InstalledSigmaPlugins
pl = InstalledSigmaPlugins.autodiscover()
rule = """title: r
id: 11111111-1111-1111-1111-111111111111
name: r
logsource: {product: windows, category: process_creation}
detection:
  sel:
    Image|endswith: '\\cmd.exe'
  condition: sel
---
"""
f = """title: f
id: 44444444-4444-4444-4444-444444444444
logsource: {LS}
filter:
  rules: [{REF}]
  selection:
    User: admin
  condition: selection
"""
cases = {"match_ls": ("{product: windows, category: process_creation}", "11111111-1111-1111-1111-111111111111"),
         "other_ls": ("{product: linux}", "11111111-1111-1111-1111-111111111111"),
         "product_only": ("{product: windows}", "11111111-1111-1111-1111-111111111111"),
         "missing_ref": ("{product: windows, category: process_creation}", "99999999-9999-9999-9999-999999999999"),
         "by_name": ("{product: windows, category: process_creation}", "r")}
for n,(ls,ref) in cases.items():
    for t in sys.argv[1:]:
        try:
            q = pl.backends[t]().convert(SigmaCollection.from_yaml(rule + f.replace("{LS}", ls).replace("{REF}", ref)))
            r = "Q: " + " ;; ".join(str(x) for x in q)
        except Exception as e:
            r = "ERR: " + type(e).__name__ + ": " + str(e).split("\n")[0][:160]
        print(f"{n:13s} {t:7s} {r[:250]!r}")
