"""SC2: what the Sigma correlation JSON schema accepts (docs/spec-clarifications.md).

    pip install jsonschema==4.23.0
    python results/phase3/spec_clarifications/SC2_schema_check.py <sigma-specification>/json-schema/sigma-correlation-rules-schema.json

Every line should print "valid": the schema accepts each of these malformed correlations.
"""
import copy
import json
import sys

from jsonschema.validators import validator_for

schema = json.load(open(sys.argv[1], encoding="utf-8"))
validator = validator_for(schema)(schema)
base = {"title": "Many failed logons", "id": "0e95725d-7320-415d-80f7-004da920fc12",
        "correlation": {"type": "event_count", "rules": ["failed_logon"], "group-by": ["User"], "timespan": "5m"}}
checks = {
    "condition {}": {"condition": {}},
    "condition {foo: bar}": {"condition": {"foo": "bar"}},
    "condition {gt: 'x'}": {"condition": {"gt": "x"}},
    "condition with all six operators": {"condition": {"gt": 1, "gte": 2, "lt": 5, "lte": 4, "eq": 3, "neq": 0}},
    "value_count without field": {"type": "value_count", "condition": {"gte": 3}},
    "alias values that are not strings": {"condition": {"gte": 3}, "aliases": {"ip": {"failed_logon": 123}}},
}
for name, change in checks.items():
    rule = copy.deepcopy(base)
    rule["correlation"].update(change)
    errors = [e.message for e in validator.iter_errors(rule)]
    print(f"{name}: {'valid' if not errors else errors}")
