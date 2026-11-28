"""Reference evaluator: the oracle that decides what a Sigma rule should match.

Design (see docs/phase2.md for the rationale):

* Parsing is pySigma's. Rule YAML, value modifiers (contains, windash, base64offset, ...),
  wildcard and escape handling (SigmaString) and the condition grammar come from pySigma,
  so the oracle sees exactly the values that every pySigma backend receives (spec clauses
  S5, S13, S27, S55).
* Everything after parsing is ours. The evaluator does not use pySigma's lowered condition
  tree. It resolves identifiers and `x of` selectors itself (S28, S29, S56), compiles each
  detection item to a Python predicate, and implements every matching rule from
  docs/spec-clauses.md (S1 to S69) directly, including the working interpretations for
  ambiguous clauses.
* Logsource is a configuration choice (S36): `neutral` ignores it, `production` applies the
  taxonomy appendix mapping of category/service to EventID and Channel (S37).

Public API:

    rule = compile_rule(yaml_text)            # -> CompiledRule, raises RuleError
    rule.matches(event)                       # -> bool
    evaluate(rule, events, config="neutral")  # -> list of matching event_id values

Global filters and correlation rules (S31 to S35, S70 to S83, S89 to S93) are in collection.py:

    coll = compile_collection(yaml_text)      # several documents: rules, filters, correlations
    evaluate_collection(coll, events)         # -> CollectionResult (rule matches, alerts, emitted)
"""
from .collection import CollectionResult, compile_collection, evaluate_collection
from .core import CompiledRule, RuleError, UnsupportedLogsource, compile_rule, evaluate

__all__ = ["CollectionResult", "CompiledRule", "RuleError", "UnsupportedLogsource", "compile_collection",
           "compile_rule", "evaluate", "evaluate_collection"]
