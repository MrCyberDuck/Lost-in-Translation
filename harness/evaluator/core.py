"""Core of the reference evaluator. Clause ids (S1...) refer to docs/spec-clauses.md."""
from __future__ import annotations

import ipaddress
import json
import pathlib
import re
from dataclasses import dataclass, field
from typing import Any, Callable, Iterable

from sigma.collection import SigmaCollection
from sigma.conditions import (
    ConditionAND,
    ConditionIdentifier,
    ConditionNOT,
    ConditionOR,
    ConditionSelector,
)
from sigma.exceptions import SigmaError
from sigma.rule import SigmaDetection, SigmaDetectionItem, SigmaRule
from sigma.types import (
    CompareOperators,
    SigmaBool,
    SigmaCasedString,
    SigmaCIDRExpression,
    SigmaCompareExpression,
    SigmaExists,
    SigmaExpansion,
    SigmaFieldReference,
    SigmaNull,
    SigmaNumber,
    SigmaRegularExpression,
    SigmaRegularExpressionFlag,
    SigmaString,
    SpecialChars,
)

Event = dict[str, Any]
Pred = Callable[[Event], bool]

MISSING = object()
# Fields the harness adds to every event; they are not log content (S10).
HARNESS_FIELDS = frozenset({"event_id", "@timestamp", "@userdata"})

TAXONOMY_PATH = pathlib.Path(__file__).with_name("taxonomy_windows.json")

# S60: regex syntax outside the spec subset.
OUT_OF_SPEC_REGEX = [
    ("shorthand class", re.compile(r"(?<!\\)(?:\\\\)*\\[dDwWsSbB]")),
    ("non-capturing group", re.compile(r"\(\?:")),
    ("inline flag", re.compile(r"\(\?[aiLmsux-]+[):]")),
    ("lazy quantifier", re.compile(r"(?:[*+?}])\?")),
    ("lookaround", re.compile(r"\(\?<?[=!]")),
    ("backreference", re.compile(r"(?<!\\)\\[1-9]")),
]


@dataclass(frozen=True)
class Semantics:
    """Deviations from the spec, used ONLY to explain native-engine disagreements
    (harness/explain.py). The defaults are the spec; the oracle never changes them."""

    three_valued_missing: bool = False  # a value test on a missing field is unknown, not false
    null_explicit_only: bool = False    # `field: null` needs the field present with JSON null
    strict_bool: bool = False           # a string in the rule never matches a boolean event value
    strict_number: bool = False         # a number in the rule never matches a string event value


SPEC = Semantics()


def _and3(vals) -> bool | None:
    # Chainsaw (tau), from probe rules: left to right, the first value that is not true wins,
    # so AND(unknown, false) is unknown but AND(false, unknown) is false.
    for v in vals:
        if v is not True:
            return v
    return True


def _or3(vals) -> bool | None:
    # Chainsaw (tau), from probe rules: true if any branch is true, else false if any branch is
    # false, else unknown.
    seen_false = False
    for v in vals:
        if v is True:
            return True
        if v is False:
            seen_false = True
    return False if seen_false else None


def _not3(v) -> bool | None:
    return None if v is None else not v


class RuleError(Exception):
    """The rule cannot be evaluated by the spec (an error the spec says a tool must raise,
    or a working interpretation that rejects the rule, for example S49, S51, S52)."""


class UnsupportedLogsource(RuleError):
    """Production config only: the taxonomy appendix has no EventID/Channel mapping."""


@dataclass
class CompiledRule:
    rule: SigmaRule
    predicate: Pred
    logsource_filter: Pred | None = None
    logsource_error: str | None = None
    out_of_spec: list[str] = field(default_factory=list)  # S60 constructs found
    clauses: set[str] = field(default_factory=set)        # spec clauses this rule exercises

    @property
    def id(self) -> str:
        return str(self.rule.id) if self.rule.id else self.rule.title

    def matches(self, event: Event) -> bool:
        return self.predicate(normalise_fields(event))

    def in_logsource(self, event: Event) -> bool:
        if self.logsource_error:
            raise UnsupportedLogsource(self.logsource_error)
        return self.logsource_filter is None or self.logsource_filter(event)


# --------------------------------------------------------------------------- values


def normalise_fields(event: Event) -> Event:
    """S85: rule field names are log field names with all spaces stripped (`Source Name` is
    written `SourceName`). Add the stripped name as an alias; an exact name always wins."""
    if not any(" " in k for k in event):
        return event
    out = dict(event)
    for k, v in event.items():
        if " " in k:
            out.setdefault(k.replace(" ", ""), v)
    return out


def _values(event: Event, name: str) -> list:
    """Values of a field; an array field is several values (S44). Missing -> []."""
    val = event.get(name, MISSING)
    if val is MISSING:
        return []
    if isinstance(val, list):
        return val
    return [val]


def to_text(val: Any) -> str | None:
    """Field value as the string Sigma compares against (S11, S39). None if not a scalar."""
    if isinstance(val, bool):
        return "true" if val else "false"
    if isinstance(val, (int, float)):
        return str(val)
    if isinstance(val, str):
        return val
    return None


def string_pattern(value: SigmaString, cased: bool, substring: bool = False) -> re.Pattern:
    """Compile a SigmaString (wildcards already parsed by pySigma, S4/S5) to an anchored regex.

    * case-insensitive via str.casefold() on both sides unless `cased` (S1, S2, S65);
    * `*` matches any sequence including newlines, `?` one code point (S4, S46);
    * no trimming or whitespace collapsing (S45, S48); no Unicode normalisation (S47).
    """
    parts = []
    for part in value.s:
        if isinstance(part, str):
            parts.append(re.escape(part if cased else part.casefold()))
        elif part is SpecialChars.WILDCARD_MULTI:
            parts.append(".*")
        elif part is SpecialChars.WILDCARD_SINGLE:
            parts.append(".")
        else:  # unresolved placeholder (S21, S67)
            raise RuleError(f"unresolved placeholder {part!r}")
    pattern = "".join(parts)
    if substring:
        pattern = f".*{pattern}.*"
    return re.compile(pattern, re.DOTALL)


def _parse_number(text: str | None) -> int | float | None:
    if text is None:
        return None
    try:
        return int(text)
    except ValueError:
        pass
    try:
        num = float(text)
    except ValueError:
        return None
    return None if num != num else num  # reject NaN


_COMPARE = {
    CompareOperators.LT: lambda a, b: a < b,
    CompareOperators.LTE: lambda a, b: a <= b,
    CompareOperators.GT: lambda a, b: a > b,
    CompareOperators.GTE: lambda a, b: a >= b,
}


def _ip_in(text: str | None, network) -> bool:
    """S17, S59: Python ipaddress; zone ids, leading zeros, other families do not match."""
    if text is None or "%" in text:
        return False
    try:
        addr = ipaddress.ip_address(text)  # no trimming (S45)
    except ValueError:
        return False
    return addr.version == network.version and addr in network


class _Compiler:
    def __init__(self, rule: SigmaRule, sem: Semantics = SPEC):
        self.rule = rule
        self.sem = sem
        self.tv = sem.three_valued_missing
        self.out_of_spec: list[str] = []
        self.clauses: set[str] = set()

    # ---- single values

    def value(self, name: str, value) -> Pred:
        if isinstance(value, SigmaExpansion):  # S13, S14: OR of the expanded values
            preds = [self.value(name, v) for v in value.values]
            return lambda e: any(p(e) for p in preds)

        if isinstance(value, SigmaNull):  # S24: absent or JSON null
            self.clauses.add("S24")
            if self.sem.null_explicit_only:
                return lambda e: name in e and e[name] is None
            return lambda e: e.get(name, MISSING) is MISSING or e.get(name) is None

        if isinstance(value, SigmaExists):  # S18
            self.clauses.add("S18")
            want = bool(value.exists)
            return lambda e: (name in e) == want

        if isinstance(value, SigmaFieldReference):  # S20
            self.clauses.add("S20")
            ref, sw, ew = value.field, value.starts_with, value.ends_with

            def fieldref(e: Event) -> bool:
                others = [t.casefold() for t in map(to_text, _values(e, ref)) if t is not None]
                for v in _values(e, name):
                    t = to_text(v)
                    if t is None:
                        continue
                    t = t.casefold()
                    for o in others:
                        if (sw and t.startswith(o)) or (ew and t.endswith(o)) or (not sw and not ew and t == o):
                            return True
                return False

            return fieldref

        if isinstance(value, SigmaRegularExpression):  # S15, S60, S61, S62
            self.clauses.add("S15")
            src = value.regexp.to_plain() if isinstance(value.regexp, SigmaString) else str(value.regexp)
            for label, rx in OUT_OF_SPEC_REGEX:
                if rx.search(src):
                    self.out_of_spec.append(f"{name}: {label}")
            flags = 0
            for f in value.flags or ():
                flags |= {
                    SigmaRegularExpressionFlag.IGNORECASE: re.IGNORECASE,
                    SigmaRegularExpressionFlag.MULTILINE: re.MULTILINE,
                    SigmaRegularExpressionFlag.DOTALL: re.DOTALL,
                }[f]
            try:
                rx_c = re.compile(src, flags)
            except re.error as exc:
                raise RuleError(f"regex does not compile: {exc}") from exc
            return self._any_text(name, lambda t: rx_c.search(t) is not None)

        if isinstance(value, SigmaCIDRExpression):
            self.clauses.add("S17")
            net = value.network
            return self._any_text(name, lambda t: _ip_in(t, net))

        if isinstance(value, SigmaCompareExpression):  # S16, S69
            self.clauses.add("S16")
            op, ref_num = _COMPARE[value.op], value.number.number

            def cmp(t: str) -> bool:
                n = _parse_number(t)
                return n is not None and op(n, ref_num)

            return self._any_text(name, cmp, skip_bool=True)

        if isinstance(value, SigmaBool):  # S39
            self.clauses.add("S39")
            want = "true" if value.boolean else "false"
            return self._any_text(name, lambda t: t.casefold() == want)

        if isinstance(value, SigmaNumber):  # S11: compared as strings
            self.clauses.add("S11")
            want = str(value.number)
            if self.sem.strict_number:
                return lambda e: any(not isinstance(v, (str, bool)) and to_text(v) == want for v in _values(e, name))
            return self._any_text(name, lambda t: t == want)

        if isinstance(value, SigmaString):  # S1 to S6, S23, S41, S45 to S48
            cased = isinstance(value, SigmaCasedString)
            rx = string_pattern(value, cased)
            strict = self.sem.strict_bool
            if cased:
                return self._any_text(name, lambda t: rx.fullmatch(t) is not None, skip_bool=strict)
            return self._any_text(name, lambda t: rx.fullmatch(t.casefold()) is not None, skip_bool=strict)

        raise RuleError(f"unsupported value type {type(value).__name__} for field {name}")

    @staticmethod
    def _any_text(name: str, test: Callable[[str], bool], skip_bool: bool = False) -> Pred:
        """True if any value of the field (S44) converts to text and passes. Missing -> False (S25)."""

        def pred(e: Event) -> bool:
            for v in _values(e, name):
                if skip_bool and isinstance(v, bool):
                    continue
                t = to_text(v)
                if t is not None and test(t):
                    return True
            return False

        return pred

    def keyword(self, value) -> Pred:
        """S10: case-insensitive substring (wildcards honoured) in any string field value."""
        self.clauses.add("S10")
        if isinstance(value, SigmaExpansion):
            preds = [self.keyword(v) for v in value.values]
            return lambda e: any(p(e) for p in preds)
        if isinstance(value, SigmaNumber):
            value = SigmaString(str(value.number))
        if not isinstance(value, SigmaString):
            raise RuleError(f"unsupported keyword value {type(value).__name__}")
        cased = isinstance(value, SigmaCasedString)
        rx = string_pattern(value, cased, substring=True)

        def pred(e: Event) -> bool:
            for k, v in e.items():
                if k in HARNESS_FIELDS:
                    continue
                for item in v if isinstance(v, list) else [v]:
                    if isinstance(item, str) and rx.fullmatch(item if cased else item.casefold()):
                        return True
            return False

        return pred

    # ---- detection items and detections

    def item(self, item: SigmaDetectionItem) -> Pred:
        values = list(item.value)
        if not values:
            raise RuleError("empty list of values (S51)")
        if len(values) > 1 and any(isinstance(v, SigmaNull) for v in values):
            raise RuleError("null inside a list of values (S49)")
        if item.field is None:
            preds = [self.keyword(v) for v in values]
        else:
            preds = [self.value(item.field, v) for v in values]
        linking_all = item.value_linking is ConditionAND  # S7: OR, or AND with |all
        if linking_all:
            self.clauses.add("S7")

        def base(e: Event) -> bool:
            if linking_all:
                return all(p(e) for p in preds)
            return any(p(e) for p in preds)

        if getattr(item, "negated", False):  # neq: S19 (missing field fails), S58 (differs from all)
            self.clauses.update({"S19", "S58"})
            name = item.field
            return lambda e: name in e and e[name] is not None and not base(e)
        if self.tv and item.field is not None and not any(isinstance(v, (SigmaNull, SigmaExists)) for v in values):
            name = item.field
            return lambda e: None if name not in e else base(e)
        return base

    def detection(self, det: SigmaDetection) -> Pred:
        if not det.detection_items:
            raise RuleError("empty selection (S51)")
        preds = [self.detection(d) if isinstance(d, SigmaDetection) else self.item(d) for d in det.detection_items]
        if det.item_linking is ConditionOR:  # S9: list of maps
            return self._or(preds)
        return self._and(preds)  # S8: keys of a map

    def _and(self, preds: list[Pred]) -> Pred:
        if self.tv:
            return lambda e: _and3(p(e) for p in preds)
        return lambda e: all(p(e) for p in preds)

    def _or(self, preds: list[Pred]) -> Pred:
        if self.tv:
            return lambda e: _or3(p(e) for p in preds)
        return lambda e: any(p(e) for p in preds)

    # ---- conditions

    def condition(self, node, detections: dict[str, Pred]) -> Pred:
        if isinstance(node, ConditionAND):
            return self._and([self.condition(a, detections) for a in node.args])
        if isinstance(node, ConditionOR):
            return self._or([self.condition(a, detections) for a in node.args])
        if isinstance(node, ConditionNOT):
            inner = self.condition(node.args[0], detections)
            if self.tv:
                return lambda e: _not3(inner(e))
            return lambda e: not inner(e)
        if isinstance(node, ConditionIdentifier):
            name = node.args[0]
            if name not in detections:
                raise RuleError(f"condition references undefined identifier {name!r} (S52)")
            return detections[name]
        if isinstance(node, ConditionSelector):
            pattern = node.pattern
            if pattern == "them":  # S28: them excludes _ identifiers
                names = [n for n in detections if not n.startswith("_")]
            else:  # S29, S56: explicit patterns include _ identifiers
                rx = re.compile(".*".join(re.escape(p) for p in pattern.split("*")))
                names = [n for n in detections if rx.fullmatch(n)]
            if not names:
                raise RuleError(f"selector {pattern!r} matches no identifier (S29)")
            parts = [detections[n] for n in names]
            if node.cond_class is ConditionAND:
                return self._and(parts)
            return self._or(parts)
        raise RuleError(f"unsupported condition node {type(node).__name__}")


# --------------------------------------------------------------------------- logsource


_taxonomy_cache: dict | None = None


def taxonomy() -> dict:
    global _taxonomy_cache
    if _taxonomy_cache is None:
        _taxonomy_cache = json.loads(TAXONOMY_PATH.read_text(encoding="utf-8"))
    return _taxonomy_cache


def logsource_filter(rule: SigmaRule) -> tuple[Pred | None, str | None]:
    """S37: Windows category/service -> EventID and Channel filter from the taxonomy appendix."""
    ls = rule.logsource
    if (ls.product or "").lower() != "windows":
        return None, f"product {ls.product!r} has no Windows taxonomy mapping"
    tax = taxonomy()
    channels: set[str] | None = None
    event_ids: set[str] | None = None
    if ls.category:
        entry = tax["category"].get(ls.category)
        if entry is None or not entry.get("channels"):
            return None, f"category {ls.category!r} has no EventID/Channel mapping in the taxonomy appendix"
        channels = {c.casefold() for c in entry["channels"]}
        event_ids = {str(i) for i in entry["event_ids"]} or None
    if ls.service:
        entry = tax["service"].get(ls.service)
        if entry is None:
            return None, f"service {ls.service!r} is not in the taxonomy appendix"
        svc = {c.casefold() for c in entry["channels"]}
        channels = svc if channels is None else channels & svc
    if channels is None:
        return None, None  # product only: every Windows event

    def pred(e: Event) -> bool:
        ch = e.get("Channel")
        if not isinstance(ch, str) or ch.casefold() not in channels:
            return False
        return event_ids is None or str(e.get("EventID")) in event_ids

    return pred, None


# --------------------------------------------------------------------------- entry points


def compile_rule(rule_yaml: str | SigmaRule, sem: Semantics = SPEC) -> CompiledRule:
    if isinstance(rule_yaml, SigmaRule):
        rule = rule_yaml
    else:
        try:
            coll = SigmaCollection.from_yaml(rule_yaml)
        except SigmaError as exc:
            raise RuleError(f"pySigma rejects the rule: {exc}") from exc
        rules = [r for r in coll.rules if isinstance(r, SigmaRule)]
        if len(rules) != 1:
            raise RuleError(f"expected one detection rule, found {len(coll.rules)} items")
        rule = rules[0]
    comp = _Compiler(rule, sem)
    try:
        detections = {name: comp.detection(det) for name, det in rule.detection.detections.items()}
        conds = [comp.condition(c.parse(postprocess=False), detections) for c in rule.detection.parsed_condition]
    except SigmaError as exc:
        raise RuleError(f"pySigma rejects the rule: {exc}") from exc
    if len(conds) == 1:
        top = conds[0]
    else:  # S30: a list of conditions is an OR
        top = comp._or(conds)
    predicate = (lambda e: top(e) is True) if comp.tv else top
    flt, err = logsource_filter(rule)
    return CompiledRule(rule, predicate, flt, err, comp.out_of_spec, comp.clauses)


def evaluate(rule: CompiledRule, events: Iterable[Event], config: str = "neutral") -> list[str]:
    """Event ids the rule matches. `neutral` ignores logsource (S36); `production` applies S37."""
    if config not in ("neutral", "production"):
        raise ValueError(config)
    out = []
    for e in events:
        e = normalise_fields(e)
        if config == "production" and not rule.in_logsource(e):
            continue
        if rule.predicate(e):
            out.append(e["event_id"])
    return out
