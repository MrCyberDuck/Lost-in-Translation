"""Rule collections for the reference evaluator: global filters and correlation rules.

Clause ids refer to docs/spec-clauses.md. Detection rules are compiled by core.compile_rule. Filters
and correlations are read from the YAML documents directly, not through pySigma's objects, because
pySigma 1.5.1 deviates from the spec here: SigmaCollection ANDs a filter's condition into the rule
(T23.1), rejects a correlation condition with a range (S34), and accepts timespan units the spec does
not have (S80).

    coll = compile_collection(yaml_text)                 # -> CompiledCollection, raises RuleError
    result = evaluate_collection(coll, events, "neutral")
    result.rules         # {rule id: [event_id, ...]} after filters, every detection rule
    result.alerts        # {correlation id: [Alert, ...]}
    result.emitted       # rule ids whose matches are alerts on their own (S77)

Working interpretations (all documented in docs/spec-clauses.md):

* S81 a filter removes the events its condition matches: `rule and not filter`. A filter needs a
  `selection` and a `condition` (filters spec, both mandatory).
* S82 a filter applies only to rules whose logsource equals its own.
* S83 a filter reference to an unknown rule is ignored with a warning.
* S89 a filter applies to a detection rule before any correlation counts its matches.
* S31, S70 seven correlation types; `value_median` and extended conditions are out of spec.
  value_sum and value_avg use the events whose field parses as a number (S16) and ignore the rest.
* S32 an event without a group-by field, or with a list or map there, is not counted; S90 group-by
  values are compared after case folding, as S1 does for matching.
* S33 sliding window: the windows are the spans of `timespan` that end at an event of the group;
  S91 both ends are included; S96 a condition is tested on every such window, so an upper bound
  (`lt`, `lte`, `eq`) can hold on the way up to a larger count.
* S34 every operator in the condition must hold (a range is an AND).
* S35 temporal_ordered needs strictly increasing timestamps in the order of `rules`.
* S92 temporal and temporal_ordered without a condition need every referenced rule in the window;
  with a condition, temporal counts the referenced rules present and temporal_ordered the length of
  the longest prefix of `rules` seen in order.
* S93 one burst gives one alert: an alert is raised when the condition becomes true for a group, at
  the event that ends the window (rising edge). Comparisons with backends use the groups that fire.
* S94 a correlation over a correlation sees one item for every window where the inner condition
  holds (not only the rising edges), at the time of the event that ends it and with that event's
  fields, so the outer correlation groups by its own fields.
* S95 an event matched by several referenced rules is one event: event_count and the value types
  count it once; temporal counts each rule it matches.
* S71 without group-by, all events form one group.
* S72, S73 value_count counts distinct case-folded values; several fields count distinct tuples;
  events without the field add no value.
* S74 value_percentile: some value's share of the window's events that have the field, in percent,
  meets the condition.
* S75 aliases map a group-by name to a field per rule; S97 for a rule the alias does not list, the
  group-by name is read as a field name.
* S76 references by id or name; the same rule referenced twice is a rule error (the JSON schema has
  `uniqueItems`); a correlation may reference a correlation (S94).
* S77 base rules referenced by a correlation are not emitted unless `generate: true`; `generate` is
  a top-level boolean (JSON schema); `correlation.generate`, where pySigma reads it, is used when the
  top-level key is absent.
* S80 timespan is digits plus s, m, h or d in lower case.

Timestamps are compared in nanoseconds. An event without a parseable `@timestamp` cannot be placed in
a window: it is not counted, and CollectionResult.warnings says how many were dropped.
"""
from __future__ import annotations

import datetime as dt
import re
from dataclasses import dataclass, field
from typing import Any, Iterable

import yaml
from sigma.exceptions import SigmaError
from sigma.rule import SigmaRule

from .core import (CompiledRule, Event, RuleError, Semantics, SPEC, _parse_number, compile_rule, load_yaml_documents,
                   normalise_fields, to_text)

TYPES = ("event_count", "value_count", "temporal", "temporal_ordered", "value_sum", "value_avg", "value_percentile")
VALUE_TYPES = ("value_count", "value_sum", "value_avg", "value_percentile")
OPERATORS = {"gt": lambda a, b: a > b, "gte": lambda a, b: a >= b, "lt": lambda a, b: a < b,
             "lte": lambda a, b: a <= b, "eq": lambda a, b: a == b, "neq": lambda a, b: a != b}
TIMESPAN = re.compile(r"^([0-9]+)([smhd])$")
UNIT = {"s": 1, "m": 60, "h": 3600, "d": 86400}


@dataclass
class Alert:
    correlation: str               # id of the correlation rule
    group: tuple                   # group-by values, case-folded, in group-by order
    time: dt.datetime              # timestamp of the event that ends the window
    events: list[str]              # event ids in the window (for a chain: the inner alerts' events)
    value: float | int | None = None  # the count, sum, average or share that met the condition
    ns: int = 0                    # the same time in nanoseconds since the epoch


@dataclass
class CompiledFilter:
    id: str
    logsource: tuple
    refs: list[str]
    predicate: Any                 # CompiledRule of the filter's own detection


@dataclass
class CompiledCorrelation:
    id: str
    name: str | None
    type: str
    refs: list[str]
    group_by: list[str]
    aliases: dict[str, dict[str, str]]   # alias -> {rule reference: field}
    seconds: int
    conditions: list[tuple[str, float]]  # (operator, threshold), all must hold (S34)
    fields: list[str]                    # condition `field`, for the value_* types
    generate: bool
    targets: list[str] = field(default_factory=list)  # refs resolved to ids (S76)


@dataclass
class CompiledCollection:
    rules: dict[str, CompiledRule]                 # detection rules by id
    names: dict[str, str]                          # name -> id, for rules and correlations
    filters: list[CompiledFilter]
    correlations: dict[str, CompiledCorrelation]   # by id
    order: list[str]                               # correlations, referenced ones first
    warnings: list[str] = field(default_factory=list)
    clauses: set[str] = field(default_factory=set)

    def resolve(self, ref: str) -> str | None:
        """S76: a reference is an id or a name."""
        if ref in self.rules or ref in self.correlations:
            return ref
        return self.names.get(ref)


@dataclass
class CollectionResult:
    rules: dict[str, list[str]]
    alerts: dict[str, list[Alert]]
    emitted: list[str]
    warnings: list[str] = field(default_factory=list)


# --------------------------------------------------------------------------- compiling


def _logsource_key(ls: dict | None) -> tuple:
    ls = ls or {}
    return tuple((str(ls.get(k)).lower() if ls.get(k) is not None else None) for k in ("category", "product", "service"))


def _timespan(spec: Any) -> int:
    m = TIMESPAN.match(str(spec)) if isinstance(spec, (str, int)) else None
    if not m or isinstance(spec, int):
        raise RuleError(f"S80: timespan {spec!r} is not a number followed by s, m, h or d in lower case")
    return int(m.group(1)) * UNIT[m.group(2)]


def _correlation(doc: dict, clauses: set[str]) -> CompiledCorrelation:
    c = doc.get("correlation") or {}
    rid = str(doc.get("id") or doc.get("title"))
    ctype = c.get("type")
    clauses.add("S31")
    if ctype not in TYPES:
        raise RuleError(f"S31/S70: correlation type {ctype!r} is not one of the seven in the spec")
    if ctype in ("value_sum", "value_avg", "value_percentile"):
        clauses.add("S70")
    refs = c.get("rules")
    if not isinstance(refs, list) or not refs:
        raise RuleError("S76: a correlation needs a list of referenced rules")
    refs = [str(r) for r in refs]
    group_by = c.get("group-by")
    if group_by is None:
        clauses.add("S71")
        group_by = []
    elif not isinstance(group_by, list):
        group_by = [group_by]
    group_by = [str(g) for g in group_by]
    if group_by:
        clauses.update({"S32", "S90"})
    aliases = {}
    for alias, mapping in (c.get("aliases") or {}).items():
        clauses.add("S75")
        aliases[str(alias)] = {str(k): str(v) for k, v in (mapping or {}).items()}
    if "timespan" not in c:
        raise RuleError("S80: a correlation needs a timespan")
    seconds = _timespan(c["timespan"])
    clauses.update({"S33", "S80", "S91", "S93", "S96"})
    cond = c.get("condition")
    conditions: list[tuple[str, float]] = []
    fields: list[str] = []
    if cond is None:
        if ctype not in ("temporal", "temporal_ordered"):
            raise RuleError(f"S34: a {ctype} correlation needs a condition")
        clauses.add("S92")
    elif not isinstance(cond, dict):
        raise RuleError("S34: an extended (expression) condition is not in the spec")
    else:
        clauses.add("S34")
        unknown = set(cond) - set(OPERATORS) - {"field"}
        if unknown:
            raise RuleError(f"S34: unknown condition keys {sorted(unknown)}")
        for op in OPERATORS:
            if op in cond:
                num = _parse_number(to_text(cond[op]))
                if num is None:
                    raise RuleError(f"S34: condition {op} needs a number, got {cond[op]!r}")
                conditions.append((op, num))
        if not conditions:
            raise RuleError("S34: the condition has no operator")
        if "field" in cond:
            fields = [str(f) for f in (cond["field"] if isinstance(cond["field"], list) else [cond["field"]])]
    if ctype in VALUE_TYPES and not fields:
        raise RuleError(f"S31: a {ctype} correlation needs `field` in its condition")
    if ctype == "value_count":
        clauses.add("S72")
        if len(fields) > 1:
            clauses.add("S73")
    if ctype == "value_percentile":
        clauses.add("S74")
    if ctype == "temporal_ordered":
        clauses.add("S35")
    generate = doc["generate"] if "generate" in doc else c.get("generate", False)
    if not isinstance(generate, bool):
        raise RuleError(f"S77: generate must be a boolean, got {generate!r}")
    clauses.add("S77")
    return CompiledCorrelation(rid, doc.get("name"), ctype, refs, group_by, aliases, seconds, conditions,
                               fields, generate)


def compile_collection(text: str, sem: Semantics = SPEC) -> CompiledCollection:
    """Compile a multi-document YAML file of detection rules, filters and correlations."""
    try:
        docs = load_yaml_documents(text)
    except yaml.YAMLError as exc:
        raise RuleError(f"YAML error: {exc}") from exc
    rules: dict[str, CompiledRule] = {}
    names: dict[str, str] = {}
    filters: list[CompiledFilter] = []
    correlations: dict[str, CompiledCorrelation] = {}
    clauses: set[str] = set()
    warnings: list[str] = []
    for doc in docs:
        if not isinstance(doc, dict):
            raise RuleError("a YAML document is not a mapping")
        if "correlation" in doc:
            corr = _correlation(doc, clauses)
            correlations[corr.id] = corr
            if corr.name:
                names[str(corr.name)] = corr.id
        elif "filter" in doc:
            flt = doc["filter"] or {}
            if "selection" not in flt or "condition" not in flt:
                raise RuleError("filters spec: a filter needs `selection` and `condition`")
            clauses.add("S81")
            refs = flt.get("rules") or []
            refs = [str(r) for r in (refs if isinstance(refs, list) else [refs])]
            detection = {k: v for k, v in flt.items() if k != "rules"}
            pseudo = {"title": str(doc.get("title", "filter")), "logsource": doc.get("logsource") or {},
                      "detection": detection}
            try:
                comp = compile_rule(SigmaRule.from_dict(pseudo), sem)
            except SigmaError as exc:
                raise RuleError(f"pySigma rejects the filter: {exc}") from exc
            filters.append(CompiledFilter(str(doc.get("id") or doc.get("title")), _logsource_key(doc.get("logsource")),
                                          refs, comp))
        else:
            comp = compile_rule(yaml.safe_dump(doc, sort_keys=False, allow_unicode=True), sem)
            rules[comp.id] = comp
            if doc.get("name"):
                names[str(doc["name"])] = comp.id
            clauses |= comp.clauses
    coll = CompiledCollection(rules, names, filters, correlations, [], warnings, clauses)
    for f in filters:
        for ref in f.refs:
            if coll.resolve(ref) not in rules:
                clauses.add("S83")
                warnings.append(f"S83: filter {f.id} references unknown rule {ref!r}; ignored")
    for corr in correlations.values():
        for ref in corr.refs:
            if coll.resolve(ref) is None:
                raise RuleError(f"S76: correlation {corr.id} references unknown rule {ref!r}")
            if coll.resolve(ref) in correlations:
                clauses.add("S76")
        corr.targets = [coll.resolve(r) for r in corr.refs]
        if len(set(corr.targets)) != len(corr.targets):
            raise RuleError(f"S76: correlation {corr.id} references the same rule twice")
        if any(t in correlations for t in corr.targets):
            clauses.add("S94")
        if len(corr.targets) > 1 and corr.type not in ("temporal", "temporal_ordered"):
            clauses.add("S95")
        if any(len(m) < len(corr.targets) for m in corr.aliases.values()):
            clauses.add("S97")
        # S75: aliases name rules by `name`; key them by id like the items
        corr.aliases = {a: {(coll.resolve(k) or k): v for k, v in m.items()} for a, m in corr.aliases.items()}
    filtered = {coll.resolve(r) for f in filters for r in f.refs}
    if any(t in filtered for c in correlations.values() for t in (coll.resolve(r) for r in c.refs)):
        clauses.add("S89")
    coll.order = _order(coll)
    return coll


def _order(coll: CompiledCollection) -> list[str]:
    """Correlations sorted so that a referenced correlation comes before the one that uses it."""
    out: list[str] = []
    state: dict[str, int] = {}

    def visit(cid: str) -> None:
        if state.get(cid) == 2:
            return
        if state.get(cid) == 1:
            raise RuleError(f"S76: correlation chain loops through {cid}")
        state[cid] = 1
        for ref in coll.correlations[cid].refs:
            target = coll.resolve(ref)
            if target in coll.correlations:
                visit(target)
        state[cid] = 2
        out.append(cid)

    for cid in coll.correlations:
        visit(cid)
    return out


# --------------------------------------------------------------------------- evaluating


def parse_time(value: Any) -> dt.datetime | None:
    """ISO 8601 timestamps as the harness writes them (`2026-03-11T05:16:41.8163273Z`), to microseconds."""
    ns = parse_ns(value)
    return None if ns is None else dt.datetime.fromtimestamp(ns // 1000 / 1e6, dt.timezone.utc)


def parse_ns(value: Any) -> int | None:
    """Nanoseconds since the epoch, keeping up to 9 fractional digits; naive times are UTC."""
    if not isinstance(value, str):
        return None
    m = re.match(r"^\s*(\d{4}-\d\d-\d\d[T ]\d\d:\d\d:\d\d)(?:\.(\d+))?\s*(Z|[+-]\d\d:?\d\d)?\s*$", value)
    if not m:
        return None
    try:
        base = dt.datetime.fromisoformat(m.group(1).replace(" ", "T"))
    except ValueError:
        return None
    tz = m.group(3)
    if tz and tz != "Z":
        sign = 1 if tz[0] == "+" else -1
        hh, mm = int(tz[1:3]), int(tz[-2:])
        base = base.replace(tzinfo=dt.timezone(sign * dt.timedelta(hours=hh, minutes=mm)))
    else:
        base = base.replace(tzinfo=dt.timezone.utc)
    frac = (m.group(2) or "")[:9].ljust(9, "0")
    return int(base.timestamp()) * 1_000_000_000 + int(frac)


def _fold(v: Any) -> Any:
    text = to_text(v)
    return text.casefold() if text is not None else None


@dataclass
class _Item:
    ns: int                   # time in nanoseconds since the epoch
    target: str               # id of the rule or correlation that produced this item
    values: dict[str, Any]    # field -> value, as the correlation may read it
    events: list[str]
    key: str                  # identity of the event (S95) or of the inner match (S94)


def _group_value(corr: CompiledCorrelation, name: str, item: _Item) -> Any:
    alias = corr.aliases.get(name)
    if alias is not None and item.target in alias:
        return item.values.get(alias[item.target])
    return item.values.get(name)  # S97: a rule the alias does not list reads the field itself


def _holds(corr: CompiledCorrelation, value: float | int) -> bool:
    return all(OPERATORS[op](value, thr) for op, thr in corr.conditions)


def _distinct(window: list[_Item]) -> list[_Item]:
    """S95: one item per event, however many referenced rules matched it."""
    seen, out = set(), []
    for it in window:
        if it.key not in seen:
            seen.add(it.key)
            out.append(it)
    return out


def _measure(corr: CompiledCorrelation, window: list[_Item]) -> tuple[bool, Any]:
    t = corr.type
    if t == "event_count":
        n = len(_distinct(window))
        return _holds(corr, n), n
    if t == "value_count":
        seen = set()
        for it in _distinct(window):
            vals = tuple(_fold(it.values.get(f)) for f in corr.fields)
            if None not in vals:
                seen.add(vals)
        return _holds(corr, len(seen)), len(seen)
    if t in ("value_sum", "value_avg"):
        nums = [n for it in _distinct(window)
                if (n := _parse_number(to_text(it.values.get(corr.fields[0])))) is not None]
        if not nums:
            return False, None
        val = sum(nums) if t == "value_sum" else sum(nums) / len(nums)
        return _holds(corr, val), val
    if t == "value_percentile":
        counts: dict[Any, int] = {}
        for it in _distinct(window):
            v = _fold(it.values.get(corr.fields[0]))
            if v is not None:
                counts[v] = counts.get(v, 0) + 1
        total = sum(counts.values())
        for v, n in sorted(counts.items(), key=lambda kv: kv[1]):
            share = 100 * n / total
            if _holds(corr, share):
                return True, share
        return False, None
    refs = corr.targets
    if t == "temporal":
        present = {it.target for it in window}
        n = sum(1 for r in refs if r in present)
        ok = _holds(corr, n) if corr.conditions else n == len(refs)
        return ok, n
    if t == "temporal_ordered":
        # S35: the rules in list order, with strictly increasing timestamps; greedy earliest match
        idx, last = 0, None
        for it in sorted(window, key=lambda i: i.ns):
            if idx < len(refs) and it.target == refs[idx] and (last is None or it.ns > last):
                idx, last = idx + 1, it.ns
        ok = _holds(corr, idx) if corr.conditions else idx == len(refs)
        return ok, idx
    raise RuleError(t)


@dataclass
class _Match:
    """One window where the condition holds (S94: what a chained correlation sees)."""
    group: tuple
    end: _Item
    events: list[str]
    value: Any


def _correlate(corr: CompiledCorrelation, items: list[_Item]) -> tuple[list[Alert], list[_Match]]:
    groups: dict[tuple, list[_Item]] = {}
    for it in items:
        key = []
        for g in corr.group_by:
            v = _fold(_group_value(corr, g, it))
            if v is None:  # S32: an item without the group-by field is not counted
                break
            key.append(v)
        else:
            groups.setdefault(tuple(key), []).append(it)
    alerts: list[Alert] = []
    matches: list[_Match] = []
    span = corr.seconds * 1_000_000_000
    for key, its in groups.items():
        its.sort(key=lambda i: i.ns)
        was = False
        ends = sorted({i.ns for i in its})
        for end_ns in ends:
            # S33 sliding window ending at this time, S91 both ends included
            window = [i for i in its if end_ns - span <= i.ns <= end_ns]
            ok, value = _measure(corr, window)
            if ok:
                end = max((i for i in window if i.ns == end_ns), key=lambda i: i.key)
                evs = sorted({e for i in window for e in i.events})
                matches.append(_Match(key, end, evs, value))
                if not was:  # S93 rising edge
                    t = dt.datetime.fromtimestamp(end_ns // 1000 / 1e6, dt.timezone.utc)
                    alerts.append(Alert(corr.id, key, t, evs, value, end_ns))
            was = ok
    return alerts, matches


def evaluate_collection(coll: CompiledCollection, events: Iterable[Event], config: str = "neutral") -> CollectionResult:
    if config not in ("neutral", "production"):
        raise ValueError(config)
    events = [normalise_fields(e) for e in events]
    matched: dict[str, list[Event]] = {}
    for rid, rule in coll.rules.items():
        filters = [f for f in coll.filters
                   if any(coll.resolve(r) == rid for r in f.refs)
                   and f.logsource == _logsource_key(_rule_logsource(rule))]  # S82
        hits = []
        for e in events:
            if config == "production" and not rule.in_logsource(e):
                continue
            if rule.predicate(e) and not any(f.predicate.predicate(e) for f in filters):  # S81
                hits.append(e)
        matched[rid] = hits
    alerts: dict[str, list[Alert]] = {}
    matches: dict[str, list[_Match]] = {}
    warnings = list(coll.warnings)
    for cid in coll.order:
        corr = coll.correlations[cid]
        items: list[_Item] = []
        for target in corr.targets:
            if target in coll.rules:
                dropped = 0
                for e in matched[target]:
                    ns = parse_ns(e.get("@timestamp"))
                    if ns is None:
                        dropped += 1
                        continue
                    items.append(_Item(ns, target, e, [e["event_id"]], str(e["event_id"])))
                if dropped:
                    warnings.append(f"{cid}: {dropped} match(es) of {target} have no parseable @timestamp; not counted")
            else:  # S94 chain: every window where the inner condition holds
                for i, m in enumerate(matches[target]):
                    items.append(_Item(m.end.ns, target, m.end.values, m.events, f"{target}#{i}"))
        alerts[cid], matches[cid] = _correlate(corr, items)
    referenced = {t for c in coll.correlations.values() if not c.generate for t in c.targets}
    emitted = [rid for rid in coll.rules if rid not in referenced]
    emitted += [cid for cid in coll.correlations if cid not in referenced]
    return CollectionResult({rid: [e["event_id"] for e in hits] for rid, hits in matched.items()}, alerts, emitted,
                            warnings)


def _rule_logsource(rule: CompiledRule) -> dict:
    ls = rule.rule.logsource
    return {"category": ls.category, "product": ls.product, "service": ls.service}
