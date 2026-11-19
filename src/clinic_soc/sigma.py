"""Load Sigma rules and evaluate the subset this clinic pack runs locally.

Supported detection language:

- Selections are AND across fields and OR across list values.
- ``|contains``, ``|startswith``, ``|endswith``, ``|re``, ``|gt``, ``|gte``,
  ``|lt``, ``|lte``. Add ``|all`` to require every list value.
- Conditions use ``and``, ``or``, ``not``, and parentheses. ``and`` binds
  tighter than ``or``.
- Aggregations: ``| count() by field > 10`` and
  ``| count(distinct field) by field > 10``, with ``timeframe`` (for example
  ``15m``). ``count(distinct ...)`` is a local extension. Upstream Sigma
  would express that as a correlation. It is how credential stuffing is
  separated from one person mistyping a password.
- ``group_by`` plus ``timeframe`` collapses several matching events into
  one alert. That key is local.
- ``correlation`` links a follow-up event to an earlier alert. The ``join``
  field is the value that must match (named ``join`` because YAML would
  read a bare ``on:`` as a boolean). Local.

String compares are case-insensitive. Windows command lines and account
names arrive in mixed case.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import timedelta
from pathlib import Path

import yaml

from clinic_soc.clinic import ROOT

_TOKEN = re.compile(r"[A-Za-z_][A-Za-z0-9_]*|\d+|>=|<=|>|<|\(|\)|\||,")
_MODIFIERS = {
    "contains",
    "startswith",
    "endswith",
    "re",
    "gt",
    "gte",
    "lt",
    "lte",
    "all",
}
_RESERVED = {"condition", "timeframe", "group_by"}
_LEVELS = {"informational", "low", "medium", "high", "critical"}


@dataclass
class Rule:
    name: str
    path: Path
    title: str
    uid: str
    level: str
    description: str
    logsource: dict
    selections: dict
    condition: tuple
    aggregation: dict | None
    timeframe: timedelta | None
    group_by: list[str]
    correlation: dict | None
    attack: list[dict]
    hipaa: dict
    triage: str
    playbook_path: str
    playbook_md: str
    falsepositives: list[str]
    tags: list[str]
    author: str
    raw: dict = field(repr=False)


def load_rules(directory: Path | None = None) -> list[Rule]:
    directory = directory or (ROOT / "rules")
    rules = [load_rule(path) for path in sorted(directory.glob("*.yml"))]
    names = {rule.name for rule in rules}
    for rule in rules:
        parent = (rule.correlation or {}).get("after_rule")
        if parent and parent not in names:
            raise ValueError(f"{rule.name} follows unknown rule {parent}")
    return rules


def load_rule(path: Path) -> Rule:
    raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    name = path.stem
    detection = dict(raw["detection"])
    condition_text = detection.pop("condition")
    timeframe = _parse_duration(detection.pop("timeframe", None))
    group_by = list(detection.pop("group_by", []) or [])
    for key in list(detection):
        if key in _RESERVED:
            raise ValueError(f"{name}: unexpected detection key {key}")
    selections = detection
    condition, aggregation = _parse_condition(condition_text)
    _check_names(name, condition, selections)
    correlation = raw.get("correlation")
    if correlation and aggregation:
        raise ValueError(f"{name}: correlation rules cannot aggregate")
    level = raw["level"]
    if level not in _LEVELS:
        raise ValueError(f"{name}: bad level {level}")
    playbook_rel = raw["playbook"]
    playbook_file = ROOT / playbook_rel
    if not playbook_file.is_file():
        raise ValueError(f"{name}: missing playbook {playbook_rel}")
    hipaa = raw["hipaa"]
    for key in ("concern", "minimum_necessary", "breach_notification"):
        if key not in hipaa:
            raise ValueError(f"{name}: hipaa.{key} is required")
    if not raw.get("attack"):
        raise ValueError(f"{name}: attack mapping is required")
    _validate_modifiers(name, selections)
    return Rule(
        name=name,
        path=path,
        title=raw["title"].strip(),
        uid=str(raw["id"]),
        level=level,
        description=_as_text(raw.get("description", "")),
        logsource=dict(raw["logsource"]),
        selections=selections,
        condition=condition,
        aggregation=aggregation,
        timeframe=timeframe,
        group_by=group_by,
        correlation=dict(correlation) if correlation else None,
        attack=list(raw["attack"]),
        hipaa={key: _as_text(hipaa[key]) for key in hipaa},
        triage=_as_text(raw.get("triage", "")),
        playbook_path=playbook_rel,
        playbook_md=playbook_file.read_text(encoding="utf-8"),
        falsepositives=list(raw.get("falsepositives") or []),
        tags=list(raw.get("tags") or []),
        author=raw.get("author", ""),
        raw=raw,
    )


def event_matches(rule: Rule, event: dict) -> bool:
    if not _logsource_ok(rule, event):
        return False
    return _eval_expr(rule.condition, event, rule.selections)


def _logsource_ok(rule: Rule, event: dict) -> bool:
    for key, expected in rule.logsource.items():
        actual = event.get(f"_{key}")
        if actual is None or str(actual).casefold() != str(expected).casefold():
            return False
    return True


def _eval_expr(expr: tuple, event: dict, selections: dict) -> bool:
    kind = expr[0]
    if kind == "sel":
        return _match_selection(event, selections[expr[1]])
    if kind == "not":
        return not _eval_expr(expr[1], event, selections)
    if kind == "and":
        return _eval_expr(expr[1], event, selections) and _eval_expr(expr[2], event, selections)
    if kind == "or":
        return _eval_expr(expr[1], event, selections) or _eval_expr(expr[2], event, selections)
    raise ValueError(kind)


def _match_selection(event: dict, selection: dict) -> bool:
    return all(_match_field(event, key, expected) for key, expected in selection.items())


def _match_field(event: dict, key: str, expected) -> bool:
    field_name, mods = _split_field(key)
    value = event.get(field_name)
    if isinstance(expected, list):
        checks = [_match_one(value, mods, item) for item in expected]
        return all(checks) if "all" in mods else any(checks)
    return _match_one(value, mods, expected)


def _match_one(value, mods: list[str], expected) -> bool:
    if value is None:
        return False
    if "re" in mods:
        return re.search(str(expected), str(value), flags=re.IGNORECASE) is not None
    if any(name in mods for name in ("gt", "gte", "lt", "lte")):
        return _match_number(value, mods, expected)
    if any(name in mods for name in ("contains", "startswith", "endswith")):
        haystack = str(value).casefold()
        needle = str(expected).casefold()
        if "contains" in mods and needle not in haystack:
            return False
        if "startswith" in mods and not haystack.startswith(needle):
            return False
        if "endswith" in mods and not haystack.endswith(needle):
            return False
        return True
    if isinstance(expected, bool):
        return isinstance(value, bool) and value is expected
    if isinstance(expected, (int, float)) and not isinstance(expected, bool):
        try:
            return float(value) == float(expected)
        except (TypeError, ValueError):
            return False
    return str(value).casefold() == str(expected).casefold()


def _match_number(value, mods: list[str], expected) -> bool:
    try:
        left = float(value)
        right = float(expected)
    except (TypeError, ValueError):
        return False
    if "gt" in mods:
        return left > right
    if "gte" in mods:
        return left >= right
    if "lt" in mods:
        return left < right
    if "lte" in mods:
        return left <= right
    return False


def _split_field(key: str) -> tuple[str, list[str]]:
    parts = key.split("|")
    mods = parts[1:]
    unknown = [mod for mod in mods if mod not in _MODIFIERS]
    if unknown:
        raise ValueError(f"unknown modifier on {key}: {unknown}")
    return parts[0], mods


def _validate_modifiers(rule_name: str, selections: dict) -> None:
    for selection in selections.values():
        for key in selection:
            try:
                _split_field(key)
            except ValueError as exc:
                raise ValueError(f"{rule_name}: {exc}") from exc


def _parse_duration(value) -> timedelta | None:
    if value is None:
        return None
    text = str(value).strip()
    unit = text[-1]
    amount = int(text[:-1])
    scale = {"s": "seconds", "m": "minutes", "h": "hours"}
    if unit not in scale:
        raise ValueError(f"bad timeframe {value}")
    return timedelta(**{scale[unit]: amount})


def _parse_condition(text: str) -> tuple[tuple, dict | None]:
    tokens = _TOKEN.findall(text)
    if not tokens:
        raise ValueError(f"empty condition: {text!r}")
    joined = "".join(tokens)
    compact = "".join(re.findall(r"\S+", text))
    # Reject characters the tokenizer would silently drop, such as quotes.
    if joined != compact:
        raise ValueError(f"condition has unsupported characters: {text}")
    parser = _Parser(tokens)
    expr = parser.parse_or()
    aggregation = None
    if parser.peek() == "|":
        parser.pop()
        aggregation = parser.parse_agg()
    if parser.peek() is not None:
        raise ValueError(f"trailing token {parser.peek()} in {text}")
    return expr, aggregation


def _check_names(rule_name: str, expr: tuple, selections: dict) -> None:
    needed = _names_in(expr)
    unknown = needed - set(selections)
    if unknown:
        raise ValueError(f"{rule_name}: condition uses unknown selection {unknown}")


def _names_in(expr: tuple) -> set[str]:
    if expr[0] == "sel":
        return {expr[1]}
    if expr[0] == "not":
        return _names_in(expr[1])
    return _names_in(expr[1]) | _names_in(expr[2])


class _Parser:
    def __init__(self, tokens: list[str]):
        self.tokens = tokens
        self.index = 0

    def peek(self) -> str | None:
        if self.index >= len(self.tokens):
            return None
        return self.tokens[self.index]

    def pop(self, expected: str | None = None) -> str:
        token = self.peek()
        if token is None:
            raise ValueError(f"condition ended, expected {expected or 'a token'}")
        if expected is not None and token != expected:
            raise ValueError(f"expected {expected}, got {token}")
        self.index += 1
        return token

    def parse_or(self) -> tuple:
        node = self.parse_and()
        while self.peek() == "or":
            self.pop()
            node = ("or", node, self.parse_and())
        return node

    def parse_and(self) -> tuple:
        node = self.parse_not()
        while self.peek() == "and":
            self.pop()
            node = ("and", node, self.parse_not())
        return node

    def parse_not(self) -> tuple:
        if self.peek() == "not":
            self.pop()
            return ("not", self.parse_not())
        return self.parse_atom()

    def parse_atom(self) -> tuple:
        if self.peek() == "(":
            self.pop()
            node = self.parse_or()
            self.pop(")")
            return node
        name = self.pop()
        if name in {"or", "and", "not", "count", "by", "distinct"} or name[0].isdigit():
            raise ValueError(f"expected a selection name, got {name}")
        return ("sel", name)

    def parse_agg(self) -> dict:
        self.pop("count")
        self.pop("(")
        distinct = None
        if self.peek() == "distinct":
            self.pop("distinct")
            distinct = self.pop()
        elif self.peek() != ")":
            raise ValueError("use count() or count(distinct field)")
        self.pop(")")
        self.pop("by")
        groups = [self.pop()]
        while self.peek() == ",":
            self.pop(",")
            groups.append(self.pop())
        op = self.pop()
        if op not in {">", ">=", "<", "<="}:
            raise ValueError(f"bad comparison {op}")
        threshold = int(self.pop())
        return {
            "distinct": distinct,
            "group": groups,
            "op": op,
            "threshold": threshold,
        }


def _as_text(value) -> str:
    if value is None:
        return ""
    return str(value).strip()


def compare(value: int, op: str, threshold: int) -> bool:
    if op == ">":
        return value > threshold
    if op == ">=":
        return value >= threshold
    if op == "<":
        return value < threshold
    if op == "<=":
        return value <= threshold
    raise ValueError(op)
