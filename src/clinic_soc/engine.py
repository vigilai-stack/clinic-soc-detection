"""Run clinic rules over events and build alerts."""

from __future__ import annotations

from collections import defaultdict, deque
from dataclasses import asdict, dataclass, field
from datetime import datetime

from clinic_soc.sigma import Rule, compare, event_matches
from clinic_soc.sources import ENTITY_FIELDS

MAX_EVIDENCE = 8


@dataclass
class Alert:
    id: str
    time: datetime
    match_start: datetime
    match_end: datetime
    rule_name: str
    rule_uid: str
    title: str
    severity: str
    summary: str
    triage: str
    description: str
    attack: list[dict]
    hipaa: dict
    playbook_path: str
    playbook_md: str
    falsepositives: list[str]
    entities: dict
    evidence_count: int
    evidence: list[dict]
    tags: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        payload = asdict(self)
        for key in ("time", "match_start", "match_end"):
            payload[key] = self._iso(payload[key])
        payload["evidence"] = [_public_event(item) for item in self.evidence]
        return payload

    @staticmethod
    def _iso(value: datetime) -> str:
        return value.isoformat()


def detect(events: list[dict], rules: list[Rule]) -> list[Alert]:
    prepared = [_with_time(event) for event in events]
    base_rules = [rule for rule in rules if not rule.correlation]
    follow_rules = [rule for rule in rules if rule.correlation]
    alerts: list[Alert] = []
    for rule in base_rules:
        matched = [event for event in prepared if event_matches(rule, event)]
        if rule.aggregation:
            alerts.extend(_aggregate(rule, matched))
        else:
            alerts.extend(_collapse(rule, matched))
    for rule in follow_rules:
        alerts.extend(_correlate(rule, alerts, prepared))
    alerts.sort(key=lambda alert: (alert.time, alert.rule_name, _entity_key(alert)))
    for index, alert in enumerate(alerts, start=1):
        alert.id = f"ALT-{index:03d}"
    return alerts


def _aggregate(rule: Rule, events: list[dict]) -> list[Alert]:
    spec = rule.aggregation
    if rule.timeframe is None:
        raise ValueError(f"{rule.name} aggregates without a timeframe")
    window = rule.timeframe
    grouped: dict[tuple, deque] = defaultdict(deque)
    last_emit: dict[tuple, datetime] = {}
    found: list[Alert] = []
    for event in sorted(events, key=lambda item: item["_time"]):
        key = _group_key(event, spec["group"])
        if key is None:
            continue
        bucket = grouped[key]
        bucket.append(event)
        cutoff = event["_time"] - window
        while bucket and bucket[0]["_time"] < cutoff:
            bucket.popleft()
        if spec["distinct"]:
            value = len({item.get(spec["distinct"]) for item in bucket})
        else:
            value = len(bucket)
        if not compare(value, spec["op"], spec["threshold"]):
            continue
        previous = last_emit.get(key)
        if previous is not None and event["_time"] - previous < window:
            continue
        last_emit[key] = event["_time"]
        evidence = list(bucket)
        entities = {field_name: key[index] for index, field_name in enumerate(spec["group"])}
        entities["match_count"] = value
        distinct_note = (
            f"{value} distinct {spec['distinct']}"
            if spec["distinct"]
            else f"{value} events"
        )
        group_note = ", ".join(f"{name} {entities[name]}" for name in spec["group"])
        summary = (
            f"{rule.title}. {distinct_note} for {group_note} "
            f"inside { _window_label(window) } (threshold {spec['op']} {spec['threshold']})."
        )
        found.append(_make_alert(rule, evidence, entities, summary))
    return found


def _collapse(rule: Rule, events: list[dict]) -> list[Alert]:
    ordered = sorted(events, key=lambda item: item["_time"])
    if not rule.group_by or rule.timeframe is None:
        return [_single(rule, event) for event in ordered]
    open_groups: dict[tuple, list[dict]] = {}
    closed: list[list[dict]] = []
    for event in ordered:
        key = _group_key(event, rule.group_by)
        if key is None:
            closed.append([event])
            continue
        current = open_groups.get(key)
        if current and event["_time"] - current[0]["_time"] <= rule.timeframe:
            current.append(event)
            continue
        if current:
            closed.append(current)
        open_groups[key] = [event]
    closed.extend(open_groups.values())
    found = []
    for evidence in closed:
        entities = {
            name: evidence[0].get(name)
            for name in ENTITY_FIELDS
            if evidence[0].get(name) not in (None, "")
        }
        for name in rule.group_by:
            entities[name] = evidence[0].get(name)
        entities["match_count"] = len(evidence)
        summary = f"{rule.title}. {_phrase(entities)}."
        found.append(_make_alert(rule, evidence, entities, summary))
    return found


def _single(rule: Rule, event: dict) -> Alert:
    entities = {
        name: event.get(name)
        for name in ENTITY_FIELDS
        if event.get(name) not in (None, "")
    }
    entities["match_count"] = 1
    return _make_alert(rule, [event], entities, f"{rule.title}. {_phrase(entities)}.")


def _correlate(rule: Rule, prior: list[Alert], events: list[dict]) -> list[Alert]:
    spec = rule.correlation
    window = _parse_within(spec["within"])
    join_field = spec["join"]
    parents = [alert for alert in prior if alert.rule_name == spec["after_rule"]]
    found: list[Alert] = []
    used: set[int] = set()
    for parent in parents:
        pivot = parent.entities.get(join_field)
        if pivot is None:
            continue
        end = parent.match_end + window
        matched = []
        for event in events:
            if id(event) in used:
                continue
            if not event_matches(rule, event):
                continue
            if event.get(join_field) != pivot:
                continue
            if parent.match_start <= event["_time"] <= end:
                matched.append(event)
        if not matched:
            continue
        for event in matched:
            used.add(id(event))
        entities = {
            name: matched[0].get(name)
            for name in ENTITY_FIELDS
            if matched[0].get(name) not in (None, "")
        }
        entities[join_field] = pivot
        entities["after_rule"] = parent.rule_name
        entities["match_count"] = len(matched)
        summary = (
            f"{rule.title}. {join_field} {pivot} had {parent.rule_name} "
            f"and then {len(matched)} matching event(s)."
        )
        found.append(_make_alert(rule, matched, entities, summary))
    return found


def _make_alert(rule: Rule, evidence: list[dict], entities: dict, summary: str) -> Alert:
    start = min(item["_time"] for item in evidence)
    end = max(item["_time"] for item in evidence)
    return Alert(
        id="",
        time=end,
        match_start=start,
        match_end=end,
        rule_name=rule.name,
        rule_uid=rule.uid,
        title=rule.title,
        severity=rule.level,
        summary=summary,
        triage=rule.triage,
        description=rule.description,
        attack=rule.attack,
        hipaa=rule.hipaa,
        playbook_path=rule.playbook_path,
        playbook_md=rule.playbook_md,
        falsepositives=rule.falsepositives,
        entities=entities,
        evidence_count=len(evidence),
        evidence=evidence[:MAX_EVIDENCE],
        tags=rule.tags,
    )


def _with_time(event: dict) -> dict:
    stamped = dict(event)
    raw = event.get("timestamp")
    if isinstance(raw, datetime):
        moment = raw
    else:
        moment = datetime.fromisoformat(str(raw))
    if moment.tzinfo is None:
        raise ValueError(f"timestamp needs a timezone offset: {raw}")
    stamped["_time"] = moment
    return stamped


def _group_key(event: dict, fields: list[str]) -> tuple | None:
    values = []
    for name in fields:
        value = event.get(name)
        if value is None or value == "":
            return None
        values.append(value)
    return tuple(values)


def _phrase(entities: dict) -> str:
    parts = [
        f"{name} {value}"
        for name, value in entities.items()
        if name not in {"match_count", "after_rule"}
    ]
    return ", ".join(parts) if parts else "matching event"


def _entity_key(alert: Alert) -> str:
    return "|".join(f"{key}={alert.entities[key]}" for key in sorted(alert.entities))


def _window_label(window) -> str:
    seconds = int(window.total_seconds())
    if seconds % 3600 == 0:
        return f"{seconds // 3600}h"
    if seconds % 60 == 0:
        return f"{seconds // 60}m"
    return f"{seconds}s"


def _parse_within(value: str):
    from clinic_soc.sigma import _parse_duration

    parsed = _parse_duration(value)
    if parsed is None:
        raise ValueError(value)
    return parsed


def _public_event(event: dict) -> dict:
    hidden = {"_time"}
    public = {}
    for key, value in event.items():
        if key in hidden:
            continue
        if isinstance(value, datetime):
            public[key] = value.isoformat()
        else:
            public[key] = value
    return public
