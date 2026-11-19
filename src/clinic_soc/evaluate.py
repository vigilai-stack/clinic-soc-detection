"""Compare alerts to the planted-case labels.

The generator writes labels. The detector never reads them. This module
is the practice scorecard: did each planted case produce the alert we
expected, for the account or address we expected?
"""

from __future__ import annotations


def evaluate(alerts: list[dict], labels: dict) -> list[dict]:
    rows = []
    for scenario in labels.get("scenarios", []):
        entity = scenario.get("entity") or {}
        for rule_name in scenario.get("expect", []):
            hits = [
                alert["id"]
                for alert in alerts
                if alert["rule_name"] == rule_name and _entity_ok(alert, entity)
            ]
            rows.append(
                {
                    "scenario": scenario["id"],
                    "title": scenario.get("title", scenario["id"]),
                    "detail": scenario.get("detail", ""),
                    "rule": rule_name,
                    "ok": bool(hits),
                    "alert_ids": hits,
                }
            )
    return rows


def _entity_ok(alert: dict, entity: dict) -> bool:
    actual = alert.get("entities") or {}
    return all(actual.get(key) == value for key, value in entity.items())
