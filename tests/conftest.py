"""Put the package on the path and share small event builders."""

from __future__ import annotations

import sys
from datetime import datetime, timedelta
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from clinic_soc.engine import detect  # noqa: E402
from clinic_soc.sigma import load_rules  # noqa: E402
from clinic_soc.sources import SOURCES  # noqa: E402

ANCHOR = datetime.fromisoformat("2026-11-12T22:00:00-06:00")


def ev(source: str, minutes: int = 0, **fields) -> dict:
    product, service = SOURCES[source]
    moment = ANCHOR + timedelta(minutes=minutes)
    event = {
        "timestamp": moment.isoformat(),
        "_source": source,
        "_product": product,
        "_service": service,
    }
    event.update(fields)
    return event


def run(rule_names, events):
    wanted = set(rule_names)
    rules = [rule for rule in load_rules() if rule.name in wanted]
    missing = wanted - {rule.name for rule in rules}
    assert not missing, missing
    return detect(events, rules)
