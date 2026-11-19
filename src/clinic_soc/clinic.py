"""Load the clinic configuration and resolve paths."""

from __future__ import annotations

from datetime import datetime, time
from pathlib import Path
from zoneinfo import ZoneInfo

import yaml

ROOT = Path(__file__).resolve().parents[2]
CLINIC_PATH = ROOT / "config" / "clinic.yaml"


def load_clinic(path: Path | None = None) -> dict:
    path = path or CLINIC_PATH
    with path.open(encoding="utf-8") as handle:
        data = yaml.safe_load(handle)
    if not isinstance(data, dict):
        raise ValueError(f"{path} did not contain a mapping")
    data["_path"] = str(path)
    return data


def timezone(clinic: dict) -> ZoneInfo:
    return ZoneInfo(clinic["timezone"])


def sample_day_start(clinic: dict) -> datetime:
    year, month, day = (int(part) for part in clinic["sample_day"].split("-"))
    return datetime(year, month, day, tzinfo=timezone(clinic))


def users_by_name(clinic: dict) -> dict[str, dict]:
    return {user["user"]: user for user in clinic["users"]}


def hosts_by_name(clinic: dict) -> dict[str, dict]:
    return {host["name"]: host for host in clinic["hosts"]}


def parse_hhmm(value: str) -> time:
    hour, minute = value.split(":")
    return time(int(hour), int(minute))


def is_after_hours(moment: datetime, clinic: dict) -> bool:
    """True when the clinic is closed in its own timezone.

    The end of business hours is exclusive: 19:00 is after hours when the
    schedule says the clinic closes at 19:00. A day with no hours (the
    weekend, in this clinic) is after hours all day.
    """
    local = moment.astimezone(timezone(clinic))
    key = ("mon", "tue", "wed", "thu", "fri", "sat", "sun")[local.weekday()]
    window = clinic["business_hours"].get(key)
    if not window:
        return True
    start = parse_hhmm(window[0])
    end = parse_hhmm(window[1])
    return not (start <= local.time() < end)


def is_on_call(user: str, moment: datetime, clinic: dict) -> bool:
    local_day = moment.astimezone(timezone(clinic)).date().isoformat()
    roster = clinic.get("on_call", {}).get(local_day, []) or []
    return user in roster


def role_allows(clinic: dict, role: str, record_type: str) -> bool:
    roles = clinic["roles"]
    if role not in roles:
        return False
    return record_type in roles[role]["allowed_record_types"]
