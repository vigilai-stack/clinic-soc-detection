"""Add the fields rules rely on, from the clinic roster and the clock.

Raw EHR audits say who opened a chart and when. They do not say whether
that was after close, whether the person was on call, or whether the
job is allowed to see that kind of record. A small pipeline would join
the roster and the business calendar. This step is that join.

Recomputed fields are replaced even if a log line already has them.
The detector then trusts the pipeline, not a value typed into the log.
"""

from __future__ import annotations

from datetime import datetime

from clinic_soc.clinic import is_after_hours, is_on_call, role_allows, users_by_name


def enrich(events: list[dict], clinic: dict) -> list[dict]:
    directory = users_by_name(clinic)
    allow_ips = set(clinic["allowlists"]["egress_ips"])
    webmail = {item.casefold() for item in clinic["allowlists"]["webmail_domains"]}
    countries = {item.casefold() for item in clinic["allowlists"]["vpn_countries"]}
    enriched = []
    for event in events:
        item = dict(event)
        moment = _time(item)
        service = item.get("_service")
        if service == "ehr":
            _enrich_ehr(item, moment, clinic, directory)
        elif service == "firewall":
            item["dst_allowlisted"] = item.get("dst_ip") in allow_ips
        elif service == "vpn":
            country = str(item.get("country") or "")
            if country:
                item["country_allowlisted"] = country.casefold() in countries
        elif service == "email":
            item["recipient_webmail"] = _domain(item.get("recipient", "")) in webmail
        enriched.append(item)
    return enriched


def _enrich_ehr(item: dict, moment: datetime, clinic: dict, directory: dict) -> None:
    user = directory.get(item.get("user"))
    role = user["role"] if user else "unknown"
    record_type = item.get("record_type", "")
    item["role"] = role
    item["after_hours"] = is_after_hours(moment, clinic)
    item["on_call"] = is_on_call(str(item.get("user")), moment, clinic)
    item["role_allows_record"] = role_allows(clinic, role, record_type)


def _domain(address: str) -> str:
    if "@" not in address:
        return ""
    return address.rsplit("@", 1)[1].casefold()


def _time(event: dict) -> datetime:
    raw = event.get("timestamp")
    if isinstance(raw, datetime):
        moment = raw
    else:
        moment = datetime.fromisoformat(str(raw))
    if moment.tzinfo is None:
        raise ValueError(f"timestamp needs a timezone offset: {raw}")
    return moment
