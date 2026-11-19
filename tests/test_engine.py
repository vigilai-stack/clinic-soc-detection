"""Engine, enrichment, and report behavior that is not one rule's sample."""

from datetime import datetime, timedelta

from clinic_soc.clinic import is_after_hours, is_on_call, load_clinic, role_allows
from clinic_soc.enrich import enrich
from clinic_soc.report import build_html
from clinic_soc.sigma import _parse_condition, load_rules

from conftest import ev, run


def test_and_binds_tighter_than_or():
    expr, _agg = _parse_condition("left or right and not skipped")
    # or( left, and( right, not skipped ) )
    assert expr[0] == "or"
    assert expr[2][0] == "and"
    assert expr[2][2][0] == "not"


def test_distinct_threshold_and_window():
    rule = "portal_credential_stuffing"
    ten = [
        ev("portal", minutes=i, username=f"p{i}", src_ip="198.51.100.23", result="failure")
        for i in range(10)
    ]
    assert run([rule], ten) == []
    eleven = ten + [
        ev("portal", minutes=10, username="p10", src_ip="198.51.100.23", result="failure")
    ]
    assert len(run([rule], eleven)) == 1
    split = [
        ev("portal", minutes=i, username=f"early{i}", src_ip="198.51.100.23", result="failure")
        for i in range(6)
    ] + [
        ev("portal", minutes=20 + i, username=f"late{i}", src_ip="198.51.100.23", result="failure")
        for i in range(5)
    ]
    assert run([rule], split) == []


def test_correlation_respects_address_and_time():
    rules = ["portal_credential_stuffing", "portal_success_after_stuffing"]
    failures = [
        ev("portal", minutes=i, username=f"p{i}", src_ip="198.51.100.23", result="failure")
        for i in range(11)
    ]
    success = ev(
        "portal", minutes=15, username="p1", src_ip="198.51.100.23", result="success"
    )
    alerts = run(rules, failures + [success])
    assert any(alert.rule_name == "portal_success_after_stuffing" for alert in alerts)

    other_ip = ev(
        "portal", minutes=15, username="p1", src_ip="198.51.100.44", result="success"
    )
    alerts = run(rules, failures + [other_ip])
    assert not any(alert.rule_name == "portal_success_after_stuffing" for alert in alerts)

    late = ev(
        "portal", minutes=11 + 31, username="p1", src_ip="198.51.100.23", result="success"
    )
    alerts = run(rules, failures + [late])
    assert not any(alert.rule_name == "portal_success_after_stuffing" for alert in alerts)

    # No stuffing alert, so a normal success is not "after stuffing".
    small = [
        ev("portal", minutes=i, username=f"p{i}", src_ip="198.51.100.23", result="failure")
        for i in range(3)
    ]
    small.append(success)
    assert run(rules, small) == []


def test_execution_policy_is_not_encoded_powershell():
    command = (
        "powershell.exe -ExecutionPolicy Bypass -File C:\\clinic-it\\inventory.ps1"
    )
    event = ev(
        "windows",
        EventID=4688,
        NewProcessName=r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
        CommandLine=command,
        SubjectUserName="sam.patel",
        Computer="WS-IT-01.riverside.local",
    )
    assert run(["win_encoded_powershell"], [event]) == []


def test_business_hours_and_roster():
    clinic = load_clinic()
    thursday_open = datetime.fromisoformat("2026-11-12T18:59:00-06:00")
    thursday_closed = datetime.fromisoformat("2026-11-12T19:00:00-06:00")
    sunday = datetime.fromisoformat("2026-11-15T10:00:00-06:00")
    assert is_after_hours(thursday_open, clinic) is False
    assert is_after_hours(thursday_closed, clinic) is True
    assert is_after_hours(sunday, clinic) is True
    assert is_on_call("priya.shah", thursday_closed, clinic) is True
    assert is_on_call("david.nguyen", thursday_closed, clinic) is False
    assert role_allows(clinic, "billing", "clinical_note") is False
    assert role_allows(clinic, "front_desk", "scheduling") is True
    assert role_allows(clinic, "rn", "clinical_note") is True
    assert role_allows(clinic, "it", "clinical_note") is False


def test_enrichment_recomputes_owned_fields():
    clinic = load_clinic()
    event = ev(
        "ehr",
        minutes=0,
        user="david.nguyen",
        patient_mrn="MRN-10001",
        action="view",
        record_type="clinical_note",
        break_glass=False,
        access_reason="",
        after_hours=False,
        on_call=True,
        role="rn",
        role_allows_record=True,
    )
    # 22:00 clinic time is after close. The log's own flags are wrong on purpose.
    [fixed] = enrich([event], clinic)
    assert fixed["after_hours"] is True
    assert fixed["on_call"] is False
    assert fixed["role"] == "billing"
    assert fixed["role_allows_record"] is False

    firewall = ev(
        "firewall",
        action="allow",
        direction="outbound",
        dst_ip="203.0.113.50",
        dst_allowlisted=False,
    )
    webmail = ev("email", recipient="a@gmail.com", recipient_webmail=False)
    vpn = ev("vpn", country="DE", country_allowlisted=True)
    enriched = {item["_service"]: item for item in enrich([firewall, webmail, vpn], clinic)}
    assert enriched["firewall"]["dst_allowlisted"] is True
    assert enriched["email"]["recipient_webmail"] is True
    assert enriched["vpn"]["country_allowlisted"] is False


def test_report_escapes_hostile_text():
    hostile = "<script>alert(1)</script>"
    clinic = load_clinic()
    alert = {
        "id": "ALT-001",
        "time": "2026-11-12T22:00:00-06:00",
        "match_start": "2026-11-12T22:00:00-06:00",
        "match_end": "2026-11-12T22:05:00-06:00",
        "rule_name": "example",
        "rule_uid": "uid",
        "title": hostile,
        "severity": "high",
        "summary": hostile,
        "triage": "Look at the account.",
        "description": "desc",
        "attack": [{"id": "T0000", "name": "Example", "tactic": "Test"}],
        "hipaa": {
            "concern": "c",
            "minimum_necessary": "m",
            "breach_notification": "b",
        },
        "playbook_path": "playbooks/x.md",
        "playbook_md": "# Title\n\n- " + hostile,
        "falsepositives": [],
        "entities": {"user": hostile},
        "evidence_count": 1,
        "evidence": [{"user": hostile, "timestamp": "2026-11-12T22:00:00-06:00"}],
        "tags": [],
    }
    page = build_html(
        clinic,
        {"seed": 1, "events": 1, "by_source": {"ehr": 1}, "report_path": "out/report.html"},
        [alert],
        [],
        load_rules(),
    )
    assert hostile not in page
    assert "&lt;script&gt;" in page


def test_every_rule_file_loads_and_has_a_playbook():
    rules = load_rules()
    assert len(rules) >= 16
    names = [rule.name for rule in rules]
    assert len(names) == len(set(names))
    for rule in rules:
        assert rule.playbook_md.startswith("#")
        assert rule.attack
        assert rule.triage
