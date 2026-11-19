"""The sample day, end to end, including the planted cases and the quiet ones."""

import json
import re
from pathlib import Path

from clinic_soc.clinic import load_clinic
from clinic_soc.engine import detect
from clinic_soc.generate import generate, load_logs, stamp
from clinic_soc.pipeline import run_pipeline
from clinic_soc.sigma import load_rules

IP = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
SSN = re.compile(r"\b\d{3}-\d{2}-\d{4}\b")


def _allowed_ip(value: str) -> bool:
    parts = tuple(int(piece) for piece in value.split("."))
    if any(part > 255 for part in parts):
        return False
    if value == "127.0.0.1":
        return True
    if parts[0] == 10 and parts[1] == 20:
        return True
    return parts[:3] in {(192, 0, 2), (198, 51, 100), (203, 0, 113)}


def test_sample_day_catches_planted_cases_and_leaves_benign_work_alone(tmp_path: Path):
    result = run_pipeline(seed=42, out=tmp_path, clinic=load_clinic())
    alerts = result["alerts"]
    fired = {alert["rule_name"] for alert in alerts}
    loaded = {rule.name for rule in load_rules()}
    labeled = {rule for scenario in result["labels"]["scenarios"] for rule in scenario["expect"]}
    assert labeled == loaded
    assert fired == loaded
    assert all(row["ok"] for row in result["evaluation"])

    def of(rule):
        return [alert for alert in alerts if alert["rule_name"] == rule]

    stuffing = of("portal_credential_stuffing")
    assert len(stuffing) == 1
    assert stuffing[0]["entities"]["src_ip"] == "198.51.100.23"

    vpn = of("vpn_untrusted_country")
    assert [alert["entities"]["user"] for alert in vpn] == ["david.nguyen"]

    after_hours = of("ehr_after_hours_bulk_view")
    assert [alert["entities"]["user"] for alert in after_hours] == ["david.nguyen"]

    low = of("ehr_minimum_necessary")
    assert any(
        alert["entities"].get("user") == "maria.chen" and alert["entities"].get("match_count") == 1
        for alert in low
    )
    assert {alert["entities"]["user"] for alert in of("ehr_minimum_necessary_bulk")} == {
        "maria.chen",
        "david.nguyen",
    }
    assert [alert["entities"]["user"] for alert in of("ehr_bulk_export")] == ["maria.chen"]

    for alert in alerts:
        if alert["rule_name"].startswith("ehr_"):
            assert alert["entities"].get("user") not in {
                "alex.morgan",
                "james.okonkwo",
                "priya.shah",
                "avery.brooks",
                "sam.patel",
            }

    assert [alert["entities"]["dst_ip"] for alert in of("fw_large_outbound")] == ["203.0.113.199"]
    assert [alert["entities"]["TargetUserName"] for alert in of("win_rdp_to_server")] == ["maria.chen"]
    assert [alert["entities"]["IpAddress"] for alert in of("win_service_account_from_workstation")] == [
        "10.20.1.11"
    ]
    inhibit = of("win_inhibit_recovery")
    assert len(inhibit) == 1
    assert inhibit[0]["entities"]["Computer"].startswith("FS-01")
    assert "vssadmin delete shadows" in json.dumps(inhibit[0]["evidence"])
    powershell = of("win_encoded_powershell")
    assert len(powershell) == 1
    assert "inventory.ps1" not in json.dumps(powershell[0]["evidence"])
    macro = of("email_macro_delivered")
    assert len(macro) == 1
    assert macro[0]["entities"]["attachment_name"] == "invoice.docm"
    assert [alert["entities"]["recipient"] for alert in of("email_export_to_webmail")] == [
        "maria.personal@gmail.com"
    ]
    assert of("win_local_admin_added")[0]["entities"]["MemberName"] == "helpdesk"
    assert of("win_security_log_cleared")[0]["entities"]["Computer"].startswith("WS-FRONT-01")

    report = (tmp_path / "report.html").read_text(encoding="utf-8")
    assert "Riverside Family Clinic" in report
    assert "Timeline" in report
    assert "ATT&amp;CK coverage" in report
    assert "Synthetic data" in report
    assert "missing" not in report.split("Planted cases")[1].split("<h2>")[0]

    summary = (tmp_path / "summary.txt").read_text(encoding="utf-8")
    assert "Planted checks:" in summary
    assert result["stats"]["events"] > 100


def test_generation_is_deterministic_and_synthetic():
    clinic = load_clinic()
    first_logs, first_labels = generate(clinic, seed=7)
    second_logs, second_labels = generate(clinic, seed=7)
    assert first_logs == second_logs
    assert first_labels == second_labels
    other_logs, _other_labels = generate(clinic, seed=8)
    assert other_logs != first_logs

    blob = json.dumps(first_logs)
    assert SSN.search(blob) is None
    assert re.search(r"\bssn\b", blob, flags=re.IGNORECASE) is None
    for address in IP.findall(blob):
        assert _allowed_ip(address), address
    for events in first_logs.values():
        for event in events:
            if "patient_mrn" in event:
                assert re.fullmatch(r"MRN-\d{5}", event["patient_mrn"])


def test_detector_does_not_use_raw_flags_the_pipeline_is_supposed_to_add():
    clinic = load_clinic()
    logs, _labels = generate(clinic, seed=42)
    raw_alerts = detect(stamp(logs), load_rules())
    names = {alert.rule_name for alert in raw_alerts}
    assert "ehr_after_hours_bulk_view" not in names
    assert "ehr_minimum_necessary" not in names
    assert "vpn_untrusted_country" not in names
    assert "fw_large_outbound" not in names
    assert "email_export_to_webmail" not in names


def test_logs_round_trip_from_disk(tmp_path: Path):
    run_pipeline(seed=42, out=tmp_path, clinic=load_clinic())
    events = load_logs(tmp_path / "logs")
    assert events
    assert all("_service" in event and "timestamp" in event for event in events)
    # The answer key is not a log the detector loads.
    assert not (tmp_path / "logs" / "labels.json").exists()
