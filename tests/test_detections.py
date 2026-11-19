"""True positive and false positive for every detection."""

import pytest

from conftest import ev, run

FRONT = "WS-FRONT-01.riverside.local"
FILE_SERVER = "FS-01.riverside.local"
BACKUP = "BK-01.riverside.local"
POWERSHELL = r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
VSSADMIN = r"C:\Windows\System32\vssadmin.exe"


def portal_failures(count, ip="198.51.100.23", distinct=True, prefix="p"):
    events = []
    for index in range(count):
        username = f"{prefix}{index}" if distinct else f"{prefix}same"
        events.append(
            ev(
                "portal",
                minutes=index,
                username=username,
                src_ip=ip,
                result="failure",
                reason="bad_password",
            )
        )
    return events


def charts(count, **fields):
    return [
        ev("ehr", minutes=index, patient_mrn=f"MRN-{10001 + index}", **fields)
        for index in range(count)
    ]


CASES = []


def case(rule, kind, events, also=()):
    CASES.append({"rule": rule, "kind": kind, "events": events, "also": also})


case(
    "portal_credential_stuffing",
    "tp",
    portal_failures(11),
)
case(
    "portal_credential_stuffing",
    "fp_one_patient",
    portal_failures(12, distinct=False),
)
case(
    "portal_credential_stuffing",
    "fp_under_threshold",
    portal_failures(10),
)
case(
    "portal_credential_stuffing",
    "fp_monitor",
    portal_failures(12, ip="198.51.100.5", prefix="healthcheck-"),
)

case(
    "portal_success_after_stuffing",
    "tp",
    portal_failures(11)
    + [ev("portal", minutes=20, username="p1", src_ip="198.51.100.23", result="success")],
    also=("portal_credential_stuffing",),
)
case(
    "portal_success_after_stuffing",
    "fp_other_address",
    portal_failures(11)
    + [ev("portal", minutes=20, username="p1", src_ip="198.51.100.44", result="success")],
    also=("portal_credential_stuffing",),
)
case(
    "portal_success_after_stuffing",
    "fp_without_stuffing",
    portal_failures(4)
    + [ev("portal", minutes=6, username="p1", src_ip="198.51.100.23", result="success")],
    also=("portal_credential_stuffing",),
)

case(
    "ehr_after_hours_bulk_view",
    "tp",
    charts(
        16,
        user="david.nguyen",
        action="view",
        record_type="clinical_note",
        after_hours=True,
        on_call=False,
        break_glass=False,
    ),
)
case(
    "ehr_after_hours_bulk_view",
    "fp_on_call",
    charts(
        16,
        user="priya.shah",
        action="view",
        record_type="clinical_note",
        after_hours=True,
        on_call=True,
        break_glass=False,
    ),
)
case(
    "ehr_after_hours_bulk_view",
    "fp_small_panel",
    charts(
        8,
        user="alex.morgan",
        action="view",
        record_type="clinical_note",
        after_hours=True,
        on_call=False,
        break_glass=False,
    ),
)
case(
    "ehr_after_hours_bulk_view",
    "fp_billing_records",
    charts(
        16,
        user="david.nguyen",
        action="view",
        record_type="billing",
        after_hours=True,
        on_call=False,
        break_glass=False,
    ),
)

case(
    "ehr_minimum_necessary",
    "tp",
    [
        ev(
            "ehr",
            user="maria.chen",
            patient_mrn="MRN-10001",
            action="view",
            record_type="clinical_note",
            role_allows_record=False,
            break_glass=False,
            access_reason="",
        )
    ],
)
case(
    "ehr_minimum_necessary",
    "fp_allowed_role",
    [
        ev(
            "ehr",
            user="priya.shah",
            patient_mrn="MRN-10001",
            action="view",
            record_type="clinical_note",
            role_allows_record=True,
            break_glass=False,
            access_reason="",
        )
    ],
)
case(
    "ehr_minimum_necessary",
    "fp_break_glass",
    [
        ev(
            "ehr",
            user="sam.patel",
            patient_mrn="MRN-10001",
            action="view",
            record_type="clinical_note",
            role_allows_record=False,
            break_glass=True,
            access_reason="ticket 4412",
        )
    ],
)
case(
    "ehr_minimum_necessary",
    "fp_patient_release",
    [
        ev(
            "ehr",
            user="avery.brooks",
            patient_mrn="MRN-10001",
            action="export",
            record_type="clinical_note",
            role_allows_record=False,
            break_glass=False,
            access_reason="patient_release",
        )
    ],
)

case(
    "ehr_minimum_necessary_bulk",
    "tp",
    charts(
        9,
        user="david.nguyen",
        action="view",
        record_type="clinical_note",
        role_allows_record=False,
        break_glass=False,
        access_reason="",
    ),
)
case(
    "ehr_minimum_necessary_bulk",
    "fp_under_threshold",
    charts(
        8,
        user="david.nguyen",
        action="view",
        record_type="clinical_note",
        role_allows_record=False,
        break_glass=False,
        access_reason="",
    ),
)
case(
    "ehr_minimum_necessary_bulk",
    "fp_allowed_role",
    charts(
        12,
        user="alex.morgan",
        action="view",
        record_type="clinical_note",
        role_allows_record=True,
        break_glass=False,
        access_reason="",
    ),
)

case(
    "ehr_bulk_export",
    "tp",
    charts(
        11,
        user="maria.chen",
        action="export",
        record_type="clinical_note",
        break_glass=False,
    ),
)
case(
    "ehr_bulk_export",
    "fp_one_release",
    [
        ev(
            "ehr",
            user="avery.brooks",
            patient_mrn="MRN-10008",
            action="export",
            record_type="clinical_note",
            break_glass=False,
            access_reason="patient_release",
        )
    ],
)
case(
    "ehr_bulk_export",
    "fp_views_are_not_exports",
    charts(
        12,
        user="david.nguyen",
        action="view",
        record_type="clinical_note",
        break_glass=False,
    ),
)

case(
    "win_rdp_to_server",
    "tp",
    [
        ev(
            "windows",
            EventID=4624,
            LogonType=10,
            Computer=FILE_SERVER,
            TargetUserName="maria.chen",
            IpAddress="10.20.1.11",
        )
    ],
)
case(
    "win_rdp_to_server",
    "fp_it_account",
    [
        ev(
            "windows",
            EventID=4624,
            LogonType=10,
            Computer="EHR-APP-01.riverside.local",
            TargetUserName="sam.patel",
            IpAddress="10.20.1.17",
        )
    ],
)
case(
    "win_rdp_to_server",
    "fp_workstation_console",
    [
        ev(
            "windows",
            EventID=4624,
            LogonType=2,
            Computer=FRONT,
            TargetUserName="maria.chen",
            IpAddress="127.0.0.1",
        )
    ],
)

case(
    "win_service_account_from_workstation",
    "tp",
    [
        ev(
            "windows",
            EventID=4624,
            LogonType=3,
            TargetUserName="svc.ehr",
            IpAddress="10.20.1.11",
            Computer="EHR-APP-01.riverside.local",
        )
    ],
)
case(
    "win_service_account_from_workstation",
    "fp_backup_server",
    [
        ev(
            "windows",
            EventID=4624,
            LogonType=3,
            TargetUserName="svc.backup",
            IpAddress="10.20.2.30",
            Computer=FILE_SERVER,
        ),
        ev(
            "windows",
            EventID=4648,
            TargetUserName="svc.backup",
            Computer=BACKUP,
            IpAddress="10.20.2.30",
        ),
    ],
)

case(
    "win_inhibit_recovery",
    "tp",
    [
        ev(
            "windows",
            EventID=4688,
            Computer=FILE_SERVER,
            NewProcessName=VSSADMIN,
            CommandLine="vssadmin delete shadows /all /quiet",
            SubjectUserName="svc.ehr",
        )
    ],
)
case(
    "win_inhibit_recovery",
    "tp_via_cmd",
    [
        ev(
            "windows",
            EventID=4688,
            Computer=FILE_SERVER,
            NewProcessName=r"C:\Windows\System32\cmd.exe",
            CommandLine="cmd.exe /c vssadmin delete shadows /all /quiet",
            SubjectUserName="svc.ehr",
        )
    ],
)
case(
    "win_inhibit_recovery",
    "fp_list_shadows",
    [
        ev(
            "windows",
            EventID=4688,
            Computer=BACKUP,
            NewProcessName=VSSADMIN,
            CommandLine="vssadmin list shadows",
            SubjectUserName="svc.backup",
        )
    ],
)
case(
    "win_inhibit_recovery",
    "fp_start_backup",
    [
        ev(
            "windows",
            EventID=4688,
            Computer=BACKUP,
            NewProcessName=r"C:\Windows\System32\wbadmin.exe",
            CommandLine="wbadmin start backup -backupTarget:E: -include:D:\\ehr-exports -quiet",
            SubjectUserName="svc.backup",
        )
    ],
)
case(
    "win_inhibit_recovery",
    "fp_recovery_left_on",
    [
        ev(
            "windows",
            EventID=4688,
            Computer=FILE_SERVER,
            NewProcessName=r"C:\Windows\System32\bcdedit.exe",
            CommandLine="bcdedit /set {default} recoveryenabled yes",
            SubjectUserName="sam.patel",
        )
    ],
)

case(
    "win_encoded_powershell",
    "tp",
    [
        ev(
            "windows",
            EventID=4688,
            Computer=FRONT,
            NewProcessName=POWERSHELL,
            CommandLine="powershell.exe -NoP -enc SQBFAFgA",
            SubjectUserName="maria.chen",
        )
    ],
)
case(
    "win_encoded_powershell",
    "fp_inventory_script",
    [
        ev(
            "windows",
            EventID=4688,
            Computer="WS-IT-01.riverside.local",
            NewProcessName=POWERSHELL,
            CommandLine="powershell.exe -ExecutionPolicy Bypass -File C:\\clinic-it\\inventory.ps1",
            SubjectUserName="sam.patel",
        )
    ],
)

case(
    "fw_large_outbound",
    "tp",
    [
        ev(
            "firewall",
            action="allow",
            direction="outbound",
            src_ip="10.20.1.11",
            dst_ip="203.0.113.199",
            dst_port=443,
            bytes_out=850_000_000,
            dst_allowlisted=False,
        )
    ],
)
case(
    "fw_large_outbound",
    "fp_vendor_update",
    [
        ev(
            "firewall",
            action="allow",
            direction="outbound",
            src_ip="10.20.2.10",
            dst_ip="203.0.113.50",
            dst_port=443,
            bytes_out=250_000_000,
            dst_allowlisted=True,
        )
    ],
)
case(
    "fw_large_outbound",
    "fp_under_threshold",
    [
        ev(
            "firewall",
            action="allow",
            direction="outbound",
            src_ip="10.20.1.14",
            dst_ip="203.0.113.20",
            dst_port=443,
            bytes_out=100_000_000,
            dst_allowlisted=False,
        )
    ],
)

case(
    "email_export_to_webmail",
    "tp",
    [
        ev(
            "email",
            direction="outbound",
            sender="maria.chen@riverside-clinic.example",
            recipient="maria.personal@gmail.com",
            attachment_name="cedar_export_patients.csv",
            attachment_bytes=8_500_000,
            recipient_webmail=True,
            verdict="allowed",
        )
    ],
)
case(
    "email_export_to_webmail",
    "fp_statement_pdf",
    [
        ev(
            "email",
            direction="outbound",
            sender="billing@riverside-clinic.example",
            recipient="patient.mailbox@gmail.com",
            attachment_name="statement.pdf",
            attachment_bytes=60_000,
            recipient_webmail=True,
            verdict="allowed",
        )
    ],
)
case(
    "email_export_to_webmail",
    "fp_partner_domain",
    [
        ev(
            "email",
            direction="outbound",
            sender="records@riverside-clinic.example",
            recipient="roi@regionlab.example",
            attachment_name="panel.csv",
            attachment_bytes=5_000_000,
            recipient_webmail=False,
            verdict="allowed",
        )
    ],
)

case(
    "email_macro_delivered",
    "tp",
    [
        ev(
            "email",
            direction="inbound",
            sender="billing@rivrsid-clinic.example",
            recipient="maria.chen@riverside-clinic.example",
            attachment_name="invoice.docm",
            attachment_bytes=180_000,
            verdict="allowed",
        )
    ],
)
case(
    "email_macro_delivered",
    "fp_quarantine",
    [
        ev(
            "email",
            direction="inbound",
            sender="dropbox@unknown-mail.example",
            recipient="maria.chen@riverside-clinic.example",
            attachment_name="payroll.xlsm",
            attachment_bytes=240_000,
            verdict="quarantine",
        )
    ],
)
case(
    "email_macro_delivered",
    "fp_pdf",
    [
        ev(
            "email",
            direction="inbound",
            sender="results@regionlab.example",
            recipient="records@riverside-clinic.example",
            attachment_name="batch-884.pdf",
            attachment_bytes=80_000,
            verdict="allowed",
        )
    ],
)

case(
    "vpn_untrusted_country",
    "tp",
    [
        ev(
            "vpn",
            action="success",
            user="david.nguyen",
            src_ip="198.51.100.77",
            country="DE",
            country_allowlisted=False,
        )
    ],
)
case(
    "vpn_untrusted_country",
    "fp_us",
    [
        ev(
            "vpn",
            action="success",
            user="sam.patel",
            src_ip="198.51.100.81",
            country="US",
            country_allowlisted=True,
        )
    ],
)
case(
    "vpn_untrusted_country",
    "fp_failed_attempt",
    [
        ev(
            "vpn",
            action="failure",
            user="david.nguyen",
            src_ip="198.51.100.77",
            country="DE",
            country_allowlisted=False,
        )
    ],
)

case(
    "win_local_admin_added",
    "tp",
    [
        ev(
            "windows",
            EventID=4732,
            Computer=FRONT,
            SubjectUserName="maria.chen",
            TargetUserName="Administrators",
            MemberName="helpdesk",
        )
    ],
)
case(
    "win_local_admin_added",
    "fp_other_group",
    [
        ev(
            "windows",
            EventID=4732,
            Computer=FRONT,
            SubjectUserName="sam.patel",
            TargetUserName="Remote Desktop Users",
            MemberName="scanner-front",
        )
    ],
)

case(
    "win_security_log_cleared",
    "tp",
    [
        ev(
            "windows",
            EventID=1102,
            Computer=FRONT,
            SubjectUserName="maria.chen",
        )
    ],
)
case(
    "win_security_log_cleared",
    "fp_service_shutdown",
    [
        ev(
            "windows",
            EventID=1100,
            Computer=BACKUP,
            SubjectUserName="svc.backup",
        )
    ],
)


@pytest.mark.parametrize("case", CASES, ids=lambda item: f"{item['rule']}-{item['kind']}")
def test_detection_case(case):
    alerts = run((case["rule"], *case["also"]), case["events"])
    hit = [alert for alert in alerts if alert.rule_name == case["rule"]]
    if case["kind"].startswith("tp"):
        assert hit, case["rule"]
    else:
        assert hit == [], case["rule"]


def test_each_rule_has_a_true_and_false_case():
    rules = {item["rule"] for item in CASES}
    true_positive = {item["rule"] for item in CASES if item["kind"].startswith("tp")}
    false_positive = {item["rule"] for item in CASES if item["kind"].startswith("fp")}
    from clinic_soc.sigma import load_rules

    loaded = {rule.name for rule in load_rules()}
    assert true_positive == loaded
    assert false_positive == loaded
    assert rules == loaded
