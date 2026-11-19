"""Build one synthetic clinic day, with planted cases mixed into ordinary work.

Nothing here is a real patient, a real address, or a real password.
Outside the clinic LAN, every address is in a documentation range
(TEST-NET, RFC 5737). The detector does not read the labels this
module writes next to the logs.
"""

from __future__ import annotations

import json
import random
from datetime import datetime, timedelta
from pathlib import Path

from clinic_soc.clinic import hosts_by_name, sample_day_start
from clinic_soc.sources import SOURCES

STUFFING_IP = "198.51.100.23"
BENIGN_PORTAL_IP = "198.51.100.44"
MONITOR_IP = "198.51.100.5"
DAVID_VPN_IP = "198.51.100.77"
SAM_VPN_IP = "198.51.100.81"
PRIYA_VPN_IP = "198.51.100.82"
VENDOR_IP = "203.0.113.50"
EXFIL_IP = "203.0.113.199"
WEB_IP = "203.0.113.20"


def generate(clinic: dict, seed: int = 42) -> tuple[dict[str, list[dict]], dict]:
    day = _Day(clinic, seed)
    day.baseline()
    day.portal_stuffing()
    day.misclick()
    day.support_break_glass()
    day.records_release()
    day.intrusion()
    day.insider()
    day.on_call_charting()
    for source, events in day.logs.items():
        events.sort(key=lambda item: item["timestamp"])
    labels = {
        "seed": seed,
        "day": clinic["sample_day"],
        "note": (
            "Planted cases for practice. The detector does not read this file. "
            "A normal day at a clinic this size would be quieter."
        ),
        "scenarios": day.scenarios,
    }
    return day.logs, labels


def write_logs(directory: Path, logs: dict[str, list[dict]]) -> None:
    directory.mkdir(parents=True, exist_ok=True)
    for name, events in logs.items():
        path = directory / f"{name}.jsonl"
        lines = [json.dumps(event, separators=(",", ":")) for event in events]
        path.write_text("\n".join(lines) + ("\n" if lines else ""), encoding="utf-8")


def load_logs(directory: Path) -> list[dict]:
    events = []
    for name, (product, service) in SOURCES.items():
        path = directory / f"{name}.jsonl"
        if not path.is_file():
            continue
        for line in path.read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            event = json.loads(line)
            event["_source"] = name
            event["_product"] = product
            event["_service"] = service
            events.append(event)
    return events


def stamp(logs: dict[str, list[dict]]) -> list[dict]:
    events = []
    for name, rows in logs.items():
        product, service = SOURCES[name]
        for row in rows:
            event = dict(row)
            event["_source"] = name
            event["_product"] = product
            event["_service"] = service
            events.append(event)
    return events


class _Day:
    def __init__(self, clinic: dict, seed: int):
        self.clinic = clinic
        self.rng = random.Random(seed)
        self.start = sample_day_start(clinic)
        self.hosts = hosts_by_name(clinic)
        self.logs = {name: [] for name in SOURCES}
        self.patients = [f"MRN-{10001 + index}" for index in range(24)]
        self.rng.shuffle(self.patients)
        self.scenarios: list[dict] = []

    def at(self, hour: int, minute: int, second: int = 0) -> datetime:
        return self.start.replace(hour=hour, minute=minute, second=second)

    def add(self, source: str, moment: datetime, **fields) -> None:
        self.logs[source].append({"timestamp": moment.isoformat(), **fields})

    def host(self, name: str) -> dict:
        return self.hosts[name]

    def scenario(self, scenario_id: str, title: str, detail: str, expect: list[str], entity: dict) -> None:
        self.scenarios.append(
            {
                "id": scenario_id,
                "title": title,
                "detail": detail,
                "expect": expect,
                "entity": entity,
            }
        )

    def baseline(self) -> None:
        arrivals = [
            ("maria.chen", "WS-FRONT-01", 7, 42),
            ("james.okonkwo", "WS-MA-01", 7, 36),
            ("priya.shah", "WS-NURSE-01", 7, 28),
            ("alex.morgan", "WS-CLIN-01", 7, 50),
            ("david.nguyen", "WS-BILLING-01", 8, 5),
            ("avery.brooks", "WS-ADMIN-01", 8, 2),
            ("sam.patel", "WS-IT-01", 8, 15),
        ]
        for user, host_name, hour, minute in arrivals:
            host = self.host(host_name)
            self.add(
                "windows",
                self.at(hour, minute),
                EventID=4624,
                Computer=host["fqdn"],
                TargetUserName=user,
                TargetDomainName="RIVERSIDE",
                LogonType=2,
                IpAddress="127.0.0.1",
                WorkstationName=host_name,
            )
        self.add(
            "windows",
            self.at(8, 6),
            EventID=4625,
            Computer=self.host("WS-BILLING-01")["fqdn"],
            TargetUserName="david.nguyen",
            LogonType=2,
            IpAddress="127.0.0.1",
            Status="0xc000006a",
        )
        # IT remote support during the day. Filtered by the RDP rule.
        self.add(
            "windows",
            self.at(13, 10),
            EventID=4624,
            Computer=self.host("EHR-APP-01")["fqdn"],
            TargetUserName="sam.patel",
            TargetDomainName="RIVERSIDE",
            LogonType=10,
            IpAddress=self.host("WS-IT-01")["ip"],
            WorkstationName="WS-IT-01",
        )
        self.add(
            "windows",
            self.at(9, 5),
            EventID=4732,
            Computer=self.host("WS-FRONT-01")["fqdn"],
            SubjectUserName="sam.patel",
            TargetUserName="Remote Desktop Users",
            MemberName="scanner-front",
        )
        self.add(
            "windows",
            self.at(11, 20),
            EventID=4688,
            Computer=self.host("WS-IT-01")["fqdn"],
            SubjectUserName="sam.patel",
            NewProcessName=r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
            ParentProcessName=r"C:\Windows\explorer.exe",
            CommandLine=(
                "powershell.exe -ExecutionPolicy Bypass -File "
                r"C:\clinic-it\inventory.ps1"
            ),
        )
        # Nightly backup. Looks a bit like the ransomware commands and must not alert.
        backup = self.host("BK-01")
        file_server = self.host("FS-01")
        self.add(
            "windows",
            self.at(1, 5),
            EventID=4688,
            Computer=backup["fqdn"],
            SubjectUserName="svc.backup",
            NewProcessName=r"C:\Windows\System32\vssadmin.exe",
            ParentProcessName=r"C:\Windows\System32\cmd.exe",
            CommandLine="vssadmin list shadows",
        )
        self.add(
            "windows",
            self.at(1, 6),
            EventID=4688,
            Computer=backup["fqdn"],
            SubjectUserName="svc.backup",
            NewProcessName=r"C:\Windows\System32\wbadmin.exe",
            ParentProcessName=r"C:\Windows\System32\cmd.exe",
            CommandLine="wbadmin start backup -backupTarget:E: -include:D:\\ehr-exports -quiet",
        )
        self.add(
            "windows",
            self.at(1, 7),
            EventID=4624,
            Computer=file_server["fqdn"],
            TargetUserName="svc.backup",
            TargetDomainName="RIVERSIDE",
            LogonType=3,
            IpAddress=backup["ip"],
            WorkstationName="BK-01",
        )
        self.add(
            "windows",
            self.at(1, 8),
            EventID=1100,
            Computer=backup["fqdn"],
            SubjectUserName="svc.backup",
        )
        self._chart("alex.morgan", "WS-CLIN-01", self.at(8, 10), 10, "clinical_note", "view")
        self._chart("alex.morgan", "WS-CLIN-01", self.at(9, 0), 4, "lab_result", "view")
        self._chart("alex.morgan", "WS-CLIN-01", self.at(9, 40), 4, "medication", "view")
        self._chart("alex.morgan", "WS-CLIN-01", self.at(10, 10), 6, "demographics", "view")
        self._chart("priya.shah", "WS-NURSE-01", self.at(8, 0), 8, "clinical_note", "view")
        self._chart("priya.shah", "WS-NURSE-01", self.at(10, 30), 6, "vitals", "view")
        self._chart("priya.shah", "WS-NURSE-01", self.at(11, 10), 4, "lab_result", "view")
        self._chart("james.okonkwo", "WS-MA-01", self.at(8, 5), 8, "vitals", "view")
        self._chart("james.okonkwo", "WS-MA-01", self.at(8, 50), 6, "demographics", "view")
        self._chart("maria.chen", "WS-FRONT-01", self.at(8, 0), 10, "scheduling", "view")
        self._chart("maria.chen", "WS-FRONT-01", self.at(9, 10), 8, "demographics", "view")
        self._chart("david.nguyen", "WS-BILLING-01", self.at(8, 20), 12, "billing", "view")
        self._chart("david.nguyen", "WS-BILLING-01", self.at(10, 0), 6, "insurance", "view")
        self._chart("david.nguyen", "WS-BILLING-01", self.at(11, 30), 4, "demographics", "view")
        self._chart("avery.brooks", "WS-ADMIN-01", self.at(9, 15), 4, "scheduling", "view")
        self._chart("avery.brooks", "WS-ADMIN-01", self.at(9, 40), 4, "billing", "view")

        for index, (hour, minute) in enumerate(
            [(9, 5), (9, 40), (10, 15), (11, 5), (12, 30), (14, 10), (15, 20), (16, 5)]
        ):
            self.add(
                "portal",
                self.at(hour, minute),
                username=f"p{10001 + index}",
                src_ip=f"198.51.100.{50 + index}",
                result="success",
                reason="ok",
                user_agent="PortalClient/3.2 (synthetic)",
            )
        for minute in range(6):
            self.add(
                "portal",
                self.at(12, minute),
                username="p10020",
                src_ip=BENIGN_PORTAL_IP,
                result="failure",
                reason="bad_password",
                user_agent="PortalClient/3.2 (synthetic)",
            )
        self.add(
            "portal",
            self.at(12, 8),
            username="p10020",
            src_ip=BENIGN_PORTAL_IP,
            result="success",
            reason="ok",
            user_agent="PortalClient/3.2 (synthetic)",
        )
        for index in range(3):
            self.add(
                "portal",
                self.at(16, 30 + index),
                username=f"p1003{index}",
                src_ip="198.51.100.46",
                result="failure",
                reason="bad_password",
                user_agent="PortalClient/3.2 (synthetic)",
            )
        for index in range(12):
            self.add(
                "portal",
                self.at(2, index),
                username=f"healthcheck-{index:02d}",
                src_ip=MONITOR_IP,
                result="failure",
                reason="monitor",
                user_agent="clinic-monitor/1.0",
            )

        self._mail(
            self.at(8, 30),
            "outbound",
            "appointments@riverside-clinic.example",
            "patient.mailbox@yahoo.com",
            "Appointment reminder",
            "",
            0,
            "allowed",
        )
        self._mail(
            self.at(9, 12),
            "inbound",
            "results@regionlab.example",
            "records@riverside-clinic.example",
            "Lab batch",
            "batch-884.pdf",
            80000,
            "allowed",
        )
        self._mail(
            self.at(11, 45),
            "outbound",
            "billing@riverside-clinic.example",
            "patient.mailbox@gmail.com",
            "Statement",
            "statement.pdf",
            60000,
            "allowed",
        )
        self._mail(
            self.at(10, 5),
            "inbound",
            "dropbox@unknown-mail.example",
            "maria.chen@riverside-clinic.example",
            "Please review",
            "payroll.xlsm",
            240000,
            "quarantine",
        )
        self._mail(
            self.at(13, 20),
            "outbound",
            "records@riverside-clinic.example",
            "roi@regionlab.example",
            "Records for continuing care",
            "release-one.pdf",
            180000,
            "allowed",
        )

        self._flow(self.at(11, 15), self.host("EHR-APP-01")["ip"], VENDOR_IP, 250_000_000, "ehr-vendor-update")
        for index, host_name in enumerate(["WS-FRONT-01", "WS-NURSE-01", "WS-CLIN-01", "WS-BILLING-01"]):
            self._flow(
                self.at(10, 20 + index * 5),
                self.host(host_name)["ip"],
                WEB_IP,
                4_000_000 + index * 100_000,
                "web",
            )
        self.add(
            "vpn",
            self.at(7, 50),
            action="failure",
            user="maria.chen",
            src_ip="198.51.100.60",
            country="US",
            assigned_ip="",
            device="FW-01",
        )
        self.add(
            "vpn",
            self.at(13, 5),
            action="success",
            user="sam.patel",
            src_ip=SAM_VPN_IP,
            country="US",
            assigned_ip="10.20.8.15",
            device="FW-01",
        )

    def portal_stuffing(self) -> None:
        start = self.at(1, 20)
        usernames = [f"p{10001 + index}" for index in range(18)]
        for index, username in enumerate(usernames):
            self.add(
                "portal",
                start + timedelta(seconds=20 * index),
                username=username,
                src_ip=STUFFING_IP,
                result="failure",
                reason="bad_password",
                user_agent="python-requests/2.31 (synthetic)",
            )
        self.add(
            "portal",
            self.at(1, 29),
            username="p10021",
            src_ip=STUFFING_IP,
            result="success",
            reason="ok",
            user_agent="python-requests/2.31 (synthetic)",
        )
        self.scenario(
            "portal_stuffing",
            "Credential stuffing on the patient portal",
            "One documentation-range address failed many patient usernames just after 1:20 a.m., then signed in as one of them.",
            ["portal_credential_stuffing", "portal_success_after_stuffing"],
            {"src_ip": STUFFING_IP},
        )

    def misclick(self) -> None:
        self._access(
            "maria.chen",
            "WS-FRONT-01",
            self.at(8, 20),
            self.patients[0],
            "clinical_note",
            "view",
            access_reason="",
        )
        self.scenario(
            "front_desk_misclick",
            "Front desk opened one clinical note",
            "During check-in, the front desk account opened a single clinical note. That is outside the job. It is not a bulk export.",
            ["ehr_minimum_necessary"],
            {"user": "maria.chen", "match_count": 1},
        )

    def support_break_glass(self) -> None:
        self._access(
            "sam.patel",
            "WS-IT-01",
            self.at(10, 30),
            self.patients[1],
            "clinical_note",
            "view",
            break_glass=True,
            access_reason="ticket 4412 workstation freeze",
        )

    def records_release(self) -> None:
        self._access(
            "avery.brooks",
            "WS-ADMIN-01",
            self.at(11, 0),
            self.patients[2],
            "clinical_note",
            "export",
            access_reason="patient_release",
        )

    def intrusion(self) -> None:
        front = self.host("WS-FRONT-01")
        file_server = self.host("FS-01")
        ehr = self.host("EHR-APP-01")
        self._mail(
            self.at(13, 42),
            "inbound",
            "billing@rivrsid-clinic.example",
            "maria.chen@riverside-clinic.example",
            "Overdue invoice 88421",
            "invoice.docm",
            180000,
            "allowed",
        )
        self.add(
            "windows",
            self.at(13, 49),
            EventID=4688,
            Computer=front["fqdn"],
            SubjectUserName="maria.chen",
            NewProcessName=r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
            ParentProcessName=r"C:\Windows\System32\cmd.exe",
            CommandLine="powershell.exe -NoP -enc SQBFAFgA",
        )
        self.add(
            "windows",
            self.at(13, 52),
            EventID=4732,
            Computer=front["fqdn"],
            SubjectUserName="maria.chen",
            TargetUserName="Administrators",
            MemberName="helpdesk",
        )
        self.add(
            "windows",
            self.at(13, 55),
            EventID=4648,
            Computer=front["fqdn"],
            SubjectUserName="maria.chen",
            TargetUserName="svc.ehr",
            TargetServerName="EHR-APP-01",
            IpAddress=front["ip"],
        )
        for computer, moment in (
            (ehr, self.at(13, 56)),
            (file_server, self.at(13, 56, 20)),
        ):
            self.add(
                "windows",
                moment,
                EventID=4624,
                Computer=computer["fqdn"],
                TargetUserName="svc.ehr",
                TargetDomainName="RIVERSIDE",
                LogonType=3,
                IpAddress=front["ip"],
                WorkstationName="WS-FRONT-01",
            )
        self.add(
            "windows",
            self.at(13, 57),
            EventID=5140,
            Computer=file_server["fqdn"],
            SubjectUserName="svc.ehr",
            ShareName=r"\\FS-01\ehr-exports",
            IpAddress=front["ip"],
        )
        self.add(
            "windows",
            self.at(13, 58),
            EventID=4624,
            Computer=file_server["fqdn"],
            TargetUserName="maria.chen",
            TargetDomainName="RIVERSIDE",
            LogonType=10,
            IpAddress=front["ip"],
            WorkstationName="WS-FRONT-01",
        )
        self.add(
            "windows",
            self.at(14, 2),
            EventID=4688,
            Computer=file_server["fqdn"],
            SubjectUserName="svc.ehr",
            NewProcessName=r"C:\Windows\System32\vssadmin.exe",
            ParentProcessName=r"C:\Windows\System32\cmd.exe",
            CommandLine="vssadmin delete shadows /all /quiet",
        )
        self.add(
            "windows",
            self.at(14, 3),
            EventID=4688,
            Computer=file_server["fqdn"],
            SubjectUserName="svc.ehr",
            NewProcessName=r"C:\Windows\System32\bcdedit.exe",
            ParentProcessName=r"C:\Windows\System32\cmd.exe",
            CommandLine="bcdedit /set {default} recoveryenabled No",
        )
        self._flow(self.at(14, 6), front["ip"], EXFIL_IP, 850_000_000, "unknown-https")
        self._mail(
            self.at(14, 8),
            "outbound",
            "maria.chen@riverside-clinic.example",
            "maria.personal@gmail.com",
            "export",
            "cedar_export_patients.csv",
            8_500_000,
            "allowed",
        )
        self._chart(
            "maria.chen",
            "WS-FRONT-01",
            self.at(14, 8),
            16,
            "clinical_note",
            "export",
            client_ip=front["ip"],
        )
        self.add(
            "windows",
            self.at(14, 12),
            EventID=1102,
            Computer=front["fqdn"],
            SubjectUserName="maria.chen",
            SubjectDomainName="RIVERSIDE",
        )
        self.scenario(
            "phish_delivered",
            "Macro attachment delivered to the front desk",
            "The gateway allowed invoice.docm from a lookalike sender. A second macro file earlier in the day was quarantined and should stay quiet.",
            ["email_macro_delivered"],
            {"recipient": "maria.chen@riverside-clinic.example"},
        )
        self.scenario(
            "encoded_powershell",
            "Encoded PowerShell on the front desk PC",
            "Minutes after the attachment, powershell.exe ran with -enc on WS-FRONT-01. The IT inventory script does not use -enc.",
            ["win_encoded_powershell"],
            {"Computer": front["fqdn"]},
        )
        self.scenario(
            "local_admin",
            "Local administrator added on the front desk PC",
            "The front desk account added a local user named helpdesk to Administrators.",
            ["win_local_admin_added"],
            {"Computer": front["fqdn"]},
        )
        self.scenario(
            "service_account_lateral",
            "EHR service account used from a front desk PC",
            "svc.ehr authenticated to the EHR server and the file server from 10.20.1.11. The backup account from the backup server is ordinary.",
            ["win_service_account_from_workstation"],
            {"IpAddress": front["ip"]},
        )
        self.scenario(
            "rdp_to_file_server",
            "Front desk account opened RDP to the file server",
            "maria.chen took a remote desktop session on FS-01. Sam Patel's earlier RDP to the EHR server is his job.",
            ["win_rdp_to_server"],
            {"TargetUserName": "maria.chen"},
        )
        self.scenario(
            "recovery_inhibit",
            "Shadow copies and recovery turned off on the file server",
            "vssadmin delete shadows and bcdedit recoveryenabled No ran on FS-01. The 1 a.m. backup job only listed shadows and started a backup.",
            ["win_inhibit_recovery"],
            {"Computer": file_server["fqdn"]},
        )
        self.scenario(
            "https_exfil",
            "Large upload from the front desk PC",
            "WS-FRONT-01 sent about 850 MB to an unapproved documentation-range address. The EHR vendor update to 203.0.113.50 is on the allow list.",
            ["fw_large_outbound"],
            {"dst_ip": EXFIL_IP},
        )
        self.scenario(
            "webmail_export",
            "Patient export emailed to personal webmail",
            "The front desk mailbox sent cedar_export_patients.csv to a gmail.com address.",
            ["email_export_to_webmail"],
            {"recipient": "maria.personal@gmail.com"},
        )
        self.scenario(
            "ehr_export",
            "Front desk exported a stack of clinical notes",
            "Sixteen clinical notes were exported by the front desk account around 2 p.m. The office manager's single patient-release export is separate and expected to stay quiet.",
            ["ehr_bulk_export", "ehr_minimum_necessary_bulk"],
            {"user": "maria.chen"},
        )
        self.scenario(
            "log_cleared",
            "Security log cleared on the front desk PC",
            "Event 1102 was recorded on WS-FRONT-01. The backup server's event-log service stop (1100) is not the same thing.",
            ["win_security_log_cleared"],
            {"Computer": front["fqdn"]},
        )

    def insider(self) -> None:
        self.add(
            "vpn",
            self.at(21, 48),
            action="success",
            user="david.nguyen",
            src_ip=DAVID_VPN_IP,
            country="DE",
            assigned_ip="10.20.8.40",
            device="FW-01",
        )
        self._chart(
            "david.nguyen",
            "WS-BILLING-01",
            self.at(22, 5),
            22,
            "clinical_note",
            "view",
            minutes=30,
            client_ip="10.20.8.40",
        )
        self.scenario(
            "vpn_untrusted_country",
            "Billing VPN session from outside the country list",
            "david.nguyen connected from country DE at 9:48 p.m. Sam Patel and the on-call nurse connected from the US and should not match this rule.",
            ["vpn_untrusted_country"],
            {"user": "david.nguyen"},
        )
        self.scenario(
            "after_hours_snooping",
            "Billing account read clinical notes after close",
            "After the VPN session, the billing account opened 22 clinical notes. Billing's daytime work was claims and demographics only. The on-call nurse's evening charting is on the roster.",
            ["ehr_after_hours_bulk_view", "ehr_minimum_necessary", "ehr_minimum_necessary_bulk"],
            {"user": "david.nguyen"},
        )

    def on_call_charting(self) -> None:
        self.add(
            "vpn",
            self.at(22, 28),
            action="success",
            user="priya.shah",
            src_ip=PRIYA_VPN_IP,
            country="US",
            assigned_ip="10.20.8.41",
            device="FW-01",
        )
        self._chart(
            "priya.shah",
            "WS-NURSE-01",
            self.at(22, 32),
            5,
            "clinical_note",
            "view",
            client_ip="10.20.8.41",
        )

    def _chart(
        self,
        user: str,
        host_name: str,
        start: datetime,
        count: int,
        record_type: str,
        action: str,
        minutes: int = 40,
        client_ip: str | None = None,
        access_reason: str = "",
    ) -> None:
        step = 0 if count <= 1 else (minutes * 60) / (count - 1)
        for index in range(count):
            # Whole seconds. A fractional timestamp is harder to read and
            # does not change whether two events fall in the same window.
            moment = start + timedelta(seconds=round(step * index))
            self._access(
                user,
                host_name,
                moment,
                self.patients[index % len(self.patients)],
                record_type,
                action,
                access_reason=access_reason,
                client_ip=client_ip,
            )

    def _access(
        self,
        user: str,
        host_name: str,
        moment: datetime,
        patient: str,
        record_type: str,
        action: str,
        break_glass: bool = False,
        access_reason: str = "",
        client_ip: str | None = None,
    ) -> None:
        host = self.host(host_name)
        self.add(
            "ehr",
            moment,
            user=user,
            patient_mrn=patient,
            action=action,
            record_type=record_type,
            workstation=host["fqdn"],
            client_ip=client_ip or host["ip"],
            break_glass=break_glass,
            access_reason=access_reason,
            result="success",
            application="cedarchart",
        )

    def _mail(
        self,
        moment: datetime,
        direction: str,
        sender: str,
        recipient: str,
        subject: str,
        attachment_name: str,
        attachment_bytes: int,
        verdict: str,
    ) -> None:
        self.add(
            "email",
            moment,
            direction=direction,
            sender=sender,
            recipient=recipient,
            subject=subject,
            attachment_name=attachment_name,
            attachment_bytes=attachment_bytes,
            verdict=verdict,
        )

    def _flow(self, moment: datetime, src_ip: str, dst_ip: str, bytes_out: int, rule_name: str) -> None:
        self.add(
            "firewall",
            moment,
            action="allow",
            direction="outbound",
            src_ip=src_ip,
            dst_ip=dst_ip,
            dst_port=443,
            protocol="tcp",
            bytes_out=bytes_out,
            bytes_in=2_000_000,
            duration_sec=400,
            device="FW-01",
            rule_name=rule_name,
        )
