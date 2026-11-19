"""Log file names and the Sigma logsource each one belongs to."""

# file stem -> (product, service)
SOURCES = {
    "windows": ("windows", "security"),
    "ehr": ("clinic", "ehr"),
    "firewall": ("clinic", "firewall"),
    "vpn": ("clinic", "vpn"),
    "email": ("clinic", "email"),
    "portal": ("clinic", "portal"),
}

# Copied onto single-event alerts when the field is present.
# Aggregate alerts use the group key instead, so one patient id
# is not presented as if it were the whole match.
ENTITY_FIELDS = (
    "src_ip",
    "dst_ip",
    "IpAddress",
    "user",
    "username",
    "TargetUserName",
    "SubjectUserName",
    "Computer",
    "MemberName",
    "sender",
    "recipient",
    "attachment_name",
    "workstation",
    "country",
)
