# Service account used from a workstation

## What happened

The EHR service account or the backup service account authenticated from a clinical PC. Those accounts exist so a server process can run. A person on a front desk PC should not be holding that password.

## Why it matters here

The service account can reach the EHR files and the shares. If the password is known on a workstation, every other alert on that PC matters more, because the attacker is no longer limited to the front desk job.

## What to do first

1. Call Sam Patel (555-0174) and Sangeeta Sinha (555-0108).
2. Disconnect the workstation whose address is in the alert. Leave it on.
3. IT prepares a new password for the service account and a plan to update the EHR service and the backup job. Do not change the password until those services are ready, or the EHR will be down with no warning. Do it the same day, not next week.
4. Look for shadow-copy deletion, a bulk export, and a cleared log.

## What to isolate

The workstation. After the password change, old sessions of that service account. Not the backup server, if the only logon from there is the nightly job.

## Evidence to keep

The 4624 and 4648 events, the workstation name, and the time the password was changed.

## Breach-notification considerations

A service-account logon is a security incident. Whether it is a reportable breach depends on what was opened or copied afterward. Follow the export and firewall alerts before anyone drafts a patient letter. This checklist is not legal advice.

## False alarms

The backup server at 10.20.2.30 uses svc.backup every night. That address is not a clinical workstation and should not match. If a new PC is numbered into 10.20.1.0/24 by mistake, fix the address plan.
