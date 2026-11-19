# Bulk export from the EHR

## What happened

One account exported records for many patients inside an hour. A normal release of information is one patient, done by the office manager, with a reason.

## Why it matters here

An export is a copy. Copies get emailed and uploaded. This is the alert that most often lines up with a personal-webmail message or a large firewall upload.

## What to do first

1. Call Sam Patel (555-0174) and Sangeeta Sinha (555-0108).
2. Disable the EHR account that ran the export.
3. Look at email and firewall alerts for the same hour and the same workstation.
4. If a csv or zip already went to webmail, use that playbook. Do not send the file to yourself "to see what is in it."
5. Ask IT to find the export file on the workstation and the file server. Note the path and the size. Copy it to an encrypted drive the privacy lead holds. Then remove the working copy from the shared drive so the next person does not stumble on it.

## What to isolate

The account, the workstation, and, if the file is on the share, access to that folder. Do not power the file server off.

## Evidence to keep

The EHR export audit, the file path, the size, the hash if IT can make one, and the email or firewall alert if there is one.

## Breach-notification considerations

Treat a bulk export as a likely impermissible disclosure until you can show the file never left and was destroyed. The assessment has to say where the copy went. Call the clinic's cyber insurer the same day if the file left, or if you cannot tell. Counsel handles patient notice. This checklist is not legal advice.

## False alarms

A planned quality pull should be a named job with a ticket, not a front desk login. If the clinic starts doing those pulls, give them their own account and a filter, and keep this rule for everyone else.
