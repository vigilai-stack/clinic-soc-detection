# Macro attachment delivered

## What happened

The mail gateway let through an inbound message with a macro-enabled document or a script file. If the gateway had quarantined it, this alert would not exist.

## Why it matters here

Front desk opens invoices all day. A macro document is a common way a PC starts running PowerShell the user did not mean to run.

## What to do first

1. Call the recipient on the clinic phone. Tell them not to open the attachment. If they already opened it, say so to Sam Patel and stop using that PC.
2. Sam Patel (555-0174) quarantines or deletes the message from the mailbox.
3. If it was opened, disconnect that PC from the network, leave it on, and look for an encoded PowerShell alert for that user.
4. Look at the sender domain. A one-letter difference from the clinic's own domain is a lookalike, not a vendor.

## What to isolate

The message. The workstation only if the file was opened. Not the whole mailbox system.

## Evidence to keep

The gateway log (sender, recipient, file name, verdict) and the user's answer about whether they opened it.

## Breach-notification considerations

An unopened attachment is not a disclosure of patient information. An opened attachment that is followed by an export or a large upload may be. This checklist is not legal advice.

## False alarms

A lab or a payer that still sends real macro workbooks will fire this alert. Ask them for a pdf or csv. Until they change, a person looks at each one. Do not add a blanket exception for all spreadsheets.
