# Remote desktop to a clinic server

## What happened

Someone who is not the IT account took a Remote Desktop session to the EHR server, the file server, or the domain controller.

## Why it matters here

Those machines hold the charts and the logons. Front desk, nursing, and billing do their work on their own PCs and in the EHR application. They do not sit on the server desktop.

## What to do first

1. Call Sam Patel (555-0174). If the account is a clinical one, also call Sangeeta Sinha (555-0108).
2. Disconnect the source PC from the network. Unplug the cable or disable the switch port. Leave the PC on.
3. Disable the user account that appears as the RDP logon.
4. Ask IT to sign the session off on the server.
5. Read the next alerts for that PC: service account, new local admin, encoded PowerShell, cleared Security log.

## What to isolate

The source workstation and the user account. Do not shut down the file server or the EHR server as the first move. That stops the clinic and can wipe information IT still needs.

## Evidence to keep

The 4624 event (time, account, source address, destination computer) and a photo or export of who is still logged on to the server.

## Breach-notification considerations

A remote desktop session does not, by itself, prove a chart was opened. It does mean the person was in a place they should not be. Use the EHR audit to see whether charts moved. This checklist is not legal advice.

## False alarms

Sam Patel's own RDP is filtered. A new IT contractor will fire this rule until you add the account. Add the person. Do not turn the rule off for the afternoon.
