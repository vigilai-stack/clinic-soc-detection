# Encoded PowerShell

## What happened

PowerShell ran with an encoded command, or the command line refers to FromBase64String. The clinic's inventory script is a normal file launch and does not do this.

## Why it matters here

Encoded PowerShell is a way to hide a script the user did not type. On a front desk PC it usually follows an email attachment.

## What to do first

1. Read the user and the computer on the alert. If it is Sam Patel on the IT PC and he says he ran a named script, match the script path and stop.
2. Otherwise call Sam Patel (555-0174). Tell the user not to click anything else.
3. If the user is not IT, disconnect that PC from the network and leave it on.
4. Look at the mail gateway for a macro attachment to that person in the previous two hours.
5. Do not paste the encoded text into a website to decode it. IT can decode it on a machine that is not the clinic's EHR server.

## What to isolate

The workstation, until IT has read the command. Not the user's EHR account, unless charts were exported or a server logon followed.

## Evidence to keep

The full command line, the parent process, the user, and the email message if there was one.

## Breach-notification considerations

The script is not a disclosure. What it did next might be. Check export, email, and firewall alerts before talking about notice. This checklist is not legal advice.

## False alarms

If IT starts shipping tools as encoded commands, this rule will nag. Give those tools a normal script path and keep the rule for everything else.
