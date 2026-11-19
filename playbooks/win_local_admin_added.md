# New local administrator

## What happened

Someone added a member to the local Administrators group. Adding a scanner to Remote Desktop Users is a different event and does not use this playbook.

## Why it matters here

A local administrator on a front desk PC can install programs, read files, and clear logs. Front desk staff do not need that to check patients in.

## What to do first

1. See who made the change. If it was Sam Patel during a ticket, confirm the ticket and record the new account name. Stop there.
2. If it was anyone else, call Sam Patel (555-0174) and Sangeeta Sinha (555-0108).
3. Disconnect that PC from the network and leave it on.
4. IT removes the new administrator after the event has been copied out. Then disable the account that did the adding, unless that account is a shared front desk login you still need in the morning. If it is shared, change the password and watch it.

## What to isolate

The workstation. Not the domain, unless the group change was on the domain controller. This rule watches the local Administrators name on the computer in the event.

## Evidence to keep

The 4732 event: time, who added, who was added, which computer.

## Breach-notification considerations

A new admin is persistence. It becomes a privacy incident if files were copied after the change. Check the firewall and email alerts for that PC. This checklist is not legal advice.

## False alarms

IT building a PC will do this. The subject account should be IT. If the front desk account is the one adding admins, it is not a false alarm.
