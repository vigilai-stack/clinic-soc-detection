# Recovery and shadow copies turned off

## What happened

A command deleted volume shadow copies, deleted the backup catalog, or turned Windows recovery off. Those commands show up before files get encrypted. The nightly backup job lists shadows and starts a backup. It does not delete them.

## Why it matters here

If the copies are gone and files are encrypted, the clinic can lose recent scans, notes, and the schedule. Patients still need refills and results in the morning. The first hour is about stopping the spread, not about the ransom message.

## What to do first

1. Call Sam Patel (555-0174) and Sangeeta Sinha (555-0108). Call the clinic's cyber insurer from the number on the policy, not from a link in an email.
2. Unplug the network cable on the computer in the alert, and on any workstation that logged onto it in the past hour. Leave the machines powered on.
3. Tell staff to stop using the shared drive and to leave unsaved work. Avery Brooks tells the front desk in person.
4. Do not reboot. Do not "clean" the disk. Do not reply to a ransom note. Do not pay from a staff mailbox.
5. IT checks whether the backup server still has last night's copy and disconnects that server from the rest of the network so a later encryption pass cannot reach it.

## What to isolate

The affected PC, the file server if the command ran there, and the path from the PCs to the backup server. Keep one internet path for IT to call the insurer, from a machine that did not run the command.

## Evidence to keep

The command line, the time, the user, and a note of which cables were pulled. Report the incident to IC3 (the FBI's internet-crime center) when the privacy lead and insurer agree on who files it.

## Breach-notification considerations

If records are unavailable and you do not yet know whether they were also copied out, counsel treats availability and confidentiality as separate questions. Start both conversations the same day. This checklist is not legal advice.

## False alarms

IT rebuilding a PC may delete old shadow copies on purpose. If that is the case, the account will be IT's and there will be a ticket. Still answer the phone. The cost of a false alarm here is an hour. The cost of a miss is the chart system.
