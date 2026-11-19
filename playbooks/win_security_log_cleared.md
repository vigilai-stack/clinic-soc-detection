# Security log cleared

## What happened

Windows recorded event 1102, the Security log was cleared. The logging service stopping (event 1100) during a backup is not this.

## Why it matters here

The Security log is how the clinic shows who signed in. Clearing it is a way to hide the RDP session, the service account, or the new administrator that happened first. The EHR audit and the firewall log are separate, and they may still be intact.

## What to do first

1. Call Sam Patel (555-0174) and Sangeeta Sinha (555-0108) immediately.
2. Disconnect the computer from the network. Do not reboot it. A reboot can lose what is still in memory, and IT may want that.
3. Export any remaining local log, and export the EHR audit and the firewall log for the surrounding two hours, to a USB drive that stays with the privacy lead.
4. Read the other alerts for that computer. Treat missing earlier Windows events as expected, not as "nothing else happened."

## What to isolate

That computer. If it is a server, isolate it from the workstations but do not power it off until IT says so.

## Evidence to keep

The 1102 event itself (it often survives in the sense that the clear is the newest event), plus the other systems' logs. Write down the time you exported them.

## Breach-notification considerations

A cleared log makes the investigation weaker. It does not, alone, prove records were viewed or stolen. Tell counsel that the Windows log is incomplete and which other logs you still have. This checklist is not legal advice.

## False alarms

There is almost no routine reason for a clinic to clear the Security log. If IT did it on purpose, they can say so, and the alert should remain in the packet.
