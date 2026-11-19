# Patient portal credential stuffing

## What happened

Many different patient usernames failed to sign in from one internet address in a few minutes. Patients mistype their own password. They do not try the rest of the directory.

## Why it matters here

The portal shows appointments, messages, and bills. A run of failures is an attempt. The critical question is whether any username then succeeded from that same address. If it did, use the "sign-in succeeded after stuffing" playbook as well.

## What to do first

1. Call Sam Patel (IT, 555-0174) and Sangeeta Sinha (privacy and security lead, 555-0108). After hours, call the clinic line 555-0190 and ask them to reach those two.
2. On the firewall, block the source address from the alert. Do not take the portal offline. Other patients still use it for refills and messages.
3. In the portal admin page, list every username in the burst and mark which ones succeeded.
4. Leave the portal logs where they are. Do not rotate or delete them tonight.

## What to isolate

The source address. Not the whole portal, and not every patient account. Reset a password only for an account that actually signed in.

## Evidence to keep

The portal log for an hour on either side of the burst, the firewall block you added, and the list of usernames.

## Breach-notification considerations

Failed attempts, with no successful session and no record viewed, are usually an incident to record and not a notice to patients. Say that to counsel anyway if a success is even possible, because the logs may be incomplete. Notice timelines, if counsel decides notice is required, run from discovery and have an outer limit of 60 days for individuals (45 CFR 164.404). This checklist is not legal advice.

## False alarms

A handful of failures from one household, or the healthcheck accounts, should not reach this rule. If a guest Wi-Fi address at the clinic starts to, raise the distinct-username threshold rather than turning the rule off.
