# Portal sign-in after credential stuffing

## What happened

An address that had just failed many portal usernames then signed in as one of them. Until the patient says otherwise, treat that session as someone else.

## Why it matters here

A successful session can show appointments, messages between the patient and the clinic, and billing. That is enough for a risk assessment even though the portal is not the full chart.

## What to do first

1. Call Sangeeta Sinha (555-0108) and Sam Patel (555-0174).
2. Disable the portal account named in the alert and end its other sessions.
3. Force a password reset. Do not email the temporary password to an address that just appeared in the attack.
4. Block the source address if the stuffing playbook has not already done that.
5. Call the patient on the phone number already in the chart. Ask if they signed in at the time in the alert.

## What to isolate

That portal account and the source address. Other patients stay on the portal.

## Evidence to keep

The successful session time, what pages the portal says were opened if the audit has that, the password-reset time, and the patient's answer.

## Breach-notification considerations

Start the risk assessment the same day. The questions counsel will ask are the ones in 45 CFR 164.402: what was in the portal, who had the session, whether anything was actually opened, and how fast the clinic cut it off. Do not promise the patient "this was not a breach" on the phone. Tell them the account was locked because of a suspicious sign-in, and that the privacy lead will follow up. This checklist is not legal advice.

## False alarms

The real patient might sign in from that address while the guessing is going on, for example if they are on the same public Wi-Fi as the attacker. The phone call is how you tell those apart. Do not skip it.
