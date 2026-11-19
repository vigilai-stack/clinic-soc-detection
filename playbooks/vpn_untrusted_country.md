# VPN sign-in from an unexpected country

## What happened

A workforce account signed in to the VPN from a country that is not on the clinic's list. The list for this clinic is the United States. A failed password from anywhere does not match.

## Why it matters here

The VPN lands on the clinic network. From there the EHR is reachable. A billing account connecting from another country at night, and then opening charts, is one incident, not two.

## What to do first

1. Call the person on the phone number in the roster. Do not use a number from a new email.
2. If they confirm travel that the office manager already knew about, note it and add the country for those dates only.
3. If they do not confirm the session, disable the account, disconnect the VPN session, and call Sangeeta Sinha (555-0108) and Sam Patel (555-0174).
4. Read the EHR audit for that user from the VPN time forward.

## What to isolate

The VPN session and, if the person did not confirm it, the account. Do not disable the VPN for the on-call nurse who is connecting from home in the US.

## Evidence to keep

The VPN log (user, country, source address, assigned clinic address, time) and the EHR rows that follow it.

## Breach-notification considerations

The country code is not a breach. Charts opened during a session the employee did not make are an access question for counsel. This checklist is not legal advice.

## False alarms

Geo lookups are sometimes wrong, and staff do travel. The phone call is the check. Do not expand the allow list to every country to make the alert go away.
