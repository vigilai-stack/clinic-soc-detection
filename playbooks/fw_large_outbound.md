# Large upload to an unapproved address

## What happened

More than 100 MB left the clinic over HTTPS to an address that is not the EHR vendor's update server. The vendor update is on the allow list and should stay quiet even when it is large.

## Why it matters here

The clinic does not have a business reason to upload hundreds of megabytes from a front desk PC. That volume fits a copied chart export better than a web page.

## What to do first

1. Call Sam Patel (555-0174) and Sangeeta Sinha (555-0108).
2. Block the destination address on the firewall. Do not block all outbound HTTPS. The portal, the lab, and the payer still need it.
3. Match the source address to a workstation in config/clinic.yaml.
4. Disconnect that workstation if an EHR export or encoded PowerShell alert names it in the same hour.
5. Ask IT which process opened the connection. Write the process name down. Do not install new tools on the EHR server to find out.

## What to isolate

The destination address, and the source workstation if the rest of the hour looks wrong. Leave the vendor update address alone.

## Evidence to keep

Firewall log line (time, source, destination, bytes), the block you added, and the process name if IT found one.

## Breach-notification considerations

You may not know what the bytes were. Say that plainly in the assessment. If an EHR export or a csv-to-webmail alert sits in the same hour, assume the upload and the export are one event until shown otherwise. Counsel decides notice. This checklist is not legal advice.

## False alarms

A new software vendor will trip this the first time their update is large. Confirm the address with IT, add it to the allow list, and keep the rule.
