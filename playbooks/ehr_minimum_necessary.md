# One record outside the job

## What happened

Someone opened, exported, or printed a record type their role is not allowed to use. The count is small. The bulk playbook is the one to use when many patients are involved.

## Why it matters here

Front desk needs the schedule and demographics. Billing needs the claim. The clinical note is for the people providing care. One open can be a mis-click during check-in. It is still worth ten minutes of conversation, because that is how the clinic shows it looks at minimum necessary.

## What to do first

1. Check the alert list for a bulk minimum-necessary alert, an after-hours alert, or an export alert for the same user. If one exists, stop using this playbook and use that one.
2. If this is the only alert, Avery Brooks talks with the person on the next business day. Ask what they were looking for and whether they found it another way.
3. Write down the answer. Sangeeta Sinha keeps the note with the other privacy records.
4. Do not disable an account for a single daytime mis-click unless the person has done this before.

## What to isolate

Nothing, if it is truly one chart during the workday and nothing was exported. The account stays under the office manager's eye for the week.

## Evidence to keep

The one audit row and the note of the conversation.

## Breach-notification considerations

A single mistaken view by a workforce member is often a sanction and a log entry, not a patient notice. Counsel still makes that call, especially if the chart was printed or the patient is someone the employee knows personally. Do not decide it in the group chat. This checklist is not legal advice.

## False alarms

Break-glass with a ticket, and an export marked patient_release by the office manager, are supposed to stay quiet. If IT's break-glass starts alerting, the flag is missing from the audit event and the EHR vendor needs a fix.
