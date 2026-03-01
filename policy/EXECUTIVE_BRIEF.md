# Executive brief — Beacon-style intrusion pattern (draft)

## What this is
A recurring real-world intrusion pattern: an endpoint establishes **periodic outbound communications** ("beaconing") and maintains **persistence** via scheduled execution.

## Why it matters
- Beaconing enables continuous operator control and data exfiltration opportunities.
- Persistence converts a one-time compromise into an ongoing incident.

## What we recommend (controls)
1) **Egress controls**: restrict outbound traffic to approved destinations; log all DNS + proxy.
2) **Persistence monitoring**: alert on new or modified cron entries; inventory scheduled jobs.
3) **Process telemetry**: collect process creation logs; flag unexpected interpreters (bash/python) spawned by schedulers.
4) **Incident playbook**: define containment actions (isolate host, rotate credentials, forensic collection).

## Risk framing
- Likelihood: medium–high (common technique)
- Impact: medium–high (enables follow-on actions)

## Exceptions
If teams require cron for legitimate automation, enforce:
- standard job locations
- code-owner review for automation scripts
- allowlisted binaries and destinations
- time-bound exceptions with re-approval
