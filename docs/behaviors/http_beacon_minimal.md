# http_beacon_minimal — Periodic HTTP heartbeat to single domain

## Model
This behavior describes a simple periodic callback using `curl` to a single domain+path.

- Interval: ~15s
- Jitter: small (±3s)

## Defensive translation
Generated artifacts:
- Sigma (process creation)
- SPL / KQL (process creation)
- Optional Suricata host match (illustrative)

## Limitations
- A single host+path match is usually too weak on its own.
- Timing and fleet-wide prevalence should be incorporated for robustness.

## False positives
- Monitoring/health checks
- Internal automation scripts
