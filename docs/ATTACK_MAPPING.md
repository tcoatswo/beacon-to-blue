# ATT&CK mapping (draft)

This project focuses on a common pattern defenders encounter: **periodic outbound beacons** combined with **persistence**.

## Techniques (illustrative)

### Persistence
- **T1053.003 — Scheduled Task/Job: Cron**
  - Signal: modifications to user crontab; new jobs running frequently with redirected output
  - Controls: restrict cron usage; alert on new crontab entries; auditd process monitoring

### Command and Control
- **T1071.001 — Application Layer Protocol: Web Protocols**
  - Signal: periodic HTTP POSTs to uncommon destinations; jitter-like periodicity
  - Controls: egress allowlists; DNS logging; proxy inspection; anomaly detection on periodicity

### Defense Evasion (detection relevant, not implementation)
- **T1027 — Obfuscated/Compressed Files and Information**
  - Signal: base64 blobs; XOR-like patterns; unusual encoded payloads
  - Controls: content inspection; alert on high-entropy payloads; logging at egress points

## Notes
This repo is intentionally defensive: it documents signals and detections rather than providing operational steps.
