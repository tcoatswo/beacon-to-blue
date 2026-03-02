# beacon-to-blue

A defensive, applied-research repo that treats “beacon behavior” like a **compilable specification**.

Instead of shipping another one-off detection, `beacon-to-blue` aims to make the translation step *repeatable*:

1) **Represent** a behavior as a structured spec (with assumptions + telemetry requirements)  
2) **Compile** it into defender artifacts (Sigma, SPL, KQL, optional Suricata)  
3) **Evaluate** it against benign lookalikes to reason about false positives and detection latency

## Why admissions reviewers should care
This is security engineering with a research mindset:
- explicit behavioral model
- reproducible artifacts
- measurement loop (not vibes)

## Repo tour
- `spec/schema.json` — JSON Schema for behavior specs
- `spec/examples/` — example behaviors
- `beacon_to_blue/` — compiler + evaluation harness
- `datasets/` — synthetic benign vs malicious-like telemetry
- `docs/behaviors/` — short writeups per behavior

## Quick start

### Install
```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -U pip
pip install -e '.[dev]'
```

### Compile a behavior spec into artifacts
```bash
beacon-to-blue \
  --input spec/examples/http_beacon_minimal.yml \
  --out out/artifacts

# outputs under:
# out/artifacts/http_beacon_minimal/
#   - sigma.yml
#   - splunk.spl
#   - kql.kql
#   - suricata.rules (optional)
```

### Evaluate against benign lookalikes
```bash
python -m beacon_to_blue.evaluate \
  --behavior spec/examples/http_beacon_minimal.yml \
  --positive datasets/malicious_like/http_beacon_minimal.jsonl \
  --benign datasets/benign/http_lookalike.jsonl \
  --out out/report_http_beacon_minimal.json

cat out/report_http_beacon_minimal.json
```

## Behavior specs (what goes in a model)
A spec can include:
- **MITRE ATT&CK mappings** (tactics/techniques)
- **timing model** (interval/jitter notes)
- **observables** (process, HTTP)
- **false positive notes** + **assumptions**
- **required telemetry** (what you must be logging for detections to work)

## Defensive scope / non-goals
- No malware
- No C2 tooling
- No exploitation

This is about *translation* and *measurement*.

Policy note: this project is designed to make detection logic auditable by documenting assumptions and required telemetry for each rule and validating outputs with a small evaluation harness to support defensible security decisions.

## License
MIT
