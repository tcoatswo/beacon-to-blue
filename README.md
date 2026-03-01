# beacon-to-blue

A **defender-first** project that translates common “beacon-style” intrusion tradecraft into:

1) **actionable detections** (Sigma, osquery)
2) **repeatable lab simulation** (benign log generator)
3) **policy-ready decision artifacts** (risk + controls + exceptions)

This repo is intentionally designed to be safe and publishable: it contains **no persistence tooling, no covert C2, and no remote execution**. Instead, it focuses on what defenders and risk owners need: **signals, controls, and governance**.

## What’s inside

### Engineering deliverables
- `detections/sigma/` — detection rules (process + persistence behaviors)
- `osquery/` — packs + queries to inventory cron persistence and suspicious binaries
- `simulator/` — benign scripts that generate realistic audit logs / events to test rules
- `docs/` — architecture, ATT&CK mappings, and evaluation notes

### Policy deliverables
- `policy/` — executive briefs, risk acceptance language, and control mappings

## Why this is grad-school relevant
This is a “bridge” project:
- **InfoSec:** maps observed attacker behaviors → concrete detection logic
- **Policy:** provides defensible prioritization, control selection, and exception handling

## Quickstart

### 1) Run the simulator (benign)
```bash
python3 -m venv .venv
. .venv/bin/activate
pip install -r simulator/requirements.txt
python simulator/generate_events.py --out out/events.jsonl
```

### 2) Use the detections
- Import Sigma rules from `detections/sigma/` into your Sigma pipeline / SIEM backend
- Run osquery packs from `osquery/packs/`

## Ethics & scope
This repository is a **defensive translation** of commonly discussed techniques. It intentionally avoids publishing offensive code or step-by-step guidance for misuse.

## License
MIT
