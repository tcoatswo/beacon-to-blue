# beacon-to-blue

Translate red-team style “beacon behaviors” into **defender-first** artifacts: detections, hunting queries, and hardening guidance.

## Why it matters
Security teams frequently receive intelligence in attacker language. This project helps convert that into:
- detection logic
- observable behaviors
- actionable prevention steps

## What it does
- Maps common beaconing patterns to defender observables
- Produces blue-team outputs (queries/rules) that can be adapted to common stacks

## Quick start
```bash
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt

python -m beacon_to_blue --input examples/behavior.yaml --out out/
```

## Scope / Non-goals
- Not malware
- Not C2 tooling
- Defensive translation only

## License
MIT
