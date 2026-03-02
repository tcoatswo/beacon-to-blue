# beacon-to-blue

Translate attacker-described **beacon behaviors** into defender-first artifacts: **schemas**, **detection generation**, and **evaluation**.

This repo is designed to read like a small applied research project:
- represent behaviors as structured specifications
- compile them into blue-team artifacts (Sigma, SPL, KQL, etc.)
- evaluate against benign lookalikes to reason about false positives

## What’s included
- `spec/schema.json` — a behavior specification schema
- `spec/examples/` — example behaviors with MITRE ATT&CK mappings and assumptions
- `beacon_to_blue/` — compiler + generators + evaluation harness
- `datasets/` — small synthetic datasets (benign vs malicious-like)
- `docs/behaviors/` — short writeups per behavior

## Quick start

### 1) Generate artifacts from a behavior spec
```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt

python3 -m beacon_to_blue.cli --input spec/examples/http_beacon_minimal.yml --out out/artifacts
```

### 2) Run evaluation
```bash
python3 -m beacon_to_blue.evaluate \
  --behavior spec/examples/http_beacon_minimal.yml \
  --positive datasets/malicious_like/http_beacon_minimal.jsonl \
  --benign datasets/benign/http_lookalike.jsonl \
  --out out/report_http_beacon_minimal.json
```

## Defensive scope
No malware, no C2, no exploitation. The focus is defensive translation and measurement.

## License
MIT
