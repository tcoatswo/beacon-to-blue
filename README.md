# beacon-to-blue

Turn a structured beacon behavior description into reviewable detection drafts and measure how well its observables separate periodic callbacks from benign lookalikes.

The workflow is defensive: specs describe what a defender can observe; the compiler writes Sigma, Splunk SPL, KQL, and optional Suricata drafts; the evaluator scores synthetic telemetry. This repository does not contain a beacon, C2 server, or exploitation code.

## Install

Requires Python 3.11 or newer.

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -e '.[dev]'
```

## Compile and validate

```bash
# Validate one spec or all specs in a directory without writing files.
beacon-to-blue --input spec/examples --validate-only

# Compile a single spec or every YAML/JSON spec in a directory.
beacon-to-blue --input spec/examples --out out/artifacts
```

Each behavior gets an output directory named by its `id`. The compiler writes only artifacts for event types that have actual criteria:

| File | Purpose |
| --- | --- |
| `sigma.yml`, `splunk.spl`, `kql.kql` | Process creation criteria |
| `sigma_http.yml`, `splunk_http.spl`, `kql_http.kql` | HTTP host and URI criteria |
| `suricata.rules` | One HTTP host content rule per domain, when domains are specified |
| `manifest.json` | Source name, artifact list, telemetry assumptions, and timing model |

Process and HTTP rules are independent event detections. A spec containing both does **not** imply the two events are correlated in generated rules. The `timing_model` is measured by the evaluator; it is not encoded in the static rules. Review the manifest and adapt field mappings, data sources, and thresholds for your environment before deploying any draft.

The SPL drafts expect normalized fields `event_type`, `image`, `command_line`, `http_host`, and `http_uri`. The process KQL draft uses Microsoft Defender `DeviceProcessEvents` (`FolderPath`, `ProcessCommandLine`); the HTTP KQL draft uses `CommonSecurityLog` (`DestinationHostName`, `RequestURL`). These tables and mappings are starting points, since vendors and ingestion pipelines differ. Suricata's host `content` match is broader than the exact host comparison used by the evaluator and other drafts.

## Evaluate

```bash
python -m beacon_to_blue.evaluate \
  --behavior spec/examples/http_beacon_minimal.yml \
  --positive datasets/malicious_like/http_beacon_minimal.jsonl \
  --benign datasets/benign/http_lookalike.jsonl \
  --out out/report_http_beacon_minimal.json
```

The report includes event counts, matched event counts, hit or false positive rate, and the index of the first match for each dataset. If the spec has a timing model and HTTP criteria, it also reports qualifying source-host/destination groups, the first detection time, observed intervals, and latency from the first event in the qualifying run.

The sample positive dataset has callbacks at approximately 15-second intervals. The benign lookalike reaches the same HTTP path at irregular intervals. Both can have event-level matches; the timing result distinguishes them. Rates from these small synthetic files are examples, not estimates of production performance.

### Matching semantics

- Values within one field are alternatives: `image_contains: [curl, wget]` matches either image.
- Different populated fields must all match. HTTP host comparisons are case-insensitive and exact; URI and process fields use case-insensitive substring matching.
- An event type with no observable criteria never matches. Empty specs are rejected.
- Timing groups matching HTTP events by `host` and `http_host`, sorts their timezone-aware `ts` values, and looks for `min_samples` consecutive events whose intervals are each within `interval_s ± jitter_s`. `min_samples` defaults to 3. Events without usable timestamps or grouping fields are counted as skipped.

Example:

```yaml
id: http_beacon_minimal
name: Periodic HTTP heartbeat to single domain
timing_model:
  interval_s: 15
  jitter_s: 3
  min_samples: 3
observables:
  http:
    domains: [example.com]
    uri_contains: [/heartbeat]
required_telemetry:
  - proxy/http logs with host, URI, source host, and timestamp
```

See [the JSON Schema](spec/schema.json) and [example specs](spec/examples) for the full format. A packaged copy of the schema is included so validation works after wheel installation.

## Generate repeatable sample telemetry

The simulator writes JSONL without sending traffic:

```bash
python simulator/generate_events.py --mode periodic-http --count 20 --out out/periodic.jsonl
python simulator/generate_events.py --mode irregular-http --count 20 --out out/irregular.jsonl
python simulator/generate_events.py --mode process --count 20 --out out/process.jsonl
```

`--seed`, `--start`, `--interval-s`, `--jitter-s`, `--host`, `--domain`, and `--uri` control the generated samples. The default seed and start time make repeated runs byte-for-byte reproducible.

## Development

```bash
pytest -q
make demo
```

CI runs the tests, sample compilation, evaluation, and synthetic event generator. The project is intended for repeatable detection research and review, not production deployment without local validation.

MIT licensed.
