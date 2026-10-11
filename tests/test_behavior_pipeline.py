import json
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

from beacon_to_blue.compiler import compile_behavior, load_behavior
from beacon_to_blue.evaluate import analyze_timing, build_report, iter_jsonl, match_event
from beacon_to_blue.schema import load_schema


EXAMPLE = Path("spec/examples/http_beacon_minimal.yml")


def test_matching_uses_or_within_fields_and_and_between_fields():
    behavior = {
        "id": "example",
        "observables": {
            "process_creation": {
                "image_contains": ["curl", "wget"],
                "command_line_contains": ["/heartbeat"],
            },
            "http": {"domains": ["example.com"], "uri_contains": ["/heartbeat", "/checkin"]},
        },
    }
    assert match_event(behavior, {"event_type": "process_creation", "image": "/bin/wget", "command_line": "wget /heartbeat"})
    assert not match_event(behavior, {"event_type": "process_creation", "image": "/bin/wget", "command_line": "wget /status"})
    assert match_event(behavior, {"event_type": "network_http", "http_host": "EXAMPLE.COM", "http_uri": "/checkin"})
    assert not match_event(behavior, {"event_type": "network_http", "http_host": "notexample.com", "http_uri": "/heartbeat"})
    assert not match_event({"observables": {"http": {"domains": ["example.com"]}}}, {"event_type": "process_creation"})


def test_compiler_emits_event_specific_rules_and_unique_suricata_ids():
    behavior = load_behavior(EXAMPLE)
    behavior["observables"]["http"]["domains"].append("second.example")
    artifacts = compile_behavior(behavior)
    files = artifacts.files()
    assert {"sigma.yml", "sigma_http.yml", "splunk.spl", "splunk_http.spl", "kql.kql", "kql_http.kql", "suricata.rules"} <= files.keys()
    assert yaml.safe_load(files["sigma.yml"])["logsource"]["category"] == "process_creation"
    assert yaml.safe_load(files["sigma_http.yml"])["logsource"]["category"] == "proxy"
    assert "http_host" in files["splunk_http.spl"]
    assert files["suricata.rules"].count("alert http") == 2
    assert len({line.split("sid:")[1].split(";")[0] for line in files["suricata.rules"].splitlines()}) == 2
    behavior["observables"].pop("process_creation")
    assert "sigma.yml" not in compile_behavior(behavior).files()


def test_timing_distinguishes_periodic_and_irregular_lookalikes():
    behavior = load_behavior(EXAMPLE)
    positive = list(iter_jsonl(Path("datasets/malicious_like/http_beacon_minimal.jsonl")))
    benign = list(iter_jsonl(Path("datasets/benign/http_lookalike.jsonl")))
    report = build_report(behavior, positive, benign)
    assert report["positive"]["timing"]["qualifying_groups"] == 1
    assert report["positive"]["timing"]["detections"][0]["latency_s"] == 29
    assert report["benign"]["hits"] > 0
    assert report["benign"]["timing"]["qualifying_groups"] == 0


def test_timing_does_not_combine_hosts_or_accept_missing_timestamps():
    behavior = load_behavior(EXAMPLE)
    base = {"event_type": "network_http", "http_host": "example.com", "http_uri": "/heartbeat"}
    events = [
        {**base, "host": "a", "ts": "2026-03-02T00:00:00Z"},
        {**base, "host": "b", "ts": "2026-03-02T00:00:15Z"},
        {**base, "host": "a", "ts": "2026-03-02T00:00:30Z"},
        {**base, "host": "a", "ts": "invalid"},
    ]
    result = analyze_timing(behavior, events)
    assert result["qualifying_groups"] == 0
    assert result["groups_evaluated"] == 2
    assert result["skipped_missing_or_invalid_timestamps"] == 1


def test_validation_rejects_empty_observables_and_bad_timing(tmp_path):
    path = tmp_path / "empty.yml"
    path.write_text("id: empty\nname: Empty\nobservables: {http: {domains: []}}\n")
    with pytest.raises(ValueError):
        load_behavior(path)
    path.write_text("id: bad\nname: Bad\nobservables: {http: {domains: [example.com]}}\ntiming_model: {interval_s: -1}\n")
    with pytest.raises(ValueError, match="interval_s"):
        load_behavior(path)


def test_packaged_schema_matches_public_schema():
    assert load_schema() == json.loads(Path("spec/schema.json").read_text())


def test_cli_compiles_directory_with_manifest(tmp_path):
    output = tmp_path / "artifacts"
    subprocess.run(
        [sys.executable, "-m", "beacon_to_blue.cli", "--input", "spec/examples", "--out", str(output)],
        check=True,
        capture_output=True,
        text=True,
    )
    manifest = json.loads((output / "http_beacon_minimal" / "manifest.json").read_text())
    assert "sigma_http.yml" in manifest["artifacts"]
    assert manifest["timing_model"]["interval_s"] == 15
    assert len(list(output.iterdir())) == 3
    http_only = load_behavior(EXAMPLE)
    http_only["observables"].pop("process_creation")
    updated = tmp_path / "http_only.yml"
    updated.write_text(yaml.safe_dump(http_only))
    subprocess.run(
        [sys.executable, "-m", "beacon_to_blue.cli", "--input", str(updated), "--out", str(output)],
        check=True,
        capture_output=True,
        text=True,
    )
    assert not (output / "http_beacon_minimal" / "sigma.yml").exists()
    assert (output / "http_beacon_minimal" / "sigma_http.yml").exists()


def test_simulator_generated_traffic_exercises_timing_detector(tmp_path):
    datasets = []
    for mode in ("periodic-http", "irregular-http"):
        path = tmp_path / f"{mode}.jsonl"
        subprocess.run(
            [sys.executable, "simulator/generate_events.py", "--mode", mode, "--count", "8", "--out", str(path)],
            check=True,
            capture_output=True,
            text=True,
        )
        datasets.append(list(iter_jsonl(path)))
    report = build_report(load_behavior(EXAMPLE), *datasets)
    assert report["positive"]["timing"]["qualifying_groups"] == 1
    assert report["benign"]["timing"]["qualifying_groups"] == 0
