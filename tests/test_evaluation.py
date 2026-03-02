import json
from pathlib import Path

from beacon_to_blue.evaluate import match_event
from beacon_to_blue.compiler import load_behavior


def test_evaluation_matches_positive():
    b = load_behavior(Path("spec/examples/http_beacon_minimal.yml"))
    pos = [json.loads(l) for l in Path("datasets/malicious_like/http_beacon_minimal.jsonl").read_text().splitlines() if l.strip()]
    assert any(match_event(b, e) for e in pos)
