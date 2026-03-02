from pathlib import Path

from beacon_to_blue.compiler import compile_behavior, load_behavior


def test_compile_generates_outputs():
    b = load_behavior(Path("spec/examples/http_beacon_minimal.yml"))
    artifacts = compile_behavior(b)
    assert "title" in artifacts.sigma_rule.lower()
    assert "search" in artifacts.splunk_spl
    assert "where" in artifacts.kql or artifacts.kql.startswith("SecurityEvent")
