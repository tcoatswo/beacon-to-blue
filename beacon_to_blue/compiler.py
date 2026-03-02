from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional

import yaml
from jsonschema import Draft202012Validator

from .schema import load_schema


def load_behavior(path: Path) -> Dict[str, Any]:
    raw = path.read_text(encoding="utf-8")
    if path.suffix.lower() in {".yml", ".yaml"}:
        data = yaml.safe_load(raw)
    else:
        data = json.loads(raw)

    schema = load_schema()
    v = Draft202012Validator(schema)
    errors = sorted(v.iter_errors(data), key=lambda e: e.path)
    if errors:
        msg = "\n".join([f"- {list(e.path)}: {e.message}" for e in errors])
        raise ValueError(f"Behavior spec validation failed for {path}:\n{msg}")

    return data


@dataclass
class CompiledArtifacts:
    behavior_id: str
    sigma_rule: str
    splunk_spl: str
    kql: str
    suricata_rule: Optional[str] = None


def _contains_clause(field: str, values: List[str], op: str) -> str:
    # op is one of: splunk|kql
    if op == "splunk":
        parts = [f'{field}="*{v}*"' for v in values]
        return "(" + " OR ".join(parts) + ")"
    if op == "kql":
        parts = [f'{field} has "{v}"' for v in values]
        return "(" + " or ".join(parts) + ")"
    raise ValueError(op)


def compile_behavior(behavior: Dict[str, Any]) -> CompiledArtifacts:
    bid = behavior["id"]
    title = behavior["name"]
    desc = behavior.get("description", "")

    # Minimal cross-platform model: process + http
    proc = behavior.get("observables", {}).get("process_creation", {})
    http = behavior.get("observables", {}).get("http", {})

    image_contains = proc.get("image_contains", [])
    cmd_contains = proc.get("command_line_contains", [])
    domains = http.get("domains", [])
    uri_contains = http.get("uri_contains", [])

    # Sigma YAML (very small rule, intentionally not exhaustive)
    sigma = {
        "title": title,
        "id": bid,
        "status": "experimental",
        "description": desc,
        "logsource": {"category": "process_creation"},
        "detection": {
            "selection": {},
            "condition": "selection",
        },
        "falsepositives": behavior.get("false_positive_notes", []),
        "level": "medium",
    }
    if image_contains:
        sigma["detection"]["selection"]["Image|contains"] = image_contains
    if cmd_contains:
        sigma["detection"]["selection"]["CommandLine|contains"] = cmd_contains

    sigma_rule = yaml.safe_dump(sigma, sort_keys=False)

    # SPL / KQL
    spl = ["index=* sourcetype=* event_type=process_creation"]
    if image_contains:
        spl.append(_contains_clause("image", image_contains, "splunk"))
    if cmd_contains:
        spl.append(_contains_clause("command_line", cmd_contains, "splunk"))
    splunk_spl = " | search " + " ".join(spl[1:]) if len(spl) > 1 else spl[0]
    splunk_spl = spl[0] + splunk_spl

    kql = ["SecurityEvent"]
    where = []
    if image_contains:
        where.append(_contains_clause("Image", image_contains, "kql"))
    if cmd_contains:
        where.append(_contains_clause("CommandLine", cmd_contains, "kql"))
    kql_query = "\n| where " + " and ".join(where) if where else ""
    kql = "\n".join(kql) + kql_query

    # Optional: Suricata only if domains exist
    suri = None
    if domains:
        # Note: demonstrative. Real TLS/HTTP parsing varies by environment.
        dom = domains[0]
        suri = (
            f'alert http any any -> any any (msg:"{title}"; http.host; content:"{dom}"; nocase; sid:9000001; rev:1;)'
        )

    return CompiledArtifacts(
        behavior_id=bid,
        sigma_rule=sigma_rule,
        splunk_spl=splunk_spl,
        kql=kql,
        suricata_rule=suri,
    )
