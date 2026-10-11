"""Compile a behavior spec into auditable, event-specific detection artifacts."""

from __future__ import annotations

import json
import uuid
import zlib
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml
from jsonschema import Draft202012Validator

from .schema import load_schema

ARTIFACT_NAMES = (
    "sigma.yml",
    "splunk.spl",
    "kql.kql",
    "sigma_http.yml",
    "splunk_http.spl",
    "kql_http.kql",
    "suricata.rules",
)


def load_behavior(path: Path) -> dict[str, Any]:
    try:
        raw = path.read_text(encoding="utf-8")
        data = yaml.safe_load(raw) if path.suffix.lower() in {".yml", ".yaml"} else json.loads(raw)
    except (OSError, ValueError, yaml.YAMLError) as exc:
        raise ValueError(f"Cannot read behavior spec {path}: {exc}") from exc

    errors = sorted(Draft202012Validator(load_schema()).iter_errors(data), key=lambda e: str(e.path))
    if errors:
        msg = "\n".join(f"- {'.'.join(map(str, e.path)) or '<root>'}: {e.message}" for e in errors)
        raise ValueError(f"Behavior spec validation failed for {path}:\n{msg}")
    obs = data["observables"]
    if not any(values for group in obs.values() for values in group.values()):
        raise ValueError(f"Behavior spec validation failed for {path}: at least one observable value is required")
    if data.get("timing_model") and not any(obs.get("http", {}).values()):
        raise ValueError(f"Behavior spec validation failed for {path}: timing_model requires HTTP observables")
    return data


@dataclass
class CompiledArtifacts:
    behavior_id: str
    sigma_rule: str | None = None
    splunk_spl: str | None = None
    kql: str | None = None
    sigma_http_rule: str | None = None
    splunk_http_spl: str | None = None
    kql_http: str | None = None
    suricata_rule: str | None = None

    def files(self) -> dict[str, str]:
        content = {
            "sigma.yml": self.sigma_rule,
            "splunk.spl": self.splunk_spl,
            "kql.kql": self.kql,
            "sigma_http.yml": self.sigma_http_rule,
            "splunk_http.spl": self.splunk_http_spl,
            "kql_http.kql": self.kql_http,
            "suricata.rules": self.suricata_rule,
        }
        return {
            name: value + ("" if value.endswith("\n") else "\n")
            for name, value in content.items()
            if value is not None
        }


def _quoted(value: str) -> str:
    return json.dumps(value, ensure_ascii=False)


def _splunk_value(value: str) -> str:
    # Escape user wildcards so only compiler-added surrounding wildcards act as operators.
    return '"*' + value.replace("\\", "\\\\").replace('"', '\\"').replace("*", "\\*") + '*"'


def _any_clause(field: str, values: list[str], dialect: str, exact: bool = False) -> str:
    if dialect == "splunk":
        parts = [f"{field}={_quoted(v) if exact else _splunk_value(v)}" for v in values]
        return "(" + " OR ".join(parts) + ")"
    parts = [f"{field} {'=~' if exact else 'contains'} {_quoted(v)}" for v in values]
    return "(" + " or ".join(parts) + ")"


def _sigma(behavior: dict[str, Any], category: str, selection: dict[str, Any], suffix: str) -> str:
    rule = {
        "title": behavior["name"] + suffix,
        "id": str(uuid.uuid5(uuid.NAMESPACE_URL, "beacon-to-blue:" + behavior["id"] + ":" + category)),
        "status": "experimental",
        "description": behavior.get("description", ""),
        "logsource": {"category": category},
        "detection": {"selection": selection, "condition": "selection"},
        "falsepositives": behavior.get("false_positive_notes", []),
        "level": "medium",
    }
    techniques = [
        tag for tag in behavior.get("tactics_techniques", [])
        if tag.upper().startswith("T") and not tag.upper().startswith("TA")
    ]
    if techniques:
        rule["tags"] = [f"attack.{tag.lower()}" for tag in techniques]
    return yaml.safe_dump(rule, sort_keys=False)


def _suricata_escape(value: str) -> str:
    return value.replace("\\", "\\\\").replace('"', '\\"').replace(";", "\\;").replace("|", "\\|")


def compile_behavior(behavior: dict[str, Any]) -> CompiledArtifacts:
    """Generate separate process and HTTP rules; never emit a match-all rule."""
    bid = behavior["id"]
    obs = behavior["observables"]
    proc = obs.get("process_creation", {})
    http = obs.get("http", {})
    result = CompiledArtifacts(behavior_id=bid)

    image = proc.get("image_contains", [])
    command = proc.get("command_line_contains", [])
    if image or command:
        selection: dict[str, Any] = {}
        clauses: list[str] = []
        kql_clauses: list[str] = []
        if image:
            selection["Image|contains"] = image
            clauses.append(_any_clause("image", image, "splunk"))
            kql_clauses.append(_any_clause("Image", image, "kql"))
        if command:
            selection["CommandLine|contains"] = command
            clauses.append(_any_clause("command_line", command, "splunk"))
            kql_clauses.append(_any_clause("CommandLine", command, "kql"))
        result.sigma_rule = _sigma(behavior, "process_creation", selection, " - process")
        result.splunk_spl = "index=* sourcetype=* event_type=process_creation | search " + " AND ".join(clauses)
        result.kql = (
            "DeviceProcessEvents\n"
            "| extend Image = tostring(FolderPath), CommandLine = tostring(ProcessCommandLine)\n"
            "| where " + " and ".join(kql_clauses)
        )

    domains = http.get("domains", [])
    uris = http.get("uri_contains", [])
    if domains or uris:
        selection = {}
        clauses = []
        kql_clauses = []
        if domains:
            selection["http_host"] = domains
            clauses.append(_any_clause("http_host", domains, "splunk", exact=True))
            kql_clauses.append(_any_clause("http_host", domains, "kql", exact=True))
        if uris:
            selection["http_uri|contains"] = uris
            clauses.append(_any_clause("http_uri", uris, "splunk"))
            kql_clauses.append(_any_clause("http_uri", uris, "kql"))
        result.sigma_http_rule = _sigma(behavior, "proxy", selection, " - HTTP")
        result.splunk_http_spl = "index=* sourcetype=* event_type=network_http | search " + " AND ".join(clauses)
        result.kql_http = (
            "CommonSecurityLog\n"
            "| extend http_host = tostring(DestinationHostName), http_uri = tostring(RequestURL)\n"
            "| where " + " and ".join(kql_clauses)
        )
        if domains:
            rules = []
            for domain in domains:
                sid = 9000000 + zlib.crc32(f"{bid}:{domain}".encode()) % 1000000
                rules.append(
                    f'alert http any any -> any any (msg:"{_suricata_escape(behavior["name"])}"; '
                    f'http.host; content:"{_suricata_escape(domain)}"; nocase; '
                    f'sid:{sid}; rev:1;)'
                )
            result.suricata_rule = "\n".join(rules)
    return result
