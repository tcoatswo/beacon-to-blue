"""Evaluate observable matches and periodic HTTP sequences in synthetic JSONL."""

from __future__ import annotations

import argparse
import json
from collections import defaultdict
from datetime import datetime
from pathlib import Path
from typing import Any, Iterable

from .compiler import load_behavior


def iter_jsonl(path: Path) -> Iterable[dict[str, Any]]:
    with path.open("r", encoding="utf-8") as stream:
        for number, line in enumerate(stream, start=1):
            if line.strip():
                try:
                    event = json.loads(line)
                except json.JSONDecodeError as exc:
                    raise ValueError(f"{path}:{number}: invalid JSON: {exc.msg}") from exc
                if not isinstance(event, dict):
                    raise ValueError(f"{path}:{number}: expected a JSON object")
                yield event


def _contains_any(value: Any, terms: list[str]) -> bool:
    return not terms or any(term.casefold() in str(value or "").casefold() for term in terms)


def match_event(behavior: dict[str, Any], event: dict[str, Any]) -> bool:
    obs = behavior.get("observables", {})
    if event.get("event_type") == "process_creation":
        proc = obs.get("process_creation", {})
        if not any(proc.values()):
            return False
        return (
            _contains_any(event.get("image"), proc.get("image_contains", []))
            and _contains_any(event.get("command_line"), proc.get("command_line_contains", []))
        )
    if event.get("event_type") == "network_http":
        http = obs.get("http", {})
        if not any(http.values()):
            return False
        host = str(event.get("http_host") or "").casefold()
        domains = [domain.casefold() for domain in http.get("domains", [])]
        return (
            (not domains or host in domains)
            and _contains_any(event.get("http_uri"), http.get("uri_contains", []))
        )
    return False


def score(behavior: dict[str, Any], events: list[dict[str, Any]]) -> tuple[int, int]:
    indices = [index for index, event in enumerate(events, start=1) if match_event(behavior, event)]
    return len(indices), indices[0] if indices else -1


def analyze_timing(behavior: dict[str, Any], events: list[dict[str, Any]]) -> dict[str, Any] | None:
    """Find the first interval-conforming run for each endpoint on each source host."""
    model = behavior.get("timing_model")
    http = behavior.get("observables", {}).get("http", {})
    if not model or not any(http.values()):
        return None
    interval = model["interval_s"]
    jitter = model.get("jitter_s", 0)
    min_samples = model.get("min_samples", 3)
    groups: dict[tuple[str, str], list[datetime]] = defaultdict(list)
    skipped = 0
    for event in events:
        if event.get("event_type") != "network_http" or not match_event(behavior, event):
            continue
        try:
            stamp = datetime.fromisoformat(str(event["ts"]).replace("Z", "+00:00"))
            if stamp.tzinfo is None:
                raise ValueError("timezone required")
        except (KeyError, TypeError, ValueError):
            skipped += 1
            continue
        if not event.get("host") or not event.get("http_host"):
            skipped += 1
            continue
        key = (str(event["host"]), str(event["http_host"]).casefold())
        groups[key].append(stamp)

    detections = []
    for (source_host, http_host), stamps in sorted(groups.items()):
        stamps.sort()
        for end in range(min_samples - 1, len(stamps)):
            window = stamps[end - min_samples + 1:end + 1]
            deltas = [(b - a).total_seconds() for a, b in zip(window, window[1:])]
            if all(max(0, interval - jitter) <= delta <= interval + jitter for delta in deltas):
                detections.append({
                    "source_host": source_host,
                    "http_host": http_host,
                    "first_event_ts": window[0].isoformat(),
                    "detected_at_ts": window[-1].isoformat(),
                    "latency_s": (window[-1] - window[0]).total_seconds(),
                    "observed_intervals_s": deltas,
                })
                break
    return {
        "interval_s": interval,
        "jitter_s": jitter,
        "min_samples": min_samples,
        "groups_evaluated": len(groups),
        "qualifying_groups": len(detections),
        "skipped_missing_or_invalid_timestamps": skipped,
        "detections": detections,
    }


def build_report(
    behavior: dict[str, Any],
    positive: list[dict[str, Any]],
    benign: list[dict[str, Any]],
) -> dict[str, Any]:
    report: dict[str, Any] = {"behavior_id": behavior["id"]}
    for label, events in (("positive", positive), ("benign", benign)):
        hits, first = score(behavior, events)
        report[label] = {
            "events": len(events),
            "hits": hits,
            "hit_rate" if label == "positive" else "false_positive_rate": hits / len(events) if events else 0,
            "first_hit_event_index": first,
        }
        timing = analyze_timing(behavior, events)
        if timing is not None:
            report[label]["timing"] = timing
    return report


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--behavior", type=Path, required=True)
    ap.add_argument("--positive", type=Path, required=True)
    ap.add_argument("--benign", type=Path, required=True)
    ap.add_argument("--out", type=Path, required=True)
    args = ap.parse_args()

    report = build_report(
        load_behavior(args.behavior),
        list(iter_jsonl(args.positive)),
        list(iter_jsonl(args.benign)),
    )
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(args.out)


if __name__ == "__main__":
    main()
