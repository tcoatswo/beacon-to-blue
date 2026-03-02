"""Evaluation harness for generated detections.

This is NOT a full Sigma engine.
Instead, it evaluates compiled behavior observables against synthetic events.

The goal is to demonstrate research-minded measurement:
- hit rate on positive samples
- false positives on benign lookalikes
- detection latency (events until first hit)
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any, Dict, Iterable, List, Tuple

from .compiler import load_behavior


def iter_jsonl(path: Path) -> Iterable[Dict[str, Any]]:
    with path.open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            yield json.loads(line)


def match_event(behavior: Dict[str, Any], event: Dict[str, Any]) -> bool:
    obs = behavior.get("observables", {})
    proc = obs.get("process_creation", {})
    http = obs.get("http", {})

    if event.get("event_type") == "process_creation":
        img = (event.get("image") or "").lower()
        cmd = (event.get("command_line") or "").lower()
        for s in proc.get("image_contains", []):
            if s.lower() not in img:
                return False
        for s in proc.get("command_line_contains", []):
            if s.lower() not in cmd:
                return False
        return True

    if event.get("event_type") == "network_http":
        host = (event.get("http_host") or "").lower()
        uri = (event.get("http_uri") or "").lower()
        domains = [d.lower() for d in http.get("domains", [])]
        if domains and not any(d in host for d in domains):
            return False
        for s in http.get("uri_contains", []):
            if s.lower() not in uri:
                return False
        return True

    return False


def score(behavior: Dict[str, Any], events: List[Dict[str, Any]]) -> Tuple[int, int]:
    hits = 0
    first_hit = None
    for i, e in enumerate(events, start=1):
        if match_event(behavior, e):
            hits += 1
            if first_hit is None:
                first_hit = i
    return hits, (first_hit or -1)


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--behavior", type=Path, required=True)
    ap.add_argument("--positive", type=Path, required=True)
    ap.add_argument("--benign", type=Path, required=True)
    ap.add_argument("--out", type=Path, required=True)
    args = ap.parse_args()

    behavior = load_behavior(args.behavior)

    pos_events = list(iter_jsonl(args.positive))
    ben_events = list(iter_jsonl(args.benign))

    pos_hits, pos_first = score(behavior, pos_events)
    ben_hits, ben_first = score(behavior, ben_events)

    report = {
        "behavior_id": behavior["id"],
        "positive": {
            "events": len(pos_events),
            "hits": pos_hits,
            "hit_rate": (pos_hits / len(pos_events)) if pos_events else 0,
            "first_hit_event_index": pos_first,
        },
        "benign": {
            "events": len(ben_events),
            "hits": ben_hits,
            "false_positive_rate": (ben_hits / len(ben_events)) if ben_events else 0,
            "first_hit_event_index": ben_first,
        },
    }

    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(args.out)


if __name__ == "__main__":
    main()
