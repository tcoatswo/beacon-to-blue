#!/usr/bin/env python3
"""Write reproducible synthetic telemetry; no network or system changes."""

from __future__ import annotations

import argparse
import json
import random
from datetime import datetime, timedelta, timezone
from pathlib import Path


def generate_process_events(count: int, seed: int, start: datetime):
    rng = random.Random(seed)
    images = ["/usr/bin/crontab", "/usr/bin/curl", "/usr/bin/python3", "/bin/bash"]
    users = ["ubuntu", "ec2-user", "tyler", "root"]
    hosts = ["ip-10-0-1-10", "ip-10-0-2-20"]
    for index in range(count):
        image = rng.choice(images)
        if image.endswith("crontab"):
            command = image + rng.choice([" -l", " -"])
        elif image.endswith("curl"):
            command = image + " -sS https://example.com/heartbeat"
        elif image.endswith("python3"):
            command = image + " agent.py"
        else:
            command = image + " -lc echo ok"
        yield {
            "ts": (start + timedelta(seconds=index)).isoformat(),
            "host": rng.choice(hosts),
            "user": rng.choice(users),
            "event_type": "process_creation",
            "image": image,
            "command_line": command,
            "pid": 1000 + index,
        }


def generate_http_events(
    count: int,
    seed: int,
    start: datetime,
    interval_s: float,
    jitter_s: float,
    irregular: bool,
    host: str,
    domain: str,
    uri: str,
):
    rng = random.Random(seed)
    elapsed = 0.0
    for index in range(count):
        if index:
            delta = (
                interval_s * rng.uniform(2, 6)
                if irregular else interval_s + rng.uniform(-jitter_s, jitter_s)
            )
            elapsed += delta
        yield {
            "ts": (start + timedelta(seconds=elapsed)).isoformat(),
            "host": host,
            "event_type": "network_http",
            "http_host": domain,
            "http_uri": uri,
            "status": 200,
        }


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--out", type=Path, required=True)
    ap.add_argument("--mode", choices=("process", "periodic-http", "irregular-http"), default="process")
    ap.add_argument("--count", type=int, default=200)
    ap.add_argument("--seed", type=int, default=1337)
    ap.add_argument("--interval-s", type=float, default=15)
    ap.add_argument("--jitter-s", type=float, default=3)
    ap.add_argument("--host", default="lab-1")
    ap.add_argument("--domain", default="example.com")
    ap.add_argument("--uri", default="/heartbeat")
    ap.add_argument("--start", default="2026-03-02T00:00:00Z", help="ISO 8601 timestamp with timezone")
    args = ap.parse_args()
    if args.count < 1 or args.interval_s <= 0 or args.jitter_s < 0 or args.jitter_s >= args.interval_s:
        ap.error("count must be positive and 0 <= jitter-s < interval-s")
    try:
        start = datetime.fromisoformat(args.start.replace("Z", "+00:00"))
        if start.tzinfo is None:
            raise ValueError("timezone required")
        start = start.astimezone(timezone.utc)
    except ValueError as exc:
        ap.error(f"invalid --start: {exc}")

    if args.mode == "process":
        events = generate_process_events(args.count, args.seed, start)
    else:
        events = generate_http_events(
            args.count,
            args.seed,
            start,
            args.interval_s,
            args.jitter_s,
            args.mode == "irregular-http",
            args.host,
            args.domain,
            args.uri,
        )
    args.out.parent.mkdir(parents=True, exist_ok=True)
    with args.out.open("w", encoding="utf-8") as stream:
        for event in events:
            stream.write(json.dumps(event) + "\n")
    print(args.out)


if __name__ == "__main__":
    main()
