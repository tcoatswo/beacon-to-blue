#!/usr/bin/env python3
"""Generate benign, synthetic events resembling common persistence + beacon signals.

This script does NOT modify the system. It only writes JSONL to disk.
"""

from __future__ import annotations

import argparse
import json
import random
from datetime import datetime, timezone
from pathlib import Path


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", type=Path, required=True)
    ap.add_argument("--count", type=int, default=200)
    args = ap.parse_args()

    random.seed(1337)

    images = ["/usr/bin/crontab", "/usr/bin/curl", "/usr/bin/python3", "/bin/bash"]
    users = ["ubuntu", "ec2-user", "tyler", "root"]
    hosts = ["ip-10-0-1-10", "ip-10-0-2-20"]

    args.out.parent.mkdir(parents=True, exist_ok=True)
    with args.out.open("w", encoding="utf-8") as f:
        for i in range(args.count):
            img = random.choice(images)
            cmd = img
            if img.endswith("crontab"):
                cmd += random.choice([" -l", " -"])
            elif img.endswith("curl"):
                cmd += " -sS https://example.com/heartbeat"
            elif img.endswith("python3"):
                cmd += " agent.py"
            elif img.endswith("bash"):
                cmd += " -lc echo ok"

            event = {
                "ts": now_iso(),
                "host": random.choice(hosts),
                "user": random.choice(users),
                "event_type": "process_creation",
                "image": img,
                "command_line": cmd,
                "pid": 1000 + i,
            }
            f.write(json.dumps(event) + "\n")


if __name__ == "__main__":
    main()
