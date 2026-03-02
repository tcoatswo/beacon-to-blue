from __future__ import annotations

import argparse
from pathlib import Path

from .compiler import compile_behavior, load_behavior


def main() -> None:
    ap = argparse.ArgumentParser(prog="beacon-to-blue")
    ap.add_argument("--input", type=Path, required=True, help="Path to behavior spec (yaml/json)")
    ap.add_argument("--out", type=Path, required=True, help="Output directory")
    args = ap.parse_args()

    behavior = load_behavior(args.input)
    artifacts = compile_behavior(behavior)

    out = args.out / artifacts.behavior_id
    out.mkdir(parents=True, exist_ok=True)

    (out / "sigma.yml").write_text(artifacts.sigma_rule, encoding="utf-8")
    (out / "splunk.spl").write_text(artifacts.splunk_spl + "\n", encoding="utf-8")
    (out / "kql.kql").write_text(artifacts.kql + "\n", encoding="utf-8")
    if artifacts.suricata_rule:
        (out / "suricata.rules").write_text(artifacts.suricata_rule + "\n", encoding="utf-8")

    print(str(out))


if __name__ == "__main__":
    main()
