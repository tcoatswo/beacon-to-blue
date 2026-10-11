from __future__ import annotations

import argparse
import json
from pathlib import Path

from .compiler import ARTIFACT_NAMES, compile_behavior, load_behavior


def main() -> None:
    ap = argparse.ArgumentParser(prog="beacon-to-blue")
    ap.add_argument("--input", type=Path, required=True, help="Behavior spec or directory of specs")
    ap.add_argument("--out", type=Path, help="Output directory (required for compilation)")
    ap.add_argument("--validate-only", action="store_true", help="Validate specs without writing artifacts")
    args = ap.parse_args()

    if not args.validate_only and args.out is None:
        ap.error("--out is required unless --validate-only is set")
    paths = (
        sorted(path for path in args.input.iterdir() if path.suffix.lower() in {".yml", ".yaml", ".json"})
        if args.input.is_dir() else [args.input]
    )
    if not paths:
        ap.error("no behavior specs found")
    try:
        behaviors = [(path, load_behavior(path)) for path in paths]
    except ValueError as exc:
        ap.error(str(exc))
    ids = [behavior["id"] for _, behavior in behaviors]
    if len(ids) != len(set(ids)):
        ap.error("duplicate behavior IDs in input directory")
    for path, behavior in behaviors:
        if args.validate_only:
            print(f"valid: {path}")
            continue
        artifacts = compile_behavior(behavior)
        out = args.out / artifacts.behavior_id
        out.mkdir(parents=True, exist_ok=True)
        files = artifacts.files()
        for name in set(ARTIFACT_NAMES) - files.keys():
            (out / name).unlink(missing_ok=True)
        for name, value in files.items():
            (out / name).write_text(value, encoding="utf-8")
        manifest = {
            "behavior_id": behavior["id"],
            "source": path.name,
            "artifacts": sorted(files),
            "assumptions": behavior.get("assumptions", []),
            "required_telemetry": behavior.get("required_telemetry", []),
            "timing_model": behavior.get("timing_model"),
            "note": "Static rules match observables only; evaluate.py measures cadence separately.",
        }
        (out / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
        print(out)


if __name__ == "__main__":
    main()
