from __future__ import annotations

from pathlib import Path
import json

SCHEMA_PATH = Path(__file__).resolve().parent.parent / "spec" / "schema.json"


def load_schema() -> dict:
    return json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
