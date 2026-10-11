from __future__ import annotations

import json
from importlib.resources import files

def load_schema() -> dict:
    return json.loads(files("beacon_to_blue").joinpath("schema.json").read_text(encoding="utf-8"))
