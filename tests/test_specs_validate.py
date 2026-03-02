from pathlib import Path

from beacon_to_blue.compiler import load_behavior


def test_example_specs_validate():
    examples = Path("spec/examples").glob("*.yml")
    for p in examples:
        load_behavior(p)
