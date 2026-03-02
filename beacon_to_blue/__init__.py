"""beacon-to-blue

Translate attacker-described beacon behaviors into defender-first artifacts.

This is a defensive research/engineering repo: schemas + generators + evaluation.
"""

__all__ = ["compile_behavior", "load_behavior"]

from .compiler import compile_behavior, load_behavior
