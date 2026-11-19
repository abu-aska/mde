# ruff: noqa: E501
"""Worker module for verifying Python CST byte-span edits."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class Entry:
    key: str
    value: int


# Preserve this sibling comment and trailing comma formatting.
DEFAULT_WEIGHTS = {
    "prose": 1.0,
    "code": 0.4,
}


def compute_score(entries: list[Entry]) -> int:  # type: ignore[misc]
    """Sum positive entry values."""
    total = 0
    for item in entries:
        if item.value > 0:
            total += item.value
    return total


def dynamic_dispatch(target: Any, method_name: str, payload: dict[str, Any]) -> Any:
    """Calls a named attribute dynamically (triggers G2.2 unresolved dynamic site)."""
    fn = getattr(target, method_name)
    return fn(payload)
