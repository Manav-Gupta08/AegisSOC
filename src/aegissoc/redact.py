from __future__ import annotations

from typing import Any

REDACTED = "[REDACTED]"


def redact(value: Any, secrets: list[str]) -> Any:
    """Recursively replace known secret values in strings, dict values, and lists."""
    needles = sorted((s for s in secrets if s), key=len, reverse=True)
    if not needles:
        return value

    def _walk(obj: Any) -> Any:
        if isinstance(obj, str):
            for needle in needles:
                obj = obj.replace(needle, REDACTED)
            return obj
        if isinstance(obj, dict):
            return {k: _walk(v) for k, v in obj.items()}
        if isinstance(obj, (list, tuple)):
            return [_walk(v) for v in obj]
        return obj

    return _walk(value)
