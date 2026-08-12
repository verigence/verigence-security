from __future__ import annotations

import re

_PERMISSION = re.compile(r"^[a-z0-9]+(\.[a-z0-9_-]+){2,}$")


def is_canonical_permission(value: str) -> bool:
    return bool(_PERMISSION.fullmatch(value)) and ":" not in value


def validate_permissions(values: list[str]) -> list[str]:
    invalid = [p for p in values if not is_canonical_permission(p)]
    if invalid:
        raise ValueError(f"Invalid canonical permission(s): {', '.join(invalid)}")
    return sorted(set(values))
