from __future__ import annotations

import re

ONBOARDING_KEY_PREFIX = "VGN"
ONBOARDING_KEY_DIGITS = 8
ONBOARDING_KEY_PATTERN = re.compile(rf"^{ONBOARDING_KEY_PREFIX}[0-9]{{{ONBOARDING_KEY_DIGITS}}}$")
ONBOARDING_KEY_EXAMPLE = f"{ONBOARDING_KEY_PREFIX}{'0' * ONBOARDING_KEY_DIGITS}"


def normalize_onboarding_key(value: str) -> str:
    return value.strip().upper()


def require_onboarding_key_shape(value: str) -> str:
    normalized = normalize_onboarding_key(value)
    if ONBOARDING_KEY_PATTERN.fullmatch(normalized) is None:
        raise ValueError(
            f"Onboarding key must be {ONBOARDING_KEY_PREFIX} followed by "
            f"{ONBOARDING_KEY_DIGITS} digits"
        )
    return normalized
