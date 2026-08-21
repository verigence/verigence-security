from __future__ import annotations

import pytest

from verigence_security.services.onboarding_key import require_onboarding_key_shape


def test_onboarding_key_shape_normalizes_prefix_case() -> None:
    assert require_onboarding_key_shape(" vgn-1234567 ") == "VGN-1234567"


@pytest.mark.parametrize(
    "value",
    [
        "ABC12345678",
        "VGN1234ABCD",
        "VGN1234567",
        "VGN123456789",
        "VGN-12345678",
        "",
    ],
)
def test_onboarding_key_shape_rejects_invalid_structure(value: str) -> None:
    with pytest.raises(ValueError):
        require_onboarding_key_shape(value)
