import re
from uuid import UUID

import pytest

from verigence_security.core.correlation import resolve_correlation_id
from verigence_security.core.errors import SecurityError


def test_preserves_valid_correlation_id():
    assert resolve_correlation_id("abc-123:DI") == "abc-123:DI"


def test_generates_uuid_when_absent():
    value = resolve_correlation_id(None)
    assert str(UUID(value)) == value


def test_rejects_invalid_correlation_id():
    with pytest.raises(SecurityError) as exc:
        resolve_correlation_id(" bad value ")
    assert exc.value.code == "CORRELATION_ID_INVALID"
