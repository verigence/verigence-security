from verigence_security.services.permissions import is_canonical_permission, validate_permissions


def test_canonical_permission_format():
    assert is_canonical_permission("di.document.upload")
    assert is_canonical_permission("di.document.content.read")
    assert not is_canonical_permission("document:upload")
    assert not is_canonical_permission("document.upload")


def test_permission_deduplication():
    assert validate_permissions(["di.document.read","di.document.read"]) == ["di.document.read"]
