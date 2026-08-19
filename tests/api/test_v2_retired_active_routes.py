from __future__ import annotations

from verigence_security.main import app


def test_platformadmin_jwt_routes_are_retired_but_dependent_oauth_compatibility_remains() -> None:
    paths = set(app.openapi().get("paths", {}))

    # Audit Core dev still uses the legacy OAuth/token-exchange contract. Keep these
    # paths temporarily until that dependent repo migrates; no new Security code should
    # consume them.
    assert "/oauth/token" in paths
    assert "/security/v1/auth/login" in paths
    assert "/security/v1/access-sessions" in paths

    # The separate PlatformAdmin JWT control-plane path has no remaining Phase-1 purpose.
    assert "/security/v1/platform/auth/login" not in paths
    assert "/security/v1/platform/bootstrap/claim" not in paths
    assert "/security/v1/platform/me" not in paths
