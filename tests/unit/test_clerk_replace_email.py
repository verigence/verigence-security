from __future__ import annotations

import json

import httpx
import pytest

from verigence_security.adapters.clerk_backend import ClerkBackendClient, ClerkBackendError
from verigence_security.config import Settings


class _FakeClerkServer:
    """A small stand-in for the provider's email-address rules: ids, one primary, and no deleting
    the primary address. Records every call so the ORDER of calls can be checked."""

    def __init__(self, emails: list[str], *, verify_new: bool = True, taken: set[str] | None = None) -> None:
        self.items = [
            {"id": f"idn_{i}", "email_address": e, "verification": {"status": "verified"}} for i, e in enumerate(emails)
        ]
        self.primary = "idn_0"
        self.verify_new = verify_new
        self.taken = taken or set()
        self.calls: list[tuple[str, str]] = []

    def user(self) -> dict[str, object]:
        return {"id": "user_1", "primary_email_address_id": self.primary, "email_addresses": self.items}

    def __call__(self, request: httpx.Request) -> httpx.Response:
        path = request.url.path.removeprefix("/v1")
        self.calls.append((request.method, path))
        if request.method == "GET" and path == "/users/user_1":
            return httpx.Response(200, json=self.user())
        if request.method == "POST" and path == "/email_addresses":
            body = json.loads(request.content)
            if body["email_address"] in self.taken:
                return httpx.Response(422, json={"errors": [{"code": "form_identifier_exists"}]})
            item = {
                "id": f"idn_{len(self.items) + 10}",
                "email_address": body["email_address"],
                "verification": {"status": "verified" if body["verified"] and self.verify_new else "unverified"},
            }
            self.items.append(item)
            return httpx.Response(200, json=item)
        if request.method == "PATCH" and path.startswith("/email_addresses/"):
            self.primary = path.rsplit("/", 1)[1]
            return httpx.Response(200, json={"id": self.primary})
        if request.method == "DELETE" and path.startswith("/email_addresses/"):
            target = path.rsplit("/", 1)[1]
            if target == self.primary:
                return httpx.Response(400, json={"errors": [{"code": "primary_cannot_be_deleted"}]})
            self.items = [i for i in self.items if i["id"] != target]
            return httpx.Response(200, json={"deleted": True})
        return httpx.Response(404, json={})


def _clerk(server: _FakeClerkServer) -> tuple[ClerkBackendClient, httpx.Client]:
    client = httpx.Client(transport=httpx.MockTransport(server))
    settings = Settings(
        clerk_secret_key="clerk-unit-test-credential", clerk_backend_api_url="https://api.clerk.test/v1"
    )
    return ClerkBackendClient(settings, client=client), client


def _emails(server: _FakeClerkServer) -> list[str]:
    return [str(i["email_address"]) for i in server.items]


def test_new_email_is_added_and_primary_before_the_old_one_is_removed() -> None:
    server = _FakeClerkServer(["old@example.com"])
    clerk, client = _clerk(server)
    try:
        assert clerk.replace_primary_email("user_1", "New@Example.com") == "old@example.com"
        added = [c for c in server.calls if c[0] == "POST"]
        assert added == [("POST", "/email_addresses")]
        assert not any(c[0] == "DELETE" for c in server.calls)  # replace never deletes
        assert clerk.primary_email("user_1") == "new@example.com"
        assert clerk.remove_other_emails("user_1", "new@example.com") == 1
        assert _emails(server) == ["new@example.com"]
    finally:
        client.close()


def test_repeating_the_replace_changes_nothing_more() -> None:
    server = _FakeClerkServer(["old@example.com"])
    clerk, client = _clerk(server)
    try:
        clerk.replace_primary_email("user_1", "new@example.com")
        before = len(server.items)
        calls_before = [c for c in server.calls if c[0] in ("POST", "PATCH", "DELETE")]
        assert clerk.replace_primary_email("user_1", "new@example.com") == "new@example.com"
        assert len(server.items) == before
        assert [c for c in server.calls if c[0] in ("POST", "PATCH", "DELETE")] == calls_before
    finally:
        client.close()


def test_an_address_left_from_an_earlier_attempt_is_reused_not_added_again() -> None:
    server = _FakeClerkServer(["old@example.com", "new@example.com"])
    clerk, client = _clerk(server)
    try:
        clerk.replace_primary_email("user_1", "new@example.com")
        assert not any(c[0] == "POST" for c in server.calls)
        assert clerk.primary_email("user_1") == "new@example.com"
    finally:
        client.close()


def test_an_email_the_provider_will_not_verify_leaves_everything_as_it_was() -> None:
    server = _FakeClerkServer(["old@example.com"], verify_new=False)
    clerk, client = _clerk(server)
    try:
        with pytest.raises(ClerkBackendError):
            clerk.replace_primary_email("user_1", "new@example.com")
        assert _emails(server) == ["old@example.com"] and server.primary == "idn_0"
    finally:
        client.close()


def test_an_email_already_used_at_the_provider_is_refused_and_nothing_changes() -> None:
    server = _FakeClerkServer(["old@example.com"], taken={"new@example.com"})
    clerk, client = _clerk(server)
    try:
        with pytest.raises(ClerkBackendError) as caught:
            clerk.replace_primary_email("user_1", "new@example.com")
        assert caught.value.provider_code == "form_identifier_exists"
        assert _emails(server) == ["old@example.com"] and server.primary == "idn_0"
    finally:
        client.close()


def test_the_cleanup_refuses_to_run_unless_the_email_to_keep_is_primary() -> None:
    server = _FakeClerkServer(["old@example.com", "other@example.com"])
    clerk, client = _clerk(server)
    try:
        with pytest.raises(ClerkBackendError):
            clerk.remove_other_emails("user_1", "other@example.com")
        assert len(server.items) == 2
    finally:
        client.close()
