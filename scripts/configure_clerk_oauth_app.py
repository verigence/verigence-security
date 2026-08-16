from __future__ import annotations

import json
import os

import httpx

CLERK_API = "https://api.clerk.com/v1"
APP_NAME = "Verigence Security DEV"


def main() -> None:
    secret = _required("CLERK_SECRET_KEY")
    public_domain = _required("RAILWAY_PUBLIC_DOMAIN")
    redirect_uri = f"https://{public_domain}/auth/callback"
    headers = {"Authorization": f"Bearer {secret}"}

    with httpx.Client(timeout=20.0, headers=headers) as client:
        response = client.get(f"{CLERK_API}/oauth_applications", params={"limit": 100})
        response.raise_for_status()
        payload = response.json()
        applications = payload.get("data", []) if isinstance(payload, dict) else payload
        existing = next(
            (item for item in applications if isinstance(item, dict) and item.get("name") == APP_NAME),
            None,
        )

        if existing is None:
            response = client.post(
                f"{CLERK_API}/oauth_applications",
                json={
                    "name": APP_NAME,
                    "redirect_uris": [redirect_uri],
                    "scopes": "profile email",
                    "public": False,
                },
            )
            response.raise_for_status()
            application = response.json()
        else:
            application_id = _field(existing, "id")
            response = client.patch(
                f"{CLERK_API}/oauth_applications/{application_id}",
                json={
                    "name": APP_NAME,
                    "redirect_uris": [redirect_uri],
                    "scopes": "profile email",
                    "public": False,
                },
            )
            response.raise_for_status()
            response = client.post(
                f"{CLERK_API}/oauth_applications/{application_id}/rotate_secret"
            )
            response.raise_for_status()
            application = response.json()

    values = {
        "CLERK_OAUTH_AUTHORIZE_URL": _field(application, "authorize_url", "authorizeUrl"),
        "CLERK_OAUTH_TOKEN_URL": _field(application, "token_fetch_url", "tokenFetchUrl"),
        "CLERK_OAUTH_USERINFO_URL": _field(application, "user_info_url", "userInfoUrl"),
        "CLERK_OAUTH_CLIENT_ID": _field(application, "client_id", "clientId"),
        "CLERK_OAUTH_CLIENT_SECRET": _field(application, "client_secret", "clientSecret"),
        "CLERK_OAUTH_REDIRECT_URI": redirect_uri,
    }
    print(json.dumps(values))


def _field(value: dict, *names: str) -> str:
    for name in names:
        item = value.get(name)
        if isinstance(item, str) and item:
            return item
    raise RuntimeError(f"Clerk OAuth application response is missing one of: {', '.join(names)}")


def _required(name: str) -> str:
    value = os.environ.get(name, "")
    if not value:
        raise RuntimeError(f"{name} is required")
    return value


if __name__ == "__main__":
    main()
