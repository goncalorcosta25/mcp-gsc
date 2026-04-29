"""Web-flow Google OAuth helpers — used by /api/oauth/start and /api/oauth/callback.

The existing `gsc_server.py` uses InstalledAppFlow.run_local_server(), which
requires a local browser and TTY. That doesn't work on Vercel. This module
builds an equivalent ``Flow`` configured from environment variables instead of
a client_secrets.json file.
"""

from __future__ import annotations

import os
from typing import Optional

import requests
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import Flow


SCOPES = [
    "https://www.googleapis.com/auth/webmasters",
    "openid",
    "https://www.googleapis.com/auth/userinfo.email",
]


def _client_config() -> dict:
    client_id = os.environ.get("GOOGLE_CLIENT_ID")
    client_secret = os.environ.get("GOOGLE_CLIENT_SECRET")
    if not client_id or not client_secret:
        raise RuntimeError(
            "GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET must be set in Vercel "
            "environment variables. Create a Web-application OAuth client in "
            "Google Cloud Console and copy its credentials."
        )
    return {
        "web": {
            "client_id": client_id,
            "client_secret": client_secret,
            "auth_uri": "https://accounts.google.com/o/oauth2/auth",
            "token_uri": "https://oauth2.googleapis.com/token",
            "auth_provider_x509_cert_url": "https://www.googleapis.com/oauth2/v1/certs",
        }
    }


def redirect_uri() -> str:
    uri = os.environ.get("OAUTH_REDIRECT_URI")
    if not uri:
        raise RuntimeError(
            "OAUTH_REDIRECT_URI is not set. It must match the redirect URI "
            "registered in Google Cloud Console, e.g. "
            "https://<your-vercel-domain>/api/oauth/callback"
        )
    return uri


def _flow() -> Flow:
    flow = Flow.from_client_config(_client_config(), scopes=SCOPES, redirect_uri=redirect_uri())
    # Explicit: we manage code_verifier ourselves and persist it in Redis alongside
    # the state nonce, so disable autogeneration here.
    flow.autogenerate_code_verifier = False
    flow.code_verifier = None
    return flow


def build_authorize_url(state: str) -> tuple[str, str]:
    """Build the Google consent URL and return ``(url, code_verifier)``.

    The verifier must be persisted (alongside ``state``) and supplied to
    ``exchange_code`` in the callback handler — otherwise Google returns
    ``invalid_grant: Missing code verifier`` because the auth request includes
    a PKCE code challenge but the token exchange has no matching verifier.

    ``prompt=consent`` ensures we always receive a refresh_token.
    """
    flow = _flow()
    # Generate a 128-char PKCE verifier; google-auth-oauthlib will derive the
    # S256 code challenge and append it to the URL automatically.
    import secrets as _secrets
    import string as _string
    chars = _string.ascii_letters + _string.digits + "-._~"
    flow.code_verifier = "".join(_secrets.choice(chars) for _ in range(128))
    auth_url, _ = flow.authorization_url(
        access_type="offline",
        prompt="consent",
        include_granted_scopes="true",
        state=state,
    )
    return auth_url, flow.code_verifier


def exchange_code(code: str, code_verifier: Optional[str] = None) -> Credentials:
    flow = _flow()
    if code_verifier:
        flow.code_verifier = code_verifier
    flow.fetch_token(code=code)
    return flow.credentials


def userinfo_email(creds: Credentials) -> Optional[str]:
    """Resolve the Google account email tied to these credentials."""
    resp = requests.get(
        "https://www.googleapis.com/oauth2/v2/userinfo",
        headers={"Authorization": f"Bearer {creds.token}"},
        timeout=10,
    )
    resp.raise_for_status()
    return resp.json().get("email")
