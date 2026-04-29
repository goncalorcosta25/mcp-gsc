"""Minimal OAuth 2.0 + PKCE Authorization Server for MCP clients.

Implements just enough of RFC 6749 / RFC 7636 / RFC 7591 for Claude.ai's
custom-MCP-connector flow:

- ``/.well-known/oauth-authorization-server`` — RFC 8414 metadata
- ``/.well-known/oauth-protected-resource``   — RFC 9728 resource metadata
- ``/register`` — Dynamic Client Registration (RFC 7591), accepts any client
- ``/authorize`` — consent gated by ``MCP_BEARER_TOKEN`` (the operator's
  shared admin password), then issues an authorization code
- ``/token``     — exchanges code for an access token (PKCE S256 verified)

State stored in Redis:
- ``gsc:oauth_code:<code>``  -> JSON of {code_challenge, redirect_uri, ...}, TTL 5 min
- ``gsc:oauth_token:<tok>``  -> any non-empty marker, TTL 1 h (used by auth_guard)

Access tokens are opaque random strings issued only after a successful PKCE
exchange. Both these tokens AND the static ``MCP_BEARER_TOKEN`` are accepted
by the MCP endpoint.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import secrets
import time
from typing import Optional

from . import token_store


_CODE_PREFIX = "gsc:oauth_code:"
_TOKEN_PREFIX = "gsc:oauth_token:"

CODE_TTL = 5 * 60          # auth code lifetime
ACCESS_TOKEN_TTL = 60 * 60  # access token lifetime


# ── Redirect URI allowlist ────────────────────────────────────────────────────

def _allowed_redirect(redirect_uri: str) -> bool:
    """Only allow Claude's MCP callback (covers claude.ai + claude.com)."""
    if not redirect_uri:
        return False
    allowed_prefixes = (
        "https://claude.ai/",
        "https://claude.com/",
    )
    extra = os.environ.get("OAUTH_EXTRA_REDIRECT_PREFIXES", "")
    if extra:
        allowed_prefixes = allowed_prefixes + tuple(p.strip() for p in extra.split(",") if p.strip())
    return redirect_uri.startswith(allowed_prefixes)


# ── PKCE helpers ──────────────────────────────────────────────────────────────

def _pkce_matches(code_verifier: str, code_challenge: str) -> bool:
    digest = hashlib.sha256(code_verifier.encode("ascii")).digest()
    expected = base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")
    return hmac.compare_digest(expected, code_challenge)


# ── Auth code lifecycle ───────────────────────────────────────────────────────

def issue_code(*, redirect_uri: str, code_challenge: str, code_challenge_method: str,
               client_id: str, scope: str = "") -> str:
    """Generate a fresh auth code and persist its bound parameters."""
    code = secrets.token_urlsafe(40)
    payload = json.dumps({
        "redirect_uri": redirect_uri,
        "code_challenge": code_challenge,
        "code_challenge_method": code_challenge_method,
        "client_id": client_id,
        "scope": scope,
        "ts": int(time.time()),
    })
    # Re-use token_store internals; we're storing under a different prefix.
    from . import token_store as ts
    ts._set(_CODE_PREFIX + code, payload, ex=CODE_TTL)  # noqa: SLF001
    return code


def consume_code(code: str) -> Optional[dict]:
    """One-shot code exchange — returns the bound params and deletes the entry."""
    from . import token_store as ts
    raw = ts._get(_CODE_PREFIX + code)  # noqa: SLF001
    if not raw:
        return None
    ts._del(_CODE_PREFIX + code)  # noqa: SLF001
    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        return None


# ── Access token lifecycle ────────────────────────────────────────────────────

def issue_access_token(client_id: str = "") -> str:
    token = secrets.token_urlsafe(40)
    from . import token_store as ts
    ts._set(_TOKEN_PREFIX + token, client_id or "anon", ex=ACCESS_TOKEN_TTL)  # noqa: SLF001
    return token


def is_valid_access_token(token: str) -> bool:
    if not token:
        return False
    from . import token_store as ts
    val = ts._get(_TOKEN_PREFIX + token)  # noqa: SLF001
    return val is not None
