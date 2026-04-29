"""Bearer-token ASGI middleware for the Streamable HTTP MCP endpoint.

Accepts EITHER:
  * the static ``MCP_BEARER_TOKEN`` (operator-issued, used by curl/scripts), OR
  * an OAuth 2.0 access token issued via ``lib.oauth_server`` (used by
    Claude's custom-connector flow).

On 401 it sets a ``WWW-Authenticate`` header that points clients to the OAuth
metadata document, so Claude knows where to start the authorization flow.
"""

from __future__ import annotations

import hmac
import os
from typing import Awaitable, Callable


def _origin_from_scope(scope) -> str:
    """Best-effort base URL for building absolute discovery URLs."""
    headers = dict(scope.get("headers") or [])
    host = headers.get(b"host", b"").decode("latin-1") or "localhost"
    scheme = "https" if scope.get("scheme") == "https" else "http"
    if scope.get("scheme") == "http" and host.endswith(".vercel.app"):
        scheme = "https"  # X-Forwarded-Proto stripped; Vercel is always https
    return f"{scheme}://{host}"


def bearer_required(app: Callable) -> Callable:
    async def asgi(scope, receive, send):
        if scope["type"] != "http":
            await app(scope, receive, send)
            return

        expected = os.environ.get("MCP_BEARER_TOKEN")
        if not expected:
            await _send_text(send, 503, "MCP_BEARER_TOKEN is not configured.")
            return

        headers = dict(scope.get("headers") or [])
        auth = headers.get(b"authorization", b"").decode("latin-1")
        token = ""
        if auth.lower().startswith("bearer "):
            token = auth[7:].strip()

        if not token:
            await _send_unauthorized(scope, send, "Missing bearer token.")
            return

        # Static admin bearer token always works.
        if hmac.compare_digest(token, expected):
            await app(scope, receive, send)
            return

        # OAuth-issued access token — looked up in Redis. Imported lazily to
        # avoid a circular import at module load time.
        try:
            from .oauth_server import is_valid_access_token
            if is_valid_access_token(token):
                await app(scope, receive, send)
                return
        except Exception:
            pass

        await _send_unauthorized(scope, send, "Invalid bearer token.")

    return asgi


async def _send_text(send, status: int, body: str) -> None:
    await send({
        "type": "http.response.start",
        "status": status,
        "headers": [(b"content-type", b"text/plain; charset=utf-8")],
    })
    await send({"type": "http.response.body", "body": body.encode("utf-8")})


async def _send_unauthorized(scope, send, body: str) -> None:
    base = _origin_from_scope(scope)
    metadata = f'{base}/.well-known/oauth-protected-resource'
    challenge = (
        f'Bearer realm="mcp-gsc", '
        f'resource_metadata="{metadata}"'
    ).encode("latin-1")
    await send({
        "type": "http.response.start",
        "status": 401,
        "headers": [
            (b"content-type", b"text/plain; charset=utf-8"),
            (b"www-authenticate", challenge),
        ],
    })
    await send({"type": "http.response.body", "body": body.encode("utf-8")})
