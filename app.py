"""ASGI entrypoint for Vercel deployment.

Vercel's Python runtime detects Starlette/uvicorn (installed transitively by
mcp[cli]) and expects a single file that exports ``app``. This file wires:

  POST /mcp          — FastMCP Streamable HTTP transport (bearer-protected)
  GET  /api/oauth/start    — start Google OAuth consent flow
  GET  /api/oauth/callback — receive authorization code, store token in KV
  GET  /api/accounts       — list linked Google accounts (bearer-protected)

The Claude org custom-connector URL is: https://<your-vercel-domain>/mcp
"""
from __future__ import annotations

import hmac
import os
import secrets
import sys

os.environ.setdefault("MCP_TRANSPORT", "vercel")

_ROOT = os.path.abspath(os.path.dirname(__file__))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from starlette.applications import Starlette  # noqa: E402
from starlette.requests import Request  # noqa: E402
from starlette.responses import (  # noqa: E402
    HTMLResponse,
    JSONResponse,
    PlainTextResponse,
    RedirectResponse,
)
from starlette.routing import Route  # noqa: E402

from gsc_server import mcp  # noqa: E402
from lib import oauth_web, token_store  # noqa: E402
from lib.auth_guard import bearer_required  # noqa: E402


# ── MCP transport (served at /mcp by streamable_http_app) ─────────────────────

if hasattr(mcp, "streamable_http_app"):
    _mcp_inner = mcp.streamable_http_app()
elif hasattr(mcp, "sse_app"):
    _mcp_inner = mcp.sse_app()
else:
    raise RuntimeError(
        "Installed mcp SDK exposes neither streamable_http_app() nor sse_app(). "
        "Bump mcp[cli] to >=1.10."
    )

_mcp_protected = bearer_required(_mcp_inner)


# ── OAuth endpoints ────────────────────────────────────────────────────────────

async def oauth_start(request: Request):
    try:
        state = secrets.token_urlsafe(32)
        token_store.put_oauth_state(state)
        url = oauth_web.build_authorize_url(state)
        return RedirectResponse(url, status_code=302)
    except Exception as exc:
        return PlainTextResponse(f"OAuth start failed: {exc}", status_code=500)


_SUCCESS_HTML = """<!doctype html>
<html><head><meta charset="utf-8"><title>mcp-gsc — account linked</title>
<style>body{{font-family:system-ui,sans-serif;max-width:540px;margin:64px auto;padding:0 16px;color:#222}}
code{{background:#f3f3f3;padding:2px 6px;border-radius:4px}}</style></head>
<body><h1>&#x2705; Linked: {email}</h1>
<p>This Google account is now part of the shared pool. Anyone in your Claude
organization can query its Search Console data through the MCP connector.</p>
<p>Pass <code>account="{email}"</code> to any tool to target this account,
or call <code>list_linked_accounts</code> to see all linked accounts.</p>
</body></html>"""


async def oauth_callback(request: Request):
    params = request.query_params
    code = params.get("code")
    state = params.get("state")
    error = params.get("error")

    if error:
        return PlainTextResponse(f"Google returned an error: {error}", status_code=400)
    if not code or not state:
        return PlainTextResponse("Missing 'code' or 'state' query parameter.", status_code=400)
    if token_store.pop_oauth_state(state) is None:
        return PlainTextResponse(
            "Invalid or expired OAuth state. Restart the flow at /api/oauth/start.",
            status_code=400,
        )
    try:
        creds = oauth_web.exchange_code(code)
        email = oauth_web.userinfo_email(creds)
    except Exception as exc:
        return PlainTextResponse(f"Token exchange failed: {exc}", status_code=500)

    if not email:
        return PlainTextResponse("Could not resolve Google account email.", status_code=500)
    try:
        token_store.set_token(email, creds.to_json())
    except Exception as exc:
        return PlainTextResponse(f"Failed to persist token: {exc}", status_code=500)
    return HTMLResponse(_SUCCESS_HTML.format(email=email))


# ── Accounts endpoint ──────────────────────────────────────────────────────────

async def accounts(request: Request):
    expected = os.environ.get("MCP_BEARER_TOKEN")
    if not expected:
        return PlainTextResponse("MCP_BEARER_TOKEN is not configured on the server.", status_code=503)
    auth = request.headers.get("authorization", "")
    if not auth.lower().startswith("bearer "):
        return PlainTextResponse("Missing bearer token.", status_code=401)
    if not hmac.compare_digest(auth[7:].strip(), expected):
        return PlainTextResponse("Invalid bearer token.", status_code=401)
    try:
        return JSONResponse({
            "accounts": token_store.list_accounts(),
            "default": token_store.get_default(),
        })
    except Exception as exc:
        return PlainTextResponse(f"Error: {exc}", status_code=500)


# ── Root ASGI dispatcher ───────────────────────────────────────────────────────
# Non-MCP routes are handled by a Starlette sub-app to get proper 404s.
# Everything else (including /mcp) is forwarded to the bearer-protected MCP app.

_oauth_app = Starlette(routes=[
    Route("/api/oauth/start", oauth_start, methods=["GET"]),
    Route("/api/oauth/callback", oauth_callback, methods=["GET"]),
    Route("/api/accounts", accounts, methods=["GET"]),
])

_HANDLED_PATHS = frozenset(["/api/oauth/start", "/api/oauth/callback", "/api/accounts"])


class _App:
    async def __call__(self, scope, receive, send):
        if scope["type"] == "lifespan":
            await _mcp_inner(scope, receive, send)
            return
        if scope["type"] == "http":
            path = scope.get("path", "/")
            if path in _HANDLED_PATHS:
                await _oauth_app(scope, receive, send)
                return
        await _mcp_protected(scope, receive, send)


app = _App()
