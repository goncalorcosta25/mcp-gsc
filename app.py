"""ASGI entrypoint for Vercel deployment.

Vercel's Python runtime detects Starlette/uvicorn (installed transitively by
mcp[cli]) and expects a single file that exports ``app``. This file wires:

  POST /mcp                — FastMCP Streamable HTTP transport (bearer-protected)
  GET  /api/oauth/start    — start Google OAuth consent flow
  GET  /api/oauth/callback — receive authorization code, store token in KV
  GET  /api/accounts       — list linked Google accounts as JSON (bearer-protected)
  GET  /dashboard          — HTML dashboard: linked accounts + GSC properties
  GET  /                   — landing page with links into the above

The Claude org custom-connector URL is: https://<your-vercel-domain>/mcp
"""
from __future__ import annotations

import asyncio
import hmac
import html
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
        url, code_verifier = oauth_web.build_authorize_url(state)
        # Persist the PKCE verifier with the state so the callback (a separate
        # serverless invocation with no shared memory) can complete the flow.
        token_store.put_oauth_state(state, code_verifier)
        return RedirectResponse(url, status_code=302)
    except Exception as exc:
        return PlainTextResponse(f"OAuth start failed: {exc}", status_code=500)


_SUCCESS_HTML = """<!doctype html>
<html><head><meta charset="utf-8"><title>mcp-gsc — account linked</title>
<style>body{{font-family:system-ui,sans-serif;max-width:540px;margin:64px auto;padding:0 16px;color:#222;line-height:1.5}}
code{{background:#f3f3f3;padding:2px 6px;border-radius:4px}}
a.btn{{display:inline-block;background:#111;color:#fff;padding:8px 14px;border-radius:6px;text-decoration:none;margin-right:8px;margin-top:8px}}
a.btn.secondary{{background:#eee;color:#222}}</style></head>
<body><h1>&#x2705; Linked: {email}</h1>
<p>This Google account is now part of the shared pool. Anyone in your Claude
organization can query its Search Console data through the MCP connector.</p>
<p>Pass <code>account="{email}"</code> to any tool to target this account,
or call <code>list_linked_accounts</code> to see all linked accounts.</p>
<p><a class="btn" href="/dashboard">View dashboard</a><a class="btn secondary" href="/api/oauth/start">Link another account</a></p>
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
    code_verifier = token_store.pop_oauth_state(state)
    if code_verifier is None:
        return PlainTextResponse(
            "Invalid or expired OAuth state. Restart the flow at /api/oauth/start.",
            status_code=400,
        )
    try:
        creds = oauth_web.exchange_code(code, code_verifier=code_verifier)
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


# ── Dashboard ──────────────────────────────────────────────────────────────────

def _check_bearer(request: Request) -> tuple[bool, str | None]:
    """Validate bearer-token from Authorization header OR ``?token=`` query param.

    Returns (ok, expected_token_or_None). Used by /dashboard so a logged-in
    operator can paste the token into the URL instead of crafting curl.
    """
    expected = os.environ.get("MCP_BEARER_TOKEN")
    if not expected:
        return False, None
    auth = request.headers.get("authorization", "")
    provided = auth[7:].strip() if auth.lower().startswith("bearer ") else ""
    if not provided:
        provided = request.query_params.get("token", "")
    return (bool(provided) and hmac.compare_digest(provided, expected), expected)


def _fetch_properties(account: str) -> tuple[list[dict], str | None]:
    """Return (properties, error_msg). Errors are returned, not raised."""
    try:
        from gsc_server import get_gsc_service
        service = get_gsc_service(account)
        resp = service.sites().list().execute()
        sites = resp.get("siteEntry", []) or []
        return sites, None
    except Exception as exc:
        return [], str(exc)


def _render_token_form(message: str = "") -> str:
    msg = f'<p style="color:#b00">{html.escape(message)}</p>' if message else ""
    return f"""<!doctype html><html><head><meta charset="utf-8">
<title>mcp-gsc dashboard</title>
<style>body{{font-family:system-ui,sans-serif;max-width:480px;margin:96px auto;padding:0 16px;color:#222}}
input{{width:100%;padding:10px;font-family:ui-monospace,monospace;border:1px solid #ccc;border-radius:6px;box-sizing:border-box}}
button{{margin-top:12px;background:#111;color:#fff;padding:10px 16px;border:0;border-radius:6px;cursor:pointer}}</style>
</head><body>
<h1>mcp-gsc dashboard</h1>
<p>Paste the <code>MCP_BEARER_TOKEN</code> set in Vercel to view linked accounts and properties.</p>
{msg}
<form method="GET" action="/dashboard">
  <input type="password" name="token" placeholder="Bearer token" autofocus required>
  <button type="submit">Open dashboard</button>
</form>
</body></html>"""


def _render_dashboard(rows: list[dict], default_email: str | None) -> str:
    parts: list[str] = []
    parts.append("""<!doctype html><html><head><meta charset="utf-8">
<title>mcp-gsc dashboard</title>
<style>
body{font-family:system-ui,sans-serif;max-width:920px;margin:32px auto;padding:0 16px;color:#222;line-height:1.5}
header{display:flex;justify-content:space-between;align-items:center;margin-bottom:24px}
h1{margin:0;font-size:1.5rem}
a.btn{display:inline-block;background:#111;color:#fff;padding:8px 14px;border-radius:6px;text-decoration:none}
a.btn.secondary{background:#eee;color:#222}
.account{border:1px solid #e2e2e2;border-radius:10px;padding:18px 20px;margin-bottom:16px;background:#fafafa}
.account h2{margin:0 0 8px;font-size:1.1rem;display:flex;align-items:center;gap:8px}
.badge{font-size:.7rem;background:#0a7;color:#fff;padding:2px 8px;border-radius:999px;text-transform:uppercase;letter-spacing:.5px}
table{width:100%;border-collapse:collapse;margin-top:8px;font-size:.95rem}
th,td{text-align:left;padding:6px 8px;border-bottom:1px solid #eee}
th{background:#f3f3f3;font-weight:600}
.empty{color:#888;font-style:italic;font-size:.9rem;margin:8px 0 0}
.error{background:#fff0f0;border:1px solid #fbb;color:#900;padding:10px 12px;border-radius:6px;margin-top:8px;font-size:.9rem;font-family:ui-monospace,monospace;white-space:pre-wrap}
footer{margin-top:32px;color:#888;font-size:.85rem}
code{background:#f3f3f3;padding:2px 6px;border-radius:4px}
</style></head><body>""")
    parts.append('<header><h1>mcp-gsc dashboard</h1>')
    parts.append('<a class="btn" href="/api/oauth/start">+ Link another account</a></header>')

    if not rows:
        parts.append('<p class="empty">No Google accounts linked yet. '
                     'Click "Link another account" above to add one.</p>')
    else:
        parts.append(f'<p>{len(rows)} linked account(s). The default '
                     f'(used when a tool call omits the <code>account</code> arg) is '
                     f'<code>{html.escape(default_email or "—")}</code>.</p>')
        for row in rows:
            email = row["email"]
            email_e = html.escape(email)
            badge = '<span class="badge">default</span>' if row["is_default"] else ""
            parts.append(f'<section class="account"><h2>{email_e}{badge}</h2>')
            if row["error"]:
                parts.append(f'<div class="error">Failed to fetch properties: '
                             f'{html.escape(row["error"])}</div>')
            elif not row["sites"]:
                parts.append('<p class="empty">No GSC properties accessible from this account.</p>')
            else:
                parts.append('<table><thead><tr><th>Property (site_url)</th>'
                             '<th>Permission</th></tr></thead><tbody>')
                for site in row["sites"]:
                    site_url = html.escape(site.get("siteUrl", "—"))
                    perm = html.escape(site.get("permissionLevel", "—"))
                    parts.append(f'<tr><td><code>{site_url}</code></td><td>{perm}</td></tr>')
                parts.append('</tbody></table>')
            parts.append('</section>')

    parts.append('<footer>Pass <code>account="email@domain.com"</code> to any MCP tool '
                 'to scope a call to a specific linked account.</footer>')
    parts.append('</body></html>')
    return "".join(parts)


async def dashboard(request: Request):
    ok, expected = _check_bearer(request)
    if not expected:
        return PlainTextResponse(
            "MCP_BEARER_TOKEN is not configured on the server.", status_code=503,
        )
    if not ok:
        provided = request.query_params.get("token") or ""
        msg = "Invalid token." if provided else ""
        return HTMLResponse(_render_token_form(msg), status_code=401 if provided else 200)

    try:
        accounts_list = token_store.list_accounts()
        default = token_store.get_default()
    except Exception as exc:
        return PlainTextResponse(f"Token store error: {exc}", status_code=500)

    # GSC sites().list() is sync (googleapiclient) — fan out via threads so N
    # accounts don't serialize into N×latency.
    rows_data = await asyncio.gather(*(
        asyncio.to_thread(_fetch_properties, email) for email in accounts_list
    ))
    rows = [
        {
            "email": email,
            "is_default": email == default,
            "sites": sites,
            "error": err,
        }
        for email, (sites, err) in zip(accounts_list, rows_data)
    ]
    return HTMLResponse(_render_dashboard(rows, default))


# ── Landing page ───────────────────────────────────────────────────────────────

_LANDING_HTML = """<!doctype html><html><head><meta charset="utf-8">
<title>mcp-gsc</title>
<style>body{font-family:system-ui,sans-serif;max-width:560px;margin:96px auto;padding:0 16px;color:#222;line-height:1.6}
a.btn{display:inline-block;background:#111;color:#fff;padding:10px 16px;border-radius:6px;text-decoration:none;margin-right:8px;margin-top:8px}
a.btn.secondary{background:#eee;color:#222}
code{background:#f3f3f3;padding:2px 6px;border-radius:4px}</style></head><body>
<h1>mcp-gsc</h1>
<p>Remote MCP server bridging Google Search Console to a Claude organization.</p>
<p><a class="btn" href="/api/oauth/start">Link a Google account</a>
<a class="btn secondary" href="/dashboard">Open dashboard</a></p>
<p style="color:#888;font-size:.9rem;margin-top:32px">
Claude connector URL: <code>/mcp</code> (bearer-token auth required).
</p></body></html>"""


async def landing(request: Request):
    return HTMLResponse(_LANDING_HTML)


# ── Root ASGI dispatcher ───────────────────────────────────────────────────────
# Non-MCP routes are handled by a Starlette sub-app to get proper 404s.
# Everything else (including /mcp) is forwarded to the bearer-protected MCP app.

_oauth_app = Starlette(routes=[
    Route("/", landing, methods=["GET"]),
    Route("/dashboard", dashboard, methods=["GET"]),
    Route("/api/oauth/start", oauth_start, methods=["GET"]),
    Route("/api/oauth/callback", oauth_callback, methods=["GET"]),
    Route("/api/accounts", accounts, methods=["GET"]),
])

_HANDLED_PATHS = frozenset([
    "/", "/dashboard",
    "/api/oauth/start", "/api/oauth/callback", "/api/accounts",
])


class _App:
    """Root ASGI app.

    Routes /api/oauth/*, /api/accounts, /, /dashboard to the Starlette
    sub-app. Everything else (/mcp, plus any other path) is forwarded to the
    bearer-protected FastMCP Streamable HTTP app.

    Vercel's Python runtime does not reliably emit ASGI ``lifespan`` events
    for serverless functions, but FastMCP's StreamableHTTPSessionManager
    requires its task group to be initialised by the lifespan startup hook —
    otherwise the very first /mcp request fails with "Task group is not
    initialized". We emulate the lifespan startup ourselves the first time
    an HTTP request arrives, and keep the lifespan task running for the
    process lifetime so the task group stays alive across warm invocations.
    """

    def __init__(self) -> None:
        self._lifespan_started = False
        self._lifespan_lock: asyncio.Lock | None = None
        self._lifespan_task: asyncio.Task | None = None
        # Used to keep lifespan running indefinitely in the background.
        self._never_shutdown: asyncio.Event | None = None

    async def _ensure_lifespan_started(self) -> None:
        if self._lifespan_started:
            return
        # Lazy-init lock/event because they bind to the running event loop.
        if self._lifespan_lock is None:
            self._lifespan_lock = asyncio.Lock()
        async with self._lifespan_lock:
            if self._lifespan_started:
                return
            startup_complete: asyncio.Event = asyncio.Event()
            self._never_shutdown = asyncio.Event()

            async def fake_receive():
                if not startup_complete.is_set():
                    # Drive the inner app through startup the first time.
                    return {"type": "lifespan.startup"}
                # Block forever — never request shutdown so the task group
                # in StreamableHTTPSessionManager.run() stays alive.
                await self._never_shutdown.wait()
                return {"type": "lifespan.shutdown"}

            async def fake_send(message):
                t = message.get("type")
                if t in ("lifespan.startup.complete", "lifespan.startup.failed"):
                    startup_complete.set()

            async def runner():
                try:
                    await _mcp_inner(
                        {"type": "lifespan", "asgi": {"version": "3.0"}},
                        fake_receive,
                        fake_send,
                    )
                except Exception:
                    # Surface lifespan errors on the next request rather than
                    # silently swallowing them.
                    startup_complete.set()
                    raise

            self._lifespan_task = asyncio.create_task(runner())
            await startup_complete.wait()
            self._lifespan_started = True

    async def __call__(self, scope, receive, send):
        if scope["type"] == "lifespan":
            # Some adapters DO emit lifespan; honour it and mark started so
            # we don't double-init.
            self._lifespan_started = True
            await _mcp_inner(scope, receive, send)
            return
        if scope["type"] == "http":
            path = scope.get("path", "/")
            if path in _HANDLED_PATHS:
                await _oauth_app(scope, receive, send)
                return
            # MCP path — make sure the session manager's task group is up.
            await self._ensure_lifespan_started()
        await _mcp_protected(scope, receive, send)


app = _App()
