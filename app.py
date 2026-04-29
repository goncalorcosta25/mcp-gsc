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
from lib import oauth_server, oauth_web, token_store  # noqa: E402
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


# ── OAuth 2.0 endpoints (Claude's custom MCP connector flow) ──────────────────

def _origin(request: Request) -> str:
    host = request.headers.get("host") or "localhost"
    scheme = request.url.scheme or "https"
    if host.endswith(".vercel.app"):
        scheme = "https"
    return f"{scheme}://{host}"


async def oauth_authorization_server_metadata(request: Request):
    base = _origin(request)
    return JSONResponse({
        "issuer": base,
        "authorization_endpoint": f"{base}/authorize",
        "token_endpoint": f"{base}/token",
        "registration_endpoint": f"{base}/register",
        "scopes_supported": ["mcp"],
        "response_types_supported": ["code"],
        "grant_types_supported": ["authorization_code"],
        "code_challenge_methods_supported": ["S256"],
        "token_endpoint_auth_methods_supported": ["none"],
    })


async def oauth_protected_resource_metadata(request: Request):
    base = _origin(request)
    return JSONResponse({
        "resource": f"{base}/mcp",
        "authorization_servers": [base],
        "bearer_methods_supported": ["header"],
    })


async def oauth_register(request: Request):
    """RFC 7591 Dynamic Client Registration. Accept any registration."""
    try:
        body = await request.json()
    except Exception:
        body = {}
    redirect_uris = body.get("redirect_uris") or []
    # Issue a random client_id; we don't persist registrations because the
    # actual gating happens on /authorize via the operator's bearer token.
    client_id = secrets.token_urlsafe(24)
    return JSONResponse({
        "client_id": client_id,
        "client_id_issued_at": 0,
        "redirect_uris": redirect_uris,
        "grant_types": ["authorization_code"],
        "response_types": ["code"],
        "token_endpoint_auth_method": "none",
    })


_CONSENT_HTML = """<!doctype html><html><head><meta charset="utf-8">
<title>mcp-gsc — authorize Claude</title>
<style>body{{font-family:system-ui,sans-serif;max-width:480px;margin:80px auto;padding:0 16px;color:#222;line-height:1.55}}
.card{{border:1px solid #e2e2e2;border-radius:10px;padding:24px;background:#fafafa;margin-top:24px}}
input{{width:100%;padding:10px;font-family:ui-monospace,monospace;border:1px solid #ccc;border-radius:6px;box-sizing:border-box}}
button{{margin-top:12px;background:#111;color:#fff;padding:10px 16px;border:0;border-radius:6px;cursor:pointer;font-size:1rem}}
.err{{color:#b00;background:#fff0f0;border:1px solid #fbb;padding:10px 12px;border-radius:6px;margin-top:12px;font-size:.9rem}}
.muted{{color:#666;font-size:.85rem;margin-top:14px}}
code{{background:#f3f3f3;padding:2px 6px;border-radius:4px;font-size:.9em}}</style>
</head><body>
<h1>Authorize Claude to use mcp-gsc</h1>
<p>Claude is requesting access to your Google Search Console MCP server.</p>
<div class="card">
  <p>Redirect URI: <code>{redirect_uri}</code></p>
  <p>Confirm by entering the <code>MCP_BEARER_TOKEN</code> set in Vercel:</p>
  {error}
  <form method="POST" action="/authorize">
    <input type="hidden" name="response_type" value="{response_type}">
    <input type="hidden" name="client_id" value="{client_id}">
    <input type="hidden" name="redirect_uri" value="{redirect_uri}">
    <input type="hidden" name="code_challenge" value="{code_challenge}">
    <input type="hidden" name="code_challenge_method" value="{code_challenge_method}">
    <input type="hidden" name="state" value="{state}">
    <input type="hidden" name="scope" value="{scope}">
    <input type="password" name="admin_token" placeholder="Bearer token" autofocus required>
    <button type="submit">Approve</button>
  </form>
</div>
<p class="muted">This step is one-time per Claude organization. The bearer
token is the same value you configured in Vercel as <code>MCP_BEARER_TOKEN</code>
and registered in the connector form.</p>
</body></html>"""


def _render_consent(params: dict, error: str = "") -> str:
    err = f'<p class="err">{html.escape(error)}</p>' if error else ""
    return _CONSENT_HTML.format(
        redirect_uri=html.escape(params.get("redirect_uri", "")),
        response_type=html.escape(params.get("response_type", "code")),
        client_id=html.escape(params.get("client_id", "")),
        code_challenge=html.escape(params.get("code_challenge", "")),
        code_challenge_method=html.escape(params.get("code_challenge_method", "S256")),
        state=html.escape(params.get("state", "")),
        scope=html.escape(params.get("scope", "")),
        error=err,
    )


def _redirect_with_error(redirect_uri: str, state: str, error: str, description: str = "") -> RedirectResponse:
    from urllib.parse import urlencode
    sep = "&" if "?" in redirect_uri else "?"
    qs = urlencode({"error": error, "error_description": description, "state": state})
    return RedirectResponse(redirect_uri + sep + qs, status_code=302)


async def authorize(request: Request):
    if request.method == "GET":
        params = dict(request.query_params)
    else:
        params = dict(await request.form())

    response_type = params.get("response_type", "")
    redirect_uri = params.get("redirect_uri", "")
    code_challenge = params.get("code_challenge", "")
    code_challenge_method = params.get("code_challenge_method", "")
    state = params.get("state", "")
    client_id = params.get("client_id", "")
    scope = params.get("scope", "")

    # Hard-fail validations that we cannot redirect for (no usable redirect_uri).
    if not redirect_uri or not oauth_server._allowed_redirect(redirect_uri):
        return PlainTextResponse(
            "invalid_request: redirect_uri is missing or not allowed. "
            "Only Claude's MCP callback URLs are permitted.",
            status_code=400,
        )
    if response_type != "code":
        return _redirect_with_error(redirect_uri, state, "unsupported_response_type",
                                    "only response_type=code is supported")
    if code_challenge_method != "S256" or not code_challenge:
        return _redirect_with_error(redirect_uri, state, "invalid_request",
                                    "PKCE S256 code_challenge is required")

    if request.method == "GET":
        return HTMLResponse(_render_consent(params))

    # POST: verify operator's bearer token, then issue auth code.
    expected = os.environ.get("MCP_BEARER_TOKEN")
    admin_token = params.get("admin_token", "")
    if not expected:
        return PlainTextResponse("MCP_BEARER_TOKEN is not configured.", status_code=503)
    if not admin_token or not hmac.compare_digest(admin_token, expected):
        return HTMLResponse(_render_consent(params, error="Invalid token. Try again."),
                            status_code=401)

    code = oauth_server.issue_code(
        redirect_uri=redirect_uri,
        code_challenge=code_challenge,
        code_challenge_method=code_challenge_method,
        client_id=client_id,
        scope=scope,
    )
    from urllib.parse import urlencode
    sep = "&" if "?" in redirect_uri else "?"
    qs = urlencode({"code": code, "state": state})
    return RedirectResponse(redirect_uri + sep + qs, status_code=302)


async def token_endpoint(request: Request):
    form = await request.form()
    grant_type = form.get("grant_type", "")
    code = form.get("code", "")
    code_verifier = form.get("code_verifier", "")
    redirect_uri = form.get("redirect_uri", "")
    client_id = form.get("client_id", "")

    if grant_type != "authorization_code":
        return JSONResponse({"error": "unsupported_grant_type"}, status_code=400)
    if not code or not code_verifier:
        return JSONResponse({"error": "invalid_request",
                             "error_description": "code and code_verifier are required"},
                            status_code=400)

    bound = oauth_server.consume_code(code)
    if bound is None:
        return JSONResponse({"error": "invalid_grant",
                             "error_description": "code is invalid or expired"},
                            status_code=400)
    if redirect_uri and bound.get("redirect_uri") != redirect_uri:
        return JSONResponse({"error": "invalid_grant",
                             "error_description": "redirect_uri mismatch"},
                            status_code=400)
    if not oauth_server._pkce_matches(code_verifier, bound.get("code_challenge", "")):
        return JSONResponse({"error": "invalid_grant",
                             "error_description": "PKCE verifier does not match challenge"},
                            status_code=400)

    access_token = oauth_server.issue_access_token(client_id=client_id)
    return JSONResponse({
        "access_token": access_token,
        "token_type": "Bearer",
        "expires_in": oauth_server.ACCESS_TOKEN_TTL,
        "scope": bound.get("scope", ""),
    })


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
<p><a class="btn" href="/docs">Read the docs</a>
<a class="btn secondary" href="/dashboard">Open dashboard</a>
<a class="btn secondary" href="/api/oauth/start">Link a Google account</a></p>
<p style="color:#888;font-size:.9rem;margin-top:32px">
Claude connector URL: <code>/mcp</code> (bearer-token or OAuth required).
</p></body></html>"""


async def landing(request: Request):
    return HTMLResponse(_LANDING_HTML)


# ── Documentation page ────────────────────────────────────────────────────────

_DOCS_HTML = """<!doctype html><html lang="en"><head><meta charset="utf-8">
<title>mcp-gsc — documentation</title>
<meta name="viewport" content="width=device-width,initial-scale=1">
<style>
:root{--fg:#111;--muted:#666;--bg:#fff;--soft:#f6f6f7;--border:#e3e3e6;--accent:#0a7;--accent-bg:#e6f7f0}
*{box-sizing:border-box}
body{font-family:system-ui,-apple-system,Segoe UI,Roboto,sans-serif;max-width:880px;margin:0 auto;padding:48px 24px 96px;color:var(--fg);line-height:1.6;background:var(--bg)}
header{margin-bottom:48px}
header h1{margin:0 0 8px;font-size:2rem;letter-spacing:-.02em}
header p.lead{color:var(--muted);margin:0;font-size:1.1rem}
nav.toc{background:var(--soft);border:1px solid var(--border);border-radius:10px;padding:16px 20px;margin:32px 0}
nav.toc h3{margin:0 0 8px;font-size:.8rem;text-transform:uppercase;letter-spacing:.1em;color:var(--muted)}
nav.toc ol{margin:0;padding-left:18px}
nav.toc a{color:var(--fg);text-decoration:none}
nav.toc a:hover{text-decoration:underline}
h2{font-size:1.4rem;margin:48px 0 12px;letter-spacing:-.01em}
h3{font-size:1.1rem;margin:24px 0 8px}
hr{border:0;border-top:1px solid var(--border);margin:48px 0}
code{background:var(--soft);padding:2px 6px;border-radius:4px;font-size:.92em;font-family:ui-monospace,SFMono-Regular,Menlo,monospace}
pre{background:#1d1f21;color:#f8f8f2;padding:14px 16px;border-radius:8px;overflow:auto;font-size:.88rem;line-height:1.5}
pre code{background:transparent;color:inherit;padding:0}
a.btn{display:inline-block;background:var(--fg);color:#fff;padding:8px 14px;border-radius:6px;text-decoration:none;margin-right:6px;font-size:.92rem}
a.btn.secondary{background:#eee;color:var(--fg)}
.callout{background:var(--accent-bg);border-left:3px solid var(--accent);padding:12px 16px;border-radius:0 6px 6px 0;margin:16px 0;font-size:.95rem}
.warn{background:#fff7e6;border-left-color:#d97706}
.diagram{display:grid;grid-template-columns:repeat(7,1fr);gap:8px;align-items:center;margin:24px 0;padding:24px 12px;background:var(--soft);border:1px solid var(--border);border-radius:10px;font-size:.85rem}
.diagram .box{background:#fff;border:1px solid var(--border);border-radius:8px;padding:14px 8px;text-align:center;grid-column:span 1}
.diagram .box.span2{grid-column:span 2}
.diagram .box .icon{font-size:1.6rem;line-height:1}
.diagram .box .label{font-weight:600;margin-top:6px}
.diagram .box .sub{color:var(--muted);font-size:.78rem;margin-top:2px}
.diagram .arrow{text-align:center;color:var(--muted);font-size:1.4rem}
.diagram .box.accent{background:#111;color:#fff;border-color:#111}
.diagram .box.accent .sub{color:#bbb}
table{width:100%;border-collapse:collapse;margin:12px 0;font-size:.93rem}
th,td{text-align:left;padding:8px 10px;border-bottom:1px solid var(--border);vertical-align:top}
th{background:var(--soft);font-weight:600}
.steps{counter-reset:step;list-style:none;padding:0;margin:24px 0}
.steps>li{counter-increment:step;position:relative;padding:18px 18px 18px 60px;border:1px solid var(--border);border-radius:10px;margin-bottom:12px;background:#fff}
.steps>li::before{content:counter(step);position:absolute;left:18px;top:18px;width:30px;height:30px;border-radius:50%;background:var(--fg);color:#fff;display:flex;align-items:center;justify-content:center;font-weight:600;font-size:.95rem}
.steps>li h3{margin:0 0 6px;font-size:1.05rem}
.steps>li p{margin:6px 0}
.kbd{background:#fff;border:1px solid var(--border);border-bottom-width:2px;padding:1px 6px;border-radius:4px;font-family:inherit;font-size:.85em}
footer{margin-top:64px;padding-top:24px;border-top:1px solid var(--border);color:var(--muted);font-size:.9rem}
@media (max-width:640px){.diagram{grid-template-columns:1fr;gap:4px}.diagram .arrow{transform:rotate(90deg);margin:0}.diagram .box.span2{grid-column:span 1}}
</style></head><body>

<header>
  <h1>mcp-gsc</h1>
  <p class="lead">Bring Google Search Console data into Claude conversations across your organization.</p>
  <p style="margin-top:16px"><a class="btn" href="/dashboard">Dashboard</a><a class="btn secondary" href="/api/oauth/start">Link an account</a></p>
</header>

<nav class="toc">
  <h3>On this page</h3>
  <ol>
    <li><a href="#what">What this is</a></li>
    <li><a href="#how">How it works</a></li>
    <li><a href="#setup">Setup in 3 steps</a></li>
    <li><a href="#example">A worked example</a></li>
    <li><a href="#tools">Tool reference</a></li>
    <li><a href="#troubleshoot">Troubleshooting</a></li>
  </ol>
</nav>

<h2 id="what">What this is</h2>
<p>This is a remote <strong>Model Context Protocol</strong> server that lets anyone in your Claude organization
query Google Search Console — top queries, indexing status, sitemaps, performance trends — directly from a chat,
without ever leaving Claude. It's a single endpoint your org admins register once as a <em>custom connector</em>.</p>

<p>The server holds OAuth tokens for one or more Google accounts in a shared pool. Anyone in the org can ask
about any property the linked accounts have access to. New Google accounts can be added by anyone with the
admin token, no redeploy needed.</p>

<h2 id="how">How it works</h2>

<div class="diagram" aria-label="Architecture diagram">
  <div class="box"><div class="icon">&#x1F464;</div><div class="label">You</div><div class="sub">in a Claude chat</div></div>
  <div class="arrow">&rarr;</div>
  <div class="box"><div class="icon">&#x1F916;</div><div class="label">Claude</div><div class="sub">org connector</div></div>
  <div class="arrow">&rarr;</div>
  <div class="box accent span2"><div class="icon">&#x2699;&#xFE0F;</div><div class="label">mcp-gsc</div><div class="sub">this server</div></div>
  <div class="arrow">&rarr;</div>
  <div class="box"><div class="icon">&#x1F50D;</div><div class="label">Google</div><div class="sub">Search Console</div></div>
</div>

<p>Two separate authentication layers run side by side:</p>
<table>
  <thead><tr><th>Layer</th><th>Who authenticates</th><th>How</th></tr></thead>
  <tbody>
    <tr><td><strong>Claude &rarr; mcp-gsc</strong></td><td>Your Claude organization</td>
      <td>OAuth 2.0 + PKCE (set up once by an org admin), gated on first use by the operator's <code>MCP_BEARER_TOKEN</code>. Each Claude session gets a 1-hour access token.</td></tr>
    <tr><td><strong>mcp-gsc &rarr; Google</strong></td><td>The Google account owner</td>
      <td>Standard Google OAuth consent. Refresh tokens are stored in Vercel's Redis (Upstash); they're shared across all org users so anyone can query data for any linked account.</td></tr>
  </tbody>
</table>

<div class="callout warn">
  <strong>Privacy note.</strong> Once a Google account is linked, every Claude user in the org can query GSC
  data for that account's properties. Don't link accounts whose data shouldn't be visible org-wide.
</div>

<h2 id="setup">Setup in 3 steps</h2>

<ol class="steps">
  <li>
    <h3>Open the dashboard and link Google accounts</h3>
    <p>Visit <a href="/dashboard">/dashboard</a>. You'll be asked for the admin token (the
    <code>MCP_BEARER_TOKEN</code> set in Vercel). Once in, click <em>+&nbsp;Link another account</em>
    to start the Google consent flow. After approving, the dashboard lists every property that account can access in
    Search Console along with the permission level (<code>siteOwner</code>, <code>siteFullUser</code>, etc.).</p>
    <p>Repeat for each Google account you want available to Claude.</p>
  </li>
  <li>
    <h3>Add the MCP connector to your Claude organization</h3>
    <p>In Claude.ai &rarr; <em>Settings &rarr; Connectors &rarr; Add custom connector</em> (org admin):</p>
    <table>
      <tr><th>Name</th><td>Google Search Console (or anything you like)</td></tr>
      <tr><th>URL</th><td><code>https://&lt;your-domain&gt;/mcp</code></td></tr>
      <tr><th>Authentication</th><td>Leave on the default (OAuth). Claude auto-discovers our endpoints from <code>/.well-known/oauth-authorization-server</code>; you don't need to fill in client ID or secret.</td></tr>
    </table>
    <p>When you click <em>Connect</em> the first time, Claude opens a consent page on this server. Paste your <code>MCP_BEARER_TOKEN</code> there, click <em>Approve</em>. From then on, anyone you've authorized in your Claude org can use the connector.</p>
  </li>
  <li>
    <h3>Use it from any chat</h3>
    <p>Start a chat with the connector enabled and just ask. Claude will pick the right tool and call it.</p>
    <p>If a tool needs a specific Google account, mention it: <em>&ldquo;use the gcosta@example.com account&rdquo;</em>. Otherwise the default (first-linked) account is used.</p>
  </li>
</ol>

<h2 id="example">A worked example</h2>

<p>Suppose you've linked one Google account and your dashboard shows three properties. In Claude, you ask:</p>

<pre><code>Pull the top 10 queries for sc-domain:example.com over the last 28 days.
Sort by clicks descending.</code></pre>

<p>Claude calls the <code>get_search_analytics</code> tool with these arguments:</p>

<pre><code>{
  "site_url": "sc-domain:example.com",
  "days": 28,
  "dimensions": "query",
  "row_limit": 10
}</code></pre>

<p>The MCP server fetches a fresh access token for the linked Google account, queries the Search Analytics API, and returns:</p>

<pre><code>{
  "site_url": "sc-domain:example.com",
  "date_range": { "start": "2026-04-01", "end": "2026-04-29", "days": 28 },
  "dimensions": ["query"],
  "row_count": 10,
  "rows": [
    { "query": "example brand",          "clicks": 4821, "impressions": 41203, "ctr": 0.117, "position":  2.3 },
    { "query": "example reviews",        "clicks": 1192, "impressions": 18004, "ctr": 0.066, "position":  4.1 },
    { "query": "example pricing",        "clicks":  874, "impressions": 11488, "ctr": 0.076, "position":  3.7 },
    { "query": "example vs competitor",  "clicks":  651, "impressions":  9322, "ctr": 0.070, "position":  5.2 },
    { "query": "example login",          "clicks":  544, "impressions":  6011, "ctr": 0.090, "position":  1.8 },
    { "query": "example api docs",       "clicks":  421, "impressions":  7234, "ctr": 0.058, "position":  6.4 },
    { "query": "how does example work",  "clicks":  398, "impressions": 12005, "ctr": 0.033, "position":  8.9 },
    { "query": "example free trial",     "clicks":  366, "impressions":  4982, "ctr": 0.073, "position":  3.2 },
    { "query": "example alternatives",   "clicks":  311, "impressions":  9711, "ctr": 0.032, "position":  9.1 },
    { "query": "example support",        "clicks":  287, "impressions":  3140, "ctr": 0.091, "position":  2.0 }
  ]
}</code></pre>

<p>Claude turns that into a summary &mdash; biggest movers, CTR outliers, opportunity queries &mdash; without you ever opening the Search Console UI. From there you can drill in: <em>&ldquo;for the &lsquo;example api docs&rsquo; query, which page is ranking?&rdquo;</em> calls <code>get_advanced_search_analytics</code> with a query filter, and so on.</p>

<h2 id="tools">Tool reference</h2>

<p>22 tools available, grouped here by purpose:</p>

<table>
  <thead><tr><th>Group</th><th>Tools</th></tr></thead>
  <tbody>
    <tr><td>Discovery</td><td><code>get_capabilities</code>, <code>list_properties</code>, <code>list_linked_accounts</code>, <code>get_site_details</code></td></tr>
    <tr><td>Analytics</td><td><code>get_search_analytics</code>, <code>get_performance_overview</code>, <code>compare_search_periods</code>, <code>get_search_by_page_query</code>, <code>get_advanced_search_analytics</code></td></tr>
    <tr><td>URL inspection</td><td><code>inspect_url_enhanced</code>, <code>batch_url_inspection</code>, <code>check_indexing_issues</code></td></tr>
    <tr><td>Sitemaps</td><td><code>get_sitemaps</code>, <code>list_sitemaps_enhanced</code>, <code>get_sitemap_details</code>, <code>submit_sitemap</code>, <code>delete_sitemap</code>, <code>manage_sitemaps</code></td></tr>
    <tr><td>Account / safety</td><td><code>add_site</code>, <code>delete_site</code>, <code>reauthenticate</code></td></tr>
  </tbody>
</table>

<p>Every tool accepts an optional <code>account</code> argument to pin the call to a specific linked Google email. <code>add_site</code>, <code>delete_site</code>, and <code>delete_sitemap</code> are disabled unless <code>GSC_ALLOW_DESTRUCTIVE=true</code> is set on the server.</p>

<h2 id="troubleshoot">Troubleshooting</h2>

<table>
  <thead><tr><th>Symptom</th><th>Likely cause &amp; fix</th></tr></thead>
  <tbody>
    <tr><td>Connector adds, but no tools appear in Claude</td>
      <td>The server returned 401 to the initial <code>tools/list</code>. Re-open the connector settings and reconnect — Claude's old session token may have expired (1h TTL). If it persists, regenerate <code>MCP_BEARER_TOKEN</code> and re-authorize.</td></tr>
    <tr><td><code>(invalid_grant) Missing code verifier</code> on Google consent</td>
      <td>PKCE state didn't survive between the start and callback. Usually transient — try the link flow again from <a href="/api/oauth/start">/api/oauth/start</a>.</td></tr>
    <tr><td>Tool returns &ldquo;No Google accounts are linked&rdquo;</td>
      <td>Empty pool. Visit <a href="/api/oauth/start">/api/oauth/start</a> and authorize at least one account.</td></tr>
    <tr><td>Tool returns 404 for a property you can see in GSC</td>
      <td>The <code>site_url</code> string must match GSC <em>exactly</em> &mdash; trailing slashes, http vs https, and the <code>sc-domain:</code> prefix all matter. Call <code>list_properties</code> first and copy the value.</td></tr>
    <tr><td>Claude says &ldquo;Denied&rdquo; despite valid setup</td>
      <td>Check the raw tool output (expand the call in the chat). The dashboard runs the same Google API call &mdash; if it shows properties there, the server is fine and Claude is paraphrasing something else.</td></tr>
  </tbody>
</table>

<footer>
  <p>Open source: MIT-licensed FastMCP server, Python 3.12, deployed on Vercel with Marketplace Redis.
  See the <a href="https://github.com/AminForou/mcp-gsc">upstream repo</a> for the tool implementations,
  or this fork for the Vercel deployment layer.</p>
</footer>

</body></html>"""


async def docs(request: Request):
    return HTMLResponse(_DOCS_HTML)


# ── Root ASGI dispatcher ───────────────────────────────────────────────────────
# Non-MCP routes are handled by a Starlette sub-app to get proper 404s.
# Everything else (including /mcp) is forwarded to the bearer-protected MCP app.

_oauth_app = Starlette(routes=[
    Route("/", landing, methods=["GET"]),
    Route("/docs", docs, methods=["GET"]),
    Route("/dashboard", dashboard, methods=["GET"]),
    Route("/api/oauth/start", oauth_start, methods=["GET"]),
    Route("/api/oauth/callback", oauth_callback, methods=["GET"]),
    Route("/api/accounts", accounts, methods=["GET"]),
    # Claude's custom-MCP-connector OAuth flow
    Route("/.well-known/oauth-authorization-server",
          oauth_authorization_server_metadata, methods=["GET"]),
    Route("/.well-known/oauth-protected-resource",
          oauth_protected_resource_metadata, methods=["GET"]),
    Route("/register", oauth_register, methods=["POST"]),
    Route("/authorize", authorize, methods=["GET", "POST"]),
    Route("/token", token_endpoint, methods=["POST"]),
])

_HANDLED_PATHS = frozenset([
    "/", "/docs", "/dashboard",
    "/api/oauth/start", "/api/oauth/callback", "/api/accounts",
    "/.well-known/oauth-authorization-server",
    "/.well-known/oauth-protected-resource",
    "/register", "/authorize", "/token",
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
