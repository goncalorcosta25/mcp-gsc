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
<title>mcp-gsc — docs</title>
<meta name="viewport" content="width=device-width,initial-scale=1">
<style>
body{font-family:system-ui,sans-serif;max-width:680px;margin:0 auto;padding:40px 24px 64px;color:#111;line-height:1.6}
h1{margin:0 0 8px;font-size:1.6rem}
h2{margin:28px 0 8px;font-size:1.05rem}
p{margin:8px 0}
.lead{color:#666;margin:0 0 20px}
ol{padding-left:20px}
ol li{margin:10px 0}
code{background:#f3f3f3;padding:1px 6px;border-radius:4px;font-size:.92em;font-family:ui-monospace,SFMono-Regular,Menlo,monospace}
pre{background:#1d1f21;color:#f8f8f2;padding:12px 14px;border-radius:6px;overflow:auto;font-size:.85rem;margin:8px 0}
pre code{background:transparent;color:inherit;padding:0;font-size:inherit}
a.btn{display:inline-block;background:#111;color:#fff;padding:6px 12px;border-radius:5px;text-decoration:none;font-size:.9rem;margin-right:6px}
a.btn.s{background:#eee;color:#111}
nav.tabs{display:flex;gap:4px;border-bottom:1px solid #e3e3e6;margin:24px 0 0}
nav.tabs label{padding:8px 14px;cursor:pointer;color:#666;border-bottom:2px solid transparent;margin-bottom:-1px;font-size:.95rem}
input[name=tab]{display:none}
.panel{display:none;padding-top:8px}
#t1:checked~.body .p1,#t2:checked~.body .p2{display:block}
#t1:checked~nav.tabs label[for=t1],#t2:checked~nav.tabs label[for=t2]{color:#111;border-bottom-color:#111;font-weight:600}
table.tools{width:100%;border-collapse:collapse;margin:8px 0;font-size:.92rem}
table.tools td{padding:6px 8px;border-bottom:1px solid #eee;vertical-align:top}
table.tools td:first-child{white-space:nowrap;font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:.85rem;color:#0366d6}
table.tools tr.group td{background:#fafafa;font-weight:600;font-family:inherit;color:#666;font-size:.78rem;text-transform:uppercase;letter-spacing:.06em;padding-top:14px}
.muted{color:#888;font-size:.85rem}
</style></head><body>

<input type="radio" name="tab" id="t1" checked>
<input type="radio" name="tab" id="t2">

<h1>mcp-gsc</h1>
<p class="lead">Use Google Search Console from a Claude org chat.</p>
<p><a class="btn" href="/dashboard">Dashboard</a><a class="btn s" href="/api/oauth/start">Link a Google account</a></p>

<nav class="tabs">
  <label for="t1">Get started</label>
  <label for="t2">Tools</label>
</nav>

<div class="body">

<section class="panel p1">
<h2>Connect it to your Claude</h2>
<ol>
  <li><strong>Get the access token</strong> from whoever set up this server. You'll paste it once during connector setup.</li>
  <li><strong>Add the connector.</strong> In Claude → your <em>Settings → Connectors → Add custom connector</em>, set the URL to <code>https://&lt;this-domain&gt;/mcp</code>. Leave authentication on the default — Claude auto-discovers the rest.</li>
  <li><strong>Approve once.</strong> Click <em>Connect</em>. Claude opens a consent page on this server; paste the access token from step 1 and approve. That's it — the connector is now wired into all your chats.</li>
  <li><strong>Use it.</strong> Start a chat and ask in plain English. If you want a specific linked Google account, mention the email; otherwise the default is used.</li>
</ol>

<h2>Example</h2>
<p>Ask:</p>
<pre><code>Top 10 queries for sc-domain:example.com over the last 28 days.</code></pre>
<p>Claude calls <code>get_search_analytics</code> and gets back JSON like:</p>
<pre><code>{
  "site_url": "sc-domain:example.com",
  "rows": [
    { "query": "example brand",   "clicks": 4821, "impressions": 41203, "ctr": 0.117, "position": 2.3 },
    { "query": "example reviews", "clicks": 1192, "impressions": 18004, "ctr": 0.066, "position": 4.1 }
  ]
}</code></pre>
<p>Claude summarizes it. Drill in by asking follow-ups ("which page ranks for X?", "compare last 28 vs prior 28 days").</p>

<h2>Add a new Google account to the pool</h2>
<p>Anyone with the access token can do this — no admin required. Open <a href="/dashboard">/dashboard</a>, paste the token, then click <em>+&nbsp;Link another account</em> and approve in Google. The new account becomes available to everyone in the org immediately.</p>

<h2>Heads up</h2>
<p>Linked Google accounts are <strong>shared</strong>. Anyone using the connector can query Search Console data for any linked account. Don't link a Google account whose data shouldn't be org-wide.</p>
</section>

<section class="panel p2">
<h2>22 tools</h2>
<p class="muted">Every tool accepts an optional <code>account</code> argument to pin the call to a specific linked Google email. Destructive tools are disabled unless the server has <code>GSC_ALLOW_DESTRUCTIVE=true</code>.</p>
<table class="tools">
<tr class="group"><td colspan="2">Discovery</td></tr>
<tr><td>get_capabilities</td><td>Lists every tool grouped by category and shows current auth status. Call first if unsure what's available.</td></tr>
<tr><td>list_properties</td><td>All GSC properties the linked account can see, with permission level.</td></tr>
<tr><td>list_linked_accounts</td><td>The pool of Google accounts linked to this server and which one is the default.</td></tr>
<tr><td>get_site_details</td><td>Verification, ownership, and permission info for a single property.</td></tr>

<tr class="group"><td colspan="2">Search analytics</td></tr>
<tr><td>get_search_analytics</td><td>Top queries / pages with clicks, impressions, CTR, position over a date range. Group by query, page, device, country, or date.</td></tr>
<tr><td>get_performance_overview</td><td>Property-level totals plus a daily trend for the period.</td></tr>
<tr><td>compare_search_periods</td><td>Diffs metrics between two date ranges so you can see what moved.</td></tr>
<tr><td>get_search_by_page_query</td><td>Queries driving traffic to one specific page URL.</td></tr>
<tr><td>get_advanced_search_analytics</td><td>Same data as get_search_analytics with full filtering, pagination, sorting, and search-type selection (web / image / video / news / discover).</td></tr>

<tr class="group"><td colspan="2">URL inspection</td></tr>
<tr><td>inspect_url_enhanced</td><td>Full crawl + index + rich-results status for one URL.</td></tr>
<tr><td>batch_url_inspection</td><td>Inspect up to 10 URLs in one call.</td></tr>
<tr><td>check_indexing_issues</td><td>Bucketize a list of URLs into not-indexed / canonical-issues / robots-blocked / fetch-issues / indexed.</td></tr>

<tr class="group"><td colspan="2">Sitemaps</td></tr>
<tr><td>get_sitemaps</td><td>Plain list of submitted sitemaps for a property.</td></tr>
<tr><td>list_sitemaps_enhanced</td><td>Detailed sitemap list with last submitted/downloaded times, type, and error/warning counts.</td></tr>
<tr><td>get_sitemap_details</td><td>Drill into one sitemap (status, content breakdown, errors).</td></tr>
<tr><td>submit_sitemap</td><td>Submit (or resubmit) a sitemap URL to Google.</td></tr>
<tr><td>delete_sitemap</td><td>Unsubmit a sitemap. <span class="muted">Destructive — gated.</span></td></tr>
<tr><td>manage_sitemaps</td><td>All-in-one wrapper: list / details / submit / delete via an <code>action</code> argument.</td></tr>

<tr class="group"><td colspan="2">Account &amp; safety</td></tr>
<tr><td>add_site</td><td>Add a new property to GSC. <span class="muted">Destructive — gated.</span></td></tr>
<tr><td>delete_site</td><td>Remove a property from GSC. <span class="muted">Destructive — gated.</span></td></tr>
<tr><td>reauthenticate</td><td>Returns the URL to link a new Google account to the shared pool.</td></tr>
<tr><td>get_creator_info</td><td>About the upstream tool author (Amin Foroutan).</td></tr>
</table>
</section>

</div>

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
