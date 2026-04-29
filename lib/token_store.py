"""Token storage for the shared multi-account pool.

Backed by any standard Redis instance reached via ``REDIS_URL`` (e.g. the
Vercel Marketplace Redis integration, Upstash, Redis Cloud). Falls back to the
legacy Vercel KV REST API (``KV_REST_API_URL`` / ``KV_REST_API_TOKEN``) if
``REDIS_URL`` is not set, so existing Vercel KV deploys keep working.

Keys:
- ``gsc:token:<email>``   -> JSON string of google.oauth2.credentials.Credentials
- ``gsc:accounts``        -> SET of linked Google emails
- ``gsc:default_account`` -> string, the default account when a tool call omits ``account``
- ``gsc:oauth_state:<s>`` -> short-lived nonce written by /api/oauth/start, popped by /callback
"""

from __future__ import annotations

import json
import os
from typing import Any, Optional


_TOKEN_PREFIX = "gsc:token:"
_ACCOUNTS_SET = "gsc:accounts"
_DEFAULT_KEY = "gsc:default_account"
_STATE_PREFIX = "gsc:oauth_state:"


# ── Backend selection ─────────────────────────────────────────────────────────

def _redis_url() -> Optional[str]:
    return os.environ.get("REDIS_URL") or os.environ.get("KV_URL")


_redis_client = None


def _redis() -> Any:
    """Lazily build a redis-py client and cache it for the function's lifetime."""
    global _redis_client
    if _redis_client is not None:
        return _redis_client
    url = _redis_url()
    if not url:
        return None
    import redis
    _redis_client = redis.from_url(url, decode_responses=True, socket_timeout=10)
    return _redis_client


def _kv_rest(*command: str) -> object:
    """Execute one Upstash REST command (legacy Vercel KV path)."""
    import requests
    url = os.environ.get("KV_REST_API_URL")
    tok = os.environ.get("KV_REST_API_TOKEN")
    if not url or not tok:
        raise RuntimeError(
            "No Redis backend configured. Set REDIS_URL (preferred) or "
            "KV_REST_API_URL + KV_REST_API_TOKEN (legacy Vercel KV)."
        )
    resp = requests.post(
        url.rstrip("/"),
        headers={"Authorization": f"Bearer {tok}"},
        json=list(command),
        timeout=10,
    )
    resp.raise_for_status()
    return resp.json().get("result")


# ── Public API ────────────────────────────────────────────────────────────────

def get_token(email: str) -> Optional[dict]:
    raw = _get(_TOKEN_PREFIX + email)
    if not raw:
        return None
    return json.loads(raw)


def set_token(email: str, creds_json: str) -> None:
    _set(_TOKEN_PREFIX + email, creds_json)
    _sadd(_ACCOUNTS_SET, email)
    if not get_default():
        set_default(email)


def list_accounts() -> list[str]:
    members = _smembers(_ACCOUNTS_SET) or []
    return sorted(members)


def get_default() -> Optional[str]:
    return _get(_DEFAULT_KEY)


def set_default(email: str) -> None:
    _set(_DEFAULT_KEY, email)


def put_oauth_state(state: str, value: str = "1", ttl_seconds: int = 600) -> None:
    _set(_STATE_PREFIX + state, value, ex=ttl_seconds)


def pop_oauth_state(state: str) -> Optional[str]:
    key = _STATE_PREFIX + state
    value = _get(key)
    if value is not None:
        _del(key)
    return value


# ── Backend dispatch ──────────────────────────────────────────────────────────

def _get(key: str) -> Optional[str]:
    r = _redis()
    if r is not None:
        return r.get(key)
    return _kv_rest("GET", key)


def _set(key: str, value: str, ex: Optional[int] = None) -> None:
    r = _redis()
    if r is not None:
        if ex is not None:
            r.set(key, value, ex=ex)
        else:
            r.set(key, value)
        return
    if ex is not None:
        _kv_rest("SET", key, value, "EX", str(ex))
    else:
        _kv_rest("SET", key, value)


def _del(key: str) -> None:
    r = _redis()
    if r is not None:
        r.delete(key)
        return
    _kv_rest("DEL", key)


def _sadd(key: str, member: str) -> None:
    r = _redis()
    if r is not None:
        r.sadd(key, member)
        return
    _kv_rest("SADD", key, member)


def _smembers(key: str) -> list[str]:
    r = _redis()
    if r is not None:
        return list(r.smembers(key))
    members = _kv_rest("SMEMBERS", key)
    return list(members) if members else []
