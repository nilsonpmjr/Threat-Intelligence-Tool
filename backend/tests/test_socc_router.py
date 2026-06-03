"""Tests for /api/socc proxy router (Fase 2).

These tests don't talk to a real socc-plugin container. They monkeypatch
httpx.AsyncClient so we can assert:
  - the JWT we mint has the PRD-required claims (scope/iss/aud/ttl);
  - cross-user 404 from the plugin is surfaced unchanged;
  - the ollama gate fires before any HTTP call;
  - audit log entries are recorded with the PRD action names;
  - SSE pass-through propagates the upstream content-type and frames.
"""

from __future__ import annotations

import json
from typing import Any

import httpx
import jwt
import pytest

from config import settings


# ── helpers ────────────────────────────────────────────────────────────


def _decode_jwt(token: str) -> dict[str, Any]:
    secret = bytes.fromhex(settings.socc_internal_secret)
    return jwt.decode(
        token,
        secret,
        algorithms=["HS256"],
        issuer="vantage",
        audience="socc-plugin",
    )


class _FakeResponse:
    def __init__(self, status_code: int, body: dict | bytes | None = None):
        self.status_code = status_code
        if isinstance(body, dict):
            self.content = json.dumps(body).encode()
            self._json = body
        elif isinstance(body, bytes):
            self.content = body
            self._json = None
        else:
            self.content = b""
            self._json = None

    def json(self):
        if self._json is None:
            raise ValueError("not JSON")
        return self._json


class _CallRecorder:
    def __init__(self):
        self.calls: list[dict[str, Any]] = []

    def push(self, **kwargs):
        self.calls.append(kwargs)

    def last(self) -> dict[str, Any]:
        assert self.calls, "no calls recorded"
        return self.calls[-1]


def _patch_async_client_request(monkeypatch, recorder: _CallRecorder, response: _FakeResponse):
    """Patch httpx.AsyncClient.request ONLY for upstream calls to the
    socc plugin URL. The pytest harness itself uses httpx.AsyncClient to
    drive the FastAPI app, so we must let those calls fall through to
    the original implementation."""
    original = httpx.AsyncClient.request
    plugin_base = settings.socc_plugin_url.rstrip("/")

    async def fake_request(self, method, url, *, headers=None, json=None, **kwargs):
        url_str = str(url)
        if url_str.startswith(plugin_base):
            recorder.push(method=method, url=url_str, headers=headers, json=json)
            return response
        return await original(self, method, url, headers=headers, json=json, **kwargs)

    monkeypatch.setattr(httpx.AsyncClient, "request", fake_request)


# ── auth wiring ────────────────────────────────────────────────────────


def _auth_headers(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


# ── tests ──────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_minted_jwt_has_prd_required_claims(async_client, tech_token, monkeypatch):
    """When the proxy forwards a request, the upstream Authorization
    header carries a freshly-minted scope=socc JWT with the right claims
    (PRD §Security)."""
    rec = _CallRecorder()
    _patch_async_client_request(
        monkeypatch, rec, _FakeResponse(200, {"credentials": []})
    )

    res = await async_client.get(
        "/api/socc/providers", headers=_auth_headers(tech_token)
    )
    assert res.status_code == 200

    upstream_token = rec.last()["headers"]["Authorization"].removeprefix("Bearer ")
    claims = _decode_jwt(upstream_token)
    assert claims["scope"] == "socc"
    assert claims["iss"] == "vantage"
    assert claims["aud"] == "socc-plugin"
    assert claims["sub"] == "techuser"
    assert claims["exp"] - claims["iat"] <= 60  # PRD §Security TTL


@pytest.mark.asyncio
async def test_ollama_blocked_when_local_providers_disabled(
    async_client, tech_token, monkeypatch
):
    """PRD §US-1 AC: ollama is rejected without ever reaching the plugin
    when the admin flag is off."""
    rec = _CallRecorder()
    # Should NOT be called — assert via empty calls list at the end.
    _patch_async_client_request(monkeypatch, rec, _FakeResponse(500))
    monkeypatch.setattr(settings, "socc_allow_local_providers", False)

    res = await async_client.post(
        "/api/socc/providers",
        headers=_auth_headers(tech_token),
        json={
            "provider": "ollama",
            "label": "local",
            "apiKey": "fakeapikey",
            "defaultModel": "llama3",
        },
    )
    assert res.status_code == 403
    assert res.json()["error"] == "local_provider_disabled"
    assert rec.calls == []  # plugin never called


@pytest.mark.asyncio
async def test_cross_user_404_passes_through(async_client, tech_token, monkeypatch):
    """PRD §US-4 AC3: cross-user lookups must surface 404, not 403, and
    must not leak existence."""
    rec = _CallRecorder()
    _patch_async_client_request(
        monkeypatch, rec, _FakeResponse(404, {"error": "session_not_found"})
    )

    res = await async_client.delete(
        "/api/socc/session/01HSOMEONEELSESID",
        headers=_auth_headers(tech_token),
    )
    assert res.status_code == 404
    assert res.json() == {"error": "session_not_found"}


@pytest.mark.asyncio
async def test_audit_log_records_session_started_with_target(
    async_client, tech_token, fake_db, monkeypatch
):
    """PRD §Security: socc_session_started in audit_log with sessionId
    as target. Content of messages is NEVER logged (separate test)."""
    rec = _CallRecorder()
    _patch_async_client_request(
        monkeypatch,
        rec,
        _FakeResponse(201, {"sessionId": "01H_NEW", "userId": "techuser"}),
    )

    res = await async_client.post(
        "/api/socc/session",
        headers=_auth_headers(tech_token),
        json={"credentialId": "cred_x"},
    )
    assert res.status_code == 201

    entry = await fake_db.audit_log.find_one({"action": "socc_session_started"})
    assert entry is not None
    assert entry["target"] == "01H_NEW"
    assert entry["user"] == "techuser"
    assert entry["result"] == "success"


@pytest.mark.asyncio
async def test_message_audit_carries_only_metadata(
    async_client, tech_token, fake_db, monkeypatch
):
    """PRD §Security: socc_message_sent must contain only metadata, never
    conversation text. We only forbid the message text from showing up."""

    # Fake the streaming proxy: replace AsyncClient.stream with a minimal
    # async context manager that yields one SSE frame.
    class _FakeStreamCtx:
        status_code = 200

        def __init__(self):
            self.aread_called = False

        async def __aenter__(self):
            return self

        async def __aexit__(self, exc_type, exc, tb):
            return False

        async def aiter_raw(self):
            yield b"event: message.start\ndata: {\"messageId\":\"m1\"}\n\n"

        async def aread(self):
            return b""

    def fake_stream(self, method, url, *, headers=None, json=None, **kwargs):
        return _FakeStreamCtx()

    monkeypatch.setattr(httpx.AsyncClient, "stream", fake_stream)

    secret_text = "this exact phrase must never appear in audit"
    res = await async_client.post(
        "/api/socc/session/01H_SID/message",
        headers=_auth_headers(tech_token),
        json={"text": secret_text},
    )
    assert res.status_code == 200
    assert "text/event-stream" in res.headers["content-type"]
    body = res.text
    assert "event: message.start" in body

    entry = await fake_db.audit_log.find_one({"action": "socc_message_sent"})
    assert entry is not None
    assert entry["target"] == "01H_SID"
    serialized = json.dumps(entry, default=str)
    assert secret_text not in serialized  # PRD requirement


@pytest.mark.asyncio
async def test_unreachable_plugin_returns_socc_unavailable(
    async_client, tech_token, monkeypatch
):
    """When the plugin can't be reached, the proxy returns 503 with
    code `socc_unavailable` (PRD §Security reserved code)."""
    original = httpx.AsyncClient.request
    plugin_base = settings.socc_plugin_url.rstrip("/")

    async def fake_request(self, method, url, *, headers=None, json=None, **kwargs):
        if str(url).startswith(plugin_base):
            raise httpx.ConnectError("nope", request=httpx.Request(method, url))
        return await original(self, method, url, headers=headers, json=json, **kwargs)

    monkeypatch.setattr(httpx.AsyncClient, "request", fake_request)

    res = await async_client.get(
        "/api/socc/providers", headers=_auth_headers(tech_token)
    )
    assert res.status_code == 503
    assert res.json()["error"] == "socc_unavailable"
