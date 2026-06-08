"""SOC Copilot — Vantage backend proxy (Fase 2 of socc-copilot-plugin PRD).

This router is the ONLY legitimate caller of the `socc-copilot` container
in production. It:

  1. authenticates the Vantage user via existing cookies/JWT;
  2. mints a short-lived (≤ 60s) HS256 internal JWT with scope=socc,
     sub=user_id, sid=session_id (when applicable);
  3. forwards the request to the plugin over the internal docker network;
  4. records audit events for sensitive actions;
  5. enforces per-user rate limits and provider-flag guards before
     touching the plugin (the plugin enforces them too, but failing fast
     on this side avoids a round trip and keeps audit logs cleaner).

The plugin already enforces ownership and returns 404 (not 403) for
cross-user lookups (PRD §US-4 AC3). We trust those status codes and pass
them through verbatim — the only mapping we do is on transport-level
errors (plugin unreachable → 503 with code `socc_unavailable`).

Routes mounted under `/api/socc` (and `/api/v1/socc`) by main.py.

Disable the entire router by leaving SOCC_INTERNAL_SECRET empty in env;
main.py probes settings.socc_internal_secret before include_router().
"""

from __future__ import annotations

import logging
import time
from typing import Any, AsyncIterator, Optional

import httpx
import jwt
from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.responses import JSONResponse, StreamingResponse
from pydantic import BaseModel, Field

from audit import log_action
from auth import get_current_user
from config import settings
from db import db_manager
from limiters import limiter

logger = logging.getLogger("socc")
router = APIRouter(prefix="/socc", tags=["socc"])


JWT_ISSUER = "vantage"
JWT_AUDIENCE = "socc-plugin"
JWT_SCOPE = "socc"
JWT_TTL_SECONDS = 60

# Reserved error codes from PRD §Security. We don't import the enum from
# the plugin (no shared package); literals here mirror src/server/errors.ts.
ERR_PROVIDER_UNAVAILABLE = "provider_unavailable"
ERR_SESSION_NOT_FOUND = "session_not_found"
ERR_LOCAL_PROVIDER_DISABLED = "local_provider_disabled"
ERR_SOCC_UNAVAILABLE = "socc_unavailable"
ERR_SOCC_NOT_INSTALLED = "socc_not_installed"
ERR_QUOTA_EXCEEDED = "quota_exceeded"
ERR_INTERNAL = "internal_error"


# ── helpers ────────────────────────────────────────────────────────────


def _mint_internal_jwt(sub: str, sid: Optional[str] = None) -> str:
    """Sign a scope=socc HS256 JWT with TTL ≤ 60s (PRD §Security)."""
    if not settings.socc_internal_secret:
        # Should never reach here — main.py refuses to mount the router
        # when the secret is missing — but defensively guard anyway.
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail={"error": ERR_SOCC_NOT_INSTALLED},
        )
    secret = bytes.fromhex(settings.socc_internal_secret)
    if len(secret) < 32:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail={"error": ERR_INTERNAL, "message": "SOCC_INTERNAL_SECRET too short"},
        )
    now = int(time.time())
    claims: dict[str, Any] = {
        "sub": sub,
        "scope": JWT_SCOPE,
        "iss": JWT_ISSUER,
        "aud": JWT_AUDIENCE,
        "iat": now,
        "exp": now + JWT_TTL_SECONDS,
    }
    if sid:
        claims["sid"] = sid
    return jwt.encode(claims, secret, algorithm="HS256")


def _client_ip(request: Request) -> str:
    return request.client.host if request.client else ""


async def _audit(
    user: dict, action: str, target: str = "", result: str = "success", detail: str = "", ip: str = ""
) -> None:
    """Wrapper that pulls the username out of the user dict + tolerates a
    missing db (e.g. unit tests that don't connect Mongo)."""
    try:
        await log_action(
            db_manager.db,
            user=user.get("username", "unknown"),
            action=action,
            target=target,
            ip=ip,
            result=result,
            detail=detail,
        )
    except Exception:
        # Audit failures must never crash an in-flight request.
        logger.exception("audit log failed for action=%s target=%s", action, target)


def _build_proxy_url(path: str) -> str:
    base = settings.socc_plugin_url.rstrip("/")
    return f"{base}{path}"


async def _proxy_json(
    method: str,
    path: str,
    *,
    user: dict,
    sid: Optional[str] = None,
    json: Optional[dict] = None,
) -> JSONResponse:
    """Forward a non-streaming request to the plugin, propagating its
    status code and JSON body. Cross-user 404s pass through unchanged."""
    token = _mint_internal_jwt(sub=user["username"], sid=sid)
    headers = {"Authorization": f"Bearer {token}"}
    url = _build_proxy_url(path)
    timeout = httpx.Timeout(settings.socc_proxy_timeout_seconds)
    try:
        async with httpx.AsyncClient(timeout=timeout) as client:
            resp = await client.request(method, url, headers=headers, json=json)
    except httpx.HTTPError as exc:
        logger.warning("socc proxy unreachable: %s", exc)
        return JSONResponse(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            content={"error": ERR_SOCC_UNAVAILABLE, "message": "plugin unreachable"},
        )
    # Pass through status + body verbatim. JSON body or empty body only —
    # streaming routes use a different helper below.
    body: Any = None
    if resp.content:
        try:
            body = resp.json()
        except ValueError:
            body = {"error": ERR_INTERNAL, "message": "plugin returned non-JSON"}
            return JSONResponse(status_code=resp.status_code, content=body)
    return JSONResponse(status_code=resp.status_code, content=body)


async def _proxy_multipart(
    path: str,
    *,
    user: dict,
    sid: str,
    raw_request: Request,
) -> JSONResponse:
    """Forward a multipart/form-data request to the plugin verbatim.
    Used for attachment uploads so we don't buffer the entire file in Python."""
    token = _mint_internal_jwt(sub=user["username"], sid=sid)
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": raw_request.headers.get("content-type", ""),
    }
    url = _build_proxy_url(path)
    timeout = httpx.Timeout(settings.socc_proxy_timeout_seconds)
    try:
        body_bytes = await raw_request.body()
        async with httpx.AsyncClient(timeout=timeout) as client:
            resp = await client.post(url, headers=headers, content=body_bytes)
    except httpx.HTTPError as exc:
        logger.warning("socc proxy unreachable: %s", exc)
        return JSONResponse(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            content={"error": ERR_SOCC_UNAVAILABLE, "message": "plugin unreachable"},
        )
    body: Any = None
    if resp.content:
        try:
            body = resp.json()
        except ValueError:
            body = {"error": ERR_INTERNAL, "message": "plugin returned non-JSON"}
    return JSONResponse(status_code=resp.status_code, content=body)


async def _proxy_stream(
    path: str, *, user: dict, sid: Optional[str], json: dict
) -> StreamingResponse:
    """SSE pass-through — the plugin streams `text/event-stream` frames;
    we forward them byte-for-byte and let the client EventSource parse."""
    token = _mint_internal_jwt(sub=user["username"], sid=sid)
    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "text/event-stream",
        "Cache-Control": "no-cache",
    }
    url = _build_proxy_url(path)
    # Long-lived stream: don't apply the short proxy_timeout. The plugin
    # owns the 90s per-turn timeout (PRD §Security).
    client = httpx.AsyncClient(timeout=httpx.Timeout(None, connect=10.0))

    async def gen() -> AsyncIterator[bytes]:
        try:
            async with client.stream("POST", url, headers=headers, json=json) as resp:
                if resp.status_code >= 400:
                    # Drain the JSON body and re-emit as a single SSE
                    # error frame so the client sees a uniform stream
                    # contract instead of an HTTP error.
                    body = await resp.aread()
                    yield (
                        b"event: error\n"
                        b"data: " + body + b"\n\n"
                    )
                    return
                async for chunk in resp.aiter_raw():
                    if chunk:
                        yield chunk
        except httpx.HTTPError as exc:
            logger.warning("socc stream broken: %s", exc)
            yield (
                b'event: error\n'
                b'data: {"type":"error","code":"' + ERR_SOCC_UNAVAILABLE.encode() + b'","message":"plugin unreachable","retriable":true}\n\n'
            )
        finally:
            await client.aclose()

    return StreamingResponse(
        gen(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache, no-transform",
            "X-Accel-Buffering": "no",
            "Connection": "keep-alive",
        },
    )


# ── schemas (kept narrow — full validation happens at the plugin) ──────


class OAuthCallback(BaseModel):
    code: str = Field(min_length=1)
    state: str = Field(min_length=1)


class CreateProvider(BaseModel):
    provider: str = Field(pattern=r"^(anthropic|openai|gemini|ollama|openai-compatible)$")
    label: str = Field(min_length=1, max_length=80)
    apiKey: str = Field(min_length=8)
    baseUrl: Optional[str] = None
    defaultModel: str = Field(min_length=1)
    maxOutputTokens: Optional[int] = Field(default=None, gt=0)


class CreateSession(BaseModel):
    credentialId: str = Field(min_length=1)
    modelOverride: Optional[str] = Field(default=None, max_length=128)
    systemPrompt: Optional[str] = Field(default=None, max_length=32_000)
    analysisId: Optional[str] = Field(default=None, max_length=128)


class InjectContext(BaseModel):
    iocs: Optional[list[str]] = None
    hashes: Optional[list[str]] = None
    ips: Optional[list[str]] = None
    domains: Optional[list[str]] = None
    cves: Optional[list[str]] = None
    rawContext: Optional[str] = Field(default=None, max_length=8_000)
    analysisId: Optional[str] = Field(default=None, max_length=128)


class SendMessage(BaseModel):
    text: str = Field(min_length=1, max_length=32_000)
    attachmentIds: Optional[list[str]] = None


class AbortBody(BaseModel):
    turnId: Optional[str] = None


# ── OAuth ──────────────────────────────────────────────────────────────


SUPPORTED_OAUTH_PROVIDERS = {"anthropic", "openai"}


@router.get("/auth/{provider}/initiate")
async def oauth_initiate(
    request: Request,
    provider: str,
    current_user: dict = Depends(get_current_user),
):
    if provider not in SUPPORTED_OAUTH_PROVIDERS:
        return JSONResponse(
            status_code=status.HTTP_400_BAD_REQUEST,
            content={"error": "unsupported_provider", "supported": list(SUPPORTED_OAUTH_PROVIDERS)},
        )
    await _audit(
        current_user,
        action="socc_oauth_initiate",
        target=provider,
        ip=_client_ip(request),
    )
    return await _proxy_json("GET", f"/v1/auth/{provider}/initiate", user=current_user)


@router.post("/auth/{provider}/callback")
async def oauth_callback(
    request: Request,
    provider: str,
    body: OAuthCallback,
    current_user: dict = Depends(get_current_user),
):
    if provider not in SUPPORTED_OAUTH_PROVIDERS:
        return JSONResponse(
            status_code=status.HTTP_400_BAD_REQUEST,
            content={"error": "unsupported_provider"},
        )
    response = await _proxy_json(
        "POST",
        f"/v1/auth/{provider}/callback",
        user=current_user,
        json=body.model_dump(),
    )
    result = "success" if response.status_code == 201 else "failure"
    credential_id = ""
    if response.status_code == 201:
        try:
            import json as _json
            data = _json.loads(response.body or b"{}")
            credential_id = data.get("credentialId", "")
        except Exception:
            pass
    await _audit(
        current_user,
        action="socc_oauth_callback",
        target=f"{provider}:{credential_id}",
        result=result,
        ip=_client_ip(request),
    )
    return response


# ── providers ──────────────────────────────────────────────────────────


@router.post("/providers")
async def create_provider(
    request: Request,
    body: CreateProvider,
    current_user: dict = Depends(get_current_user),
):
    # PRD §US-1 AC: ollama gated by admin flag — fail fast before
    # forwarding so the plugin never sees a request we know will fail.
    if body.provider == "ollama" and not settings.socc_allow_local_providers:
        await _audit(
            current_user,
            action="socc_provider_created",
            result="denied",
            detail="local_provider_disabled",
            ip=_client_ip(request),
        )
        return JSONResponse(
            status_code=status.HTTP_403_FORBIDDEN,
            content={"error": ERR_LOCAL_PROVIDER_DISABLED},
        )
    response = await _proxy_json("POST", "/v1/credentials", user=current_user, json=body.model_dump())
    target = ""
    if isinstance(response.body, (bytes, bytearray)):
        # FastAPI hasn't serialized yet; we only use it for audit detail.
        pass
    if response.status_code == 201:
        # Pull the new id from the JSON we just returned to the user.
        try:
            import json as _json
            data = _json.loads(response.body or b"{}")
            target = data.get("id", "")
        except Exception:
            target = ""
    await _audit(
        current_user,
        action="socc_provider_created",
        target=target,
        result="success" if response.status_code == 201 else "failure",
        ip=_client_ip(request),
    )
    return response


@router.get("/providers")
async def list_providers(current_user: dict = Depends(get_current_user)):
    return await _proxy_json("GET", "/v1/credentials", user=current_user)


@router.delete("/providers/{provider_id}")
async def revoke_provider(
    request: Request,
    provider_id: str,
    current_user: dict = Depends(get_current_user),
):
    response = await _proxy_json(
        "DELETE", f"/v1/credentials/{provider_id}", user=current_user
    )
    await _audit(
        current_user,
        action="socc_provider_revoked",
        target=provider_id,
        result="success" if response.status_code == 204 else "failure",
        ip=_client_ip(request),
    )
    return response


@router.post("/providers/{provider_id}/test")
async def test_provider(
    request: Request,
    provider_id: str,
    current_user: dict = Depends(get_current_user),
):
    """US-1 AC: the frontend disables save until this comes back ok=true."""
    response = await _proxy_json(
        "POST", f"/v1/credentials/{provider_id}/test", user=current_user
    )
    detail = ""
    try:
        import json as _json
        data = _json.loads(response.body or b"{}")
        detail = data.get("result", "")
    except Exception:
        pass
    await _audit(
        current_user,
        action="socc_provider_tested",
        target=provider_id,
        result=detail or "unknown",
        ip=_client_ip(request),
    )
    return response


@router.get("/providers/{provider_id}/models")
async def list_provider_models(
    provider_id: str,
    current_user: dict = Depends(get_current_user),
):
    """US-7: return curated model list for the credential's provider."""
    return await _proxy_json("GET", f"/v1/credentials/{provider_id}/models", user=current_user)


# ── sessions ───────────────────────────────────────────────────────────


@router.post("/session")
async def create_session(
    request: Request,
    body: CreateSession,
    current_user: dict = Depends(get_current_user),
):
    response = await _proxy_json(
        "POST", "/v1/session", user=current_user, json=body.model_dump()
    )
    target = ""
    if response.status_code == 201:
        try:
            import json as _json
            data = _json.loads(response.body or b"{}")
            target = data.get("sessionId", "")
        except Exception:
            target = ""
    await _audit(
        current_user,
        action="socc_session_started",
        target=target,
        result="success" if response.status_code == 201 else "failure",
        ip=_client_ip(request),
    )
    return response


@router.get("/session")
async def list_sessions(current_user: dict = Depends(get_current_user)):
    return await _proxy_json("GET", "/v1/session", user=current_user)


@router.delete("/session/{session_id}")
async def close_session(
    request: Request,
    session_id: str,
    current_user: dict = Depends(get_current_user),
):
    response = await _proxy_json(
        "DELETE", f"/v1/session/{session_id}", user=current_user, sid=session_id
    )
    await _audit(
        current_user,
        action="socc_session_ended",
        target=session_id,
        result="success" if response.status_code == 204 else "failure",
        ip=_client_ip(request),
    )
    return response


@router.post("/session/{session_id}/attachments")
async def upload_attachment(
    request: Request,
    session_id: str,
    current_user: dict = Depends(get_current_user),
):
    """US-3: Forward multipart attachment to the plugin."""
    content_type = request.headers.get("content-type", "")
    if "multipart/form-data" not in content_type:
        return JSONResponse(
            status_code=status.HTTP_415_UNSUPPORTED_MEDIA_TYPE,
            content={"error": "Expected multipart/form-data"},
        )
    return await _proxy_multipart(
        f"/v1/session/{session_id}/attachments",
        user=current_user,
        sid=session_id,
        raw_request=request,
    )


@router.get("/session/{session_id}/history")
async def get_turn_history(
    session_id: str,
    current_user: dict = Depends(get_current_user),
):
    """P-1: Retrieve encrypted turn history for a session (opt-in feature)."""
    return await _proxy_json(
        "GET",
        f"/v1/session/{session_id}/history",
        user=current_user,
        sid=session_id,
    )


@router.post("/session/{session_id}/context")
async def inject_context(
    request: Request,
    session_id: str,
    body: InjectContext,
    current_user: dict = Depends(get_current_user),
):
    """V-1: Inject VANTAGE threat context into a session's system prompt."""
    response = await _proxy_json(
        "POST",
        f"/v1/session/{session_id}/context",
        user=current_user,
        sid=session_id,
        json=body.model_dump(exclude_none=True),
    )
    if response.status_code == 200 and body.analysisId:
        await _audit(
            current_user,
            action="socc_context_injected",
            target=f"{session_id}:{body.analysisId}",
            ip=_client_ip(request),
        )
    return response


@router.post("/session/{session_id}/abort")
async def abort_turn(
    session_id: str,
    body: AbortBody,
    current_user: dict = Depends(get_current_user),
):
    return await _proxy_json(
        "POST",
        f"/v1/session/{session_id}/abort",
        user=current_user,
        sid=session_id,
        json=body.model_dump(),
    )


# ── streaming turn (SSE) ───────────────────────────────────────────────
#
# PRD §Security: 20 msgs/min/user — applied with slowapi using the
# already-existing per-user key function. The plugin enforces the same
# cap via its own quota; the Vantage limit is what the user actually
# hits because requests don't reach the plugin until we let them.


@router.post("/session/{session_id}/message")
@limiter.limit(settings.rate_limit_socc_message)
async def send_message(
    request: Request,
    session_id: str,
    body: SendMessage,
    current_user: dict = Depends(get_current_user),
):
    # Audit the metadata BEFORE streaming. PRD §Security explicitly
    # forbids logging conversation content.
    await _audit(
        current_user,
        action="socc_message_sent",
        target=session_id,
        result="streaming",
        detail=f"len={len(body.text)}",
        ip=_client_ip(request),
    )
    return await _proxy_stream(
        f"/v1/session/{session_id}/message",
        user=current_user,
        sid=session_id,
        json=body.model_dump(),
    )


# ── LGPD: portability + erasure ────────────────────────────────────────


@router.get("/export")
async def export_data(
    request: Request,
    current_user: dict = Depends(get_current_user),
):
    """LGPD portability — return the user's socc data (keys masked)."""
    await _audit(
        current_user,
        action="socc_data_exported",
        target=current_user["username"],
        ip=_client_ip(request),
    )
    return await _proxy_json("GET", "/v1/data/export", user=current_user)


async def purge_user_socc_data(username: str) -> bool:
    """LGPD erasure hook — delete all socc data for a user in the plugin.

    Invoked from the user lifecycle (deactivate/delete) in users.py. It must
    never raise: a plugin that is down or not installed must not block the
    user operation. Returns True only when the plugin confirmed deletion.
    """
    if not settings.socc_internal_secret:
        return False
    try:
        token = _mint_internal_jwt(sub=username)
        headers = {"Authorization": f"Bearer {token}"}
        url = _build_proxy_url("/v1/data")
        timeout = httpx.Timeout(settings.socc_proxy_timeout_seconds)
        async with httpx.AsyncClient(timeout=timeout) as client:
            resp = await client.request("DELETE", url, headers=headers)
        return resp.status_code == 200
    except Exception:
        logger.warning("socc data purge failed for user=%s", username, exc_info=True)
        return False
