"""Generic extensions API — install/start/stop/restart/uninstall any
declarative extension by `ext_id`. PRD §Extensions Platform (Fase 4).

This router knows NOTHING about SOC Copilot specifically. Adding a new
extension to the catalog is `mkdir backend/extensions/<id>` + writing
the manifest + compose. The UI in /extensions reads the catalog and
renders cards generically.

Admin + MFA gate: every mutating endpoint requires
`require_role(["admin"])`. The MFA enrollment is enforced upstream in
auth.py for admin sessions per the existing platform policy.
"""

from __future__ import annotations

import logging
from typing import Any

import json as _json

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Request, status
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field

from audit import log_action
from auth import get_current_user, require_role
from config import settings
from db import db_manager

from services.extensions import (
    DockerProxyClient,
    DockerProxyError,
    ExtensionManager,
    ExtensionRegistry,
    LifecycleError,
    PreflightError,
)

logger = logging.getLogger("extensions")
router = APIRouter(prefix="/extensions", tags=["extensions"])


# ── singletons (initialized on first request) ────────────────────────


_registry: ExtensionRegistry | None = None
_manager: ExtensionManager | None = None


def _resolve_extensions_root():
    from pathlib import Path

    # backend/extensions/<id>/manifest.yaml — relative to this file's parent.
    return Path(__file__).resolve().parent.parent / "extensions"


def get_manager() -> ExtensionManager:
    """Lazy bootstrap so tests can swap the registry/docker via DI."""
    global _registry, _manager
    if _manager is None:
        _registry = ExtensionRegistry(_resolve_extensions_root())
        _registry.reload()
        _manager = ExtensionManager(
            db=db_manager.db,
            registry=_registry,
            docker=DockerProxyClient(base_url=settings.docker_proxy_url),
        )
    return _manager


# ── helpers ──────────────────────────────────────────────────────────


def _client_ip(request: Request) -> str:
    return request.client.host if request.client else ""


async def _audit(user: dict, action: str, target: str, **kw: Any) -> None:
    try:
        await log_action(
            db_manager.db,
            user=user.get("username", "unknown"),
            action=action,
            target=target,
            ip=kw.get("ip", ""),
            result=kw.get("result", "success"),
            detail=kw.get("detail", ""),
        )
    except Exception:
        logger.exception("audit log failed for action=%s", action)


def _http_for_lifecycle_error(e: LifecycleError) -> HTTPException:
    msg = str(e)
    if "locked" in msg.lower():
        return HTTPException(status_code=409, detail={"error": "locked", "message": msg})
    if "not allowed" in msg or "did not match" in msg or "unknown" in msg:
        return HTTPException(status_code=400, detail={"error": "bad_state", "message": msg})
    return HTTPException(status_code=400, detail={"error": "lifecycle", "message": msg})


# ── catalog (read-only) ──────────────────────────────────────────────


@router.get("")
async def list_extensions(
    current_user: dict = Depends(get_current_user),
):
    """Anyone authenticated can browse the catalog. Admin actions are
    gated separately on the mutating endpoints."""
    return {"extensions": await get_manager().list()}


@router.get("/{ext_id}")
async def get_extension(
    ext_id: str,
    current_user: dict = Depends(get_current_user),
):
    item = await get_manager().get(ext_id)
    if not item:
        raise HTTPException(status_code=404, detail={"error": "not_found"})
    return item


@router.get("/{ext_id}/status")
async def status_extension(
    ext_id: str,
    current_user: dict = Depends(get_current_user),
):
    """Lightweight status probe — runs the manifest's healthcheck and
    returns the freshly-updated state doc."""
    mgr = get_manager()
    if not mgr._registry.get(ext_id):  # noqa: SLF001 — internal access OK here
        raise HTTPException(status_code=404, detail={"error": "not_found"})
    try:
        await mgr.healthcheck(ext_id)
    except LifecycleError as e:
        raise _http_for_lifecycle_error(e) from e
    return await mgr.get(ext_id)


# ── lifecycle (admin + MFA) ──────────────────────────────────────────


class _UninstallBody(BaseModel):
    confirm_phrase: str = Field(min_length=1, max_length=120)
    destroy_volumes: bool | None = None


class _SettingsBody(BaseModel):
    settings: dict[str, Any]


@router.post("/{ext_id}/install", status_code=202)
async def install(
    ext_id: str,
    request: Request,
    background: BackgroundTasks,
    current_user: dict = Depends(require_role(["admin"])),
):
    """Async install — returns 202 immediately, the actual `compose up`
    runs in a BackgroundTask. Frontend polls /status."""
    mgr = get_manager()
    if not mgr._registry.get(ext_id):  # noqa: SLF001
        raise HTTPException(status_code=404, detail={"error": "not_found"})

    async def _run():
        try:
            await mgr.install(ext_id, user=current_user["username"])
            await _audit(
                current_user,
                action=f"{ext_id}_install",
                target=ext_id,
                ip=_client_ip(request),
            )
        except (LifecycleError, PreflightError, DockerProxyError) as e:
            logger.error("install %s failed: %s", ext_id, e)
            await _audit(
                current_user,
                action=f"{ext_id}_install",
                target=ext_id,
                result="failure",
                detail=str(e)[:240],
                ip=_client_ip(request),
            )

    background.add_task(_run)
    return {"task_id": f"install:{ext_id}", "status": "accepted"}


@router.post("/{ext_id}/uninstall", status_code=202)
async def uninstall(
    ext_id: str,
    body: _UninstallBody,
    request: Request,
    background: BackgroundTasks,
    current_user: dict = Depends(require_role(["admin"])),
):
    mgr = get_manager()
    if not mgr._registry.get(ext_id):  # noqa: SLF001
        raise HTTPException(status_code=404, detail={"error": "not_found"})

    # Pre-check state synchronously so the frontend gets immediate
    # feedback instead of 202 + silent BackgroundTask failure.
    try:
        await mgr._guard_action(ext_id, "uninstall")  # noqa: SLF001
    except LifecycleError as e:
        raise _http_for_lifecycle_error(e) from e

    async def _run():
        try:
            await mgr.uninstall(
                ext_id,
                user=current_user["username"],
                confirm_phrase=body.confirm_phrase,
                destroy_volumes=body.destroy_volumes,
            )
            await _audit(
                current_user,
                action=f"{ext_id}_uninstall",
                target=ext_id,
                ip=_client_ip(request),
                detail=f"destroy_volumes={body.destroy_volumes}",
            )
        except (LifecycleError, DockerProxyError) as e:
            logger.error("uninstall %s failed: %s", ext_id, e)
            await _audit(
                current_user,
                action=f"{ext_id}_uninstall",
                target=ext_id,
                result="failure",
                detail=str(e)[:240],
                ip=_client_ip(request),
            )

    background.add_task(_run)
    return {"task_id": f"uninstall:{ext_id}", "status": "accepted"}


@router.post("/{ext_id}/start")
async def start(
    ext_id: str,
    request: Request,
    current_user: dict = Depends(require_role(["admin"])),
):
    mgr = get_manager()
    try:
        await mgr.start(ext_id, user=current_user["username"])
    except LifecycleError as e:
        raise _http_for_lifecycle_error(e) from e
    await _audit(current_user, action=f"{ext_id}_start", target=ext_id, ip=_client_ip(request))
    return await mgr.get(ext_id)


@router.post("/{ext_id}/stop")
async def stop(
    ext_id: str,
    request: Request,
    current_user: dict = Depends(require_role(["admin"])),
):
    mgr = get_manager()
    try:
        await mgr.stop(ext_id, user=current_user["username"])
    except LifecycleError as e:
        raise _http_for_lifecycle_error(e) from e
    await _audit(current_user, action=f"{ext_id}_stop", target=ext_id, ip=_client_ip(request))
    return await mgr.get(ext_id)


@router.post("/{ext_id}/restart")
async def restart(
    ext_id: str,
    request: Request,
    current_user: dict = Depends(require_role(["admin"])),
):
    mgr = get_manager()
    try:
        await mgr.restart(ext_id, user=current_user["username"])
    except LifecycleError as e:
        raise _http_for_lifecycle_error(e) from e
    await _audit(current_user, action=f"{ext_id}_restart", target=ext_id, ip=_client_ip(request))
    return await mgr.get(ext_id)


@router.patch("/{ext_id}/settings")
async def patch_settings(
    ext_id: str,
    body: _SettingsBody,
    request: Request,
    current_user: dict = Depends(require_role(["admin"])),
):
    mgr = get_manager()
    try:
        applied = await mgr.patch_settings(
            ext_id, settings_patch=body.settings, user=current_user["username"]
        )
    except LifecycleError as e:
        raise _http_for_lifecycle_error(e) from e
    await _audit(
        current_user,
        action=f"{ext_id}_flag_changed",
        target=ext_id,
        detail=",".join(applied.keys()),
        ip=_client_ip(request),
    )
    return {"settings": applied}


@router.post("/{ext_id}/secrets/{secret_name}/rotate")
async def rotate_secret(
    ext_id: str,
    secret_name: str,
    request: Request,
    current_user: dict = Depends(require_role(["admin"])),
):
    mgr = get_manager()
    try:
        await mgr.rotate_secret(ext_id, secret_name, user=current_user["username"])
    except LifecycleError as e:
        raise _http_for_lifecycle_error(e) from e
    await _audit(
        current_user,
        action=f"{ext_id}_secret_rotated",
        target=secret_name,
        ip=_client_ip(request),
    )
    return {"rotated": secret_name}


# ── log streaming (SSE) ──────────────────────────────────────────────


@router.get("/{ext_id}/logs")
async def stream_logs(
    ext_id: str,
    current_user: dict = Depends(require_role(["admin"])),
    tail: int = 200,
):
    """Tail logs of the extension's primary container as SSE.

    Multi-container streaming would require multiplexing; the MVP picks
    the container whose name matches the manifest id (e.g. `socc-copilot`
    for `socc`). Convention is enforced in the compose file.
    """
    mgr = get_manager()
    entry = mgr._registry.get(ext_id)  # noqa: SLF001
    if not entry:
        raise HTTPException(status_code=404, detail={"error": "not_found"})

    container_name = entry.manifest.health.url.split("//", 1)[-1].split(":", 1)[0]
    docker = mgr._docker  # noqa: SLF001

    # Check container existence before opening the SSE stream.
    try:
        await docker.inspect_container(container_name)
    except DockerProxyError as e:
        if e.status == 404:
            async def _not_found():
                yield b'event: error\ndata: {"error":"container_not_found","message":"Extension not installed or container missing"}\n\n'
            return StreamingResponse(
                _not_found(), media_type="text/event-stream"
            )
        raise

    async def gen():
        try:
            async for chunk in docker.stream_logs(container_name, tail=tail, follow=True):
                yield b"event: log\ndata: " + chunk.replace(b"\n", b"\\n") + b"\n\n"
        except Exception as e:
            # Catch DockerProxyError, httpx.ConnectError, and any other unexpected
            # error so they surface as an SSE error frame rather than crashing the
            # response mid-stream and triggering a client reconnect loop.
            payload = _json.dumps({"error": "logs_failed", "message": str(e)})
            yield b"event: error\ndata: " + payload.encode() + b"\n\n"

    return StreamingResponse(
        gen(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache, no-transform",
            "X-Accel-Buffering": "no",
            "Connection": "keep-alive",
        },
    )
