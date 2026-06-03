"""ExtensionManager — orchestrator for the install/start/stop/uninstall
lifecycle. PRD §Extensions Platform.

State lives in Mongo collection `extensions_state` (one doc per ext_id):

    {
      "_id": "<ext_id>",
      "status": "<ExtensionStatus>",
      "version": "<manifest.version at install time>",
      "installed_at": <datetime|null>,
      "last_health_ts": <datetime|null>,
      "last_error": "<str|null>",
      "settings": {<setting key>: <value>},
      "secrets_present": [<secret name>...],     # presence only, never the value
      "locked_by": {"action": "...", "user": "...", "started_at": ...} | None,
    }

Generated secrets are stored in `extensions_secrets` (separate
collection so they can have a different access policy in v2):

    {
      "_id": "<ext_id>:<secret_name>",
      "ext_id": "...",
      "name": "...",
      "value": "<base64 or hex string>",
      "rotated_at": <datetime>,
    }

The MVP keeps secrets in plaintext at rest because the Vantage backend
already requires Mongo auth. Encryption-at-rest with `crypto.py` is
listed in TODO Hardening transversal.
"""

from __future__ import annotations

import asyncio
import base64
import logging
import secrets
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any

import httpx

from .docker_client import DockerProxyClient, DockerProxyError
from .manifest import Manifest
from .registry import ExtensionRegistry, RegistryEntry

logger = logging.getLogger("extensions.manager")


class ExtensionStatus(str, Enum):
    NOT_INSTALLED = "not_installed"
    INSTALLING = "installing"
    INSTALLED_HEALTHY = "installed_healthy"
    INSTALLED_UNHEALTHY = "installed_unhealthy"
    STOPPED = "stopped"
    INSTALLING_FAILED = "installing_failed"
    UNINSTALLING = "uninstalling"


# Statuses where a new lifecycle action is allowed. Keeps `start` from
# firing during `installing`, etc.
_ACTIONABLE = {
    "install":   {ExtensionStatus.NOT_INSTALLED, ExtensionStatus.INSTALLING_FAILED},
    "start":     {ExtensionStatus.STOPPED, ExtensionStatus.INSTALLED_UNHEALTHY},
    "stop":      {ExtensionStatus.INSTALLED_HEALTHY, ExtensionStatus.INSTALLED_UNHEALTHY},
    "restart":   {ExtensionStatus.INSTALLED_HEALTHY, ExtensionStatus.INSTALLED_UNHEALTHY, ExtensionStatus.STOPPED},
    "uninstall": {
        ExtensionStatus.INSTALLED_HEALTHY,
        ExtensionStatus.INSTALLED_UNHEALTHY,
        ExtensionStatus.STOPPED,
        ExtensionStatus.INSTALLING_FAILED,
    },
}


class LifecycleError(Exception):
    """User-facing lifecycle failure (wrong state, locked, etc.)."""


class PreflightError(Exception):
    """Pre-flight check failed (proxy down, disk full, compose invalid)."""


# ── secret generators ───────────────────────────────────────────────


def _generate_secret(generator: str, length: int) -> str:
    """Length is in BYTES; output is base64- or hex-encoded as the
    manifest declares."""
    raw = secrets.token_bytes(length)
    if generator == "random_bytes_base64":
        return base64.b64encode(raw).decode("ascii")
    if generator == "random_bytes_hex":
        return raw.hex()
    raise ValueError(f"unknown generator '{generator}'")


# ── manager ─────────────────────────────────────────────────────────


@dataclass
class ManagerConfig:
    free_disk_required_mb: int = 0  # set per-extension via manifest
    healthcheck_timeout_seconds: float = 5.0
    project_prefix: str = "vantage"


class ExtensionManager:
    def __init__(
        self,
        *,
        db,
        registry: ExtensionRegistry,
        docker: DockerProxyClient,
        config: ManagerConfig | None = None,
    ):
        self._db = db
        self._registry = registry
        self._docker = docker
        self._config = config or ManagerConfig()

    # ── state helpers ──────────────────────────────────────────────

    async def _state(self, ext_id: str) -> dict[str, Any]:
        if self._db is None:
            return {"_id": ext_id, "status": ExtensionStatus.NOT_INSTALLED.value}
        doc = await self._db.extensions_state.find_one({"_id": ext_id})
        if doc:
            return doc
        return {"_id": ext_id, "status": ExtensionStatus.NOT_INSTALLED.value}

    async def _set_status(
        self, ext_id: str, status: ExtensionStatus, **patch: Any
    ) -> None:
        if self._db is None:
            return
        update = {"status": status.value, **patch}
        await self._db.extensions_state.update_one(
            {"_id": ext_id}, {"$set": update}, upsert=True
        )

    async def _try_acquire_lock(
        self, ext_id: str, action: str, user: str
    ) -> bool:
        """Atomic Mongo `$exists` guard. Returns True if we got the lock,
        False if someone else already holds it."""
        if self._db is None:
            return True
        now = datetime.now(timezone.utc)
        result = await self._db.extensions_state.update_one(
            {
                "_id": ext_id,
                "$or": [{"locked_by": None}, {"locked_by": {"$exists": False}}],
            },
            {
                "$set": {
                    "locked_by": {"action": action, "user": user, "started_at": now}
                }
            },
            upsert=True,
        )
        return result.modified_count == 1 or result.upserted_id is not None

    async def _release_lock(self, ext_id: str) -> None:
        if self._db is None:
            return
        await self._db.extensions_state.update_one(
            {"_id": ext_id}, {"$set": {"locked_by": None}}
        )

    async def current_lock(self, ext_id: str) -> dict | None:
        """Used by routers/extensions.py to format the 409 response."""
        st = await self._state(ext_id)
        return st.get("locked_by")

    # ── catalog view ───────────────────────────────────────────────

    async def list(self) -> list[dict]:
        """Catalog snapshot consumed by `GET /api/extensions`."""
        out = []
        for entry in self._registry.list():
            state = await self._state(entry.extension_id)
            out.append(self._render(entry, state))
        return out

    async def get(self, ext_id: str) -> dict | None:
        entry = self._registry.get(ext_id)
        if not entry:
            return None
        state = await self._state(ext_id)
        return self._render(entry, state)

    def _render(self, entry: RegistryEntry, state: dict) -> dict:
        return {
            "id": entry.extension_id,
            "name": entry.manifest.name,
            "description": entry.manifest.description,
            "version": entry.manifest.version,
            "status": state.get("status", ExtensionStatus.NOT_INSTALLED.value),
            "installed_at": state.get("installed_at"),
            "last_health_ts": state.get("last_health_ts"),
            "last_error": state.get("last_error"),
            "settings": state.get("settings", {}),
            "operations": entry.manifest.operations,
            "requires": entry.manifest.requires.model_dump(),
            "settings_schema": [s.model_dump() for s in entry.manifest.settings],
            "uninstall": entry.manifest.uninstall.model_dump(),
            "locked_by": state.get("locked_by"),
        }

    # ── pre-flight ─────────────────────────────────────────────────

    async def preflight(self, manifest: Manifest) -> None:
        """Raises PreflightError if the host can't host this extension."""
        if manifest.requires.docker_socket_proxy:
            ok = await self._docker.ping()
            if not ok:
                raise PreflightError("docker-socket-proxy is unreachable")
        # Disk + ports could be checked here; for the MVP we only enforce
        # the proxy reachability since it's the deal-breaker.

    # ── lifecycle ──────────────────────────────────────────────────

    async def install(self, ext_id: str, *, user: str) -> None:
        entry = self._require(ext_id)
        await self._guard_action(ext_id, "install")
        if not await self._try_acquire_lock(ext_id, "install", user):
            raise LifecycleError("another install operation is already running")
        try:
            await self._set_status(ext_id, ExtensionStatus.INSTALLING, last_error=None)
            await self.preflight(entry.manifest)
            # Validate compose YAML before touching anything.
            try:
                await self._docker.compose_config(str(entry.compose_path))
            except DockerProxyError as e:
                raise PreflightError(f"compose config dry-run failed: {e}") from e
            # Generate + persist secrets if they aren't there yet.
            await self._ensure_secrets(entry)
            # Hand off to docker compose up via the proxy.
            project = self._project_name(ext_id)
            try:
                await self._docker.compose_up(str(entry.compose_path), project)
            except DockerProxyError as e:
                await self._set_status(
                    ext_id,
                    ExtensionStatus.INSTALLING_FAILED,
                    last_error=str(e),
                )
                raise LifecycleError(f"compose up failed: {e}") from e
            await self._set_status(
                ext_id,
                ExtensionStatus.INSTALLED_HEALTHY,
                installed_at=datetime.now(timezone.utc),
                version=entry.manifest.version,
            )
        finally:
            await self._release_lock(ext_id)

    async def start(self, ext_id: str, *, user: str) -> None:
        entry = self._require(ext_id)
        await self._guard_action(ext_id, "start")
        if not await self._try_acquire_lock(ext_id, "start", user):
            raise LifecycleError("locked")
        try:
            project = self._project_name(ext_id)
            await self._docker.compose_start(str(entry.compose_path), project)
            await self._set_status(ext_id, ExtensionStatus.INSTALLED_HEALTHY)
        finally:
            await self._release_lock(ext_id)

    async def stop(self, ext_id: str, *, user: str) -> None:
        entry = self._require(ext_id)
        await self._guard_action(ext_id, "stop")
        if not await self._try_acquire_lock(ext_id, "stop", user):
            raise LifecycleError("locked")
        try:
            project = self._project_name(ext_id)
            await self._docker.compose_stop(str(entry.compose_path), project)
            await self._set_status(ext_id, ExtensionStatus.STOPPED)
        finally:
            await self._release_lock(ext_id)

    async def restart(self, ext_id: str, *, user: str) -> None:
        entry = self._require(ext_id)
        await self._guard_action(ext_id, "restart")
        if not await self._try_acquire_lock(ext_id, "restart", user):
            raise LifecycleError("locked")
        try:
            project = self._project_name(ext_id)
            await self._docker.compose_restart(str(entry.compose_path), project)
            await self._set_status(ext_id, ExtensionStatus.INSTALLED_HEALTHY)
        finally:
            await self._release_lock(ext_id)

    async def uninstall(
        self,
        ext_id: str,
        *,
        user: str,
        confirm_phrase: str,
        destroy_volumes: bool | None = None,
    ) -> None:
        entry = self._require(ext_id)
        if confirm_phrase != entry.manifest.uninstall.confirm_phrase:
            raise LifecycleError("confirm_phrase did not match manifest value")
        await self._guard_action(ext_id, "uninstall")
        if not await self._try_acquire_lock(ext_id, "uninstall", user):
            raise LifecycleError("locked")
        try:
            await self._set_status(ext_id, ExtensionStatus.UNINSTALLING)
            project = self._project_name(ext_id)
            destroy = (
                entry.manifest.uninstall.destroy_volumes_by_default
                if destroy_volumes is None
                else destroy_volumes
            )
            await self._docker.compose_down(
                str(entry.compose_path), project, remove_volumes=destroy
            )
            # Forget secrets — we'll regenerate on the next install.
            if self._db is not None:
                await self._db.extensions_secrets.delete_many({"ext_id": ext_id})
                await self._db.extensions_state.delete_one({"_id": ext_id})
        finally:
            await self._release_lock(ext_id)

    # ── settings + secrets ─────────────────────────────────────────

    async def patch_settings(
        self, ext_id: str, *, settings_patch: dict[str, Any], user: str
    ) -> dict:
        entry = self._require(ext_id)
        # Only known keys with the right type can be set.
        allowed = {s.key: s for s in entry.manifest.settings}
        validated: dict[str, Any] = {}
        for k, v in settings_patch.items():
            if k not in allowed:
                raise LifecycleError(f"unknown setting '{k}'")
            decl = allowed[k]
            if decl.type == "boolean" and not isinstance(v, bool):
                raise LifecycleError(f"setting '{k}' must be boolean")
            if decl.type == "integer" and not isinstance(v, int):
                raise LifecycleError(f"setting '{k}' must be integer")
            if decl.type == "string" and not isinstance(v, str):
                raise LifecycleError(f"setting '{k}' must be string")
            validated[k] = v
        if self._db is not None:
            await self._db.extensions_state.update_one(
                {"_id": ext_id},
                {"$set": {f"settings.{k}": v for k, v in validated.items()}},
                upsert=True,
            )
        # Note: caller decides whether to restart the extension to pick up the change.
        return validated

    async def rotate_secret(self, ext_id: str, secret_name: str, *, user: str) -> None:
        entry = self._require(ext_id)
        match = next(
            (s for s in entry.manifest.secrets if s.name == secret_name), None
        )
        if match is None:
            raise LifecycleError(f"secret '{secret_name}' not declared in manifest")
        new_value = _generate_secret(match.generator, match.length)
        if self._db is not None:
            now = datetime.now(timezone.utc)
            await self._db.extensions_secrets.update_one(
                {"_id": f"{ext_id}:{secret_name}"},
                {
                    "$set": {
                        "ext_id": ext_id,
                        "name": secret_name,
                        "value": new_value,
                        "rotated_at": now,
                    }
                },
                upsert=True,
            )

    async def _ensure_secrets(self, entry: RegistryEntry) -> None:
        if self._db is None or not entry.manifest.secrets:
            return
        existing = {
            doc["name"]
            async for doc in self._db.extensions_secrets.find(
                {"ext_id": entry.extension_id}, {"name": 1}
            )
        }
        for spec in entry.manifest.secrets:
            if spec.name in existing:
                continue
            value = _generate_secret(spec.generator, spec.length)
            await self._db.extensions_secrets.insert_one(
                {
                    "_id": f"{entry.extension_id}:{spec.name}",
                    "ext_id": entry.extension_id,
                    "name": spec.name,
                    "value": value,
                    "rotated_at": datetime.now(timezone.utc),
                }
            )
        # Record presence (NOT the value) on the state doc so the
        # admin UI can show "✓ provisioned" without exposing the secret.
        await self._db.extensions_state.update_one(
            {"_id": entry.extension_id},
            {"$set": {"secrets_present": [s.name for s in entry.manifest.secrets]}},
            upsert=True,
        )

    # ── health ─────────────────────────────────────────────────────

    async def healthcheck(self, ext_id: str) -> bool:
        """Calls the manifest's `health.url` and updates state. Used by
        the routers' status endpoint and by the boot reconciler."""
        entry = self._require(ext_id)
        h = entry.manifest.health
        timeout = httpx.Timeout(h.timeout_seconds)
        try:
            async with httpx.AsyncClient(timeout=timeout) as client:
                resp = await client.get(h.url)
            ok = 200 <= resp.status_code < 300
        except httpx.HTTPError:
            ok = False
        await self._set_status(
            ext_id,
            ExtensionStatus.INSTALLED_HEALTHY if ok else ExtensionStatus.INSTALLED_UNHEALTHY,
            last_health_ts=datetime.now(timezone.utc),
        )
        return ok

    async def reconcile(self) -> None:
        """Boot-time scan: walk extensions in state, verify their
        containers exist, sync status. PRD §Extensions Platform:
        'Reconcilia estado no boot'."""
        if self._db is None:
            return
        async for state in self._db.extensions_state.find(
            {
                "status": {
                    "$in": [
                        ExtensionStatus.INSTALLED_HEALTHY.value,
                        ExtensionStatus.INSTALLED_UNHEALTHY.value,
                    ]
                }
            }
        ):
            ext_id = state["_id"]
            entry = self._registry.get(ext_id)
            if not entry:
                continue
            try:
                await self.healthcheck(ext_id)
            except Exception:
                logger.exception("reconcile healthcheck failed for %s", ext_id)

    # ── helpers ────────────────────────────────────────────────────

    def _require(self, ext_id: str) -> RegistryEntry:
        entry = self._registry.get(ext_id)
        if not entry:
            raise LifecycleError(f"unknown extension '{ext_id}'")
        return entry

    async def _guard_action(self, ext_id: str, action: str) -> None:
        state = await self._state(ext_id)
        status = ExtensionStatus(state.get("status", ExtensionStatus.NOT_INSTALLED.value))
        if status not in _ACTIONABLE[action]:
            raise LifecycleError(
                f"action '{action}' not allowed in status '{status.value}'"
            )

    def _project_name(self, ext_id: str) -> str:
        return f"{self._config.project_prefix}_{ext_id}"


# Re-exported for convenience in __init__.py
__all__ = [
    "ExtensionManager",
    "ExtensionStatus",
    "LifecycleError",
    "PreflightError",
    "ManagerConfig",
]
