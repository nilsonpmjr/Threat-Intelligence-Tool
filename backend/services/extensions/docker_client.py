"""Thin async wrapper for talking to the Docker Engine REST API through
the `docker-socket-proxy` sidecar (PRD §Integration Points).

Why httpx instead of docker-py: docker-py opens its own socket; we want
all traffic to go through the ACL-restricted proxy so the host socket
is never directly accessible. Going through HTTP is also simpler to
test (stub the AsyncClient).

This module DOES NOT know what an "extension" is. It speaks Docker
verbs only — `manager.py` glues those into install/start/stop flows.
"""

from __future__ import annotations

import asyncio
import logging
import subprocess
from typing import Any, AsyncIterator

import httpx

logger = logging.getLogger("extensions.docker")


class DockerProxyError(RuntimeError):
    """Raised on transport errors or 4xx/5xx from the proxy. The status
    attribute is None for transport failures."""

    def __init__(self, message: str, status: int | None = None, body: Any = None):
        super().__init__(message)
        self.status = status
        self.body = body


class DockerProxyClient:
    """Async client targeting `tcp://docker-socket-proxy:2375`.

    All public methods raise `DockerProxyError` on any non-2xx response
    so callers don't have to inspect status codes.
    """

    def __init__(
        self,
        base_url: str = "http://docker-socket-proxy:2375",
        timeout_seconds: float = 30.0,
    ):
        self._base = base_url.rstrip("/")
        self._timeout = httpx.Timeout(timeout_seconds, connect=5.0)

    async def _request(
        self, method: str, path: str, *, json: Any = None, params: dict | None = None
    ) -> Any:
        url = f"{self._base}{path}"
        async with httpx.AsyncClient(timeout=self._timeout) as client:
            try:
                resp = await client.request(method, url, json=json, params=params)
            except httpx.HTTPError as e:
                raise DockerProxyError(f"docker proxy unreachable: {e}") from e
        if resp.status_code >= 400:
            try:
                body = resp.json()
            except ValueError:
                body = resp.text
            raise DockerProxyError(
                f"docker proxy {method} {path} -> {resp.status_code}",
                status=resp.status_code,
                body=body,
            )
        if resp.status_code == 204 or not resp.content:
            return None
        try:
            return resp.json()
        except ValueError:
            return resp.text

    # ── liveness ────────────────────────────────────────────────────

    async def ping(self) -> bool:
        """`GET /_ping` returns 'OK' on a healthy daemon."""
        try:
            res = await self._request("GET", "/_ping")
            # _ping returns the literal string "OK"; treat any 2xx as up.
            return res == "OK" or res is None or isinstance(res, str)
        except DockerProxyError:
            return False

    # ── containers ──────────────────────────────────────────────────

    async def list_containers(
        self, *, all_: bool = True, label_filter: str | None = None
    ) -> list[dict]:
        """Returns a list of container summary dicts."""
        params: dict[str, Any] = {"all": "true" if all_ else "false"}
        if label_filter:
            params["filters"] = (
                '{"label":["' + label_filter.replace('"', '\\"') + '"]}'
            )
        return await self._request("GET", "/containers/json", params=params)

    async def inspect_container(self, name_or_id: str) -> dict:
        return await self._request("GET", f"/containers/{name_or_id}/json")

    async def stop_container(self, name_or_id: str, timeout_seconds: int = 10) -> None:
        try:
            await self._request(
                "POST",
                f"/containers/{name_or_id}/stop",
                params={"t": str(timeout_seconds)},
            )
        except DockerProxyError as e:
            # Already-stopped containers return 304 — also OK.
            if e.status == 304:
                return
            raise

    async def remove_container(
        self, name_or_id: str, *, force: bool = False, remove_volumes: bool = False
    ) -> None:
        params = {
            "force": "true" if force else "false",
            "v": "true" if remove_volumes else "false",
        }
        try:
            await self._request(
                "DELETE", f"/containers/{name_or_id}", params=params
            )
        except DockerProxyError as e:
            if e.status == 404:
                return  # idempotent
            raise

    # ── volumes ─────────────────────────────────────────────────────

    async def remove_volume(self, name: str, *, force: bool = False) -> None:
        params = {"force": "true"} if force else None
        try:
            await self._request("DELETE", f"/volumes/{name}", params=params)
        except DockerProxyError as e:
            if e.status == 404:
                return
            raise

    # ── compose orchestration ───────────────────────────────────────
    #
    # docker-socket-proxy exposes the Docker Engine API but NOT a
    # `docker compose up` shortcut — compose is a client-side concept.
    # Two options:
    #
    #   (a) reimplement compose-up in Python by parsing the YAML and
    #       calling /containers/create + /networks/create + /volumes/create
    #       directly. Correct but heavy (init_containers semantics,
    #       depends_on conditions, healthchecks, etc.).
    #   (b) shell out to the `docker` CLI configured to point at the
    #       proxy. Simple and matches the existing ACL.
    #
    # We pick (b) for the MVP. The CLI is already in the backend's image
    # (it's an Alpine slim with `docker:cli`-like tooling); when it isn't,
    # the call surfaces a clear error and the admin can install it.
    #
    # The CLI subprocess respects the proxy by setting `DOCKER_HOST`.

    async def compose_up(self, compose_path: str, project_name: str) -> None:
        await self._compose(["compose", "-p", project_name, "-f", compose_path, "up", "-d"])

    async def compose_down(
        self,
        compose_path: str,
        project_name: str,
        *,
        remove_volumes: bool = False,
    ) -> None:
        cmd = ["compose", "-p", project_name, "-f", compose_path, "down"]
        if remove_volumes:
            cmd.append("-v")
        await self._compose(cmd)

    async def compose_start(self, compose_path: str, project_name: str) -> None:
        await self._compose(["compose", "-p", project_name, "-f", compose_path, "start"])

    async def compose_stop(self, compose_path: str, project_name: str) -> None:
        await self._compose(["compose", "-p", project_name, "-f", compose_path, "stop"])

    async def compose_restart(self, compose_path: str, project_name: str) -> None:
        await self._compose(["compose", "-p", project_name, "-f", compose_path, "restart"])

    async def compose_config(self, compose_path: str) -> str:
        """`docker compose config` — dry-run validation that the YAML is
        well-formed and references resolvable. Used as pre-flight before
        install (PRD §Risks: 'Compose files passam por compose config
        dry-run antes de up')."""
        return await self._compose(
            ["compose", "-f", compose_path, "config"], capture_stdout=True
        )

    async def _compose(self, args: list[str], *, capture_stdout: bool = False) -> str:
        """Run `docker <args>` with DOCKER_HOST pointing at the proxy.

        We use asyncio.create_subprocess_exec so the orchestrator
        doesn't block while compose pulls images / waits on healthchecks.
        """
        env = {"DOCKER_HOST": "tcp://docker-socket-proxy:2375"}
        proc = await asyncio.create_subprocess_exec(
            "docker",
            *args,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env={**__import__("os").environ, **env},
        )
        stdout, stderr = await proc.communicate()
        if proc.returncode != 0:
            raise DockerProxyError(
                f"docker {' '.join(args)} exited {proc.returncode}: "
                f"{stderr.decode(errors='replace').strip()}"
            )
        return stdout.decode(errors="replace") if capture_stdout else ""

    # ── log streaming ───────────────────────────────────────────────

    async def stream_logs(
        self, name_or_id: str, *, tail: int = 100, follow: bool = True
    ) -> AsyncIterator[bytes]:
        """Async iterator of raw log bytes. Used by /api/extensions/:id/logs.

        Docker's log frame format mixes stdout/stderr with a 8-byte header
        per chunk; the SSE handler in routers/extensions.py is responsible
        for stripping the headers if needed. For the MVP we forward as-is
        and let the frontend display raw text.
        """
        params = {
            "stdout": "true",
            "stderr": "true",
            "tail": str(tail),
            "follow": "true" if follow else "false",
            "timestamps": "true",
        }
        url = f"{self._base}/containers/{name_or_id}/logs"
        async with httpx.AsyncClient(
            timeout=httpx.Timeout(None, connect=5.0)
        ) as client:
            async with client.stream("GET", url, params=params) as resp:
                if resp.status_code >= 400:
                    body = await resp.aread()
                    raise DockerProxyError(
                        f"logs stream failed: {resp.status_code}",
                        status=resp.status_code,
                        body=body,
                    )
                async for chunk in resp.aiter_raw():
                    if chunk:
                        yield chunk
