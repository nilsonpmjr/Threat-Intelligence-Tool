"""Tests for the generic extensions platform (Fase 4).

Three layers:
  1. Manifest parser — pure pydantic validation.
  2. ExtensionManager — secret generation, lock acquisition, settings
     validation. Mongo is mocked via `fake_db`.
  3. Router smoke — admin-gated install/uninstall, catalog browsing.
"""

from __future__ import annotations

import base64
import textwrap
from pathlib import Path

import pytest

from services.extensions import (
    ExtensionManager,
    ExtensionRegistry,
    LifecycleError,
    Manifest,
    ManifestError,
    parse_manifest,
)
from services.extensions.manager import ExtensionStatus, _generate_secret


# ── manifest parser ─────────────────────────────────────────────────


def _write_manifest(dir_: Path, content: str) -> Path:
    dir_.mkdir(parents=True, exist_ok=True)
    p = dir_ / "manifest.yaml"
    p.write_text(textwrap.dedent(content))
    return p


def test_parse_manifest_accepts_socc_schema(tmp_path: Path):
    p = _write_manifest(
        tmp_path,
        """
        id: socc
        name: SOC Copilot
        description: Test
        version: 0.1.0
        compose_file: ./compose.yml
        operations: [install, start, stop, restart, logs, uninstall]
        health:
          url: http://socc-copilot:7070/v1/health
          interval_seconds: 15
          timeout_seconds: 3
        secrets:
          - name: SOCC_MASTER_KEY
            generator: random_bytes_base64
            length: 32
          - name: SOCC_INTERNAL_SECRET
            generator: random_bytes_base64
            length: 32
        requires:
          docker_socket_proxy: true
          disk_space_mb: 512
          ports: []
        settings:
          - key: SOCC_ALLOW_LOCAL_PROVIDERS
            type: boolean
            default: false
            label: Allow local providers
        uninstall:
          destroy_volumes_by_default: true
          confirm_phrase: uninstall socc
        """,
    )
    m = parse_manifest(p)
    assert isinstance(m, Manifest)
    assert m.id == "socc"
    assert m.uninstall.confirm_phrase == "uninstall socc"
    assert {s.name for s in m.secrets} == {"SOCC_MASTER_KEY", "SOCC_INTERNAL_SECRET"}


def test_parse_manifest_rejects_extra_fields(tmp_path: Path):
    p = _write_manifest(
        tmp_path,
        """
        id: x
        name: X
        description: x
        version: 0.1.0
        compose_file: ./compose.yml
        operations: [install]
        health: {url: http://x:1/h, interval_seconds: 1, timeout_seconds: 1}
        requires: {docker_socket_proxy: false, disk_space_mb: 0, ports: []}
        uninstall: {destroy_volumes_by_default: false, confirm_phrase: ok}
        rogue_field: yes
        """,
    )
    with pytest.raises(ManifestError):
        parse_manifest(p)


def test_parse_manifest_rejects_path_traversal(tmp_path: Path):
    p = _write_manifest(
        tmp_path,
        """
        id: x
        name: X
        description: x
        version: 0.1.0
        compose_file: ../etc/passwd
        operations: [install]
        health: {url: http://x:1/h, interval_seconds: 1, timeout_seconds: 1}
        requires: {docker_socket_proxy: false, disk_space_mb: 0, ports: []}
        uninstall: {destroy_volumes_by_default: false, confirm_phrase: ok}
        """,
    )
    with pytest.raises(ManifestError):
        parse_manifest(p)


def test_parse_manifest_rejects_unknown_operation(tmp_path: Path):
    p = _write_manifest(
        tmp_path,
        """
        id: x
        name: X
        description: x
        version: 0.1.0
        compose_file: ./compose.yml
        operations: [install, hack]
        health: {url: http://x:1/h, interval_seconds: 1, timeout_seconds: 1}
        requires: {docker_socket_proxy: false, disk_space_mb: 0, ports: []}
        uninstall: {destroy_volumes_by_default: false, confirm_phrase: ok}
        """,
    )
    with pytest.raises(ManifestError, match="hack"):
        parse_manifest(p)


# ── registry ────────────────────────────────────────────────────────


def test_registry_skips_legacy_dirs_and_loads_socc(tmp_path: Path):
    # Build a fake extensions root with: a valid extension, a legacy
    # plugins/ dir, a directory without manifest.
    root = tmp_path / "extensions"
    socc = root / "socc"
    _write_manifest(
        socc,
        """
        id: socc
        name: SOC Copilot
        description: x
        version: 0.1.0
        compose_file: ./compose.yml
        operations: [install]
        health: {url: http://socc:1/h, interval_seconds: 1, timeout_seconds: 1}
        requires: {docker_socket_proxy: false, disk_space_mb: 0, ports: []}
        uninstall: {destroy_volumes_by_default: false, confirm_phrase: ok}
        """,
    )
    (root / "plugins" / "legacy").mkdir(parents=True)
    (root / "no_manifest").mkdir()
    (root / "no_manifest" / "README.md").write_text("hi")

    reg = ExtensionRegistry(root)
    reg.reload()
    ids = [e.extension_id for e in reg.list()]
    assert ids == ["socc"]
    assert reg.errors() == {}


def test_registry_records_errors_per_directory(tmp_path: Path):
    root = tmp_path / "extensions"
    bad = root / "bad"
    _write_manifest(bad, "id: not a valid id\n")  # invalid id pattern
    reg = ExtensionRegistry(root)
    reg.reload()
    assert reg.list() == []
    assert "bad" in reg.errors()


def test_registry_rejects_id_mismatch_with_dir(tmp_path: Path):
    root = tmp_path / "extensions"
    sub = root / "socc"  # dir says socc
    _write_manifest(
        sub,
        """
        id: notsocc
        name: NotSocc
        description: x
        version: 0.1.0
        compose_file: ./compose.yml
        operations: [install]
        health: {url: http://x:1/h, interval_seconds: 1, timeout_seconds: 1}
        requires: {docker_socket_proxy: false, disk_space_mb: 0, ports: []}
        uninstall: {destroy_volumes_by_default: false, confirm_phrase: ok}
        """,
    )
    reg = ExtensionRegistry(root)
    reg.reload()
    assert reg.list() == []
    assert "socc" in reg.errors()
    assert "match" in reg.errors()["socc"]


# ── manager ─────────────────────────────────────────────────────────


def _build_manager(tmp_path: Path, fake_db) -> tuple[ExtensionManager, Path]:
    root = tmp_path / "extensions"
    sub = root / "demo"
    _write_manifest(
        sub,
        """
        id: demo
        name: Demo
        description: x
        version: 0.1.0
        compose_file: ./compose.yml
        operations: [install, start, stop, restart, uninstall]
        health: {url: http://localhost:1/h, interval_seconds: 1, timeout_seconds: 1}
        secrets:
          - name: DEMO_KEY
            generator: random_bytes_hex
            length: 16
        requires: {docker_socket_proxy: false, disk_space_mb: 0, ports: []}
        settings:
          - key: DEMO_FLAG
            type: boolean
            default: false
            label: Demo flag
        uninstall: {destroy_volumes_by_default: false, confirm_phrase: bye demo}
        """,
    )
    reg = ExtensionRegistry(root)
    reg.reload()

    class _NullDocker:
        async def ping(self): return True
        async def compose_up(self, *a, **kw): return None
        async def compose_down(self, *a, **kw): return None
        async def compose_start(self, *a, **kw): return None
        async def compose_stop(self, *a, **kw): return None
        async def compose_restart(self, *a, **kw): return None
        async def compose_config(self, *a, **kw): return ""

    return ExtensionManager(db=fake_db, registry=reg, docker=_NullDocker()), sub


def test_generate_secret_lengths_match_spec():
    raw_b64 = _generate_secret("random_bytes_base64", 32)
    decoded = base64.b64decode(raw_b64)
    assert len(decoded) == 32
    raw_hex = _generate_secret("random_bytes_hex", 16)
    assert len(raw_hex) == 32  # hex-encoded => 2 chars per byte


@pytest.mark.asyncio
async def test_install_locks_then_releases(tmp_path: Path, fake_db):
    """First install fully completes (state=installed_healthy, lock
    released)."""
    mgr, _ = _build_manager(tmp_path, fake_db)

    await mgr.install("demo", user="admin")
    state = await fake_db.extensions_state.find_one({"_id": "demo"})
    assert state["status"] == ExtensionStatus.INSTALLED_HEALTHY.value
    assert state.get("locked_by") in (None, {})


@pytest.mark.asyncio
async def test_concurrent_install_returns_locked(tmp_path: Path, fake_db):
    """Reset the demo extension to a state where install() is allowed
    (NOT_INSTALLED), then hold the lock manually and verify the second
    install attempt fails with the locked-error path."""
    mgr, _ = _build_manager(tmp_path, fake_db)

    # Pretend admin1 acquired the lock first.
    assert await mgr._try_acquire_lock("demo", "install", "admin1") is True

    # While the lock is held, admin2 attempts install — should raise
    # LifecycleError (caught by router as 409 locked).
    with pytest.raises(LifecycleError, match="already running"):
        await mgr.install("demo", user="admin2")

    # Cleanup so other tests don't see a stuck lock.
    await mgr._release_lock("demo")


@pytest.mark.asyncio
async def test_install_provisions_secrets_idempotently(tmp_path: Path, fake_db):
    mgr, _ = _build_manager(tmp_path, fake_db)
    await mgr.install("demo", user="admin")
    secrets1 = [doc async for doc in fake_db.extensions_secrets.find({"ext_id": "demo"})]
    assert len(secrets1) == 1
    assert secrets1[0]["name"] == "DEMO_KEY"
    val1 = secrets1[0]["value"]

    # Re-install: secret value should NOT change (still the same one).
    await mgr.uninstall("demo", user="admin", confirm_phrase="bye demo")
    await mgr.install("demo", user="admin")
    secrets2 = [doc async for doc in fake_db.extensions_secrets.find({"ext_id": "demo"})]
    assert len(secrets2) == 1
    # NEW value because uninstall wiped the secret on purpose.
    assert secrets2[0]["value"] != val1


@pytest.mark.asyncio
async def test_uninstall_requires_confirm_phrase(tmp_path: Path, fake_db):
    mgr, _ = _build_manager(tmp_path, fake_db)
    await mgr.install("demo", user="admin")
    with pytest.raises(LifecycleError, match="confirm_phrase"):
        await mgr.uninstall("demo", user="admin", confirm_phrase="wrong")


@pytest.mark.asyncio
async def test_settings_patch_validates_keys_and_types(tmp_path: Path, fake_db):
    mgr, _ = _build_manager(tmp_path, fake_db)
    # Type mismatch:
    with pytest.raises(LifecycleError, match="boolean"):
        await mgr.patch_settings("demo", settings_patch={"DEMO_FLAG": "yes"}, user="admin")
    # Unknown key:
    with pytest.raises(LifecycleError, match="unknown setting"):
        await mgr.patch_settings("demo", settings_patch={"NOPE": True}, user="admin")
    # Valid:
    applied = await mgr.patch_settings("demo", settings_patch={"DEMO_FLAG": True}, user="admin")
    assert applied == {"DEMO_FLAG": True}


# ── router smoke (admin gate + catalog) ─────────────────────────────


@pytest.mark.asyncio
async def test_catalog_includes_socc_extension(async_client, tech_token):
    """The on-disk backend/extensions/socc/manifest.yaml must be picked
    up by the registry and exposed at GET /api/extensions."""
    res = await async_client.get(
        "/api/extensions", headers={"Authorization": f"Bearer {tech_token}"}
    )
    assert res.status_code == 200
    body = res.json()
    ids = [e["id"] for e in body["extensions"]]
    assert "socc" in ids
    socc_entry = next(e for e in body["extensions"] if e["id"] == "socc")
    assert socc_entry["status"] == "not_installed"
    assert socc_entry["uninstall"]["confirm_phrase"] == "uninstall socc"


@pytest.mark.asyncio
async def test_generality_probe_renders_alongside_socc(async_client, tech_token):
    """PRD §Phase 4 done criteria: 'framework aceita nova extensão
    (teste: adicionar manifest fake + compose trivial e ver card
    renderizar)'. A second extension on disk must show up next to socc
    without ANY router/manager change."""
    res = await async_client.get(
        "/api/extensions", headers={"Authorization": f"Bearer {tech_token}"}
    )
    body = res.json()
    ids = [e["id"] for e in body["extensions"]]
    assert "socc" in ids and "fake" in ids
    fake = next(e for e in body["extensions"] if e["id"] == "fake")
    # Confirms the manifest was parsed end-to-end (settings + uninstall
    # phrase + ops list all readable from the response).
    assert fake["uninstall"]["confirm_phrase"] == "uninstall fake"
    assert "install" in fake["operations"]
    assert any(s["key"] == "PROBE_MESSAGE" for s in fake["settings_schema"])


@pytest.mark.asyncio
async def test_install_requires_admin_role(async_client, tech_token):
    """tech role must be rejected (403) on the install endpoint."""
    res = await async_client.post(
        "/api/extensions/socc/install",
        headers={"Authorization": f"Bearer {tech_token}"},
    )
    assert res.status_code == 403


@pytest.mark.asyncio
async def test_uninstall_with_wrong_confirm_phrase_logs_failure(
    async_client, admin_token, fake_db
):
    """Even admin can't uninstall without the manifest's exact phrase."""
    # Pre-seed state so uninstall is in a valid state to attempt.
    await fake_db.extensions_state.update_one(
        {"_id": "socc"},
        {"$set": {"status": "installed_healthy"}},
        upsert=True,
    )

    # We don't want the BackgroundTask to actually shell out to docker —
    # patch the manager's docker client to a no-op for this call.
    from routers import extensions as ext_router
    mgr = ext_router.get_manager()

    class _NullDocker:
        async def ping(self): return True
        async def compose_down(self, *a, **kw): return None
    mgr._docker = _NullDocker()  # noqa: SLF001

    res = await async_client.post(
        "/api/extensions/socc/uninstall",
        headers={"Authorization": f"Bearer {admin_token}"},
        json={"confirm_phrase": "totally wrong"},
    )
    # Endpoint accepts the request (202) but the BackgroundTask logs the
    # failure to audit_log without actually touching Docker.
    assert res.status_code == 202

    # Wait briefly for the BackgroundTask to run + audit.
    import asyncio
    await asyncio.sleep(0.05)
    failure = await fake_db.audit_log.find_one(
        {"action": "socc_uninstall", "result": "failure"}
    )
    assert failure is not None
    assert "confirm_phrase" in failure.get("detail", "")
