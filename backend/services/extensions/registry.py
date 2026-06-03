"""Extension registry — discovers and validates extensions on disk.

Each extension lives in `backend/extensions/<id>/` with at least:
  - manifest.yaml
  - compose.yml (or whatever the manifest's compose_file points to)

The registry is populated lazily at boot; reload() re-reads the disk.
Manifest parse errors are isolated per-extension — one bad manifest
doesn't break the whole catalog.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from pathlib import Path

from .manifest import Manifest, ManifestError, parse_manifest

logger = logging.getLogger("extensions.registry")

# Skip these subdirs — they predate the v1 manifest schema and use the
# in-process Python plugin model from the legacy extensions system.
LEGACY_DIRS = {"plugins", "local_plugins", "premium_plugins", "__pycache__"}


@dataclass(frozen=True)
class RegistryEntry:
    """One extension found on disk."""

    extension_id: str
    root: Path
    manifest: Manifest

    @property
    def compose_path(self) -> Path:
        return (self.root / self.manifest.compose_file).resolve()


class ExtensionRegistry:
    def __init__(self, extensions_root: Path):
        self._root = extensions_root
        self._entries: dict[str, RegistryEntry] = {}
        self._errors: dict[str, str] = {}

    @property
    def extensions_root(self) -> Path:
        return self._root

    def reload(self) -> None:
        """Rescan the extensions directory. Idempotent."""
        self._entries.clear()
        self._errors.clear()
        if not self._root.is_dir():
            logger.warning("extensions root does not exist: %s", self._root)
            return
        for child in sorted(self._root.iterdir()):
            if not child.is_dir():
                continue
            if child.name in LEGACY_DIRS or child.name.startswith("."):
                continue
            manifest_path = child / "manifest.yaml"
            if not manifest_path.is_file():
                # Silently skip — a directory without a manifest isn't an
                # extension by this schema. Could be README-only, etc.
                continue
            try:
                manifest = parse_manifest(manifest_path)
            except ManifestError as e:
                self._errors[child.name] = str(e)
                logger.error("failed to load manifest for %s: %s", child.name, e)
                continue
            if manifest.id != child.name:
                self._errors[child.name] = (
                    f"manifest.id={manifest.id!r} does not match directory name={child.name!r}"
                )
                logger.error(self._errors[child.name])
                continue
            entry = RegistryEntry(
                extension_id=manifest.id, root=child.resolve(), manifest=manifest
            )
            self._entries[manifest.id] = entry
            logger.info("loaded extension %s v%s", manifest.id, manifest.version)

    def list(self) -> list[RegistryEntry]:
        return list(self._entries.values())

    def get(self, extension_id: str) -> RegistryEntry | None:
        return self._entries.get(extension_id)

    def errors(self) -> dict[str, str]:
        """Per-directory parse failures from the last reload(). Surfaced
        in the admin UI so a malformed manifest doesn't disappear silently."""
        return dict(self._errors)
