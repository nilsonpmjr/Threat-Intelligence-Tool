"""Manifest parser — strict pydantic validation of every extension's
`manifest.yaml` against the schema declared in PRD §Extensions Platform
(socc-copilot-plugin.md, lines 212-247).

PRD §Risks: "Extensão maliciosa consegue escapar via manifest injection
(Baixa/Crítico)" — mitigation says "Manifests são arquivos do repo, não
upload via UI. Parser valida contra schema estrito (zod-equiv em
pydantic)". This module IS that parser.

We deliberately reject unknown fields and refuse to expand env vars
beyond what's listed in `secrets[]` and `settings[]`. No path
traversal, no shell, no host mounts.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field, field_validator


# ── component schemas ────────────────────────────────────────────────


class HealthSpec(BaseModel):
    model_config = ConfigDict(extra="forbid")

    url: str
    interval_seconds: int = Field(ge=1, le=600)
    timeout_seconds: int = Field(ge=1, le=60)


class SecretSpec(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str = Field(pattern=r"^[A-Z_][A-Z0-9_]*$")  # POSIX env-var convention
    generator: Literal["random_bytes_base64", "random_bytes_hex"]
    length: int = Field(ge=8, le=64)


class RequiresSpec(BaseModel):
    model_config = ConfigDict(extra="forbid")

    docker_socket_proxy: bool = False
    disk_space_mb: int = Field(default=0, ge=0)
    ports: list[int] = Field(default_factory=list)


class SettingSpec(BaseModel):
    model_config = ConfigDict(extra="forbid")

    key: str = Field(pattern=r"^[A-Z_][A-Z0-9_]*$")
    type: Literal["boolean", "string", "integer"]
    default: Any
    label: str = Field(min_length=1, max_length=120)


class UninstallSpec(BaseModel):
    model_config = ConfigDict(extra="forbid")

    destroy_volumes_by_default: bool
    confirm_phrase: str = Field(min_length=1, max_length=120)


# ── full manifest ────────────────────────────────────────────────────


VALID_OPERATIONS = ("install", "start", "stop", "restart", "logs", "uninstall")


class Manifest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str = Field(pattern=r"^[a-z][a-z0-9_-]{0,30}[a-z0-9]$")
    name: str = Field(min_length=1, max_length=80)
    description: str = Field(min_length=1, max_length=500)
    version: str = Field(pattern=r"^\d+\.\d+\.\d+([-+].+)?$")
    compose_file: str
    operations: list[str]
    health: HealthSpec
    secrets: list[SecretSpec] = Field(default_factory=list)
    requires: RequiresSpec
    settings: list[SettingSpec] = Field(default_factory=list)
    uninstall: UninstallSpec

    @field_validator("operations")
    @classmethod
    def _ops_subset(cls, v: list[str]) -> list[str]:
        for op in v:
            if op not in VALID_OPERATIONS:
                raise ValueError(
                    f"unknown operation '{op}'; must be one of {VALID_OPERATIONS}"
                )
        if not v:
            raise ValueError("operations[] cannot be empty")
        if len(set(v)) != len(v):
            raise ValueError("operations[] contains duplicates")
        return v

    @field_validator("compose_file")
    @classmethod
    def _no_traversal(cls, v: str) -> str:
        # PRD §Risks: deny anything that could read outside the
        # extension's own folder.
        if v.startswith("/") or ".." in v.split("/"):
            raise ValueError("compose_file must be a relative path inside the extension")
        return v

    @field_validator("secrets")
    @classmethod
    def _unique_secret_names(cls, v: list[SecretSpec]) -> list[SecretSpec]:
        names = [s.name for s in v]
        if len(set(names)) != len(names):
            raise ValueError("secrets[].name must be unique")
        return v

    @field_validator("settings")
    @classmethod
    def _unique_setting_keys(cls, v: list[SettingSpec]) -> list[SettingSpec]:
        keys = [s.key for s in v]
        if len(set(keys)) != len(keys):
            raise ValueError("settings[].key must be unique")
        return v


# ── public errors + entry point ──────────────────────────────────────


class ManifestError(ValueError):
    """Raised when a manifest is unreadable, malformed, or invalid."""


def parse_manifest(path: str | Path) -> Manifest:
    """Read + validate a manifest.yaml. Raises ManifestError on any
    problem; never returns a partially-valid manifest."""
    p = Path(path)
    if not p.is_file():
        raise ManifestError(f"manifest not found: {p}")
    try:
        with p.open("r", encoding="utf-8") as f:
            raw = yaml.safe_load(f)
    except yaml.YAMLError as e:
        raise ManifestError(f"invalid YAML in {p}: {e}") from e
    if not isinstance(raw, dict):
        raise ManifestError(f"manifest root must be a mapping; got {type(raw).__name__}")
    try:
        return Manifest.model_validate(raw)
    except Exception as e:
        raise ManifestError(f"manifest validation failed for {p}: {e}") from e
