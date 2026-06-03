"""Vantage Extensions Platform — generic install/lifecycle for any
declarative extension (PRD §Extensions Platform, Fase 4).

Public surface re-exported here so callers don't need to know which
sub-module owns what.
"""

from .manifest import (
    Manifest,
    ManifestError,
    HealthSpec,
    SecretSpec,
    SettingSpec,
    UninstallSpec,
    parse_manifest,
)
from .registry import ExtensionRegistry, RegistryEntry
from .docker_client import DockerProxyClient, DockerProxyError
from .manager import (
    ExtensionManager,
    ExtensionStatus,
    LifecycleError,
    PreflightError,
)

__all__ = [
    "Manifest",
    "ManifestError",
    "HealthSpec",
    "SecretSpec",
    "SettingSpec",
    "UninstallSpec",
    "parse_manifest",
    "ExtensionRegistry",
    "RegistryEntry",
    "DockerProxyClient",
    "DockerProxyError",
    "ExtensionManager",
    "ExtensionStatus",
    "LifecycleError",
    "PreflightError",
]
