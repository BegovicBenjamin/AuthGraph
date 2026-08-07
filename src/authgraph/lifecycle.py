"""Fail-closed vault lifecycle state shared by session brokers."""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import Protocol, runtime_checkable


class VaultLifecyclePhase(StrEnum):
    """Admission state for one principal-owned vault."""

    ACTIVE = "ACTIVE"
    REVISION_PENDING = "REVISION_PENDING"
    BLOCKED = "BLOCKED"


@dataclass(frozen=True, slots=True)
class VaultLifecycleState:
    principal_id: str
    vault_id: str
    phase: VaultLifecyclePhase
    current_revision: int
    next_revision: int | None
    generation: int


@dataclass(frozen=True, slots=True)
class VaultRevisionTransition:
    """Capability for finalizing one prepared envelope revision change."""

    principal_id: str
    vault_id: str
    current_revision: int
    next_revision: int
    generation: int


@dataclass(frozen=True, slots=True)
class VaultManagementTransition:
    """Capability for finalizing one management/revocation transition."""

    principal_id: str
    vault_id: str
    envelope_revision: int
    generation: int


@runtime_checkable
class VaultGuard(Protocol):
    """A fenced per-vault lifecycle lease."""

    @property
    def principal_id(self) -> str: ...

    @property
    def vault_id(self) -> str: ...

    @property
    def generation(self) -> int: ...

    def renew(self) -> None:
        """Renew the guard or fail if ownership has been lost."""

    def assert_active(self) -> None:
        """Fail if this guard is no longer the current fenced owner."""
