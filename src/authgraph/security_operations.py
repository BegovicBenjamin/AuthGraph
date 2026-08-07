"""Coordinated, audited key-custody lifecycle operations.

Provider revocation alone cannot revoke keys already copied into a session.
This coordinator always revokes the vault's sessions before removing future
provider release capability.  Recovery rewrap consumes a single-use,
policy-bound scope grant and never accepts principal/vault/scope identifiers
from a chatbot argument.
"""

from __future__ import annotations

import unicodedata
from contextlib import AbstractContextManager
from typing import Protocol, runtime_checkable

from .audit import (
    SecurityAuditLogger,
    SecurityEventOutcome,
    SecurityEventType,
)
from .key_custody import EnvelopeScopeKeyProvider, RecoveryRewrapResult
from .lifecycle import (
    VaultGuard,
    VaultLifecycleState,
    VaultManagementTransition,
)
from .unlock_policy import (
    ScopeGrantConsumer,
    ScopeGrantDenied,
    ScopeUnlockGrant,
)


@runtime_checkable
class VaultSessionRevoker(Protocol):
    def vault_guard(
        self,
        principal_id: str,
        vault_id: str,
    ) -> AbstractContextManager[VaultGuard]: ...

    def begin_management_transition(
        self,
        principal_id: str,
        vault_id: str,
        envelope_revision: int,
    ) -> VaultManagementTransition: ...

    def finalize_management_transition(
        self,
        transition: VaultManagementTransition,
    ) -> VaultLifecycleState: ...


class SecurityOperations:
    """Trusted management boundary for revoke, rotate, and recovery."""

    def __init__(
        self,
        sessions: VaultSessionRevoker,
        provider: EnvelopeScopeKeyProvider,
        audit: SecurityAuditLogger,
        *,
        recovery_profile_id: str = "recovery",
    ) -> None:
        if not isinstance(sessions, VaultSessionRevoker):
            raise TypeError("sessions must support vault lifecycle management.")
        if not isinstance(provider, EnvelopeScopeKeyProvider):
            raise TypeError("provider must be an EnvelopeScopeKeyProvider.")
        if not isinstance(audit, SecurityAuditLogger):
            raise TypeError("audit must be a SecurityAuditLogger.")
        if (
            type(recovery_profile_id) is not str
            or not recovery_profile_id
            or len(recovery_profile_id) > 256
            or any(
                unicodedata.category(character).startswith("C")
                for character in recovery_profile_id
            )
        ):
            raise TypeError("recovery_profile_id must be an opaque identifier.")
        self._sessions = sessions
        self._provider = provider
        self._audit = audit
        self._recovery_profile_id = recovery_profile_id

    def revoke_scope_access(
        self,
        principal_id: str,
        vault_id: str,
        scope_ids: tuple[str, ...],
        *,
        envelope_revision: int,
    ) -> int:
        """Revoke current sessions and tombstone future provider releases."""

        if type(envelope_revision) is not int or envelope_revision <= 0:
            raise TypeError("envelope_revision must be a trusted revision.")
        operation = self._audit.prepare_operation(
            SecurityEventType.KEY_REVOKED,
            principal_id=principal_id,
            vault_id=vault_id,
            scope_ids=scope_ids,
        )
        terminal_attempted = False
        try:
            with self._sessions.vault_guard(principal_id, vault_id) as guard:
                guard.assert_active()
                transition = self._sessions.begin_management_transition(
                    principal_id,
                    vault_id,
                    envelope_revision,
                )
                guard.assert_active()
                changed = self._provider.revoke_scope_keys(
                    principal_id=principal_id,
                    vault_id=vault_id,
                    scope_ids=scope_ids,
                )
                guard.assert_active()
                terminal_attempted = True
                self._audit.complete_operation(
                    operation,
                    SecurityEventOutcome.SUCCEEDED,
                    principal_id=principal_id,
                    vault_id=vault_id,
                    scope_ids=scope_ids,
                    metadata={"count": changed},
                )
                self._sessions.finalize_management_transition(transition)
        except Exception:
            if not terminal_attempted:
                self._audit.complete_operation(
                    operation,
                    SecurityEventOutcome.FAILED,
                    principal_id=principal_id,
                    vault_id=vault_id,
                    scope_ids=scope_ids,
                    metadata={"reason_code": "unavailable"},
                )
            raise
        return changed

    def rewrap_provider_keys(
        self,
        principal_id: str,
        vault_id: str,
        scope_ids: tuple[str, ...],
        *,
        envelope_revision: int,
        destination_backend_id: str,
    ) -> int:
        """Rotate the provider KEK generation without changing scope DEKs."""

        if type(envelope_revision) is not int or envelope_revision <= 0:
            raise TypeError("envelope_revision must be a trusted revision.")
        operation = self._audit.prepare_operation(
            SecurityEventType.KEY_REWRAPPED,
            principal_id=principal_id,
            vault_id=vault_id,
            scope_ids=scope_ids,
        )
        terminal_attempted = False
        try:
            with self._sessions.vault_guard(principal_id, vault_id) as guard:
                guard.assert_active()
                transition = self._sessions.begin_management_transition(
                    principal_id,
                    vault_id,
                    envelope_revision,
                )
                guard.assert_active()
                changed = self._provider.rewrap_provider_key(
                    principal_id,
                    vault_id,
                    scope_ids,
                    destination_backend_id=destination_backend_id,
                )
                guard.assert_active()
                terminal_attempted = True
                self._audit.complete_operation(
                    operation,
                    SecurityEventOutcome.SUCCEEDED,
                    principal_id=principal_id,
                    vault_id=vault_id,
                    scope_ids=scope_ids,
                    metadata={"count": changed},
                )
                self._sessions.finalize_management_transition(transition)
        except Exception:
            if not terminal_attempted:
                self._audit.complete_operation(
                    operation,
                    SecurityEventOutcome.FAILED,
                    principal_id=principal_id,
                    vault_id=vault_id,
                    scope_ids=scope_ids,
                    metadata={"reason_code": "unavailable"},
                )
            raise
        return changed

    def recover_provider_keys(
        self,
        grant: ScopeUnlockGrant,
        grant_consumer: ScopeGrantConsumer,
        *,
        destination_backend_id: str,
    ) -> RecoveryRewrapResult:
        """Consume one recovery grant, revoke sessions, and rewrap keys.

        The server-owned recovery profile fixes the vault and scopes.  The
        caller supplies no separate authority identifiers that could diverge
        from the consumed grant.
        """

        if (
            not isinstance(grant, ScopeUnlockGrant)
            or not isinstance(grant_consumer, ScopeGrantConsumer)
            or not grant.scope_ids
            or grant.profile_id != self._recovery_profile_id
        ):
            raise ScopeGrantDenied()
        operation = self._audit.prepare_operation(
            SecurityEventType.KEY_REWRAPPED,
            principal_id=grant.principal_id,
            vault_id=grant.vault_id,
            scope_ids=grant.scope_ids,
            metadata={"recovery_used": True},
        )
        terminal_attempted = False
        try:
            consumed = grant_consumer.consume(grant)
            if (
                not isinstance(consumed, ScopeUnlockGrant)
                or consumed != grant
                or not consumed.scope_ids
                or consumed.profile_id != self._recovery_profile_id
            ):
                raise ScopeGrantDenied()
            with self._sessions.vault_guard(
                consumed.principal_id,
                consumed.vault_id,
            ) as guard:
                guard.assert_active()
                transition = self._sessions.begin_management_transition(
                    consumed.principal_id,
                    consumed.vault_id,
                    consumed.authorization_epoch,
                )
                guard.assert_active()
                result = self._provider.recover_provider_key(
                    consumed.principal_id,
                    consumed.vault_id,
                    consumed.scope_ids,
                    destination_backend_id=destination_backend_id,
                )
                guard.assert_active()
                terminal_attempted = True
                self._audit.complete_operation(
                    operation,
                    SecurityEventOutcome.SUCCEEDED,
                    principal_id=consumed.principal_id,
                    vault_id=consumed.vault_id,
                    scope_ids=consumed.scope_ids,
                    source_ids=tuple(
                        source.audit_source_id() for source in result.sources
                    ),
                    metadata={
                        "count": result.changed_count,
                        "recovery_used": True,
                    },
                )
                self._sessions.finalize_management_transition(transition)
        except Exception:
            if not terminal_attempted:
                self._audit.complete_operation(
                    operation,
                    SecurityEventOutcome.FAILED,
                    principal_id=grant.principal_id,
                    vault_id=grant.vault_id,
                    scope_ids=grant.scope_ids,
                    metadata={
                        "reason_code": "unavailable",
                        "recovery_used": True,
                    },
                )
            raise
        return result
