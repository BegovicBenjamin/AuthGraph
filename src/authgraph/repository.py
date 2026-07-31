"""Storage boundary used by the trusted AuthGraph service."""

from __future__ import annotations

from typing import Protocol

from .models import (
    EncryptedEntityRow,
    EncryptedNeighborhoodRow,
    EncryptedRelationshipRow,
    EncryptedVaultSnapshotRow,
    KeyEnvelope,
    ProtectionScopeRow,
    ScopedEncryptedEntityRow,
    ScopedEncryptedRelationshipRow,
    ScopedEncryptedVaultSnapshotRow,
    VaultRow,
)


class VaultRepository(Protocol):
    """Common versioned vault-envelope operations."""

    def create_vault(self, row: VaultRow) -> bool: ...

    def get_vault(self, principal_id: str, vault_id: str) -> VaultRow | None: ...

    def replace_envelope(
        self,
        principal_id: str,
        vault_id: str,
        expected_revision: int,
        envelope: KeyEnvelope,
    ) -> bool: ...


class GraphRepository(VaultRepository, Protocol):
    """Fixed legacy-v1 whole-vault operations; never arbitrary Cypher."""

    def put_entity(
        self,
        principal_id: str,
        vault_id: str,
        envelope_revision: int,
        row: EncryptedEntityRow,
    ) -> bool: ...

    def get_entity(
        self,
        principal_id: str,
        vault_id: str,
        envelope_revision: int,
        entity_id: str,
    ) -> EncryptedEntityRow | None: ...

    def put_relationship(
        self,
        principal_id: str,
        vault_id: str,
        envelope_revision: int,
        row: EncryptedRelationshipRow,
    ) -> bool: ...

    def put_entity_relationship_bundle(
        self,
        principal_id: str,
        vault_id: str,
        envelope_revision: int,
        entity_rows: tuple[EncryptedEntityRow, ...],
        relationship_row: EncryptedRelationshipRow,
    ) -> bool:
        """Atomically create helper entities and one relationship."""

        ...

    def get_neighborhood(
        self,
        principal_id: str,
        vault_id: str,
        envelope_revision: int,
        entity_id: str,
        *,
        limit: int,
    ) -> EncryptedNeighborhoodRow | None: ...

    def get_vault_snapshot(
        self,
        principal_id: str,
        vault_id: str,
        envelope_revision: int,
        *,
        entity_limit: int,
        relationship_limit: int,
    ) -> EncryptedVaultSnapshotRow | None:
        """Fetch at most each limit plus one row to detect truncation."""

        ...


class ScopedGraphRepository(VaultRepository, Protocol):
    """Fixed v2 protection-scope operations; never arbitrary Cypher."""

    def put_protection_scope(
        self,
        principal_id: str,
        vault_id: str,
        envelope_revision: int,
        row: ProtectionScopeRow,
    ) -> bool: ...

    def get_protection_scopes(
        self,
        principal_id: str,
        vault_id: str,
        envelope_revision: int,
        scope_ids: tuple[str, ...],
    ) -> tuple[ProtectionScopeRow, ...] | None: ...

    def put_scoped_entity(
        self,
        principal_id: str,
        vault_id: str,
        envelope_revision: int,
        row: ScopedEncryptedEntityRow,
    ) -> bool: ...

    def get_scoped_entity(
        self,
        principal_id: str,
        vault_id: str,
        envelope_revision: int,
        allowed_scope_ids: tuple[str, ...],
        entity_id: str,
    ) -> ScopedEncryptedEntityRow | None: ...

    def replace_scoped_entity(
        self,
        principal_id: str,
        vault_id: str,
        envelope_revision: int,
        allowed_scope_ids: tuple[str, ...],
        expected_record_revision: int,
        row: ScopedEncryptedEntityRow,
    ) -> bool: ...

    def delete_scoped_entity(
        self,
        principal_id: str,
        vault_id: str,
        envelope_revision: int,
        allowed_scope_ids: tuple[str, ...],
        entity_id: str,
        expected_record_revision: int,
    ) -> bool:
        """Delete an unconnected entity with an optimistic revision check."""

        ...

    def put_scoped_relationship(
        self,
        principal_id: str,
        vault_id: str,
        envelope_revision: int,
        allowed_scope_ids: tuple[str, ...],
        row: ScopedEncryptedRelationshipRow,
    ) -> bool: ...

    def put_scoped_entity_relationship_bundle(
        self,
        principal_id: str,
        vault_id: str,
        envelope_revision: int,
        allowed_scope_ids: tuple[str, ...],
        entity_rows: tuple[ScopedEncryptedEntityRow, ...],
        relationship_row: ScopedEncryptedRelationshipRow,
    ) -> bool:
        """Atomically create helper entities and one scoped relationship."""

        ...

    def get_scoped_relationship(
        self,
        principal_id: str,
        vault_id: str,
        envelope_revision: int,
        allowed_scope_ids: tuple[str, ...],
        relationship_id: str,
    ) -> ScopedEncryptedRelationshipRow | None: ...

    def replace_scoped_relationship(
        self,
        principal_id: str,
        vault_id: str,
        envelope_revision: int,
        allowed_scope_ids: tuple[str, ...],
        expected_record_revision: int,
        row: ScopedEncryptedRelationshipRow,
    ) -> bool: ...

    def delete_scoped_relationship(
        self,
        principal_id: str,
        vault_id: str,
        envelope_revision: int,
        allowed_scope_ids: tuple[str, ...],
        relationship_id: str,
        expected_record_revision: int,
    ) -> bool: ...

    def get_scoped_vault_snapshot(
        self,
        principal_id: str,
        vault_id: str,
        envelope_revision: int,
        allowed_scope_ids: tuple[str, ...],
        *,
        entity_limit: int,
        relationship_limit: int,
    ) -> ScopedEncryptedVaultSnapshotRow | None:
        """Return ciphertext only from granted scopes, plus overflow sentinels."""

        ...
