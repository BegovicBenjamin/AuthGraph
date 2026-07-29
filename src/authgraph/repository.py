"""Storage boundary used by the trusted AuthGraph service."""

from __future__ import annotations

from typing import Protocol

from .models import (
    EncryptedEntityRow,
    EncryptedNeighborhoodRow,
    EncryptedRelationshipRow,
    EncryptedVaultSnapshotRow,
    KeyEnvelope,
    VaultRow,
)


class GraphRepository(Protocol):
    """Only fixed, vault-scoped operations are exposed—never arbitrary Cypher."""

    def create_vault(self, row: VaultRow) -> bool: ...

    def get_vault(self, principal_id: str, vault_id: str) -> VaultRow | None: ...

    def replace_envelope(
        self,
        principal_id: str,
        vault_id: str,
        expected_revision: int,
        envelope: KeyEnvelope,
    ) -> bool: ...

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
