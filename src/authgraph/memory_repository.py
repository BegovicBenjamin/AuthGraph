"""Thread-safe ciphertext-only repository for tests and local demonstrations."""

from __future__ import annotations

import base64
import threading
from dataclasses import replace

from .models import (
    EncryptedEntityRow,
    EncryptedNeighborhoodRow,
    EncryptedPayload,
    EncryptedRelationshipRow,
    EncryptedVaultSnapshotRow,
    KeyEnvelope,
    VaultRow,
)


class InMemoryGraphRepository:
    """Implements the same complete-mediation rules as the Neo4j adapter."""

    def __init__(self) -> None:
        self._vaults: dict[str, VaultRow] = {}
        self._entities: dict[tuple[str, str], EncryptedEntityRow] = {}
        self._relationships: dict[
            tuple[str, str], EncryptedRelationshipRow
        ] = {}
        self._lock = threading.RLock()

    def _owned_vault(
        self,
        principal_id: str,
        vault_id: str,
        envelope_revision: int | None = None,
    ) -> VaultRow | None:
        row = self._vaults.get(vault_id)
        if (
            row is None
            or row.principal_id != principal_id
            or (
                envelope_revision is not None
                and row.envelope.envelope_revision != envelope_revision
            )
        ):
            return None
        return row

    def create_vault(self, row: VaultRow) -> bool:
        with self._lock:
            if row.vault_id in self._vaults:
                return False
            self._vaults[row.vault_id] = row
            return True

    def get_vault(self, principal_id: str, vault_id: str) -> VaultRow | None:
        with self._lock:
            return self._owned_vault(principal_id, vault_id)

    def replace_envelope(
        self,
        principal_id: str,
        vault_id: str,
        expected_revision: int,
        envelope: KeyEnvelope,
    ) -> bool:
        with self._lock:
            row = self._owned_vault(principal_id, vault_id)
            if (
                row is None
                or row.envelope.envelope_revision != expected_revision
                or envelope.envelope_revision != expected_revision + 1
            ):
                return False
            self._vaults[vault_id] = replace(row, envelope=envelope)
            return True

    def put_entity(
        self,
        principal_id: str,
        vault_id: str,
        envelope_revision: int,
        row: EncryptedEntityRow,
    ) -> bool:
        with self._lock:
            key = (vault_id, row.entity_id)
            if (
                self._owned_vault(
                    principal_id, vault_id, envelope_revision
                ) is None
                or row.vault_id != vault_id
                or key in self._entities
            ):
                return False
            self._entities[key] = row
            return True

    def get_entity(
        self,
        principal_id: str,
        vault_id: str,
        envelope_revision: int,
        entity_id: str,
    ) -> EncryptedEntityRow | None:
        with self._lock:
            if (
                self._owned_vault(
                    principal_id, vault_id, envelope_revision
                )
                is None
            ):
                return None
            return self._entities.get((vault_id, entity_id))

    def put_relationship(
        self,
        principal_id: str,
        vault_id: str,
        envelope_revision: int,
        row: EncryptedRelationshipRow,
    ) -> bool:
        with self._lock:
            key = (vault_id, row.relationship_id)
            endpoints_exist = (
                (vault_id, row.from_entity_id) in self._entities
                and (vault_id, row.to_entity_id) in self._entities
            )
            if (
                self._owned_vault(
                    principal_id, vault_id, envelope_revision
                ) is None
                or row.vault_id != vault_id
                or not endpoints_exist
                or key in self._relationships
            ):
                return False
            self._relationships[key] = row
            return True

    def get_neighborhood(
        self,
        principal_id: str,
        vault_id: str,
        envelope_revision: int,
        entity_id: str,
        *,
        limit: int,
    ) -> EncryptedNeighborhoodRow | None:
        with self._lock:
            center = self.get_entity(
                principal_id,
                vault_id,
                envelope_revision,
                entity_id,
            )
            if center is None:
                return None
            relationships = [
                row
                for (row_vault, _), row in self._relationships.items()
                if row_vault == vault_id
                and (
                    row.from_entity_id == entity_id
                    or row.to_entity_id == entity_id
                )
            ][:limit]
            neighbor_ids = {
                row.to_entity_id
                if row.from_entity_id == entity_id
                else row.from_entity_id
                for row in relationships
            }
            neighbors = tuple(
                self._entities[(vault_id, neighbor_id)]
                for neighbor_id in neighbor_ids
            )
            return EncryptedNeighborhoodRow(
                center=center,
                neighbors=neighbors,
                relationships=tuple(relationships),
            )

    def get_vault_snapshot(
        self,
        principal_id: str,
        vault_id: str,
        envelope_revision: int,
        *,
        entity_limit: int,
        relationship_limit: int,
    ) -> EncryptedVaultSnapshotRow | None:
        """Return bounded ciphertext rows plus one overflow sentinel row."""

        if (
            type(entity_limit) is not int
            or entity_limit <= 0
            or type(relationship_limit) is not int
            or relationship_limit <= 0
        ):
            raise ValueError("Snapshot repository limits must be positive integers.")
        with self._lock:
            if (
                self._owned_vault(
                    principal_id,
                    vault_id,
                    envelope_revision,
                )
                is None
            ):
                return None
            entities = tuple(
                row
                for (row_vault, _), row in sorted(self._entities.items())
                if row_vault == vault_id
            )[: entity_limit + 1]
            relationships = tuple(
                row
                for (row_vault, _), row in sorted(
                    self._relationships.items()
                )
                if row_vault == vault_id
            )[: relationship_limit + 1]
            return EncryptedVaultSnapshotRow(
                entities=entities,
                relationships=relationships,
            )

    def ciphertext_snapshot(self) -> dict[str, object]:
        """Return storage-shaped ciphertext for assertions—never plaintext."""

        def payload(value: EncryptedPayload) -> dict[str, object]:
            return {
                "version": value.version,
                "key_version": value.key_version,
                "algorithm": value.algorithm,
                "nonce": base64.b64encode(value.nonce).decode("ascii"),
                "ciphertext": base64.b64encode(value.ciphertext).decode("ascii"),
            }

        with self._lock:
            return {
                "vaults": [
                    {
                        "vault_id": vault_id,
                        "envelope": {
                            "version": row.envelope.version,
                            "envelope_revision": row.envelope.envelope_revision,
                            "key_version": row.envelope.key_version,
                            "wrapping_algorithm": row.envelope.wrapping_algorithm,
                            "salt": base64.b64encode(
                                row.envelope.salt
                            ).decode("ascii"),
                            "nonce": base64.b64encode(
                                row.envelope.nonce
                            ).decode("ascii"),
                            "wrapped_dek": base64.b64encode(
                                row.envelope.wrapped_dek
                            ).decode("ascii"),
                        },
                    }
                    for vault_id, row in self._vaults.items()
                ],
                "entities": [
                    {
                        "vault_id": vault_id,
                        "entity_id": entity_id,
                        "payload": payload(row.payload),
                    }
                    for (vault_id, entity_id), row in self._entities.items()
                ],
                "relationships": [
                    {
                        "vault_id": vault_id,
                        "relationship_id": relationship_id,
                        "payload": payload(row.payload),
                    }
                    for (
                        vault_id,
                        relationship_id,
                    ), row in self._relationships.items()
                ],
            }

    def tamper_entity_for_testing(self, vault_id: str, entity_id: str) -> None:
        """Flip one ciphertext bit. This helper is intentionally test-only."""

        with self._lock:
            key = (vault_id, entity_id)
            row = self._entities[key]
            changed = bytearray(row.payload.ciphertext)
            changed[0] ^= 1
            self._entities[key] = replace(
                row,
                payload=replace(row.payload, ciphertext=bytes(changed)),
            )

    def swap_entity_payloads_for_testing(
        self,
        vault_id: str,
        first_entity_id: str,
        second_entity_id: str,
    ) -> None:
        """Move valid ciphertext between IDs to verify AAD binding."""

        with self._lock:
            first_key = (vault_id, first_entity_id)
            second_key = (vault_id, second_entity_id)
            first = self._entities[first_key]
            second = self._entities[second_key]
            self._entities[first_key] = replace(first, payload=second.payload)
            self._entities[second_key] = replace(second, payload=first.payload)
