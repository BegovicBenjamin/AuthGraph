"""Thread-safe ciphertext-only repository for tests and local demonstrations."""

from __future__ import annotations

import base64
import threading
import unicodedata
from dataclasses import replace

from .crypto import NONCE_BYTES
from .errors import IntegrityViolation
from .models import (
    EncryptedEntityRow,
    EncryptedNeighborhoodRow,
    EncryptedPayload,
    EncryptedRelationshipRow,
    EncryptedVaultSnapshotRow,
    KeyEnvelope,
    ProtectionScopeRow,
    ScopeKeyEnvelope,
    ScopedEncryptedEntityRow,
    ScopedEncryptedRelationshipRow,
    ScopedEncryptedVaultSnapshotRow,
    VaultRow,
)
from .scoped_crypto import (
    SCOPE_DEK_CIPHERTEXT_BYTES,
    SCOPE_ENVELOPE_VERSION,
    SCOPE_WRAPPING_ALGORITHM,
)
from .scoped_sessions import MAX_SCOPES_PER_SESSION


MAX_OPAQUE_ID_CHARS = 256
AES_GCM_TAG_BYTES = 16
SCOPED_PAYLOAD_VERSION = 2
SCOPED_PAYLOAD_ALGORITHM = "AES-256-GCM"


def _valid_opaque_id(value: object) -> bool:
    return (
        isinstance(value, str)
        and bool(value)
        and len(value) <= MAX_OPAQUE_ID_CHARS
        and not any(
            unicodedata.category(char).startswith("C")
            for char in value
        )
    )


def _valid_scope_ids(scope_ids: object) -> bool:
    return (
        isinstance(scope_ids, tuple)
        and 0 < len(scope_ids) <= MAX_SCOPES_PER_SESSION
        and all(_valid_opaque_id(scope_id) for scope_id in scope_ids)
        and len(set(scope_ids)) == len(scope_ids)
    )


def _valid_scope_envelope(envelope: object) -> bool:
    return (
        isinstance(envelope, ScopeKeyEnvelope)
        and type(envelope.version) is int
        and envelope.version == SCOPE_ENVELOPE_VERSION
        and type(envelope.root_key_version) is int
        and envelope.root_key_version > 0
        and type(envelope.scope_key_version) is int
        and envelope.scope_key_version > 0
        and envelope.algorithm == SCOPE_WRAPPING_ALGORITHM
        and isinstance(envelope.nonce, bytes)
        and len(envelope.nonce) == NONCE_BYTES
        and isinstance(envelope.wrapped_scope_dek, bytes)
        and len(envelope.wrapped_scope_dek) == SCOPE_DEK_CIPHERTEXT_BYTES
    )


def _valid_scoped_payload(payload: object) -> bool:
    return (
        isinstance(payload, EncryptedPayload)
        and type(payload.version) is int
        and payload.version == SCOPED_PAYLOAD_VERSION
        and type(payload.key_version) is int
        and payload.key_version > 0
        and payload.algorithm == SCOPED_PAYLOAD_ALGORITHM
        and isinstance(payload.nonce, bytes)
        and len(payload.nonce) == NONCE_BYTES
        and isinstance(payload.ciphertext, bytes)
        and len(payload.ciphertext) >= AES_GCM_TAG_BYTES
    )


def _valid_record_revision(value: object) -> bool:
    return type(value) is int and value > 0


def _valid_protection_scope_row(
    row: object,
    *,
    vault_id: str,
    scope_id: str | None = None,
) -> bool:
    return (
        isinstance(row, ProtectionScopeRow)
        and row.vault_id == vault_id
        and _valid_opaque_id(row.scope_id)
        and (scope_id is None or row.scope_id == scope_id)
        and _valid_scope_envelope(row.envelope)
    )


def _valid_scoped_entity_row(
    row: object,
    *,
    vault_id: str,
    expected_key_version: int,
) -> bool:
    return (
        isinstance(row, ScopedEncryptedEntityRow)
        and row.vault_id == vault_id
        and _valid_opaque_id(row.scope_id)
        and _valid_opaque_id(row.entity_id)
        and _valid_record_revision(row.record_revision)
        and _valid_scoped_payload(row.payload)
        and row.payload.key_version == expected_key_version
    )


def _valid_scoped_relationship_row(
    row: object,
    *,
    vault_id: str,
    expected_key_version: int,
) -> bool:
    return (
        isinstance(row, ScopedEncryptedRelationshipRow)
        and row.vault_id == vault_id
        and _valid_opaque_id(row.scope_id)
        and _valid_opaque_id(row.relationship_id)
        and _valid_opaque_id(row.from_entity_id)
        and _valid_opaque_id(row.to_entity_id)
        and _valid_record_revision(row.record_revision)
        and _valid_scoped_payload(row.payload)
        and row.payload.key_version == expected_key_version
    )


class InMemoryGraphRepository:
    """Implements the same complete-mediation rules as the Neo4j adapter."""

    def __init__(self) -> None:
        self._vaults: dict[str, VaultRow] = {}
        self._entities: dict[tuple[str, str], EncryptedEntityRow] = {}
        self._relationships: dict[
            tuple[str, str], EncryptedRelationshipRow
        ] = {}
        self._protection_scopes: dict[
            tuple[str, str], ProtectionScopeRow
        ] = {}
        self._scoped_entities: dict[
            tuple[str, str], ScopedEncryptedEntityRow
        ] = {}
        self._scoped_relationships: dict[
            tuple[str, str], ScopedEncryptedRelationshipRow
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

    def _owned_scoped_vault(
        self,
        principal_id: str,
        vault_id: str,
        envelope_revision: int | None = None,
    ) -> VaultRow | None:
        row = self._owned_vault(
            principal_id,
            vault_id,
            envelope_revision,
        )
        if (
            row is None
            or not isinstance(row, VaultRow)
            or not isinstance(row.envelope, KeyEnvelope)
            or type(row.envelope.version) is not int
            or row.envelope.version != 2
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
                or (
                    row.envelope.version == 2
                    and (
                        type(envelope.version) is not int
                        or envelope.version != 2
                        or type(envelope.key_version) is not int
                        or envelope.key_version != row.envelope.key_version
                    )
                )
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

    def put_entity_relationship_bundle(
        self,
        principal_id: str,
        vault_id: str,
        envelope_revision: int,
        entity_rows: tuple[EncryptedEntityRow, ...],
        relationship_row: EncryptedRelationshipRow,
    ) -> bool:
        """Atomically create helper entities and their encrypted edge."""

        with self._lock:
            entity_keys = tuple(
                (vault_id, row.entity_id) for row in entity_rows
            )
            relationship_key = (
                vault_id,
                relationship_row.relationship_id,
            )
            available_entity_ids = {
                entity_id
                for row_vault, entity_id in self._entities
                if row_vault == vault_id
            } | {row.entity_id for row in entity_rows}
            if (
                self._owned_vault(
                    principal_id,
                    vault_id,
                    envelope_revision,
                )
                is None
                or not entity_rows
                or len(entity_keys) != len(set(entity_keys))
                or any(row.vault_id != vault_id for row in entity_rows)
                or any(key in self._entities for key in entity_keys)
                or relationship_row.vault_id != vault_id
                or relationship_key in self._relationships
                or relationship_row.from_entity_id not in available_entity_ids
                or relationship_row.to_entity_id not in available_entity_ids
            ):
                return False
            for key, row in zip(entity_keys, entity_rows, strict=True):
                self._entities[key] = row
            self._relationships[relationship_key] = relationship_row
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

    def put_protection_scope(
        self,
        principal_id: str,
        vault_id: str,
        envelope_revision: int,
        row: ProtectionScopeRow,
    ) -> bool:
        with self._lock:
            vault = self._owned_scoped_vault(
                principal_id,
                vault_id,
                envelope_revision,
            )
            if not _valid_protection_scope_row(row, vault_id=vault_id):
                return False
            key = (vault_id, row.scope_id)
            if (
                vault is None
                or row.envelope.root_key_version
                != vault.envelope.key_version
                or any(
                    stored_scope_id == row.scope_id
                    for _, stored_scope_id in self._protection_scopes
                )
            ):
                return False
            self._protection_scopes[key] = row
            return True

    def get_protection_scopes(
        self,
        principal_id: str,
        vault_id: str,
        envelope_revision: int,
        scope_ids: tuple[str, ...],
    ) -> tuple[ProtectionScopeRow, ...] | None:
        if not _valid_scope_ids(scope_ids):
            return None
        with self._lock:
            vault = self._owned_scoped_vault(
                principal_id,
                vault_id,
                envelope_revision,
            )
            if vault is None:
                return None
            rows: list[ProtectionScopeRow] = []
            for scope_id in scope_ids:
                row = self._protection_scopes.get((vault_id, scope_id))
                if row is None:
                    continue
                if (
                    not _valid_protection_scope_row(
                        row,
                        vault_id=vault_id,
                        scope_id=scope_id,
                    )
                    or row.envelope.root_key_version
                    != vault.envelope.key_version
                ):
                    raise IntegrityViolation()
                rows.append(row)
            return tuple(rows)

    def put_scoped_entity(
        self,
        principal_id: str,
        vault_id: str,
        envelope_revision: int,
        row: ScopedEncryptedEntityRow,
    ) -> bool:
        with self._lock:
            if (
                not isinstance(row, ScopedEncryptedEntityRow)
                or row.vault_id != vault_id
                or not _valid_opaque_id(row.scope_id)
                or not _valid_opaque_id(row.entity_id)
                or row.record_revision != 1
                or not _valid_scoped_payload(row.payload)
            ):
                return False
            vault = self._owned_scoped_vault(
                principal_id,
                vault_id,
                envelope_revision,
            )
            scope = self._protection_scopes.get(
                (vault_id, row.scope_id)
            )
            key = (vault_id, row.entity_id)
            if (
                vault is None
                or not _valid_protection_scope_row(
                    scope,
                    vault_id=vault_id,
                    scope_id=row.scope_id,
                )
                or scope.envelope.root_key_version
                != vault.envelope.key_version
                or row.payload.key_version
                != scope.envelope.scope_key_version
                or any(
                    stored_entity_id == row.entity_id
                    for _, stored_entity_id in self._scoped_entities
                )
            ):
                return False
            self._scoped_entities[key] = row
            return True

    def get_scoped_entity(
        self,
        principal_id: str,
        vault_id: str,
        envelope_revision: int,
        allowed_scope_ids: tuple[str, ...],
        entity_id: str,
    ) -> ScopedEncryptedEntityRow | None:
        if not _valid_scope_ids(allowed_scope_ids):
            return None
        with self._lock:
            if (
                self._owned_scoped_vault(
                    principal_id,
                    vault_id,
                    envelope_revision,
                )
                is None
            ):
                return None
            row = self._scoped_entities.get((vault_id, entity_id))
            if row is None:
                return None
            if not isinstance(row, ScopedEncryptedEntityRow):
                raise IntegrityViolation()
            if row.scope_id not in allowed_scope_ids:
                return None
            scope = self._protection_scopes.get(
                (vault_id, row.scope_id)
            )
            if scope is None:
                return None
            if (
                not _valid_protection_scope_row(
                    scope,
                    vault_id=vault_id,
                    scope_id=row.scope_id,
                )
                or not _valid_scoped_entity_row(
                    row,
                    vault_id=vault_id,
                    expected_key_version=scope.envelope.scope_key_version,
                )
                or row.entity_id != entity_id
            ):
                raise IntegrityViolation()
            return row

    def replace_scoped_entity(
        self,
        principal_id: str,
        vault_id: str,
        envelope_revision: int,
        allowed_scope_ids: tuple[str, ...],
        expected_record_revision: int,
        row: ScopedEncryptedEntityRow,
    ) -> bool:
        if (
            not _valid_scope_ids(allowed_scope_ids)
            or not _valid_record_revision(expected_record_revision)
            or not isinstance(row, ScopedEncryptedEntityRow)
            or row.vault_id != vault_id
            or row.scope_id not in allowed_scope_ids
            or row.record_revision != expected_record_revision + 1
            or not _valid_scoped_payload(row.payload)
        ):
            return False
        with self._lock:
            vault = self._owned_scoped_vault(
                principal_id,
                vault_id,
                envelope_revision,
            )
            scope = self._protection_scopes.get((vault_id, row.scope_id))
            current = self._scoped_entities.get(
                (vault_id, row.entity_id)
            )
            if (
                vault is None
                or not _valid_protection_scope_row(
                    scope,
                    vault_id=vault_id,
                    scope_id=row.scope_id,
                )
                or scope.envelope.root_key_version
                != vault.envelope.key_version
                or not _valid_scoped_entity_row(
                    row,
                    vault_id=vault_id,
                    expected_key_version=scope.envelope.scope_key_version,
                )
            ):
                return False
            if current == row:
                return True
            if (
                not _valid_scoped_entity_row(
                    current,
                    vault_id=vault_id,
                    expected_key_version=scope.envelope.scope_key_version,
                )
                or current.entity_id != row.entity_id
                or current.scope_id != row.scope_id
                or current.record_revision != expected_record_revision
            ):
                return False
            self._scoped_entities[(vault_id, row.entity_id)] = row
            return True

    def delete_scoped_entity(
        self,
        principal_id: str,
        vault_id: str,
        envelope_revision: int,
        allowed_scope_ids: tuple[str, ...],
        entity_id: str,
        expected_record_revision: int,
    ) -> bool:
        if (
            not _valid_scope_ids(allowed_scope_ids)
            or not _valid_opaque_id(entity_id)
            or not _valid_record_revision(expected_record_revision)
        ):
            return False
        with self._lock:
            vault = self._owned_scoped_vault(
                principal_id,
                vault_id,
                envelope_revision,
            )
            row = self._scoped_entities.get((vault_id, entity_id))
            if (
                vault is None
                or not isinstance(row, ScopedEncryptedEntityRow)
                or row.scope_id not in allowed_scope_ids
            ):
                return False
            scope = self._protection_scopes.get((vault_id, row.scope_id))
            if (
                not _valid_protection_scope_row(
                    scope,
                    vault_id=vault_id,
                    scope_id=row.scope_id,
                )
                or scope.envelope.root_key_version
                != vault.envelope.key_version
                or not _valid_scoped_entity_row(
                    row,
                    vault_id=vault_id,
                    expected_key_version=scope.envelope.scope_key_version,
                )
                or row.entity_id != entity_id
                or row.record_revision != expected_record_revision
                or any(
                    relationship_vault == vault_id
                    and (
                        not isinstance(
                            relationship,
                            ScopedEncryptedRelationshipRow,
                        )
                        or relationship.from_entity_id == entity_id
                        or relationship.to_entity_id == entity_id
                    )
                    for (
                        relationship_vault,
                        _,
                    ), relationship in self._scoped_relationships.items()
                )
            ):
                return False
            del self._scoped_entities[(vault_id, entity_id)]
            return True

    def put_scoped_relationship(
        self,
        principal_id: str,
        vault_id: str,
        envelope_revision: int,
        allowed_scope_ids: tuple[str, ...],
        row: ScopedEncryptedRelationshipRow,
    ) -> bool:
        if (
            not _valid_scope_ids(allowed_scope_ids)
            or not isinstance(row, ScopedEncryptedRelationshipRow)
            or row.vault_id != vault_id
            or row.scope_id not in allowed_scope_ids
            or not _valid_opaque_id(row.scope_id)
            or not _valid_opaque_id(row.relationship_id)
            or not _valid_opaque_id(row.from_entity_id)
            or not _valid_opaque_id(row.to_entity_id)
            or row.record_revision != 1
            or not _valid_scoped_payload(row.payload)
        ):
            return False
        with self._lock:
            key = (vault_id, row.relationship_id)
            vault = self._owned_scoped_vault(
                principal_id,
                vault_id,
                envelope_revision,
            )
            relationship_scope = self._protection_scopes.get(
                (vault_id, row.scope_id)
            )
            source = self._scoped_entities.get(
                (vault_id, row.from_entity_id)
            )
            target = self._scoped_entities.get(
                (vault_id, row.to_entity_id)
            )
            if (
                vault is None
                or not _valid_protection_scope_row(
                    relationship_scope,
                    vault_id=vault_id,
                    scope_id=row.scope_id,
                )
                or relationship_scope.envelope.root_key_version
                != vault.envelope.key_version
                or row.payload.key_version
                != relationship_scope.envelope.scope_key_version
                or source is None
                or target is None
                or not isinstance(source, ScopedEncryptedEntityRow)
                or not isinstance(target, ScopedEncryptedEntityRow)
                or source.vault_id != vault_id
                or target.vault_id != vault_id
                or source.entity_id != row.from_entity_id
                or target.entity_id != row.to_entity_id
                or not _valid_opaque_id(source.scope_id)
                or not _valid_opaque_id(target.scope_id)
                or (
                    vault_id,
                    source.scope_id,
                )
                not in self._protection_scopes
                or (
                    vault_id,
                    target.scope_id,
                )
                not in self._protection_scopes
                or source.scope_id not in allowed_scope_ids
                or target.scope_id not in allowed_scope_ids
                or any(
                    stored_relationship_id == row.relationship_id
                    for _, stored_relationship_id in self._scoped_relationships
                )
            ):
                return False
            self._scoped_relationships[key] = row
            return True

    def put_scoped_entity_relationship_bundle(
        self,
        principal_id: str,
        vault_id: str,
        envelope_revision: int,
        allowed_scope_ids: tuple[str, ...],
        entity_rows: tuple[ScopedEncryptedEntityRow, ...],
        relationship_row: ScopedEncryptedRelationshipRow,
    ) -> bool:
        if (
            not _valid_scope_ids(allowed_scope_ids)
            or not isinstance(entity_rows, tuple)
            or not 1 <= len(entity_rows) <= 2
            or not isinstance(
                relationship_row,
                ScopedEncryptedRelationshipRow,
            )
            or relationship_row.vault_id != vault_id
            or relationship_row.scope_id not in allowed_scope_ids
            or relationship_row.record_revision != 1
            or not _valid_scoped_payload(relationship_row.payload)
            or any(
                not isinstance(row, ScopedEncryptedEntityRow)
                or row.vault_id != vault_id
                or row.scope_id != relationship_row.scope_id
                or row.record_revision != 1
                or not _valid_scoped_payload(row.payload)
                for row in entity_rows
            )
        ):
            return False
        new_by_id = {row.entity_id: row for row in entity_rows}
        endpoint_ids = {
            relationship_row.from_entity_id,
            relationship_row.to_entity_id,
        }
        if (
            len(new_by_id) != len(entity_rows)
            or set(new_by_id) - endpoint_ids
        ):
            return False

        with self._lock:
            vault = self._owned_scoped_vault(
                principal_id,
                vault_id,
                envelope_revision,
            )
            relationship_scope = self._protection_scopes.get(
                (vault_id, relationship_row.scope_id)
            )
            if (
                vault is None
                or not _valid_protection_scope_row(
                    relationship_scope,
                    vault_id=vault_id,
                    scope_id=relationship_row.scope_id,
                )
                or relationship_scope.envelope.root_key_version
                != vault.envelope.key_version
                or not _valid_scoped_relationship_row(
                    relationship_row,
                    vault_id=vault_id,
                    expected_key_version=(
                        relationship_scope.envelope.scope_key_version
                    ),
                )
                or any(
                    not _valid_scoped_entity_row(
                        row,
                        vault_id=vault_id,
                        expected_key_version=(
                            relationship_scope.envelope.scope_key_version
                        ),
                    )
                    for row in entity_rows
                )
            ):
                return False

            existing_bundle_is_exact = (
                all(
                    self._scoped_entities.get(
                        (vault_id, row.entity_id)
                    )
                    == row
                    for row in entity_rows
                )
                and self._scoped_relationships.get(
                    (vault_id, relationship_row.relationship_id)
                )
                == relationship_row
            )
            if not existing_bundle_is_exact and (
                any(
                    stored_entity_id in new_by_id
                    for _, stored_entity_id in self._scoped_entities
                )
                or any(
                    stored_relationship_id
                    == relationship_row.relationship_id
                    for (
                        _,
                        stored_relationship_id,
                    ) in self._scoped_relationships
                )
            ):
                return False

            for entity_id in (
                relationship_row.from_entity_id,
                relationship_row.to_entity_id,
            ):
                row = new_by_id.get(entity_id)
                if row is None:
                    row = self._scoped_entities.get(
                        (vault_id, entity_id)
                    )
                if not isinstance(row, ScopedEncryptedEntityRow):
                    return False
                scope = self._protection_scopes.get(
                    (vault_id, row.scope_id)
                )
                if (
                    row.scope_id not in allowed_scope_ids
                    or not _valid_protection_scope_row(
                        scope,
                        vault_id=vault_id,
                        scope_id=row.scope_id,
                    )
                    or scope.envelope.root_key_version
                    != vault.envelope.key_version
                    or not _valid_scoped_entity_row(
                        row,
                        vault_id=vault_id,
                        expected_key_version=(
                            scope.envelope.scope_key_version
                        ),
                    )
                    or row.entity_id != entity_id
                ):
                    return False

            if existing_bundle_is_exact:
                return True

            for row in entity_rows:
                self._scoped_entities[(vault_id, row.entity_id)] = row
            self._scoped_relationships[
                (vault_id, relationship_row.relationship_id)
            ] = relationship_row
            return True

    def get_scoped_relationship(
        self,
        principal_id: str,
        vault_id: str,
        envelope_revision: int,
        allowed_scope_ids: tuple[str, ...],
        relationship_id: str,
    ) -> ScopedEncryptedRelationshipRow | None:
        if (
            not _valid_scope_ids(allowed_scope_ids)
            or not _valid_opaque_id(relationship_id)
        ):
            return None
        allowed = frozenset(allowed_scope_ids)
        with self._lock:
            vault = self._owned_scoped_vault(
                principal_id,
                vault_id,
                envelope_revision,
            )
            if vault is None:
                return None
            row = self._scoped_relationships.get(
                (vault_id, relationship_id)
            )
            if row is None:
                return None
            if not isinstance(row, ScopedEncryptedRelationshipRow):
                raise IntegrityViolation()
            if row.scope_id not in allowed:
                return None
            relationship_scope = self._protection_scopes.get(
                (vault_id, row.scope_id)
            )
            source = self._scoped_entities.get(
                (vault_id, row.from_entity_id)
            )
            target = self._scoped_entities.get(
                (vault_id, row.to_entity_id)
            )
            if (
                not isinstance(source, ScopedEncryptedEntityRow)
                or not isinstance(target, ScopedEncryptedEntityRow)
            ):
                raise IntegrityViolation()
            if (
                source.scope_id not in allowed
                or target.scope_id not in allowed
            ):
                return None
            source_scope = self._protection_scopes.get(
                (vault_id, source.scope_id)
            )
            target_scope = self._protection_scopes.get(
                (vault_id, target.scope_id)
            )
            if (
                not _valid_protection_scope_row(
                    relationship_scope,
                    vault_id=vault_id,
                    scope_id=row.scope_id,
                )
                or not _valid_protection_scope_row(
                    source_scope,
                    vault_id=vault_id,
                    scope_id=source.scope_id,
                )
                or not _valid_protection_scope_row(
                    target_scope,
                    vault_id=vault_id,
                    scope_id=target.scope_id,
                )
                or relationship_scope.envelope.root_key_version
                != vault.envelope.key_version
                or source_scope.envelope.root_key_version
                != vault.envelope.key_version
                or target_scope.envelope.root_key_version
                != vault.envelope.key_version
                or not _valid_scoped_relationship_row(
                    row,
                    vault_id=vault_id,
                    expected_key_version=(
                        relationship_scope.envelope.scope_key_version
                    ),
                )
                or not _valid_scoped_entity_row(
                    source,
                    vault_id=vault_id,
                    expected_key_version=(
                        source_scope.envelope.scope_key_version
                    ),
                )
                or not _valid_scoped_entity_row(
                    target,
                    vault_id=vault_id,
                    expected_key_version=(
                        target_scope.envelope.scope_key_version
                    ),
                )
                or row.relationship_id != relationship_id
                or source.entity_id != row.from_entity_id
                or target.entity_id != row.to_entity_id
            ):
                raise IntegrityViolation()
            return row

    def replace_scoped_relationship(
        self,
        principal_id: str,
        vault_id: str,
        envelope_revision: int,
        allowed_scope_ids: tuple[str, ...],
        expected_record_revision: int,
        row: ScopedEncryptedRelationshipRow,
    ) -> bool:
        if (
            not _valid_scope_ids(allowed_scope_ids)
            or not _valid_record_revision(expected_record_revision)
            or not isinstance(row, ScopedEncryptedRelationshipRow)
            or row.vault_id != vault_id
            or row.scope_id not in allowed_scope_ids
            or row.record_revision != expected_record_revision + 1
            or not _valid_scoped_payload(row.payload)
        ):
            return False
        with self._lock:
            current = self.get_scoped_relationship(
                principal_id,
                vault_id,
                envelope_revision,
                allowed_scope_ids,
                row.relationship_id,
            )
            if current == row:
                return True
            if (
                current is None
                or current.scope_id != row.scope_id
                or current.from_entity_id != row.from_entity_id
                or current.to_entity_id != row.to_entity_id
                or current.record_revision != expected_record_revision
            ):
                return False
            relationship_scope = self._protection_scopes.get(
                (vault_id, row.scope_id)
            )
            if (
                not _valid_protection_scope_row(
                    relationship_scope,
                    vault_id=vault_id,
                    scope_id=row.scope_id,
                )
                or not _valid_scoped_relationship_row(
                    row,
                    vault_id=vault_id,
                    expected_key_version=(
                        relationship_scope.envelope.scope_key_version
                    ),
                )
            ):
                return False
            self._scoped_relationships[
                (vault_id, row.relationship_id)
            ] = row
            return True

    def delete_scoped_relationship(
        self,
        principal_id: str,
        vault_id: str,
        envelope_revision: int,
        allowed_scope_ids: tuple[str, ...],
        relationship_id: str,
        expected_record_revision: int,
    ) -> bool:
        if not _valid_record_revision(expected_record_revision):
            return False
        with self._lock:
            row = self.get_scoped_relationship(
                principal_id,
                vault_id,
                envelope_revision,
                allowed_scope_ids,
                relationship_id,
            )
            if (
                row is None
                or row.record_revision != expected_record_revision
            ):
                return False
            del self._scoped_relationships[(vault_id, relationship_id)]
            return True

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
        if (
            type(entity_limit) is not int
            or entity_limit <= 0
            or type(relationship_limit) is not int
            or relationship_limit <= 0
        ):
            raise ValueError("Snapshot repository limits must be positive integers.")
        if not _valid_scope_ids(allowed_scope_ids):
            return None
        allowed = frozenset(allowed_scope_ids)
        with self._lock:
            if (
                self._owned_scoped_vault(
                    principal_id,
                    vault_id,
                    envelope_revision,
                )
                is None
            ):
                return None
            visible_entities: list[ScopedEncryptedEntityRow] = []
            for (row_vault, entity_id), row in sorted(
                self._scoped_entities.items()
            ):
                if row_vault != vault_id:
                    continue
                if not isinstance(row, ScopedEncryptedEntityRow):
                    raise IntegrityViolation()
                if row.scope_id not in allowed:
                    continue
                scope = self._protection_scopes.get(
                    (vault_id, row.scope_id)
                )
                if scope is None:
                    continue
                if (
                    not _valid_protection_scope_row(
                        scope,
                        vault_id=vault_id,
                        scope_id=row.scope_id,
                    )
                    or not _valid_scoped_entity_row(
                        row,
                        vault_id=vault_id,
                        expected_key_version=(
                            scope.envelope.scope_key_version
                        ),
                    )
                    or row.entity_id != entity_id
                ):
                    raise IntegrityViolation()
                visible_entities.append(row)

            visible_entity_ids = {
                row.entity_id for row in visible_entities
            }
            visible_relationships: list[
                ScopedEncryptedRelationshipRow
            ] = []
            for (row_vault, relationship_id), row in sorted(
                self._scoped_relationships.items()
            ):
                if row_vault != vault_id:
                    continue
                if not isinstance(row, ScopedEncryptedRelationshipRow):
                    raise IntegrityViolation()
                if (
                    row.scope_id not in allowed
                    or row.from_entity_id not in visible_entity_ids
                    or row.to_entity_id not in visible_entity_ids
                ):
                    continue
                scope = self._protection_scopes.get(
                    (vault_id, row.scope_id)
                )
                if scope is None:
                    continue
                if (
                    not _valid_protection_scope_row(
                        scope,
                        vault_id=vault_id,
                        scope_id=row.scope_id,
                    )
                    or not _valid_scoped_relationship_row(
                        row,
                        vault_id=vault_id,
                        expected_key_version=(
                            scope.envelope.scope_key_version
                        ),
                    )
                    or row.relationship_id != relationship_id
                ):
                    raise IntegrityViolation()
                visible_relationships.append(row)

            entities = tuple(visible_entities[: entity_limit + 1])
            relationships = tuple(
                visible_relationships[: relationship_limit + 1]
            )
            return ScopedEncryptedVaultSnapshotRow(
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
                "protection_scopes": [
                    {
                        "vault_id": vault_id,
                        "scope_id": scope_id,
                        "envelope": {
                            "version": row.envelope.version,
                            "root_key_version": (
                                row.envelope.root_key_version
                            ),
                            "scope_key_version": (
                                row.envelope.scope_key_version
                            ),
                            "algorithm": row.envelope.algorithm,
                            "nonce": base64.b64encode(
                                row.envelope.nonce
                            ).decode("ascii"),
                            "wrapped_scope_dek": base64.b64encode(
                                row.envelope.wrapped_scope_dek
                            ).decode("ascii"),
                        },
                    }
                    for (
                        vault_id,
                        scope_id,
                    ), row in self._protection_scopes.items()
                ],
                "scoped_entities": [
                    {
                        "vault_id": vault_id,
                        "scope_id": row.scope_id,
                        "entity_id": entity_id,
                        "payload": payload(row.payload),
                    }
                    for (
                        vault_id,
                        entity_id,
                    ), row in self._scoped_entities.items()
                ],
                "scoped_relationships": [
                    {
                        "vault_id": vault_id,
                        "scope_id": row.scope_id,
                        "relationship_id": relationship_id,
                        "payload": payload(row.payload),
                    }
                    for (
                        vault_id,
                        relationship_id,
                    ), row in self._scoped_relationships.items()
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
